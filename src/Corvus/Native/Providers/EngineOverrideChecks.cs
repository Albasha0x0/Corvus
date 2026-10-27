using System.Collections.Concurrent;
using System.Text;
using System.Xml.Linq;
using Corvus.Core;

namespace Corvus.Native.Providers;

/// <summary>Checks import overrides against what the installed engines know: Ghidra's .ldefs files and IDA's processor modules.</summary>
internal static class EngineOverrideChecks
{
    private static readonly ConcurrentDictionary<string, IReadOnlyDictionary<string, string[]>> Languages = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, IReadOnlySet<string>> Processors = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Ghidra's language ids with their compiler spec ids, from every .ldefs file of the install (processors and extensions).</summary>
    internal static IReadOnlyDictionary<string, string[]> GhidraLanguages(string ghidraDirectory) => Languages.GetOrAdd(ghidraDirectory, dir =>
    {
        var map = new Dictionary<string, string[]>(StringComparer.Ordinal);
        var root = Path.Combine(dir, "Ghidra");
        if (!Directory.Exists(root)) return map;
        foreach (var file in Directory.EnumerateFiles(root, "*.ldefs", SearchOption.AllDirectories))
        {
            try
            {
                foreach (var language in XDocument.Load(file).Descendants("language"))
                    if (language.Attribute("id")?.Value is { Length: > 0 } id)
                        map[id] = [.. language.Elements("compiler").Select(c => c.Attribute("id")?.Value).OfType<string>()];
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Xml.XmlException) { }
        }
        return map;
    });

    /// <summary>InvalidArgument when Ghidra has no such language, or the compiler spec is not one of the language's (any language's without one).</summary>
    internal static void CheckGhidra(string ghidraDirectory, EngineOverrides overrides, string? rawLanguage = null)
    {
        var languages = GhidraLanguages(ghidraDirectory);
        if (languages.Count == 0) return;
        var language = overrides.Language ?? rawLanguage;
        if (overrides.Language is { } wanted && !languages.ContainsKey(wanted))
            throw new ToolError(ErrorCode.InvalidArgument, $"Ghidra has no language '{wanted}'.",
                $"one of its .ldefs ids, e.g. {string.Join(", ", EngineOverrides.Nearest(wanted, languages.Keys))}");
        if (overrides.CompilerSpec is not { } spec) return;
        if (language != null && languages.TryGetValue(language, out var specs))
        {
            if (!specs.Contains(spec, StringComparer.Ordinal))
                throw new ToolError(ErrorCode.InvalidArgument, $"Ghidra's language {language} has no compiler spec '{spec}'.", $"one of: {string.Join(", ", specs)}");
        }
        else if (!languages.Values.Any(s => s.Contains(spec, StringComparer.Ordinal)))
            throw new ToolError(ErrorCode.InvalidArgument, $"No Ghidra language has a compiler spec '{spec}'.",
                $"e.g. {string.Join(", ", EngineOverrides.Nearest(spec, languages.Values.SelectMany(s => s)))}");
    }

    /// <summary>Short processor names found in IDA's processor modules (NUL-terminated in binaries, quoted in Python modules).</summary>
    internal static IReadOnlySet<string> IdaProcessorNames(string idaDirectory) => Processors.GetOrAdd(idaDirectory, dir =>
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var procs = Path.Combine(dir, "procs");
        if (!Directory.Exists(procs)) return names;
        foreach (var file in Directory.EnumerateFiles(procs))
        {
            try
            {
                if (file.EndsWith(".py", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(File.ReadAllText(file), "[\"']([A-Za-z0-9_\\-]{2,16})[\"']"))
                        names.Add(m.Groups[1].Value);
                    continue;
                }
                var bytes = File.ReadAllBytes(file);
                for (int i = 0, start = 0; i < bytes.Length; i++)
                {
                    if (bytes[i] != 0) continue;
                    int length = i - start;
                    if (length is >= 2 and <= 16 && (start == 0 || bytes[start - 1] == 0) && bytes.AsSpan(start, length).IndexOfAnyExceptInRange((byte)0x21, (byte)0x7E) < 0)
                        names.Add(Encoding.ASCII.GetString(bytes, start, length));
                    start = i + 1;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        return names;
    });

    /// <summary>InvalidArgument when no processor module of the install carries the processor name.</summary>
    internal static void CheckIda(string idaDirectory, EngineOverrides overrides)
    {
        if (overrides.Processor is not { } processor) return;
        var names = IdaProcessorNames(idaDirectory);
        if (names.Count == 0 || names.Contains(processor)) return;
        throw new ToolError(ErrorCode.InvalidArgument, $"IDA has no processor '{processor}' in {Path.Combine(idaDirectory, "procs")}.",
            $"IDA's short processor name, e.g. {string.Join(", ", EngineOverrides.Nearest(processor, names.Where(n => n.All(char.IsAsciiLetterOrDigit) && n.Length <= 10), 6))}");
    }
}
