using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>Detects ReadyToRun precompilation and assembly-merge traces. Never throws on malformed input.</summary>
public static class AssemblyTraits
{
    /// <summary>True when the image carries ReadyToRun native code alongside its IL.</summary>
    public static bool IsReadyToRun(ReadOnlySpan<byte> image)
    {
        var pe = PeImage.TryParse(image);
        return pe != null && pe.IsReadyToRun(image);
    }

    /// <summary>Describes a merged assembly, or null when there is no sign of merging.</summary>
    // Signs: an ILRepack.List resource; ILMerge "Input.Old" renames of clashing types (C# names have no dots, so the
    // count is a lower bound); several pre-Roslyn "<PrivateImplementationDetails>{MVID}" types.
    public static string? MergeNote(ModuleDef module)
    {
        try
        {
            var repack = module.Resources.FirstOrDefault(r => r.Name == "ILRepack.List");
            if (repack != null)
            {
                var names = repack is EmbeddedResource er ? ReadRepackList(er.CreateReader().ToArray()) : null;
                return names == null
                    ? "Merged by ILRepack; its ILRepack.List resource is unreadable."
                    : $"Merged by ILRepack from {names.Count} assemblies: {string.Join(", ", names.Select(ShortName))}.";
            }

            var inputs = IlMergeInputs(module);
            var pidModules = module.Types.Select(t => PidGuid.Match(t.Name)).Where(m => m.Success).Select(m => m.Groups[1].Value.ToUpperInvariant()).Distinct().Count();
            if (inputs.Count == 0 && pidModules < 2) return null;
            // +1 for the input that kept the original names.
            int atLeast = Math.Max(inputs.Count + 1, pidModules);
            var from = inputs.Count > 0 ? $" (renamed types from {string.Join(", ", inputs)})" : "";
            return $"Merged assembly (ILMerge-style): at least {atLeast} original modules{from}.";
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static readonly Regex PidGuid = new(@"^<PrivateImplementationDetails>\{([0-9A-Fa-f-]{36})\}$", RegexOptions.CultureInvariant);

    /// <summary>Input names recovered from ILMerge-renamed types ("Input.Old" / "Input123.Old").</summary>
    private static List<string> IlMergeInputs(ModuleDef module)
    {
        var names = new HashSet<(string Namespace, string Name)>();
        foreach (var t in module.Types) names.Add((t.Namespace.String, t.Name.String));
        // Compiler-generated renames carry the bare input name; others append a numeric key.
        var exact = new HashSet<string>(StringComparer.Ordinal);
        var keyed = new List<string>();
        foreach (var t in module.Types)
        {
            string name = t.Name.String;
            // Input names may contain dots; try every split, longest prefix first.
            for (int dot = name.LastIndexOf('.'); dot > 0; dot = name.LastIndexOf('.', dot - 1))
            {
                if (!names.Contains((t.Namespace.String, name[(dot + 1)..]))) continue;
                if (t.CustomAttributes.IsDefined("System.Runtime.CompilerServices.CompilerGeneratedAttribute")) exact.Add(name[..dot]);
                else keyed.Add(name[..dot]);
                break;
            }
        }
        var inputs = new SortedSet<string>(exact, StringComparer.Ordinal);
        foreach (var prefix in keyed)
        {
            // "Lib27" is "Lib2" + key 7 when "Lib2" is known; otherwise strip trailing digits.
            var known = exact.Where(e => prefix.Length > e.Length && prefix.StartsWith(e, StringComparison.Ordinal) && prefix[e.Length..].All(char.IsAsciiDigit))
                .MaxBy(e => e.Length);
            var trimmed = prefix.TrimEnd("0123456789".ToCharArray());
            inputs.Add(known ?? (trimmed.Length > 0 ? trimmed : prefix));
        }
        return [.. inputs];
    }

    private static string ShortName(string fullName) => fullName.Split(',')[0].Trim();

    /// <summary>Parses a BinaryFormatter string[] (17-byte header, 0x11 id count, then 0x06 id 7-bit-length UTF-8 per item), or null.</summary>
    internal static List<string>? ReadRepackList(byte[] data)
    {
        const int header = 17;
        if (data.Length < header + 9 || data[header] != 0x11) return null;
        int count = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(header + 5));
        if (count < 0 || count > 10_000) return null;
        int pos = header + 9;
        var names = new List<string>(count);
        for (int i = 0; i < count; i++)
        {
            if (pos + 5 > data.Length || data[pos] != 0x06) return null;
            pos += 5;
            int len = 0, shift = 0;
            byte b;
            do
            {
                if (pos >= data.Length || shift > 28) return null;
                b = data[pos++];
                len |= (b & 0x7F) << shift;
                shift += 7;
            } while ((b & 0x80) != 0);
            if (len > data.Length - pos) return null;
            names.Add(Encoding.UTF8.GetString(data, pos, len));
            pos += len;
        }
        return names;
    }
}
