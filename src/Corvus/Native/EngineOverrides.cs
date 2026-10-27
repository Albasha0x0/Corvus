using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Corvus.Core;

namespace Corvus.Native;

public enum SeedKind { Function, Code, Label }

/// <summary>A start the engine is given before its first analysis: a function (optionally named), code, or a label.</summary>
public sealed record EngineSeed(SeedKind Kind, uint Rva, string? Name)
{
    public string Text => $"{Kind.ToString().ToLowerInvariant()}:rva:0x{Rva:X}{(Name != null ? "=" + Name : "")}";
}

/// <summary>Engine import options set at load; each set gets its own engine database (<see cref="Key"/>), so the default analysis is kept beside it.</summary>
public sealed partial record EngineOverrides(string? Processor, string? Language, string? CompilerSpec, IReadOnlyList<EngineSeed> Seeds,
    IReadOnlyList<string> DisabledAnalyzers)
{
    public const int MaxSeeds = 4096, MaxAnalyzers = 64;

    /// <summary>IDA's compiler ids (ida_typeinf COMP_*) for Ghidra's compiler spec ids; the specs without one leave IDA's own detection.</summary>
    public static readonly IReadOnlyDictionary<string, int> IdaCompilers = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
    {
        ["windows"] = 0x01, ["clangwindows"] = 0x01, ["borlandcpp"] = 0x02, ["gcc"] = 0x06, ["borlanddelphi"] = 0x08,
    };

    /// <summary>The overrides in canonical form, e.g. "compilerSpec=borlandcpp; seeds=function:rva:0x1000=main".</summary>
    public string Text => string.Join("; ", new[]
    {
        Processor != null ? "processor=" + Processor : null,
        Language != null ? "language=" + Language : null,
        CompilerSpec != null ? "compilerSpec=" + CompilerSpec : null,
        Seeds.Count > 0 ? "seeds=" + string.Join(",", Seeds.Select(s => s.Text)) : null,
        DisabledAnalyzers.Count > 0 ? "disableAnalyzers=" + string.Join(",", DisabledAnalyzers) : null,
    }.Where(p => p != null));

    /// <summary>Part of the engine database names: <c>ov-</c> and 12 hex digits of the SHA-256 of <see cref="Text"/>.</summary>
    public string Key => "ov-" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Text)))[..12];

    public bool Equals(EngineOverrides? other) => other is not null && Text == other.Text;
    public override int GetHashCode() => Text.GetHashCode(StringComparison.Ordinal);

    /// <summary>The IDA compiler for <see cref="CompilerSpec"/>, or null.</summary>
    public int? IdaCompiler => CompilerSpec != null && IdaCompilers.TryGetValue(CompilerSpec, out var id) ? id : null;

    /// <summary>The load_assembly overrides checked for form, names checked later by the engines; null when none was given; throws on a malformed value.</summary>
    public static EngineOverrides? Parse(INativeImage image, string? processor, string? language, string? compilerSpec, string[]? seeds, string[]? disableAnalyzers)
    {
        processor = Blank(processor);
        language = Blank(language);
        compilerSpec = Blank(compilerSpec);
        if (processor == null && language == null && compilerSpec == null && seeds is not { Length: > 0 } && disableAnalyzers is not { Length: > 0 }) return null;
        if (processor != null && !ProcessorForm().IsMatch(processor))
            throw new ToolError(ErrorCode.InvalidArgument, $"processor '{processor}' is not an IDA processor name.", "pass IDA's short name, e.g. processor=metapc, arm, mipsl, ppc");
        if (language != null && !LanguageForm().IsMatch(language))
            throw new ToolError(ErrorCode.InvalidArgument, $"language '{language}' is not a Ghidra language id.", "pass processor:endian:size:variant, e.g. language=x86:LE:32:default");
        if (compilerSpec != null && !ProcessorForm().IsMatch(compilerSpec))
            throw new ToolError(ErrorCode.InvalidArgument, $"compilerSpec '{compilerSpec}' is not a compiler spec id.", "pass a Ghidra compiler spec id, e.g. compilerSpec=borlandcpp, windows, gcc");
        if (seeds is { Length: > MaxSeeds }) throw new ToolError(ErrorCode.LimitExceeded, $"{seeds.Length} seeds; at most {MaxSeeds}.");
        if (disableAnalyzers is { Length: > MaxAnalyzers }) throw new ToolError(ErrorCode.LimitExceeded, $"{disableAnalyzers.Length} analyzers; at most {MaxAnalyzers}.");
        var parsed = (seeds ?? []).Select(s => Seed(image, s)).Distinct().OrderBy(s => s.Rva).ThenBy(s => s.Kind).ToList();
        var analyzers = (disableAnalyzers ?? []).Select(a => a.Trim()).Where(a => a.Length > 0).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();
        foreach (var a in analyzers)
            if (a.Length > 128 || a.IndexOfAny(['=', ';', ',', '\n', '\r']) >= 0)
                throw new ToolError(ErrorCode.InvalidArgument, $"analyzer '{a}' is not an analyzer name.", "pass names as reanalyze_native analyzers=true lists them, e.g. AF_FLIRT or 'Decompiler Switch Analysis'");
        return new EngineOverrides(processor, language, compilerSpec, parsed, analyzers);
    }

    private static EngineSeed Seed(INativeImage image, string text)
    {
        var t = text.Trim();
        var kind = SeedKind.Function;
        int colon = t.IndexOf(':');
        if (colon > 0 && Enum.TryParse<SeedKind>(t[..colon], ignoreCase: true, out var k) && !char.IsDigit(t[0]))
            (kind, t) = (k, t[(colon + 1)..].Trim());
        string? name = null;
        int eq = t.IndexOf('=');
        if (eq >= 0) (t, name) = (t[..eq].Trim(), t[(eq + 1)..].Trim());
        if (name is { Length: 0 }) name = null;
        if (name != null && !NameForm().IsMatch(name))
            throw new ToolError(ErrorCode.InvalidArgument, $"seed name '{name}' is not a symbol name.", "letters, digits and _ $ ? @ . : < > ~, at most 256");
        if (kind == SeedKind.Label && name == null)
            throw new ToolError(ErrorCode.InvalidArgument, $"label seed '{text}' has no name.", "label:0x401000=name");
        return new EngineSeed(kind, NativeAddress.Parse(image, t), name);
    }

    private static string? Blank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    [GeneratedRegex(@"^[A-Za-z0-9_\-.]{1,64}$")]
    private static partial Regex ProcessorForm();

    [GeneratedRegex(@"^[A-Za-z0-9_\-.]+:(LE|BE):\d{1,3}:[A-Za-z0-9_\-. ]{1,64}$")]
    private static partial Regex LanguageForm();

    [GeneratedRegex(@"^[A-Za-z_$?@.][A-Za-z0-9_$?@.:<>~]{0,255}$")]
    private static partial Regex NameForm();

    /// <summary>The <paramref name="max"/> names of <paramref name="known"/> closest to <paramref name="name"/> (shared prefix, then edit distance).</summary>
    public static IEnumerable<string> Nearest(string name, IEnumerable<string> known, int max = 8) =>
        known.Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(k => CommonPrefix(k, name))
            .ThenBy(k => Distance(k.ToLowerInvariant(), name.ToLowerInvariant()))
            .ThenBy(k => k, StringComparer.Ordinal).Take(max);

    private static int CommonPrefix(string a, string b)
    {
        int n = 0;
        while (n < a.Length && n < b.Length && char.ToLowerInvariant(a[n]) == char.ToLowerInvariant(b[n])) n++;
        return n;
    }

    private static int Distance(string a, string b)
    {
        var row = Enumerable.Range(0, b.Length + 1).ToArray();
        for (int i = 1; i <= a.Length; i++)
        {
            int prev = row[0];
            row[0] = i;
            for (int j = 1; j <= b.Length; j++)
            {
                int cur = row[j];
                row[j] = Math.Min(Math.Min(row[j] + 1, row[j - 1] + 1), prev + (a[i - 1] == b[j - 1] ? 0 : 1));
                prev = cur;
            }
        }
        return row[b.Length];
    }
}
