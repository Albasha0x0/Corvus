using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Corvus.Core;

namespace Corvus.Native.Providers.Worker.Yara;

/// <summary>A rule that did not compile: its file, line and column, the enclosing rule (null outside one), code and message.</summary>
public sealed record YaraRuleError(string File, int Line, int Column, string? Rule, string Code, string Message);

/// <summary>One match of a pattern: offset (or address) and length in bytes.</summary>
public sealed record YaraPatternMatch(string Pattern, long Offset, long Length);

/// <summary>A rule that matched: namespace, name, tags, metadata (key, value) in rule order, and its pattern matches.</summary>
public sealed record YaraRuleMatch(string Namespace, string Rule, IReadOnlyList<string> Tags, IReadOnlyList<KeyValuePair<string, string>> Meta,
    IReadOnlyList<YaraPatternMatch> Patterns);

/// <summary>Rules compiled once from text, a file or a folder; failing rules go to <see cref="Errors"/> and the rest still run.</summary>
// Compiled rules are never saved or loaded: VirusTotal/yara-x#720, a file from another version aborts the loader.
internal sealed partial class YaraRules : IDisposable
{
    /// <summary>Rule files read from a folder; past it the rest are named as not read.</summary>
    public const int MaxFiles = 10_000;

    /// <summary>Matches kept per pattern and scan.</summary>
    public const int MaxMatchesPerPattern = 100;

    private IntPtr _rules;

    public int Count { get; }
    public int Files { get; }
    public IReadOnlyList<YaraRuleError> Errors { get; }
    public IReadOnlyList<string> Notes { get; }

    private YaraRules(IntPtr rules, int count, int files, IReadOnlyList<YaraRuleError> errors, IReadOnlyList<string> notes)
    {
        _rules = rules;
        Count = count;
        Files = files;
        Errors = errors;
        Notes = notes;
    }

    /// <summary>Origin of rule source passed as text rather than read from a file.</summary>
    public const string QueryOrigin = "query";

    /// <summary>Compiles the rule file or folder at <paramref name="path"/>; a missing path or a folder without rules is an invalid argument.</summary>
    public static YaraRules Compile(string path)
    {
        YaraX.Load();
        var notes = new List<string>();
        var files = RuleFiles(path, notes);
        return Build([.. files.Select(f => (f, File.ReadAllBytes(f)))], notes);
    }

    /// <summary>Compiles rule text as origin <see cref="QueryOrigin"/>; no resulting rule is an invalid argument naming the first error.</summary>
    public static YaraRules CompileSource(string source)
    {
        YaraX.Load();
        var rules = Build([(QueryOrigin, Encoding.UTF8.GetBytes(source))], []);
        if (rules.Count > 0) return rules;
        var first = rules.Errors.FirstOrDefault();
        rules.Dispose();
        throw new ToolError(ErrorCode.InvalidArgument,
            "query names no rule file or folder, and as rule source it compiled to no rules"
            + (first != null ? $": {QueryOrigin}:{first.Line}:{first.Column}: {first.Code} {first.Message}" : "."),
            "pass rule text, or the path of an existing .yar file or folder of rules");
    }

    private static YaraRules Build(List<(string Origin, byte[] Text)> sources, List<string> notes)
    {
        if (YaraX.yrx_compiler_create(YaraX.RelaxedReSyntax, out var compiler) != YaraX.Success)
            throw new ToolError(ErrorCode.Failed, $"YARA-X could not create a compiler: {YaraX.LastError()}");
        try
        {
            // cuckoo and vt read sandbox reports and VirusTotal data, which Corvus does not supply.
            foreach (var module in new[] { "cuckoo", "vt" })
                YaraX.Check(YaraX.yrx_compiler_ban_module(compiler, YaraX.Utf8(module), YaraX.Utf8($"module `{module}` is not available"),
                    YaraX.Utf8("Corvus scans files and memory only")), "ban a module");
            var byOrigin = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            foreach (var (origin, text) in sources)
            {
                byOrigin[origin] = text;
                // A source that does not compile fails here; its errors are read below.
                _ = YaraX.yrx_compiler_add_source_with_origin(compiler, [.. text, 0], YaraX.Utf8(origin));
            }
            var errors = ReadErrors(compiler, byOrigin, sources.Count == 1 ? sources[0].Origin : null);
            var rules = YaraX.yrx_compiler_build(compiler);
            compiler = IntPtr.Zero;
            return new YaraRules(rules, YaraX.yrx_rules_count(rules), sources.Count, errors, notes);
        }
        finally
        {
            if (compiler != IntPtr.Zero) YaraX.yrx_compiler_destroy(compiler);
        }
    }

    private static List<string> RuleFiles(string path, List<string> notes)
    {
        if (File.Exists(path)) return [Path.GetFullPath(path)];
        if (!Directory.Exists(path))
            throw new ToolError(ErrorCode.InvalidArgument, $"No rule file or folder at {path}.", "pass a .yar file or a folder of .yar and .yara files as query");
        var all = Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".yara", StringComparison.OrdinalIgnoreCase))
            .Order(StringComparer.Ordinal).ToList();
        if (all.Count == 0)
            throw new ToolError(ErrorCode.InvalidArgument, $"{path} holds no .yar or .yara files.", "pass a rule file, or a folder that holds them");
        if (all.Count > MaxFiles)
        {
            notes.Add($"{all.Count:N0} rule files; read the first {MaxFiles:N0} in path order");
            all = all[..MaxFiles];
        }
        return all;
    }

    /// <summary>The compiler's errors with the rule each falls in; the origin names the file, or <paramref name="single"/> when it is the only one.</summary>
    private static List<YaraRuleError> ReadErrors(IntPtr compiler, Dictionary<string, byte[]> sources, string? single)
    {
        if (YaraX.yrx_compiler_errors_json(compiler, out var buffer) != YaraX.Success) return [];
        string json;
        try
        {
            var b = Marshal.PtrToStructure<YaraX.Buffer>(buffer);
            json = YaraX.Text(b.Data, b.Length);
        }
        finally { YaraX.yrx_buffer_destroy(buffer); }
        var errors = new List<YaraRuleError>();
        using var doc = JsonDocument.Parse(json);
        foreach (var e in doc.RootElement.EnumerateArray())
        {
            var label = e.TryGetProperty("labels", out var labels) && labels.GetArrayLength() > 0 ? labels[0] : default;
            var file = label.ValueKind == JsonValueKind.Object && label.TryGetProperty("code_origin", out var o) && o.ValueKind == JsonValueKind.String
                ? o.GetString()! : single ?? "";
            int start = label.ValueKind == JsonValueKind.Object && label.TryGetProperty("span", out var span) ? span.GetProperty("start").GetInt32() : -1;
            errors.Add(new YaraRuleError(file, Int(e, "line"), Int(e, "column"),
                sources.TryGetValue(file, out var text) && start >= 0 ? EnclosingRule(text, start) : null,
                e.TryGetProperty("code", out var c) ? c.GetString() ?? "" : "",
                e.TryGetProperty("title", out var t) ? t.GetString() ?? "" : ""));
        }
        return errors;

        static int Int(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : 0;
    }

    /// <summary>The name of the last rule declared before byte <paramref name="offset"/> of <paramref name="source"/>, or null.</summary>
    internal static string? EnclosingRule(byte[] source, int offset)
    {
        var before = Encoding.UTF8.GetString(source, 0, Math.Clamp(offset, 0, source.Length));
        var last = RuleHead().Matches(before).LastOrDefault();
        return last?.Groups[1].Value;
    }

    // NonBacktracking matches in linear time, so no match timeout.
    [GeneratedRegex(@"(?m)^[ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)", RegexOptions.NonBacktracking)]
    private static partial Regex RuleHead();

    /// <summary>A scanner over these rules; one per thread.</summary>
    public YaraScanner Scanner(TimeSpan timeout) => new(_rules, timeout);

    public void Dispose()
    {
        if (_rules != IntPtr.Zero) YaraX.yrx_rules_destroy(_rules);
        _rules = IntPtr.Zero;
    }
}

/// <summary>Scans buffers or files with compiled rules and returns the rules that matched, in the order they matched.</summary>
internal sealed class YaraScanner : IDisposable
{
    private IntPtr _scanner;
    private readonly List<YaraRuleMatch> _found = [];
    // Kept as fields so the collector cannot free them while native code holds the pointers.
    private readonly YaraX.RuleCallback _onRule;

    public YaraScanner(IntPtr rules, TimeSpan timeout)
    {
        if (YaraX.yrx_scanner_create(rules, out _scanner) != YaraX.Success)
            throw new ToolError(ErrorCode.Failed, $"YARA-X could not create a scanner: {YaraX.LastError()}");
        // Whole seconds and best effort; the worker op's own time limit is the hard one.
        YaraX.Check(YaraX.yrx_scanner_set_timeout(_scanner, (ulong)Math.Max(1, Math.Ceiling(timeout.TotalSeconds))), "set the scan timeout");
        YaraX.Check(YaraX.yrx_scanner_max_matches_per_pattern(_scanner, YaraRules.MaxMatchesPerPattern), "bound the matches");
        _onRule = (rule, _) => _found.Add(Describe(rule));
        YaraX.Check(YaraX.yrx_scanner_on_matching_rule(_scanner, _onRule, IntPtr.Zero), "set the match callback");
    }

    /// <summary>The rules matching <paramref name="data"/>; a timeout throws one naming the limit.</summary>
    public List<YaraRuleMatch> Scan(byte[] data, int length) => Run(() => YaraX.yrx_scanner_scan(_scanner, data, (nuint)length));

    /// <summary>The rules matching the file at <paramref name="path"/> (read by the library, mapped where it can).</summary>
    public List<YaraRuleMatch> ScanFile(string path) => Run(() => YaraX.yrx_scanner_scan_file(_scanner, YaraX.Utf8(path)));

    /// <summary>Adds bytes at <paramref name="address"/> to a block scan; afterwards this scanner serves block scans only.</summary>
    public void ScanBlock(ulong address, byte[] data, int length) => Check(YaraX.yrx_scanner_scan_block(_scanner, (nuint)address, data, (nuint)length));

    /// <summary>The rules matching the blocks added since the last finish, their pattern offsets as block addresses.</summary>
    public List<YaraRuleMatch> Finish() => Run(() => YaraX.yrx_scanner_finish(_scanner));

    private List<YaraRuleMatch> Run(Func<int> scan)
    {
        _found.Clear();
        Check(scan());
        return [.. _found];
    }

    private static void Check(int result)
    {
        if (result == YaraX.ScanTimeout) throw new ToolError(ErrorCode.Timeout, "YARA-X stopped the scan at its time limit.");
        if (result != YaraX.Success) throw new ToolError(ErrorCode.Failed, $"YARA-X scan failed: {YaraX.LastError()}");
    }

    private static YaraRuleMatch Describe(IntPtr rule)
    {
        YaraX.Check(YaraX.yrx_rule_namespace(rule, out var ns, out var nsLength), "read a rule's namespace");
        YaraX.Check(YaraX.yrx_rule_identifier(rule, out var id, out var idLength), "read a rule's name");
        var tags = new List<string>();
        YaraX.Check(YaraX.yrx_rule_iter_tags(rule, (tag, _) => tags.Add(Marshal.PtrToStringUTF8(tag) ?? ""), IntPtr.Zero), "read a rule's tags");
        var meta = new List<KeyValuePair<string, string>>();
        // A rule without metadata answers NO_METADATA, which is not a failure.
        _ = YaraX.yrx_rule_iter_metadata(rule, (in YaraX.Metadata m, IntPtr _) => meta.Add(new(Marshal.PtrToStringUTF8(m.Identifier) ?? "", Value(m))), IntPtr.Zero);
        var patterns = new List<YaraPatternMatch>();
        YaraX.Check(YaraX.yrx_rule_iter_patterns(rule, (pattern, _) =>
        {
            YaraX.Check(YaraX.yrx_pattern_identifier(pattern, out var p, out var pLength), "read a pattern's name");
            var name = YaraX.Text(p, pLength);
            YaraX.Check(YaraX.yrx_pattern_iter_matches(pattern, (in YaraX.Match m, IntPtr _) => patterns.Add(new(name, (long)m.Offset, (long)m.Length)), IntPtr.Zero),
                "read a pattern's matches");
        }, IntPtr.Zero), "read a rule's patterns");
        return new YaraRuleMatch(YaraX.Text(ns, nsLength), YaraX.Text(id, idLength), tags, meta, patterns);
    }

    private static string Value(in YaraX.Metadata m) => m.Type switch
    {
        YaraX.MetadataType.I64 => ((long)m.Value0).ToString(System.Globalization.CultureInfo.InvariantCulture),
        YaraX.MetadataType.F64 => BitConverter.Int64BitsToDouble((long)m.Value0).ToString(System.Globalization.CultureInfo.InvariantCulture),
        YaraX.MetadataType.Boolean => ((long)m.Value0 & 0xFF) != 0 ? "true" : "false",
        YaraX.MetadataType.String => Marshal.PtrToStringUTF8(m.Value0) ?? "",
        // Bytes: (length, data); shown as text when they are valid UTF-8.
        _ => Bytes(m.Value1, (int)(long)m.Value0),
    };

    private static string Bytes(IntPtr data, int length)
    {
        var bytes = new byte[length];
        if (length > 0) Marshal.Copy(data, bytes, 0, length);
        try { return new UTF8Encoding(false, true).GetString(bytes); }
        catch (DecoderFallbackException) { return Convert.ToHexString(bytes); }
    }

    public void Dispose()
    {
        if (_scanner != IntPtr.Zero) YaraX.yrx_scanner_destroy(_scanner);
        _scanner = IntPtr.Zero;
    }
}
