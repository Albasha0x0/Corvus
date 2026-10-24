using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Worker;

namespace Corvus.Services.Analysis;

/// <summary>
/// A capa rule that matched: its name and namespace, its static scope (file, function, basic block, instruction), its
/// ATT&amp;CK and MBC labels as capa prints them ("Execution::Command and Scripting Interpreter [T1059]"), and where it
/// matched: function starts (VAs; .NET method tokens), or the match address where capa's layout names no function.
/// Addresses is empty for a rule matched at no address (a file-scope rule).
/// </summary>
public sealed record CapaLabel(string Name, string? Namespace, string Scope, IReadOnlyList<string> Attack, IReadOnlyList<string> Mbc,
    IReadOnlyList<ulong> Addresses);

/// <summary>
/// capa's labels for a PE, ELF or .NET file. State is "matched" (capa read the file; Labels may be empty), "not checked"
/// (capa is not set up, or does not read the file's format) or "unknown" (capa failed or its result could not be read);
/// Notes say why and name capa's own file limitations. Format is capa's name for the file's format (pe, elf, dotnet);
/// Tested is false when the capa that ran is not <see cref="NativeCapa.TestedVersion"/>.
/// </summary>
public sealed record CapaReport(string State, string? Checker, bool Tested, string? Format, IReadOnlyList<CapaLabel> Labels, IReadOnlyList<string> Notes)
{
    /// <summary>The image base capa loaded a PE or ELF file at; null for .NET and when the document states none.</summary>
    public ulong? BaseAddress { get; init; }

    /// <summary><paramref name="va"/> moved from capa's image base to <paramref name="imageBase"/>; unchanged when capa stated none.</summary>
    public ulong Rebase(ulong va, ulong imageBase) => BaseAddress is { } b ? va - b + imageBase : va;
}

/// <summary>
/// capa's behaviour labels of a whole file, from the standalone capa (<see cref="ExternalTools.Capa"/>) run in the worker
/// host. Reports are kept per file (path, size and write time) for the server's lifetime, so a function dossier reads
/// the labels a survey already found without running capa again.
/// </summary>
internal sealed partial class NativeCapa : IWorkerOps
{
    public const string AnalyzeOp = "capa_analyze";

    /// <summary>The worker kind capa runs in, apart from the file reads so a long analysis holds none of them up.</summary>
    public const string WorkerKind = "capa";

    /// <summary>The capa version whose result document this reader was checked against.</summary>
    public const string TestedVersion = "10.0.0";

    /// <summary>The state of a report capa did not produce: not set up, or a format it does not read.</summary>
    public const string NotChecked = "not checked";

    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(30);
    private const long MaxOutput = 256L * 1024 * 1024;
    private const int MaxReports = 16;

    /// <summary>Server and worker read and write the report with these options.</summary>
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public IReadOnlyDictionary<string, WorkerOp> Ops => new Dictionary<string, WorkerOp> { [AnalyzeOp] = AnalyzeInWorker };

    private static readonly Dictionary<string, CapaReport> Reports = new(StringComparer.Ordinal);

    /// <summary>The report capa already gave for the file at <paramref name="path"/> as it is now, or null when capa has not read it.</summary>
    public static CapaReport? Cached(string path)
    {
        var key = Key(path);
        lock (Reports) return key != null && Reports.TryGetValue(key, out var hit) ? hit : null;
    }

    /// <summary>
    /// capa's labels for the PE, ELF or .NET file at <paramref name="path"/>: kept from an earlier run, else from capa run
    /// in the worker host (in this process when the host is off). Not checked when capa is not set up; unknown, with the
    /// reason, when capa or its worker failed. Only a report capa produced is kept.
    /// </summary>
    public static CapaReport Analyze(string path, CancellationToken ct)
    {
        if (Cached(path) is { } hit) return hit;
        var probe = ExternalTools.Probe(ExternalTools.Capa);
        if (!probe.Usable) return new(NotChecked, null, false, null, [], [$"capa {probe.Problem}; {probe.Remediation}"]);
        var version = probe.Version?.Split(' ', StringSplitOptions.RemoveEmptyEntries).LastOrDefault();
        var args = new JsonObject { ["capa"] = probe.Path, ["path"] = path, ["version"] = version };
        CapaReport report;
        if (WorkerPool.Shared.Enabled)
            try
            {
                // The op waits up to Timeout for capa; a minute more covers the worker's start and its reply.
                var answer = WorkerPool.Shared.RunAsync(WorkerKind, AnalyzeOp, args, Timeout + TimeSpan.FromMinutes(1), ct, path).GetAwaiter().GetResult();
                report = answer.Deserialize<CapaReport>(Json) ?? Unknown(Checker(version), version, "the capa worker answered without a result");
            }
            catch (ToolError e) when (e.Code is ErrorCode.ProviderUnavailable or ErrorCode.LimitExceeded or ErrorCode.Timeout)
            {
                report = Unknown(Checker(version), version, $"capa was not run to the end: {e.Message}");
            }
        else report = Run(probe.Path!, path, version, ct);
        if (report.State == "matched" && Key(path) is { } key)
            lock (Reports)
            {
                if (Reports.Count >= MaxReports) Reports.Clear();
                Reports[key] = report;
            }
        return report;
    }

    private static Task<JsonNode?> AnalyzeInWorker(JsonObject args, CancellationToken ct)
    {
        string Arg(string name) => args[name]?.GetValueKind() == JsonValueKind.String && args[name]!.GetValue<string>() is { Length: > 0 } value
            ? value : throw new ToolError(ErrorCode.InvalidArgument, $"{AnalyzeOp} needs '{name}'.");
        var version = args["version"]?.GetValueKind() == JsonValueKind.String ? args["version"]!.GetValue<string>() : null;
        return Task.FromResult(JsonSerializer.SerializeToNode(Run(Arg("capa"), Arg("path"), version, ct), Json));
    }

    private static CapaReport Run(string capa, string path, string? version, CancellationToken ct)
    {
        var run = ExternalTools.Run(capa, ExternalTools.Arguments(ExternalTools.Capa, "analyze", ("file", path)), Timeout, MaxOutput, ct, UserName);
        return Read(run, Checker(version), version == TestedVersion);
    }

    // capa 10.0.0's vivisect reads getpass.getuser() on import; on Windows that needs USERNAME, as Python's fallback (the
    // pwd module) does not exist there, so the minimal environment gets a neutral name rather than the user's own.
    private static readonly Dictionary<string, string?> UserName = new() { ["USERNAME"] = "capa" };

    private static string Checker(string? version) => $"capa {version ?? "(version unknown)"}";

    private static CapaReport Unknown(string checker, string? version, string why) =>
        new("unknown", checker, version == TestedVersion, null, [], [version == TestedVersion ? why : $"{why}; the result format was checked with capa {TestedVersion}"]);

    /// <summary>The file's identity for the kept reports: full path, size and write time; null when it cannot be read.</summary>
    private static string? Key(string path)
    {
        try
        {
            var info = new FileInfo(Path.GetFullPath(path));
            return info.Exists ? $"{info.FullName}|{info.Length}|{info.LastWriteTimeUtc.Ticks}" : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { return null; }
    }

    // capa's exit codes for a file it does not read: E_INVALID_FILE_TYPE, E_INVALID_FILE_ARCH and E_INVALID_FILE_OS.
    private static readonly int[] UnreadFormat = [16, 17, 18];

    /// <summary>
    /// The labels of capa's JSON result document, as capa's own report lists them: library rules, rules capa adds for a
    /// subscope, and malware-classification rules are left out, and rules under internal/limitation become notes.
    /// Block and instruction matches are mapped to their function through the blocks the document's layout lists.
    /// </summary>
    internal static CapaReport Read(ExternalTools.RunResult run, string checker, bool tested)
    {
        string Untested(string note) => tested ? note : $"{note}; the result format was checked with capa {TestedVersion}";
        if (run.StartError == null && !run.TimedOut && run.ExitCode is { } code && UnreadFormat.Contains(code))
            return new(NotChecked, checker, tested, null, [], [$"capa does not read this file (exit {code}: {Message(run.Stderr)})"]);
        if (run.StartError != null || run.TimedOut || run.Truncated || run.ExitCode != 0)
        {
            var why = run.StartError ?? (run.TimedOut ? $"no answer within {Timeout.TotalMinutes:0} min" : run.Truncated ? $"a result over {MaxOutput >> 20} MiB"
                : $"exit {run.ExitCode}: {Message(run.Stderr)}");
            return new("unknown", checker, tested, null, [], [Untested($"capa failed ({why})")]);
        }
        var labels = new List<CapaLabel>();
        var notes = new List<string>();
        string? format;
        ulong? baseAddress;
        try
        {
            using var doc = JsonDocument.Parse(run.Output, new JsonDocumentOptions { MaxDepth = 512 });
            var analysis = doc.RootElement.GetProperty("meta").GetProperty("analysis");
            format = Text(analysis, "format");
            baseAddress = analysis.TryGetProperty("base_address", out var b) && Text(b, "type") == "absolute" ? Location(b) : null;
            var functions = new HashSet<ulong>();
            var blocks = new SortedList<ulong, ulong>();
            if (analysis.TryGetProperty("layout", out var layout) && layout.TryGetProperty("functions", out var fs) && fs.ValueKind == JsonValueKind.Array)
                foreach (var f in fs.EnumerateArray())
                {
                    if (Location(f.GetProperty("address")) is not { } start) continue;
                    functions.Add(start);
                    if (f.TryGetProperty("matched_basic_blocks", out var bbs) && bbs.ValueKind == JsonValueKind.Array)
                        foreach (var bb in bbs.EnumerateArray())
                            if (Location(bb.GetProperty("address")) is { } at) blocks[at] = start;
                }
            foreach (var rule in doc.RootElement.GetProperty("rules").EnumerateObject())
            {
                var meta = rule.Value.GetProperty("meta");
                var name = Text(meta, "name") ?? rule.Name;
                var ns = Text(meta, "namespace");
                if (ns != null && ns.StartsWith("internal/limitation/", StringComparison.Ordinal))
                {
                    notes.Add($"capa file limitation: {name}");
                    continue;
                }
                if (Flag(meta, "lib") || Flag(meta, "is_subscope_rule") || Classifies(meta)) continue;
                var addresses = new SortedSet<ulong>();
                foreach (var m in rule.Value.GetProperty("matches").EnumerateArray())
                    if (m.ValueKind == JsonValueKind.Array && m.GetArrayLength() > 0 && Location(m[0]) is { } at)
                        addresses.Add(functions.Contains(at) ? at : format == "dotnet" ? at : Containing(blocks, at) ?? at);
                var scope = meta.TryGetProperty("scopes", out var scopes) && Text(scopes, "static") is { } s ? s : "unknown";
                labels.Add(new CapaLabel(name, ns, scope, Specs(meta, "attack", "tactic", "technique", "subtechnique"),
                    Specs(meta, "mbc", "objective", "behavior", "method"), [.. addresses]));
            }
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
        {
            return new("unknown", checker, tested, null, [], [Untested($"capa's result could not be read ({ex.Message})")]);
        }
        if (!tested) notes.Add(Untested($"{checker} ran"));
        return new("matched", checker, tested, format,
            [.. labels.OrderBy(l => l.Namespace, StringComparer.Ordinal).ThenBy(l => l.Name, StringComparer.Ordinal)], notes) { BaseAddress = baseAddress };
    }

    /// <summary>
    /// The function of the block that starts at or last before <paramref name="at"/>; null when none does. capa's layout
    /// lists the block of every block and instruction match, so the last block start at or before a match holds it.
    /// </summary>
    private static ulong? Containing(SortedList<ulong, ulong> blocks, ulong at)
    {
        var starts = blocks.Keys;
        int lo = 0, hi = starts.Count - 1;
        ulong? found = null;
        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;
            if (starts[mid] <= at) { found = blocks.Values[mid]; lo = mid + 1; }
            else hi = mid - 1;
        }
        return found;
    }

    /// <summary>The address a match or layout entry names: absolute VA, file offset, or .NET method token; null for no address.</summary>
    private static ulong? Location(JsonElement address)
    {
        if (address.ValueKind != JsonValueKind.Object || !address.TryGetProperty("value", out var v)) return null;
        return Text(address, "type") switch
        {
            "absolute" or "relative" or "file" or "dn_token" when v.ValueKind == JsonValueKind.Number => v.GetUInt64(),
            // Token and IL offset: the match is inside the method with that token.
            "dn_token_offset" when v.ValueKind == JsonValueKind.Array && v.GetArrayLength() > 0 => v[0].GetUInt64(),
            _ => null,
        };
    }

    /// <summary>ATT&amp;CK or MBC entries as capa prints them: the parts joined by "::", then the id in brackets.</summary>
    private static List<string> Specs(JsonElement meta, string property, params string[] parts)
    {
        var list = new List<string>();
        if (!meta.TryGetProperty(property, out var specs) || specs.ValueKind != JsonValueKind.Array) return list;
        foreach (var spec in specs.EnumerateArray())
        {
            var text = string.Join("::", parts.Select(p => Text(spec, p)).Where(p => !string.IsNullOrEmpty(p)));
            list.Add(Text(spec, "id") is { Length: > 0 } id ? $"{text} [{id}]" : text);
        }
        return list;
    }

    /// <summary>A rule that states an analysis conclusion or malware family or category, which capa's own report leaves out.</summary>
    private static bool Classifies(JsonElement meta) =>
        meta.TryGetProperty("maec", out var maec) && maec.ValueKind == JsonValueKind.Object
        && maec.EnumerateObject().Any(p => p.Value.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined));

    private static bool Flag(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;

    private static string? Text(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    /// <summary>
    /// capa's first logged message in <paramref name="stderr"/>, its wrapped lines joined and source locations and rules
    /// dropped, else the last line; at most 500 characters.
    /// </summary>
    internal static string Message(string stderr)
    {
        var lines = stderr.ReplaceLineEndings("\n").Split('\n');
        var messages = new List<StringBuilder>();
        foreach (var raw in lines)
        {
            var line = Decoration().Replace(raw, "").Trim();
            if (LogLevel().Match(line) is { Success: true } m) messages.Add(new StringBuilder(line[m.Length..].Trim()));
            else if (messages.Count > 0 && line.Length > 0) messages[^1].Append(' ').Append(line);
        }
        var text = messages.Select(b => b.ToString().Trim()).FirstOrDefault(t => t.Any(char.IsLetter))
                   ?? lines.Select(l => l.Trim()).LastOrDefault(l => l.Length > 0) ?? "no message";
        return text[..Math.Min(text.Length, 500)];
    }

    [GeneratedRegex(@"^(ERROR|WARNING|INFO|DEBUG|CRITICAL)\s+capa[\w.]*:")]
    private static partial Regex LogLevel();

    // capa logs through rich: each line ends with its Python source location, and messages are framed by rules of dashes.
    [GeneratedRegex(@"\s+\S+\.py:\d+\s*$|-{5,}")]
    private static partial Regex Decoration();
}
