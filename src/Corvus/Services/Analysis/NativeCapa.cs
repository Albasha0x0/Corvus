using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Worker;

namespace Corvus.Services.Analysis;

/// <summary>A matched capa rule; Addresses are function starts (VA or .NET token) or match addresses, empty for a file-scope rule.</summary>
public sealed record CapaLabel(string Name, string? Namespace, string Scope, IReadOnlyList<string> Attack, IReadOnlyList<string> Mbc,
    IReadOnlyList<ulong> Addresses);

/// <summary>
/// capa's labels for a file; State is matched, not checked, unknown, running or cancelled, and Notes say why.
/// Tested is false when capa is not <see cref="NativeCapa.TestedVersion"/>.
/// </summary>
public sealed record CapaReport(string State, string? Checker, bool Tested, string? Format, IReadOnlyList<CapaLabel> Labels, IReadOnlyList<string> Notes)
{
    /// <summary>The image base capa loaded a PE or ELF file at; null for .NET and when the document states none.</summary>
    public ulong? BaseAddress { get; init; }

    /// <summary><paramref name="va"/> moved from capa's image base to <paramref name="imageBase"/>; unchanged when capa stated none.</summary>
    public ulong Rebase(ulong va, ulong imageBase) => BaseAddress is { } b ? va - b + imageBase : va;
}

/// <summary>Runs capa in the worker host, one run per file; matched reports are kept on disk per path, size and write time.</summary>
internal sealed partial class NativeCapa : IWorkerOps
{
    public const string AnalyzeOp = "capa_analyze";

    /// <summary>The worker kind capa runs in, apart from the file reads so a long analysis holds none of them up.</summary>
    public const string WorkerKind = "capa";

    /// <summary>The capa version whose result document this reader was checked against.</summary>
    public const string TestedVersion = "10.0.0";

    /// <summary>The state of a report capa did not produce: not set up, or a format it does not read.</summary>
    public const string NotChecked = "not checked";

    private const long MaxOutput = 256L * 1024 * 1024;

    /// <summary>Reports kept on disk; the oldest are evicted past this.</summary>
    internal const int MaxReports = 256;

    /// <summary>The state of a run that was stopped by a cancel call.</summary>
    public const string Cancelled = "cancelled";

    /// <summary>The state of a run that has not ended; the notes give the elapsed time and the next call.</summary>
    public const string Running = "running";

    /// <summary>Server and worker read and write the report with these options.</summary>
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public IReadOnlyDictionary<string, WorkerOp> Ops => new Dictionary<string, WorkerOp> { [AnalyzeOp] = AnalyzeInWorker };

    /// <summary>Tests: replaces the capa run itself, in the flow that sets it.</summary>
    internal static readonly AsyncLocal<Func<string, StallRule, CancellationToken, CapaReport>?> RunOverride = new();

    /// <summary>Tests: the folder of the kept reports and the estimate history, in the flow that sets it.</summary>
    internal static readonly AsyncLocal<string?> RootOverride = new();

    private static string Root => RootOverride.Value ?? AnalysisCache.DefaultRoot;

    private static string Folder => System.IO.Path.Combine(Root, "capa");

    /// <summary>The engine name of capa's runs in the estimate history.</summary>
    private const string EstimateName = "capa";

    private static readonly ServerOptions Detached = new();

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<CallJoin, System.Collections.Concurrent.ConcurrentDictionary<string, CapaRun>> RunTables = new();

    /// <summary>Running capa runs by file key for one join table, for the estimate, the stall rule and the waiting callers.</summary>
    private static System.Collections.Concurrent.ConcurrentDictionary<string, CapaRun> RunsOf(CallJoin joins) =>
        RunTables.GetValue(joins, _ => new(StringComparer.Ordinal));

    private sealed class CapaRun
    {
        public DateTime Started = DateTime.UtcNow;
        public OpenEstimate.Estimate Expected;
        public long Length;
        public StallRule? Rule;
        public readonly CancellationTokenSource Halt = new();
        public readonly TaskCompletionSource Done = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public CapaReport? Outcome;
        public int Waiting, Notified;
    }

    /// <summary>Tests: the task that ends with the run on <paramref name="path"/>; null when none is going.</summary>
    internal static Task? Ending(string path, AssemblyWorkspace? workspace) =>
        RunsOf(CallJoin.For(workspace?.Options ?? Detached)).TryGetValue(Key(path) ?? System.IO.Path.GetFullPath(path), out var run) ? run.Done.Task : null;

    internal static string EntryPath(string key) =>
        System.IO.Path.Combine(Folder, Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(key))) + ".json");

    private sealed record Kept(string Key, CapaReport Report);

    /// <summary>The report kept for the file at <paramref name="path"/> as it is now; null when none is kept or the entry is unreadable.</summary>
    public static CapaReport? Cached(string path)
    {
        var key = Key(path);
        if (key == null) return null;
        try
        {
            var entry = EntryPath(key);
            return File.Exists(entry) && JsonSerializer.Deserialize<Kept>(File.ReadAllBytes(entry), Json) is { } kept && kept.Key == key ? kept.Report : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { return null; }
    }

    /// <summary>Keeps a matched report on disk and evicts the oldest entries past <paramref name="capacity"/>; a failed write is skipped.</summary>
    internal static void Keep(string key, CapaReport report, int capacity = MaxReports)
    {
        try
        {
            PrivateFolder.Create(Folder);
            SafeFile.WritePrivate(EntryPath(key), JsonSerializer.SerializeToUtf8Bytes(new Kept(key, report), Json), overwrite: true);
            var files = new DirectoryInfo(Folder).GetFiles("*.json").OrderBy(f => f.LastWriteTimeUtc).ToList();
            foreach (var old in files.Take(Math.Max(0, files.Count - capacity)))
                try { old.Delete(); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>
    /// capa's labels for the file; one run per file starts if none is going and outlives the call, a repeat joins it.
    /// A null <paramref name="wait"/> waits for the end; past a wait the state is running and <paramref name="workspace"/> gets the end as a notice.
    /// Without capa the state is not checked, and an unreadable path is unknown.
    /// </summary>
    public static CapaReport Analyze(string path, TimeSpan? wait, CancellationToken ct, AssemblyWorkspace? workspace)
    {
        if (Cached(path) is { } hit) return hit;
        var probe = ExternalTools.Probe(ExternalTools.Capa);
        if (!probe.Usable) return new(NotChecked, null, false, null, [], [$"capa {probe.Problem}; {probe.Remediation}"]);
        var full = System.IO.Path.GetFullPath(path);
        var key = Key(path) ?? full;
        var options = workspace?.Options ?? Detached;
        var joins = CallJoin.For(options);
        var runs = RunsOf(joins);
        var started = new CapaRun();
        var over = RunOverride.Value;
        var joined = joins.Run("capa:" + key, _ =>
        {
            Begin(started, full, TimeSpan.FromSeconds(options.StallSeconds));
            runs[key] = started;
            return Task.Run(() => Execute(runs, key, started, full, probe, over), CancellationToken.None);
        }, CancellationToken.None, r => r);
        var run = joined.WasRunning && runs.TryGetValue(key, out var existing) ? existing : started;
        Interlocked.Increment(ref run.Waiting);
        var left = false;
        try
        {
            if (wait is not { } limit) joined.Work.Wait(ct);
            else if (!joined.Work.Wait((int)Math.Min(limit.TotalMilliseconds, int.MaxValue), ct)) return Leave();
            return joined.Result.Result;
        }
        catch (OperationCanceledException)
        {
            Leave();
            throw;
        }
        finally
        {
            if (!left) Interlocked.Decrement(ref run.Waiting);
        }

        // Leave the wait first, then register, so an end in between still finds this caller gone.
        CapaReport Leave()
        {
            left = true;
            Interlocked.Decrement(ref run.Waiting);
            if (workspace != null)
                _ = joined.Work.ContinueWith(_ => NotifyEnd(run, full, workspace), CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            return Waiting(run, full);
        }
    }

    /// <summary>Stops the run on the file at <paramref name="path"/>; state cancelled, running if it is still stopping, null when none is going.</summary>
    public static CapaReport? Cancel(string path, AssemblyWorkspace? workspace)
    {
        var full = System.IO.Path.GetFullPath(path);
        if (!RunsOf(CallJoin.For(workspace?.Options ?? Detached)).TryGetValue(Key(path) ?? full, out var run)) return null;
        // The cancel is answered here, so the end sends no notice.
        Interlocked.Exchange(ref run.Notified, 1);
        run.Halt.Cancel();
        // The run ends within a poll of the cancel; a worker is cancelled through its pipe.
        return run.Done.Task.Wait(TimeSpan.FromSeconds(10)) ? run.Outcome : Waiting(run, full);
    }

    private static void Begin(CapaRun run, string path, TimeSpan window)
    {
        // The history is advisory, so a failure here never fails the run.
        try
        {
            run.Length = new FileInfo(path).Length;
            run.Expected = new OpenEstimate(Root).Seconds(EstimateName, run.Length);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        run.Started = DateTime.UtcNow;
        run.Rule = new StallRule(window);
    }

    private static CapaReport Execute(System.Collections.Concurrent.ConcurrentDictionary<string, CapaRun> runs, string key, CapaRun run, string path,
        ExternalToolProbe probe, Func<string, StallRule, CancellationToken, CapaReport>? over)
    {
        var version = probe.Version?.Split(' ', StringSplitOptions.RemoveEmptyEntries).LastOrDefault();
        CapaReport report;
        try
        {
            report = over != null ? over(path, run.Rule!, run.Halt.Token) : RunOnce(probe.Path!, path, version, run.Rule!, run.Halt.Token);
            // A completed report survives a cancel that came after it; a run cut short by the cancel is cancelled.
            if (run.Halt.IsCancellationRequested && report.State != "matched") throw new OperationCanceledException();
        }
        catch (OperationCanceledException)
        {
            report = new(Cancelled, Checker(version), version == TestedVersion, null, [], ["capa was stopped by a cancel call"]);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            report = Unknown(Checker(version), version, $"capa was not run to the end: {ex.Message}");
        }
        if (report.State == "matched")
        {
            Keep(key, report);
            try { new OpenEstimate(Root).Record(EstimateName, run.Length, (DateTime.UtcNow - run.Started).TotalSeconds); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        run.Outcome = report;
        runs.TryRemove(new KeyValuePair<string, CapaRun>(key, run));
        run.Done.TrySetResult();
        return report;
    }

    private static CapaReport RunOnce(string capa, string path, string? version, StallRule rule, CancellationToken ct)
    {
        if (!WorkerPool.Shared.Enabled) return Run(capa, path, version, rule, ct);
        var args = new JsonObject { ["capa"] = capa, ["path"] = path, ["version"] = version };
        try
        {
            var answer = WorkerPool.Shared.RunAsync(WorkerKind, AnalyzeOp, args, Timeout.InfiniteTimeSpan, ct, path, rule.Window).GetAwaiter().GetResult();
            return answer.Deserialize<CapaReport>(Json) ?? Unknown(Checker(version), version, "the capa worker answered without a result");
        }
        catch (ToolError e) when (e.Code is ErrorCode.ProviderUnavailable or ErrorCode.LimitExceeded or ErrorCode.Timeout)
        {
            var again = e.Message.Contains(StallRule.MessagePrefix, StringComparison.Ordinal)
                ? $"; repeat the call to run it again, or raise {ServerOptions.StallWindowVariable} (seconds without progress)" : "";
            return Unknown(Checker(version), version, $"capa was not run to the end: {e.Message}{again}");
        }
    }

    /// <summary>The state running with the time spent, the estimate and its basis, and the calls that wait for the end or stop it.</summary>
    private static CapaReport Waiting(CapaRun run, string path)
    {
        var seconds = (DateTime.UtcNow - run.Started).TotalSeconds;
        var minutes = Math.Max(1, (int)Math.Ceiling(run.Expected.Seconds / 60));
        var call = $"survey_features path={path} category=capa";
        var window = run.Rule?.Window ?? ServerOptions.StallWindow();
        return new(Running, null, false, null, [],
        [
            $"capa running {seconds:0} s, about {minutes} min ({run.Expected.Basis}); it ends on completion, exit, cancel or after {window.TotalSeconds:0} s without progress",
            $"next: {call} waitSeconds=60 waits for the end; {call} cancel=true stops it",
        ]);
    }

    /// <summary>Queues the end of a run once; none while a caller still waits and gets the result, none after a cancel call.</summary>
    private static void NotifyEnd(CapaRun run, string path, AssemblyWorkspace workspace)
    {
        if (Volatile.Read(ref run.Waiting) > 0 || Interlocked.Exchange(ref run.Notified, 1) != 0) return;
        var report = run.Outcome!;
        var name = $"capa {System.IO.Path.GetFileName(path)}";
        var seconds = (DateTime.UtcNow - run.Started).TotalSeconds;
        var call = $"survey_features path={path} category=capa";
        var why = Format.Clip(report.Notes.FirstOrDefault()?.Split('\n')[0] ?? "no reason reported", 200);
        workspace.Notify(report.State switch
        {
            "matched" => $"{name} complete in {seconds:0} s; next: {call} lists its {report.Labels.Count} labels",
            Cancelled => $"{name} cancelled after {seconds:0} s; next: {call} runs it again",
            NotChecked => $"{name} not checked ({why}); next: {call} shows the reason",
            _ => $"{name} failed ({why}); next: {call} runs it again",
        });
    }

    private static Task<JsonNode?> AnalyzeInWorker(JsonObject args, CancellationToken ct)
    {
        string Arg(string name) => args[name]?.GetValueKind() == JsonValueKind.String && args[name]!.GetValue<string>() is { Length: > 0 } value
            ? value : throw new ToolError(ErrorCode.InvalidArgument, $"{AnalyzeOp} needs '{name}'.");
        var version = args["version"]?.GetValueKind() == JsonValueKind.String ? args["version"]!.GetValue<string>() : null;
        return Task.FromResult(JsonSerializer.SerializeToNode(Run(Arg("capa"), Arg("path"), version, null, ct), Json));
    }

    /// <summary>Runs capa on a private copy; a null <paramref name="rule"/> leaves the stall to the worker request that holds the run.</summary>
    private static CapaReport Run(string capa, string path, string? version, StallRule? rule, CancellationToken ct)
    {
        // vivisect, capa's backend, loads and saves a workspace file beside its input: a copy in a fresh private folder gives it the file alone.
        var dir = Native.Providers.PrivateFolder.Temp("capa", $"{Environment.ProcessId}-{Guid.NewGuid():N}");
        try
        {
            PrivateFolder.Create(dir);
            var copy = System.IO.Path.Combine(dir, System.IO.Path.GetFileName(path));
            File.Copy(path, copy);
            var run = ExternalTools.Run(capa, ExternalTools.Arguments(ExternalTools.Capa, "analyze", ("file", copy)), Timeout.InfiniteTimeSpan, MaxOutput, ct, UserName,
                watch: rule != null ? new(rule) : null);
            return Read(run, Checker(version), version == TestedVersion, rule?.Window);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Unknown(Checker(version), version, $"capa was not run: {ex.Message}");
        }
        finally
        {
            try { Directory.Delete(dir, true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    // capa 10.0.0's vivisect calls getpass.getuser(), which needs USERNAME on Windows; a neutral name hides the user's.
    private static readonly Dictionary<string, string?> UserName = new() { ["USERNAME"] = "capa" };

    private static string Checker(string? version) => $"capa {version ?? "(version unknown)"}";

    private static CapaReport Unknown(string checker, string? version, string why) =>
        new("unknown", checker, version == TestedVersion, null, [], [version == TestedVersion ? why : $"{why}; the result format was checked with capa {TestedVersion}"]);

    /// <summary>The file's identity for the kept reports: full path, size and write time; null when it cannot be read.</summary>
    internal static string? Key(string path)
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

    /// <summary>Labels from capa's JSON document as capa's report lists them; internal/limitation rules become notes. A stall names <paramref name="window"/>.</summary>
    internal static CapaReport Read(ExternalTools.RunResult run, string checker, bool tested, TimeSpan? window = null)
    {
        string Untested(string note) => tested ? note : $"{note}; the result format was checked with capa {TestedVersion}";
        if (run.StartError == null && run.StalledAt == null && run.ExitCode is { } code && UnreadFormat.Contains(code))
            return new(NotChecked, checker, tested, null, [], [$"capa does not read this file (exit {code}: {Message(run.Stderr)})"]);
        if (run.StartError != null || run.StalledAt != null || run.Truncated || run.ExitCode != 0)
        {
            var why = run.StartError ?? (run.StalledAt is { } reached
                ? $"no output for {(window ?? ServerOptions.StallWindow()).TotalSeconds:0.###} s and under 1% of a core after {reached:N0} bytes; repeat the call to run it again, or raise {ServerOptions.StallWindowVariable} (seconds without progress)"
                : run.Truncated ? $"a result over {MaxOutput >> 20} MiB"
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

    /// <summary>The function of the last block starting at or before <paramref name="at"/>; null when none does.</summary>
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

    /// <summary>capa's first logged message in <paramref name="stderr"/>, else its last line; at most 500 characters.</summary>
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
