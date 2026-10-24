using System.ComponentModel;
using System.Runtime.CompilerServices;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class SessionTools(AssemblyWorkspace workspace, IndexingService indexing, ServerOptions options, ResultStore results,
    NativeEngineService? engines = null, NotesService? notes = null, LiveSessionService? live = null)
{
    public sealed record Capability(string Name, bool Available, string Detail, string? Remediation);

    public sealed record Toolset(string Name, bool Enabled, bool InCore, int Tools, string Description);

    public sealed record Client(string Name, string? Version);

    public sealed record NoteCounts(int Open, int Total, string Store);

    /// <summary>Unavailable tools sharing one reason and fix; a tool's entry names its mode when only that mode is affected.</summary>
    public sealed record UnavailableGroup(IReadOnlyList<string> Tools, string Reason, string? Remediation);

    [Description("The --tools-file list in effect and its tool count; the --trace / CORVUS_TRACE file.")]
    public sealed record CatalogFilter(string? ToolsFile, int? ToolsFileTools, string? TraceFile);

    public sealed record EngineSession(string Image, string Engine, int? WorkerPid,
        [property: Description("opening, idle, busy or closed.")] string State,
        [property: Description("The request running (or open/restart), its seconds and the worker's last stage.")] string? BusyOp, double BusySeconds, string? Stage,
        [property: Description("Requests waiting for this session.")] int Queued,
        [property: Description("Unsaved edits a restart would replay.")] int Unsaved,
        int Restarts, string? Database, bool ReusedDatabase,
        [property: Description("no auto-analysis, or a read-only snapshot of a database another process holds.")] string? Note)
    {
        [Description("running, complete or partial (the analysis budget ran out).")] public string? Analysis { get; init; }
    }

    [Description("Seconds per engine request (CORVUS_ENGINE_REQUEST_TIMEOUT) and open (CORVUS_ENGINE_OPEN_TIMEOUT).")]
    public sealed record EngineLimits(int RequestSeconds, int OpenSeconds);

    public sealed record ServerStatus(string Server, string Version,
        [property: Description("Version, plus +<commit> when known.")]
        string InformationalVersion,
        [property: Description("The running server program.")]
        string Executable,
        [property: Description("Whether Executable is expectedExecutable (links followed); null if not given.")]
        bool? ExecutableMatches,
        [property: Description("script, dotnet-tool, dnx, winget, scoop, homebrew or source.")]
        string InstallKind,
        DateTimeOffset StartedAt, long UptimeSeconds,
        [property: Description("The MCP protocol version negotiated with this client.")]
        string? ProtocolVersion,
        [property: Description("The client's name and version from its initialize request.")]
        Client? Client,
        [property: Description("Digest of the tool and prompt catalog: t<tools>-<hash>.p<prompts>-<hash>.")]
        string CatalogDigest,
        [property: Description("Whether CatalogDigest equals expectedCatalogDigest; null when none was given.")]
        bool? CatalogMatches,
        [property: Description("On a mismatch, what differs (tool or prompt counts, or definitions); else null.")]
        string? CatalogDifference,
        int Tools, int LoadedAssemblies, string BackgroundIndexing,
        long WorkingSetMB, IReadOnlyList<Capability> Capabilities,
        [property: Description("Tools that can take over 10 s on large inputs.")]
        IReadOnlyList<string> LongRunningTools,
        [property: Description("Tool families and whether registered; all unless --toolsets or CORVUS_TOOLSETS limits them.")]
        IReadOnlyList<Toolset> Toolsets,
        [property: Description("Registered tools or modes (engine=ida) that cannot work here: one row per reason and fix.")]
        IReadOnlyList<UnavailableGroup> UnavailableTools,
        [property: Description("Notes in the per-user store (record_note): open, total, store directory.")]
        NoteCounts? Notes,
        EngineLimits EngineTimeLimits,
        IReadOnlyList<EngineSession> EngineSessions,
        CatalogFilter ToolsFileAndTrace,
        [property: Description("budget, results (kept-result store), caches, calls (leftover calls, lock holders), workers (child PIDs), run.")]
        IReadOnlyList<StatusSection> Sections);

    [McpServerTool(Name = "server_status", Title = "Server status", UseStructuredContent = true)]
    [Description("Which server runs (version, program, install kind, client), catalog digest, what is loaded, limits, long-running tools, " +
                 "capabilities with fixes, tool families, unusable tools, engine sessions. expectedCatalogDigest detects a stale server; " +
                 "expectedExecutable checks the registered copy.")]
    public ServerStatus GetServerStatus(
        [Description("Catalog digest to compare (t92-0123456789ab.p5-01234567).")] string? expectedCatalogDigest = null,
        [Description("Registered server path, compared with the running one.")] string? expectedExecutable = null,
        RequestContext<CallToolRequestParams> context = null!)
    {
        var server = context?.Server?.ServerOptions;
        var digest = context?.Server is { } listed ? ToolListCache.Digest(listed) : "";
        bool expected = !string.IsNullOrWhiteSpace(expectedCatalogDigest);
        var difference = expected ? Catalog.Difference(expectedCatalogDigest!, digest) : null;
        int toolCount = server?.ToolCollection?.Count ?? 0;

        List<Capability> capabilities =
        [
            new(".NET decompilation, search, navigation, editing", true, "built in", null),
            ReferencePacks.Offline
                ? new("reference pack download", false, "CORVUS_OFFLINE is set: assemblies targeting an uninstalled .NET version resolve fewer references", "unset CORVUS_OFFLINE")
                : new("reference pack download", true, "on demand for an uninstalled framework, SHA-512 checked" +
                    (ReferencePacks.LastProblem is { } problem ? $"; last: {problem}" : ""), null),
        ];
        capabilities.Add(new("native PE analysis", true, "built in", null));
        // The engines are checked beside the external programs, each check in parallel (see ExternalToolCapabilities).
        var deadline = DateTime.UtcNow + Native.Providers.ExternalTools.StatusWait;
        var external = OwnThread(() => ExternalToolCapabilities(Native.Providers.ExternalTools.StatusWait).ToList());
        // The sections' own waits (cache folder counts) run beside the checks rather than after them.
        var sections = context?.Services is { } services ? OwnThread(() => StatusSections.Collect(services)) : null;
        var providers = engines?.Providers ?? [];
        var checks = providers.Select(provider => OwnThread(provider.CheckAvailability)).ToList();
        var availability = new List<Native.Providers.ProviderAvailability>();
        foreach (var (provider, check) in providers.Zip(checks))
        {
            if (!Settle(check, deadline))
            {
                // Unknown is not absent: the engine's tools stay listed while its check runs on.
                availability.Add(Native.Providers.ProviderAvailability.Ok(provider.Id, new Dictionary<string, string>()));
                capabilities.Add(new($"native decompilation ({provider.DisplayName})", true, Pending, null));
                continue;
            }
            var a = check.GetAwaiter().GetResult();
            availability.Add(a);
            capabilities.Add(new($"native decompilation ({provider.DisplayName})", a.IsAvailable,
                a.IsAvailable ? string.Join(", ", a.Details.Select(d => $"{d.Key} {d.Value}")) : a.Reason ?? "unavailable", a.Remediation));
        }
        if (engines?.Prewarming is { } p)
            capabilities.Add(p.Enabled
                ? new("engine background analysis on load", true,
                    $"on ({p.Engine}): {(p.Running != null ? $"analyzing {p.Running} ({p.RunningSeconds:0} s)" : "idle")}, {p.Queued} queued, {p.Done} done, {p.Failed} failed, {p.Cancelled} cancelled" +
                    (p.LastError != null ? $"; last error: {Bounded(p.LastError, 160)}" : ""), null)
                : new("engine background analysis on load", false, "off: a first engine call waits for the analysis",
                    $"--prewarm ida|ghidra|auto (or {ServerOptions.PrewarmVariable})"));
        capabilities.Add(new("native engine preference", true,
            options.Engine switch
            {
                EngineMode.Ours => "default ours: the built-in index",
                EngineMode.Ida => "default ida: IDA's analysis, started or waited for",
                EngineMode.Ghidra => "default ghidra: Ghidra's analysis, started or waited for",
                _ => "default auto: IDA, then Ghidra, whichever analyzed the image, else the built-in index",
            } + $"; set by --engine (or {ServerOptions.EngineVariable}), per call by engine=", null));
        capabilities.AddRange(external.GetAwaiter().GetResult());
        if (options.AllowLive)
            capabilities.Add(options.LiveAllow.Count > 0
                ? new("programs sessions may open", true, "limited to: " + string.Join(", ", options.LiveAllow), null)
                : new("programs sessions may open", true, "any program the session switches allow",
                    $"limit them with {ServerOptions.LiveAllowOption} <program or folder> (repeatable)"));
        if (options.AllowLive && live?.Backend is { } backend) capabilities.Add(LiveBackendCapability(backend));
        // listed only when on: status is at its report budget, and a refused save names the switch
        if (options.AllowReplaceOriginal)
            capabilities.Add(new("saves that replace the loaded file", true, "on: save_assembly and save_native take replaceOriginal=true (a .bak is kept)", null));
        int loaded = workspace.LoadedCount; // without the lock: status answers while a long call holds it
        var registered = (server?.ToolCollection?.Select(t => t.ProtocolTool.Name) ?? []).ToHashSet(StringComparer.Ordinal);
        var client = context?.Server?.ClientInfo;
        var unavailable = Group(ToolAvailability.Of(registered, availability, options.IdaScripting, OperatingSystem.IsWindows(), options.AllowDeviceChanges, options.GhidraScripting, options.AllowLive, options.AllowLiveSpawn, options.LiveScripting, options.AllowLiveAttach,
            // What is left of the one status deadline: these programs were checked above already.
            deadline > DateTime.UtcNow ? deadline - DateTime.UtcNow : TimeSpan.Zero));
        return new ServerStatus(ServerIdentity.Product, typeof(ServerOptions).Assembly.GetName().Version?.ToString(3) ?? "?", ServerIdentity.InformationalVersion,
            ServerIdentity.Executable, string.IsNullOrWhiteSpace(expectedExecutable) ? null : ServerIdentity.SamePath(expectedExecutable.Trim(), ServerIdentity.Executable),
            ServerIdentity.InstallKind, ServerIdentity.StartedAt, (long)(DateTimeOffset.UtcNow - ServerIdentity.StartedAt).TotalSeconds,
            context?.Server?.NegotiatedProtocolVersion, client == null ? null : new Client(client.Name, client.Version),
            digest, expected ? difference == null : null, difference,
            toolCount, loaded, indexing.Status, Environment.WorkingSet / (1024 * 1024), PointToUnavailable(capabilities, unavailable),
            ToolEffects.LongRunning.Where(registered.Contains).ToList(),
            Core.Toolsets.Families.Select(f => new Toolset(f.Name, f.Tools.Any(registered.Contains), Profiles.InCore(f), f.Tools.Length, f.Description)).ToList(),
            unavailable,
            NoteCountsOf(notes),
            new EngineLimits(options.EngineRequestTimeoutSeconds, options.EngineOpenTimeoutSeconds),
            (engines?.SessionStates() ?? []).Select(e => new EngineSession(e.Image, e.State.Engine, e.State.WorkerPid, e.State.State, e.State.BusyOp,
                e.State.BusySeconds, e.State.Stage, e.State.Queued, e.State.Unsaved, e.State.Restarts, e.State.Database, e.State.ReusedDatabase, e.State.Note)
                    { Analysis = e.State.Analysis }).ToList(),
            new CatalogFilter(options.ToolAllowList != null ? options.ToolAllowListSource ?? "(set)" : null, options.ToolAllowList?.Count, options.TracePath),
            sections?.GetAwaiter().GetResult() ?? []);
    }

    private const string Pending = "its check is still running; call server_status again";

    // A check may start a program and block for seconds; a pool thread would
    // starve the requests running beside it on a machine with few cores.
    private static Task<T> OwnThread<T>(Func<T> check) =>
        Task.Factory.StartNew(check, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

    // True when the task finished by the deadline, whether it succeeded or not.
    private static bool Settle(Task task, DateTime deadline)
    {
        var left = deadline - DateTime.UtcNow;
        return task.IsCompleted || left > TimeSpan.Zero && ((IAsyncResult)task).AsyncWaitHandle.WaitOne(left);
    }

    /// <summary>
    /// One capability per external program the server runs (test oracles left out), probed once per file. A version check
    /// still running after <paramref name="wait"/> (default: no limit) is reported as an unknown version.
    /// </summary>
    internal static IEnumerable<Capability> ExternalToolCapabilities(TimeSpan? wait = null)
    {
        var tools = Native.Providers.ExternalTools.Table.Where(t => !t.TestOracle).ToList();
        // Side by side: each probe may start a program, so a first status waits for the slowest, not for their sum.
        var probes = tools.Select(t => OwnThread(() => wait is { } w ? Native.Providers.ExternalTools.Probe(t, w) : Native.Providers.ExternalTools.Probe(t))).ToList();
        return probes.Select(task => task.GetAwaiter().GetResult())
            .Select(p => new Capability($"{p.Name}: {p.Purpose}", p.Usable, p.Usable ? Found(p) : p.Problem!, p.Usable ? null : p.Remediation)).ToList();
    }

    // A path the user set in the tool's variable is theirs already; a searched one is named.
    private static string Found(Native.Providers.ExternalToolProbe p) =>
        (p.Source == Native.Providers.ExternalTools.Get(p.Id).Variable ? $"from {p.Source}" : $"{p.Path} (from {p.Source})") +
        (p.Version != null ? $", version {p.Version}" : p.VersionUnknown != null ? $", version unknown ({p.VersionUnknown})" : ", version unknown");

    /// <summary>The session backend: whether it can start, and for Frida its version against the tested range.</summary>
    internal static Capability LiveBackendCapability(Native.Providers.Live.ILiveBackend backend)
    {
        var name = $"live sessions ({backend.Name})";
        // the private environment is made by the first session, not by a status call
        if (backend is Native.Providers.Live.FridaBackend { PrivatePending: true, PrivateEnvironment.Offline: false } pending)
            return new(name, true, $"Frida {Native.Providers.Live.FridaVersions.Pinned} is installed into {pending.PrivateEnvironment.Folder} by the first session", null);
        if (backend.Unavailable() is { } missing) return new(name, false, missing.Reason, missing.Remediation);
        if (backend is not Native.Providers.Live.FridaBackend { FridaVersion: var version, Python: var python }) return new(name, true, "ready", null);
        var untested = Native.Providers.Live.FridaVersions.Warning(version);
        var from = python?.Source == Native.Providers.Live.FridaEnvironment.Source ? "private environment" : $"user Python, from {python?.Source}";
        return new(name, true, $"Frida {version} in {python?.Executable} ({from}): " + (untested ?? $"in the tested range {Native.Providers.Live.FridaVersions.TestedRange}"),
            untested == null ? null : Native.Providers.Live.FridaBackend.Upgrade);
    }

    // The report budget: a reason or a fix already in an unavailableTools row is said once, there.
    internal static List<Capability> PointToUnavailable(List<Capability> capabilities, List<UnavailableGroup> unavailable) =>
        [.. capabilities.Select(c => !c.Available && unavailable.Any(u => c.Detail.Length > 40 && u.Reason.Contains(c.Detail, StringComparison.Ordinal) ||
                c.Remediation != null && u.Remediation == c.Remediation)
            ? c with { Detail = "unavailable: see unavailableTools", Remediation = null } : c)];

    // An engine's message is unbounded; status keeps its head so the report budget holds.
    private static string Bounded(string text, int max) => text.Length <= max ? text : text[..(max - 3)] + "...";

    private static NoteCounts? NoteCountsOf(NotesService? notes)
    {
        if (notes == null) return null;
        var (open, total) = notes.Counts();
        return new NoteCounts(open, total, StatusPaths.Short(notes.Root));
    }

    /// <summary>One row per (reason, fix), in first-seen order: 24 engine tools share the one engine-not-found text.</summary>
    internal static List<UnavailableGroup> Group(IEnumerable<ToolAvailability.Unavailable> rows) =>
        [.. rows.GroupBy(r => (r.Reason, r.Remediation)).Select(g => new UnavailableGroup(Entries(g), g.Key.Reason, g.Key.Remediation))];

    // An engine value missing on every tool that takes engine is one entry, not one per tool (a server without IDA or Ghidra).
    private static List<string> Entries(IEnumerable<ToolAvailability.Unavailable> rows)
    {
        var list = rows.ToList();
        var byEngine = list.Where(r => r.Mode?.StartsWith("engine=", StringComparison.Ordinal) == true).GroupBy(r => r.Mode!).Where(m => m.Count() > 3).ToList();
        var folded = byEngine.SelectMany(m => m).ToHashSet();
        return [.. list.Where(r => !folded.Contains(r)).Select(r => r.Mode == null ? r.Tool : $"{r.Tool} {r.Mode}"),
            .. byEngine.Select(m => $"{m.Key} on the {m.Count()} tools that take engine")];
    }

    /// <summary>Page size of read_result when maxTokens is not given.</summary>
    public const int ReadResultTokens = 6_000;

    [McpServerTool(Name = "read_result", Title = "Read a kept result", UseStructuredContent = true, OutputSchemaType = typeof(ReadResultRecord))]
    [Description("Read a kept result (resultId; on disk 7 days): page it, search it with query, or write it whole to outputPath. " +
                 "format=evidence: results (r-... or last:N) and their calls to outputPath; verify re-runs a bundle, entry (file.json#r-...) or " +
                 "result, or compares it with against.")]
    public async Task<string> ReadResult(
        [Description("Result id, e.g. r-0123456789ab.")] string id,
        [Description("Character offset (nextOffset).")] int offset = 0,
        [Description("Page size in tokens (default 6000).")] int? maxTokens = null,
        [Description("Only lines containing this text (/regex/ for a pattern), with offsets.")] string? query = null,
        [Description("text; json: the structured record; jsonl: its items, one per line.")] string format = "text",
        [Description("Write the whole result to this file; returns path, bytes, SHA-256.")] string? outputPath = null,
        [Description("Overwrite outputPath.")] bool overwrite = false,
        [Description("format=verify: compare with this, not a re-run: " + EvidenceInput.ReferenceDescription + ".")] string? against = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default)
    {
        switch (format.Trim().ToLowerInvariant())
        {
            case "evidence":
            {
                if (string.IsNullOrWhiteSpace(outputPath)) throw new ToolError(ErrorCode.InvalidArgument, "format=evidence writes a bundle file.", "pass outputPath");
                var bundle = EvidenceBundle.Build(results, context?.Services?.GetService(typeof(RecentCalls)) as RecentCalls, id.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries));
                var bytes = System.Text.Encoding.UTF8.GetBytes(EvidenceBundle.Serialize(bundle));
                var path = SafeFile.WriteAllBytes(outputPath, bytes, overwrite);
                var sha = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes));
                return ToolOutput.With($"Wrote {bundle.Records.Count} record(s) ({string.Join(", ", bundle.Records.Select(r => $"{r.Id} {r.Tool}"))}) to {path}: " +
                                       $"{bytes.Length:N0} bytes, SHA-256 {sha}. read_result format=verify id={path} re-runs them.",
                    new ReadResultRecord(string.Join(",", bundle.Records.Select(r => r.Id)), "evidence", bytes.Length) { Path = path, Bytes = bytes.Length, Sha256 = sha });
            }
            case "verify":
            {
                var recent = context?.Services?.GetService(typeof(RecentCalls)) as RecentCalls;
                var bundle = EvidenceBundle.Of(id, results, recent);
                string input;
                List<EvidenceBundle.Check> checks;
                if (!string.IsNullOrWhiteSpace(against))
                {
                    if (bundle.Records.Count != 1)
                        throw new ToolError(ErrorCode.InvalidArgument, $"{id} holds {bundle.Records.Count} records; against compares one.", "name one entry: <bundle>#<id>");
                    var other = EvidenceInput.Resolve(against, results, recent);
                    input = $"compared with {EvidenceInput.Describe(other.Source)}; nothing re-run";
                    checks = [EvidenceBundle.Compare(bundle.Records[0], other)];
                }
                else
                {
                    input = "each call re-run";
                    checks = await EvidenceBundle.Verify(bundle, context!, results, workspace, cancellationToken);
                }
                int failed = checks.Count(c => !c.Matches);
                return ToolOutput.With($"{id}: {checks.Count} record(s), {checks.Count - failed} verified, {failed} differ ({input})\n" +
                                       string.Join("\n", checks.Select(c => $"  {(c.Matches ? "ok" : "DIFFERS")}  {c.Id} {c.Tool}: {c.Detail}")),
                    new ReadResultRecord(id, "verify", 0) { Checks = checks, Input = input });
            }
        }
        return ReadKept(id, offset, maxTokens, query, format, outputPath, overwrite);
    }

    /// <summary>read_result on one kept result (every format but evidence and verify).</summary>
    internal string ReadKept(string id, int offset = 0, int? maxTokens = null, string? query = null, string format = "text", string? outputPath = null, bool overwrite = false)
    {
        if (offset < 0) throw new ToolError(ErrorCode.InvalidArgument, $"offset must be 0 or more, not {offset}.", "pass a nextOffset from an earlier page");
        if (maxTokens is < 1) throw new ToolError(ErrorCode.InvalidArgument, $"maxTokens must be 1 or more, not {maxTokens}.", "omit maxTokens for the default page");
        var kept = results.Read(id);
        var body = ReadResultView.Body(kept, format);
        if (!string.IsNullOrWhiteSpace(outputPath))
        {
            if (query != null) throw new ToolError(ErrorCode.InvalidArgument, "query and outputPath cannot be combined.", "write the whole result, then search the file; or drop outputPath");
            var bytes = System.Text.Encoding.UTF8.GetBytes(body);
            var path = SafeFile.WriteAllBytes(outputPath, bytes, overwrite);
            var sha = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes));
            return ToolOutput.With($"Wrote {kept.Id} ({kept.Info.Tool}, {format}) to {path}: {bytes.Length:N0} bytes, SHA-256 {sha}.",
                new ReadResultRecord(kept.Id, kept.Info.Tool, body.Length) { Path = path, Bytes = bytes.Length, Sha256 = sha });
        }
        var header = $"[{kept.Id}: {kept.Info.Tool} result, {format}, {body.Length:N0} chars]\n";
        // Inside a call the page leaves room for its header and for the record carrying the same page.
        long budget = OutputCall.Budgeted is { } call ? call.Tokens * 85 / 100 - 60 : maxTokens ?? ReadResultTokens;
        var record = new ReadResultRecord(kept.Id, kept.Info.Tool, body.Length) { Offset = offset };
        if (query != null)
        {
            var hits = new List<ReadResultMatch>();
            var found = ReadResultView.Search(body, query, offset, budget, hits, out var after);
            return ToolOutput.With(header + found, record with { Matches = hits, NextOffset = after });
        }
        var page = ReadResultView.Page(body, offset, budget, out var end);
        return ToolOutput.With(header + page, record with
        {
            Code = offset < body.Length ? body[offset..end] : "",
            NextOffset = end < body.Length ? end : null,
        });
    }
}
