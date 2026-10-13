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
    NativeEngineService? engines = null, NotesService? notes = null)
{
    public sealed record Capability(string Name, bool Available, string Detail, string? Remediation);

    public sealed record Toolset(string Name, bool Enabled, bool InCore, int Tools, string Description);

    public sealed record Client(string Name, string? Version);

    public sealed record NoteCounts(int Open, int Total, string Store);

    [Description("The --tools-file whitelist in effect (list name or path) and the tools it names; the call trace file (--trace / CORVUS_TRACE).")]
    public sealed record CatalogFilter(string? ToolsFile, int? ToolsFileTools, string? TraceFile);

    public sealed record EngineSession(string Image, string Engine, int? WorkerPid,
        [property: Description("opening, idle, busy or closed.")] string State,
        [property: Description("The request running (or open/restart), its seconds and the worker's last stage.")] string? BusyOp, double BusySeconds, string? Stage,
        [property: Description("Requests waiting for this session.")] int Queued,
        [property: Description("Unsaved edits a restart would replay.")] int Unsaved,
        int Restarts, string? Database, bool ReusedDatabase,
        [property: Description("no auto-analysis, or a read-only snapshot of a database another process holds.")] string? Note);

    [Description("Seconds per IDA or Ghidra request (CORVUS_ENGINE_REQUEST_TIMEOUT) and per engine start plus analysis (CORVUS_ENGINE_OPEN_TIMEOUT).")]
    public sealed record EngineLimits(int RequestSeconds, int OpenSeconds);

    public sealed record ServerStatus(string Server, string Version,
        [property: Description("Version, plus +<commit> when known.")]
        string InformationalVersion,
        [property: Description("The running server program.")]
        string Executable,
        [property: Description("Whether Executable is expectedExecutable (also through links); null when none was given.")]
        bool? ExecutableMatches,
        [property: Description("script, dotnet-tool, dnx, winget, scoop, homebrew or source.")]
        string InstallKind,
        DateTimeOffset StartedAt, long UptimeSeconds,
        [property: Description("The MCP protocol version negotiated with this client.")]
        string? ProtocolVersion,
        [property: Description("The client's name and version from its initialize request.")]
        Client? Client,
        [property: Description("Digest of the tool and prompt catalog (names, schemas, descriptions, annotations; prompt arguments): t<tools>-<hash>.p<prompts>-<hash>.")]
        string CatalogDigest,
        [property: Description("Whether CatalogDigest equals expectedCatalogDigest; null when none was given.")]
        bool? CatalogMatches,
        [property: Description("On a mismatch, what differs as far as the digests tell (tool or prompt counts, or definitions); else null.")]
        string? CatalogDifference,
        int Tools, int LoadedAssemblies, string BackgroundIndexing,
        long WorkingSetMB, IReadOnlyList<Capability> Capabilities,
        [property: Description("Tools that can take over 10 s on large inputs.")]
        IReadOnlyList<string> LongRunningTools,
        [property: Description("Tool families and whether this server registers them; every family unless the server was started with --toolsets <list> (or CORVUS_TOOLSETS: all, core, or names such as core,dumps).")]
        IReadOnlyList<Toolset> Toolsets,
        [property: Description("Registered tools, or modes of them (e.g. engine=ida), that cannot work here, with the reason and the fix.")]
        IReadOnlyList<ToolAvailability.Unavailable> UnavailableTools,
        [property: Description("Analyst notes in the per-user store (record_note): open, total and the store directory.")]
        NoteCounts? Notes,
        EngineLimits EngineTimeLimits,
        IReadOnlyList<EngineSession> EngineSessions,
        CatalogFilter ToolsFileAndTrace,
        [property: Description("budget (profile, ceiling, deadline, delivery, with sources), results (kept-result store), caches, calls (leftover calls, lock holders), workers (child PIDs, start times), run.")]
        IReadOnlyList<StatusSection> Sections);

    [McpServerTool(Name = "server_status", Title = "Server status", UseStructuredContent = true)]
    [Description("Which server runs (version, program, install kind, client), a catalog digest, what is loaded, limits, long-running tools, " +
                 "capabilities with the fix when missing, tool families, unusable tools, and engine sessions (busy op, queue). expectedCatalogDigest " +
                 "detects a stale server; expectedExecutable checks the registered copy.")]
    public ServerStatus GetServerStatus(
        [Description("Catalog digest to compare (t92-0123456789ab.p5-01234567).")] string? expectedCatalogDigest = null,
        [Description("Registered server program path, compared with the running one.")] string? expectedExecutable = null,
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
                : new("reference pack download", true, "downloads the reference pack of an uninstalled target framework on demand", null),
        ];
        capabilities.Add(new("native PE analysis (headers, imports, exports, resources, C++ classes, bytes)", true, "built in", null));
        var availability = new List<Native.Providers.ProviderAvailability>();
        foreach (var provider in engines?.Providers ?? [])
        {
            var a = provider.CheckAvailability();
            availability.Add(a);
            capabilities.Add(new($"native decompilation ({provider.DisplayName})", a.IsAvailable,
                a.IsAvailable ? string.Join(", ", a.Details.Select(d => $"{d.Key} {d.Value}")) : a.Reason ?? "unavailable", a.Remediation));
        }
        if (engines?.Prewarming is { } p)
            capabilities.Add(p.Enabled
                ? new("engine background analysis on load", true,
                    $"on ({p.Engine}): {(p.Running != null ? $"analyzing {p.Running} ({p.RunningSeconds:0} s)" : "idle")}, {p.Queued} queued, {p.Done} done, {p.Failed} failed, {p.Cancelled} cancelled" +
                    (p.LastError != null ? $"; last error: {p.LastError}" : ""), null)
                : new("engine background analysis on load", false, "off: the first engine call on an image waits for the engine's auto-analysis",
                    $"start the server with --prewarm ida|ghidra|auto (or {ServerOptions.PrewarmVariable})"));
        capabilities.Add(new("native engine preference (list_functions, disassemble, get_cfg, find_xrefs, native_call_tree)", true,
            options.Engine switch
            {
                EngineMode.Ours => "default ours: the built-in index; no engine is consulted unless a call passes engine=ida or engine=ghidra",
                EngineMode.Ida => "default ida: IDA's analysis, started or waited for by the call; engine=ours, ghidra or auto per call",
                EngineMode.Ghidra => "default ghidra: Ghidra's analysis, started or waited for by the call; engine=ours, ida or auto per call",
                _ => "default auto: the functions, references and blocks of the first engine (IDA, then Ghidra) that has analyzed an image's bytes, open or saved, else the built-in index",
            } + $"; --engine auto|ours|ida|ghidra (or {ServerOptions.EngineVariable}) sets the default, each of those tools takes engine", null));
        capabilities.AddRange(ExternalToolCapabilities());
        int loaded = workspace.LoadedCount; // without the lock: status answers while a long call holds it
        var registered = (server?.ToolCollection?.Select(t => t.ProtocolTool.Name) ?? []).ToHashSet(StringComparer.Ordinal);
        var client = context?.Server?.ClientInfo;
        return new ServerStatus(ServerIdentity.Product, typeof(ServerOptions).Assembly.GetName().Version?.ToString(3) ?? "?", ServerIdentity.InformationalVersion,
            ServerIdentity.Executable, string.IsNullOrWhiteSpace(expectedExecutable) ? null : ServerIdentity.SamePath(expectedExecutable.Trim(), ServerIdentity.Executable),
            ServerIdentity.InstallKind, ServerIdentity.StartedAt, (long)(DateTimeOffset.UtcNow - ServerIdentity.StartedAt).TotalSeconds,
            context?.Server?.NegotiatedProtocolVersion, client == null ? null : new Client(client.Name, client.Version),
            digest, expected ? difference == null : null, difference,
            toolCount, loaded, indexing.Status, Environment.WorkingSet / (1024 * 1024), capabilities,
            ToolEffects.LongRunning.Where(registered.Contains).ToList(),
            Core.Toolsets.Families.Select(f => new Toolset(f.Name, f.Tools.Any(registered.Contains), Profiles.InCore(f), f.Tools.Length, f.Description)).ToList(),
            ToolAvailability.Of(registered, availability, options.IdaScripting, OperatingSystem.IsWindows(), options.AllowDeviceChanges, options.GhidraScripting),
            NoteCountsOf(notes),
            new EngineLimits(options.EngineRequestTimeoutSeconds, options.EngineOpenTimeoutSeconds),
            (engines?.SessionStates() ?? []).Select(e => new EngineSession(e.Image, e.State.Engine, e.State.WorkerPid, e.State.State, e.State.BusyOp,
                e.State.BusySeconds, e.State.Stage, e.State.Queued, e.State.Unsaved, e.State.Restarts, e.State.Database, e.State.ReusedDatabase, e.State.Note)).ToList(),
            new CatalogFilter(options.ToolAllowList != null ? options.ToolAllowListSource ?? "(set)" : null, options.ToolAllowList?.Count, options.TracePath),
            context?.Services is { } services ? StatusSections.Collect(services) : []);
    }

    /// <summary>One capability per external program the server runs (test oracles left out), probed once per file.</summary>
    internal static IEnumerable<Capability> ExternalToolCapabilities() =>
        Native.Providers.ExternalTools.Table.Where(t => !t.TestOracle).Select(Native.Providers.ExternalTools.Probe).Select(p =>
            new Capability($"external tool: {p.Name}, for {p.Purpose}", p.Usable,
                p.Usable ? $"{p.Path} (from {p.Source}{(p.Version != null ? $", version {p.Version}" : "")})" : p.Problem!,
                p.Usable ? null : p.Remediation));

    private static NoteCounts? NoteCountsOf(NotesService? notes)
    {
        if (notes == null) return null;
        var (open, total) = notes.Counts();
        return new NoteCounts(open, total, notes.Root);
    }

    /// <summary>Page size of read_result when maxTokens is not given.</summary>
    public const int ReadResultTokens = 6_000;

    [McpServerTool(Name = "read_result", Title = "Read a kept result", UseStructuredContent = true, OutputSchemaType = typeof(ReadResultRecord))]
    [Description("Read a kept result (resultId; kept on disk 7 days): page it, search it with query, or write it whole to outputPath.")]
    public string ReadResult(
        [Description("Result id, e.g. r-0123456789ab.")] string id,
        [Description("Character offset (nextOffset).")] int offset = 0,
        [Description("Page size in tokens (default 6000).")] int? maxTokens = null,
        [Description("Only lines containing this text (/regex/ for a pattern), with their offsets.")] string? query = null,
        [Description("text; json: the structured record; jsonl: its items, one per line.")] string format = "text",
        [Description("Write the whole result to this file; returns path, bytes and SHA-256.")] string? outputPath = null,
        bool overwrite = false)
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
                new ReadResultRecord(kept.Id, kept.Info.Tool, format, body.Length) { Path = path, Bytes = bytes.Length, Sha256 = sha });
        }
        var header = $"[{kept.Id}: {kept.Info.Tool} result, {format}, {body.Length:N0} chars]\n";
        // Inside a call the page leaves room for its header and for the record carrying the same page.
        long budget = OutputCall.Budgeted is { } call ? call.Tokens * 85 / 100 - 60 : maxTokens ?? ReadResultTokens;
        var record = new ReadResultRecord(kept.Id, kept.Info.Tool, format, body.Length) { Offset = offset };
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
