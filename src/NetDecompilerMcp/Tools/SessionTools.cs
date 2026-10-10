using System.ComponentModel;
using System.Runtime.CompilerServices;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class SessionTools(AssemblyWorkspace workspace, IndexingService indexing, ServerOptions options, ResultStore results, OutputPager pager,
    NativeEngineService? engines = null, NativeCodeService? code = null)
{
    public sealed record Capability(string Name, bool Available, string Detail, string? Remediation);

    public sealed record Toolset(string Name, bool Enabled, bool InCore, int Tools, string Description);

    public sealed record Client(string Name, string? Version);

    public sealed record ServerStatus(string Version,
        [property: Description("Version plus +<commit> when the build knew its source revision.")]
        string InformationalVersion,
        [property: Description("The running server's program (its .dll under the dotnet host).")]
        string Executable,
        [property: Description("Whether Executable is expectedExecutable (also through links); null when none was given.")]
        bool? ExecutableMatches,
        [property: Description("How this copy was installed, from its path: script, dotnet-tool, dnx, winget, scoop, homebrew or source.")]
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
        int MaxOutputChars, int TimeoutSeconds, long WorkingSetMB, IReadOnlyList<Capability> Capabilities,
        [property: Description("Tools whose calls can take more than 10 s on large inputs (whole-input work, an external engine, a native image's first code index).")]
        IReadOnlyList<string> LongRunningTools,
        [property: Description("Tool families and whether this server registers them; every family unless the server was started with --toolsets <list> (or NDM_TOOLSETS: all, core, or names such as core,dumps).")]
        IReadOnlyList<Toolset> Toolsets,
        [property: Description("Registered tools, or modes of them (e.g. engine=ida), that cannot work here, with the reason and the fix.")]
        IReadOnlyList<ToolAvailability.Unavailable> UnavailableTools);

    private static readonly ConditionalWeakTable<McpServerOptions, string> Digests = new();

    [McpServerTool(Name = "server_status", Title = "Server status", UseStructuredContent = true)]
    [Description("Which server is running (version and commit, program path, install kind, start time, protocol, client), a digest of the tool and " +
                 "prompt catalog, what is loaded, background indexing state, response limits, long-running tools, which capabilities are available here " +
                 "with the reason and the fix when one is not, the tool families registered, and the tools or modes that cannot work here. Pass " +
                 "expectedCatalogDigest (from an earlier server_status, or NetDecompilerMcp doctor) to detect a stale server, and expectedExecutable to " +
                 "check that the client started the copy it was registered with.")]
    public ServerStatus GetServerStatus(
        [Description("Catalog digest to compare with this server's (e.g. t92-0123456789ab.p5-01234567).")] string? expectedCatalogDigest = null,
        [Description("Path of the server program the client is registered with, compared with the running one.")] string? expectedExecutable = null,
        RequestContext<CallToolRequestParams> context = null!)
    {
        var server = context?.Server?.ServerOptions;
        var digest = server == null ? "" : Digests.GetValue(server, o =>
        {
            var (tools, prompts) = Catalog.Of(o);
            return Catalog.Digest(tools, prompts);
        });
        bool expected = !string.IsNullOrWhiteSpace(expectedCatalogDigest);
        var difference = expected ? Catalog.Difference(expectedCatalogDigest!, digest) : null;
        int toolCount = server?.ToolCollection?.Count ?? 0;

        List<Capability> capabilities =
        [
            new(".NET decompilation, search, navigation, editing", true, "built in", null),
            ReferencePacks.Offline
                ? new("reference pack download", false, "NDM_OFFLINE is set: assemblies targeting an uninstalled .NET version resolve fewer references", "unset NDM_OFFLINE")
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
                ? new("IDA background analysis on load", true,
                    $"on: {(p.Running != null ? $"analyzing {p.Running} ({p.RunningSeconds:0} s)" : "idle")}, {p.Queued} queued, {p.Done} done, {p.Failed} failed, {p.Cancelled} cancelled" +
                    (p.LastError != null ? $"; last error: {p.LastError}" : ""), null)
                : new("IDA background analysis on load", false, "off: the first decompile_native on an image waits for IDA's auto-analysis",
                    $"start the server with --ida-prewarm (or {ServerOptions.IdaPrewarmVariable}=1)"));
        capabilities.Add(new("native engine preference (list_functions, disassemble, get_cfg, find_xrefs, native_call_tree)", true,
            options.Engine switch
            {
                EngineMode.Ours => "default ours: the built-in index; IDA is not consulted unless a call passes engine=ida",
                EngineMode.Ida => "default ida: IDA's analysis, started or waited for by the call; engine=ours or auto per call",
                _ => "default auto: IDA's functions, references and blocks once its analysis of an image is complete in this session, else the built-in index",
            } + $"; --engine auto|ours|ida (or {ServerOptions.EngineVariable}) sets the default, each of those tools takes engine", null));
        if (code != null)
            capabilities.Add(code.IndexCache?.Status() is { } c
                ? new("saved native code indexes", true,
                    $"on: {c.Root}, {c.Entries} entries, {c.Bytes / (1024.0 * 1024):0.#} of {c.MaxBytes >> 20} MB, unused entries kept {c.MaxAge.TotalDays:0} days; " +
                    $"this session {c.Hits} loaded, {c.Misses} not found, {c.Rejected} unusable (rebuilt), {c.Writes} saved, {c.Evicted} evicted" +
                    (c.LastError != null ? $"; last problem: {c.LastError}" : ""), null)
                : new("saved native code indexes", false, "off: every image's code index is built when it is opened",
                    "start the server without --index-cache off (and without NDM_CODE_INDEX_CACHE=off)"));
        if (code != null)
        {
            var s = code.ImportStats;
            capabilities.Add(new("saved imported names (load_pdb, apply_il2cpp_names)", true,
                $"on: {code.AnnotationRoot}; this session {s.LayersRestored} layer(s) restored on load ({s.NamesRestored} names), {s.LayersSaved} saved" +
                (s.LastProblem != null ? $"; last problem: {s.LastProblem}" : ""), null));
        }
        int loaded = workspace.Read(() => workspace.Assemblies.Count + workspace.Natives.Count);
        var registered = (server?.ToolCollection?.Select(t => t.ProtocolTool.Name) ?? []).ToHashSet(StringComparer.Ordinal);
        var client = context?.Server?.ClientInfo;
        return new ServerStatus(typeof(ServerOptions).Assembly.GetName().Version?.ToString(3) ?? "?", ServerIdentity.InformationalVersion,
            ServerIdentity.Executable, string.IsNullOrWhiteSpace(expectedExecutable) ? null : ServerIdentity.SamePath(expectedExecutable.Trim(), ServerIdentity.Executable),
            ServerIdentity.InstallKind, ServerIdentity.StartedAt, (long)(DateTimeOffset.UtcNow - ServerIdentity.StartedAt).TotalSeconds,
            context?.Server?.NegotiatedProtocolVersion, client == null ? null : new Client(client.Name, client.Version),
            digest, expected ? difference == null : null, difference,
            toolCount, loaded, indexing.Status, options.MaxOutputChars, options.TimeoutSeconds, Environment.WorkingSet / (1024 * 1024), capabilities,
            ToolEffects.LongRunning.Where(registered.Contains).ToList(),
            Core.Toolsets.Families.Select(f => new Toolset(f.Name, options.Toolsets.Contains(f.Name), f.InCore, f.Tools.Length, f.Description)).ToList(),
            ToolAvailability.Of(registered, availability, options.IdaScripting, OperatingSystem.IsWindows()));
    }

    [McpServerTool(Name = "read_result", Title = "Read a kept result")]
    [Description("Page through a result that was too large to send (a limit_exceeded error names it, e.g. r3). Results are kept while memory allows.")]
    public string ReadResult(
        [Description("Kept result id from the limit_exceeded error, e.g. r3.")] string id,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null)
    {
        var (tool, text) = results.Get(id);
        return $"[{id}: {tool} result, {text.Length:N0} chars]\n" + pager.Page(text, offset, maxChars);
    }
}
