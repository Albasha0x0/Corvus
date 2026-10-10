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
    NativeEngineService? engines = null)
{
    public sealed record Capability(string Name, bool Available, string Detail, string? Remediation);

    public sealed record ServerStatus(string Version,
        [property: Description("Digest of the tool and prompt catalog (names, schemas, descriptions, annotations; prompt arguments): t<tools>-<hash>.p<prompts>-<hash>.")]
        string CatalogDigest,
        [property: Description("Whether CatalogDigest equals expectedCatalogDigest; null when none was given.")]
        bool? CatalogMatches,
        [property: Description("On a mismatch, what differs as far as the digests tell (tool or prompt counts, or definitions); else null.")]
        string? CatalogDifference,
        int Tools, int LoadedAssemblies, string BackgroundIndexing,
        int MaxOutputChars, int TimeoutSeconds, long WorkingSetMB, IReadOnlyList<Capability> Capabilities,
        [property: Description("Tools whose calls can take more than 10 s on large inputs (whole-input work, an external engine, a native image's first code index).")]
        IReadOnlyList<string> LongRunningTools);

    private static readonly ConditionalWeakTable<McpServerOptions, string> Digests = new();

    [McpServerTool(Name = "server_status", Title = "Server status", UseStructuredContent = true)]
    [Description("Version, a digest of the tool and prompt catalog, what is loaded, background indexing state, response limits, long-running tools, " +
                 "and which capabilities are available here with the reason and the fix when one is not. Pass expectedCatalogDigest (from an earlier " +
                 "server_status, or NetDecompilerMcp doctor) to detect a stale server: the result says whether it matches and what differs.")]
    public ServerStatus GetServerStatus(
        [Description("Catalog digest to compare with this server's (e.g. t92-0123456789ab.p5-01234567).")] string? expectedCatalogDigest = null,
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
        foreach (var provider in engines?.Providers ?? [])
        {
            var a = provider.CheckAvailability();
            capabilities.Add(new($"native decompilation ({provider.DisplayName})", a.IsAvailable,
                a.IsAvailable ? string.Join(", ", a.Details.Select(d => $"{d.Key} {d.Value}")) : a.Reason ?? "unavailable", a.Remediation));
        }
        int loaded = workspace.Read(() => workspace.Assemblies.Count + workspace.Natives.Count);
        return new ServerStatus(typeof(ServerOptions).Assembly.GetName().Version?.ToString(3) ?? "?", digest, expected ? difference == null : null, difference,
            toolCount, loaded, indexing.Status, options.MaxOutputChars, options.TimeoutSeconds, Environment.WorkingSet / (1024 * 1024), capabilities,
            ToolEffects.LongRunning.ToList());
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
