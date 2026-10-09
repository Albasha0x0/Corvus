using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class SessionTools(AssemblyWorkspace workspace, IndexingService indexing, ServerOptions options, ResultStore results, OutputPager pager,
    NativeEngineService? engines = null)
{
    public sealed record Capability(string Name, bool Available, string Detail, string? Remediation);

    public sealed record ServerStatus(string Version, string CatalogDigest, int Tools, int LoadedAssemblies, string BackgroundIndexing,
        int MaxOutputChars, int TimeoutSeconds, long WorkingSetMB, IReadOnlyList<Capability> Capabilities);

    [McpServerTool(Name = "server_status", Title = "Server status", ReadOnly = true, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Version, a digest of the tool catalog (compare it to detect a stale server), what is loaded, background indexing state, " +
                 "response limits, and which capabilities are available here with the reason and the fix when one is not.")]
    public ServerStatus GetServerStatus(RequestContext<CallToolRequestParams> context = null!)
    {
        var tools = context?.Server?.ServerOptions.ToolCollection?.Select(t => t.ProtocolTool).OrderBy(t => t.Name, StringComparer.Ordinal).ToList() ?? [];
        var catalog = new StringBuilder();
        foreach (var t in tools)
            catalog.Append(t.Name).Append('\n').Append(t.InputSchema.GetRawText()).Append('\n').Append(t.OutputSchema?.GetRawText()).Append('\n');
        var digest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(catalog.ToString())))[..16];

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
        return new ServerStatus(typeof(ServerOptions).Assembly.GetName().Version?.ToString(3) ?? "?", digest, tools.Count, loaded, indexing.Status,
            options.MaxOutputChars, options.TimeoutSeconds, Environment.WorkingSet / (1024 * 1024), capabilities);
    }

    [McpServerTool(Name = "read_result", Title = "Read a kept result", ReadOnly = true, Idempotent = true, OpenWorld = false)]
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
