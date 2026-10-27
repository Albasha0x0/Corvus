using System.Text.Json.Nodes;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Corvus.Mcp;

/// <summary>What each tool does to its environment: the one source of its MCP annotations, audited against its code.</summary>
// ReadOnly: changes nothing loaded, writes no file; loading an image named by path and private caches count as reading.
// Destructive: can replace or discard state (bodies, names, bytes, edits, an existing file); false for tools that only add.
// Idempotent: the same call again has no further effect.
// OpenWorld: some argument can launch a process, reach the network or read another process; every tool with an engine parameter.
// OpenWorld leaves out server-wide settings, reference pack downloads and the DAC revocation check (off with CORVUS_OFFLINE=1).
// LongRunning (not an MCP annotation): a call can exceed ~10 s; advertised as a description suffix, _meta and in server_status.
public static partial class ToolEffects
{
    public sealed record Effects(bool ReadOnly, bool Destructive, bool Idempotent, bool OpenWorld, bool LongRunning);

    private static Effects Reads(bool longRunning = false, bool openWorld = false) => new(true, false, true, openWorld, longRunning);

    private static Effects Changes(bool destructive, bool idempotent, bool longRunning = false, bool openWorld = false) =>
        new(false, destructive, idempotent, openWorld, longRunning);

    public const string LongRunningMetaKey = "corvus/longRunning";
    // The errors guide topic says what it means: over 10 s.
    public const string LongRunningSuffix = " [Long-running.]";

    /// <summary>Every tool's row, by family; the rows are in the per-family files beside this one.</summary>
    internal static readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, Effects>> ByFamily = new Dictionary<string, IReadOnlyDictionary<string, Effects>>(StringComparer.Ordinal)
    {
        ["session"] = SessionTools(),
        ["dotnet"] = DotnetTools(),
        ["containers"] = ContainersTools(),
        ["edit"] = EditTools(),
        ["aot"] = AotTools(),
        ["native"] = NativeTools(),
        ["native-edit"] = NativeEditTools(),
        ["builds"] = BuildsTools(),
        ["notes"] = NotesTools(),
        ["engine"] = EngineTools(),
        ["android"] = AndroidTools(),
        ["dumps"] = DumpsTools(),
        ["live"] = LiveTools(),
        ["web"] = WebTools(),
    };

    /// <summary>Every tool, by name.</summary>
    public static readonly IReadOnlyDictionary<string, Effects> Table = FamilyTables.Join(ByFamily);

    /// <summary>MCP's defaults for a tool the table does not list: may change, destroy and reach anything.</summary>
    public static readonly Effects Unlisted = new(false, true, false, true, false);

    public static Effects Of(string tool) => Table.TryGetValue(tool, out var e) ? e : Unlisted;

    /// <summary>Tools that can run long, by name.</summary>
    public static IEnumerable<string> LongRunning => Table.Where(t => t.Value.LongRunning).Select(t => t.Key).Order(StringComparer.Ordinal);

    /// <summary>The _meta key that raises Claude Code's text result limit.</summary>
    public const string MaxResultSizeMetaKey = "anthropic/maxResultSizeChars";
    // Claude Code saves a text result over 50,000 characters to a file (cap 500,000); this keeps a default page plus ResponseBudget.Slack in context.
    public const int MaxResultSizeChars = 100_000;

    /// <summary>Claude Code loads these tools' definitions up front instead of behind tool search.</summary>
    public const string AlwaysLoadMetaKey = "anthropic/alwaysLoad";
    public static readonly IReadOnlySet<string> AlwaysLoad = new HashSet<string>(StringComparer.Ordinal) { "load_assembly", "server_status" };

    /// <summary>Sets every tool's annotations, marks long-running tools in the description and _meta, and sets the client _meta keys.</summary>
    public static void Apply(IEnumerable<McpServerTool> tools)
    {
        foreach (var tool in tools)
        {
            var t = tool.ProtocolTool;
            var e = Of(t.Name);
            // The title is said once, at the top level (annotations.title predates it and repeated it: 5 KB of tools/list).
            t.Title ??= t.Annotations?.Title;
            t.Annotations = new ToolAnnotations
            {
                ReadOnlyHint = e.ReadOnly,
                // MCP reads these two only when readOnlyHint is false; a read-only tool leaves them out (4.6 KB of tools/list).
                DestructiveHint = e.ReadOnly ? null : e.Destructive,
                IdempotentHint = e.ReadOnly ? null : e.Idempotent,
                OpenWorldHint = e.OpenWorld,
            };
            t.Meta ??= new JsonObject();
            t.Meta[MaxResultSizeMetaKey] = MaxResultSizeChars;
            if (AlwaysLoad.Contains(t.Name)) t.Meta[AlwaysLoadMetaKey] = true;
            if (!e.LongRunning) continue;
            if (t.Description is { } d && !d.EndsWith(LongRunningSuffix, StringComparison.Ordinal)) t.Description = d + LongRunningSuffix;
            t.Meta[LongRunningMetaKey] = true;
        }
    }
}
