using System.Text.Json.Nodes;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Corvus.Mcp;

/// <summary>
/// What each tool does to its environment: the one source of the tools' MCP annotations (applied at startup by
/// <see cref="Apply"/>; [McpServerTool] attributes set none). Audited against each tool's code.
/// <list type="bullet">
/// <item>ReadOnly: changes nothing loaded and writes no file. Loading an image named by path (the native and ReadyToRun tools
/// accept a path) counts as reading: it adds the file to the session as load_assembly would. Private caches (the IDA
/// database, downloaded reference packs and PDBs) do not count.</item>
/// <item>Destructive: can replace or discard existing state: method bodies, names, bytes or edits in the workspace, or an
/// existing file. False for tools that only add (new members, a newly loaded file, files in an empty directory).</item>
/// <item>Idempotent: the same call again has no further effect.</item>
/// <item>OpenWorld: some argument value can make the call launch a process (IDA through idalib, Python, a Ghidra JVM, diec), reach the network
/// or read another running process; so every tool with an engine parameter is open-world. Not counted: server-wide settings
/// (--engine, --prewarm) and a reference pack download (any .NET tool can trigger one when an assembly targets a .NET
/// version that is not installed; CORVUS_OFFLINE=1 turns it off).</item>
/// <item>LongRunning (not an MCP annotation): a call can run for more than ~10 s on large inputs: whole-assembly or whole-image
/// work, an external engine, or the first use of a native image, which waits for its code index. Advertised as a
/// description suffix, as _meta "corvus/longRunning": true, and in server_status.</item>
/// </list>
/// </summary>
public static partial class ToolEffects
{
    public sealed record Effects(bool ReadOnly, bool Destructive, bool Idempotent, bool OpenWorld, bool LongRunning);

    private static Effects Reads(bool longRunning = false, bool openWorld = false) => new(true, false, true, openWorld, longRunning);

    private static Effects Changes(bool destructive, bool idempotent, bool longRunning = false, bool openWorld = false) =>
        new(false, destructive, idempotent, openWorld, longRunning);

    public const string LongRunningMetaKey = "corvus/longRunning";
    public const string LongRunningSuffix = " [Long-running: can exceed 10 s.]";

    /// <summary>Every tool's row, by family; the rows are in the per-family files beside this one.</summary>
    internal static readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, Effects>> ByFamily = new Dictionary<string, IReadOnlyDictionary<string, Effects>>(StringComparer.Ordinal)
    {
        ["session"] = SessionTools(),
        ["dotnet"] = DotnetTools(),
        ["containers"] = ContainersTools(),
        ["edit"] = EditTools(),
        ["il2cpp"] = Il2CppTools(),
        ["native"] = NativeTools(),
        ["native-edit"] = NativeEditTools(),
        ["builds"] = BuildsTools(),
        ["notes"] = NotesTools(),
        ["engine"] = EngineTools(),
        ["android"] = AndroidTools(),
        ["dumps"] = DumpsTools(),
        ["live"] = LiveTools(),
    };

    /// <summary>Every tool, by name.</summary>
    public static readonly IReadOnlyDictionary<string, Effects> Table = FamilyTables.Join(ByFamily);

    /// <summary>MCP's defaults for a tool the table does not list: may change, destroy and reach anything.</summary>
    public static readonly Effects Unlisted = new(false, true, false, true, false);

    public static Effects Of(string tool) => Table.TryGetValue(tool, out var e) ? e : Unlisted;

    /// <summary>Tools that can run long, by name.</summary>
    public static IEnumerable<string> LongRunning => Table.Where(t => t.Value.LongRunning).Select(t => t.Key).Order(StringComparer.Ordinal);

    /// <summary>
    /// Claude Code saves a text result over 50,000 characters to a file unless the tool raises this limit (capped at 500,000).
    /// This value is over the default page plus ResponseBudget.Slack, so a default page stays in context.
    /// </summary>
    public const string MaxResultSizeMetaKey = "anthropic/maxResultSizeChars";
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
                DestructiveHint = e.Destructive,
                IdempotentHint = e.Idempotent,
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
