using System.ComponentModel;
using ModelContextProtocol.Server;

namespace NetDecompilerMcp.Mcp;

/// <summary>Reusable reverse-engineering workflows, exposed as MCP prompts (slash commands in most clients).</summary>
[McpServerPromptType]
public static class WorkflowPrompts
{
    [McpServerPrompt(Name = "analyze_assembly", Title = "Analyze an assembly")]
    [Description("Load an assembly or game folder and produce an architecture overview.")]
    public static string AnalyzeAssembly(
        [Description("Path to an assembly file or folder (e.g. a game's Managed folder).")] string path,
        [Description("What you care about (optional), e.g. networking, saves, anti-cheat.")] string? focus = null) => $"""
        Use the net-decompiler tools to analyze {path}.
        1. load_assembly (path={path}; it can be a folder). Then get_assembly_info on the main assembly (for a Unity game: Assembly-CSharp).
        2. list_namespaces, then list_types per interesting namespace. Note Il2Cpp dummy DLLs (bodies are stubs) if reported.
        3. Identify entry points and core systems: managers/singletons, networking, persistence, UI, gameplay loop. Use search_symbols and get_type_info (cheaper than decompiling).
        4. Decompile only the key members with decompile_member and summarize what each system does.
        {(string.IsNullOrWhiteSpace(focus) ? "" : $"Focus especially on: {focus}.\n")}Finish with: a namespace map, the 10 most important types with one-line roles, and suggested next steps. Cite tokens so results can be revisited.
        """;

    [McpServerPrompt(Name = "find_feature", Title = "Find where a feature is implemented")]
    [Description("Locate the code that implements a behaviour, starting from strings, names and constants.")]
    public static string FindFeature(
        [Description("The behaviour to find, e.g. 'license check', 'damage calculation', 'save file encryption'.")] string feature,
        [Description("Assembly id to focus on (optional).")] string? assembly = null) => $"""
        Find where "{feature}" is implemented{(assembly is null ? "" : $" in {assembly}")} using the net-decompiler tools.
        - Start broad: search_strings for UI/log text related to it, search_symbols for likely names (use wildcards), search_constants for known magic numbers.
        - For each candidate, get_type_info / decompile_member, then follow the flow with find_references (callers) and find_callees (callees).
        - For virtual/interface methods, use find_overrides; for obfuscated names, rely on strings, constants and search_il patterns.
        Report the call chain from entry point to the core logic, with tokens, and quote the decisive lines of decompiled code.
        """;

    [McpServerPrompt(Name = "explain_type", Title = "Explain a type")]
    [Description("Explain what a type does, how it is used, and its important members.")]
    public static string ExplainType(
        [Description("Type name or token.")] string type,
        [Description("Assembly id (optional).")] string? assembly = null) => $"""
        Explain {type}{(assembly is null ? "" : $" from {assembly}")}.
        Use get_type_info first, then get_type_hierarchy, then decompile_type (page through long output). Use find_references on the type to see who creates and uses it.
        Describe: purpose, state (fields), lifecycle (constructors / Unity callbacks), public API, collaborators, and anything surprising. Keep it grounded in the decompiled code.
        """;

    [McpServerPrompt(Name = "plan_patch", Title = "Plan and apply a patch")]
    [Description("Find the right patch point for a behaviour change, preview it, apply it and save a patched copy.")]
    public static string PlanPatch(
        [Description("The behaviour change wanted, e.g. 'skip the version check', 'double the XP gain'.")] string goal,
        [Description("Assembly id (optional).")] string? assembly = null) => $"""
        Goal: {goal}{(assembly is null ? "" : $" (assembly {assembly})")}.
        1. Locate the decisive method (search_strings / search_symbols / find_references) and read it with decompile_member.
        2. Pick the smallest change: stub_method for "always return X"; patch_method_csharp for logic changes (lambdas, async and LINQ work); add_members_csharp / add_types_csharp for new code; patch_method_il for surgical prepend hooks or IL that C# cannot express. Check the result with diff_edits; undo_edit if it is wrong.
        3. Run the edit with dryRun=true first and check the result; then apply it and re-read with decompile_member.
        4. save_assembly to a new file (never overwrite the original unless explicitly asked). Report exactly what changed and how to revert.
        """;

    [McpServerPrompt(Name = "map_native_address", Title = "Map an Il2Cpp native address")]
    [Description("Identify the managed method behind a native address from IDA/Ghidra or a crash log (Il2Cpp games).")]
    public static string MapNativeAddress(
        [Description("Native address (hex), e.g. 0x1A2B3C.")] string address,
        [Description("Folder with Il2CppDumper/Cpp2IL dummy DLLs, if not loaded yet.")] string? dummyDllFolder = null) => $"""
        {(dummyDllFolder is null ? "" : $"load_assembly {dummyDllFolder} first.\n")}Use find_method_by_address with address {address} (kind auto). Then get_il2cpp_info on the owning type for neighbouring methods and field offsets,
        and get_type_info for the managed shape of the type. Explain which method the address belongs to, how far inside it is, and which fields are at the offsets likely being accessed.
        """;
}
