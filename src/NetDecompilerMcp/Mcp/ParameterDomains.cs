using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol.Server;

namespace NetDecompilerMcp.Mcp;

/// <summary>
/// The closed value sets of string parameters, advertised as JSON Schema "enum" (applied at startup by <see cref="Apply"/>)
/// and checked by <see cref="ArgumentCheck"/> before the tool runs. Audited against each tool's parser: Values are the
/// documented spellings, Aliases the other spellings the parser also takes (accepted, not advertised). Matching ignores
/// case and surrounding white space; an empty string is passed to the tool, which treats it as the default.
/// Comma-separated lists and open sets (a status or a reason code) are not listed.
/// </summary>
public static class ParameterDomains
{
    public sealed record Domain(string[] Values, string[] Aliases);

    private static Domain Of(string[] values, params string[] aliases) => new(values, aliases);

    private static readonly Domain Engine = Of(["auto", "ours", "ida", "ghidra"], "built-in", "builtin");
    private static readonly Domain DecompilerEngine = Of(["auto", "ida", "ghidra"]);
    /// <summary>Tools only IDA serves.</summary>
    private static readonly Domain IdaEngine = Of(["auto", "ida"]);
    private static readonly Domain ShowDecompile = Of(["none", "after", "diff"], "true", "false");
    private static readonly Domain Relocations =Of(["auto", "keep", "neutralize"], "neutralise");
    private static readonly Domain StubMode = Of(["replace", "before", "after"]);
    private static readonly Domain Placement = Of(["auto", "cave", "section"]);
    private static readonly string[] KindAliases = ["all", "class", "types", "methods", "fields", "properties", "events", "members"];
    private static readonly Domain AnyKind = Of(["any", "type", "method", "field", "property", "event", "member"], KindAliases);
    private static readonly Domain ResolveKind = Of(["type", "method", "field", "property", "event"], [.. KindAliases, "any", "member"]);
    private static readonly Domain Direction = Of(["callers", "callees"]);
    private static readonly Domain NoteKind = Of(["finding", "question", "hypothesis", "todo"]);
    private static readonly Domain NoteStatus = Of(["open", "confirmed", "refuted", "answered", "dropped"]);

    /// <summary>By tool, then parameter.</summary>
    public static readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, Domain>> Table = new Dictionary<string, IReadOnlyDictionary<string, Domain>>(StringComparer.Ordinal)
    {
        ["resolve_symbol"] = new Dictionary<string, Domain> { ["kind"] = AnyKind },
        ["search_symbols"] = new Dictionary<string, Domain> { ["kind"] = AnyKind },
        ["find_references"] = new Dictionary<string, Domain> { ["kind"] = ResolveKind },
        ["rename_symbol"] = new Dictionary<string, Domain> { ["kind"] = ResolveKind },
        ["decompile_member"] = new Dictionary<string, Domain> { ["kind"] = Of(["any", "method", "field", "property", "event"], [.. KindAliases, "type", "member"]) },
        ["list_types"] = new Dictionary<string, Domain> { ["kind"] = Of(["class", "struct", "interface", "enum", "delegate"], "static class") },
        ["search_container"] = new Dictionary<string, Domain> { ["kind"] = Of(["type", "method", "field", "property"], "any") },
        ["get_call_tree"] = new Dictionary<string, Domain> { ["direction"] = Of(Direction.Values, "caller", "callee", "up", "down", "in", "out") },
        ["find_method_by_address"] = new Dictionary<string, Domain> { ["kind"] = Of(["auto", "rva", "va", "offset"], "any", "fileoffset") },
        ["generate_cpp_binding"] = new Dictionary<string, Domain> { ["style"] = Of(["mono", "il2cpp", "hostapi"]) },
        ["patch_method_il"] = new Dictionary<string, Domain> { ["mode"] = Of(["replace", "prepend"], "prefix", "insert") },
        ["apply_edits"] = new Dictionary<string, Domain> { ["targetBuild"] = Of(["same", "other"]) },
        ["load_session"] = new Dictionary<string, Domain> { ["targetBuild"] = Of(["same", "other"]) },
        ["extract_strings"] = new Dictionary<string, Domain> { ["format"] = Of(["json", "csv"]) },
        ["verify_native_imports"] = new Dictionary<string, Domain> { ["platform"] = Of(["auto", "windows", "linux", "osx", "android", "ios"], "macos") },
        ["load_assembly"] = new Dictionary<string, Domain>
        {
            ["slice"] = Of(["arm64e", "arm64", "x86_64", "x86_64h", "arm64_32", "armv7", "armv7s", "armv7k", "i386", "arm64-v8a", "armeabi-v7a", "x86"],
                [.. Enumerable.Range(0, 64).Select(i => i.ToString(System.Globalization.CultureInfo.InvariantCulture))]),
        },
        ["dump_stack"] = new Dictionary<string, Domain> { ["managed"] = Of(["auto", "off"]) },
        ["dump_heap"] = new Dictionary<string, Domain> { ["mode"] = Of(["stats", "objects"]) },
        ["bucket_minidumps"] = new Dictionary<string, Domain> { ["managed"] = Of(["auto", "off"]) },
        ["symbolize_stack_text"] = new Dictionary<string, Domain> { ["format"] = Of(["auto", "unity", "dotnet", "wer", "eventlog", "windbg"]) },
        ["disassemble_dex"] = new Dictionary<string, Domain> { ["format"] = Of(["smali", "annotated"]) },
        ["decompile_java"] = new Dictionary<string, Domain> { ["engine"] = Of(["jadx"]) },
        ["read_android_log"] = new Dictionary<string, Domain> { ["priority"] = Of(["V", "D", "I", "W", "E", "F"], "verbose", "debug", "info", "warn", "warning", "error", "fatal") },
        ["search_dex"] = new Dictionary<string, Domain> { ["kind"] = Of(["string", "type", "method", "field", "const", "opcode"], "class") },
        ["find_dex_references"] = new Dictionary<string, Domain> { ["direction"] = Of(["to", "from"]), ["kind"] = Of(["auto", "class", "method", "field", "string"]) },
        ["inspect_process"] = new Dictionary<string, Domain> { ["regionFilter"] = Of(["committed", "all", "executable", "writable", "image", "private", "mapped"]) },

        ["get_nativeaot_info"] = new Dictionary<string, Domain> { ["view"] = Of(["summary", "sections", "types", "type", "methods", "strings"]) },
        ["list_functions"] = new Dictionary<string, Domain> { ["sort"] = Of(["address", "name", "size", "callers"]), ["engine"] = Engine },
        ["disassemble"] = new Dictionary<string, Domain> { ["engine"] = Engine },
        ["inspect_instruction"] = new Dictionary<string, Domain> { ["engine"] = Engine },
        ["search_instructions"] = new Dictionary<string, Domain> { ["engine"] = Engine },
        ["list_globals"] = new Dictionary<string, Domain> { ["engine"] = Engine },
        ["search_native_strings"] = new Dictionary<string, Domain> { ["engine"] = Engine },
        ["list_cpp_classes"] = new Dictionary<string, Domain> { ["engine"] = Of(["auto", "ours", "ghidra"], "built-in", "builtin") },
        ["get_cfg"] = new Dictionary<string, Domain> { ["engine"] = Engine },
        ["find_xrefs"] = new Dictionary<string, Domain> { ["engine"] = Engine, ["direction"] = Of(["to", "from", "both"]), ["kind"] = Of(["any", "code", "data"]) },
        ["native_call_tree"] = new Dictionary<string, Domain> { ["direction"] = Of(["callers", "callees", "both"]), ["calls"] = Of(["all", "direct", "virtual"]), ["engine"] = Engine },
        ["decompile_native"] = new Dictionary<string, Domain> { ["engine"] = DecompilerEngine },
        ["get_native_frame"] = new Dictionary<string, Domain> { ["engine"] = DecompilerEngine },
        ["get_engine_status"] = new Dictionary<string, Domain> { ["engine"] = DecompilerEngine },
        ["define_native"] = new Dictionary<string, Domain> { ["kind"] = Of(["code", "function", "undefine", "data"]), ["engine"] = DecompilerEngine },
        ["set_native_operand"] = new Dictionary<string, Domain> { ["display"] = Of(Native.Providers.NativeOperandEdit.Displays), ["engine"] = DecompilerEngine },
        ["set_native_stack_var"] = new Dictionary<string, Domain> { ["showDecompile"] = ShowDecompile, ["engine"] = DecompilerEngine },
        ["set_native_type"] = new Dictionary<string, Domain> { ["showDecompile"] = ShowDecompile, ["engine"] = DecompilerEngine },
        ["set_native_local"] = new Dictionary<string, Domain> { ["showDecompile"] = ShowDecompile, ["engine"] = DecompilerEngine },
        ["declare_native_types"] = new Dictionary<string, Domain> { ["engine"] = DecompilerEngine },
        ["list_native_types"] = new Dictionary<string, Domain> { ["engine"] = DecompilerEngine, ["kind"] = Of(["struct", "union", "udt", "enum", "typedef", "func", "ptr"]), ["sort"] = Of(["name", "size"], "ordinal") },
        ["get_native_type"] = new Dictionary<string, Domain>
        {
            ["source"] = Of(["auto", "pdb", "rtti", "il2cpp", "engine"]), ["format"] = Of(["table", "c"]), ["engine"] = DecompilerEngine,
        },
        ["ida_python"] = new Dictionary<string, Domain> { ["engine"] = IdaEngine },
        ["export_engine_database"] = new Dictionary<string, Domain> { ["engine"] = IdaEngine },
        ["find_virtual_calls"] = new Dictionary<string, Domain> { ["status"] = Of(["exact", "possible", "unresolved"]) },
        ["trace_native_values"] = new Dictionary<string, Domain> { ["direction"] = Of(["backward", "forward", "both"], "back", "fwd"), ["engine"] = Engine },
        ["resolve_call_targets"] = new Dictionary<string, Domain>
        {
            ["scope"] = Of(["site", "function", "image"]),
            ["status"] = Of(["all", "resolved", "possible", "ambiguous", "unresolved", "indirect"]),
            ["engine"] = Engine,
        },
        ["analyze_native_function"] = new Dictionary<string, Domain> { ["engine"] = DecompilerEngine },
        ["search_pdb_symbols"] = new Dictionary<string, Domain> { ["kind"] = Of(["function", "data", "public", "all"], "functions", "publics") },
        ["make_code_pattern"] = new Dictionary<string, Domain> { ["anchor"] = Of(["auto", "address", "reference", "xrefs", "range"]), ["engine"] = Engine, ["format"] = Of(["ida", "x64dbg", "mask", "bitmask"]) },
        ["compare_native_images"] = new Dictionary<string, Domain> { ["view"] = Of(["pairs", "changed", "unmatched", "ambiguous"]) },
        ["diff_function"] = new Dictionary<string, Domain> { ["side"] = Of(["old", "new"]), ["view"] = Of(["asm", "pseudocode"]), ["engine"] = DecompilerEngine },
        ["export_native_patches"] = new Dictionary<string, Domain> { ["format"] = Of(["ida", "dif", "ips", "ips32", "json"], "idapython", "py", "diff") },
        ["export_native_annotations"] = new Dictionary<string, Domain> { ["format"] = Of(["ida", "ghidra", "json", "header"], "idapython", "idc", "h") },
        ["rename_native"] = new Dictionary<string, Domain> { ["showDecompile"] = ShowDecompile, ["engine"] = DecompilerEngine },
        ["comment_native"] = new Dictionary<string, Domain> { ["scope"] = Of(["auto", "line", "eol", "pre", "plate", "pseudocode", "function"], "disassembly", "repeatable", "decompiler", "func"), ["engine"] = DecompilerEngine },
        ["patch_bytes"] = new Dictionary<string, Domain> { ["type"] = Of(["i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64", "ptr", "i16be", "u16be", "i32be", "u32be", "i64be", "u64be", "f32be", "f64be"]), ["relocations"] = Relocations, ["stubMode"] = StubMode, ["placement"] = Placement },
        ["patch_asm"] = new Dictionary<string, Domain> { ["relocations"] = Relocations, ["stubMode"] = StubMode, ["placement"] = Placement },
        ["record_note"] = new Dictionary<string, Domain> { ["kind"] = NoteKind, ["status"] = NoteStatus },
        ["update_note"] = new Dictionary<string, Domain> { ["kind"] = NoteKind, ["status"] = NoteStatus },
        ["list_notes"] = new Dictionary<string, Domain> { ["kind"] = NoteKind, ["status"] = Of([.. NoteStatus.Values, "all"]) },
        ["update_to_new_build"] = new Dictionary<string, Domain>
        {
            ["stubPlacement"] = Placement,
            ["category"] = Of(["names", "pdb", "il2cpp_names", "patches", "patterns", "il2cpp_mapping", "notes", "dotnet"]),
            ["outcome"] = Of(["carried", "would_carry", "already_present", "refused", "not_applicable", "ambiguous"]),
        },
    };

    public static Domain? Find(string? tool, string parameter) =>
        tool != null && Table.TryGetValue(tool, out var parameters) && parameters.TryGetValue(parameter, out var domain) ? domain : null;

    /// <summary>Adds "enum" to each listed parameter's schema (with null when the parameter takes null).</summary>
    public static void Apply(IEnumerable<McpServerTool> tools)
    {
        foreach (var tool in tools)
        {
            var t = tool.ProtocolTool;
            if (!Table.TryGetValue(t.Name, out var parameters)) continue;
            var schema = JsonNode.Parse(t.InputSchema.GetRawText())!.AsObject();
            foreach (var (name, domain) in parameters)
            {
                if (schema["properties"]?[name] is not JsonObject property) continue;
                var values = new JsonArray(domain.Values.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray());
                if (property["type"] is JsonArray types && types.Any(x => (string?)x == "null")) values.Add(null);
                property["enum"] = values;
            }
            t.InputSchema = JsonSerializer.SerializeToElement(schema);
        }
    }
}
