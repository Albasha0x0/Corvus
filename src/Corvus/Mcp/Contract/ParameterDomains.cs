using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol.Server;

namespace Corvus.Mcp;

/// <summary>
/// The closed value sets of string parameters, advertised as JSON Schema "enum" (applied at startup by <see cref="Apply"/>)
/// and checked by <see cref="ArgumentCheck"/> before the tool runs. Audited against each tool's parser: Values are the
/// documented spellings, Aliases the other spellings the parser also takes (accepted, not advertised). Matching ignores
/// case and surrounding white space; an empty string is passed to the tool, which treats it as the default.
/// Comma-separated lists and open sets (a status or a reason code) are not listed.
/// </summary>
public static partial class ParameterDomains
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

    /// <summary>By family, then tool, then parameter; the rows are in the per-family files.</summary>
    internal static readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, IReadOnlyDictionary<string, Domain>>> ByFamily =
        new Dictionary<string, IReadOnlyDictionary<string, IReadOnlyDictionary<string, Domain>>>(StringComparer.Ordinal)
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

    /// <summary>By tool, then parameter.</summary>
    public static readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, Domain>> Table = FamilyTables.Join(ByFamily);

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
