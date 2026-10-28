using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>The catalog passes the strictest schema consumers (no root unions, ECMAScript and RE2 patterns, size caps) and grows only by decision.</summary>
public class CatalogAuditTests
{
    /// <summary>Largest input schema of one tool, compact UTF-8 JSON.</summary>
    private const int MaxInputSchemaBytes = 8 * 1024;

    /// <summary>Ceiling of the model-facing catalog bytes (names, descriptions, input schemas): the measured size rounded up to 50; trim descriptions before raising it.</summary>
    private const int MaxModelFacingBytes = 153_100;

    /// <summary>Ceiling of the full profile's whole tools/list result: the measured size rounded up to 50.</summary>
    private const int MaxToolsListBytes = 298_750;

    [Fact]
    public void Tools_list_stays_within_its_ceiling()
    {
        var list = new JsonObject { ["tools"] = new JsonArray([.. Catalog.OfThisBuild(Toolsets.All).Tools]) };
        var bytes = Encoding.UTF8.GetByteCount(list.ToJsonString());
        Assert.True(bytes <= MaxToolsListBytes, $"tools/list is {bytes:N0} bytes, over {MaxToolsListBytes:N0}: trim descriptions or output schemas");
    }

    private static readonly List<JsonNode> Tools = Catalog.OfThisBuild().Tools;

    private static int Bytes(JsonNode? node) => node == null ? 0 : Encoding.UTF8.GetByteCount(node.ToJsonString());

    /// <summary>The tools made in parallel at startup are the SDK's WithToolsFromAssembly tools: same order, names and schemas.</summary>
    [Fact]
    public void Tools_made_in_parallel_match_the_SDK_registration()
    {
        static List<string> Made(Action<IMcpServerBuilder> add)
        {
            var services = new ServiceCollection();
            add(services.AddMcpServer());
            using var provider = services.BuildServiceProvider();
            return [.. provider.GetServices<ModelContextProtocol.Server.McpServerTool>()
                .Select(t => $"{t.ProtocolTool.Name} {t.ProtocolTool.InputSchema.GetRawText()} {t.ProtocolTool.OutputSchema?.GetRawText()}")];
        }
        var assembly = typeof(Catalog).Assembly;
        var sdk = Made(b => b.WithToolsFromAssembly(assembly, Catalog.ToolSerializerOptions));
        var parallel = Made(b => b.WithToolsInParallel(assembly, Catalog.ToolSerializerOptions));
        Assert.True(sdk.Count > 100);
        Assert.Equal(sdk, parallel);
    }

    [Fact]
    public void Input_schemas_are_flat_objects()
    {
        foreach (var tool in Tools)
        {
            var name = (string)tool["name"]!;
            var input = tool["inputSchema"]!.AsObject();
            Assert.True((string?)input["type"] == "object", $"{name}: input schema is not an object");
            foreach (var union in new[] { "anyOf", "oneOf", "allOf", "not", "if", "$ref" })
                Assert.False(input.ContainsKey(union), $"{name}: input schema has a root {union}");
            if (tool["outputSchema"] is JsonObject output)
                Assert.True((string?)output["type"] == "object", $"{name}: output schema is not an object");
        }
    }

    /// <summary>E1: every tool, in every toolset, stays inside the schema subset the strictest model gateways accept.</summary>
    [Fact]
    public void Schemas_pass_the_strictest_gateways()
    {
        var problems = SchemaGate.Check(Catalog.OfThisBuild(Toolsets.All).Tools);
        Assert.True(problems.Count == 0, string.Join("\n", problems.Take(30)));
    }

    [Fact]
    public void Schema_gate_names_the_tool_and_keyword()
    {
        var tool = JsonNode.Parse("""
            {"name":"t","inputSchema":{"type":"object","properties":{"a":{"anyOf":[{"type":"string"}]},"b":{"type":"array"},"c":{"type":["string","null"]}}},
             "outputSchema":{"type":"object","properties":{"rows":{"type":"array","items":{"$ref":"#/properties/x"}}}}}
            """);
        var problems = SchemaGate.Check([tool]).Select(p => p.ToString()).ToList();
        Assert.Contains("t/a: keyword anyOf", problems);
        Assert.Contains("t/b: array without items", problems);
        Assert.Contains("t/c: type is a union", problems);
        Assert.Contains("t#output/rows/items: keyword $ref", problems);
    }

    [Fact]
    public void Every_output_array_declares_its_item_type()
    {
        var untyped = new List<string>();
        foreach (var tool in Catalog.OfThisBuild(Toolsets.All).Tools)
            Untyped(tool["outputSchema"], $"{tool["name"]}", untyped);
        foreach (var (name, schema) in Catalog.DescribedOutputSchemas())
            Untyped(JsonNode.Parse(schema.GetRawText()), $"{name} (described)", untyped);
        Assert.True(untyped.Count == 0, string.Join("\n", untyped.Take(30)));

        static void Untyped(JsonNode? node, string path, List<string> found)
        {
            if (node is JsonObject o)
            {
                if (o["type"] is JsonValue t && (string?)t == "array" || o["type"] is JsonArray types && types.Any(x => (string?)x == "array"))
                    if (o["items"] is not JsonObject { Count: > 0 }) found.Add($"{path}: array without an item type");
                foreach (var (key, child) in o) Untyped(child, $"{path}/{key}", found);
            }
            else if (node is JsonArray a)
                for (int i = 0; i < a.Count; i++) Untyped(a[i], $"{path}/{i}", found);
        }
    }

    [Fact]
    public void Schemas_carry_no_null_defaults()
    {
        foreach (var tool in Tools)
            foreach (var schema in new[] { "inputSchema", "outputSchema" })
                Assert.True(NullDefault(tool[schema]) is null, $"{tool["name"]}.{schema}: default null at {NullDefault(tool[schema])}");

        static string? NullDefault(JsonNode? node, string path = "#") => node switch
        {
            JsonObject o when o.TryGetPropertyValue("default", out var d) && d is null => path,
            JsonObject o => o.Select(p => NullDefault(p.Value, $"{path}/{p.Key}")).FirstOrDefault(p => p != null),
            JsonArray a => a.Select((v, i) => NullDefault(v, $"{path}/{i}")).FirstOrDefault(p => p != null),
            _ => null,
        };
    }

    [Fact]
    public void Schema_sizes_stay_within_their_ceilings()
    {
        long modelFacing = 0;
        foreach (var tool in Tools)
        {
            var name = (string)tool["name"]!;
            var input = Bytes(tool["inputSchema"]);
            Assert.True(input <= MaxInputSchemaBytes, $"{name}: input schema is {input} bytes, over {MaxInputSchemaBytes}");
            modelFacing += Encoding.UTF8.GetByteCount(name) + Encoding.UTF8.GetByteCount((string?)tool["description"] ?? "") + input;
        }
        Assert.True(modelFacing <= MaxModelFacingBytes,
            $"the model-facing catalog is {modelFacing:N0} bytes, over the recorded {MaxModelFacingBytes:N0}: trim descriptions or raise the ceiling deliberately");
    }

    /// <summary>S8.1 per-tool limits, compact UTF-8 bytes.</summary>
    private const int MaxDescriptionBytes = 600, MaxParameterBytes = 160, MaxInputSchemaGuardBytes = 13_312, MaxOutputSchemaBytes = 4 * 1024;

    [Fact]
    public void Tools_stay_within_their_limits()
    {
        var descriptions = new Dictionary<string, string>();
        var parameters = new Dictionary<string, string>();
        var outputs = new Dictionary<string, string>();
        foreach (var tool in Tools)
        {
            var name = (string)tool["name"]!;
            Assert.Matches("^[a-z0-9_]{1,40}$", name);
            Assert.True(Bytes(tool["inputSchema"]) <= MaxInputSchemaGuardBytes, $"{name}: input schema over {MaxInputSchemaGuardBytes} bytes");
            if (Encoding.UTF8.GetByteCount((string?)tool["description"] ?? "") is var d && d > MaxDescriptionBytes) descriptions[name] = $"{d} bytes";
            foreach (var (p, schema) in tool["inputSchema"]!["properties"] as JsonObject ?? [])
                if (Encoding.UTF8.GetByteCount((string?)schema?["description"] ?? "") is var b && b > MaxParameterBytes) parameters[$"{name}.{p}"] = $"{b} bytes";
            if (Bytes(tool["outputSchema"]) is var o && o > MaxOutputSchemaBytes) outputs[name] = $"{o} bytes";
        }
        Ratchet.Check("description-bytes", $"a description is at most {MaxDescriptionBytes} bytes (S8.1)", descriptions);
        Ratchet.Check("parameter-bytes", $"a parameter description is at most {MaxParameterBytes} bytes (S8.1)", parameters);
        Ratchet.Check("output-schema-bytes", $"an output schema is at most {MaxOutputSchemaBytes} bytes in tools/list (S8.1)", outputs);
    }

    /// <summary>Per profile: tool count and the ceiling of model-facing bytes, the measured size rounded up to 50.</summary>
    [Theory]
    [InlineData(Toolsets.Lean, 40, 37_550)]
    [InlineData(Toolsets.CoreName, 100, 89_300)]
    public void Profiles_stay_within_their_ceilings(string profile, int maxTools, int maxModelFacing)
    {
        var tools = Catalog.OfThisBuild(Toolsets.Parse(profile)).Tools;
        Assert.True(tools.Count <= maxTools, $"{profile}: {tools.Count} tools, over {maxTools}");
        long bytes = tools.Sum(t => Encoding.UTF8.GetByteCount((string)t["name"]!) + Encoding.UTF8.GetByteCount((string?)t["description"] ?? "") + Bytes(t["inputSchema"]));
        Assert.True(bytes <= maxModelFacing, $"{profile}: the model-facing catalog is {bytes:N0} bytes, over {maxModelFacing:N0}");
        Assert.Equal(Profiles.ToolsOf(Toolsets.Parse(profile)).Order(StringComparer.Ordinal), tools.Select(t => (string)t["name"]!).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Every_tool_has_a_family_and_a_contract_row()
    {
        foreach (var tool in Tools.Select(t => (string)t["name"]!))
        {
            Assert.True(Toolsets.FamilyOf(tool) != null, $"{tool}: no family (Core/Toolsets.cs)");
            Assert.True(ToolContract.Table.ContainsKey(tool), $"{tool}: no contract row (Mcp/Contract), which records its lean and core membership");
        }
    }

    [Fact]
    public void Patterns_are_portable()
    {
        foreach (var tool in Tools)
            foreach (var schema in new[] { tool["inputSchema"], tool["outputSchema"] })
                foreach (var (path, pattern) in Patterns(schema, (string)tool["name"]!))
                {
                    Assert.True(PortabilityProblem(pattern) is null, $"{path}: '{pattern}' {PortabilityProblem(pattern)}");
                    var ex = Record.Exception(() => new Regex(pattern, RegexOptions.ECMAScript));
                    Assert.True(ex is null, $"{path}: '{pattern}' is not a valid ECMAScript pattern: {ex?.Message}");
                }
    }

    [Theory]
    [InlineData(@"^[0-9a-f]+$", null)]
    [InlineData(@"^\d{1,3}(\.\d+)?$", null)]
    [InlineData(@"a(?=b)", "lookaround")]
    [InlineData(@"(?<!x)y", "lookaround")]
    [InlineData(@"(a)\1", "backreference or octal escape")]
    [InlineData(@"\0", "backreference or octal escape")]
    [InlineData(@"(?>a)", "atomic group")]
    [InlineData(@"a++", "possessive quantifier")]
    [InlineData(@"[+*]+", null)]
    public void The_portability_checker_names_each_unportable_construct(string pattern, string? problem) => Assert.Equal(problem, PortabilityProblem(pattern));

    [Fact]
    public void Error_results_carry_no_structured_content()
    {
        Assert.Null(ErrorResult.From(new ToolError(ErrorCode.NotFound, "x"), "t").StructuredContent);
        Assert.Null(ErrorResult.Internal(new InvalidOperationException("x"), "t").StructuredContent);
        Assert.Null(ErrorResult.Of("internal", false, "x", null, null, "t").StructuredContent);
        // CallFilter strips structuredContent from error results (ResponseBudgetTests); McpProtocolTests.ErrorShapeProblems checks it over the wire.
    }

    private static IEnumerable<(string Path, string Pattern)> Patterns(JsonNode? node, string path)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var (key, value) in o)
                {
                    if (key == "pattern" && value is JsonValue v && v.TryGetValue<string>(out var p)) yield return (path, p);
                    foreach (var inner in Patterns(value, $"{path}.{key}")) yield return inner;
                }
                break;
            case JsonArray a:
                for (int i = 0; i < a.Count; i++)
                    foreach (var inner in Patterns(a[i], $"{path}[{i}]")) yield return inner;
                break;
        }
    }

    /// <summary>Features outside the common subset of ECMAScript and RE2 (RE2 has no lookaround, backreferences, atomic groups or possessive quantifiers; octal escapes differ).</summary>
    private static string? PortabilityProblem(string pattern)
    {
        bool inClass = false;
        for (int i = 0; i < pattern.Length; i++)
        {
            char c = pattern[i];
            if (c == '\\' && i + 1 < pattern.Length)
            {
                char n = pattern[++i];
                if (char.IsAsciiDigit(n) || n == 'k') return "backreference or octal escape";
                continue;
            }
            if (inClass) { inClass = c != ']'; continue; }
            if (c == '[') { inClass = true; continue; }
            if (c == '(' && i + 2 < pattern.Length && pattern[i + 1] == '?')
            {
                var rest = pattern[(i + 2)..];
                if (rest.StartsWith('=') || rest.StartsWith('!') || rest.StartsWith("<=", StringComparison.Ordinal) || rest.StartsWith("<!", StringComparison.Ordinal)) return "lookaround";
                if (rest.StartsWith('>')) return "atomic group";
            }
            if (c is '*' or '+' or '?' or '}' && i + 1 < pattern.Length && pattern[i + 1] == '+')
                return "possessive quantifier";
        }
        return null;
    }
}
