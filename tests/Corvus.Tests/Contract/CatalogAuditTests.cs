using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>
/// The generated catalog passes the strictest schema consumers (function-calling APIs that reject root unions, compile
/// patterns as ECMAScript or RE2, and cap schema sizes), and its size grows only by a deliberate decision.
/// </summary>
public class CatalogAuditTests
{
    /// <summary>Largest input schema of one tool, compact UTF-8 JSON.</summary>
    private const int MaxInputSchemaBytes = 8 * 1024;

    /// <summary>Model-facing catalog bytes (names, descriptions, input schemas): 172,651 at 158 tools before Phase 2; 157,825 at 155 after S-TRIM (no null in input types, implied defaults left out, shorter shared texts); 159,001 at 156 with analyze_js and its module views (C-WEB2 budget +1,200 B); 159,400 with reanalyze_native preset and background (C-ENG2a); 159,600 for C-APL and C-PCAP. Trim descriptions before raising it.</summary>
    private const int MaxModelFacingBytes = 159_600;

    /// <summary>The whole tools/list result of the full profile (§5): 410 KB before Phase 1, 349,663 after Phase 2's family lanes, 296,910 after S-TRIM.</summary>
    private const int MaxToolsListBytes = 300_000;

    [Fact]
    public void ToolsListStaysWithinItsCeiling()
    {
        var list = new JsonObject { ["tools"] = new JsonArray([.. Catalog.OfThisBuild(Toolsets.All).Tools]) };
        var bytes = Encoding.UTF8.GetByteCount(list.ToJsonString());
        Assert.True(bytes <= MaxToolsListBytes, $"tools/list is {bytes:N0} bytes, over {MaxToolsListBytes:N0}: trim descriptions or output schemas");
    }

    private static readonly List<JsonNode> Tools = Catalog.OfThisBuild().Tools;

    private static int Bytes(JsonNode? node) => node == null ? 0 : Encoding.UTF8.GetByteCount(node.ToJsonString());

    /// <summary>The tools made in parallel at startup are the SDK's WithToolsFromAssembly tools: same order, names and schemas.</summary>
    [Fact]
    public void ToolsMadeInParallelMatchTheSdkRegistration()
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
    public void InputSchemasAreFlatObjects()
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

    [Fact]
    public void SchemasCarryNoNullDefaults()
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
    public void SchemaSizesStayWithinTheirCeilings()
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
    public void ToolsStayWithinTheirLimits()
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

    /// <summary>Per profile: tool count and model-facing bytes (names, descriptions, input schemas); measured 40,584 (lean) and 101,524 (core) after S-TRIM, plus about 1%; lean 41,100 for the summarize_file views of C-APL and C-PCAP, 41,250 for read_result evidence and the C-FMT2 views.</summary>
    [Theory]
    [InlineData(Toolsets.Lean, 40, 41_250)]
    [InlineData(Toolsets.CoreName, 100, 102_500)]
    public void ProfilesStayWithinTheirCeilings(string profile, int maxTools, int maxModelFacing)
    {
        var tools = Catalog.OfThisBuild(Toolsets.Parse(profile)).Tools;
        Assert.True(tools.Count <= maxTools, $"{profile}: {tools.Count} tools, over {maxTools}");
        long bytes = tools.Sum(t => Encoding.UTF8.GetByteCount((string)t["name"]!) + Encoding.UTF8.GetByteCount((string?)t["description"] ?? "") + Bytes(t["inputSchema"]));
        Assert.True(bytes <= maxModelFacing, $"{profile}: the model-facing catalog is {bytes:N0} bytes, over {maxModelFacing:N0}");
        Assert.Equal(Profiles.ToolsOf(Toolsets.Parse(profile)).Order(StringComparer.Ordinal), tools.Select(t => (string)t["name"]!).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void EveryToolHasAFamilyAndAContractRow()
    {
        foreach (var tool in Tools.Select(t => (string)t["name"]!))
        {
            Assert.True(Toolsets.FamilyOf(tool) != null, $"{tool}: no family (Core/Toolsets.cs)");
            Assert.True(ToolContract.Table.ContainsKey(tool), $"{tool}: no contract row (Mcp/Contract), which records its lean and core membership");
        }
    }

    [Fact]
    public void PatternsArePortable()
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
    public void PortabilityChecker(string pattern, string? problem) => Assert.Equal(problem, PortabilityProblem(pattern));

    [Fact]
    public void ErrorResultsCarryNoStructuredContent()
    {
        Assert.Null(ErrorResult.From(new ToolError(ErrorCode.NotFound, "x"), "t").StructuredContent);
        Assert.Null(ErrorResult.Internal(new InvalidOperationException("x"), "t").StructuredContent);
        Assert.Null(ErrorResult.Of("internal", false, "x", null, null, "t").StructuredContent);
        // CallFilter strips structuredContent from IsError results a tool returns (ResponseBudgetTests); over the wire,
        // McpProtocolTests.ErrorShapeProblems asserts it for every tool's errors.
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
