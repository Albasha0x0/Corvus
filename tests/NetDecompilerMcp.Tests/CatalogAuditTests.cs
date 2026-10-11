using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// The generated catalog passes the strictest schema consumers (function-calling APIs that reject root unions, compile
/// patterns as ECMAScript or RE2, and cap schema sizes), and its size grows only by a deliberate decision.
/// </summary>
[Collection(InProcessCatalogCollection.Name)]
public class CatalogAuditTests
{
    /// <summary>Largest input schema of one tool, compact UTF-8 JSON.</summary>
    private const int MaxInputSchemaBytes = 8 * 1024;

    /// <summary>Model-facing catalog bytes (names, descriptions, input schemas); 181,415 at 119 tools with .NET dump decoding; the crash tools to come. Raise only deliberately.</summary>
    private const int MaxModelFacingBytes = 192_000;

    private static readonly List<JsonNode> Tools = Catalog.OfThisBuild().Tools;

    private static int Bytes(JsonNode? node) => node == null ? 0 : Encoding.UTF8.GetByteCount(node.ToJsonString());

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
