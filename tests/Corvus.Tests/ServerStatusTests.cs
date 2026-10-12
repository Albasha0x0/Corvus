using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>server_status (S14.2): the record matches its output schema and carries the status sections.</summary>
[Collection(InProcessCatalogCollection.Name)]
public class ServerStatusTests
{
    [Fact]
    public async Task StatusMatchesItsSchemaAndListsTheSections()
    {
        var (code, output, error) = await ToolCliTests.Run("server_status", "--json", "--no-index", "--max-output", "20000");
        Assert.True(code == 0, error);
        var structured = JsonNode.Parse(output)!["structured"]!;
        var schema = JsonSerializer.SerializeToElement(Corvus.Setup.ToolCli.FindTool("server_status")!["outputSchema"]);
        var problems = OutputSchema.Validate(schema, JsonSerializer.SerializeToElement(structured));
        Assert.True(problems.Count == 0, string.Join("; ", problems));

        var sections = structured["sections"]!.AsArray().ToDictionary(s => (string)s!["name"]!, s => s!["fields"]!.AsArray());
        Assert.Equal(["budget", "results", "caches", "calls", "workers", "run"], sections.Keys);
        string? Field(string section, string name, string part = "value") =>
            (string?)sections[section].FirstOrDefault(f => (string)f!["name"]! == name)?[part];
        Assert.Equal("--max-output", Field("budget", "ceiling", "source"));
        Assert.StartsWith("20,000 characters", Field("budget", "ceiling"));
        Assert.Equal("default", Field("budget", "deadline", "source"));
        Assert.NotNull(Field("budget", "profile"));
        Assert.NotNull(Field("budget", "delivery"));
        Assert.NotNull(Field("results", "mode"));
        Assert.Contains("characters", Field("results", "memory"));
        Assert.NotNull(Field("calls", "leftover"));
        Assert.Equal("free", Field("calls", "workspaceLock"));
        Assert.Equal(CallLog.RunId, Field("run", "runId"));
        Assert.Equal(Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture), Field("run", "pid"));
        // moved out of the record's top level into the budget section
        Assert.Null(structured["maxOutputChars"]);
    }
}
