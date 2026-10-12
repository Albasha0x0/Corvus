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
        Assert.Equal("--max-output", Field("budget", "page", "source"));
        Assert.StartsWith("20,000 characters", Field("budget", "page"));
        Assert.Equal("9,500 tokens per result", Field("budget", "ceiling"));
        Assert.Equal("Unknown client (unknown)", Field("budget", "client"));
        Assert.Equal("default", Field("budget", "client", "source"));
        Assert.Equal("default", Field("budget", "deadline", "source"));
        Assert.Equal("full", Field("budget", "profile"));
        Assert.NotNull(Field("calls", "joined"));
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

    [Fact]
    public async Task TheBudgetSection_ShowsTheClientProfileAndItsSources()
    {
        var (code, output, error) = await ToolCliTests.Run("server_status", "--json", "--no-index", "--client", "codex", "--client-timeout", "120", "--toolsets", "lean");
        Assert.True(code == 0, error);
        var budget = JsonNode.Parse(output)!["structured"]!["sections"]!.AsArray().Single(s => (string)s!["name"]! == "budget")!["fields"]!.AsArray();
        string? Field(string name, string part = "value") => (string?)budget.FirstOrDefault(f => (string)f!["name"]! == name)?[part];
        Assert.Equal(("Codex (codex)", "--client"), (Field("client"), Field("client", "source")));
        Assert.Equal("lean", Field("profile"));
        Assert.Equal(("9,500 tokens per result", "codex"), (Field("ceiling"), Field("ceiling", "source")));
        Assert.StartsWith("115 s per call: codex waits 120 s", Field("deadline"));
        Assert.Equal("--client-timeout", Field("deadline", "source"));
    }
}
