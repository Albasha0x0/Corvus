using System.Text.Json.Nodes;
using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>The tool CLI: commands from the catalog, argument typing, output forms and exit codes, run in process.</summary>
public class ToolCliTests
{
    internal static async Task<(int Code, string Out, string Error)> RunWithInput(string stdin, params string[] args)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var code = await ToolCli.RunAsync(args, new CliIo(output, error, new StringReader(stdin)), CancellationToken.None);
        return (code, output.ToString(), error.ToString());
    }

    internal static Task<(int Code, string Out, string Error)> Run(params string[] args) => RunWithInput("", args);

    [Fact]
    public void EveryToolResolvesAndDescribes()
    {
        Assert.NotEmpty(ToolCli.CatalogTools);
        foreach (var tool in ToolCli.CatalogTools)
        {
            var name = (string)tool["name"]!;
            Assert.Same(tool, ToolCli.FindTool(name.Replace('_', '-')));
            Assert.Same(tool, ToolCli.FindTool(name.ToUpperInvariant()));
            Assert.True(ToolCli.Handles([name]), name);
            var text = ToolCli.DescribeTool(tool);
            Assert.StartsWith(name + ": ", text, StringComparison.Ordinal);
            Assert.Contains(ToolCli.Parameters(tool).Count == 0 ? "Parameters: none." : "Parameters:\n", text, StringComparison.Ordinal);
            foreach (var p in ToolCli.Parameters(tool)) Assert.Contains($"  {p.Name} (", text, StringComparison.Ordinal);
            Assert.Contains("corvus " + name, text, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void CommandWordsAreNotServerStarts()
    {
        Assert.False(ToolCli.Handles([]));
        Assert.False(ToolCli.Handles(["--load", "app.dll"]));
        Assert.False(ToolCli.Handles(["install"]));
        Assert.False(ToolCli.Handles(["help"]));
        Assert.True(ToolCli.Handles(["help", "decompile_member"]));
        Assert.True(ToolCli.Handles(["tools"]));
        Assert.True(ToolCli.Handles(["not_a_tool"]));
    }

    [Fact]
    public void ValuesAreTypedByTheSchema()
    {
        var schema = JsonNode.Parse("""
            {"type":"object","properties":{
              "n":{"type":"integer"},"flag":{"type":"boolean"},"names":{"type":"array","items":{"type":"string"}},
              "ids":{"type":"array","items":{"type":"integer"}},"text":{"type":["string","null"]},"ratio":{"type":"number"}}}
            """);
        var file = Path.GetTempFileName();
        try
        {
            File.WriteAllText(file, "return 1;");
            var a = CliArgs.Parse(["n=0x10", "flag=yes", "names=a, b", "ids=[1,2]", "text=@" + file, "raw:={\"k\":[1]}", "ratio=0.5", "fromStdin=@-", "--args", """{"n":1,"extra":true}"""]);
            var args = a.ToolArguments(schema, new StringReader("piped"));
            string Json(string key) => System.Text.Json.JsonSerializer.Serialize(args[key]);
            Assert.Equal("16", Json("n")); // the assignment wins over --args
            Assert.Equal("true", Json("flag"));
            Assert.Equal("""["a","b"]""", Json("names"));
            Assert.Equal("[1,2]", Json("ids"));
            Assert.Equal("\"return 1;\"", Json("text"));
            Assert.Equal("""{"k":[1]}""", Json("raw"));
            Assert.Equal("0.5", Json("ratio"));
            Assert.Equal("\"piped\"", Json("fromStdin"));
            Assert.Equal("true", Json("extra"));
        }
        finally { File.Delete(file); }

        Assert.Throws<UsageException>(() => CliArgs.Parse(["n=ten"]).ToolArguments(schema, TextReader.Null));
        Assert.Throws<UsageException>(() => CliArgs.Parse(["flag=maybe"]).ToolArguments(schema, TextReader.Null));
        Assert.Throws<UsageException>(() => CliArgs.Parse(["--args", "[1]"]).ToolArguments(schema, TextReader.Null));
        Assert.Throws<UsageException>(() => CliArgs.Parse(["-x"]));
    }

    [Fact]
    public void ServerOptionsAreSeparatedFromArguments()
    {
        var a = CliArgs.Parse(["decompile_member", "--load", "app.dll", "member=X", "--no-index", "--json", "--timeout", "30"]);
        Assert.Equal(["decompile_member"], a.Positionals);
        Assert.Equal(["--load", "app.dll", "--no-index", "--timeout", "30"], a.ServerArgs);
        Assert.True(a.Json);
        var options = a.Server();
        Assert.Equal(["app.dll"], options.Preload);
        Assert.False(options.WatchFiles);
        Assert.True(options.MaxOutputChars > 1_000_000); // whole results, not pages
        Assert.Equal(60_000, CliArgs.Parse(["--max-output", "60000"]).Server().MaxOutputChars);
        Assert.Throws<UsageException>(() => CliArgs.Parse(["--bogus"]).Server());
        // One call builds indexes only on demand; a batch session keeps the background pass.
        Assert.False(CliArgs.Parse(["get_pe_info"]).Server(oneShot: true).BackgroundIndexing);
        Assert.True(CliArgs.Parse(["batch", "steps.json"]).Server().BackgroundIndexing);
        Assert.Equal("cursor", CliArgs.Parse(["--client", "cursor"]).Server().Client);
        foreach (var option in Core.ServerOptions.ValueOptions)
            Assert.Contains("Missing value", Assert.Throws<ArgumentException>(() => Core.ServerOptions.Parse([option])).Message);
    }

    [Fact]
    public void ErrorCodesMapToExitCodes()
    {
        int Code(string code) => ToolCli.ExitCode(new JsonObject { ["code"] = code });
        Assert.Equal(1, Code("not_found"));
        Assert.Equal(1, Code("limit_exceeded"));
        Assert.Equal(2, Code("invalid_argument"));
        Assert.Equal(3, Code("provider_unavailable"));
        Assert.Equal(3, Code("unsupported"));
        Assert.Equal(124, Code("timeout"));
        Assert.Equal(1, ToolCli.ExitCode(null));
    }

    [Fact]
    public async Task ToolsAndDescribe_NeedNoServer()
    {
        var (code, output, _) = await Run("tools");
        Assert.Equal(0, code);
        Assert.Contains("decompile_member", output);
        Assert.Contains($"{ToolCli.CatalogTools.Count} tools.", output);

        (code, output, _) = await Run("tools", "xref", "--json");
        Assert.Equal(0, code);
        var rows = JsonNode.Parse(output)!.AsArray();
        Assert.Contains(rows, r => (string)r!["name"]! == "find_xrefs" && (string?)r["toolset"] == "native");

        (code, output, _) = await Run("help", "decompile-member");
        Assert.Equal(0, code);
        Assert.Contains("member (string, required)", output);

        (code, output, _) = await Run("describe", "guide");
        Assert.Equal(0, code);
        Assert.Contains("guide (prompt)", output);

        var (bad, _, error) = await Run("decompile_membr");
        Assert.Equal(2, bad);
        Assert.Contains("Did you mean decompile_member", error);
    }

    [Fact]
    public async Task Call_RunsToolsWithExitCodes()
    {
        string[] server = ["--load", Env.FixturePath, "--no-index"];

        var (code, output, error) = await Run(["decompile-member", .. server, "member=Fixture.Model.Account::Charge"]);
        Assert.True(code == 0, error);
        Assert.Contains("Charge(", output);

        // Structured output only; the whole record with --json.
        (code, output, _) = await Run(["call", "list_types", .. server, "--structured"]);
        Assert.Equal(0, code);
        Assert.Contains(JsonNode.Parse(output)!["items"]!.AsArray(), i => (string?)i!["name"] == "Fixture.Model.Account");
        (code, output, _) = await Run(["list_types", .. server, "--json", "namespace=Fixture.Model"]);
        Assert.Equal(0, code);
        Assert.False((bool)JsonNode.Parse(output)!["isError"]!);
        Assert.NotEmpty(JsonNode.Parse(output)!["structured"]!["items"]!.AsArray());

        // A tool error: exit 1, the text on stderr; --json carries the parsed error record.
        (code, output, error) = await Run(["decompile_member", .. server, "member=Fixture.Model.Account::Nope"]);
        Assert.Equal(1, code);
        Assert.Equal("", output);
        Assert.Contains("Error (not_found)", error);
        (code, output, _) = await Run(["decompile_member", .. server, "member=Nope.Nope", "--json"]);
        Assert.Equal(1, code);
        var record = JsonNode.Parse(output)!;
        Assert.True((bool)record["isError"]!);
        Assert.Equal("not_found", (string?)record["error"]!["code"]);

        // The server's invalid_argument (an undeclared parameter, with the closest name) is a usage error.
        (code, _, error) = await Run(["decompile_member", .. server, "membr=X"]);
        Assert.Equal(2, code);
        Assert.Contains("member", error);

        // every tool has an output schema (S4), so --structured applies to each
        Assert.DoesNotContain(Corvus.Setup.ToolCli.CatalogTools, t => t["outputSchema"] == null);
    }

    [Fact]
    public async Task Batch_KeepsOneSessionAcrossSteps()
    {
        var path = System.Text.Json.JsonSerializer.Serialize(Env.FixturePath);
        var steps = $$$"""
            # the fixture is loaded by the first step only
            {"tool": "load-assembly", "args": {"path": {{{path}}}}}
            {"tool": "decompile_member", "args": {"member": "Fixture.Model.Account::Charge"}}
            {"tool": "decompile_member", "arguments": {"member": "Nope.Nope"}}
            {"tool": "list_assemblies"}
            """;
        var (code, output, _) = await RunWithInput(steps, "batch", "-", "--no-index");
        Assert.Equal(1, code); // the first failed step's code; later steps still run
        Assert.Contains("=== [2/4] decompile_member", output);
        Assert.Contains("Charge(", output);
        Assert.Contains("=== [3/4] decompile_member (error)", output);
        Assert.Contains("=== [4/4] list_assemblies", output);

        string error;
        (code, output, error) = await RunWithInput(steps, "batch", "-", "--no-index", "--json", "--stop-on-error");
        Assert.Equal(1, code);
        var records = output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => JsonNode.Parse(l)!).ToList();
        Assert.Equal([1, 2, 3], records.Select(r => (int)r["step"]!));
        Assert.Equal("not_found", (string?)records[2]["error"]!["code"]);
        Assert.Contains("Stopped at step 3 of 4", error);

        Assert.Equal(["a", "b"], ToolCli.ParseBatch("""[{"tool":"list_assemblies","args":{"a":1,"b":null}}]""")[0].Arguments.Keys);
        Assert.Throws<UsageException>(() => ToolCli.ParseBatch("""{"tool":"no_such_tool"}"""));
        Assert.Throws<UsageException>(() => ToolCli.ParseBatch("""{"args":{}}"""));
        Assert.Throws<UsageException>(() => ToolCli.ParseBatch("# nothing"));
    }

    [Fact]
    public async Task PromptsAndResources()
    {
        var (code, output, _) = await Run("prompts");
        Assert.Equal(0, code);
        Assert.Contains($"{ToolCli.CatalogPrompts.Count} prompts.", output);

        (code, output, _) = await Run("prompt", "guide", "topic=builds");
        Assert.Equal(0, code);
        Assert.Equal(Mcp.Guide.Topics["builds"].Trim(), output.Trim());

        (code, output, _) = await Run("resources", "--load", Env.FixturePath, "--no-index");
        Assert.Equal(0, code);
        Assert.Contains("corvus://guide/{topic}", output);

        (code, output, _) = await Run("read", "corvus://guide/edits");
        Assert.Equal(0, code);
        Assert.Contains("save_assembly", output);
    }

    [Fact]
    public void CompletionScriptsNameEveryTool()
    {
        foreach (var shell in ToolCli.Shells)
        {
            var script = ToolCli.CompletionScript(shell);
            foreach (var tool in ToolCli.CatalogTools) Assert.Contains((string)tool["name"]!, script);
            Assert.Contains("member=", script);
            Assert.Contains("uninstall", script);
        }
        Assert.Contains("complete -F", ToolCli.CompletionScript("bash"));
        Assert.Contains("bashcompinit", ToolCli.CompletionScript("zsh"));
        Assert.Contains("Register-ArgumentCompleter", ToolCli.CompletionScript("pwsh"));
    }

    [Fact]
    public async Task Cancellation_ExitsWith130()
    {
        using var cancel = new CancellationTokenSource();
        await cancel.CancelAsync();
        var io = new CliIo(new StringWriter(), new StringWriter(), TextReader.Null);
        Assert.Equal(130, await ToolCli.RunAsync(["list_assemblies"], io, cancel.Token));
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public async Task CtrlCDuringACall_StopsTheToolAndExitsWith130()
    {
        using var dir = new TempDir();
        var assembly = Path.Combine(AppContext.BaseDirectory, "corvus.dll");
        var io = new CliIo(new StringWriter(), new StringWriter(), TextReader.Null);
        using var cancel = new CancellationTokenSource();
        var run = ToolCli.RunAsync(["export_project", "--load", assembly, "assembly=corvus.dll", "outputDirectory=" + Path.Combine(dir.Path, "out")], io, cancel.Token);
        await Task.Delay(1500);
        Assert.False(run.IsCompleted, "the export finished before the cancel; pick a larger input");
        var clock = System.Diagnostics.Stopwatch.StartNew();
        await cancel.CancelAsync();
        Assert.Equal(130, await run.WaitAsync(TimeSpan.FromMinutes(1)));
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(3), $"stopped {clock.Elapsed} after the cancel");
    }
}
