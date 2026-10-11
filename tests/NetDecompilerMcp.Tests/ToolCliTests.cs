using System.Text.Json.Nodes;
using NetDecompilerMcp.Setup;

namespace NetDecompilerMcp.Tests;

/// <summary>The tool CLI: commands from the catalog, argument typing, output forms and exit codes, run in process.</summary>
[Collection(InProcessCatalogCollection.Name)]
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
            Assert.Contains("NetDecompilerMcp " + name, text, StringComparison.Ordinal);
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

        // Structured output as JSON, the whole record with --json.
        (code, output, _) = await Run(["call", "list_types", .. server, "--structured"]);
        Assert.Equal(0, code);
        Assert.Contains(JsonNode.Parse(output)!["items"]!.AsArray(), i => (string?)i!["fullName"] == "Fixture.Model.Account");

        (code, output, _) = await Run(["list_types", .. server, "--json", "namespace=Fixture.Model"]);
        Assert.Equal(0, code);
        var record = JsonNode.Parse(output)!;
        Assert.False((bool)record["isError"]!);
        Assert.NotNull(record["structured"]);

        // A tool error: exit 1, the text on stderr; --json carries the parsed error record.
        (code, output, error) = await Run(["decompile_member", .. server, "member=Fixture.Model.Account::Nope"]);
        Assert.Equal(1, code);
        Assert.Equal("", output);
        Assert.Contains("Error (not_found)", error);
        (code, output, _) = await Run(["decompile_member", .. server, "member=Nope.Nope", "--json"]);
        Assert.Equal(1, code);
        Assert.Equal("not_found", (string?)JsonNode.Parse(output)!["error"]!["code"]);

        // The server's invalid_argument (an undeclared parameter, with the closest name) is a usage error.
        (code, _, error) = await Run(["decompile_member", .. server, "membr=X"]);
        Assert.Equal(2, code);
        Assert.Contains("member", error);

        (code, _, error) = await Run(["decompile_member", "--structured"]);
        Assert.Equal(2, code);
        Assert.Contains("no structured output", error);
    }

    [Fact]
    public async Task Cancellation_ExitsWith130()
    {
        using var cancel = new CancellationTokenSource();
        await cancel.CancelAsync();
        var io = new CliIo(new StringWriter(), new StringWriter(), TextReader.Null);
        Assert.Equal(130, await ToolCli.RunAsync(["list_assemblies"], io, cancel.Token));
    }
}
