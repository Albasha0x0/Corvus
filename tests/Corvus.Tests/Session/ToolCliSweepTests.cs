using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Setup;
using ModelContextProtocol;

namespace Corvus.Tests;

/// <summary>The command line reaches every tool: each <see cref="McpProtocolTests.ToolCases"/> case runs in one batch session and reads back as name=value.</summary>
public sealed class ToolCliSweepTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    [Trait("Speed", "Slow")]
    [Fact]
    public async Task Every_tool_case_runs_from_the_command_line()
    {
        var cases = McpProtocolTests.ToolCases(_dir); // order matters: edits build on each other, unload last
        var steps = _dir.File("steps.jsonl");
        File.WriteAllLines(steps, cases.Select(c => JsonSerializer.Serialize(new { tool = c.Key, args = c.Value.Args }, McpJsonUtilities.DefaultOptions)));

        var start = new ProcessStartInfo("dotnet") { RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = System.Text.Encoding.UTF8 };
        foreach (var arg in new[] { McpProtocolTests.ServerDll, "batch", steps, "--json", "--load", Env.FixturePath, "--load", Env.ConsumerPath })
            start.ArgumentList.Add(arg);
        foreach (var (name, value) in FakeDevice.ServerEnvironment) start.Environment[name] = value;
        start.Environment["CORVUS_ANNOTATIONS_DIR"] = _dir.File("annotations");
        start.Environment[Services.MinidumpService.BucketCacheVariable] = _dir.File("buckets");
        using var process = Process.Start(start)!;
        var error = process.StandardError.ReadToEndAsync();
        var output = await process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync();

        var records = output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => JsonNode.Parse(l)!).ToList();
        Assert.True(records.Count == cases.Count, $"{records.Count} of {cases.Count} steps ran:\n{await error}");
        var failures = new List<string>();
        foreach (var ((tool, (_, expect)), record) in cases.Zip(records))
        {
            bool expectError = expect.StartsWith("Error (", StringComparison.Ordinal);
            // Expectations may name a record field, as in the MCP sweep: the text, then the structured content.
            var text = (string?)record["text"] + (record["structured"] is { } s ? "\n" + s.ToJsonString(Corvus.Mcp.Catalog.ToolSerializerOptions) : "");
            if ((string?)record["tool"] != tool || (bool)record["isError"]! != expectError || !text.Contains(expect, StringComparison.Ordinal))
                failures.Add($"{tool}: expected {(expectError ? "an error" : "success")} with '{expect}' in:\n{text}");
        }
        Assert.True(failures.Count == 0, string.Join("\n\n", failures));
    }

    /// <summary>Output to a file or pipe is UTF-8 whatever the console's code page (437 under the test host on Windows), input too.</summary>
    [Fact]
    public async Task Piped_input_and_output_are_utf8()
    {
        const string text = "Größe — 名前";
        Assert.Contains(text, await Corvus(null, "prompt", "find_feature", "feature=" + text));
        Assert.Contains(text, await Corvus(text, "prompt", "find_feature", "feature=@-"));

        static async Task<string> Corvus(string? stdin, params string[] args)
        {
            var start = new ProcessStartInfo("dotnet")
            {
                RedirectStandardInput = stdin != null, RedirectStandardOutput = true, RedirectStandardError = true,
                StandardInputEncoding = stdin != null ? new System.Text.UTF8Encoding(false) : null, StandardOutputEncoding = System.Text.Encoding.UTF8,
            };
            foreach (var arg in (string[])[McpProtocolTests.ServerDll, .. args]) start.ArgumentList.Add(arg);
            using var process = Process.Start(start)!;
            if (stdin != null) { await process.StandardInput.WriteAsync(stdin); process.StandardInput.Close(); }
            var error = process.StandardError.ReadToEndAsync();
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();
            Assert.True(process.ExitCode == 0, await error);
            return output;
        }
    }

    [Fact]
    public void Every_tool_case_reads_back_from_name_value_arguments()
    {
        var failures = new List<string>();
        foreach (var (tool, (args, _)) in McpProtocolTests.ToolCases(_dir))
        {
            var schema = ToolCli.FindTool(tool)!["inputSchema"];
            var typed = CliArgs.Parse(args.Select(a => Assignment(a.Key, a.Value)).ToArray()).ToolArguments(schema, TextReader.Null);
            var sent = JsonSerializer.SerializeToNode(args, McpJsonUtilities.DefaultOptions)!;
            var read = JsonSerializer.SerializeToNode(typed, McpJsonUtilities.DefaultOptions)!;
            if (!JsonNode.DeepEquals(sent, read)) failures.Add($"{tool}: sent {sent.ToJsonString()}, the command line read {read.ToJsonString()}");
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    /// <summary>A value as a user types it: plain text, numbers and booleans as such, lists, objects and text starting with @ as JSON.</summary>
    private static string Assignment(string name, object? value) => value switch
    {
        string s when s.StartsWith('@') => $"{name}:={JsonSerializer.Serialize(s)}",
        string s => $"{name}={s}",
        bool b => $"{name}={(b ? "true" : "false")}",
        IFormattable n => $"{name}={n.ToString(null, CultureInfo.InvariantCulture)}",
        _ => $"{name}={JsonSerializer.Serialize(value, McpJsonUtilities.DefaultOptions)}",
    };
}
