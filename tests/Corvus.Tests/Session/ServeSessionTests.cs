using System.IO.Pipes;
using System.Text;
using Corvus.Core;
using Corvus.Services;
using Corvus.Setup;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>Calls routed to a serve session share its loaded images and report failures by exit code.</summary>
public class ServeSessionTests
{
    private static string Unique() => "t" + Guid.NewGuid().ToString("N")[..12];

    private sealed class Host(string name) : IAsyncDisposable
    {
        private readonly CancellationTokenSource stop = new();
        private readonly StringWriter error = new();
        public Task<int> Task { get; private set; } = null!;

        public async Task<Host> StartAsync()
        {
            var writer = TextWriter.Synchronized(error);
            Task = ToolCli.RunAsync(["serve", "--session", name], new CliIo(new StringWriter(), writer, TextReader.Null), stop.Token);
            var deadline = DateTime.UtcNow.AddSeconds(90);
            while (!error.ToString().Contains("is ready") && !Task.IsCompleted && DateTime.UtcNow < deadline)
                await System.Threading.Tasks.Task.Delay(50);
            Assert.Contains("is ready", error.ToString());
            return this;
        }

        public async ValueTask DisposeAsync()
        {
            await stop.CancelAsync();
            Assert.Equal(0, await Task.WaitAsync(TimeSpan.FromSeconds(30)));
        }
    }

    private static async Task<string> SendRaw(string name, string line)
    {
        await using var pipe = new NamedPipeClientStream(".", ToolCli.SessionPipe(name), PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        await pipe.ConnectAsync(5000);
        await pipe.WriteAsync(Encoding.UTF8.GetBytes(line + "\n"));
        using var reader = new StreamReader(pipe, new UTF8Encoding(false));
        return await reader.ReadLineAsync() ?? "";
    }

    // Needs corvus.dll beside the test assembly, as the test project copies it.
    [Fact]
    public async Task A_routed_call_sees_an_image_loaded_by_an_earlier_routed_call()
    {
        var name = Unique();
        var image = Path.Combine(AppContext.BaseDirectory, "corvus.dll");
        await using var host = await new Host(name).StartAsync();
        var loaded = await ToolCliTests.Run("load_assembly", "--session", name, "path=" + image);
        Assert.Equal(0, loaded.Code);
        var listed = await ToolCliTests.Run("list_assemblies", "--session", name);
        Assert.Equal(0, listed.Code);
        Assert.Contains("corvus", listed.Out);
    }

    [Fact]
    public async Task A_routed_batch_step_sees_an_image_loaded_by_a_routed_call()
    {
        var name = Unique();
        var image = Path.Combine(AppContext.BaseDirectory, "corvus.dll").Replace("\\", "/");
        var steps = Path.Combine(Path.GetTempPath(), name + ".jsonl");
        await File.WriteAllTextAsync(steps, "{\"tool\":\"list_assemblies\"}\n");
        try
        {
            await using var host = await new Host(name).StartAsync();
            var loaded = await ToolCliTests.Run("load_assembly", "--session", name, "path=" + image);
            Assert.Equal(0, loaded.Code);
            var (code, output, _) = await ToolCliTests.Run("batch", steps, "--session", name);
            Assert.Equal(0, code);
            Assert.Contains("corvus", output);
        }
        finally { File.Delete(steps); }
    }

    [Fact]
    public async Task A_batch_to_a_session_that_is_not_running_exits_with_3()
    {
        var name = Unique();
        var steps = Path.Combine(Path.GetTempPath(), name + ".jsonl");
        await File.WriteAllTextAsync(steps, "{\"tool\":\"list_assemblies\"}\n");
        try
        {
            var (code, _, error) = await ToolCliTests.Run("batch", steps, "--session", name);
            Assert.Equal(3, code);
            Assert.Contains(name, error);
        }
        finally { File.Delete(steps); }
    }

    [Fact]
    public async Task A_routed_tool_error_exits_with_the_code_of_an_in_process_call()
    {
        var name = Unique();
        var missing = Path.Combine(AppContext.BaseDirectory, "no-such-image.dll");
        var direct = await ToolCliTests.Run("load_assembly", "path=" + missing);
        await using var host = await new Host(name).StartAsync();
        var routed = await ToolCliTests.Run("load_assembly", "--session", name, "path=" + missing);
        Assert.NotEqual(0, routed.Code);
        Assert.Equal(direct.Code, routed.Code);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("{}")]
    [InlineData("{\"tool\":5}")]
    [InlineData("{\"tool\":\"no_such_tool\",\"args\":{}}")]
    public async Task A_malformed_or_unknown_request_gets_a_protocol_error_reply(string request)
    {
        var name = Unique();
        await using var host = await new Host(name).StartAsync();
        var reply = await SendRaw(name, request);
        Assert.Contains("protocolError", reply);
    }

    [Fact]
    public async Task A_second_serve_on_the_same_name_is_a_usage_error()
    {
        var name = Unique();
        await using var host = await new Host(name).StartAsync();
        var (code, _, error) = await ToolCliTests.Run("serve", "--session", name);
        Assert.Equal(2, code);
        Assert.Contains("already running", error);
    }

    [Fact]
    public async Task A_call_to_a_session_that_is_not_running_exits_with_3_and_names_it()
    {
        var name = Unique();
        var (code, _, error) = await ToolCliTests.Run("list_assemblies", "--session", name);
        Assert.Equal(3, code);
        Assert.Contains(name, error);
        Assert.Contains("serve --session", error);
    }

    [Fact]
    public async Task A_server_option_on_a_routed_call_is_a_usage_error()
    {
        var (code, _, error) = await ToolCliTests.Run("list_assemblies", "--session", Unique(), "--timeout", "5");
        Assert.Equal(2, code);
        Assert.Contains("--timeout", error);
    }

    [Fact]
    public void The_session_variable_routes_a_call_that_names_no_session()
    {
        var a = CliArgs.Parse(["list_assemblies"]);
        Assert.Equal("s1", ToolCli.SessionOf(a, _ => "s1"));
        Assert.Null(ToolCli.SessionOf(a, _ => ""));
        Assert.Equal("s2", ToolCli.SessionOf(CliArgs.Parse(["--session", "s2"]), _ => "s1"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("a b")]
    [InlineData("../x")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public void A_session_name_outside_the_allowed_characters_is_a_usage_error(string name) =>
        Assert.Throws<UsageException>(() => ToolCli.SessionPipe(name));

    // Regression: every ServeSessionTests host failed on macOS CI since the
    // session pipe was added; its TMPDIR left too few bytes for the socket.
    [Fact]
    public void The_socket_of_a_64_character_session_name_fits_the_unix_path_limit()
    {
        var pipe = ToolCli.SessionPipe(new string('a', 64));
        Assert.True(OperatingSystem.IsWindows() || System.Text.Encoding.UTF8.GetByteCount(pipe) < 104, pipe);
    }

    [Fact]
    public async Task Serve_without_a_session_name_is_a_usage_error()
    {
        var (code, _, error) = await ToolCliTests.Run("serve");
        Assert.Equal(2, code);
        Assert.Contains("--session", error);
    }

    private static CallToolResult Text(string text) => new() { Content = [new TextContentBlock { Text = text }] };

    private static async Task<(Task Serve, CancellationTokenSource Stop)> ServeFake(string name, ToolCli.RoutedCall run)
    {
        var stop = new CancellationTokenSource();
        var pipe = ToolCli.SessionPipe(name);
        var first = new NamedPipeServerStream(pipe, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly | PipeOptions.FirstPipeInstance);
        await Task.Yield();
        return (ToolCli.ServeSessionAsync(run, pipe, first, stop.Token), stop);
    }

    [Fact]
    public async Task A_routed_status_call_returns_while_a_slow_routed_call_holds_the_turn()
    {
        var name = Unique();
        var release = new TaskCompletionSource();
        var (serve, stop) = await ServeFake(name, async (tool, _, _, ct) =>
        {
            if (tool == "slow_fake") await release.Task.WaitAsync(ct);
            return Text(tool);
        });
        try
        {
            var slow = SendRaw(name, "{\"tool\":\"slow_fake\",\"args\":{}}");
            await Task.Delay(300);
            var status = await SendRaw(name, "{\"tool\":\"server_status\",\"args\":{}}").WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Contains("server_status", status);
            Assert.False(slow.IsCompleted);
            release.SetResult();
            Assert.Contains("slow_fake", await slow.WaitAsync(TimeSpan.FromSeconds(10)));
        }
        finally { await stop.CancelAsync(); await serve; }
    }

    [Fact]
    public async Task A_routed_call_prints_the_progress_of_the_session_on_stderr()
    {
        var name = Unique();
        var (serve, stop) = await ServeFake(name, async (tool, _, progress, ct) =>
        {
            progress.Report(new ProgressNotificationValue { Progress = 1, Total = 2, Message = "reading" });
            await Task.Delay(100, ct);
            return Text("done");
        });
        try
        {
            var error = new StringWriter();
            var result = await ToolCli.InvokeRemote(name, "slow_fake", [], new CliIo(new StringWriter(), error, TextReader.Null), CancellationToken.None);
            Assert.NotNull(result);
            Assert.Contains("slow_fake: [1/2] reading", error.ToString());
        }
        finally { await stop.CancelAsync(); await serve; }
    }

    private static async Task<List<string>> ReadAllLines(string name, string request)
    {
        await using var pipe = new NamedPipeClientStream(".", ToolCli.SessionPipe(name), PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        await pipe.ConnectAsync(5000);
        await pipe.WriteAsync(Encoding.UTF8.GetBytes(request + "\n"));
        using var reader = new StreamReader(pipe, new UTF8Encoding(false));
        var lines = new List<string>();
        while (await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10)) is { } line)
        {
            lines.Add(line);
            if (!line.StartsWith("{\"progress\"", StringComparison.Ordinal)) break;
        }
        return lines;
    }

    [Fact]
    public async Task Progress_reported_just_before_return_reaches_the_pipe_in_order_before_the_reply()
    {
        var name = Unique();
        var (serve, stop) = await ServeFake(name, (tool, _, progress, _) =>
        {
            for (var i = 1; i <= 50; i++) progress.Report(new ProgressNotificationValue { Progress = i, Total = 50, Message = "step " + i });
            return Task.FromResult(Text("done"));
        });
        try
        {
            var lines = await ReadAllLines(name, "{\"tool\":\"fake\",\"args\":{}}");
            Assert.Equal(51, lines.Count);
            for (var i = 0; i < 50; i++) Assert.Contains("\"message\":\"step " + (i + 1) + "\"", lines[i]);
            Assert.DoesNotContain("\"progress\"", lines[^1]);
        }
        finally { await stop.CancelAsync(); await serve; }
    }

    [Fact]
    public async Task A_progress_report_without_total_or_message_prints_a_bare_step()
    {
        var name = Unique();
        var (serve, stop) = await ServeFake(name, (tool, _, progress, _) =>
        {
            progress.Report(new ProgressNotificationValue { Progress = 3 });
            return Task.FromResult(Text("done"));
        });
        try
        {
            var error = new StringWriter();
            var result = await ToolCli.InvokeRemote(name, "fake", [], new CliIo(new StringWriter(), error, TextReader.Null), CancellationToken.None);
            Assert.NotNull(result);
            Assert.Contains("fake: [3]", error.ToString());
        }
        finally { await stop.CancelAsync(); await serve; }
    }

    [Fact]
    public async Task A_malformed_line_from_the_session_is_a_protocol_error()
    {
        var name = Unique();
        await using var server = new NamedPipeServerStream(ToolCli.SessionPipe(name), PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        var served = Task.Run(async () =>
        {
            await server.WaitForConnectionAsync();
            using (var request = new StreamReader(server, leaveOpen: true)) await request.ReadLineAsync();
            await server.WriteAsync(Encoding.UTF8.GetBytes("{not json\n"));
            await server.FlushAsync();
            await Task.Delay(500);
        });
        var error = new StringWriter();
        var result = await ToolCli.InvokeRemote(name, "fake", [], new CliIo(new StringWriter(), error, TextReader.Null), CancellationToken.None);
        Assert.Null(result);
        Assert.Contains("malformed", error.ToString());
        await served;
    }

    [Fact]
    public void Every_turn_free_tool_is_a_registered_tool_that_reads_only()
    {
        foreach (var tool in ToolCli.TurnFree)
        {
            Assert.True(Corvus.Mcp.ToolContract.Table.ContainsKey(tool), tool);
            if (tool is "server_status" or "read_result") continue;
            Assert.Equal(Corvus.Mcp.LatencyClass.Instant, Corvus.Mcp.ToolContract.Table[tool].Latency);
            Assert.True(Corvus.Mcp.ToolEffects.Of(tool).ReadOnly, tool);
        }
        Assert.Contains("list_assemblies", ToolCli.TurnFree);
        Assert.DoesNotContain("load_assembly", ToolCli.TurnFree);
    }

    [Fact]
    public async Task A_workspace_listing_waits_for_a_slow_write_and_sees_its_whole_result()
    {
        using var ws = new AssemblyWorkspace(new ServerOptions { WatchFiles = false });
        var inside = new TaskCompletionSource();
        var release = new TaskCompletionSource();
        var write = Task.Run(() => ws.Write(() =>
        {
            inside.SetResult();
            release.Task.Wait();
            return 0;
        }));
        await inside.Task;
        var read = Task.Run(() => ws.Read(() => ws.Assemblies.Count));
        await Task.Delay(200);
        Assert.False(read.IsCompleted);
        release.SetResult();
        await write;
        Assert.Equal(0, await read.WaitAsync(TimeSpan.FromSeconds(10)));
    }
}
