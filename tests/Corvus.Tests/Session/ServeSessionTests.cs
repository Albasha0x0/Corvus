using System.IO.Pipes;
using System.Text;
using Corvus.Setup;

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

    [Fact]
    public async Task Serve_without_a_session_name_is_a_usage_error()
    {
        var (code, _, error) = await ToolCliTests.Run("serve");
        Assert.Equal(2, code);
        Assert.Contains("--session", error);
    }
}
