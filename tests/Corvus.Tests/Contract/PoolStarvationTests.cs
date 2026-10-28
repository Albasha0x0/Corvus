using Corvus.Native.Providers;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>Work that must not wait for the thread pool, checked with every pool thread blocked; runs alone, as it starves the process.</summary>
[CollectionDefinition(nameof(PoolStarvationTests), DisableParallelization = true)]
public class PoolStarvationCollection;

[Collection(nameof(PoolStarvationTests))]
public class PoolStarvationTests(Xunit.Abstractions.ITestOutputHelper output)
{
    private readonly Xunit.Abstractions.ITestOutputHelper _output = output;

    /// <summary>Blocks the pool with more queued blockers than it injects threads; the event is never disposed, as late blockers still wait on it.</summary>
    internal static ManualResetEventSlim Starve()
    {
        var release = new ManualResetEventSlim();
        for (int i = 0; i < ThreadPool.ThreadCount + 1000; i++) ThreadPool.UnsafeQueueUserWorkItem(_ => release.Wait(), null);
        return release;
    }

    [WindowsFact]
    public void Captured_process_reports_its_exit_and_output_on_a_starved_pool()
    {
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        PythonLocator.CaptureResult run;
        var release = Starve();
        try { run = PythonLocator.RunCapture(cmd, ["/d", "/c", "echo out& echo err 1>&2& exit 3"], TimeSpan.FromSeconds(10)); }
        finally { release.Set(); }
        Assert.False(run.TimedOut);
        Assert.Equal(3, run.ExitCode);
        Assert.Equal("out", run.Stdout.Trim());
        Assert.Equal("err", run.Stderr.Trim());
    }

    [WindowsFact]
    public void External_tool_reports_its_exit_and_output_on_a_starved_pool()
    {
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        ExternalTools.RunResult run;
        var release = Starve();
        try { run = ExternalTools.Run(cmd, ["/d", "/c", "echo out& exit 3"], TimeSpan.FromSeconds(10), 1000, default); }
        finally { release.Set(); }
        Assert.False(run.TimedOut);
        Assert.Equal(3, run.ExitCode);
        Assert.Equal("out", run.Text.Trim());
    }

    // Regression: efbb7d92's form of this test failed 3/3 with the test process
    // held to 4 cores on a loaded machine.
    // A child process of 1 or 4 processors, so the pool starts as small as a
    // small machine's.
    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    public async Task A_short_client_s_stop_is_answered_while_the_work_keeps_the_pool_busy(int cores)
    {
        if (ChildTest.Rerun(this, _output, [cores], environment: new Dictionary<string, string> { ["DOTNET_PROCESSOR_COUNT"] = $"{cores}" })) return;
        if (OperatingSystem.IsWindows() || OperatingSystem.IsLinux()) System.Diagnostics.Process.GetCurrentProcess().ProcessorAffinity = (1 << cores) - 1;
        using var services = new ServiceCollection()
            .AddSingleton(new Corvus.Core.ServerOptions { ClientTimeoutSeconds = 10 }).AddSingleton<Corvus.Core.ResultStore>()
            .AddSingleton(TimeProvider.System).BuildServiceProvider();
        var finish = new CallToolResult { Content = [new TextContentBlock { Text = "done" }] };
        var work = new TaskCompletionSource<CallToolResult>();
        var release = Starve();
        var clock = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            var call = Corvus.Mcp.CallFilter.Run(new CallToolRequestParams { Name = "export_project" }, null, services,
                _ => new ValueTask<CallToolResult>(work.Task), default).AsTask();
            // Waited on without the pool, blocked until the answer or 30 s.
            ((IAsyncResult)call).AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(30));
            var answered = clock.Elapsed;
            Assert.True(call.IsCompleted, "no answer within 30 s on a blocked pool");
            Assert.True(answered < TimeSpan.FromSeconds(10), $"answered after {answered}, past the client's 10 s");
            Assert.Equal("timeout", McpProtocolTests.ErrorJson(await call).GetProperty("code").GetString());
        }
        finally
        {
            work.TrySetResult(finish);
            release.Set();
        }
    }

    // A child process of 1 or 4 processors; the inner stream overrides only
    // Write, as the console stream does.
    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    public async Task The_transport_sends_an_answer_while_the_work_keeps_the_pool_busy(int cores)
    {
        if (ChildTest.Rerun(this, _output, [cores], environment: new Dictionary<string, string> { ["DOTNET_PROCESSOR_COUNT"] = $"{cores}" })) return;
        if (OperatingSystem.IsWindows() || OperatingSystem.IsLinux()) System.Diagnostics.Process.GetCurrentProcess().ProcessorAffinity = (1 << cores) - 1;
        var written = new WriteOnlyStream();
        // An input that never ends: at its end the transport disconnects
        // and sends nothing.
        var input = new System.IO.Pipelines.Pipe();
        var transport = new ModelContextProtocol.Server.StreamServerTransport(input.Reader.AsStream(), Corvus.Mcp.StdioStreams.Output(written), "test");
        var release = Starve();
        try
        {
            var send = transport.SendMessageAsync(new JsonRpcNotification { Method = "notifications/message" });
            // Waited on without the pool.
            ((IAsyncResult)send).AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(10));
            Assert.True(send.IsCompletedSuccessfully, "the answer was not sent within 10 s on a blocked pool");
            Assert.Contains("notifications/message", written.Text);
        }
        finally
        {
            release.Set();
            await transport.DisposeAsync();
        }
    }

    private sealed class WriteOnlyStream : Stream
    {
        private readonly MemoryStream _bytes = new();

        public string Text { get { lock (_bytes) return System.Text.Encoding.UTF8.GetString(_bytes.ToArray()); } }

        public override void Write(byte[] buffer, int offset, int count)
        {
            lock (_bytes) _bytes.Write(buffer, offset, count);
        }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    /// <summary>Blocking search visitors run on at most one thread per core, so injected pool threads stay free.</summary>
    [Fact]
    public void Blocked_search_visitors_take_one_thread_per_core()
    {
        using var workspace = new Corvus.Core.AssemblyWorkspace(new Corvus.Core.ServerOptions());
        var asm = workspace.Load(typeof(Corvus.Core.AssemblyWorkspace).Assembly.Location);
        int running = 0, peak = 0;
        Assert.Throws<Corvus.Core.ToolError>(() => Corvus.Core.MetadataUtil.ParallelCollect<int>([asm], (_, _, _) =>
        {
            int now = Interlocked.Increment(ref running);
            for (int seen = Volatile.Read(ref peak); now > seen; seen = Volatile.Read(ref peak)) Interlocked.CompareExchange(ref peak, now, seen);
            Thread.Sleep(100);
            Interlocked.Decrement(ref running);
        }, default, TimeSpan.FromSeconds(4), null));
        Assert.InRange(peak, 1, Environment.ProcessorCount);
    }
}
