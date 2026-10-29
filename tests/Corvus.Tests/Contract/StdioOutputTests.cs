using System.Text;
using System.Text.Json.Nodes;

namespace Corvus.Tests;

/// <summary>The stdio server's standard output against a client that is slow to read it.</summary>
public class StdioOutputTests
{
    // Regression: push run 2f295aa6 left 4 of 1430 contract calls without an
    // answer, the sender blocked writing a full standard output pipe.
    // Each request pads its 64 KB _meta, so the requests fill the server's
    // input pipe while the tool lists fill its output pipe.
    [Fact]
    public async Task A_client_that_writes_every_request_before_reading_gets_every_answer()
    {
        const int Requests = 60;
        var psi = McpProtocolTests.ServerStartInfo(null, ["--load", Env.FixturePath]);
        using var server = System.Diagnostics.Process.Start(psi)!;
        try
        {
            server.ErrorDataReceived += (_, _) => { };
            server.BeginErrorReadLine();
            var input = server.StandardInput.BaseStream;
            var output = server.StandardOutput;
            await Send(input, new JsonObject
            {
                ["jsonrpc"] = "2.0", ["id"] = 0, ["method"] = "initialize",
                ["params"] = new JsonObject { ["protocolVersion"] = "2025-06-18", ["capabilities"] = new JsonObject(), ["clientInfo"] = new JsonObject { ["name"] = "test", ["version"] = "1" } },
            });
            Assert.Contains("\"id\":0", await output.ReadLineAsync().WaitAsync(TimeSpan.FromMinutes(3)));
            await Send(input, new JsonObject { ["jsonrpc"] = "2.0", ["method"] = "notifications/initialized" });
            var pad = new string('a', 64 * 1024);
            var writes = Task.Run(async () =>
            {
                for (int id = 1; id <= Requests; id++)
                    await Send(input, new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["method"] = "tools/list", ["params"] = new JsonObject { ["_meta"] = new JsonObject { ["pad"] = pad } } });
            });
            await writes.WaitAsync(TimeSpan.FromMinutes(2));
            var answered = new HashSet<int>();
            while (answered.Count < Requests)
            {
                var line = await output.ReadLineAsync().WaitAsync(TimeSpan.FromMinutes(2)) ?? throw new EndOfStreamException($"{answered.Count} of {Requests} answered");
                if (JsonNode.Parse(line)?["id"] is { } id) answered.Add(id.GetValue<int>());
            }
        }
        finally
        {
            try { server.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            server.WaitForExit(10_000);
        }
    }

    // The inner stream blocks each write and flush until released, as a full
    // pipe does.
    [Fact]
    public async Task A_write_to_an_output_that_is_not_read_never_holds_the_caller_s_thread()
    {
        using var release = new ManualResetEventSlim();
        var blocked = new BlockingOutput(release);
        var output = Corvus.Mcp.StdioStreams.Output(blocked);
        Task? flushed = null;
        // On a thread of its own, so a write that holds its caller fails the
        // test instead of stopping it.
        var caller = new Thread(() =>
        {
            output.WriteAsync(Encoding.UTF8.GetBytes("{}\n")).AsTask().GetAwaiter().GetResult();
            flushed = output.FlushAsync();
        });
        caller.Start();
        bool returned = caller.Join(TimeSpan.FromSeconds(5));
        bool flushedEarly = flushed?.IsCompleted == true;
        release.Set();
        Assert.True(returned, "the write held its caller while the output was not read");
        Assert.False(flushedEarly, "the flush completed before the bytes were written");
        await flushed!.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal("{}\n", blocked.Text);
        output.Dispose();
    }

    // Regression: e78024ee, a flush done while its caller subscribed resumed
    // the caller on the pool.
    // The inner flush is released 100 ms after the writer thread enters it,
    // so a flush returned without its wait is still pending.
    [Fact]
    public void A_flush_written_within_its_wait_returns_complete()
    {
        using var release = new ManualResetEventSlim();
        using var flushing = new ManualResetEventSlim();
        using var output = Corvus.Mcp.StdioStreams.Output(new BlockingOutput(release, flushing), TimeSpan.FromSeconds(30));
        new Thread(() => { flushing.Wait(); Thread.Sleep(100); release.Set(); }) { IsBackground = true }.Start();
        var flushed = output.FlushAsync();
        Assert.True(flushed.IsCompletedSuccessfully, $"the flush returned {flushed.Status}");
    }

    // The first flush returns pending, its write released only afterwards, so
    // its continuation runs on the writer thread.
    [Fact]
    public async Task A_flush_sent_from_a_slow_flush_s_continuation_returns_at_once()
    {
        var quickFlush = TimeSpan.FromSeconds(2);
        using var release = new ManualResetEventSlim();
        var written = new BlockingOutput(release);
        using var output = Corvus.Mcp.StdioStreams.Output(written, quickFlush);
        output.Write(Encoding.UTF8.GetBytes("{}\n"));
        var first = output.FlushAsync();
        Assert.False(first.IsCompleted, "the first flush completed while its write was held");
        string? thread = null;
        var elapsed = TimeSpan.MaxValue;
        var second = first.ContinueWith(_ =>
        {
            thread = Thread.CurrentThread.Name;
            var clock = System.Diagnostics.Stopwatch.StartNew();
            output.Write(Encoding.UTF8.GetBytes("{}\n"));
            var flushed = output.FlushAsync();
            elapsed = clock.Elapsed;
            return flushed;
        }, TaskContinuationOptions.ExecuteSynchronously).Unwrap();
        release.Set();
        await second.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Equal("Corvus standard output", thread);
        Assert.True(elapsed < quickFlush, $"the flush held the writer thread for {elapsed}");
        Assert.Equal("{}\n{}\n", written.Text);
    }

    private sealed class BlockingOutput(ManualResetEventSlim release, ManualResetEventSlim? flushing = null) : Stream
    {
        private readonly MemoryStream _bytes = new();

        public string Text { get { lock (_bytes) return Encoding.UTF8.GetString(_bytes.ToArray()); } }

        public override void Write(byte[] buffer, int offset, int count)
        {
            release.Wait();
            lock (_bytes) _bytes.Write(buffer, offset, count);
        }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush()
        {
            flushing?.Set();
            release.Wait();
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    private static async Task Send(Stream input, JsonObject message)
    {
        await input.WriteAsync(Encoding.UTF8.GetBytes(message.ToJsonString() + "\n"));
        await input.FlushAsync();
    }
}
