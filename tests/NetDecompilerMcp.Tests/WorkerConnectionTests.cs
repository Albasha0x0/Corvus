using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Tests;

/// <summary><see cref="WorkerConnection"/> against an in-process worker: serial and concurrent requests, cancellation by request, kill fallback.</summary>
public class WorkerConnectionTests
{
    private static readonly WorkerConnectionOptions Concurrent = new() { Concurrent = true, CancelGrace = TimeSpan.FromSeconds(2) };

    [Fact]
    public async Task Concurrent_requests_complete_out_of_order()
    {
        using var worker = new FakeWorker();
        using var c = worker.Connect(Concurrent);
        var slow = c.RequestAsync("sleep", new JsonObject { ["ms"] = 400, ["tag"] = "slow" }, TimeSpan.FromSeconds(10), default);
        var fast = c.RequestAsync("sleep", new JsonObject { ["ms"] = 10, ["tag"] = "fast" }, TimeSpan.FromSeconds(10), default);
        var first = await Task.WhenAny(slow, fast);
        Assert.Same(fast, first);
        Assert.Equal("fast", (await fast).GetProperty("tag").GetString());
        Assert.Equal("slow", (await slow).GetProperty("tag").GetString());
        Assert.True(worker.MaxInFlight >= 2);
    }

    [Fact]
    public async Task Serial_connection_runs_one_request_at_a_time()
    {
        using var worker = new FakeWorker();
        using var c = worker.Connect(null);
        await Task.WhenAll(Enumerable.Range(0, 4).Select(i => c.RequestAsync("sleep", new JsonObject { ["ms"] = 30 }, TimeSpan.FromSeconds(10), default)));
        Assert.Equal(1, worker.MaxInFlight);
    }

    [Fact]
    public async Task Cancelled_request_is_stopped_by_the_worker_which_keeps_running()
    {
        using var worker = new FakeWorker();
        using var c = worker.Connect(Concurrent);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        var clock = Stopwatch.StartNew();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => c.RequestAsync("sleep", new JsonObject { ["ms"] = 60_000 }, TimeSpan.FromMinutes(1), cts.Token));
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5));
        Assert.True(c.IsAlive);
        Assert.Equal(1, worker.Cancelled);
        Assert.Equal(7, (await c.RequestAsync("echo", new JsonObject { ["v"] = 7 }, TimeSpan.FromSeconds(5), default)).GetProperty("v").GetInt32());
    }

    [Fact]
    public async Task Timed_out_request_is_cancelled_and_reported_as_timeout()
    {
        using var worker = new FakeWorker();
        using var c = worker.Connect(Concurrent);
        var e = await Assert.ThrowsAsync<ToolError>(() => c.RequestAsync("sleep", new JsonObject { ["ms"] = 60_000 }, TimeSpan.FromMilliseconds(200), default));
        Assert.Equal(ErrorCode.Timeout, e.Code);
        Assert.Contains("cancelled", e.Message);
        Assert.True(c.IsAlive);
    }

    [Fact]
    public async Task Request_that_ignores_cancel_kills_the_worker()
    {
        using var worker = new FakeWorker();
        using var c = worker.Connect(Concurrent with { CancelGrace = TimeSpan.FromMilliseconds(200) });
        var other = c.RequestAsync("sleep", new JsonObject { ["ms"] = 60_000 }, TimeSpan.FromMinutes(1), default);
        var e = await Assert.ThrowsAsync<ToolError>(() => c.RequestAsync("stubborn", null, TimeSpan.FromMilliseconds(200), default));
        Assert.Equal(ErrorCode.Timeout, e.Code);
        Assert.Contains("stopped", e.Message);
        Assert.False(c.IsAlive);
        // Requests still running when the worker is stopped fail as well.
        Assert.Equal(ErrorCode.ProviderUnavailable, (await Assert.ThrowsAsync<ToolError>(() => other)).Code);
    }

    [Fact]
    public async Task Serial_connection_kills_on_timeout()
    {
        using var worker = new FakeWorker();
        using var c = worker.Connect(null);
        var e = await Assert.ThrowsAsync<ToolError>(() => c.RequestAsync("sleep", new JsonObject { ["ms"] = 60_000 }, TimeSpan.FromMilliseconds(200), default));
        Assert.Equal(ErrorCode.Timeout, e.Code);
        Assert.False(c.IsAlive);
        Assert.Equal(0, worker.Cancelled);
    }

    [Fact]
    public async Task Worker_errors_map_to_tool_errors()
    {
        using var worker = new FakeWorker();
        using var c = worker.Connect(Concurrent);
        var e = await Assert.ThrowsAsync<ToolError>(() => c.RequestAsync("missing", null, TimeSpan.FromSeconds(5), default));
        Assert.Equal(ErrorCode.NotFound, e.Code);
    }

    /// <summary>A worker thread behind anonymous pipes: echo, sleep (cancellable), stubborn (ignores cancel), cancel.</summary>
    private sealed class FakeWorker : ChildProcess
    {
        private readonly AnonymousPipeServerStream _toWorker = new(PipeDirection.Out);
        private readonly AnonymousPipeClientStream _workerIn;
        private readonly AnonymousPipeServerStream _fromWorker = new(PipeDirection.In);
        private readonly AnonymousPipeClientStream _workerOut;
        private readonly AnonymousPipeServerStream _errors = new(PipeDirection.In);
        private readonly AnonymousPipeClientStream _workerErr;
        private readonly TaskCompletionSource _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly ConcurrentDictionary<long, CancellationTokenSource> _running = new();
        private readonly CancellationTokenSource _stop = new();
        private readonly object _write = new();
        private int _inFlight;

        public int MaxInFlight;
        public int Cancelled;

        public FakeWorker()
        {
            _workerIn = new AnonymousPipeClientStream(PipeDirection.In, _toWorker.ClientSafePipeHandle);
            _workerOut = new AnonymousPipeClientStream(PipeDirection.Out, _fromWorker.ClientSafePipeHandle);
            _workerErr = new AnonymousPipeClientStream(PipeDirection.Out, _errors.ClientSafePipeHandle);
            new Thread(Loop) { IsBackground = true }.Start();
        }

        public WorkerConnection Connect(WorkerConnectionOptions? options) => WorkerConnection.Attach(this, "test worker", null, options);

        private void Loop()
        {
            try
            {
                using var reader = new StreamReader(_workerIn, Encoding.UTF8);
                while (reader.ReadLine() is { } line)
                {
                    var req = JsonNode.Parse(line)!;
                    var id = (long)req["id"]!;
                    var op = (string)req["op"]!;
                    var args = req["args"]!.AsObject();
                    if (op == WorkerProtocol.CancelOp)
                    {
                        if (_running.TryGetValue((long)args["id"]!, out var target))
                        {
                            Interlocked.Increment(ref Cancelled);
                            target.Cancel();
                        }
                        continue;
                    }
                    var cts = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
                    _running[id] = cts;
                    _ = Task.Run(() => Handle(id, op, args, cts));
                }
            }
            catch (IOException) { }
            _exited.TrySetResult();
        }

        private async Task Handle(long id, string op, JsonObject args, CancellationTokenSource cts)
        {
            var n = Interlocked.Increment(ref _inFlight);
            InterlockedMax(ref MaxInFlight, n);
            try
            {
                switch (op)
                {
                    case "echo":
                        Reply(new JsonObject { ["id"] = id, ["ok"] = true, ["result"] = args.DeepClone() });
                        break;
                    case "sleep":
                        try
                        {
                            await Task.Delay((int)args["ms"]!, cts.Token);
                            Reply(new JsonObject { ["id"] = id, ["ok"] = true, ["result"] = args.DeepClone() });
                        }
                        catch (OperationCanceledException)
                        {
                            Reply(Error(id, "failed", "cancelled"));
                        }
                        break;
                    case "stubborn":
                        await Task.Delay(Timeout.Infinite, _stop.Token);
                        break;
                    default:
                        Reply(Error(id, "not_found", "unknown op " + op));
                        break;
                }
            }
            catch (OperationCanceledException) { }
            finally
            {
                Interlocked.Decrement(ref _inFlight);
                _running.TryRemove(id, out _);
                cts.Dispose();
            }
        }

        private static JsonObject Error(long id, string code, string message) =>
            new() { ["id"] = id, ["ok"] = false, ["error"] = new JsonObject { ["code"] = code, ["message"] = message } };

        private void Reply(JsonObject o)
        {
            var bytes = Encoding.UTF8.GetBytes(o.ToJsonString() + "\n");
            lock (_write)
            {
                try
                {
                    _workerOut.Write(bytes);
                    _workerOut.Flush();
                }
                catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
            }
        }

        private static void InterlockedMax(ref int target, int value)
        {
            int seen;
            while ((seen = Volatile.Read(ref target)) < value && Interlocked.CompareExchange(ref target, value, seen) != seen) { }
        }

        public override int Id => Environment.ProcessId;
        public override Stream StandardInput => _toWorker;
        public override Stream StandardOutput => _fromWorker;
        public override Stream StandardError => _errors;
        public override bool HasExited => _exited.Task.IsCompleted;
        public override int? ExitCode => HasExited ? 1 : null;
        public override Task Exited => _exited.Task;
        public override IReadOnlyList<int> TreeProcessIds() => HasExited ? [] : [Id];

        public override void Kill()
        {
            _stop.Cancel();
            lock (_write)
            {
                _workerOut.Dispose();
                _workerErr.Dispose();
            }
            _toWorker.Dispose();
            _exited.TrySetResult();
        }

        public override void Dispose()
        {
            Kill();
            _workerIn.Dispose();
            _fromWorker.Dispose();
            _errors.Dispose();
        }
    }
}
