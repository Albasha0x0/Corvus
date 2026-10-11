using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Text;
using System.Text.Json.Nodes;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// A worker thread behind anonymous pipes, speaking <see cref="WorkerProtocol"/> with concurrent requests. Ops: echo,
/// save, sleep {ms} (cancellable), hold (until <see cref="Release"/>, cancellable), partial (until cancelled, then a result marked partial), stubborn (ignores cancel),
/// timeout (the request's time limit), set {key,value} / get {key} (per-process state), crash, close, cancel.
/// </summary>
internal sealed class FakeWorkerProcess : ChildProcess
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

    public readonly ConcurrentDictionary<string, string> State = new();
    public int MaxInFlight;
    /// <summary>Request ids in the order they arrived (cancels excluded).</summary>
    public readonly ConcurrentQueue<long> Received = new();
    public int Cancelled;
    private readonly ManualResetEventSlim _released = new();

    /// <summary>Lets every held request answer.</summary>
    public void Release() => _released.Set();

    public FakeWorkerProcess(bool ready = false)
    {
        _workerIn = new AnonymousPipeClientStream(PipeDirection.In, _toWorker.ClientSafePipeHandle);
        _workerOut = new AnonymousPipeClientStream(PipeDirection.Out, _fromWorker.ClientSafePipeHandle);
        _workerErr = new AnonymousPipeClientStream(PipeDirection.Out, _errors.ClientSafePipeHandle);
        if (ready) Reply(new JsonObject { ["event"] = "ready" });
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
                if (req["timeout"] is { } timeout) args["_timeout"] = timeout.DeepClone();
                if (op == WorkerProtocol.CancelOp)
                {
                    if (_running.TryGetValue((long)args["id"]!, out var target))
                    {
                        Interlocked.Increment(ref Cancelled);
                        target.Cancel();
                    }
                    continue;
                }
                Received.Enqueue(id);
                var cts = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
                _running[id] = cts;
                // Counted on receipt, so a request is in flight before its thread gets to run.
                InterlockedMax(ref MaxInFlight, Interlocked.Increment(ref _inFlight));
                // Threads, not the pool: under the parallel suite a starved pool would delay replies past the test's limits.
                new Thread(() => Handle(id, op, args, cts)) { IsBackground = true }.Start();
            }
        }
        catch (IOException) { }
        catch (ObjectDisposedException) { }
        _exited.TrySetResult();
    }

    private void Handle(long id, string op, JsonObject args, CancellationTokenSource cts)
    {
        try
        {
            switch (op)
            {
                case "echo" or "save":
                    Reply(Ok(id, args.DeepClone()));
                    break;
                case "sleep":
                    if (!cts.Token.WaitHandle.WaitOne((int)args["ms"]!)) Reply(Ok(id, args.DeepClone()));
                    else if (!_stop.IsCancellationRequested) Reply(Error(id, "failed", "cancelled"));
                    break;
                case "hold":
                    if (WaitHandle.WaitAny([_released.WaitHandle, cts.Token.WaitHandle]) == 0) Reply(Ok(id, args.DeepClone()));
                    else if (!_stop.IsCancellationRequested) Reply(Error(id, "failed", "cancelled"));
                    break;
                case "partial":
                    cts.Token.WaitHandle.WaitOne();
                    if (!_stop.IsCancellationRequested) Reply(Ok(id, new JsonObject { ["partial"] = "cancelled", ["next"] = 42 }));
                    break;
                case "timeout":
                    Reply(Ok(id, new JsonObject { ["timeout"] = args["_timeout"]?.DeepClone() }));
                    break;
                case "stubborn":
                    _stop.Token.WaitHandle.WaitOne();
                    break;
                case "set":
                    State[(string)args["key"]!] = (string)args["value"]!;
                    Reply(Ok(id, new JsonObject()));
                    break;
                case "get":
                    Reply(Ok(id, new JsonObject { ["value"] = State.TryGetValue((string)args["key"]!, out var v) ? v : null }));
                    break;
                case "crash":
                    Kill();
                    break;
                case "close":
                    Reply(Ok(id, new JsonObject()));
                    Kill();
                    break;
                default:
                    Reply(Error(id, "not_found", "unknown op " + op));
                    break;
            }
        }
        finally
        {
            Finish(id);
            cts.Dispose();
        }
    }

    /// <summary>Ends a request's time in flight, once; before its reply is written, so the next serial request never overlaps it.</summary>
    private void Finish(long id)
    {
        if (_running.TryRemove(id, out _)) Interlocked.Decrement(ref _inFlight);
    }

    private static JsonObject Ok(long id, JsonNode result) => new() { ["id"] = id, ["ok"] = true, ["result"] = result };

    private static JsonObject Error(long id, string code, string message) =>
        new() { ["id"] = id, ["ok"] = false, ["error"] = new JsonObject { ["code"] = code, ["message"] = message } };

    private void Reply(JsonObject o)
    {
        if (o["id"] is { } id) Finish((long)id);
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
