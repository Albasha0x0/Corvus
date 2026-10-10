using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native.Providers;

/// <summary>How a <see cref="WorkerConnection"/> runs requests.</summary>
public sealed record WorkerConnectionOptions
{
    /// <summary>Requests run concurrently, matched to responses by id; otherwise one at a time.</summary>
    public bool Concurrent { get; init; }
    /// <summary>
    /// A request that times out or is cancelled is first asked to stop with a <see cref="WorkerProtocol.CancelOp"/>
    /// request; the worker is killed only when no response arrives within this time. Null: killed at once.
    /// </summary>
    public TimeSpan? CancelGrace { get; init; }
}

/// <summary>
/// A running worker process and its request channel (see <see cref="WorkerProtocol"/>). By default requests are
/// serialized, and a request that exceeds its time limit or is cancelled while running kills the worker, because an
/// engine busy in native code cannot be interrupted; <see cref="WorkerConnectionOptions"/> allows concurrent requests
/// and cancellation by request. Worker death fails the running requests with ProviderUnavailable and the last stderr lines.
/// </summary>
public sealed class WorkerConnection : IDisposable
{
    private readonly ChildProcess _process;
    private readonly string _name;
    private readonly Func<ErrorCode, string, string?> _remediation;
    private readonly WorkerConnectionOptions _options;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly TextTail _stderr = new(32_000);
    private readonly TaskCompletionSource<JsonElement> _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _stdoutDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly object _sync = new();
    private readonly object _writeSync = new();
    private readonly Dictionary<long, TaskCompletionSource<WorkerMessage.Response>> _pending = [];
    private long _nextId;
    private string? _killReason;
    private int _disposed;

    /// <summary>Progress and other events; raised on the reader thread.</summary>
    public event Action<WorkerMessage.Event>? EventReceived;

    private WorkerConnection(ChildProcess process, string name, Func<ErrorCode, string, string?> remediation, WorkerConnectionOptions options)
    {
        _process = process;
        _name = name;
        _remediation = remediation;
        _options = options;
        new Thread(ReadStdout) { IsBackground = true, Name = name + " stdout" }.Start();
        new Thread(ReadStderr) { IsBackground = true, Name = name + " stderr" }.Start();
        // Responses written just before exit are still in the pipe: closed means stdout EOF, or exit plus a short
        // grace for the case where a surviving grandchild holds the pipe open.
        _process.Exited.ContinueWith(async _ =>
        {
            await Task.WhenAny(_stdoutDone.Task, Task.Delay(500)).ConfigureAwait(false);
            OnClosed();
        }, TaskScheduler.Default);
    }

    /// <param name="name">Engine name used in error messages ("IDA worker").</param>
    /// <param name="start">The worker command.</param>
    /// <param name="remediation">Next step for an error code and message, or null.</param>
    /// <param name="options">Concurrency and cancellation; null: serial, killed on timeout.</param>
    public static WorkerConnection Start(string name, ChildProcessStart start, Func<ErrorCode, string, string?>? remediation = null,
        WorkerConnectionOptions? options = null) =>
        Attach(ChildProcess.Start(start), name, remediation, options);

    /// <summary>A connection over an already running process.</summary>
    internal static WorkerConnection Attach(ChildProcess process, string name, Func<ErrorCode, string, string?>? remediation = null,
        WorkerConnectionOptions? options = null) =>
        new(process, name, remediation ?? ((_, _) => null), options ?? new WorkerConnectionOptions());

    public int ProcessId => _process.Id;

    /// <summary>False once the process exited, its output closed or <see cref="Kill"/> was called.</summary>
    public bool IsAlive
    {
        get
        {
            lock (_sync)
                if (_killReason != null) return false;
            return !_closed.Task.IsCompleted && !_process.HasExited;
        }
    }

    public string StderrText => _stderr.Text;
    public IReadOnlyList<int> TreeProcessIds() => _process.TreeProcessIds();
    public Task Closed => _closed.Task;

    /// <summary>Waits for the worker's "ready" event.</summary>
    public async Task<JsonElement> WaitReadyAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        var done = await Task.WhenAny(_ready.Task, _closed.Task, Task.Delay(timeout, cancellationToken)).ConfigureAwait(false);
        if (done == _ready.Task) return _ready.Task.Result;
        if (done == _closed.Task) throw Died("start");
        Kill(cancellationToken.IsCancellationRequested ? "cancelled" : "start timeout");
        cancellationToken.ThrowIfCancellationRequested();
        throw new ToolError(ErrorCode.Timeout, $"{_name} did not start within {Seconds(timeout)}.{StderrSuffix()}",
            _remediation(ErrorCode.Timeout, "start"));
    }

    /// <summary>Sends one request and waits for its response; throws <see cref="ToolError"/> for worker errors.</summary>
    public async Task<JsonElement> RequestAsync(string op, JsonObject? args, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var serial = !_options.Concurrent;
        if (serial) await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        long id = 0;
        try
        {
            if (!IsAlive) throw Died(op);
            id = Interlocked.Increment(ref _nextId);
            var tcs = new TaskCompletionSource<WorkerMessage.Response>(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_sync) _pending[id] = tcs;
            var write = Send(WorkerProtocol.EncodeRequest(id, op, args));

            using var timer = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timer.CancelAfter(timeout);
            var stop = Task.Delay(Timeout.Infinite, timer.Token);
            try
            {
                var w = await Task.WhenAny(write, tcs.Task, _closed.Task, stop).ConfigureAwait(false);
                if (w == write && write.IsFaulted && !tcs.Task.IsCompleted) throw Died(op);
                if (w == write) await Task.WhenAny(tcs.Task, _closed.Task, stop).ConfigureAwait(false);
            }
            catch (IOException) { throw Died(op); }

            if (tcs.Task.IsCompleted) return Result(tcs.Task.Result);
            if (_closed.Task.IsCompleted && !timer.IsCancellationRequested) throw Died(op);
            var cancelled = cancellationToken.IsCancellationRequested;
            if (await CancelAsync(id, write, tcs.Task).ConfigureAwait(false))
            {
                if (cancelled) throw new OperationCanceledException(cancellationToken);
                throw new ToolError(ErrorCode.Timeout, $"{_name} did not finish '{op}' within {Seconds(timeout)}; the request was cancelled.",
                    _remediation(ErrorCode.Timeout, op));
            }
            if (cancelled)
            {
                Kill($"'{op}' cancelled");
                throw new OperationCanceledException(cancellationToken);
            }
            Kill($"'{op}' timed out");
            throw new ToolError(ErrorCode.Timeout, $"{_name} did not finish '{op}' within {Seconds(timeout)}; the worker was stopped.",
                _remediation(ErrorCode.Timeout, op));
        }
        finally
        {
            lock (_sync) _pending.Remove(id);
            if (serial) _gate.Release();
        }
    }

    private JsonElement Result(WorkerMessage.Response r)
    {
        if (r.Ok) return r.Result;
        var code = WorkerProtocol.MapCode(r.ErrorCode);
        var message = r.ErrorMessage ?? "error";
        if (code is ErrorCode.ProviderUnavailable or ErrorCode.Failed or ErrorCode.IoError)
            message += StderrSuffix();
        throw new ToolError(code, message, _remediation(code, message));
    }

    private Task Send(string line)
    {
        var bytes = Encoding.UTF8.GetBytes(line);
        return Task.Run(() =>
        {
            lock (_writeSync)
            {
                _process.StandardInput.Write(bytes);
                _process.StandardInput.Flush();
            }
        }, CancellationToken.None);
    }

    /// <summary>Asks the worker to stop request <paramref name="id"/>; true when it answered within the grace time and is still alive.</summary>
    private async Task<bool> CancelAsync(long id, Task write, Task<WorkerMessage.Response> response)
    {
        if (_options.CancelGrace is not { } grace || !IsAlive) return false;
        // Writes run on the pool in any order: the cancel must not overtake the request it names.
        await Task.WhenAny(write, Task.Delay(grace)).ConfigureAwait(false);
        if (!write.IsCompletedSuccessfully) return false;
        try
        {
            await Send(WorkerProtocol.EncodeRequest(Interlocked.Increment(ref _nextId), WorkerProtocol.CancelOp, new JsonObject { ["id"] = id }))
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException) { return false; }
        await Task.WhenAny(response, _closed.Task, Task.Delay(grace)).ConfigureAwait(false);
        return response.IsCompleted && IsAlive;
    }

    /// <summary>Asks the worker to close (sending <paramref name="op"/>), waits up to <paramref name="grace"/> for it to exit, then kills it.</summary>
    public async Task ShutdownAsync(string op, JsonObject? args, TimeSpan grace)
    {
        if (IsAlive)
        {
            try
            {
                await RequestAsync(op, args, grace, CancellationToken.None).ConfigureAwait(false);
                await Task.WhenAny(_process.Exited, Task.Delay(grace)).ConfigureAwait(false);
            }
            catch (ToolError) { /* stopped below */ }
        }
        Kill("shutdown");
    }

    public void Kill(string reason)
    {
        lock (_sync) _killReason ??= reason;
        _process.Kill();
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        lock (_sync) _killReason ??= "disposed";
        _process.Dispose();
        OnClosed();
    }

    private ToolError Died(string op)
    {
        string? reason;
        lock (_sync) reason = _killReason;
        var exit = _process.ExitCode is { } c ? $" with code {c} (0x{c:X8})" : "";
        var what = reason != null ? $"{_name} was stopped ({reason})" : $"{_name} exited{exit}";
        if (_process.MemoryLimitReached() is { } limit)
            what += $" after reaching its memory limit of {limit >> 20} MB ({EngineMemoryLimit.Variable})";
        var message = $"{what} while handling '{op}'.{StderrSuffix()}";
        return new ToolError(ErrorCode.ProviderUnavailable, message, _remediation(ErrorCode.ProviderUnavailable, message));
    }

    private string StderrSuffix()
    {
        var tail = _stderr.LastLines(12);
        return tail.Length == 0 ? "" : "\nworker stderr:\n" + tail;
    }

    private static string Seconds(TimeSpan t) => t.TotalSeconds < 120 ? $"{t.TotalSeconds:0.#} s" : $"{t.TotalMinutes:0.#} min";

    private void ReadStdout()
    {
        try
        {
            using var reader = new StreamReader(_process.StandardOutput, new UTF8Encoding(false), false, 4096, leaveOpen: true);
            while (reader.ReadLine() is { } line)
            {
                switch (WorkerProtocol.Parse(line))
                {
                    case WorkerMessage.Response r:
                        TaskCompletionSource<WorkerMessage.Response>? target = null;
                        lock (_sync)
                        {
                            if (r.Id is { } id) _pending.TryGetValue(id, out target);
                            else if (_pending.Count == 1) target = _pending.Values.First(); // a response the worker could not attribute
                        }
                        target?.TrySetResult(r);
                        break;
                    case WorkerMessage.Event e when e.Name == "ready":
                        _ready.TrySetResult(e.Body);
                        break;
                    case WorkerMessage.Event e:
                        try { EventReceived?.Invoke(e); } catch (Exception ex) { _stderr.Append($"[event handler failed: {ex.Message}]\n"); }
                        break;
                    case WorkerMessage.Noise n:
                        _stderr.Append("[stdout] " + n.Text + "\n");
                        break;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
        _stdoutDone.TrySetResult();
        OnClosed();
    }

    private void ReadStderr()
    {
        try
        {
            using var reader = new StreamReader(_process.StandardError, new UTF8Encoding(false), false, 4096, leaveOpen: true);
            var buffer = new char[4096];
            int n;
            while ((n = reader.Read(buffer, 0, buffer.Length)) > 0) _stderr.Append(new string(buffer, 0, n));
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
    }

    private void OnClosed() => _closed.TrySetResult();
}
