using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;

namespace Corvus.Native.Providers;

/// <summary>How a <see cref="WorkerConnection"/> runs requests.</summary>
public sealed record WorkerConnectionOptions
{
    /// <summary>Requests run concurrently, matched to responses by id; otherwise one at a time.</summary>
    public bool Concurrent { get; init; }
    /// <summary>
    /// A request that times out or is cancelled is first asked to stop with a <see cref="WorkerProtocol.CancelOp"/>
    /// request; the worker is killed only when no response arrives within this time. Null: killed at once.
    /// A timed-out request whose worker answers within the grace returns that answer (a result marked partial).
    /// </summary>
    public TimeSpan? CancelGrace { get; init; }
    /// <summary>
    /// Called with the worker's process id, then the other processes of its tree, before a worker that missed its start
    /// or a request's time is stopped: what it was doing (a thread dump summary), or null. Added to the timeout error.
    /// </summary>
    public Func<IReadOnlyList<int>, string?>? StallReport { get; init; }
    /// <summary>The setting a memory-limit hit names in its error.</summary>
    public string MemoryLimitVariable { get; init; } = EngineMemoryLimit.Variable;
}

/// <summary>A request the worker is running: its op, when it was sent, and the last progress the worker reported for it.</summary>
public sealed record WorkerRequestState(long Id, string Op, DateTime StartedUtc, string? Stage);

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
    private readonly TaskCompletionSource _stderrDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly object _sync = new();
    private readonly Dictionary<long, TaskCompletionSource<WorkerMessage.Response>> _pending = [];
    private readonly Dictionary<long, WorkerRequestState> _running = [];
    private readonly BlockingCollection<(byte[] Line, TaskCompletionSource Written)> _writes = [];
    private long _nextId;
    private int _waiting;
    // Environment.TickCount64 of the last stdout line: a live worker reports progress every 2 s.
    private long _lastLineTicks = Environment.TickCount64;
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
        new Thread(WriteStdin) { IsBackground = true, Name = name + " stdin" }.Start();
        // Responses and the exit message written just before exit are still in
        // the pipes: closed means their EOF, or exit plus a short grace for the
        // case where a surviving grandchild holds a pipe open.
        _process.Exited.ContinueWith(async _ =>
        {
            await Task.WhenAny(Task.WhenAll(_stdoutDone.Task, _stderrDone.Task), Task.Delay(500)).ConfigureAwait(false);
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

    /// <summary>The memory limit in bytes when the worker's tree reached it, else null (also when the system cannot tell).</summary>
    public long? MemoryLimitReached => _process.MemoryLimitReached();

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

    /// <summary>Requests sent and not yet answered, oldest first.</summary>
    public IReadOnlyList<WorkerRequestState> Running
    {
        get { lock (_sync) return _running.Values.OrderBy(r => r.Id).ToList(); }
    }

    /// <summary>Requests waiting for a serial connection to finish the running one.</summary>
    public int Waiting => Volatile.Read(ref _waiting);

    private long _requests;

    /// <summary>Requests sent through <see cref="RequestAsync"/> since the worker started.</summary>
    internal long Requests => Interlocked.Read(ref _requests);
    public IReadOnlyList<int> TreeProcessIds() => _process.TreeProcessIds();
    public Task Closed => _closed.Task;

    /// <summary>Waits for the worker's "ready" event.</summary>
    public async Task<JsonElement> WaitReadyAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        var done = await Task.WhenAny(_ready.Task, _closed.Task, Task.Delay(timeout, cancellationToken)).ConfigureAwait(false);
        if (done == _ready.Task) return _ready.Task.Result;
        if (done == _closed.Task) throw Died("start");
        var stall = cancellationToken.IsCancellationRequested ? null : Stall();
        Kill(cancellationToken.IsCancellationRequested ? "cancelled" : "start timeout");
        cancellationToken.ThrowIfCancellationRequested();
        throw new ToolError(ErrorCode.Timeout, $"{_name} did not start within {Seconds(timeout)}.{stall}{StderrSuffix()}",
            _remediation(ErrorCode.Timeout, "start"));
    }

    /// <summary>
    /// The request's last stage and how long ago the worker last wrote, so a busy worker is told from one that stopped
    /// answering; empty when there is neither.
    /// </summary>
    private string Activity(long id)
    {
        string? stage;
        lock (_sync) stage = _running.TryGetValue(id, out var r) ? r.Stage : null;
        var quiet = TimeSpan.FromMilliseconds(Environment.TickCount64 - Volatile.Read(ref _lastLineTicks));
        return (stage != null ? $" Last stage: {stage}." : "") + $" Last worker message: {Seconds(quiet)} ago.";
    }

    /// <summary>Starts a stall report that read nothing of the worker; the reason follows.</summary>
    internal const string StateUnknown = "unknown: ";

    /// <summary>
    /// The stall report of the running worker as a message suffix; "worker state unknown" with the reason when the
    /// report read nothing, so a stall is never reported silently; empty without a report.
    /// </summary>
    private string Stall()
    {
        if (_options.StallReport is not { } report || _process.HasExited) return "";
        try
        {
            return report([_process.Id, .. _process.TreeProcessIds().Where(id => id != _process.Id)]) switch
            {
                null or "" => "\nworker state unknown: the report read nothing",
                var text when text.StartsWith(StateUnknown, StringComparison.Ordinal) => "\nworker state unknown: " + text[StateUnknown.Length..],
                var text => "\nworker state:\n" + text,
            };
        }
        // A report is best effort: the timeout error stands without it.
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return "\nworker state unknown: " + ex.Message;
        }
    }

    /// <summary>The next step after an engine request of <paramref name="op"/> ran out of time: the open's limit for opens, else the request's.</summary>
    internal static string TimeoutNext(string op) => op is "start" or "open" or "load_pdb" or "export_gzf"
        ? $"Raise {ServerOptions.EngineOpenTimeoutVariable} (seconds for an engine's start and analysis) and call again."
        : $"Retry with a larger time limit (timeoutSeconds where the tool takes it, or {ServerOptions.EngineRequestTimeoutVariable}).";

    /// <summary>Sends one request and waits for its response; throws <see cref="ToolError"/> for worker errors.</summary>
    public async Task<JsonElement> RequestAsync(string op, JsonObject? args, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var serial = !_options.Concurrent;
        if (serial)
        {
            Interlocked.Increment(ref _waiting);
            try { await _gate.WaitAsync(cancellationToken).ConfigureAwait(false); }
            finally { Interlocked.Decrement(ref _waiting); }
        }
        long id = 0;
        try
        {
            if (!IsAlive) throw Died(op);
            id = Interlocked.Increment(ref _nextId);
            Interlocked.Increment(ref _requests);
            var tcs = new TaskCompletionSource<WorkerMessage.Response>(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_sync)
            {
                _pending[id] = tcs;
                _running[id] = new WorkerRequestState(id, op, DateTime.UtcNow, null);
            }
            var write = Send(WorkerProtocol.EncodeRequest(id, op, args, timeout));

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
                if (tcs.Task.Result.Ok) return tcs.Task.Result.Result;
                throw new ToolError(ErrorCode.Timeout, $"{_name} did not finish '{op}' within {Seconds(timeout)}; the request was cancelled.",
                    _remediation(ErrorCode.Timeout, op));
            }
            if (cancelled)
            {
                Kill($"'{op}' cancelled");
                throw new OperationCanceledException(cancellationToken);
            }
            var activity = Activity(id);
            var stall = Stall();
            Kill($"'{op}' timed out");
            throw new ToolError(ErrorCode.Timeout,
                $"{_name} did not finish '{op}' within {Seconds(timeout)}; the worker was stopped.{activity}{stall}{StderrSuffix()}",
                _remediation(ErrorCode.Timeout, op));
        }
        finally
        {
            lock (_sync)
            {
                _pending.Remove(id);
                _running.Remove(id);
            }
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

    /// <summary>Queues a line for the worker; written in the order queued by one thread, so a starved pool delays nothing.</summary>
    private Task Send(string line)
    {
        var written = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        try { _writes.Add((Encoding.UTF8.GetBytes(line), written)); }
        catch (InvalidOperationException) { written.TrySetException(new IOException($"{_name} input is closed.")); }
        return written.Task;
    }

    private void WriteStdin()
    {
        foreach (var (line, written) in _writes.GetConsumingEnumerable())
        {
            try
            {
                _process.StandardInput.Write(line);
                _process.StandardInput.Flush();
                written.TrySetResult();
            }
            catch (Exception ex) { written.TrySetException(ex); }
        }
    }

    /// <summary>Asks the worker to stop request <paramref name="id"/>; true when it answered within the grace time and is still alive.</summary>
    private async Task<bool> CancelAsync(long id, Task write, Task<WorkerMessage.Response> response)
    {
        if (_options.CancelGrace is not { } grace || !IsAlive) return false;
        // A request still stuck in the pipe, or whose write failed, cannot be stopped by the worker.
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
            what += $" after reaching its memory limit of {limit >> 20} MB ({_options.MemoryLimitVariable})";
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
                Volatile.Write(ref _lastLineTicks, Environment.TickCount64);
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
                        if (e.Name == "progress") Progressed(e.Body);
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
        // The exit message is read on its own thread: give it a moment, so the
        // error carries it.
        _stderrDone.Task.Wait(1000);
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
        _stderrDone.TrySetResult();
    }

    private void OnClosed()
    {
        _writes.CompleteAdding();
        _closed.TrySetResult();
    }

    /// <summary>Keeps the stage of a progress event on its request (the only one running when the event names none).</summary>
    private void Progressed(JsonElement body)
    {
        long? id = body.TryGetProperty("id", out var i) && i.TryGetInt64(out var n) ? n : null;
        var stage = body.TryGetProperty("stage", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString() : null;
        if (string.IsNullOrEmpty(stage)) return;
        lock (_sync)
        {
            var key = id ?? (_running.Count == 1 ? _running.Keys.First() : -1);
            if (_running.TryGetValue(key, out var r)) _running[key] = r with { Stage = stage };
        }
    }
}
