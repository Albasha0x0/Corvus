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
    /// <summary>
    /// Times the start wait, request time limits, the quiet limit and the cancel grace; waits for the process to exit
    /// keep the system clock.
    /// </summary>
    public TimeProvider Time { get; init; } = TimeProvider.System;
}

/// <summary>A request the worker is running: its op, when it was sent, and the last progress the worker reported for it.</summary>
public sealed record WorkerRequestState(long Id, string Op, DateTime StartedUtc, string? Stage)
{
    /// <summary>Progress events the worker sent for this request; none means the worker never reported running it.</summary>
    public int ProgressEvents { get; init; }
    /// <summary>When the request was sent or last reported progress, as a timestamp of the connection's clock.</summary>
    public long LastProgressTicks { get; init; }
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
    /// <summary>How long a dead worker's error waits for its exit code and stderr tail.</summary>
    private static readonly TimeSpan ExitGrace = TimeSpan.FromSeconds(2);

    private readonly TaskCompletionSource _stdoutDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _stderrDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly object _sync = new();
    private readonly Dictionary<long, TaskCompletionSource<WorkerMessage.Response>> _pending = [];
    private readonly Dictionary<long, WorkerRequestState> _running = [];
    private readonly Dictionary<long, string> _requestLog = [];
    // Whether the worker writes request log lines at all (the Ghidra worker does).
    private bool _logsRequests;
    private readonly BlockingCollection<(byte[] Line, TaskCompletionSource Written)> _writes = [];
    private long _nextId;
    private int _waiting;
    // Timestamp of the last stdout line: a live worker reports progress every 2 s.
    private long _lastLineTicks;
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
        _lastLineTicks = options.Time.GetTimestamp();
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

    /// <summary>Why <see cref="Kill"/> or <see cref="Dispose"/> ended the worker, or null while it was not ended on purpose.</summary>
    public string? KillReason
    {
        get { lock (_sync) return _killReason; }
    }

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

    /// <summary>Tests: the worker's log line read for request <paramref name="id"/>, or null when none was read.</summary>
    internal string? LogLineOf(long id)
    {
        lock (_sync) return _requestLog.GetValueOrDefault(id);
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
        var done = await Task.WhenAny(_ready.Task, _closed.Task, Task.Delay(timeout, _options.Time, cancellationToken)).ConfigureAwait(false);
        if (done == _ready.Task) return _ready.Task.Result;
        if (done == _closed.Task) throw await DiedAsync("start").ConfigureAwait(false);
        var stall = cancellationToken.IsCancellationRequested ? null : Stall();
        Kill(cancellationToken.IsCancellationRequested ? "cancelled" : "start timeout");
        cancellationToken.ThrowIfCancellationRequested();
        throw new ToolError(ErrorCode.Timeout, $"{_name} did not start within {Seconds(timeout)}.{stall}{StderrSuffix()}",
            _remediation(ErrorCode.Timeout, "start"));
    }

    /// <summary>
    /// What the request reached: written or not, the worker's progress reports and log lines for it, its last stage,
    /// and how long ago the worker last wrote, so a slow request is told from one the worker never ran.
    /// </summary>
    private string Activity(long id, Task write)
    {
        WorkerRequestState? r;
        string? log;
        bool logs;
        lock (_sync)
        {
            r = _running.GetValueOrDefault(id);
            log = _requestLog.GetValueOrDefault(id);
            logs = _logsRequests;
        }
        var quiet = _options.Time.GetElapsedTime(Volatile.Read(ref _lastLineTicks));
        return (write.IsCompletedSuccessfully ? "" : " The request had not been written to the worker.")
            + $" Progress events: {r?.ProgressEvents ?? 0}."
            + (r?.Stage != null ? $" Last stage: {r.Stage}." : "")
            + (logs ? $" Worker log: {log ?? "no line for this request read yet"}." : "")
            + $" Last worker message: {Seconds(quiet)} ago.";
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

    /// <summary>
    /// Sends one request and waits for its response; throws <see cref="ToolError"/> for worker errors. With
    /// <paramref name="quiet"/>, the request also stops once the worker reports no progress on it for that long.
    /// </summary>
    public async Task<JsonElement> RequestAsync(string op, JsonObject? args, TimeSpan timeout, CancellationToken cancellationToken, TimeSpan? quiet = null)
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
            if (!IsAlive) throw await DiedAsync(op).ConfigureAwait(false);
            id = Interlocked.Increment(ref _nextId);
            Interlocked.Increment(ref _requests);
            var tcs = new TaskCompletionSource<WorkerMessage.Response>(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_sync)
            {
                _pending[id] = tcs;
                _running[id] = new WorkerRequestState(id, op, DateTime.UtcNow, null) { LastProgressTicks = _options.Time.GetTimestamp() };
            }
            var write = Send(WorkerProtocol.EncodeRequest(id, op, args, timeout));

            using var expiry = new CancellationTokenSource(timeout, _options.Time);
            using var timer = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, expiry.Token);
            var wentQuiet = quiet is { } q ? QuietAsync(id, q, timer) : Task.FromResult(false);
            var stop = Task.Delay(Timeout.Infinite, timer.Token);
            try
            {
                var w = await Task.WhenAny(write, tcs.Task, _closed.Task, stop).ConfigureAwait(false);
                if (w == write && write.IsFaulted && !tcs.Task.IsCompleted) throw await DiedAsync(op).ConfigureAwait(false);
                if (w == write) await Task.WhenAny(tcs.Task, _closed.Task, stop).ConfigureAwait(false);
            }
            catch (IOException) { throw await DiedAsync(op).ConfigureAwait(false); }

            if (tcs.Task.IsCompleted) return Result(tcs.Task.Result);
            if (_closed.Task.IsCompleted && !timer.IsCancellationRequested) throw await DiedAsync(op).ConfigureAwait(false);
            var cancelled = cancellationToken.IsCancellationRequested;
            var limit = wentQuiet.IsCompletedSuccessfully && wentQuiet.Result
                ? $"reported no progress on '{op}' for {Seconds(quiet!.Value)}"
                : $"did not finish '{op}' within {Seconds(timeout)}";
            // Read the worker at the timeout, before the cancel, so the state shows the request still running or lost.
            var activity = cancelled ? "" : Activity(id, write);
            var stall = cancelled ? "" : Stall();
            if (await CancelAsync(id, write, tcs.Task).ConfigureAwait(false))
            {
                if (cancelled) throw new OperationCanceledException(cancellationToken);
                if (tcs.Task.Result.Ok) return tcs.Task.Result.Result;
                throw new ToolError(ErrorCode.Timeout, $"{_name} {limit}; the request was cancelled.{activity}{stall}",
                    _remediation(ErrorCode.Timeout, op));
            }
            if (cancelled)
            {
                Kill($"'{op}' cancelled");
                throw new OperationCanceledException(cancellationToken);
            }
            Kill($"'{op}' timed out");
            throw new ToolError(ErrorCode.Timeout,
                $"{_name} {limit}; the worker was stopped.{activity}{stall}{StderrSuffix()}",
                _remediation(ErrorCode.Timeout, op));
        }
        finally
        {
            lock (_sync)
            {
                _pending.Remove(id);
                _running.Remove(id);
                _requestLog.Remove(id);
            }
            if (serial) _gate.Release();
        }
    }

    // True once request id has gone quiet without a progress event, and then
    // cancels timer; false when the request ends first or the timer fires.
    private async Task<bool> QuietAsync(long id, TimeSpan quiet, CancellationTokenSource timer)
    {
        var token = timer.Token;
        try
        {
            while (true)
            {
                long last;
                lock (_sync)
                {
                    if (!_running.TryGetValue(id, out var r)) return false;
                    last = r.LastProgressTicks;
                }
                var left = quiet - _options.Time.GetElapsedTime(last);
                if (left <= TimeSpan.Zero)
                {
                    timer.Cancel();
                    return true;
                }
                await Task.Delay(left, _options.Time, token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException) { return false; }
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
        await Task.WhenAny(write, Task.Delay(grace, _options.Time)).ConfigureAwait(false);
        if (!write.IsCompletedSuccessfully) return false;
        try
        {
            await Send(WorkerProtocol.EncodeRequest(Interlocked.Increment(ref _nextId), WorkerProtocol.CancelOp, new JsonObject { ["id"] = id }))
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException) { return false; }
        await Task.WhenAny(response, _closed.Task, Task.Delay(grace, _options.Time)).ConfigureAwait(false);
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

    /// <summary>
    /// The error for a worker that went away during <paramref name="op"/>. Every path that sees the death builds it here,
    /// after waiting up to <see cref="ExitGrace"/> for the exit and the stderr tail, so the error names both.
    /// </summary>
    private async Task<ToolError> DiedAsync(string op)
    {
        string? reason;
        lock (_sync) reason = _killReason;
        // A broken pipe or a closed stdout can be seen before the exit is reaped (macOS, Linux).
        if (reason == null)
            await Task.WhenAny(Task.WhenAll(_process.Exited, _stderrDone.Task), Task.Delay(ExitGrace)).ConfigureAwait(false);
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
                Volatile.Write(ref _lastLineTicks, _options.Time.GetTimestamp());
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
            var line = new StringBuilder();
            while ((n = reader.Read(buffer, 0, buffer.Length)) > 0)
            {
                _stderr.Append(new string(buffer, 0, n));
                for (var k = 0; k < n; k++)
                {
                    if (buffer[k] != '\n') { line.Append(buffer[k]); continue; }
                    RequestLogged(line.ToString().TrimEnd('\r'));
                    line.Clear();
                }
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
        _stderrDone.TrySetResult();
    }

    private void OnClosed()
    {
        _writes.CompleteAdding();
        _closed.TrySetResult();
    }

    /// <summary>Keeps the worker's last log line of a pending request, apart from the stderr tail that other output pushes out.</summary>
    private void RequestLogged(string line)
    {
        if (!line.StartsWith(WorkerProtocol.RequestLogPrefix, StringComparison.Ordinal)) return;
        var rest = line.AsSpan(WorkerProtocol.RequestLogPrefix.Length);
        var space = rest.IndexOf(' ');
        if (space <= 0 || !long.TryParse(rest[..space], out var id)) return;
        lock (_sync)
        {
            _logsRequests = true;
            if (_pending.ContainsKey(id)) _requestLog[id] = line;
        }
    }

    /// <summary>Keeps the stage of a progress event on its request (the only one running when the event names none).</summary>
    private void Progressed(JsonElement body)
    {
        long? id = body.TryGetProperty("id", out var i) && i.TryGetInt64(out var n) ? n : null;
        var stage = body.TryGetProperty("stage", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString() : null;
        lock (_sync)
        {
            var key = id ?? (_running.Count == 1 ? _running.Keys.First() : -1);
            if (_running.TryGetValue(key, out var r))
                _running[key] = r with { Stage = string.IsNullOrEmpty(stage) ? r.Stage : stage, ProgressEvents = r.ProgressEvents + 1, LastProgressTicks = _options.Time.GetTimestamp() };
        }
    }
}
