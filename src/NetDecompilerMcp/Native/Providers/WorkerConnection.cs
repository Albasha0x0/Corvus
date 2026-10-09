using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native.Providers;

/// <summary>
/// A running worker process and its request channel (see <see cref="WorkerProtocol"/>). Requests are serialized;
/// a request that exceeds its time limit or is cancelled while running kills the worker, because an engine busy in
/// native code cannot be interrupted. Worker death fails the running request with ProviderUnavailable and the
/// last stderr lines.
/// </summary>
public sealed class WorkerConnection : IDisposable
{
    private readonly ChildProcess _process;
    private readonly string _name;
    private readonly Func<ErrorCode, string, string?> _remediation;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly TextTail _stderr = new(32_000);
    private readonly TaskCompletionSource<JsonElement> _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly object _sync = new();
    private TaskCompletionSource<WorkerMessage.Response>? _pending;
    private long _pendingId;
    private long _nextId;
    private string? _killReason;
    private int _disposed;

    /// <summary>Progress and other events; raised on the reader thread.</summary>
    public event Action<WorkerMessage.Event>? EventReceived;

    private WorkerConnection(ChildProcess process, string name, Func<ErrorCode, string, string?> remediation)
    {
        _process = process;
        _name = name;
        _remediation = remediation;
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

    private readonly TaskCompletionSource _stdoutDone = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <param name="name">Engine name used in error messages ("IDA worker").</param>
    /// <param name="remediation">Next step for an error code and message, or null.</param>
    public static WorkerConnection Start(string name, ChildProcessStart start, Func<ErrorCode, string, string?>? remediation = null) =>
        new(ChildProcess.Start(start), name, remediation ?? ((_, _) => null));

    public int ProcessId => _process.Id;
    public bool IsAlive => !_closed.Task.IsCompleted && !_process.HasExited;
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
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!IsAlive) throw Died(op);
            var id = Interlocked.Increment(ref _nextId);
            var tcs = new TaskCompletionSource<WorkerMessage.Response>(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_sync) { _pending = tcs; _pendingId = id; }
            var line = Encoding.UTF8.GetBytes(WorkerProtocol.EncodeRequest(id, op, args));
            var write = Task.Run(() => { _process.StandardInput.Write(line); _process.StandardInput.Flush(); }, CancellationToken.None);

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

            if (tcs.Task.IsCompleted)
            {
                var r = tcs.Task.Result;
                if (r.Ok) return r.Result;
                var code = WorkerProtocol.MapCode(r.ErrorCode);
                var message = r.ErrorMessage ?? "error";
                if (code is ErrorCode.ProviderUnavailable or ErrorCode.Failed or ErrorCode.IoError)
                    message += StderrSuffix();
                throw new ToolError(code, message, _remediation(code, message));
            }
            if (_closed.Task.IsCompleted && !timer.IsCancellationRequested) throw Died(op);
            if (cancellationToken.IsCancellationRequested)
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
            lock (_sync) { _pending = null; }
            _gate.Release();
        }
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
                            if (_pending != null && (r.Id == null || r.Id == _pendingId)) target = _pending;
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
