using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;

namespace Corvus.Native.Providers.Worker;

/// <summary>How a <see cref="WorkerPool"/> starts its workers.</summary>
public sealed record WorkerPoolOptions
{
    /// <summary>Null: <see cref="WorkerPool.EnableVariable"/> decides.</summary>
    public bool? Enabled { get; init; }
    /// <summary>Bytes; 0: none; null: <see cref="WorkerPool.MemoryVariable"/>, else half of the available memory.</summary>
    public long? MemoryLimitBytes { get; init; }
    /// <summary>The worker command; null: this program's own <c>corvus worker</c>.</summary>
    public ChildProcessStart? Start { get; init; }
    /// <summary>How long a starting worker may use no CPU; the whole start is bounded at three times this.</summary>
    public TimeSpan StartTimeout { get; init; } = TimeSpan.FromSeconds(30);
}

/// <summary>Runs ops in memory-capped <c>corvus worker</c> processes, one per kind, restarted after a crash; on unless <see cref="EnableVariable"/> is 0.</summary>
/// <remarks>Memory cap: a Job Object on Windows, RLIMIT_DATA on Linux, a footprint watchdog on macOS. A crash fails only
/// the request in flight, as provider_unavailable with the exit code and last stderr lines; the cap is limit_exceeded
/// naming <see cref="MemoryVariable"/>. Neither returns partial data.</remarks>
public sealed class WorkerPool(WorkerPoolOptions? options = null) : IDisposable
{
    /// <summary>0 turns every worker off: the file tools then read in the server.</summary>
    public const string EnableVariable = "CORVUS_WORKER_HOST";

    /// <summary>Memory limit of each worker in MB; 0 or off: none. Default: half of the memory available to this process.</summary>
    public const string MemoryVariable = "CORVUS_WORKER_MEMORY_MB";

    /// <summary>The smallest limit applied: below it the runtime itself does not start under RLIMIT_DATA.</summary>
    public const long MinimumMemoryBytes = 256L << 20;

    private static readonly WorkerPool Default = new();
    private static readonly AsyncLocal<WorkerPool?> SharedOverride = new();

    /// <summary>The server's pool, configured from the environment; its workers end with the server.</summary>
    public static WorkerPool Shared => SharedOverride.Value ?? Default;

    /// <summary>The pool a test set with <see cref="UseShared"/> in this flow, or null.</summary>
    internal static WorkerPool? Override => SharedOverride.Value;

    /// <summary>Tests: <paramref name="pool"/> serves <see cref="Shared"/> in the calling flow until disposed.</summary>
    internal static IDisposable UseShared(WorkerPool pool)
    {
        var before = SharedOverride.Value;
        SharedOverride.Value = pool;
        return new RestoreShared(before);
    }

    private sealed class RestoreShared(WorkerPool? before) : IDisposable
    {
        public void Dispose() => SharedOverride.Value = before;
    }

    private readonly WorkerPoolOptions _options = options ?? new WorkerPoolOptions();
    private readonly Dictionary<string, Slot> _slots = [];
    private int _disposed;

    /// <summary>A worker of one kind, its start serialized, and whether it reported running out of memory.</summary>
    private sealed class Slot
    {
        public readonly SemaphoreSlim Gate = new(1, 1);
        public WorkerConnection? Connection;
        public volatile bool OutOfMemory;
    }

    /// <summary>Tests: the requests the workers of every kind are running now.</summary>
    internal int RunningRequests
    {
        get { lock (_slots) return _slots.Values.Sum(s => s.Connection?.Running.Count ?? 0); }
    }

    public bool Enabled => _options.Enabled ?? Environment.GetEnvironmentVariable(EnableVariable)?.Trim() is not ("0" or "false" or "off");

    /// <summary>The memory limit each worker gets, in bytes, or null for none.</summary>
    public long? MemoryLimitBytes => _options.MemoryLimitBytes is { } c
        ? (c > 0 ? Math.Max(c, MinimumMemoryBytes) : null)
        : ParseMemory(Environment.GetEnvironmentVariable(MemoryVariable), GC.GetGCMemoryInfo().TotalAvailableMemoryBytes);

    /// <summary>A <see cref="MemoryVariable"/> value against <paramref name="available"/> bytes; unset or unreadable gives the default.</summary>
    public static long? ParseMemory(string? value, long available)
    {
        var v = value?.Trim().ToLowerInvariant();
        if (v is "0" or "off" or "none") return null;
        if (long.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out var mb) && mb > 0) return Math.Max(mb << 20, MinimumMemoryBytes);
        return available > 0 ? Math.Max(available / 2, MinimumMemoryBytes) : null;
    }

    /// <summary>Runs <paramref name="op"/> in the worker of <paramref name="kind"/>; throws provider_unavailable (host off or worker crashed), limit_exceeded (memory limit) or timeout; <paramref name="file"/> names the input in the error.</summary>
    public async Task<JsonElement> RunAsync(string kind, string op, JsonObject? args, TimeSpan timeout, CancellationToken cancellationToken, string? file = null)
    {
        if (!Enabled)
            throw new ToolError(ErrorCode.ProviderUnavailable, $"The worker host is off ({EnableVariable}=0); unset {EnableVariable} to turn it on.");
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        var slot = SlotOf(kind);
        var connection = await ConnectAsync(kind, slot, cancellationToken).ConfigureAwait(false);
        try { return await connection.RequestAsync(op, args, timeout, cancellationToken).ConfigureAwait(false); }
        catch (ToolError e) when (e.Code == ErrorCode.ProviderUnavailable && connection.KillReason is { } reason && reason != "disposed")
        {
            // Stopped for another request's timeout: run this one once more on a fresh worker.
            await RetireAsync(slot, connection).ConfigureAwait(false);
            connection = await ConnectAsync(kind, slot, cancellationToken).ConfigureAwait(false);
            return await RequestOnce(kind, op, args, timeout, slot, connection, file, cancellationToken).ConfigureAwait(false);
        }
        catch (ToolError e) when (e.Code == ErrorCode.ProviderUnavailable && connection.EndedOnItsOwn && !cancellationToken.IsCancellationRequested
                                  && Volatile.Read(ref _disposed) == 0)
        {
            // A crash or the memory limit ends every request on the worker: each
            // runs once more on a worker of its own, so only its cause fails.
            await RetireAsync(slot, connection).ConfigureAwait(false);
            return await RunAloneAsync(kind, op, args, timeout, file, cancellationToken).ConfigureAwait(false);
        }
        catch (ToolError e) when (e.Code is ErrorCode.LimitExceeded or ErrorCode.ProviderUnavailable)
        {
            throw await Failed(kind, op, slot, connection, e, file).ConfigureAwait(false);
        }
    }

    /// <summary>Runs one request on a worker started for it alone and ended after; its crash or memory limit is named as this request's own.</summary>
    private async Task<JsonElement> RunAloneAsync(string kind, string op, JsonObject? args, TimeSpan timeout, string? file, CancellationToken cancellationToken)
    {
        var slot = new Slot();
        var connection = await ConnectAsync(kind, slot, cancellationToken).ConfigureAwait(false);
        try { return await connection.RequestAsync(op, args, timeout, cancellationToken).ConfigureAwait(false); }
        catch (ToolError e) when (e.Code is ErrorCode.LimitExceeded or ErrorCode.ProviderUnavailable)
        {
            var failed = await Failed(kind, op, slot, connection, e, file).ConfigureAwait(false);
            throw new ToolError(failed.Code, $"Run alone after the {kind} worker ended, the request ended its worker again: {failed.Message}", failed.Remediation)
                { Retryable = false };
        }
        finally { connection.Dispose(); }
    }

    private async Task<JsonElement> RequestOnce(string kind, string op, JsonObject? args, TimeSpan timeout, Slot slot, WorkerConnection connection, string? file,
        CancellationToken cancellationToken)
    {
        try { return await connection.RequestAsync(op, args, timeout, cancellationToken).ConfigureAwait(false); }
        catch (ToolError e) when (e.Code is ErrorCode.LimitExceeded or ErrorCode.ProviderUnavailable)
        {
            throw await Failed(kind, op, slot, connection, e, file).ConfigureAwait(false);
        }
    }

    /// <summary>The error of a request whose worker crashed or reached its memory limit; that worker is retired.</summary>
    private async Task<ToolError> Failed(string kind, string op, Slot slot, WorkerConnection connection, ToolError e, string? file)
    {
        var outOfMemory = connection.MemoryLimitReached != null || slot.OutOfMemory;
        if (e.Code == ErrorCode.ProviderUnavailable || outOfMemory) await RetireAsync(slot, connection).ConfigureAwait(false);
        if (!outOfMemory) return e;
        var what = (connection.MemoryLimitReached ?? MemoryLimitBytes) is { } bytes
            ? $"its memory limit of {bytes >> 20} MB ({MemoryVariable})" : "the memory available to it";
        return new ToolError(ErrorCode.LimitExceeded,
            $"The {kind} worker reached {what} while running '{op}'{(file != null ? $" on {file}" : "")}; nothing from that request is kept.",
            $"raise {MemoryVariable}, or run the call on a smaller file") { Retryable = false };
    }

    /// <summary>How long a cancelled request has to stop before its worker, and every request on it, is ended.</summary>
    public static readonly TimeSpan CancelGrace = TimeSpan.FromSeconds(2);

    /// <summary>Starts the worker of <paramref name="kind"/> unless running, separating start failures from request crashes.</summary>
    public async Task StartAsync(string kind, CancellationToken cancellationToken)
    {
        if (!Enabled)
            throw new ToolError(ErrorCode.ProviderUnavailable, $"The worker host is off ({EnableVariable}=0); unset {EnableVariable} to turn it on.");
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        await ConnectAsync(kind, SlotOf(kind), cancellationToken).ConfigureAwait(false);
    }

    private Slot SlotOf(string kind)
    {
        lock (_slots)
        {
            if (!_slots.TryGetValue(kind, out var slot)) _slots[kind] = slot = new Slot();
            return slot;
        }
    }

    private async Task<WorkerConnection> ConnectAsync(string kind, Slot slot, CancellationToken cancellationToken)
    {
        await slot.Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (slot.Connection is { IsAlive: true } alive) return alive;
            slot.Connection?.Dispose();
            slot.Connection = null;
            slot.OutOfMemory = false;
            var start = (_options.Start ?? OwnCommand()) with { MemoryLimitBytes = MemoryLimitBytes, MemoryLimitOnPosix = true };
            // A pool worker reads the call's paths, so it resolves a relative one
            // against the server's folder, not a private one.
            start = start with { WorkingDirectory = start.WorkingDirectory ?? Environment.CurrentDirectory };
            if (OperatingSystem.IsMacOS() && start.MemoryLimitBytes is { } bytes)
                // The watchdog ends the worker; the GC's own limit fails a managed allocation first, which the worker reports.
                start = start with { Environment = new Dictionary<string, string?>(start.Environment) { ["DOTNET_GCHeapHardLimit"] = "0x" + bytes.ToString("X", CultureInfo.InvariantCulture) } };
            // Concurrent requests, as the worker answers in any order; a cancelled one is asked to stop before the worker is ended.
            var connection = WorkerConnection.Start($"{kind} worker", start,
                options: new WorkerConnectionOptions { MemoryLimitVariable = MemoryVariable, Concurrent = true, CancelGrace = CancelGrace });
            connection.EventReceived += e => { if (e.Name == WorkerHost.OutOfMemoryEvent) slot.OutOfMemory = true; };
            // A busy machine stretches a start that keeps using CPU, so the start limit counts idle time only.
            try { await connection.WaitReadyAsync(_options.StartTimeout * 3, cancellationToken, idle: _options.StartTimeout).ConfigureAwait(false); }
            catch
            {
                connection.Dispose();
                throw;
            }
            return slot.Connection = connection;
        }
        finally { slot.Gate.Release(); }
    }

    private static async Task RetireAsync(Slot slot, WorkerConnection connection)
    {
        await slot.Gate.WaitAsync().ConfigureAwait(false);
        try
        {
            connection.Dispose();
            if (ReferenceEquals(slot.Connection, connection)) slot.Connection = null;
        }
        finally { slot.Gate.Release(); }
    }

    /// <summary>This program run with <paramref name="command"/> (default <c>worker</c>): its apphost when there is one, else the dotnet host running corvus.dll.</summary>
    internal static ChildProcessStart OwnCommand(string command = WorkerHost.Command)
    {
        var dll = typeof(WorkerPool).Assembly.Location;
        var apphost = Path.Combine(Path.GetDirectoryName(dll)!, Path.GetFileNameWithoutExtension(dll) + (OperatingSystem.IsWindows() ? ".exe" : ""));
        if (File.Exists(apphost)) return new ChildProcessStart(apphost, [command]) { OwnProgram = true };
        return new ChildProcessStart(DotnetHost(), [dll, command]) { OwnProgram = true };
    }

    /// <summary>The dotnet host running this program, else DOTNET_HOST_PATH, else the host beside the running runtime; "dotnet" (found on PATH) when none exists.</summary>
    internal static string DotnetHost()
    {
        var file = OperatingSystem.IsWindows() ? "dotnet.exe" : "dotnet";
        if (Environment.ProcessPath is { } p && Path.GetFileNameWithoutExtension(p).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) return p;
        // The runtime folder is <root>/shared/Microsoft.NETCore.App/<version>/;
        // the host is <root>/dotnet.
        string?[] candidates = [Environment.GetEnvironmentVariable("DOTNET_HOST_PATH"),
            Path.GetFullPath(Path.Combine(System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory(), "..", "..", "..", file))];
        return candidates.FirstOrDefault(c => c != null && Path.IsPathFullyQualified(c) && File.Exists(c)) ?? "dotnet";
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        lock (_slots)
            foreach (var slot in _slots.Values) slot.Connection?.Dispose();
    }
}
