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
    public TimeSpan StartTimeout { get; init; } = TimeSpan.FromSeconds(30);
}

/// <summary>
/// Runs ops in <c>corvus worker</c> processes (<see cref="WorkerHost"/>), one per kind, started on first use and again
/// after a crash; a crash fails only the request in flight. Each worker's memory is capped (Windows: a Job Object; Linux:
/// RLIMIT_DATA; macOS: a footprint watchdog). A worker that crashes is reported as provider_unavailable with its exit
/// code and last stderr lines, one that reaches the cap as limit_exceeded naming <see cref="MemoryVariable"/>; neither
/// returns partial data. Off unless <see cref="EnableVariable"/> is 1.
/// </summary>
public sealed class WorkerPool(WorkerPoolOptions? options = null) : IDisposable
{
    /// <summary>1 turns the worker host on; off by default until the file tools use it.</summary>
    public const string EnableVariable = "CORVUS_WORKER_HOST";

    /// <summary>Memory limit of each worker in MB; 0 or off: none. Default: half of the memory available to this process.</summary>
    public const string MemoryVariable = "CORVUS_WORKER_MEMORY_MB";

    /// <summary>The smallest limit applied: below it the runtime itself does not start under RLIMIT_DATA.</summary>
    public const long MinimumMemoryBytes = 256L << 20;

    private static readonly WorkerPool Default = new();
    private static readonly AsyncLocal<WorkerPool?> SharedOverride = new();

    /// <summary>The server's pool, configured from the environment; its workers end with the server.</summary>
    public static WorkerPool Shared => SharedOverride.Value ?? Default;

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

    public bool Enabled => _options.Enabled ?? Environment.GetEnvironmentVariable(EnableVariable) == "1";

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

    /// <summary>
    /// Runs <paramref name="op"/> in the worker of <paramref name="kind"/> and returns its result. <paramref name="file"/>
    /// names the input in a limit or crash error. Throws <see cref="ToolError"/>: provider_unavailable when the host is off
    /// or the worker crashed, limit_exceeded when it reached its memory limit, timeout past <paramref name="timeout"/>.
    /// </summary>
    public async Task<JsonElement> RunAsync(string kind, string op, JsonObject? args, TimeSpan timeout, CancellationToken cancellationToken, string? file = null)
    {
        if (!Enabled)
            throw new ToolError(ErrorCode.ProviderUnavailable, $"The worker host is off; {EnableVariable}=1 turns it on.");
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        Slot slot;
        lock (_slots)
            if (!_slots.TryGetValue(kind, out slot!)) _slots[kind] = slot = new Slot();
        var connection = await ConnectAsync(kind, slot, cancellationToken).ConfigureAwait(false);
        try { return await connection.RequestAsync(op, args, timeout, cancellationToken).ConfigureAwait(false); }
        catch (ToolError e) when (e.Code is ErrorCode.LimitExceeded or ErrorCode.ProviderUnavailable)
        {
            var outOfMemory = connection.MemoryLimitReached != null || slot.OutOfMemory;
            // A worker that crashed or ran out of memory is not reused: the next call starts a fresh one.
            if (e.Code == ErrorCode.ProviderUnavailable || outOfMemory) await RetireAsync(slot, connection).ConfigureAwait(false);
            if (!outOfMemory) throw;
            var what = (connection.MemoryLimitReached ?? MemoryLimitBytes) is { } bytes
                ? $"its memory limit of {bytes >> 20} MB ({MemoryVariable})" : "the memory available to it";
            throw new ToolError(ErrorCode.LimitExceeded,
                $"The {kind} worker reached {what} while running '{op}'{(file != null ? $" on {file}" : "")}; nothing from that request is kept.",
                $"raise {MemoryVariable}, or run the call on a smaller file") { Retryable = false };
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
            if (OperatingSystem.IsMacOS() && start.MemoryLimitBytes is { } bytes)
                // The watchdog ends the worker; the GC's own limit fails a managed allocation first, which the worker reports.
                start = start with { Environment = new Dictionary<string, string?>(start.Environment) { ["DOTNET_GCHeapHardLimit"] = "0x" + bytes.ToString("X", CultureInfo.InvariantCulture) } };
            var connection = WorkerConnection.Start($"{kind} worker", start, options: new WorkerConnectionOptions { MemoryLimitVariable = MemoryVariable });
            connection.EventReceived += e => { if (e.Name == WorkerHost.OutOfMemoryEvent) slot.OutOfMemory = true; };
            try { await connection.WaitReadyAsync(_options.StartTimeout, cancellationToken).ConfigureAwait(false); }
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

    /// <summary>This program's <c>worker</c> command: its apphost when there is one, else the dotnet host running corvus.dll.</summary>
    internal static ChildProcessStart OwnCommand()
    {
        var dll = typeof(WorkerPool).Assembly.Location;
        var apphost = Path.Combine(Path.GetDirectoryName(dll)!, Path.GetFileNameWithoutExtension(dll) + (OperatingSystem.IsWindows() ? ".exe" : ""));
        if (File.Exists(apphost)) return new ChildProcessStart(apphost, [WorkerHost.Command]);
        var host = Environment.ProcessPath is { } p && Path.GetFileNameWithoutExtension(p) == "dotnet" ? p : "dotnet";
        return new ChildProcessStart(host, [dll, WorkerHost.Command]);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        lock (_slots)
            foreach (var slot in _slots.Values) slot.Connection?.Dispose();
    }
}
