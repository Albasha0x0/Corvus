using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Corvus.Core;

/// <summary>
/// Identical read-only calls share one run (D8 substitute for MCP tasks): a call whose <see cref="Key"/> matches running
/// work awaits that work instead of starting a second copy. The work outlives a caller that left at its deadline, so the
/// same call made again picks it up; it is cancelled only when every caller's client cancelled, or at its own limit.
/// </summary>
public sealed class CallJoin
{
    private static readonly ConditionalWeakTable<ServerOptions, CallJoin> Servers = new();
    private readonly Dictionary<string, Entry> _running = new(StringComparer.Ordinal);

    public static CallJoin For(ServerOptions options) => Servers.GetValue(options, _ => new CallJoin());

    private sealed class Entry(Task work, CancellationTokenSource stop)
    {
        public Task Work { get; } = work;
        public CancellationTokenSource Stop { get; } = stop;
        /// <summary>Read after <see cref="Stop"/> is disposed too.</summary>
        public CancellationToken Token { get; } = stop.Token;
        public int Attached;
    }

    /// <summary>One caller's view: the result (a copy per caller), the shared work and whether it joined work already running.</summary>
    public readonly record struct Joined<T>(Task<T> Result, Task Work, bool WasRunning, CancellationToken Stopped);

    /// <summary>Work running now.</summary>
    public int Running { get { lock (_running) return _running.Count; } }

    /// <summary>Whether work for <paramref name="key"/> is running.</summary>
    public bool IsRunning(string key) { lock (_running) return _running.ContainsKey(key); }

    /// <summary>
    /// The join key: tool name plus SHA-256 of the arguments as canonical JSON (object keys sorted, no whitespace); null
    /// unless <paramref name="readOnly"/> (the tool's contract flag), and for session tools (their answer is about the moment of the call).
    /// </summary>
    public static string? Key(string? tool, bool readOnly, IEnumerable<KeyValuePair<string, JsonElement>>? arguments)
    {
        if (tool == null || !readOnly || Toolsets.FamilyOf(tool) == Toolsets.Session) return null;
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            foreach (var (name, value) in (arguments ?? []).OrderBy(a => a.Key, StringComparer.Ordinal))
            {
                writer.WritePropertyName(name);
                WriteCanonical(writer, value);
            }
            writer.WriteEndObject();
        }
        return tool + ":" + Convert.ToHexStringLower(SHA256.HashData(buffer.ToArray()));
    }

    private static void WriteCanonical(Utf8JsonWriter writer, JsonElement value)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var p in value.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(p.Name);
                    WriteCanonical(writer, p.Value);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in value.EnumerateArray()) WriteCanonical(writer, item);
                writer.WriteEndArray();
                break;
            default:
                value.WriteTo(writer);
                break;
        }
    }

    /// <summary>
    /// Runs <paramref name="work"/> under <paramref name="key"/>, or attaches to the run already under it. The work's token
    /// is cancelled when every attached caller's <paramref name="clientToken"/> is cancelled, or after <paramref name="limit"/>
    /// from its start, measured by <paramref name="time"/> (the system clock when null). <paramref name="copy"/> gives each
    /// caller its own result to change.
    /// </summary>
    public Joined<T> Run<T>(string key, Func<CancellationToken, Task<T>> work, CancellationToken clientToken, TimeSpan? limit, Func<T, T> copy,
        TimeProvider? time = null)
    {
        Entry entry;
        bool wasRunning;
        Action? launch = null;
        lock (_running)
        {
            wasRunning = _running.TryGetValue(key, out entry!) && entry.Work is Task<T> && !entry.Stop.IsCancellationRequested;
            if (wasRunning) { entry.Attached++; }
            else
            {
                var stop = limit is { } l ? new CancellationTokenSource(l, time ?? TimeProvider.System) : new CancellationTokenSource();
                // Started after the lock; the placeholder keeps a second caller from starting its own copy meanwhile.
                var start = new TaskCompletionSource<Task<T>>(TaskCreationOptions.RunContinuationsAsynchronously);
                var shared = start.Task.Unwrap();
                entry = new Entry(shared, stop) { Attached = 1 };
                _running[key] = entry;
                var self = entry;
                shared.ContinueWith(_ =>
                {
                    lock (_running) if (_running.TryGetValue(key, out var e) && e == self) _running.Remove(key);
                    self.Stop.Dispose();
                }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                launch = () => start.SetResult(Start(work, stop.Token));
            }
        }
        launch?.Invoke();
        var attached = entry;
        if (clientToken.CanBeCanceled)
        {
            var registration = clientToken.Register(() => Detach(attached));
            attached.Work.ContinueWith(_ => registration.Dispose(), CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
        var result = ((Task<T>)attached.Work).ContinueWith(t => copy(t.GetAwaiter().GetResult()), CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        return new Joined<T>(result, attached.Work, wasRunning, attached.Token);
    }

    private static Task<T> Start<T>(Func<CancellationToken, Task<T>> work, CancellationToken token)
    {
        try { return work(token); }
        catch (Exception ex) { return Task.FromException<T>(ex); }
    }

    private void Detach(Entry entry)
    {
        lock (_running)
            if (--entry.Attached > 0) return;
        try { entry.Stop.Cancel(); }
        catch (ObjectDisposedException) { } // finished meanwhile
    }
}
