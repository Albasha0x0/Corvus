using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;

namespace Corvus.Native.Providers.Worker;

/// <summary>One worker op: its arguments in, its result record out; a <see cref="ToolError"/> is answered as that error.</summary>
public delegate Task<JsonNode?> WorkerOp(JsonObject args, CancellationToken cancellationToken);

/// <summary>Ops a <c>corvus worker</c> answers beyond ping, found as providers; a name taken twice fails the worker's start.</summary>
public interface IWorkerOps
{
    IReadOnlyDictionary<string, WorkerOp> Ops { get; }
}

/// <summary>The <c>corvus worker</c> process: runs untrusted ops so a crash ends it, not the server.</summary>
/// <remarks>Writes <c>ready</c> first. An op that runs out of memory is answered with <c>limit_exceeded</c>, then the
/// process exits, as its state is no longer trusted.</remarks>
public static class WorkerHost
{
    public const string Command = "worker";

    /// <summary>Event written before the process ends for lack of memory; carries the request id when one was running.</summary>
    public const string OutOfMemoryEvent = "out_of_memory";

    /// <summary>Set to 1 in the worker's environment to register the fixture ops (tests only).</summary>
    public const string FixtureOpsVariable = "CORVUS_WORKER_FIXTURE_OPS";

    /// <summary>Exit code after an op ran out of memory.</summary>
    public const int OutOfMemoryExitCode = 3;

    /// <summary>Runs the worker when <paramref name="args"/> is the worker command; null for any other command line.</summary>
    public static int? TryRun(string[] args)
    {
        if (args is not [Command]) return null;
        return Serve(Ops(Environment.GetEnvironmentVariable(FixtureOpsVariable) == "1"));
    }

    /// <summary>Answers requests on stdin with <paramref name="ops"/> until stdin closes, or until <paramref name="endOp"/> is answered; the exit code.</summary>
    internal static int Serve(IReadOnlyDictionary<string, WorkerOp> ops, string? endOp = null)
    {
        var protocol = Console.OpenStandardOutput();
        // Stdout carries answers only; anything a library prints goes to stderr, kept for error messages.
        Console.SetOut(Console.Error);
        using var input = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false));
        return Run(input, protocol, ops, endOp);
    }

    /// <summary>Writes an event line for ops that report outside a request (a stop, an exit); null before <see cref="Run"/>; false once the server closed the pipe.</summary>
    internal static Func<JsonObject, bool>? Emit { get; private set; }

    /// <summary>The ops this worker answers: ping and every <see cref="IWorkerOps"/> provider's, the fixture ops when <paramref name="fixtures"/>.</summary>
    internal static IReadOnlyDictionary<string, WorkerOp> Ops(bool fixtures)
    {
        var ops = new Dictionary<string, WorkerOp>(StringComparer.Ordinal) { ["ping"] = Ping };
        foreach (var provider in Core.Providers.Of<IWorkerOps>())
            foreach (var (name, op) in provider.Ops) ops.Add(name, op);
        if (fixtures)
        {
            ops["fixture_allocate"] = Allocate;
            ops["fixture_exit"] = (_, _) =>
            {
                Environment.FailFast("fixture_exit: the worker ends without unwinding");
                return Task.FromResult<JsonNode?>(null);
            };
            // Answers once the file the request names exists.
            ops["fixture_wait"] = async (args, ct) =>
            {
                var release = args["release"]!.GetValue<string>();
                while (!File.Exists(release)) await Task.Delay(20, ct).ConfigureAwait(false);
                return new JsonObject { ["pid"] = Environment.ProcessId };
            };
        }
        return ops;
    }

    private static Task<JsonNode?> Ping(JsonObject args, CancellationToken cancellationToken) =>
        Task.FromResult<JsonNode?>(new JsonObject { ["pid"] = Environment.ProcessId, ["echo"] = args["echo"]?.DeepClone() });

    /// <summary>Allocates written 16 MB blocks until one fails; <c>native</c> uses the native heap, <c>hang</c> then never answers.</summary>
    private static Task<JsonNode?> Allocate(JsonObject args, CancellationToken cancellationToken)
    {
        const int size = 16 << 20;
        var native = args["native"]?.GetValueKind() == JsonValueKind.True;
        var hang = args["hang"]?.GetValueKind() == JsonValueKind.True;
        var kept = new List<byte[]>();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (native)
            {
                IntPtr block;
                try { block = System.Runtime.InteropServices.Marshal.AllocHGlobal(size); }
                catch (OutOfMemoryException) when (hang) { Thread.Sleep(Timeout.Infinite); throw; }
                for (int i = 0; i < size; i += 4096) System.Runtime.InteropServices.Marshal.WriteByte(block, i, 1);
                continue;
            }
            var array = new byte[size];
            for (int i = 0; i < size; i += 4096) array[i] = 1;
            kept.Add(array);
        }
    }

    internal static int Run(TextReader input, Stream output, IReadOnlyDictionary<string, WorkerOp> ops, string? endOp = null)
    {
        var writer = new LineWriter(output);
        Emit = writer.TryWrite;
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            if (e.ExceptionObject is OutOfMemoryException) writer.TryWrite(new JsonObject { ["event"] = OutOfMemoryEvent });
        };
        writer.TryWrite(new JsonObject
        {
            ["event"] = "ready",
            ["pid"] = Environment.ProcessId,
            ["ops"] = new JsonArray([.. ops.Keys.Order(StringComparer.Ordinal).Select(k => (JsonNode)k)]),
        });
        var running = new ConcurrentDictionary<long, CancellationTokenSource>();
        var cancelled = new ConcurrentDictionary<long, bool>();
        var tasks = new List<Task>();
        while (input.ReadLine() is { } line)
        {
            if (Request(line) is not var (id, op, args, timeout)) continue;
            if (op == WorkerProtocol.CancelOp)
            {
                if (args["id"]?.GetValueKind() == JsonValueKind.Number && args["id"]!.GetValue<long>() is var target
                    && running.TryGetValue(target, out var stop))
                {
                    cancelled[target] = true;
                    stop.Cancel();
                }
                continue;
            }
            if (!ops.TryGetValue(op, out var run))
            {
                writer.Error(id, ErrorCode.InvalidArgument, $"the worker has no op '{op}'");
                continue;
            }
            var cts = new CancellationTokenSource();
            // Stop a little before the server's limit, so the answer arrives in time.
            if (timeout is { } t) cts.CancelAfter(t * 0.9);
            running[id] = cts;
            tasks.RemoveAll(t => t.IsCompleted);
            tasks.Add(Task.Run(async () =>
            {
                // Each request is one call: its own output count and expansion cap.
                using var spent = Spent.Enter(new Spent(cts.Token));
                try { writer.TryWrite(new JsonObject { ["id"] = id, ["ok"] = true, ["result"] = await run(args, cts.Token).ConfigureAwait(false) }); }
                catch (OutOfMemoryException)
                {
                    writer.TryWrite(new JsonObject { ["event"] = OutOfMemoryEvent, ["id"] = id });
                    writer.Error(id, ErrorCode.LimitExceeded, $"'{op}' ran out of memory");
                    Environment.Exit(OutOfMemoryExitCode);
                }
                catch (ToolError e) { writer.Error(id, e.Code, e.Message); }
                catch (OperationCanceledException) { writer.Error(id, cancelled.ContainsKey(id) ? ErrorCode.Cancelled : ErrorCode.Timeout, $"'{op}' was stopped"); }
                catch (Exception e) { writer.Error(id, ErrorCode.Failed, $"'{op}' failed: {e.GetType().Name}: {e.Message}"); }
                finally
                {
                    running.TryRemove(id, out _);
                    cancelled.TryRemove(id, out _);
                    cts.Dispose();
                }
            }));
            // The end op is answered before the worker exits, as the server waits for both.
            if (op == endOp)
            {
                tasks[^1].Wait();
                break;
            }
        }
        Task.WaitAll([.. tasks], TimeSpan.FromSeconds(5));
        return 0;
    }

    /// <summary>A request line as id, op, arguments and time limit; null for a line that is not a request.</summary>
    private static (long Id, string Op, JsonObject Args, TimeSpan? Timeout)? Request(string line)
    {
        try
        {
            if (JsonNode.Parse(line) is not JsonObject o || o["id"]?.GetValueKind() != JsonValueKind.Number
                || o["op"]?.GetValueKind() != JsonValueKind.String) return null;
            TimeSpan? timeout = o["timeout"]?.GetValueKind() == JsonValueKind.Number ? TimeSpan.FromSeconds(o["timeout"]!.GetValue<double>()) : null;
            return (o["id"]!.GetValue<long>(), o["op"]!.GetValue<string>(), o["args"] as JsonObject ?? [], timeout);
        }
        catch (JsonException) { return null; }
    }

    /// <summary>Writes one JSON object per line; lines from concurrent ops never interleave.</summary>
    private sealed class LineWriter(Stream output)
    {
        private readonly Lock _gate = new();

        public void Error(long id, ErrorCode code, string message) => TryWrite(new JsonObject
        {
            ["id"] = id,
            ["ok"] = false,
            ["error"] = new JsonObject { ["code"] = ToolError.CodeName(code), ["message"] = message },
        });

        /// <summary>Writes <paramref name="message"/>; false when the server has closed the pipe.</summary>
        public bool TryWrite(JsonObject message)
        {
            var bytes = Encoding.UTF8.GetBytes(message.ToJsonString() + "\n");
            lock (_gate)
            {
                try
                {
                    output.Write(bytes);
                    output.Flush();
                    return true;
                }
                catch (IOException) { return false; }
            }
        }
    }
}
