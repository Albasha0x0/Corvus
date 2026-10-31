using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using Corvus.Mcp;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace Corvus.Setup;

internal static partial class ToolCli
{
    /// <summary>The environment variable that routes every call to a named session.</summary>
    public const string SessionVariable = "CORVUS_SESSION";

    /// <summary>
    /// The pipe name of a session. Throws UsageException unless the name is
    /// 1 to 64 letters, digits, '.', '_' or '-'; never returns null.
    /// </summary>
    internal static string SessionPipe(string name) =>
        SessionName().IsMatch(name) ? "corvus-session-" + name
        : throw new UsageException("A session name is 1 to 64 letters, digits, '.', '_' or '-'.");

    [GeneratedRegex("^[A-Za-z0-9._-]{1,64}$")]
    private static partial Regex SessionName();

    /// <summary>
    /// The session a call is routed to: --session, else CORVUS_SESSION.
    /// Null runs the call in its own process.
    /// </summary>
    internal static string? SessionOf(CliArgs a, Func<string, string?>? environment = null) =>
        a.Session ?? ((environment ?? Environment.GetEnvironmentVariable)(SessionVariable) is { Length: > 0 } v ? v : null);

    private static async Task<int> ServeAsync(CliArgs a, CliIo io, CancellationToken cancellationToken)
    {
        if (a.Positionals.Count > 0) throw new UsageException($"Unexpected '{a.Positionals[0]}': serve takes options only.");
        var name = a.Session ?? throw new UsageException("serve needs --session NAME.");
        var pipe = SessionPipe(name);
        // Hold the name before the slow load, so a second serve fails at once.
        NamedPipeServerStream first;
        try { first = OpenInstance(pipe, firstInstance: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new UsageException($"Session {name} is already running.");
        }
        await using var _ = first;
        await using var session = await ToolSession.StartAsync(a.Server(), cancellationToken);
        io.Error.WriteLine($"Session {name} is ready. Route calls to it with --session {name} or {SessionVariable}={name}.");
        await ServeSessionAsync(session, pipe, first, cancellationToken);
        return Exit.Ok;
    }

    private static NamedPipeServerStream OpenInstance(string pipe, bool firstInstance) =>
        // CurrentUserOnly keeps other accounts from calling into the images.
        new(pipe, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly | (firstInstance ? PipeOptions.FirstPipeInstance : PipeOptions.None));

    /// <summary>Runs one routed call and reports its progress; the result is the reply.</summary>
    internal delegate Task<CallToolResult> RoutedCall(string tool, Dictionary<string, object?> arguments, IProgress<ProgressNotificationValue> progress, CancellationToken cancellationToken);

    /// <summary>
    /// Tools that answer at once and change nothing loaded, so they do not
    /// wait for the turn of a long call: the instant read-only tools of the
    /// contract, plus server_status and read_result.
    /// </summary>
    internal static readonly IReadOnlySet<string> TurnFree = new HashSet<string>(
        ToolContract.Table.Where(t => t.Value.Latency == LatencyClass.Instant && ToolEffects.Of(t.Key).ReadOnly).Select(t => t.Key)
            // The contract rates server_status interactive (it probes once) and read_result as writing
            // (outputPath); neither touches the workspace.
            .Concat(["server_status", "read_result"]),
        StringComparer.Ordinal);

    /// <summary>
    /// Answers requests on the pipe until cancelled. In-flight calls are
    /// cancelled and awaited before it returns.
    /// </summary>
    internal static Task ServeSessionAsync(ToolSession session, string pipe, NamedPipeServerStream next, CancellationToken cancellationToken) =>
        ServeSessionAsync(async (tool, arguments, progress, ct) => await session.Client.CallToolAsync(tool, arguments, progress, cancellationToken: ct), pipe, next, cancellationToken);

    /// <summary>Serves with a caller-supplied call runner.</summary>
    internal static async Task ServeSessionAsync(RoutedCall run, string pipe, NamedPipeServerStream next, CancellationToken cancellationToken)
    {
        var turn = new SemaphoreSlim(1);
        var connections = new List<Task>();
        try
        {
            while (true)
            {
                try { await next.WaitForConnectionAsync(cancellationToken); }
                catch { await next.DisposeAsync(); throw; }
                var connected = next;
                next = OpenInstance(pipe, firstInstance: false);
                connections.RemoveAll(t => t.IsCompleted);
                connections.Add(AnswerAsync(run, connected, turn, cancellationToken));
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        finally
        {
            await next.DisposeAsync();
            foreach (var t in connections)
                try { await t; } catch { }
        }
    }

    private static async Task AnswerAsync(RoutedCall run, NamedPipeServerStream pipe, SemaphoreSlim turn, CancellationToken cancellationToken)
    {
        await using var _ = pipe;
        try
        {
            var utf8 = new UTF8Encoding(false);
            using var reader = new StreamReader(pipe, utf8, false, 4096, leaveOpen: true);
            var line = await reader.ReadLineAsync(cancellationToken);
            if (line == null) return;
            // The client sends one line, so a read that ends means it left.
            using var call = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            using var watch = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var watcher = Task.Run(async () =>
            {
                try { if (await pipe.ReadAsync(new byte[1], watch.Token) == 0) await call.CancelAsync(); }
                catch (IOException) { await call.CancelAsync(); }
                catch (OperationCanceledException) { }
            }, CancellationToken.None);
            // One writer drains the lines in order, so progress precedes the reply.
            var lines = Channel.CreateUnbounded<string>(new UnboundedChannelOptions { SingleReader = true });
            var pump = Task.Run(async () =>
            {
                await foreach (var text in lines.Reader.ReadAllAsync(cancellationToken))
                    await WriteLine(text);
            }, CancellationToken.None);
            async Task WriteLine(string text)
            {
                await pipe.WriteAsync(utf8.GetBytes(text + "\n"), cancellationToken);
                await pipe.FlushAsync(cancellationToken);
            }
            string reply;
            try
            {
                if (JsonNode.Parse(line) is not JsonObject request) throw new JsonException("The request is not a JSON object.");
                if (request["tool"] is not JsonValue toolValue || !toolValue.TryGetValue<string>(out var tool))
                    throw new JsonException("The request needs a string 'tool'.");
                var arguments = new Dictionary<string, object?>(StringComparer.Ordinal);
                if (request["args"] is JsonObject args)
                    foreach (var (key, value) in args) arguments[key] = value is null ? null : JsonSerializer.SerializeToElement(value);
                var progress = new QueuedProgress(lines.Writer);
                // Turn-free tools must not change loaded state.
                var free = TurnFree.Contains(tool);
                if (!free) await turn.WaitAsync(call.Token);
                try
                {
                    var result = await run(tool, arguments, progress, call.Token);
                    reply = JsonSerializer.Serialize(result, McpJsonUtilities.DefaultOptions);
                }
                finally { if (!free) turn.Release(); }
            }
            catch (OperationCanceledException) when (call.IsCancellationRequested) { return; }
            catch (Exception ex)
            {
                reply = new JsonObject { ["protocolError"] = ex.Message }.ToJsonString();
            }
            finally
            {
                await watch.CancelAsync();
                await watcher;
                lines.Writer.TryComplete();
                await pump;
            }
            await WriteLine(reply);
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException) { }
    }

    /// <summary>Queues each report as a pipe line in call order, without posting to the thread pool.</summary>
    private sealed class QueuedProgress(ChannelWriter<string> lines) : IProgress<ProgressNotificationValue>
    {
        public void Report(ProgressNotificationValue v) =>
            lines.TryWrite(new JsonObject
            {
                ["progress"] = new JsonObject { ["progress"] = v.Progress, ["total"] = v.Total, ["message"] = v.Message },
            }.ToJsonString());
    }

    /// <summary>
    /// Sends one call to a running session and prints its progress on stderr.
    /// Returns null after reporting a protocol error (the caller exits 2); an
    /// unreachable session throws.
    /// </summary>
    internal static async Task<CallToolResult?> InvokeRemote(string name, string tool, Dictionary<string, object?> arguments, CliIo io, CancellationToken cancellationToken)
    {
        await using var pipe = new NamedPipeClientStream(".", SessionPipe(name), PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        try
        {
            using var connect = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connect.CancelAfter(TimeSpan.FromSeconds(3));
            await pipe.ConnectAsync(connect.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new SessionUnreachableException($"No session named {name} is running. Start it: {Program} serve --session {name}");
        }
        var utf8 = new UTF8Encoding(false);
        var request = new JsonObject { ["tool"] = tool, ["args"] = JsonSerializer.SerializeToNode(arguments) }.ToJsonString();
        await pipe.WriteAsync(utf8.GetBytes(request + "\n"), cancellationToken);
        await pipe.FlushAsync(cancellationToken);
        using var reader = new StreamReader(pipe, utf8, false, 4096, leaveOpen: true);
        IProgress<ProgressNotificationValue> progress = io.ErrorTty ? new ProgressLine(io.Error) : io.Log.For(tool);
        string line;
        JsonObject? reply;
        try
        {
            while (true)
            {
                line = await reader.ReadLineAsync(cancellationToken)
                    ?? throw new SessionUnreachableException($"Session {name} closed the connection without a reply.");
                reply = JsonNode.Parse(line) as JsonObject;
                if (reply?["progress"] is not JsonObject p) break;
                progress.Report(new ProgressNotificationValue
                {
                    Progress = p["progress"]?.GetValue<float>() ?? 0,
                    Total = p["total"]?.GetValue<float>(),
                    Message = p["message"]?.GetValue<string>(),
                });
            }
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException)
        {
            io.Error.WriteLine($"{tool}: the session sent a malformed line.");
            return null;
        }
        finally
        {
            if (progress is ProgressLine pl) pl.Clear();
            else io.Log.Flush();
        }
        if (reply == null)
        {
            io.Error.WriteLine($"{tool}: the session sent a reply that is not an object.");
            return null;
        }
        if (reply["protocolError"] is { } message)
        {
            io.Error.WriteLine($"{tool}: {message.GetValue<string>()}");
            return null;
        }
        return JsonSerializer.Deserialize<CallToolResult>(line, McpJsonUtilities.DefaultOptions);
    }

    /// <summary>The session is missing or closed the connection without a reply: exit code 3.</summary>
    internal sealed class SessionUnreachableException(string message) : Exception(message);
}
