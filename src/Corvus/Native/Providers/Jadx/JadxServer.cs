using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Corvus.Native.Providers.Jadx;

/// <summary>A tool result of the JADX server: its text, and whether the server marked it an error.</summary>
public sealed record JadxResult(string Text, bool IsError);

/// <summary>The JADX headless server as an MCP stdio child, one package per process; a timed-out call keeps it, only its exit ends the session. It gets a minimal environment and a private temp directory.</summary>
public sealed class JadxServer : IDisposable
{
    private readonly ChildProcess _process;
    private readonly ConcurrentDictionary<long, TaskCompletionSource<JsonNode>> _pending = new();
    private readonly StringBuilder _stderr = new();
    private readonly string _temp;
    private readonly object _write = new();
    private long _nextId;
    private int _disposed;

    public string Package { get; }
    public Task Loaded { get; private set; } = Task.CompletedTask;

    /// <summary>The process exited: every pending and later call fails.</summary>
    public bool HasExited => _process.HasExited;

    private JadxServer(ChildProcess process, string package, string temp)
    {
        _process = process;
        Package = package;
        _temp = temp;
        _ = Task.Run(ReadLoop);
        _ = Task.Run(() =>
        {
            try
            {
                using var r = new StreamReader(_process.StandardError, new UTF8Encoding(false));
                string? line;
                while ((line = r.ReadLine()) != null)
                    lock (_stderr)
                    {
                        _stderr.AppendLine(line);
                        if (_stderr.Length > 16_384) _stderr.Remove(0, _stderr.Length - 8_192);
                    }
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
        });
    }

    /// <summary>The last lines the server wrote to stderr.</summary>
    public string StderrTail
    {
        get { lock (_stderr) return string.Join('\n', _stderr.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries).TakeLast(8)); }
    }

    /// <summary>Starts the server and begins loading <paramref name="package"/>; <see cref="Loaded"/> completes when it is indexed.</summary>
    public static JadxServer Start(string java, string jar, string package, TimeSpan loadTimeout, IReadOnlyDictionary<string, string?>? environment = null)
    {
        var temp = PrivateFolder.Create(Path.Combine(Path.GetTempPath(), "corvus-jadx", $"{Environment.ProcessId}-{Guid.NewGuid():N}"));
        var env = new Dictionary<string, string?>(environment ?? new Dictionary<string, string?>()) { ["TMP"] = temp, ["TEMP"] = temp, ["TMPDIR"] = temp, ["JADX_TMP_DIR"] = temp };
        var threads = Math.Min(4, Environment.ProcessorCount).ToString(System.Globalization.CultureInfo.InvariantCulture);
        var args = ExternalTools.Arguments(ExternalTools.Java, "jar", ("jar", jar))
            .Concat(ExternalTools.Arguments(ExternalTools.JavaDecompiler, "server", ("threads", threads), ("timeoutMs", "90000"), ("maxBytes", "2000000"))).ToList();
        args.Insert(0, "-Djava.io.tmpdir=" + temp);
        var process = ChildProcess.Start(new ChildProcessStart(java, args) { Environment = ExternalTools.MinimalEnvironment(env), WorkingDirectory = temp });
        var server = new JadxServer(process, package, temp);
        server.Loaded = server.Initialize(loadTimeout);
        return server;
    }

    private async Task Initialize(TimeSpan loadTimeout)
    {
        await Request("initialize", new JsonObject
        {
            ["protocolVersion"] = "2025-06-18",
            ["capabilities"] = new JsonObject(),
            ["clientInfo"] = new JsonObject { ["name"] = "corvus", ["version"] = typeof(JadxServer).Assembly.GetName().Version?.ToString(3) ?? "1" },
        }, TimeSpan.FromMinutes(2), CancellationToken.None).ConfigureAwait(false);
        Send(new JsonObject { ["jsonrpc"] = "2.0", ["method"] = "notifications/initialized" });
        var load = await Call("load_apk", new JsonObject { ["path"] = Package }, loadTimeout, CancellationToken.None).ConfigureAwait(false);
        if (load.IsError) throw new InvalidOperationException("the JADX server could not load the package: " + load.Text);
    }

    /// <summary>Calls one tool of the server.</summary>
    public async Task<JadxResult> Call(string tool, JsonObject arguments, TimeSpan timeout, CancellationToken ct)
    {
        var result = await Request("tools/call", new JsonObject { ["name"] = tool, ["arguments"] = arguments }, timeout, ct).ConfigureAwait(false);
        var text = string.Concat((result["content"] as JsonArray ?? []).Select(c => (string?)c?["text"]));
        return new JadxResult(text, result["isError"]?.GetValue<bool>() == true);
    }

    private async Task<JsonNode> Request(string method, JsonObject parameters, TimeSpan timeout, CancellationToken ct)
    {
        var id = Interlocked.Increment(ref _nextId);
        var tcs = new TaskCompletionSource<JsonNode>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = tcs;
        try
        {
            Send(new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["method"] = method, ["params"] = parameters });
            var done = await Task.WhenAny(tcs.Task, Task.Delay(timeout, ct), _process.Exited).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            if (done == tcs.Task) return await tcs.Task.ConfigureAwait(false);
            if (done == _process.Exited && !tcs.Task.IsCompleted) throw new JadxExitedException(_process.ExitCode, StderrTail);
            if (tcs.Task.IsCompleted) return await tcs.Task.ConfigureAwait(false);
            throw new TimeoutException($"the JADX server did not answer {method} within {timeout.TotalSeconds:0} s");
        }
        finally
        {
            _pending.TryRemove(id, out _);
        }
    }

    private void Send(JsonObject message)
    {
        var bytes = Encoding.UTF8.GetBytes(message.ToJsonString() + "\n");
        lock (_write)
        {
            try
            {
                _process.StandardInput.Write(bytes);
                _process.StandardInput.Flush();
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                throw new JadxExitedException(_process.ExitCode, StderrTail);
            }
        }
    }

    private void ReadLoop()
    {
        try
        {
            using var r = new StreamReader(_process.StandardOutput, new UTF8Encoding(false));
            string? line;
            while ((line = r.ReadLine()) != null)
            {
                JsonNode? message;
                try { message = JsonNode.Parse(line); }
                // Skip non-protocol lines.
                catch (JsonException) { continue; }
                if (message?["id"] is not JsonValue idValue || !idValue.TryGetValue<long>(out var id) || !_pending.TryGetValue(id, out var tcs)) continue;
                if (message["error"] is { } error) tcs.TrySetException(new InvalidOperationException((string?)error["message"] ?? error.ToJsonString()));
                else tcs.TrySetResult(message["result"] ?? new JsonObject());
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _process.Dispose();
        try
        {
            Directory.Delete(_temp, true);
            // The shared parent, once no other server uses it.
            Directory.Delete(Path.GetDirectoryName(_temp)!);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
}

/// <summary>The JADX server process ended; the session is gone.</summary>
public sealed class JadxExitedException(int? exitCode, string stderr)
    : Exception($"the JADX server exited (code {exitCode?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "unknown"})" + (stderr.Length > 0 ? ": " + stderr : ""));
