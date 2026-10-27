using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;

namespace Corvus.Native.Providers.Live.Inspector;

/// <summary>A Chrome DevTools Protocol connection over one WebSocket; a message over <see cref="MaxMessage"/> ends it.</summary>
internal sealed class CdpConnection : IAsyncDisposable
{
    private const int MaxMessage = 64 << 20;
    private readonly ClientWebSocket _socket = new();
    private readonly ConcurrentDictionary<long, TaskCompletionSource<JsonElement>> _pending = new();
    private readonly SemaphoreSlim _send = new(1, 1);
    private readonly TaskCompletionSource<string> _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private long _next;

    /// <summary>Raised for each event (method, params) on the receive thread.</summary>
    public event Action<string, JsonElement>? Event;

    /// <summary>Completes with the reason once the connection ends.</summary>
    public Task<string> Closed => _closed.Task;

    public static async Task<CdpConnection> ConnectAsync(Uri webSocket, CancellationToken ct)
    {
        var c = new CdpConnection();
        c._socket.Options.KeepAliveInterval = TimeSpan.FromSeconds(15);
        try { await c._socket.ConnectAsync(webSocket, ct).ConfigureAwait(false); }
        catch (WebSocketException ex)
        {
            c._socket.Dispose();
            throw new ToolError(ErrorCode.NotFound, $"The inspector at {webSocket} refused the connection: {ex.Message}",
                "a target takes one client at a time: close other debuggers attached to it");
        }
        _ = Task.Run(c.ReceiveAsync, CancellationToken.None);
        return c;
    }

    /// <summary>Sends <paramref name="method"/> and returns its result; a protocol error is a <see cref="ToolError"/> naming the method.</summary>
    public async Task<JsonElement> SendAsync(string method, JsonObject? parameters, TimeSpan timeout, CancellationToken ct)
    {
        var id = Interlocked.Increment(ref _next);
        var answer = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = answer;
        var bytes = Encoding.UTF8.GetBytes(new JsonObject { ["id"] = id, ["method"] = method, ["params"] = parameters ?? [] }.ToJsonString());
        try
        {
            await _send.WaitAsync(ct).ConfigureAwait(false);
            try { await _socket.SendAsync(bytes, WebSocketMessageType.Text, true, ct).ConfigureAwait(false); }
            finally { _send.Release(); }
            var done = await Task.WhenAny(answer.Task, _closed.Task, Task.Delay(timeout, ct)).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            if (done == answer.Task) return await answer.Task.ConfigureAwait(false);
            if (done == _closed.Task) throw new ToolError(ErrorCode.Failed, $"The inspector connection ended during {method}: {_closed.Task.Result}.");
            throw new ToolError(ErrorCode.Timeout, $"The inspector did not answer {method} within {timeout.TotalSeconds:0} s.");
        }
        catch (WebSocketException ex) { throw new ToolError(ErrorCode.Failed, $"The inspector connection failed during {method}: {ex.Message}"); }
        finally { _pending.TryRemove(id, out _); }
    }

    private async Task ReceiveAsync()
    {
        var buffer = new byte[64 * 1024];
        using var message = new MemoryStream();
        string reason = "closed by the inspector";
        try
        {
            while (_socket.State == WebSocketState.Open)
            {
                var r = await _socket.ReceiveAsync(buffer, CancellationToken.None).ConfigureAwait(false);
                if (r.MessageType == WebSocketMessageType.Close) break;
                message.Write(buffer, 0, r.Count);
                if (message.Length > MaxMessage) { reason = $"a message over {MaxMessage >> 20} MiB"; break; }
                if (!r.EndOfMessage) continue;
                Dispatch(message.GetBuffer().AsSpan(0, (int)message.Length));
                message.SetLength(0);
            }
        }
        catch (WebSocketException ex) { reason = ex.Message; }
        catch (ObjectDisposedException) { reason = "closed"; }
        foreach (var p in _pending.Values) p.TrySetException(new ToolError(ErrorCode.Failed, $"The inspector connection ended: {reason}."));
        _closed.TrySetResult(reason);
    }

    private void Dispatch(ReadOnlySpan<byte> bytes)
    {
        JsonElement root;
        try { root = JsonDocument.Parse(bytes.ToArray()).RootElement; }
        catch (JsonException) { return; }
        if (root.ValueKind != JsonValueKind.Object) return;
        if (root.TryGetProperty("id", out var id) && id.TryGetInt64(out var n))
        {
            if (!_pending.TryGetValue(n, out var answer)) return;
            if (root.TryGetProperty("error", out var error))
                answer.TrySetException(new ToolError(ErrorCode.Failed, "The inspector refused the command: " + (error.TryGetProperty("message", out var m) ? m.GetString() : error.GetRawText())));
            else answer.TrySetResult(root.TryGetProperty("result", out var result) ? result : default);
        }
        else if (root.TryGetProperty("method", out var method) && method.GetString() is { } name)
            Event?.Invoke(name, root.TryGetProperty("params", out var p) ? p : default);
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (_socket.State == WebSocketState.Open)
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await _socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "session closed", cts.Token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is WebSocketException or OperationCanceledException) { }
        _socket.Dispose();
        _closed.TrySetResult("closed");
    }
}
