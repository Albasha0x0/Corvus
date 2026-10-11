using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native.Providers;

/// <summary>
/// Framing between a provider and its worker process: one JSON object per line, UTF-8, '\n' terminated.
/// Request <c>{"id":n,"op":"...","args":{...}}</c>; response <c>{"id":n,"ok":true,"result":...}</c> or
/// <c>{"id":n,"ok":false,"error":{"code":"...","message":"..."}}</c>; events <c>{"event":"...",...}</c> carry no id.
/// Lines that are not JSON objects are noise (an engine printing to stdout) and are kept with stderr.
/// A worker answers in any order and takes <see cref="CancelOp"/> with <c>{"id":n}</c>, after which request n ends
/// early (with an error, or a result marked partial). A request may carry <c>"timeout"</c> (seconds): the worker
/// stops it a little before then so that a partial result arrives in time.
/// </summary>
public static class WorkerProtocol
{
    public const string CancelOp = "cancel";

    public static string EncodeRequest(long id, string op, JsonObject? args, TimeSpan? timeout = null)
    {
        var o = new JsonObject { ["id"] = id, ["op"] = op, ["args"] = args ?? new JsonObject() };
        if (timeout is { } t && t > TimeSpan.Zero && t < TimeSpan.MaxValue) o["timeout"] = Math.Round(t.TotalSeconds, 3);
        // Default JsonSerializerOptions escape non-ASCII, so a request never contains a raw line break or invalid UTF-8.
        var line = o.ToJsonString();
        if (line.Contains('\n') || line.Contains('\r')) throw new InvalidOperationException("encoded request contains a line break");
        return line + "\n";
    }

    public static WorkerMessage Parse(string line)
    {
        line = line.TrimEnd('\r');
        if (line.Length == 0 || line[0] != '{') return new WorkerMessage.Noise(line);
        JsonElement root;
        try
        {
            using var doc = JsonDocument.Parse(line);
            root = doc.RootElement.Clone();
        }
        catch (JsonException)
        {
            return new WorkerMessage.Noise(line);
        }
        if (root.ValueKind != JsonValueKind.Object) return new WorkerMessage.Noise(line);
        if (root.TryGetProperty("event", out var ev) && ev.ValueKind == JsonValueKind.String)
            return new WorkerMessage.Event(ev.GetString()!, root);
        if (!root.TryGetProperty("ok", out var ok) || ok.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            return new WorkerMessage.Noise(line);
        long? id = root.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.Number && idEl.TryGetInt64(out var n) ? n : null;
        if (ok.GetBoolean())
            return new WorkerMessage.Response(id, root.TryGetProperty("result", out var r) ? r : default, null, null);
        string code = "failed", message = "worker reported an error without a message";
        if (root.TryGetProperty("error", out var err) && err.ValueKind == JsonValueKind.Object)
        {
            if (err.TryGetProperty("code", out var c) && c.ValueKind == JsonValueKind.String) code = c.GetString()!;
            if (err.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String) message = m.GetString()!;
        }
        return new WorkerMessage.Response(id, default, code, message);
    }

    /// <summary>Maps a worker error code (the snake_case names of <see cref="ErrorCode"/>) back to the enum.</summary>
    public static ErrorCode MapCode(string? code)
    {
        foreach (var value in Enum.GetValues<ErrorCode>())
            if (ToolError.CodeName(value) == code) return value;
        return ErrorCode.Failed;
    }
}

public abstract record WorkerMessage
{
    public sealed record Response(long? Id, JsonElement Result, string? ErrorCode, string? ErrorMessage) : WorkerMessage
    {
        public bool Ok => ErrorCode == null;
    }

    public sealed record Event(string Name, JsonElement Body) : WorkerMessage;

    public sealed record Noise(string Text) : WorkerMessage;
}

/// <summary>Keeps the last <c>capacity</c> characters of a text stream (stderr of a worker).</summary>
public sealed class TextTail(int capacity)
{
    private readonly StringBuilder _text = new();

    public void Append(string s)
    {
        lock (_text)
        {
            _text.Append(s);
            if (_text.Length > capacity) _text.Remove(0, _text.Length - capacity);
        }
    }

    public string Text
    {
        get { lock (_text) return _text.ToString(); }
    }

    /// <summary>The last <paramref name="lines"/> non-empty lines, trimmed.</summary>
    public string LastLines(int lines)
    {
        var all = Text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return string.Join("\n", all.Skip(Math.Max(0, all.Length - lines)));
    }
}
