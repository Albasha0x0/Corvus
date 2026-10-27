using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;

namespace Corvus.Native.Providers;

/// <summary>Worker framing: one UTF-8 JSON object per line (request {id, op, args, timeout?}, response {id, ok, result|error}, event {event}); other lines are noise, kept with stderr.</summary>
/// <remarks>A worker answers in any order. <see cref="CancelOp"/> with <c>{"id":n}</c> ends request n early, with an error
/// or a partial result. <c>timeout</c> is in seconds: the worker stops a little before it so a partial result arrives in
/// time.</remarks>
public static class WorkerProtocol
{
    public const string CancelOp = "cancel";
    /// <summary>Starts a worker's stderr line about one request: the id, op and what happened to it.</summary>
    public const string RequestLogPrefix = "corvus request ";

    public static string EncodeRequest(long id, string op, JsonObject? args, TimeSpan? timeout = null)
    {
        // A copy, so the caller's arguments stay unattached and a retry can send them again.
        var o = new JsonObject { ["id"] = id, ["op"] = op, ["args"] = args?.DeepClone() ?? new JsonObject() };
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
