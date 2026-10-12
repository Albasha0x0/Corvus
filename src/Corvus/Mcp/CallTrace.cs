using System.Text.Json;
using ModelContextProtocol.Protocol;
using Corvus.Core;

namespace Corvus.Mcp;

/// <summary>
/// Opt-in call trace (CORVUS_TRACE / --trace): one JSON line per tools/call with the time, run id, tool, argument names
/// (values, secrets masked by <see cref="Redaction"/>, only with --trace-args), milliseconds, error code, text characters and
/// estimated tokens per part, appended to a plain file of its own. A failed write is reported once and never fails a call.
/// </summary>
public sealed class CallTrace
{
    private static readonly Dictionary<string, CallTrace> Open = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private bool _failed;

    public string Path { get; }

    /// <summary>Argument values are recorded (masked), not only names.</summary>
    public bool Arguments { get; }

    private CallTrace(string path, bool arguments)
    {
        Path = path;
        Arguments = arguments;
    }

    /// <summary>The trace of a server's options, or null when it has none; one writer per file.</summary>
    public static CallTrace? For(ServerOptions? options)
    {
        if (options?.TracePath is not { } path) return null;
        lock (Open)
        {
            if (!Open.TryGetValue(path, out var trace) || trace.Arguments != options.TraceArguments)
                Open[path] = trace = new CallTrace(path, options.TraceArguments);
            return trace;
        }
    }

    public void Record(string? tool, IDictionary<string, JsonElement>? arguments, double milliseconds, string? error, CallToolResult? result,
        long textTokens = 0, long structuredTokens = 0)
    {
        var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer))
        {
            w.WriteStartObject();
            w.WriteString("ts", DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture));
            w.WriteString("run", CallLog.RunId);
            w.WriteString("tool", tool);
            if (Arguments)
            {
                w.WritePropertyName("args");
                w.WriteStartObject();
                foreach (var (name, value) in arguments ?? new Dictionary<string, JsonElement>())
                {
                    w.WritePropertyName(name);
                    Redaction.Write(w, value, name);
                }
                w.WriteEndObject();
            }
            else
            {
                w.WritePropertyName("argNames");
                w.WriteStartArray();
                foreach (var name in arguments?.Keys ?? []) w.WriteStringValue(name);
                w.WriteEndArray();
            }
            w.WriteNumber("ms", Math.Round(milliseconds, 1));
            if (error != null) w.WriteString("error", error);
            else w.WriteNull("error");
            w.WriteNumber("chars", result?.Content.OfType<TextContentBlock>().Sum(b => (long)b.Text.Length) ?? 0);
            w.WriteNumber("textTokens", textTokens);
            w.WriteNumber("structuredTokens", structuredTokens);
            w.WriteEndObject();
        }
        buffer.WriteByte((byte)'\n');
        lock (_gate)
        {
            if (_failed) return;
            try
            {
                using var file = new FileStream(Path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                buffer.Position = 0;
                buffer.CopyTo(file);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                _failed = true;
                Console.Error.WriteLine($"The call trace stopped: {e.Message}");
            }
        }
    }
}
