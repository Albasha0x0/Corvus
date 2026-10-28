using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Protocol;
using Corvus.Core;

namespace Corvus.Mcp;

/// <summary>
/// Opt-in audit log (--audit / CORVUS_AUDIT): one JSON line per tools/call with
/// time, account, client, version, tool, arguments (secrets masked), input and
/// result SHA-256; each line is flushed as it is written.
/// </summary>
// A failed write is reported once and never fails a call.
public sealed class CallAudit
{
    private static readonly Dictionary<string, CallAudit> Open = new(StringComparer.OrdinalIgnoreCase);
    private static readonly string User = OperatingSystem.IsWindows() ? $@"{Environment.UserDomainName}\{Environment.UserName}" : Environment.UserName;
    private readonly object _gate = new();
    private bool _failed;

    public string Path { get; }

    private CallAudit(string path) => Path = path;

    /// <summary>The audit log of a server's options, or null when it has none; one writer per file.</summary>
    public static CallAudit? For(ServerOptions? options)
    {
        if (options?.AuditPath is not { } path) return null;
        lock (Open)
        {
            if (!Open.TryGetValue(path, out var audit)) Open[path] = audit = new CallAudit(path);
            return audit;
        }
    }

    /// <summary>SHA-256 of the result's text blocks as sent; null without a result.</summary>
    public static string? TextSha256(CallToolResult? result) => result == null ? null
        : Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Concat(result.Content.OfType<TextContentBlock>().Select(b => b.Text)))));

    /// <param name="inputSha256">SHA-256 of the one file the call names; null when it names none or several.</param>
    public void Record(string? tool, IDictionary<string, JsonElement>? arguments, string? client, string outcome, string? inputSha256, CallToolResult? result)
    {
        var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer))
        {
            w.WriteStartObject();
            w.WriteString("time", DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture));
            w.WriteString("user", User);
            w.WriteString("client", client);
            w.WriteString("version", Setup.Installation.Version);
            w.WriteString("tool", tool);
            w.WritePropertyName("arguments");
            w.WriteStartObject();
            foreach (var (name, value) in arguments ?? new Dictionary<string, JsonElement>())
            {
                w.WritePropertyName(name);
                Redaction.Write(w, value, name);
            }
            w.WriteEndObject();
            w.WriteString("outcome", outcome);
            w.WriteString("inputSha256", inputSha256);
            w.WriteString("resultSha256", TextSha256(result));
            w.WriteEndObject();
        }
        buffer.WriteByte((byte)'\n');
        lock (_gate)
        {
            if (_failed) return;
            try
            {
                using var file = Native.Providers.PrivateFile.OpenAppend(Path);
                buffer.Position = 0;
                buffer.CopyTo(file);
                file.Flush(flushToDisk: true);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                _failed = true;
                Console.Error.WriteLine($"The audit log stopped: {e.Message}");
            }
        }
    }
}
