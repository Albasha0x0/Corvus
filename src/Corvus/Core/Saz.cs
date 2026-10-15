using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace Corvus.Core;

/// <summary>
/// Fiddler session archives (.saz): a zip with raw/NN_c.txt (request), raw/NN_s.txt (response) and raw/NN_m.xml (session
/// metadata) per session. Read as request and status lines plus headers; bodies are not read.
/// </summary>
public static partial class Saz
{
    private const int MaxSessions = 100_000, MaxHead = 64 * 1024;

    /// <summary>A zip whose entries include raw/&lt;n&gt;_c.txt.</summary>
    public static bool Looks(byte[] data)
    {
        if (data.Length < 4 || !data.AsSpan(0, 4).SequenceEqual("PK\u0003\u0004"u8)) return false;
        try
        {
            using var zip = new ZipArchive(new MemoryStream(data, writable: false), ZipArchiveMode.Read);
            return zip.Entries.Any(e => Session().IsMatch(e.FullName));
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or NotSupportedException) { return false; }
    }

    /// <summary>One exchange per session in session order: method, URL (absolute; a CONNECT keeps its host:port), status and response headers; Body null.</summary>
    public static List<CapturedResponse> Read(byte[] data, CancellationToken ct = default)
    {
        var result = new List<CapturedResponse>();
        try
        {
            using var zip = new ZipArchive(new MemoryStream(data, writable: false), ZipArchiveMode.Read);
            var sessions = new SortedDictionary<long, (ZipArchiveEntry? Request, ZipArchiveEntry? Response)>();
            foreach (var e in zip.Entries)
            {
                if (Session().Match(e.FullName) is not { Success: true } m || !long.TryParse(m.Groups[1].Value, out long n)) continue;
                if (!sessions.ContainsKey(n) && sessions.Count >= MaxSessions) continue;
                var s = sessions.GetValueOrDefault(n);
                sessions[n] = m.Groups[2].Value is "c" or "C" ? (e, s.Response) : (s.Request, e);
            }
            foreach (var (_, (request, response)) in sessions)
            {
                ct.ThrowIfCancellationRequested();
                if (request == null) continue;
                var (method, url, problem) = RequestLine(Head(request));
                int status = 0;
                string? mime = null, encoding = null;
                if (response != null)
                {
                    var lines = Head(response);
                    var parts = lines.Count > 0 ? lines[0].Split(' ', 3) : [];
                    if (parts.Length >= 2 && parts[0].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase)) _ = int.TryParse(parts[1], out status);
                    mime = Header(lines, "Content-Type");
                    encoding = Header(lines, "Content-Encoding");
                }
                result.Add(new CapturedResponse(method, url, status, mime, encoding, null, problem));
            }
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or NotSupportedException) { }
        return result;
    }

    /// <summary>Method and absolute URL; an origin-form target ("/path") is joined to its Host header.</summary>
    private static (string Method, string Url, string? Problem) RequestLine(List<string> lines)
    {
        if (lines.Count == 0) return ("?", "", "empty request");
        var parts = lines[0].Split(' ');
        if (parts.Length < 2) return ("?", lines[0], "no request line");
        string method = parts[0], target = parts[1];
        if (method == "CONNECT" || !target.StartsWith('/')) return (method, target, null);
        string? host = Header(lines, "Host");
        if (host == null) return (method, target, "no Host header");
        string scheme = host.EndsWith(":443", StringComparison.Ordinal) ? "https" : "http";
        return (method, $"{scheme}://{(scheme == "https" ? host[..^4] : host)}{target}", null);
    }

    private static string? Header(List<string> lines, string name)
    {
        foreach (var line in lines.Skip(1))
        {
            int colon = line.IndexOf(':');
            if (colon > 0 && line.AsSpan(0, colon).Trim().Equals(name, StringComparison.OrdinalIgnoreCase)) return line[(colon + 1)..].Trim();
        }
        return null;
    }

    /// <summary>The start line and header lines: the text before the first empty line, at most <see cref="MaxHead"/> bytes read.</summary>
    private static List<string> Head(ZipArchiveEntry entry)
    {
        using var s = entry.Open();
        var buffer = new byte[MaxHead];
        int n = s.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
        var text = Encoding.Latin1.GetString(buffer, 0, n);
        int end = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (end < 0) end = text.IndexOf("\n\n", StringComparison.Ordinal);
        if (end >= 0) text = text[..end];
        return [.. text.Split('\n').Select(l => l.TrimEnd('\r'))];
    }

    [GeneratedRegex(@"^raw[/\\]0*(\d{1,9})_([cCsS])\.txt$", RegexOptions.CultureInvariant)]
    private static partial Regex Session();
}
