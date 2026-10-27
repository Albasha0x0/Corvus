using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace Corvus.Core;

/// <summary>Fiddler session archives (.saz): request and status lines plus headers per session; bodies are not read.</summary>
public static partial class Saz
{
    private const int MaxSessions = 100_000, MaxHead = 64 * 1024;

    public const string Kind = "Fiddler session archive (.saz)";

    /// <summary>A zip whose entries include raw/&lt;n&gt;_c.txt.</summary>
    public static bool Looks(byte[] data) => Looks(new MemoryStream(data, writable: false));

    /// <summary>A zip whose entries include raw/&lt;n&gt;_c.txt, read from a seekable stream (its central directory only); the stream is left at its start.</summary>
    public static bool Looks(Stream s)
    {
        Span<byte> magic = stackalloc byte[4];
        s.Position = 0;
        bool zipped = s.ReadAtLeast(magic, 4, throwOnEndOfStream: false) == 4 && magic.SequenceEqual("PK\u0003\u0004"u8);
        s.Position = 0;
        if (!zipped) return false;
        try
        {
            using var zip = new ZipArchive(s, ZipArchiveMode.Read, leaveOpen: true);
            return zip.Entries.Any(e => Session().IsMatch(e.FullName));
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or NotSupportedException) { return false; }
        finally { s.Position = 0; }
    }

    /// <summary>One exchange per session in session order: method, URL (absolute; a CONNECT keeps its host:port), status and response headers; Body null.</summary>
    public static List<CapturedResponse> Read(byte[] data, CancellationToken ct = default) => Read(new MemoryStream(data, writable: false), ct);

    /// <summary>The sessions of a .saz read from a seekable stream: the central directory and each session's head, not the file.</summary>
    public static List<CapturedResponse> Read(Stream stream, CancellationToken ct = default)
    {
        var result = new List<CapturedResponse>();
        try
        {
            using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
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

    /// <summary>Each session's request in order, body text from the first <see cref="MaxHead"/> bytes, with response status and type.</summary>
    public static void ReadRequests(Stream stream, Action<CapturedRequest> request, CancellationToken ct = default)
    {
        try
        {
            using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
            var sessions = new SortedDictionary<long, (ZipArchiveEntry? Request, ZipArchiveEntry? Response)>();
            foreach (var e in zip.Entries)
            {
                if (Session().Match(e.FullName) is not { Success: true } m || !long.TryParse(m.Groups[1].Value, out long n)) continue;
                if (!sessions.ContainsKey(n) && sessions.Count >= MaxSessions) continue;
                var s = sessions.GetValueOrDefault(n);
                sessions[n] = m.Groups[2].Value is "c" or "C" ? (e, s.Response) : (s.Request, e);
            }
            int index = 0;
            foreach (var (_, (rq, rs)) in sessions)
            {
                ct.ThrowIfCancellationRequested();
                if (rq == null) continue;
                var (lines, body) = HeadAndBody(rq);
                var (method, url, _) = RequestLine(lines);
                var headers = lines.Skip(1).Select(l => l.Split(':', 2)).Where(p => p.Length == 2)
                    .Select(p => new KeyValuePair<string, string>(p[0].Trim(), p[1].Trim())).ToList();
                int status = 0;
                string? responseType = null;
                long responseSize = 0;
                if (rs != null)
                {
                    var head = HeadAndBody(rs).Lines;
                    var parts = head.Count > 0 ? head[0].Split(' ', 3) : [];
                    if (parts.Length >= 2 && parts[0].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase)) _ = int.TryParse(parts[1], out status);
                    responseType = Header(head, "Content-Type");
                    responseSize = long.TryParse(Header(head, "Content-Length"), out var length) ? length : 0;
                }
                var version = lines.Count > 0 && lines[0].Split(' ') is { Length: 3 } line ? line[2] : null;
                request(new CapturedRequest(index++, method, url, status)
                {
                    HttpVersion = version,
                    Headers = headers,
                    Cookies = CaptureRequests.CookieHeader(headers),
                    BodyType = Header(lines, "Content-Type"),
                    BodySize = long.TryParse(Header(lines, "Content-Length"), out var size) ? size : Encoding.UTF8.GetByteCount(body),
                    BodyText = body.Length > 0 ? body : null,
                    ResponseType = responseType,
                    ResponseSize = responseSize,
                });
            }
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or NotSupportedException) { }
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
    private static List<string> Head(ZipArchiveEntry entry) => HeadAndBody(entry).Lines;

    /// <summary>The head's lines and the body text (UTF-8) that follows it within the first <see cref="MaxHead"/> bytes.</summary>
    private static (List<string> Lines, string Body) HeadAndBody(ZipArchiveEntry entry)
    {
        using var s = entry.Open();
        var buffer = new byte[MaxHead];
        int n = s.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
        var span = buffer.AsSpan(0, n);
        int end = span.IndexOf("\r\n\r\n"u8), gap = 4;
        if (end < 0) (end, gap) = (span.IndexOf("\n\n"u8), 2);
        var head = Encoding.Latin1.GetString(end >= 0 ? span[..end] : span);
        var body = end >= 0 ? Encoding.UTF8.GetString(span[(end + gap)..]) : "";
        return ([.. head.Split('\n').Select(l => l.TrimEnd('\r'))], body);
    }

    [GeneratedRegex(@"^raw[/\\]0*(\d{1,9})_([cCsS])\.txt$", RegexOptions.CultureInvariant)]
    private static partial Regex Session();
}
