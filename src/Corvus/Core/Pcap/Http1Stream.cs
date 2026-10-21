using System.Globalization;
using System.Text;

namespace Corvus.Core.Pcap;

/// <summary>
/// HTTP/1.x over one connection's two in-order streams: requests and responses parsed as they arrive (heads up to 64 KiB,
/// bodies by Content-Length, chunked or until the connection ends), each response paired with the oldest open request and
/// handed on with its body (still content-encoded). After a gap the side resumes at the next start line.
/// </summary>
internal sealed class Http1Stream(string scheme, string server, Action<CapturedResponse> emit, long maxBody) : ITcpConsumer
{
    private const int MaxHead = 64 * 1024;

    private sealed record Request(string Method, string Url);

    private readonly Queue<Request> _requests = new();
    private readonly Side _client = new(true), _server = new(false);

    public int Requests { get; private set; }
    public int Responses { get; private set; }

    /// <summary>Whether a stream's first bytes are an HTTP/1.x request line.</summary>
    public static bool LooksLikeRequest(ReadOnlySpan<byte> b)
    {
        int space = b[..Math.Min(b.Length, 16)].IndexOf((byte)' ');
        if (space < 3) return false;
        foreach (var c in b[..space]) if (c is < (byte)'A' or > (byte)'Z') return false;
        return Methods.Contains(Encoding.ASCII.GetString(b[..space]));
    }

    private static readonly HashSet<string> Methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE", "PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "REPORT", "SEARCH"];

    private enum State { Head, Body, ChunkSize, ChunkData, ChunkEnd, Trailer, UntilClose, Lost }

    private sealed class Side(bool requests)
    {
        public readonly bool Requests = requests;
        public State State = State.Head;
        public readonly MemoryStream Buffer = new();
        public MemoryStream? Body;
        public long Remaining, Missing;
        public bool Truncated, Cut;
        /// <summary>The side resumed at a start line after bytes it could not read (a gap, a capture begun mid-stream).</summary>
        public bool Resumed;
        // the message being read
        public string Method = "", Target = "", Mime = "", Encoding = "";
        public int Status;
        public Dictionary<string, string> Headers = new(StringComparer.OrdinalIgnoreCase);
    }

    public void Data(bool fromClient, ReadOnlySpan<byte> data)
    {
        var side = fromClient ? _client : _server;
        while (data.Length > 0)
        {
            switch (side.State)
            {
                case State.Lost:
                    if (!(fromClient ? LooksLikeRequest(data) : data.StartsWith("HTTP/1."u8))) return;
                    side.State = State.Head;
                    side.Buffer.SetLength(0);
                    side.Resumed = true;
                    continue;
                case State.Head:
                    data = Head(side, data);
                    break;
                case State.Body:
                {
                    int take = (int)Math.Min(side.Remaining, data.Length);
                    Append(side, data[..take]);
                    side.Remaining -= take;
                    data = data[take..];
                    if (side.Remaining == 0) Complete(side);
                    break;
                }
                case State.UntilClose:
                    Append(side, data);
                    return;
                case State.ChunkSize or State.ChunkEnd or State.Trailer:
                {
                    int eol = data.IndexOf((byte)'\n');
                    if (eol < 0)
                    {
                        if (side.Buffer.Length + data.Length > MaxHead) { side.State = State.Lost; return; }
                        side.Buffer.Write(data);
                        return;
                    }
                    side.Buffer.Write(data[..eol]);
                    data = data[(eol + 1)..];
                    var line = Encoding.Latin1.GetString(side.Buffer.GetBuffer(), 0, (int)side.Buffer.Length).TrimEnd('\r');
                    side.Buffer.SetLength(0);
                    if (side.State == State.ChunkEnd) { side.State = State.ChunkSize; break; }
                    if (side.State == State.Trailer) { if (line.Length == 0) Complete(side); break; }
                    var hex = line.Split(';')[0].Trim();
                    if (!long.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out long size) || size < 0) { side.State = State.Lost; return; }
                    if (size == 0) side.State = State.Trailer;
                    else { side.Remaining = size; side.State = State.ChunkData; }
                    break;
                }
                case State.ChunkData:
                {
                    int take = (int)Math.Min(side.Remaining, data.Length);
                    Append(side, data[..take]);
                    side.Remaining -= take;
                    data = data[take..];
                    if (side.Remaining == 0) side.State = State.ChunkEnd;
                    break;
                }
            }
        }
    }

    /// <summary>Reads the head up to its blank line; returns what follows it.</summary>
    private ReadOnlySpan<byte> Head(Side side, ReadOnlySpan<byte> data)
    {
        // search from a little before the old end, so a CRLFCRLF split over two calls is found
        int before = (int)side.Buffer.Length;
        side.Buffer.Write(data);
        var all = side.Buffer.GetBuffer().AsSpan(0, (int)side.Buffer.Length);
        int from = Math.Max(0, before - 3);
        int end = all[from..].IndexOf("\r\n\r\n"u8), gap = 4;
        if (end < 0) { end = all[from..].IndexOf("\n\n"u8); gap = 2; }
        if (end < 0)
        {
            if (all.Length > MaxHead) side.State = State.Lost;
            return [];
        }
        end += from;
        var head = Encoding.Latin1.GetString(all[..end]);
        int used = end + gap - before;
        side.Buffer.SetLength(0);
        if (!Start(side, head)) { side.State = State.Lost; return []; }
        return data[used..];
    }

    /// <summary>The start line and headers of a message; sets how its body is read. False when it is no HTTP message.</summary>
    private bool Start(Side side, string head)
    {
        var lines = head.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        var parts = lines[0].Split(' ', 3);
        side.Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1))
        {
            int colon = line.IndexOf(':');
            if (colon > 0) side.Headers.TryAdd(line[..colon].Trim(), line[(colon + 1)..].Trim());
        }
        side.Mime = side.Headers.GetValueOrDefault("Content-Type") ?? "";
        side.Encoding = side.Headers.GetValueOrDefault("Content-Encoding") ?? "";
        side.Body = null;
        side.Truncated = side.Cut = false;
        side.Missing = 0;
        bool chunked = side.Headers.GetValueOrDefault("Transfer-Encoding")?.Contains("chunked", StringComparison.OrdinalIgnoreCase) == true;
        long? length = long.TryParse(side.Headers.GetValueOrDefault("Content-Length"), NumberStyles.None, CultureInfo.InvariantCulture, out var l) ? l : null;
        if (side.Requests)
        {
            if (parts.Length < 3 || !parts[2].StartsWith("HTTP/", StringComparison.Ordinal)) return false;
            (side.Method, side.Target) = (parts[0], parts[1]);
            Requests++;
            _requests.Enqueue(new Request(side.Method, Url(side.Target, side.Headers.GetValueOrDefault("Host"))));
            // a request body is read past, not kept
            if (chunked) side.State = State.ChunkSize;
            else if (length > 0) { side.Remaining = length.Value; side.State = State.Body; }
            else side.State = State.Head;
            side.Body = null;
            return true;
        }
        if (parts.Length < 2 || !parts[0].StartsWith("HTTP/1.", StringComparison.Ordinal) || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out side.Status))
            return false;
        if (side.Resumed)
        {
            // responses were lost unread: the newest request is the one answered (a client that does not pipeline waits for each answer)
            while (_requests.Count > 1) _requests.Dequeue();
            side.Resumed = false;
        }
        bool noBody = _requests.TryPeek(out var request) && request.Method == "HEAD";
        side.Body = new MemoryStream();
        if (side.Status is >= 100 and < 200)
        {
            side.State = State.Head; // an interim response: the final one follows for the same request
            side.Body = null;
            return true;
        }
        if (noBody || side.Status is 204 or 304) Complete(side);
        else if (chunked) side.State = State.ChunkSize;
        else if (length is { } n)
        {
            if (n == 0) Complete(side);
            else { side.Remaining = n; side.State = State.Body; }
        }
        else side.State = State.UntilClose;
        return true;
    }

    private string Url(string target, string? host)
    {
        if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || target.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return target;
        if (!target.StartsWith('/')) return target; // CONNECT host:port, OPTIONS *
        return $"{scheme}://{host ?? server}{target}";
    }

    private void Append(Side side, ReadOnlySpan<byte> data)
    {
        if (side.Body == null) return; // a request body
        if (side.Body.Length + data.Length > maxBody) { side.Truncated = true; return; }
        side.Body.Write(data);
    }

    /// <summary>A message is read: a response is paired with its request and handed on.</summary>
    private void Complete(Side side)
    {
        side.State = State.Head;
        if (side.Requests || side.Body == null) return;
        Responses++;
        var request = _requests.TryDequeue(out var r) ? r : new Request("?", $"{scheme}://{server}/");
        string? problem = side.Truncated ? $"body over {maxBody:N0} bytes, not kept" : side.Missing > 0 ? $"{side.Missing:N0} body bytes not captured"
            : side.Cut ? "the connection ended before the body did" : null;
        emit(new CapturedResponse(request.Method, request.Url, side.Status, side.Mime.Length > 0 ? side.Mime : null, side.Encoding.Length > 0 ? side.Encoding : null,
            side.Truncated ? null : side.Body.ToArray(), problem));
        side.Body = null;
    }

    public void Gap(bool fromClient, long bytes)
    {
        var side = fromClient ? _client : _server;
        if (side.State == State.Body)
        {
            // a fixed-length body keeps its place: the missing bytes are counted, not invented
            long skip = Math.Min(bytes, side.Remaining);
            side.Missing += skip;
            side.Remaining -= skip;
            if (side.Remaining == 0) Complete(side);
            if (bytes > skip) side.State = State.Lost;
            return;
        }
        if (side.State == State.UntilClose) { side.Missing += bytes; return; }
        if (!side.Requests && side.Body != null) { side.Missing += bytes; Complete(side); }
        side.State = State.Lost;
    }

    public void End()
    {
        // a body read until the connection closed is complete now; a cut one is handed on as far as it got
        if (_server.Body != null && _server.State is State.UntilClose or State.Body or State.ChunkData or State.ChunkSize or State.ChunkEnd or State.Trailer)
        {
            _server.Cut = _server.State != State.UntilClose;
            Complete(_server);
        }
    }
}
