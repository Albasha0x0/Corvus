using System.Buffers.Binary;

namespace Corvus.Core.Pcap;

/// <summary>
/// HTTP/2 over one connection's in-order streams: frames read from each side (the client's preface first), header blocks
/// decoded with each side's HPACK table, DATA gathered per stream; a response is handed on when the server ends its
/// stream. A gap stops that side (its HPACK table can no longer be followed).
/// </summary>
internal sealed class Http2Stream(string scheme, string server, Action<CapturedResponse> emit, long maxBody) : ITcpConsumer
{
    private static readonly byte[] Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();
    private const int MaxFrame = 1 << 24;
    private const int MaxStreams = 10_000;

    private sealed class Side(bool client)
    {
        public readonly bool Client = client;
        public readonly Hpack Hpack = new();
        public readonly MemoryStream Buffer = new();
        public bool AwaitPreface = client, Broken;
        public List<byte>? Block;
        public uint BlockStream;
        public byte BlockFlags;
    }

    private sealed class Exchange : HttpExchange
    {
        public MemoryStream? Body;
        public bool Truncated, Done;
    }

    private readonly Side _client = new(true), _server = new(false);
    private readonly Dictionary<uint, Exchange> _streams = [];

    public int Responses { get; private set; }

    public static bool LooksLikePreface(ReadOnlySpan<byte> b) => b.Length >= 16 && b[..Math.Min(b.Length, Preface.Length)].SequenceEqual(Preface.AsSpan(0, Math.Min(b.Length, Preface.Length)));

    public void Data(bool fromClient, ReadOnlySpan<byte> data)
    {
        var side = fromClient ? _client : _server;
        if (side.Broken) return;
        side.Buffer.Write(data);
        var all = side.Buffer.GetBuffer().AsSpan(0, (int)side.Buffer.Length);
        int at = 0;
        if (side.AwaitPreface)
        {
            if (all.Length < Preface.Length) return;
            if (!all[..Preface.Length].SequenceEqual(Preface)) { side.Broken = true; return; }
            at = Preface.Length;
            side.AwaitPreface = false;
        }
        while (all.Length - at >= 9)
        {
            var b = all[at..];
            int length = b[0] << 16 | b[1] << 8 | b[2];
            if (length > MaxFrame) { side.Broken = true; return; }
            if (b.Length < 9 + length) break;
            if (!Frame(side, b[3], b[4], BinaryPrimitives.ReadUInt32BigEndian(b[5..]) & 0x7FFFFFFF, b.Slice(9, length))) { side.Broken = true; return; }
            at += 9 + length;
        }
        var rest = all[at..].ToArray();
        side.Buffer.SetLength(0);
        side.Buffer.Write(rest);
    }

    private bool Frame(Side side, byte type, byte flags, uint stream, ReadOnlySpan<byte> body)
    {
        switch (type)
        {
            case 0: // DATA
            {
                if (!Unpad(flags, ref body)) return false;
                if (!side.Client && _streams.TryGetValue(stream, out var x) && x.Body != null)
                {
                    if (x.Body.Length + body.Length > maxBody) x.Truncated = true;
                    else x.Body.Write(body);
                }
                if ((flags & 1) != 0 && !side.Client) Finish(stream);
                return true;
            }
            case 1: // HEADERS
            {
                if (!Unpad(flags, ref body)) return false;
                if ((flags & 0x20) != 0) { if (body.Length < 5) return false; body = body[5..]; }
                side.Block = [.. body];
                side.BlockStream = stream;
                side.BlockFlags = flags;
                return (flags & 4) == 0 || Headers(side);
            }
            case 9: // CONTINUATION
                if (side.Block == null || stream != side.BlockStream) return false;
                side.Block.AddRange(body);
                return (flags & 4) == 0 || Headers(side);
            case 5: // PUSH_PROMISE: its header block still feeds the table
            {
                if (!Unpad(flags, ref body) || body.Length < 4) return false;
                var block = body[4..].ToArray();
                return side.Hpack.Decode(block, out int consumed) != null && consumed == block.Length;
            }
            default:
                return true;
        }
    }

    private static bool Unpad(byte flags, ref ReadOnlySpan<byte> body)
    {
        if ((flags & 8) == 0) return true;
        if (body.Length < 1 || body[0] >= body.Length) return false;
        body = body[1..^body[0]];
        return true;
    }

    /// <summary>A complete header block: request pseudo-headers from the client, status and content headers from the server.</summary>
    private bool Headers(Side side)
    {
        var block = side.Block!.ToArray();
        side.Block = null;
        var headers = side.Hpack.Decode(block, out int consumed);
        if (headers == null || consumed != block.Length) return false;
        uint stream = side.BlockStream;
        if (!_streams.TryGetValue(stream, out var x))
        {
            if (_streams.Count >= MaxStreams) return true;
            _streams[stream] = x = new Exchange();
        }
        x.Take(headers, side.Client);
        // an interim (1xx) response is followed by the final one's headers
        if (!side.Client && x.Status >= 200) x.Body ??= new MemoryStream();
        if ((side.BlockFlags & 1) != 0 && !side.Client) Finish(stream);
        return true;
    }

    private void Finish(uint stream, bool cut = false)
    {
        if (!_streams.Remove(stream, out var x) || x.Done) return;
        x.Done = true;
        Responses++;
        var url = $"{(x.Scheme.Length > 0 ? x.Scheme : scheme)}://{(x.Authority.Length > 0 ? x.Authority : server)}{x.Path}";
        emit(new CapturedResponse(x.Method, url, x.Status, x.Mime, x.Encoding, x.Truncated ? null : x.Body?.ToArray(),
            x.Truncated ? $"body over {maxBody:N0} bytes, not kept" : cut ? "the connection ended before the stream did" : null));
    }

    public void Gap(bool fromClient, long bytes) => (fromClient ? _client : _server).Broken = true;

    public void End()
    {
        foreach (var stream in _streams.Where(s => s.Value.Body != null).Select(s => s.Key).ToList()) Finish(stream, cut: true);
    }
}
