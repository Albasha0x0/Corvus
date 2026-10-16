using System.Buffers.Binary;

namespace Corvus.Core.Pcap;

/// <summary>One captured frame: its link type, time in microseconds since 1970, wire length and the captured bytes.</summary>
public readonly record struct PcapFrame(int LinkType, long Micros, int OriginalLength, ReadOnlyMemory<byte> Data);

/// <summary>
/// A streaming pcap / pcapng reader (both byte orders, micro and nanosecond pcap; pcapng sections, interfaces with their
/// link types and time resolutions, enhanced, simple and obsolete packet blocks). Frames share one reused buffer, so a
/// frame's data is valid until the next one is read. Malformed input ends the read with an issue, never an exception.
/// </summary>
public sealed class PcapReader(Stream stream)
{
    private const int MaxBlock = 16 << 20;
    private const int MaxInterfaces = 4096;
    private const int MaxIssues = 20;

    private byte[] _buf = new byte[64 * 1024];
    private bool _big;
    private readonly List<(int LinkType, byte Resolution)> _interfaces = [];

    /// <summary>"pcap" or "pcapng"; empty before reading or when the magic is unknown.</summary>
    public string Format { get; private set; } = "";
    public SortedSet<int> LinkTypes { get; } = [];
    public int Interfaces { get; private set; }
    public List<string> Issues { get; } = [];

    /// <summary>Receives the TLS key log text of each pcapng decryption secrets block, in file order.</summary>
    public SpanAction? Secrets { get; init; }

    public delegate void SpanAction(ReadOnlySpan<byte> data);

    public static bool Looks(ReadOnlySpan<byte> b) =>
        b.Length >= 4 && BinaryPrimitives.ReadUInt32LittleEndian(b) is 0xA1B2C3D4 or 0xD4C3B2A1 or 0xA1B23C4D or 0x4D3CB2A1 or 0x0A0D0D0A;

    public IEnumerable<PcapFrame> Frames(CancellationToken ct)
    {
        if (!Read(0, 4, out _)) { Issue("too short for a capture header"); yield break; }
        var source = BinaryPrimitives.ReadUInt32LittleEndian(_buf) == 0x0A0D0D0A ? PcapNg(ct) : Pcap(ct);
        foreach (var frame in source) yield return frame;
    }

    private IEnumerable<PcapFrame> Pcap(CancellationToken ct)
    {
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(_buf);
        _big = magic is 0xD4C3B2A1 or 0x4D3CB2A1;
        bool nano = magic is 0xA1B23C4D or 0x4D3CB2A1;
        if (!_big && magic != 0xA1B2C3D4 && !nano) { Issue("not a pcap or pcapng file"); yield break; }
        Format = "pcap";
        if (!Read(4, 20, out _)) { Issue("truncated pcap header"); yield break; }
        int linkType = (int)(U32(20) & 0xFFFF);
        LinkTypes.Add(linkType);
        Interfaces = 1;
        for (long n = 0; ; n++)
        {
            if ((n & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            if (!Read(0, 16, out int got)) { if (got > 0) Issue("truncated record header at the end"); yield break; }
            long sec = U32(0), frac = U32(4);
            uint caplen = U32(8), origlen = U32(12);
            if (caplen > MaxBlock) { Issue($"record of {caplen:N0} bytes: the rest of the file is not read"); yield break; }
            if (!Read(0, (int)caplen, out _)) { Issue("truncated record at the end"); yield break; }
            yield return new PcapFrame(linkType, sec * 1_000_000 + (nano ? frac / 1000 : frac), (int)Math.Min(origlen, int.MaxValue), _buf.AsMemory(0, (int)caplen));
        }
    }

    private IEnumerable<PcapFrame> PcapNg(CancellationToken ct)
    {
        Format = "pcapng";
        for (long n = 0; ; n++)
        {
            if ((n & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            // Frames read the first block's type
            if (!(n == 0 ? Read(4, 4, out int got) : Read(0, 8, out got))) { if (got > 0 || n == 0) Issue("truncated block header at the end"); yield break; }
            uint type = BinaryPrimitives.ReadUInt32LittleEndian(_buf); // the section header type reads the same in both orders
            int header = 8;
            if (type == 0x0A0D0D0A)
            {
                if (!Read(8, 4, out _)) { Issue("truncated section header"); yield break; }
                uint bom = BinaryPrimitives.ReadUInt32LittleEndian(_buf.AsSpan(8));
                if (bom is not (0x1A2B3C4D or 0x4D3C2B1A)) { Issue("section header without a byte-order magic"); yield break; }
                _big = bom == 0x4D3C2B1A;
                _interfaces.Clear();
                header = 12;
            }
            else if (n == 0) { Issue("pcapng file without a section header first"); yield break; }
            else type = U32(0);
            uint length = U32(4);
            if (length < 12 || length % 4 != 0 || length < header + 4) { Issue($"block of invalid length {length} at block {n}"); yield break; }
            if (length > MaxBlock) { Issue($"block of {length:N0} bytes: the rest of the file is not read"); yield break; }
            if (!Read(header, (int)length - header, out _)) { Issue("truncated block at the end"); yield break; }
            if (U32((int)length - 4) != length) { Issue($"block {n}: trailing length differs from the leading one"); yield break; }
            var body = _buf.AsSpan(8, (int)length - 12);
            switch (type)
            {
                case 1: // interface description
                    if (body.Length < 8) { Issue("short interface description block"); break; }
                    if (_interfaces.Count >= MaxInterfaces) { Issue($"more than {MaxInterfaces} interfaces"); break; }
                    int lt = U16(body);
                    _interfaces.Add((lt, Resolution(body[8..])));
                    LinkTypes.Add(lt);
                    Interfaces++;
                    break;
                case 6: // enhanced packet
                case 2: // obsolete packet
                    {
                        if (body.Length < 20) { Issue("short packet block"); break; }
                        int iface = type == 6 ? (int)Math.Min(U32(body), int.MaxValue) : U16(body);
                        uint caplen = U32(body[12..]), origlen = U32(body[16..]);
                        if (iface >= _interfaces.Count) { Issue("packet on an undeclared interface"); break; }
                        if (caplen > body.Length - 20) { Issue("packet longer than its block"); break; }
                        ulong ts = (ulong)U32(body[4..]) << 32 | U32(body[8..]);
                        var (linkType, resolution) = _interfaces[iface];
                        yield return new PcapFrame(linkType, Micros(ts, resolution), (int)Math.Min(origlen, int.MaxValue), _buf.AsMemory(8 + 20, (int)caplen));
                        break;
                    }
                case 10: // decryption secrets: a TLS key log ("TLSK") is handed to Secrets
                    if (body.Length >= 8 && U32(body) == 0x544C534B && U32(body[4..]) is var secretLength && secretLength <= body.Length - 8) Secrets?.Invoke(body.Slice(8, (int)secretLength));
                    break;
                case 3: // simple packet: interface 0, no time
                    {
                        if (body.Length < 4) { Issue("short simple packet block"); break; }
                        if (_interfaces.Count == 0) { Issue("packet on an undeclared interface"); break; }
                        uint origlen = U32(body);
                        int caplen = (int)Math.Min(origlen, (uint)(body.Length - 4));
                        yield return new PcapFrame(_interfaces[0].LinkType, 0, (int)Math.Min(origlen, int.MaxValue), _buf.AsMemory(8 + 4, caplen));
                        break;
                    }
            }
        }
    }

    /// <summary>if_tsresol (option 9) of an interface's options; 6 (microseconds) when absent.</summary>
    private byte Resolution(ReadOnlySpan<byte> options)
    {
        for (int at = 0; at + 4 <= options.Length;)
        {
            int code = U16(options[at..]), len = U16(options[(at + 2)..]);
            if (code == 0 || at + 4 + len > options.Length) break;
            if (code == 9 && len >= 1) return options[at + 4];
            at += 4 + (len + 3) / 4 * 4;
        }
        return 6;
    }

    /// <summary>A pcapng time in microseconds: units of 10^-n seconds, or 2^-n when the high bit is set.</summary>
    internal static long Micros(ulong ts, byte resolution)
    {
        int n = resolution & 0x7F;
        unchecked
        {
            if ((resolution & 0x80) != 0) return (long)(ulong)((UInt128)ts * 1_000_000 >> n);
            if (n >= 6) return n - 6 > 19 ? 0 : (long)(ts / Pow10(n - 6));
            return (long)(ts * Pow10(6 - n));
        }
    }

    private static ulong Pow10(int n)
    {
        ulong r = 1;
        for (int i = 0; i < n; i++) r *= 10;
        return r;
    }

    /// <summary>Reads <paramref name="count"/> bytes to <paramref name="at"/> in the buffer; false when the stream ends first.</summary>
    private bool Read(int at, int count, out int got)
    {
        // a length past the end of a seekable stream is truncation: no buffer is grown for it
        int want = stream.CanSeek ? (int)Math.Min(count, Math.Max(0, stream.Length - stream.Position)) : count;
        if (_buf.Length < at + want) Array.Resize(ref _buf, Math.Max(at + want, Math.Min(_buf.Length * 2, MaxBlock + 16)));
        got = stream.ReadAtLeast(_buf.AsSpan(at, want), want, throwOnEndOfStream: false);
        return got == count;
    }

    private void Issue(string text)
    {
        if (Issues.Count < MaxIssues && !Issues.Contains(text)) Issues.Add(text);
    }

    private uint U32(int at) => U32(_buf.AsSpan(at));
    private uint U32(ReadOnlySpan<byte> b) => _big ? BinaryPrimitives.ReadUInt32BigEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b);
    private ushort U16(ReadOnlySpan<byte> b) => _big ? BinaryPrimitives.ReadUInt16BigEndian(b) : BinaryPrimitives.ReadUInt16LittleEndian(b);
}
