using System.Buffers.Binary;
using System.Text;
using Corvus.Core.Installers;

namespace Corvus.Core.Documents;

/// <summary>A file of a compiled help image: path, section (0 stored, 1 LZX), offset, length.</summary>
internal sealed record ChmEntry(string Name, int Section, long Offset, long Length);

/// <summary>Reads compiled help images (ITSF 2 and 3): directory, stored and LZX files.</summary>
internal sealed class ChmFile
{
    private const string Content = "::DataSpace/Storage/MSCompressed/Content";
    private const string Control = "::DataSpace/Storage/MSCompressed/ControlData";
    private const string Reset = "::DataSpace/Storage/MSCompressed/Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable";
    private const int Frame = 0x8000, MaxEntries = 1_000_000;

    private readonly byte[] _data;
    private readonly long _contentAt;
    private readonly string _name;
    private readonly CancellationToken _ct;
    private Section? _lzx;
    private ToolError? _lzxFailure;
    private Dictionary<string, ChmEntry>? _stored;
    private (int Index, byte[] Bytes)? _segment;

    public List<ChmEntry> Entries { get; } = [];
    public List<string> Notes { get; } = [];

    /// <summary>The LZX window exponent of the compressed section, or 0 when it is unread or absent.</summary>
    public int WindowBits => _lzx?.WindowBits ?? 0;

    private sealed record Section(int WindowBits, int FramesPerReset, long Length, long CompressedLength, long[] Offsets, long At, long Size);

    /// <summary>True when <paramref name="b"/> starts with an ITSF header of version 2 or 3.</summary>
    public static bool Looks(ReadOnlySpan<byte> b) =>
        b.Length >= 0x60 && b.StartsWith("ITSF"u8) && BinaryPrimitives.ReadUInt32LittleEndian(b[4..]) is 2 or 3;

    private ChmFile(byte[] data, string name, CancellationToken ct)
    {
        _ct = ct;
        _data = data;
        _name = name;
        var h = data.AsSpan();
        uint version = BinaryPrimitives.ReadUInt32LittleEndian(h[4..]);
        ulong dirAt = BinaryPrimitives.ReadUInt64LittleEndian(h[0x48..]), dirSize = BinaryPrimitives.ReadUInt64LittleEndian(h[0x50..]);
        ulong contentAt = version == 3 ? BinaryPrimitives.ReadUInt64LittleEndian(h[0x58..]) : dirAt + dirSize;
        if (dirAt > (ulong)data.Length || dirSize < 0x54 || dirSize > (ulong)data.Length - dirAt) throw Malformed("the directory runs past the file");
        if (contentAt > (ulong)data.Length) throw Malformed("the content starts past the file");
        _contentAt = (long)contentAt;
        ReadDirectory((int)dirAt, (long)dirSize);
    }

    /// <summary>Reads the directory of <paramref name="data"/>; throws <see cref="ToolError"/> when the header or directory is damaged.</summary>
    public static ChmFile Read(byte[] data, string name, CancellationToken ct)
    {
        if (!Looks(data)) throw new ToolError(ErrorCode.MalformedInput, $"{name} is not a compiled help image (no ITSF version 2 or 3 header).");
        return new ChmFile(data, name, ct);
    }

    private ToolError Malformed(string what) => new(ErrorCode.MalformedInput, $"{_name}: {what}.");

    private void ReadDirectory(int at, long size)
    {
        var h = _data.AsSpan(at);
        if (!h.StartsWith("ITSP"u8)) throw Malformed("the directory has no ITSP header");
        uint headerLength = BinaryPrimitives.ReadUInt32LittleEndian(h[8..]), chunkSize = BinaryPrimitives.ReadUInt32LittleEndian(h[0x10..]), chunks = BinaryPrimitives.ReadUInt32LittleEndian(h[0x2C..]);
        if (headerLength < 0x54 || headerLength > size) throw Malformed("the directory header length is out of range");
        if (chunkSize < 0x20 || chunkSize > 1 << 24) throw Malformed($"the directory chunk size {chunkSize:N0} is out of range");
        long fit = (size - headerLength) / chunkSize;
        if (chunks > fit) { Notes.Add($"the directory declares {chunks:N0} chunks; {fit:N0} fit, the rest are not read"); chunks = (uint)fit; }
        int damaged = 0;
        for (uint i = 0; i < chunks; i++)
        {
            _ct.ThrowIfCancellationRequested();
            var chunk = _data.AsSpan((int)(at + headerLength + (long)i * chunkSize), (int)chunkSize);
            if (!chunk.StartsWith("PMGL"u8)) continue;
            try { ReadListing(chunk); }
            catch (ToolError ex) when (ex.Code == ErrorCode.MalformedInput)
            {
                if (++damaged <= 5) Notes.Add($"directory chunk {i}: {ex.Message}");
            }
            if (Entries.Count >= MaxEntries) { Notes.Add($"more than {MaxEntries:N0} files; the rest are not listed"); break; }
        }
        if (damaged > 5) Notes.Add($"{damaged - 5} more directory chunks unreadable");
    }

    private void ReadListing(ReadOnlySpan<byte> chunk)
    {
        uint free = BinaryPrimitives.ReadUInt32LittleEndian(chunk[4..]);
        if (free > chunk.Length - 0x14) throw Malformed("a listing chunk reports more free space than it holds");
        int end = chunk.Length - (int)free, p = 0x14;
        while (p < end && Entries.Count < MaxEntries)
        {
            ulong length = Number(chunk, ref p, end);
            if (length > (ulong)(end - p)) throw Malformed("a file name runs past its chunk");
            var name = Encoding.UTF8.GetString(chunk.Slice(p, (int)length));
            p += (int)length;
            ulong section = Number(chunk, ref p, end), offset = Number(chunk, ref p, end), size = Number(chunk, ref p, end);
            if (section > 1 || offset > long.MaxValue || size > long.MaxValue) { Notes.Add($"{name}: content section {section}, offset {offset:N0}, size {size:N0} is out of range"); continue; }
            Entries.Add(new ChmEntry(name, (int)section, (long)offset, (long)size));
        }
    }

    // A number of seven bits per byte, most significant first; the high bit
    // is set while more follow.
    private ulong Number(ReadOnlySpan<byte> b, ref int p, int end)
    {
        ulong v = 0;
        for (int n = 0; n < 10; n++)
        {
            if (p >= end) throw Malformed("a listing entry runs past its chunk");
            byte c = b[p++];
            v = (v << 7) | (c & 0x7Fu);
            if (c < 0x80) return v;
        }
        throw Malformed("a listing number is longer than 10 bytes");
    }

    /// <summary>The compression of an entry's section: "stored" or "LZX:window exponent".</summary>
    public string Compression(ChmEntry e) => e.Section == 0 ? "stored" : $"LZX:{Compressed().WindowBits}";

    /// <summary>A file's bytes; throws <see cref="ToolError"/> when damaged, over <paramref name="max"/> or in a segment over <paramref name="segmentMax"/>.</summary>
    public byte[] Extract(ChmEntry e, long max, long segmentMax)
    {
        if (e.Length > max) throw new ToolError(ErrorCode.LimitExceeded, $"{_name}: {e.Name} holds {e.Length:N0} bytes, over the {max:N0}-byte item limit.");
        if (e.Section == 0) return Stored(e.Offset, e.Length, e.Name);
        var s = Compressed();
        if (e.Offset > s.Length || e.Length > s.Length - e.Offset) throw Malformed($"{e.Name} runs past the {s.Length:N0}-byte content section");
        if (e.Length == 0) return [];
        long reset = (long)s.FramesPerReset * Frame;
        var result = new byte[e.Length];
        long at = e.Offset, left = e.Length;
        while (left > 0)
        {
            _ct.ThrowIfCancellationRequested();
            int index = (int)(at / reset);
            var segment = Segment(s, index, segmentMax);
            long from = at - index * reset;
            int take = (int)Math.Min(left, segment.Length - from);
            if (take <= 0) throw Malformed($"segment {index} of the content section is shorter than its reset table says");
            segment.AsSpan((int)from, take).CopyTo(result.AsSpan((int)(e.Length - left)));
            at += take;
            left -= take;
        }
        return result;
    }

    private byte[] Stored(long offset, long length, string what)
    {
        long start = _contentAt + offset;
        if (offset < 0 || start > _data.Length || length > _data.Length - start) throw Malformed($"{what} runs past the file");
        return _data.AsSpan((int)start, (int)length).ToArray();
    }

    // The span between two resets is decoded alone: the decoder state restarts there.
    private byte[] Segment(Section s, int index, long segmentMax)
    {
        if (_segment is { } cached && cached.Index == index) return cached.Bytes;
        long first = (long)index * s.FramesPerReset, last = Math.Min(first + s.FramesPerReset, s.Offsets.Length);
        if (first >= s.Offsets.Length) throw Malformed($"segment {index} starts past the reset table");
        long from = s.Offsets[first], to = last < s.Offsets.Length ? s.Offsets[last] : s.CompressedLength;
        if (from < 0 || to < from || to > s.Size) throw Malformed($"segment {index} has compressed offsets outside the content section");
        var frames = new List<int>();
        for (long f = first; f < last; f++)
            frames.Add(f == s.Offsets.Length - 1 ? (int)(s.Length - f * Frame) : Frame);
        long decoded = frames.Sum(f => (long)f);
        if (decoded > segmentMax) throw new ToolError(ErrorCode.LimitExceeded, $"{_name}: segment {index} decompresses to {decoded:N0} bytes, over the {segmentMax:N0}-byte total limit.");
        var compressed = _data.AsSpan((int)(_contentAt + s.At + from), (int)(to - from)).ToArray();
        byte[] bytes;
        try { bytes = Lzx.DecodeFolder(compressed, frames, s.WindowBits, segmentMax); }
        catch (InvalidDataException ex) { throw Malformed($"segment {index}: {ex.Message}"); }
        _segment = (index, bytes);
        return bytes;
    }

    private Section Compressed()
    {
        if (_lzx != null) return _lzx;
        if (_lzxFailure != null) throw _lzxFailure;
        try { return _lzx = ReadCompressed(); }
        catch (ToolError ex) { _lzxFailure = ex; throw; }
    }

    private Section ReadCompressed()
    {
        _stored ??= Entries.Where(e => e.Section == 0).GroupBy(e => e.Name).ToDictionary(g => g.Key, g => g.First());
        ChmEntry? Find(string name) => _stored.GetValueOrDefault(name);
        if (Find(Content) is not { } content || Find(Control) is not { } control || Find(Reset) is not { } reset)
            throw new ToolError(ErrorCode.Unsupported, $"{_name}: the compressed content section is missing its content, control data or reset table.");
        var c = Stored(control.Offset, control.Length, "the control data");
        if (c.Length < 0x18 || !c.AsSpan(4).StartsWith("LZXC"u8)) throw new ToolError(ErrorCode.Unsupported, $"{_name}: the compressed content is not LZX (no LZXC control data).");
        uint version = BinaryPrimitives.ReadUInt32LittleEndian(c.AsSpan(8));
        ulong interval = BinaryPrimitives.ReadUInt32LittleEndian(c.AsSpan(12)), window = BinaryPrimitives.ReadUInt32LittleEndian(c.AsSpan(16));
        if (version == 2) { interval *= Frame; window *= Frame; }
        else if (version != 1) throw new ToolError(ErrorCode.Unsupported, $"{_name}: LZX control data version {version} is not read.");
        if (!ulong.IsPow2(window) || window < 1 << 15 || window > 1 << 21) throw Malformed($"the LZX window of {window:N0} bytes is out of range");
        if (interval == 0 || interval % Frame != 0 || interval > 1UL << 32) throw Malformed($"the reset interval of {interval:N0} bytes is out of range");
        var r = Stored(reset.Offset, reset.Length, "the reset table");
        if (r.Length < 0x28) throw Malformed("the reset table is shorter than its header");
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(r.AsSpan(4)), entry = BinaryPrimitives.ReadUInt32LittleEndian(r.AsSpan(8)), header = BinaryPrimitives.ReadUInt32LittleEndian(r.AsSpan(12));
        ulong length = BinaryPrimitives.ReadUInt64LittleEndian(r.AsSpan(0x10)), compressed = BinaryPrimitives.ReadUInt64LittleEndian(r.AsSpan(0x18)), block = BinaryPrimitives.ReadUInt64LittleEndian(r.AsSpan(0x20));
        if (entry != 8 || block != Frame) throw Malformed("the reset table does not use 8-byte entries of 32 KiB frames");
        if (header > r.Length || count > (r.Length - header) / 8) throw Malformed("the reset table lists more frames than it holds");
        if (length > long.MaxValue || compressed > long.MaxValue) throw Malformed("the reset table lengths are out of range");
        if (count == 0 ? length != 0 : length <= (ulong)(count - 1) * Frame || length > (ulong)count * Frame) throw Malformed("the reset table frame count does not match the uncompressed length");
        var offsets = new long[count];
        for (int i = 0; i < count; i++)
        {
            ulong o = BinaryPrimitives.ReadUInt64LittleEndian(r.AsSpan((int)header + i * 8));
            if (o > long.MaxValue) throw Malformed("a reset table offset is out of range");
            offsets[i] = (long)o;
        }
        if (content.Offset < 0 || _contentAt + content.Offset > _data.Length || content.Length > _data.Length - (_contentAt + content.Offset)) throw Malformed("the content section runs past the file");
        return new Section(System.Numerics.BitOperations.Log2((uint)window), (int)(interval / Frame), (long)length, (long)compressed, offsets, content.Offset, content.Length);
    }
}
