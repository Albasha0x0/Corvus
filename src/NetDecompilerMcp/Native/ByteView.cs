using System.Buffers.Binary;
using System.Text;

namespace NetDecompilerMcp.Native;

/// <summary>
/// Bounds-checked, endian-aware reads from a window of a file snapshot (offsets are relative to the window):
/// out-of-range reads return 0 (or empty), never throw.
/// </summary>
internal readonly struct ByteView
{
    private readonly byte[] data;
    private readonly int origin;

    public ByteView(byte[] data, bool bigEndian) : this(data, 0, data.Length, bigEndian) { }

    public ByteView(byte[] data, long origin, long length, bool bigEndian)
    {
        this.data = data;
        this.origin = (int)Math.Clamp(origin, 0, data.Length);
        Length = Math.Clamp(length, 0, data.Length - this.origin);
        BigEndian = bigEndian;
    }

    public bool BigEndian { get; }
    public long Length { get; }

    /// <summary>The sub-window [offset, offset + length), clipped to this one.</summary>
    public ByteView Slice(long offset, long length) =>
        offset < 0 || offset >= Length ? new ByteView([], BigEndian) : new ByteView(data, origin + offset, Math.Min(length, Length - offset), BigEndian);

    public bool Has(long offset, long count) => offset >= 0 && count >= 0 && offset <= Length - count;

    public byte U8(long offset) => offset >= 0 && offset < Length ? data[origin + offset] : (byte)0;

    public ushort U16(long offset)
    {
        if (!Has(offset, 2)) return 0;
        var s = data.AsSpan(origin + (int)offset, 2);
        return BigEndian ? BinaryPrimitives.ReadUInt16BigEndian(s) : BinaryPrimitives.ReadUInt16LittleEndian(s);
    }

    public uint U32(long offset)
    {
        if (!Has(offset, 4)) return 0;
        var s = data.AsSpan(origin + (int)offset, 4);
        return BigEndian ? BinaryPrimitives.ReadUInt32BigEndian(s) : BinaryPrimitives.ReadUInt32LittleEndian(s);
    }

    public ulong U64(long offset)
    {
        if (!Has(offset, 8)) return 0;
        var s = data.AsSpan(origin + (int)offset, 8);
        return BigEndian ? BinaryPrimitives.ReadUInt64BigEndian(s) : BinaryPrimitives.ReadUInt64LittleEndian(s);
    }

    /// <summary>A 4- or 8-byte word.</summary>
    public ulong Word(long offset, bool is64) => is64 ? U64(offset) : U32(offset);

    /// <summary>Up to <paramref name="count"/> bytes at <paramref name="offset"/>, fewer at the end of the window.</summary>
    public ReadOnlySpan<byte> Span(long offset, long count) =>
        offset < 0 || offset >= Length || count <= 0 ? [] : data.AsSpan(origin + (int)offset, (int)Math.Min(count, Length - offset));

    /// <summary>A NUL-terminated UTF-8 string of at most <paramref name="max"/> bytes; null when it starts outside the window.</summary>
    public string? CString(long offset, int max)
    {
        if (offset < 0 || offset >= Length) return null;
        var rest = Span(offset, max);
        int end = rest.IndexOf((byte)0);
        return Encoding.UTF8.GetString(end < 0 ? rest : rest[..end]);
    }

    /// <summary>Writes <paramref name="value"/> as <paramref name="width"/> bytes (4 or 8) in the given byte order.</summary>
    public static void Put(Span<byte> destination, ulong value, int width, bool bigEndian)
    {
        if (width == 8)
        {
            if (bigEndian) BinaryPrimitives.WriteUInt64BigEndian(destination, value);
            else BinaryPrimitives.WriteUInt64LittleEndian(destination, value);
        }
        else if (bigEndian) BinaryPrimitives.WriteUInt32BigEndian(destination, (uint)value);
        else BinaryPrimitives.WriteUInt32LittleEndian(destination, (uint)value);
    }
}

/// <summary>Sequential LEB128 decoding over a span; reading past the end sets <see cref="Failed"/> and yields 0.</summary>
internal ref struct LebReader(ReadOnlySpan<byte> data, int position = 0)
{
    private readonly ReadOnlySpan<byte> data = data;
    public int Position = position;
    public bool Failed;

    public readonly bool AtEnd => Position >= data.Length;

    public byte Byte()
    {
        if (Position >= data.Length) { Failed = true; return 0; }
        return data[Position++];
    }

    public ulong Uleb()
    {
        ulong result = 0;
        for (int shift = 0; ; shift += 7)
        {
            if (Position >= data.Length) { Failed = true; return 0; }
            byte b = data[Position++];
            if (shift < 64) result |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) return result;
            if (shift > 70) { Failed = true; return 0; }
        }
    }

    public long Sleb()
    {
        long result = 0;
        int shift = 0;
        byte b;
        do
        {
            if (Position >= data.Length) { Failed = true; return 0; }
            b = data[Position++];
            if (shift < 64) result |= (long)(b & 0x7F) << shift;
            shift += 7;
            if (shift > 77) { Failed = true; return 0; }
        } while ((b & 0x80) != 0);
        if (shift < 64 && (b & 0x40) != 0) result |= -1L << shift;
        return result;
    }

    /// <summary>A NUL-terminated string; null (and <see cref="Failed"/>) when unterminated.</summary>
    public string? CString()
    {
        if (Position >= data.Length) { Failed = true; return null; }
        int end = data[Position..].IndexOf((byte)0);
        if (end < 0) { Failed = true; return null; }
        var s = Encoding.UTF8.GetString(data.Slice(Position, end));
        Position += end + 1;
        return s;
    }
}
