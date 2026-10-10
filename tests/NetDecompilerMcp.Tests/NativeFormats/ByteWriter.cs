using System.Buffers.Binary;
using System.Text;

namespace NetDecompilerMcp.Tests.NativeFormats;

/// <summary>Growable byte buffer with endian-aware fixed-size and LEB128 writes (test image builders).</summary>
internal sealed class ByteWriter(bool bigEndian = false)
{
    private byte[] buffer = new byte[256];

    public bool BigEndian { get; } = bigEndian;
    public int Length { get; private set; }
    public byte[] ToArray() => buffer.AsSpan(0, Length).ToArray();

    private Span<byte> Grow(int at, int count)
    {
        int end = at + count;
        if (end > buffer.Length) Array.Resize(ref buffer, Math.Max(end, buffer.Length * 2));
        if (end > Length) Length = end;
        return buffer.AsSpan(at, count);
    }

    public void U8(byte v) => Grow(Length, 1)[0] = v;
    public void U16(ushort v) => U16At(Length, v);
    public void U32(uint v) => U32At(Length, v);
    public void U64(ulong v) => U64At(Length, v);
    /// <summary>A 4- or 8-byte word.</summary>
    public void Word(ulong v, bool is64) { if (is64) U64(v); else U32((uint)v); }

    public void U16At(int at, ushort v) { var s = Grow(at, 2); if (BigEndian) BinaryPrimitives.WriteUInt16BigEndian(s, v); else BinaryPrimitives.WriteUInt16LittleEndian(s, v); }
    public void U32At(int at, uint v) { var s = Grow(at, 4); if (BigEndian) BinaryPrimitives.WriteUInt32BigEndian(s, v); else BinaryPrimitives.WriteUInt32LittleEndian(s, v); }
    public void U64At(int at, ulong v) { var s = Grow(at, 8); if (BigEndian) BinaryPrimitives.WriteUInt64BigEndian(s, v); else BinaryPrimitives.WriteUInt64LittleEndian(s, v); }
    public void WordAt(int at, ulong v, bool is64) { if (is64) U64At(at, v); else U32At(at, (uint)v); }

    public void Bytes(ReadOnlySpan<byte> bytes) => bytes.CopyTo(Grow(Length, bytes.Length));
    public void BytesAt(int at, ReadOnlySpan<byte> bytes) => bytes.CopyTo(Grow(at, bytes.Length));
    public void CString(string s) { Bytes(Encoding.UTF8.GetBytes(s)); U8(0); }
    /// <summary>A NUL-padded fixed-width name (Mach-O segment and section names).</summary>
    public void FixedString(string s, int width) { var b = new byte[width]; Encoding.ASCII.GetBytes(s).AsSpan(0, Math.Min(s.Length, width)).CopyTo(b); Bytes(b); }

    public void Align(int alignment) { while (Length % alignment != 0) U8(0); }
    public void PadTo(int length) { if (length > Length) Grow(Length, length - Length); }

    public void Uleb(ulong v)
    {
        do
        {
            byte b = (byte)(v & 0x7F);
            v >>= 7;
            U8(v != 0 ? (byte)(b | 0x80) : b);
        } while (v != 0);
    }

    public void Sleb(long v)
    {
        while (true)
        {
            byte b = (byte)(v & 0x7F);
            v >>= 7;
            bool done = (v == 0 && (b & 0x40) == 0) || (v == -1 && (b & 0x40) != 0);
            U8(done ? b : (byte)(b | 0x80));
            if (done) return;
        }
    }

    public static int UlebSize(ulong v) { int n = 1; while ((v >>= 7) != 0) n++; return n; }
}
