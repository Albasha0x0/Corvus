using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Assets;

/// <summary>A bounds-checked reader in either byte order; reading past the end throws <see cref="InvalidDataException"/>.</summary>
internal sealed class AssetBinary(byte[] data, int start, int end, bool bigEndian)
{
    public AssetBinary(byte[] data, bool bigEndian) : this(data, 0, data.Length, bigEndian) { }

    public int Position { get; set; } = start;
    public int Start { get; } = start;
    public int End => end;
    public bool BigEndian { get; set; } = bigEndian;
    public int Remaining => end - Position;

    private ReadOnlySpan<byte> Take(int n)
    {
        if (n < 0 || Position > end - n) throw new InvalidDataException($"{n} bytes past the end at 0x{Position:x}");
        var span = data.AsSpan(Position, n);
        Position += n;
        return span;
    }

    public byte U8() => Take(1)[0];
    public bool Bool() => U8() != 0;
    public short I16() => BigEndian ? BinaryPrimitives.ReadInt16BigEndian(Take(2)) : BinaryPrimitives.ReadInt16LittleEndian(Take(2));
    public ushort U16() => (ushort)I16();
    public int I32() => BigEndian ? BinaryPrimitives.ReadInt32BigEndian(Take(4)) : BinaryPrimitives.ReadInt32LittleEndian(Take(4));
    public uint U32() => (uint)I32();
    public long I64() => BigEndian ? BinaryPrimitives.ReadInt64BigEndian(Take(8)) : BinaryPrimitives.ReadInt64LittleEndian(Take(8));
    public ulong U64() => (ulong)I64();
    public float F32() => BitConverter.Int32BitsToSingle(I32());
    public double F64() => BitConverter.Int64BitsToDouble(I64());
    public byte[] Bytes(int n) => Take(n).ToArray();
    public void Skip(int n) => Take(n);

    /// <summary>Moves to the next multiple of <paramref name="n"/> from the start of the data.</summary>
    public void Align(int n = 4)
    {
        int rem = (Position - Start) % n;
        if (rem != 0) Take(n - rem);
    }

    /// <summary>A NUL-terminated UTF-8 string of at most <paramref name="max"/> bytes.</summary>
    public string CString(int max = 4096)
    {
        int limit = Math.Min(end, Position + max);
        int zero = Array.IndexOf(data, (byte)0, Position, limit - Position);
        if (zero < 0) throw new InvalidDataException($"no string end within {max} bytes at 0x{Position:x}");
        var s = Encoding.UTF8.GetString(data, Position, zero - Position);
        Position = zero + 1;
        return s;
    }

    /// <summary>A length-prefixed UTF-8 string, as serialized asset files write string fields, aligned to 4 bytes after it when asked.</summary>
    public string String(bool align)
    {
        int n = I32();
        if (n < 0 || n > Remaining) throw new InvalidDataException($"a string of {n} bytes at 0x{Position - 4:x}");
        var s = Encoding.UTF8.GetString(Take(n));
        if (align) Align();
        return s;
    }
}
