using System.Buffers.Binary;
using System.Text;

namespace Corvus.Native.ReadyToRun;

/// <summary>Malformed ReadyToRun data; the service reports it as a typed error.</summary>
public sealed class R2RFormatException(string message) : Exception(message);

/// <summary>Bounds-checked little-endian reads by RVA; reads outside the image throw <see cref="R2RFormatException"/>; <paramref name="reader"/> replaces <see cref="INativeImage.Read"/> for derived bytes.</summary>
public sealed class ImageView(INativeImage image, ImageView.Reader? reader = null)
{
    public delegate int Reader(uint rva, Span<byte> destination);

    private readonly Reader read = reader ?? image.Read;

    public INativeImage Image => image;

    private void Fill(uint rva, Span<byte> buffer)
    {
        if (read(rva, buffer) != buffer.Length)
            throw new R2RFormatException($"read of {buffer.Length} bytes at RVA 0x{rva:X} is outside the mapped image");
    }

    public byte U8(uint rva)
    {
        Span<byte> b = stackalloc byte[1];
        Fill(rva, b);
        return b[0];
    }

    public ushort U16(uint rva)
    {
        Span<byte> b = stackalloc byte[2];
        Fill(rva, b);
        return BinaryPrimitives.ReadUInt16LittleEndian(b);
    }

    public uint U32(uint rva)
    {
        Span<byte> b = stackalloc byte[4];
        Fill(rva, b);
        return BinaryPrimitives.ReadUInt32LittleEndian(b);
    }

    public byte[] Bytes(uint rva, int length)
    {
        var b = new byte[length];
        Fill(rva, b);
        return b;
    }

    /// <summary>A UTF-8 string of at most <paramref name="max"/> bytes, ending at the first zero byte.</summary>
    public string Utf8(uint rva, int max)
    {
        var b = new byte[max];
        int n = read(rva, b);
        int end = Array.IndexOf(b, (byte)0, 0, n);
        return Encoding.UTF8.GetString(b, 0, end < 0 ? n : end);
    }

    public static uint Add(uint rva, long delta)
    {
        long at = rva + delta;
        if (at < 0 || at > uint.MaxValue) throw new R2RFormatException($"offset {delta} from RVA 0x{rva:X} leaves the address space");
        return (uint)at;
    }
}

/// <summary>The runtime's native format (nativeformatreader.h): varints, NativeArray and NativeHashtable, by RVA.</summary>
public static class NativeFormat
{
    /// <summary>Decodes an unsigned integer at <paramref name="at"/>; returns the RVA after it.</summary>
    public static uint DecodeUnsigned(ImageView v, uint at, out uint value)
    {
        uint b = v.U8(at);
        if ((b & 1) == 0) { value = b >> 1; return at + 1; }
        if ((b & 2) == 0) { value = (b >> 2) | ((uint)v.U8(at + 1) << 6); return at + 2; }
        if ((b & 4) == 0) { value = (b >> 3) | ((uint)v.U8(at + 1) << 5) | ((uint)v.U8(at + 2) << 13); return at + 3; }
        if ((b & 8) == 0) { value = (b >> 4) | ((uint)v.U8(at + 1) << 4) | ((uint)v.U8(at + 2) << 12) | ((uint)v.U8(at + 3) << 20); return at + 4; }
        if ((b & 16) == 0) { value = v.U32(at + 1); return at + 5; }
        throw new R2RFormatException($"bad native-format integer at RVA 0x{at:X}");
    }

    /// <summary>Decodes a signed integer at <paramref name="at"/>; returns the RVA after it.</summary>
    public static uint DecodeSigned(ImageView v, uint at, out int value)
    {
        int b = v.U8(at);
        if ((b & 1) == 0) { value = (sbyte)b >> 1; return at + 1; }
        if ((b & 2) == 0) { value = (b >> 2) | ((sbyte)v.U8(at + 1) << 6); return at + 2; }
        if ((b & 4) == 0) { value = (b >> 3) | (v.U8(at + 1) << 5) | ((sbyte)v.U8(at + 2) << 13); return at + 3; }
        if ((b & 8) == 0) { value = (b >> 4) | (v.U8(at + 1) << 4) | (v.U8(at + 2) << 12) | ((sbyte)v.U8(at + 3) << 20); return at + 4; }
        if ((b & 16) == 0) { value = (int)v.U32(at + 1); return at + 5; }
        throw new R2RFormatException($"bad native-format integer at RVA 0x{at:X}");
    }

    /// <summary>A sparse array: blocks of 16 elements, each a small binary tree of present indices.</summary>
    public sealed class NativeArray
    {
        private const uint BlockSize = 16;
        private readonly ImageView _view;
        private readonly uint _base;
        private readonly int _entryIndexSize;

        public NativeArray(ImageView view, uint rva)
        {
            _view = view;
            _base = DecodeUnsigned(view, rva, out uint header);
            Count = header >> 2;
            _entryIndexSize = (int)(header & 3);
            if (_entryIndexSize == 3) throw new R2RFormatException($"bad native array header at RVA 0x{rva:X}");
        }

        public uint Count { get; }

        /// <summary>The RVA of element <paramref name="index"/>, or false when the element is absent.</summary>
        public bool TryGetAt(uint index, out uint rva)
        {
            rva = 0;
            if (index >= Count) return false;
            uint block = index / BlockSize;
            uint offset = _entryIndexSize switch
            {
                0 => _view.U8(_base + block),
                1 => _view.U16(_base + 2 * block),
                _ => _view.U32(_base + 4 * block),
            };
            uint at = ImageView.Add(_base, offset);
            for (uint bit = BlockSize >> 1; bit > 0; bit >>= 1)
            {
                uint next = DecodeUnsigned(_view, at, out uint val);
                if ((index & bit) != 0)
                {
                    if ((val & 2) != 0) { at = ImageView.Add(at, val >> 2); continue; }
                }
                else if ((val & 1) != 0)
                {
                    at = next;
                    continue;
                }
                // A special leaf names the one index stored below this node.
                if ((val & 3) == 0 && (val >> 2) == (index & (BlockSize - 1)))
                {
                    at = next;
                    break;
                }
                return false;
            }
            rva = at;
            return true;
        }
    }

    /// <summary>The RVA of every entry of a NativeHashtable.</summary>
    public static List<uint> HashtableEntries(ImageView v, uint rva, uint end, int maxEntries)
    {
        uint header = v.U8(rva);
        uint baseRva = rva + 1;
        int shift = (int)(header >> 2);
        int indexSize = (int)(header & 3);
        if (shift > 24 || indexSize == 3) throw new R2RFormatException($"bad hash table header at RVA 0x{rva:X}");
        uint buckets = 1u << shift;
        if (end < baseRva || (ulong)(buckets + 1) << indexSize > end - baseRva)
            throw new R2RFormatException($"hash table at RVA 0x{rva:X} claims {buckets} buckets beyond its end");
        uint Bucket(uint i) => indexSize switch
        {
            0 => v.U8(baseRva + i),
            1 => v.U16(baseRva + 2 * i),
            _ => v.U32(baseRva + 4 * i),
        };
        var entries = new List<uint>();
        for (uint i = 0; i < buckets; i++)
        {
            uint at = ImageView.Add(baseRva, Bucket(i)), stop = ImageView.Add(baseRva, Bucket(i + 1));
            if (stop < at || stop > end) throw new R2RFormatException($"hash table bucket {i} at RVA 0x{rva:X} is out of range");
            while (at < stop)
            {
                uint pos = at + 1; // skip the low hash byte
                at = DecodeSigned(v, pos, out int delta);
                entries.Add(ImageView.Add(pos, delta));
                if (entries.Count > maxEntries) throw new R2RFormatException($"hash table at RVA 0x{rva:X} has more than {maxEntries} entries");
            }
        }
        return entries;
    }
}

/// <summary>Reads 4-bit nibbles, low half first; integers are big-endian 3-bit groups with bit 3 as the continuation flag.</summary>
public sealed class NibbleReader(ImageView view, uint rva)
{
    private uint _at = rva;
    private int _pending = -1;

    private uint Nibble()
    {
        if (_pending >= 0)
        {
            uint n = (uint)_pending;
            _pending = -1;
            return n;
        }
        uint b = view.U8(_at++);
        _pending = (int)(b >> 4);
        return b & 0xF;
    }

    public uint ReadUInt()
    {
        uint value = 0;
        for (int i = 0; ; i++)
        {
            if (i > 11) throw new R2RFormatException($"nibble-encoded integer near RVA 0x{_at:X} is too long");
            uint n = Nibble();
            value = (value << 3) | (n & 7);
            if ((n & 8) == 0) return value;
        }
    }
}

/// <summary>ECMA-335 compressed integers and bytes of a signature blob, read by RVA.</summary>
public sealed class SigReader(ImageView view, uint rva)
{
    public uint Position { get; private set; } = rva;
    public ImageView View => view;

    public byte Byte() => view.U8(Position++);

    public byte Peek() => view.U8(Position);

    public uint Compressed()
    {
        uint b = Byte();
        if ((b & 0x80) == 0) return b;
        if ((b & 0xC0) == 0x80) return ((b & 0x3F) << 8) | Byte();
        if ((b & 0xE0) == 0xC0) return ((b & 0x1F) << 24) | ((uint)Byte() << 16) | ((uint)Byte() << 8) | Byte();
        throw new R2RFormatException($"bad compressed integer at RVA 0x{Position - 1:X}");
    }
}
