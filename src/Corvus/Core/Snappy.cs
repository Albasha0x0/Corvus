using System.Buffers.Binary;

namespace Corvus.Core;

/// <summary>Snappy raw block decompression; throws <see cref="InvalidDataException"/> on damaged data or a length over the limit.</summary>
internal static class Snappy
{
    public static byte[] Decompress(ReadOnlySpan<byte> src, long maxBytes)
    {
        int at = 0;
        ulong length = 0;
        for (int shift = 0; ; shift += 7)
        {
            if (at >= src.Length || shift > 28) throw new InvalidDataException("snappy: bad length");
            byte b = src[at++];
            length |= (ulong)(b & 0x7F) << shift;
            if (b < 0x80) break;
        }
        if (length > (ulong)Math.Min(maxBytes, int.MaxValue)) throw new InvalidDataException($"snappy: {length:N0} bytes is over the limit");
        var dst = new byte[length];
        int o = 0;
        while (at < src.Length)
        {
            byte tag = src[at++];
            int len, offset;
            switch (tag & 3)
            {
                case 0:
                    len = tag >> 2;
                    if (len >= 60)
                    {
                        int n = len - 59;
                        if (at + n > src.Length) throw new InvalidDataException("snappy: truncated literal length");
                        len = 0;
                        for (int i = 0; i < n; i++) len |= src[at + i] << (8 * i);
                        at += n;
                        if (len < 0) throw new InvalidDataException("snappy: bad literal length");
                    }
                    len++;
                    if (len > src.Length - at || len > dst.Length - o) throw new InvalidDataException("snappy: literal past the end");
                    src.Slice(at, len).CopyTo(dst.AsSpan(o));
                    at += len;
                    o += len;
                    continue;
                case 1:
                    if (at >= src.Length) throw new InvalidDataException("snappy: truncated copy");
                    len = 4 + ((tag >> 2) & 7);
                    offset = (tag >> 5) << 8 | src[at++];
                    break;
                case 2:
                    if (at + 2 > src.Length) throw new InvalidDataException("snappy: truncated copy");
                    len = (tag >> 2) + 1;
                    offset = BinaryPrimitives.ReadUInt16LittleEndian(src[at..]);
                    at += 2;
                    break;
                default:
                    if (at + 4 > src.Length) throw new InvalidDataException("snappy: truncated copy");
                    len = (tag >> 2) + 1;
                    offset = BinaryPrimitives.ReadInt32LittleEndian(src[at..]);
                    at += 4;
                    break;
            }
            if (offset <= 0 || offset > o || len > dst.Length - o) throw new InvalidDataException("snappy: copy outside the output");
            // A copy may overlap its own output (offset < len), so it goes byte by byte.
            for (int i = 0; i < len; i++, o++) dst[o] = dst[o - offset];
        }
        if (o != dst.Length) throw new InvalidDataException($"snappy: {o:N0} of {dst.Length:N0} bytes decoded");
        return dst;
    }
}
