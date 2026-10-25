using System.Buffers.Binary;

namespace Corvus.Core.Firmware;

/// <summary>
/// Files an Apple filesystem stores compressed (decmpfs): the com.apple.decmpfs attribute's header, and its data in the
/// attribute or in the resource fork. zlib, LZVN and LZFSE (types 3, 4, 7, 8, 11, 12) are read; other types are named.
/// </summary>
internal static class Decmpfs
{
    /// <summary>The attribute's (type, uncompressed size), or null when it carries no 'cmpf' header.</summary>
    public static (uint Type, long Size)? Header(byte[] attribute) =>
        attribute.Length >= 16 && BinaryPrimitives.ReadUInt32LittleEndian(attribute) == 0x636D7066
            ? (BinaryPrimitives.ReadUInt32LittleEndian(attribute.AsSpan(4)), (long)BinaryPrimitives.ReadUInt64LittleEndian(attribute.AsSpan(8)))
            : null;

    public static bool Readable(uint type) => type is 3 or 4 or 7 or 8 or 11 or 12;

    public static string Name(uint type) => type switch { 3 or 4 => "zlib", 7 or 8 => "LZVN", 11 or 12 => "LZFSE", 1 or 9 or 10 => "uncompressed", _ => "unknown" };

    /// <summary>
    /// The first <paramref name="n"/> bytes of a decmpfs file of <paramref name="size"/> bytes: zlib, LZVN or LZFSE in the
    /// attribute (3, 7, 11) or in 64 KiB resource fork blocks (4, 8, 12); damaged data throws InvalidDataException.
    /// </summary>
    public static byte[] Decode(uint type, byte[] attribute, Func<byte[]> resourceFork, long size, long n, long maxBytes)
    {
        if (size < 0 || size > maxBytes) throw new InvalidDataException($"{size:N0} bytes");
        var output = new byte[size];
        if (type is 7 or 11) Block(type, attribute.AsSpan(16), output);
        else if (type is 8 or 12)
        {
            // The resource fork starts with block offsets, one more than the blocks; block i ends where i + 1 starts.
            var fork = resourceFork();
            int blocks = (int)((size + 65535) / 65536);
            if (4L * (blocks + 1) > fork.Length) throw new InvalidDataException($"a decmpfs offset table of {blocks + 1:N0} entries past the resource fork");
            for (int i = 0; i < blocks && (long)i * 65536 < Math.Min(n, size); i++)
            {
                uint from = BinaryPrimitives.ReadUInt32LittleEndian(fork.AsSpan(4 * i)), to = BinaryPrimitives.ReadUInt32LittleEndian(fork.AsSpan(4 * i + 4));
                if (from > to || to > fork.Length) throw new InvalidDataException($"decmpfs block {i} lies outside the resource fork");
                Block(type, fork.AsSpan((int)from, (int)(to - from)), output.AsSpan(i * 65536, (int)Math.Min(65536, size - (long)i * 65536)));
            }
        }
        else if (type == 3)
        {
            var body = attribute.AsSpan(16);
            // A first byte with its low nibble 0xF marks the rest as stored.
            if (body.Length > 0 && (body[0] & 0x0F) == 0x0F) body[1..Math.Min(body.Length, 1 + (int)size)].CopyTo(output);
            else FsCodec.Decode("zlib", body, output);
        }
        else if (type == 4)
        {
            var fork = resourceFork();
            // Resource fork header: data offset; the resource there is a length, then the block table.
            if (fork.Length < 0x104) throw new InvalidDataException("a short decmpfs resource fork");
            int dataAt = (int)BinaryPrimitives.ReadUInt32BigEndian(fork) + 4;
            if (dataAt + 4 > fork.Length) throw new InvalidDataException("the decmpfs block table lies outside the resource fork");
            int blocks = (int)BinaryPrimitives.ReadUInt32LittleEndian(fork.AsSpan(dataAt));
            if (blocks < 0 || (long)blocks * 65536 < size || dataAt + 4 + 8L * blocks > fork.Length) throw new InvalidDataException($"a decmpfs block table of {blocks:N0} blocks for {size:N0} bytes");
            for (int i = 0; i < blocks && (long)i * 65536 < Math.Min(n, size); i++)
            {
                long offset = BinaryPrimitives.ReadUInt32LittleEndian(fork.AsSpan(dataAt + 4 + 8 * i)), length = BinaryPrimitives.ReadUInt32LittleEndian(fork.AsSpan(dataAt + 8 + 8 * i));
                if (dataAt + offset + length > fork.Length) throw new InvalidDataException($"decmpfs block {i} lies outside the resource fork");
                var block = fork.AsSpan((int)(dataAt + offset), (int)length);
                var slot = output.AsSpan(i * 65536, (int)Math.Min(65536, size - (long)i * 65536));
                if (block.Length > 0 && block[0] == 0xFF) block[1..Math.Min(block.Length, 1 + slot.Length)].CopyTo(slot);
                else FsCodec.Decode("zlib", block, slot);
            }
        }
        else throw new InvalidDataException($"decmpfs compression type {type} ({Name(type)}) is not read; {size:N0} bytes");
        return n >= size ? output : output.AsSpan(0, (int)n).ToArray();
    }

    // An LZVN block whose first byte is the end-of-stream opcode (0x06) is stored after it.
    private static void Block(uint type, ReadOnlySpan<byte> block, Span<byte> slot)
    {
        int written;
        if (type is 7 or 8 && block.Length > 0 && block[0] == 0x06)
        {
            written = Math.Min(block.Length - 1, slot.Length);
            block.Slice(1, written).CopyTo(slot);
        }
        else written = type is 7 or 8 ? Lzfse.DecodeLzvn(block, slot) : Lzfse.Decode(block, slot);
        if (written != slot.Length) throw new InvalidDataException($"a decmpfs {Name(type)} block decodes to {written:N0} of {slot.Length:N0} bytes");
    }
}
