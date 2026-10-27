using System.Buffers.Binary;

namespace Corvus.Core;

/// <summary>Where a native image's own bytes end in its file; what follows is an overlay.</summary>
public static class ImageExtent
{
    private const int MaxHeaders = 1 << 16;

    /// <summary>The end of the image in a file of <paramref name="length"/> bytes read by <paramref name="read"/> (offset, count); null when the format is not one of these or its headers are unreadable.</summary>
    public static long? Of(ReadOnlySpan<byte> head, long length, Func<long, int, byte[]> read)
    {
        try
        {
            long? end = Native.NativeImageLoader.Detect(head) switch
            {
                Native.NativeFileKind.Pe => PeImage.TryParse(head)?.EndOfImage,
                Native.NativeFileKind.Elf => Elf(head, length, read),
                Native.NativeFileKind.MachO => MachO(head, 0, length, read),
                Native.NativeFileKind.MachOFat => Fat(head, length, read),
                _ => null,
            };
            return end is > 0 ? Math.Min(end.Value, length) : null;
        }
        catch (Exception ex) when (ex is ArgumentException or EndOfStreamException or IOException) { return null; }
    }

    private static long? Elf(ReadOnlySpan<byte> h, long length, Func<long, int, byte[]> read)
    {
        if (h.Length < 0x40) return null;
        bool is64 = h[4] == 2, be = h[5] == 2;
        ulong U(ReadOnlySpan<byte> b, int at, int size) => size switch
        {
            2 => be ? BinaryPrimitives.ReadUInt16BigEndian(b[at..]) : BinaryPrimitives.ReadUInt16LittleEndian(b[at..]),
            4 => be ? BinaryPrimitives.ReadUInt32BigEndian(b[at..]) : BinaryPrimitives.ReadUInt32LittleEndian(b[at..]),
            _ => be ? BinaryPrimitives.ReadUInt64BigEndian(b[at..]) : BinaryPrimitives.ReadUInt64LittleEndian(b[at..]),
        };
        int w = is64 ? 8 : 4;
        ulong phoff = U(h, is64 ? 0x20 : 0x1C, w), shoff = U(h, is64 ? 0x28 : 0x20, w);
        int phentsize = (int)U(h, is64 ? 0x36 : 0x2A, 2), phnum = (int)U(h, is64 ? 0x38 : 0x2C, 2);
        int shentsize = (int)U(h, is64 ? 0x3A : 0x2E, 2), shnum = (int)U(h, is64 ? 0x3C : 0x30, 2);
        long end = is64 ? 0x40 : 0x34;
        byte[]? Table(ulong offset, int entsize, int count) =>
            offset == 0 || count == 0 || entsize < (is64 ? 0x38 : 0x20) || (long)offset + (long)entsize * count > length || entsize * (long)count > MaxHeaders * 64L
                ? null : read((long)offset, entsize * count);
        if (Table(phoff, phentsize, phnum) is { } ph)
        {
            end = Math.Max(end, (long)phoff + phentsize * phnum);
            for (int i = 0; i < phnum; i++)
            {
                var p = ph.AsSpan(i * phentsize);
                ulong offset = U(p, is64 ? 8 : 4, w), filesz = U(p, is64 ? 32 : 16, w);
                if (offset + filesz <= (ulong)length) end = Math.Max(end, (long)(offset + filesz));
            }
        }
        if (shentsize >= (is64 ? 0x40 : 0x28) && Table(shoff, shentsize, shnum) is { } sh)
        {
            end = Math.Max(end, (long)shoff + shentsize * shnum);
            for (int i = 0; i < shnum; i++)
            {
                var s = sh.AsSpan(i * shentsize);
                // SHT_NOBITS has no file bytes.
                if (U(s, 4, 4) == 8) continue;
                ulong offset = U(s, is64 ? 24 : 16, w), size = U(s, is64 ? 32 : 20, w);
                if (offset + size <= (ulong)length) end = Math.Max(end, (long)(offset + size));
            }
        }
        return end;
    }

    private static long? MachO(ReadOnlySpan<byte> h, long start, long length, Func<long, int, byte[]> read)
    {
        if (h.Length < 28) return null;
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(h);
        bool be = magic is 0xCEFAEDFE or 0xCFFAEDFE, is64 = magic is 0xFEEDFACF or 0xCFFAEDFE;
        uint U32(ReadOnlySpan<byte> b, int at) => be ? BinaryPrimitives.ReadUInt32BigEndian(b[at..]) : BinaryPrimitives.ReadUInt32LittleEndian(b[at..]);
        ulong U64(ReadOnlySpan<byte> b, int at) => be ? BinaryPrimitives.ReadUInt64BigEndian(b[at..]) : BinaryPrimitives.ReadUInt64LittleEndian(b[at..]);
        int header = is64 ? 32 : 28;
        uint ncmds = U32(h, 16), sizeofcmds = U32(h, 20);
        if (sizeofcmds > 64 << 20 || start + header + sizeofcmds > length) return null;
        ReadOnlySpan<byte> cmds = h.Length >= header + sizeofcmds ? h.Slice(header, (int)sizeofcmds) : read(start + header, (int)sizeofcmds);
        long end = header + sizeofcmds;
        for (int at = 0, i = 0; i < ncmds && at + 8 <= cmds.Length; i++)
        {
            uint cmd = U32(cmds, at), size = U32(cmds, at + 4);
            if (size < 8 || at + size > cmds.Length) break;
            if (cmd == 0x19 && size >= 72) end = Math.Max(end, (long)(U64(cmds, at + 40) + U64(cmds, at + 48)));
            else if (cmd == 0x1 && size >= 56) end = Math.Max(end, (long)U32(cmds, at + 32) + U32(cmds, at + 36));
            at += (int)size;
        }
        return end;
    }

    private static long? Fat(ReadOnlySpan<byte> h, long length, Func<long, int, byte[]> read)
    {
        bool fat64 = BinaryPrimitives.ReadUInt32BigEndian(h) == 0xCAFEBABF;
        uint count = BinaryPrimitives.ReadUInt32BigEndian(h[4..]);
        int entry = fat64 ? 32 : 20;
        if (count == 0 || 8 + count * entry > h.Length) return null;
        long end = 8 + count * entry;
        for (int i = 0; i < count; i++)
        {
            var a = h[(8 + i * entry)..];
            long offset = fat64 ? (long)BinaryPrimitives.ReadUInt64BigEndian(a[8..]) : BinaryPrimitives.ReadUInt32BigEndian(a[8..]);
            long size = fat64 ? (long)BinaryPrimitives.ReadUInt64BigEndian(a[16..]) : BinaryPrimitives.ReadUInt32BigEndian(a[12..]);
            if (offset < 0 || size < 0 || offset + size > length) return null;
            end = Math.Max(end, offset + size);
        }
        return end;
    }
}
