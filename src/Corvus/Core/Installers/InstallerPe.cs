namespace Corvus.Core.Installers;

/// <summary>An installer stub's PE layout, read through a range reader for both recognition and stream access.</summary>
internal static class InstallerPe
{
    /// <summary>Reads <c>count</c> bytes at a file offset; null when the range is not available (past the end, or past a head).</summary>
    public delegate byte[]? Read(long offset, int count);

    private const int ResourceDirectory = 2;
    private const int MaxEntries = 4096;

    public static Read Of(ReadOnlyMemory<byte> data) =>
        (offset, count) => offset >= 0 && count >= 0 && offset + count <= data.Length ? data.Span.Slice((int)offset, count).ToArray() : null;

    public static Read Of(Stream stream) => (offset, count) =>
    {
        if (offset < 0 || count < 0 || offset + count > stream.Length) return null;
        stream.Position = offset;
        var buffer = new byte[count];
        stream.ReadExactly(buffer);
        return buffer;
    };

    /// <summary>The file offset and size of a resource (type name or <c>#n</c>, first language); null when absent.</summary>
    public static (long Offset, int Size)? Resource(PeImage pe, ReadOnlySpan<byte> head, Read read, string type, uint id)
    {
        var (rva, size) = pe.Directory(head, ResourceDirectory);
        long root = rva == 0 || size == 0 ? -1 : pe.RvaToOffset(rva);
        if (root < 0) return null;
        var types = Entry(read, root, root, e => type.StartsWith('#') ? e.Name == null && "#" + e.Id == type : e.Name == type);
        if (types is not { Directory: true } t) return null;
        var names = Entry(read, root, root + t.Offset, e => e.Name == null && e.Id == id);
        if (names is not { Directory: true } n) return null;
        var language = Entry(read, root, root + n.Offset, _ => true);
        if (language is not { Directory: false } l || read(root + l.Offset, 8) is not { } leaf) return null;
        long at = pe.RvaToOffset(BitConverter.ToUInt32(leaf, 0));
        int length = BitConverter.ToInt32(leaf, 4);
        return at < 0 || length <= 0 ? null : (at, length);
    }

    private readonly record struct DirectoryEntry(string? Name, uint Id, uint Offset, bool Directory);

    private static DirectoryEntry? Entry(Read read, long root, long table, Func<DirectoryEntry, bool> match)
    {
        if (read(table, 16) is not { } header) return null;
        int count = BitConverter.ToUInt16(header, 12) + BitConverter.ToUInt16(header, 14);
        if (count > MaxEntries || read(table + 16, count * 8) is not { } entries) return null;
        for (int i = 0; i < count; i++)
        {
            uint key = BitConverter.ToUInt32(entries, i * 8), value = BitConverter.ToUInt32(entries, i * 8 + 4);
            string? name = (key & 0x80000000) != 0 ? Name(read, root + (key & 0x7FFFFFFF)) : null;
            var e = new DirectoryEntry(name, key & 0xFFFF, value & 0x7FFFFFFF, (value & 0x80000000) != 0);
            if (match(e)) return e;
        }
        return null;
    }

    private static string? Name(Read read, long at) =>
        read(at, 2) is { } n && read(at + 2, BitConverter.ToUInt16(n) * 2) is { } chars ? System.Text.Encoding.Unicode.GetString(chars) : null;
}
