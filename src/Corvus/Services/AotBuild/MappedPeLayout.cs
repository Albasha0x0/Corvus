using System.Buffers.Binary;

namespace Corvus.Services;

/// <summary>
/// A PE file's section table, and whether the file is a memory image (each section at its RVA) whose headers still
/// give the file layout.
/// </summary>
public static class MappedPeLayout
{
    public sealed record Section(string Name, uint Rva, uint VirtualSize, uint RawOffset, uint RawSize, uint Characteristics, int HeaderOffset)
    {
        public bool Executable => (Characteristics & 0x20000000) != 0;
        public bool Initialized => (Characteristics & 0x40) != 0;
        public bool Contains(uint rva) => rva >= Rva && rva < Rva + Math.Max(VirtualSize, RawSize);
    }

    public sealed record Header(ushort Machine, bool Is64, ulong ImageBase, int ImageBaseOffset, uint SizeOfImage, uint SizeOfHeaders, IReadOnlyList<Section> Sections)
    {
        public Section? SectionAt(uint rva) => Sections.FirstOrDefault(s => s.Contains(rva));

        /// <summary>The offset of an RVA in the file as the headers lay it out; null outside the sections' raw data.</summary>
        public ulong? FileOffset(uint rva) => SectionAt(rva) is { } s && rva - s.Rva < s.RawSize ? s.RawOffset + (ulong)(rva - s.Rva) : null;
    }

    /// <summary>The headers, or null when the bytes are not a PE image.</summary>
    public static Header? Parse(ReadOnlySpan<byte> b)
    {
        if (b.Length < 0x40 || b[0] != 'M' || b[1] != 'Z') return null;
        int pe = BinaryPrimitives.ReadInt32LittleEndian(b[0x3C..]);
        if (pe < 0 || pe > b.Length - 24 || BinaryPrimitives.ReadUInt32LittleEndian(b[pe..]) != 0x4550) return null;
        ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(b[(pe + 4)..]);
        int count = BinaryPrimitives.ReadUInt16LittleEndian(b[(pe + 6)..]);
        int optSize = BinaryPrimitives.ReadUInt16LittleEndian(b[(pe + 20)..]);
        int opt = pe + 24;
        if (opt + optSize > b.Length || optSize < 0x40) return null;
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(b[opt..]);
        bool is64 = magic == 0x20B;
        if (!is64 && magic != 0x10B) return null;
        int baseOffset = is64 ? opt + 24 : opt + 28;
        ulong imageBase = is64 ? BinaryPrimitives.ReadUInt64LittleEndian(b[baseOffset..]) : BinaryPrimitives.ReadUInt32LittleEndian(b[baseOffset..]);
        uint sizeOfImage = BinaryPrimitives.ReadUInt32LittleEndian(b[(opt + 56)..]);
        uint sizeOfHeaders = BinaryPrimitives.ReadUInt32LittleEndian(b[(opt + 60)..]);
        var sections = new List<Section>();
        int table = opt + optSize;
        for (int i = 0; i < Math.Min(count, 96); i++)
        {
            int o = table + 40 * i;
            if (o + 40 > b.Length) return null;
            var name = System.Text.Encoding.ASCII.GetString(b.Slice(o, 8)).TrimEnd('\0');
            sections.Add(new Section(name, BinaryPrimitives.ReadUInt32LittleEndian(b[(o + 12)..]), BinaryPrimitives.ReadUInt32LittleEndian(b[(o + 8)..]),
                BinaryPrimitives.ReadUInt32LittleEndian(b[(o + 20)..]), BinaryPrimitives.ReadUInt32LittleEndian(b[(o + 16)..]),
                BinaryPrimitives.ReadUInt32LittleEndian(b[(o + 36)..]), o));
        }
        return new Header(machine, is64, imageBase, baseOffset, sizeOfImage, sizeOfHeaders, sections);
    }

    /// <summary>True for a memory image: SizeOfImage long, with the first moved section's data at its RVA and zeros at its raw offset.</summary>
    public static bool IsMapped(Header h, long fileLength, Func<long, int, byte[]> read)
    {
        if (h.SizeOfImage == 0 || fileLength < h.SizeOfImage || fileLength > h.SizeOfImage + 0x1000L) return false;
        var s = h.Sections.FirstOrDefault(x => x.RawOffset != x.Rva && x.RawSize > 0 && x.VirtualSize >= 64);
        if (s == null || s.Rva + (long)s.VirtualSize > fileLength) return false;
        var atRaw = read(s.RawOffset, 64);
        var atRva = read(s.Rva, 64);
        return atRaw.Length == 64 && atRva.Length == 64 && atRva.Any(x => x != 0) && atRaw.All(x => x == 0);
    }

    public static bool IsMapped(byte[] bytes, Header h) =>
        IsMapped(h, bytes.LongLength, (offset, count) => offset + count <= bytes.LongLength ? bytes.AsSpan((int)offset, count).ToArray() : []);

    /// <summary>Reads the headers of a file (the first 64 KB); null when it is not a PE image.</summary>
    public static (Header Header, bool Mapped)? ReadFile(string path)
    {
        using var file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        long length = RandomAccess.GetLength(file);
        var head = new byte[(int)Math.Min(length, 1 << 16)];
        RandomAccess.Read(file, head, 0);
        if (Parse(head) is not { } h) return null;
        byte[] Read(long offset, int count)
        {
            if (offset < 0 || offset + count > length) return [];
            var buffer = new byte[count];
            RandomAccess.Read(file, buffer, offset);
            return buffer;
        }
        return (h, IsMapped(h, length, Read));
    }

    /// <summary>Rewrites the section table of a memory image in place so that each section's raw data is at its RVA.</summary>
    public static void Normalize(byte[] bytes, Header h)
    {
        foreach (var s in h.Sections)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(s.HeaderOffset + 20), s.Rva);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(s.HeaderOffset + 16), (uint)Math.Min(s.VirtualSize, Math.Max(0, bytes.LongLength - s.Rva)));
        }
    }
}
