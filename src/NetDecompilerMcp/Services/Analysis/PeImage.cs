using System.Buffers.Binary;
using System.Text;

namespace NetDecompilerMcp.Services.Analysis;

/// <summary>Minimal, bounds-checked PE header parser. Never throws on malformed input.</summary>
public sealed class PeImage
{
    private const int MaxHeaderOffset = 0x1000;
    private const int MaxSections = 96;

    public sealed record Section(string Name, uint VirtualAddress, uint VirtualSize, uint RawPointer, uint RawSize);

    private PeImage(int start, ushort machine, bool is64, int optionalHeaderOffset, int dataDirectoryCount, int dataDirectoriesOffset,
        List<Section> sections, long endOfImage, ushort characteristics)
    {
        Start = start;
        Machine = machine;
        Is64 = is64;
        OptionalHeaderOffset = optionalHeaderOffset;
        DataDirectoryCount = dataDirectoryCount;
        DataDirectoriesOffset = dataDirectoriesOffset;
        Sections = sections;
        EndOfImage = endOfImage;
        Characteristics = characteristics;
    }

    /// <summary>Offset of the "MZ" header within the parsed buffer.</summary>
    public int Start { get; }
    public ushort Machine { get; }
    public bool Is64 { get; }
    public ushort Characteristics { get; }
    public bool IsDll => (Characteristics & 0x2000) != 0;
    /// <summary>Relative to <see cref="Start"/>.</summary>
    public int OptionalHeaderOffset { get; }
    public int DataDirectoryCount { get; }
    public int DataDirectoriesOffset { get; }
    public IReadOnlyList<Section> Sections { get; }
    /// <summary>On-disk image length: end of the last section's raw data, overlay excluded.</summary>
    public long EndOfImage { get; }

    public string MachineName => Machine switch
    {
        0x14c => "x86",
        0x8664 => "x64",
        0xaa64 => "ARM64",
        0x1c4 => "ARM",
        _ => $"0x{Machine:X4}",
    };

    /// <summary>Parses the PE whose MZ header is at <paramref name="start"/>; null if not a plausible PE.</summary>
    public static PeImage? TryParse(ReadOnlySpan<byte> data, int start = 0)
    {
        if (start < 0 || data.Length - start < 0x40 || data[start] != 'M' || data[start + 1] != 'Z')
            return null;
        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(data[(start + 0x3C)..]);
        if (peOffset < 0x40 || peOffset > MaxHeaderOffset) return null;
        int pe = start + peOffset;
        if (data.Length - pe < 24 || BinaryPrimitives.ReadUInt32LittleEndian(data[pe..]) != 0x00004550) return null; // "PE\0\0"
        ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(data[(pe + 4)..]);
        int sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(data[(pe + 6)..]);
        int optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(data[(pe + 20)..]);
        ushort characteristics = BinaryPrimitives.ReadUInt16LittleEndian(data[(pe + 22)..]);
        if (sectionCount is 0 or > MaxSections || optionalSize < 0x60) return null;
        int opt = pe + 24;
        if (data.Length - opt < optionalSize) return null;
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(data[opt..]);
        bool is64 = magic == 0x20b;
        if (!is64 && magic != 0x10b) return null;
        int dirCountOffset = opt + (is64 ? 108 : 92);
        int dirsOffset = opt + (is64 ? 112 : 96);
        if (dirCountOffset + 4 > opt + optionalSize) return null;
        int dirCount = (int)Math.Min(16, BinaryPrimitives.ReadUInt32LittleEndian(data[dirCountOffset..]));
        if (dirsOffset + dirCount * 8 > opt + optionalSize) dirCount = Math.Max(0, (opt + optionalSize - dirsOffset) / 8);

        int sectionTable = opt + optionalSize;
        if (data.Length - sectionTable < sectionCount * 40) return null;
        var sections = new List<Section>(sectionCount);
        long end = 0;
        for (int i = 0; i < sectionCount; i++)
        {
            var s = data.Slice(sectionTable + i * 40, 40);
            var name = Encoding.ASCII.GetString(s[..8]).TrimEnd('\0');
            var section = new Section(name,
                BinaryPrimitives.ReadUInt32LittleEndian(s[12..]), BinaryPrimitives.ReadUInt32LittleEndian(s[8..]),
                BinaryPrimitives.ReadUInt32LittleEndian(s[20..]), BinaryPrimitives.ReadUInt32LittleEndian(s[16..]));
            sections.Add(section);
            if (section.RawSize > 0) end = Math.Max(end, (long)section.RawPointer + section.RawSize);
        }
        long headersEnd = sectionTable + sectionCount * 40 - start;
        end = Math.Max(end, headersEnd);
        return new PeImage(start, machine, is64, opt - start, dirCount, dirsOffset - start, sections, end, characteristics);
    }

    /// <summary>Data directory (RVA or, for the security directory, file offset) and size; (0, 0) when absent.</summary>
    public (uint Address, uint Size) Directory(ReadOnlySpan<byte> data, int index)
    {
        if (index >= DataDirectoryCount) return (0, 0);
        int at = Start + DataDirectoriesOffset + index * 8;
        if (at + 8 > data.Length) return (0, 0);
        return (BinaryPrimitives.ReadUInt32LittleEndian(data[at..]), BinaryPrimitives.ReadUInt32LittleEndian(data[(at + 4)..]));
    }

    /// <summary>File offset of the data directory entry itself.</summary>
    public int DirectoryEntryOffset(int index) => Start + DataDirectoriesOffset + index * 8;

    /// <summary>Windows subsystem: 2 = GUI, 3 = console (same offset in PE32 and PE32+).</summary>
    public ushort Subsystem(ReadOnlySpan<byte> data)
    {
        int at = Start + OptionalHeaderOffset + 68;
        return at + 2 <= data.Length ? BinaryPrimitives.ReadUInt16LittleEndian(data[at..]) : (ushort)0;
    }

    /// <summary>File offset of the optional header's CheckSum field.</summary>
    public int ChecksumOffset => Start + OptionalHeaderOffset + 64;

    /// <summary>Maps an RVA to a buffer offset; -1 if outside every section's raw data.</summary>
    public long RvaToOffset(uint rva)
    {
        foreach (var s in Sections)
        {
            uint size = Math.Max(s.VirtualSize, s.RawSize);
            if (rva >= s.VirtualAddress && rva < (long)s.VirtualAddress + size)
            {
                long delta = rva - s.VirtualAddress;
                return delta < s.RawSize ? Start + s.RawPointer + delta : -1;
            }
        }
        return -1;
    }

    public const int ComDescriptorDirectory = 14;
    public const int SecurityDirectory = 4;
    public const int ExportDirectory = 0;

    /// <summary>True when the image has a CLI (COR20) header.</summary>
    public bool IsDotNet(ReadOnlySpan<byte> data) => CorHeader(data) >= 0;

    private long CorHeader(ReadOnlySpan<byte> data)
    {
        var (rva, size) = Directory(data, ComDescriptorDirectory);
        if (rva == 0 || size < 72) return -1;
        long at = RvaToOffset(rva);
        return at >= 0 && at + 72 <= data.Length ? at : -1;
    }

    /// <summary>COR20 flags: ILONLY 0x1, 32BITREQUIRED 0x2, IL_LIBRARY 0x4, STRONGNAMESIGNED 0x8, 32BITPREFERRED 0x20000.</summary>
    public uint CorFlags(ReadOnlySpan<byte> data)
    {
        long at = CorHeader(data);
        return at < 0 ? 0 : BinaryPrimitives.ReadUInt32LittleEndian(data[(int)(at + 16)..]);
    }

    /// <summary>True when the COR20 ManagedNativeHeader points to an "RTR" header.</summary>
    public bool IsReadyToRun(ReadOnlySpan<byte> data)
    {
        long at = CorHeader(data);
        if (at < 0) return false;
        uint rva = BinaryPrimitives.ReadUInt32LittleEndian(data[(int)(at + 64)..]);
        if (rva == 0) return false;
        long header = RvaToOffset(rva);
        return header >= 0 && header + 4 <= data.Length && BinaryPrimitives.ReadUInt32LittleEndian(data[(int)header..]) == 0x00525452; // "RTR\0"
    }

    /// <summary>Exported names, up to <paramref name="max"/>.</summary>
    public List<string> Exports(ReadOnlySpan<byte> data, int max = 4096)
    {
        var result = new List<string>();
        var (rva, size) = Directory(data, ExportDirectory);
        if (rva == 0 || size < 40) return result;
        long dir = RvaToOffset(rva);
        if (dir < 0 || dir + 40 > data.Length) return result;
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(data[(int)(dir + 24)..]);
        long names = RvaToOffset(BinaryPrimitives.ReadUInt32LittleEndian(data[(int)(dir + 32)..]));
        if (names < 0) return result;
        for (uint i = 0; i < Math.Min(count, (uint)max); i++)
        {
            long entry = names + i * 4;
            if (entry + 4 > data.Length) break;
            long name = RvaToOffset(BinaryPrimitives.ReadUInt32LittleEndian(data[(int)entry..]));
            if (name < 0 || name >= data.Length) continue;
            int len = data[(int)name..].IndexOf((byte)0);
            if (len <= 0 || len > 512) continue;
            result.Add(Encoding.ASCII.GetString(data.Slice((int)name, len)));
        }
        return result;
    }

    /// <summary>NativeAOT: no CLI header, plus a ".managed" / ".hydrated" section or a DotNetRuntimeDebugHeader export.</summary>
    public bool IsNativeAot(ReadOnlySpan<byte> data) =>
        !IsDotNet(data) && (Sections.Any(s => s.Name is ".managed" or ".hydrated") || Exports(data).Contains("DotNetRuntimeDebugHeader"));
}
