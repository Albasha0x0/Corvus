using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core;

/// <summary>
/// Minimal, bounds-checked PE header parser. Never throws on malformed input. Accepts any in-file e_lfanew and any
/// section count whose table fits the data, as the Windows loader does.
/// </summary>
public sealed class PeImage
{
    public sealed record Section(string Name, uint VirtualAddress, uint VirtualSize, uint RawPointer, uint RawSize);

    /// <summary>How an RVA maps to the file.</summary>
    public enum RvaMapping { Mapped, Unmapped, VirtualOnly, Ambiguous }

    private PeImage(int start, ushort machine, bool is64, int optionalHeaderOffset, int dataDirectoryCount, int dataDirectoriesOffset,
        List<Section> sections, long endOfImage, ushort characteristics, uint sectionAlignment)
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
        SectionAlignment = sectionAlignment;
        Overlaps = FindOverlaps();
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
    public uint SectionAlignment { get; }
    /// <summary>Pairs of sections whose mapped ranges overlap; RVAs they share at different file offsets are ambiguous.</summary>
    public IReadOnlyList<string> Overlaps { get; }
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
        if (peOffset < 4 || peOffset > data.Length - start - 24) return null;
        int pe = start + peOffset;
        if (data.Length - pe < 24 || BinaryPrimitives.ReadUInt32LittleEndian(data[pe..]) != 0x00004550) return null; // "PE\0\0"
        ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(data[(pe + 4)..]);
        int sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(data[(pe + 6)..]);
        int optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(data[(pe + 20)..]);
        ushort characteristics = BinaryPrimitives.ReadUInt16LittleEndian(data[(pe + 22)..]);
        if (sectionCount == 0 || optionalSize < 0x60) return null;
        int opt = pe + 24;
        if (data.Length - opt < optionalSize) return null;
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(data[opt..]);
        bool is64 = magic == 0x20b;
        if (!is64 && magic != 0x10b) return null;
        uint sectionAlignment = BinaryPrimitives.ReadUInt32LittleEndian(data[(opt + 32)..]);
        int dirCountOffset = opt + (is64 ? 108 : 92);
        int dirsOffset = opt + (is64 ? 112 : 96);
        if (dirCountOffset + 4 > opt + optionalSize) return null;
        int dirCount = (int)Math.Min(16, BinaryPrimitives.ReadUInt32LittleEndian(data[dirCountOffset..]));
        if (dirsOffset + dirCount * 8 > opt + optionalSize) dirCount = Math.Max(0, (opt + optionalSize - dirsOffset) / 8);

        int sectionTable = opt + optionalSize;
        if (data.Length - sectionTable < sectionCount * 40L) return null;
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
        return new PeImage(start, machine, is64, opt - start, dirCount, dirsOffset - start, sections, end, characteristics, sectionAlignment);
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

    /// <summary>Maps an RVA to a buffer offset; -1 when unmapped, virtual-only (zero-filled) or ambiguous.</summary>
    public long RvaToOffset(uint rva) => MapRva(rva) is (var at, RvaMapping.Mapped) ? at : -1;

    /// <summary>
    /// Maps an RVA through the section table. Each section spans its virtual size (raw size when 0) rounded up to the
    /// section alignment, file-backed for its raw size. An RVA in two sections that back it with different file bytes is
    /// <see cref="RvaMapping.Ambiguous"/>, never resolved by section order.
    /// </summary>
    public (long Offset, RvaMapping Status) MapRva(uint rva)
    {
        long found = -1;
        var status = RvaMapping.Unmapped;
        foreach (var s in Sections)
        {
            var (begin, end) = Extent(s);
            if (rva < begin || rva >= end) continue;
            long delta = rva - s.VirtualAddress;
            long at = delta < s.RawSize ? Start + s.RawPointer + delta : -1;
            if (status == RvaMapping.Unmapped)
            {
                (found, status) = (at, at >= 0 ? RvaMapping.Mapped : RvaMapping.VirtualOnly);
                continue;
            }
            if (at != found) return (-1, RvaMapping.Ambiguous);
        }
        return (found, status);
    }

    private (long Begin, long End) Extent(Section s)
    {
        long size = s.VirtualSize != 0 ? s.VirtualSize : s.RawSize;
        uint a = SectionAlignment;
        size = a != 0 && (a & (a - 1)) == 0 ? (size + a - 1) & ~(long)(a - 1) : Math.Max(s.VirtualSize, s.RawSize);
        return (s.VirtualAddress, s.VirtualAddress + size);
    }

    private List<string> FindOverlaps()
    {
        var result = new List<string>();
        var ordered = Sections.Select((s, i) => (s, i, Extent: Extent(s))).Where(x => x.Extent.End > x.Extent.Begin)
            .OrderBy(x => x.Extent.Begin).ToList();
        for (int i = 0; i < ordered.Count && result.Count < 16; i++)
            for (int j = i + 1; j < ordered.Count && ordered[j].Extent.Begin < ordered[i].Extent.End && result.Count < 16; j++)
            {
                var (a, b) = (ordered[i], ordered[j]);
                long end = Math.Min(a.Extent.End, b.Extent.End);
                result.Add($"sections #{a.i} '{a.s.Name}' and #{b.i} '{b.s.Name}' overlap at RVA 0x{b.Extent.Begin:X}-0x{end:X}");
            }
        return result;
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

    /// <summary>
    /// NativeAOT: no CLI header, plus a ".managed" / "hydrated" section (.NET 7–8), a DotNetRuntimeDebugHeader export or a
    /// NativeAOT module header in the section data (.NET 9+ merge their sections into .text / .data, DLLs may not export the debug header).
    /// </summary>
    public bool IsNativeAot(ReadOnlySpan<byte> data) =>
        !IsDotNet(data) && (Sections.Any(s => s.Name is ".managed" or "hydrated" or ".hydrated") || Exports(data).Contains("DotNetRuntimeDebugHeader")
                            || HasNativeAotHeader(data));

    /// <summary>"RTR\0" at a 4-byte aligned RVA with the NativeAOT header shape: row size 2 pointers + 8, row type 1, 1–127 rows, ids 100–1000.</summary>
    private bool HasNativeAotHeader(ReadOnlySpan<byte> data)
    {
        int rowSize = Is64 ? 24 : 16;
        foreach (var s in Sections)
        {
            if (s.RawSize == 0 || s.RawPointer >= data.Length) continue;
            long start = Start + (long)s.RawPointer;
            var raw = data.Slice((int)start, (int)Math.Min(s.RawSize, data.Length - start));
            for (int at = 0; ;)
            {
                int hit = raw[at..].IndexOf("RTR\0"u8);
                if (hit < 0) break;
                at += hit;
                if ((s.VirtualAddress + at) % 4 == 0 && raw.Length - at >= 16 + rowSize)
                {
                    var h = raw[at..];
                    int rows = BinaryPrimitives.ReadUInt16LittleEndian(h[12..]);
                    if (h[14] == rowSize && h[15] == 1 && rows is > 0 and < 128 && raw.Length - at >= 16 + rows * rowSize)
                    {
                        bool ids = true;
                        for (int i = 0; i < rows && ids; i++)
                            ids = BinaryPrimitives.ReadInt32LittleEndian(h[(16 + i * rowSize)..]) is >= 100 and <= 1000;
                        if (ids) return true;
                    }
                }
                at += 4;
            }
        }
        return false;
    }
}
