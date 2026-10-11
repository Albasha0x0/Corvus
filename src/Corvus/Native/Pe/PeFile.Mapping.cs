using System.Buffers.Binary;
using System.Text;

namespace Corvus.Native.Pe;

public sealed partial class PeFile
{
    /// <summary>
    /// A non-overlapping range of the mapped image: [Start, End) in RVAs, backed by FileSize bytes at FileOffset and
    /// zero-filled after them. Section is the section table index, -1 for the headers.
    /// </summary>
    private readonly record struct Piece(long Start, long End, long FileOffset, long FileSize, int Section);

    private Piece[] pieces = [];

    /// <summary>
    /// Lays the sections out as the Windows loader maps them: the raw pointer rounded down to 0x200 when the file
    /// alignment is at least 0x200, the raw size rounded up to the file alignment and capped at the virtual extent, a
    /// virtual size of 0 replaced by the raw size, and images with a section alignment below the page size mapped flat
    /// (RVA = file offset), except ReadyToRun images built for another OS, which the runtime maps through the section
    /// table whatever the alignment (crossgen gives them a 0x200 section alignment with RVAs apart from the file
    /// offsets). Where sections overlap, the one starting lower owns the overlap. Raw data past the end of
    /// the file reads as zeros.
    /// </summary>
    private void BuildLayout()
    {
        uint sa = Optional.SectionAlignment, fa = Optional.FileAlignment;
        if (!IsPowerOfTwo(sa))
        {
            headerLog.Add($"SectionAlignment 0x{sa:X} is not a power of two; 0x{PageSize:X} used", OptionalHeaderOffset + 32);
            sa = PageSize;
        }
        if (!IsPowerOfTwo(fa))
        {
            headerLog.Add($"FileAlignment 0x{fa:X} is not a power of two; raw sizes used unaligned", OptionalHeaderOffset + 36);
            fa = 1;
        }
        bool flat = sa < PageSize && PeNames.NonWindowsReadyToRunOs(Coff.Machine) == null;
        if (flat && fa != sa)
            headerLog.Add($"SectionAlignment 0x{sa:X} is below the page size, which requires FileAlignment to equal it (0x{fa:X})", OptionalHeaderOffset + 32);

        var list = new List<Piece>(sections.Count + 1);
        for (int i = 0; i < sections.Count; i++)
        {
            var s = sections[i];
            long virtualSize = s.VirtualSize != 0 ? s.VirtualSize : s.RawSize;
            long mapped = Math.Min(AlignUp(virtualSize, sa), uint.MaxValue);
            long rawOffset, rawSize;
            if (flat)
            {
                rawOffset = s.Rva;
                rawSize = mapped;
                if (s.RawOffset != s.Rva && s.RawSize != 0)
                    headerLog.Add($"section {Quote(s.Name)}: raw pointer 0x{s.RawOffset:X} differs from its RVA in a flat-mapped image", SectionHeaderOffset(i));
            }
            else
            {
                rawOffset = fa >= 0x200 ? s.RawOffset & ~0x1FFu : s.RawOffset;
                rawSize = Math.Min(AlignUp(s.RawSize, fa), mapped);
                if (s.RawSize != 0 && s.RawOffset + Math.Min((long)s.RawSize, mapped) > data.Length)
                    headerLog.Add($"section {Quote(s.Name)}: raw data 0x{s.RawOffset:X}+0x{s.RawSize:X} extends past the end of the file (0x{data.Length:X}); the rest reads as zeros", SectionHeaderOffset(i));
            }
            long available = Math.Clamp(data.Length - rawOffset, 0, rawSize);
            if (mapped != 0 && s.Rva + mapped > Optional.SizeOfImage)
                headerLog.Add($"section {Quote(s.Name)} [0x{s.Rva:X}, 0x{s.Rva + mapped:X}) extends past SizeOfImage 0x{Optional.SizeOfImage:X}", SectionHeaderOffset(i));
            layouts.Add(new PeSectionLayout(s, (uint)mapped, rawOffset, (uint)available, PeNames.SectionCharacteristics(s.Characteristics)));
            if (mapped != 0) list.Add(new Piece(s.Rva, s.Rva + mapped, rawOffset, available, i));
        }

        for (int i = 1; i < sections.Count; i++)
            if (sections[i].Rva < sections[i - 1].Rva)
            {
                headerLog.Add("section headers are not in ascending RVA order", SectionHeaderOffset(i));
                break;
            }

        list.Sort((a, b) => a.Start != b.Start ? a.Start.CompareTo(b.Start) : a.Section.CompareTo(b.Section));
        var result = new List<Piece>(list.Count + 1);
        long cursor = 0;
        int last = -1;
        foreach (var p in list)
        {
            if (p.Start < cursor)
                headerLog.Add($"section {Quote(sections[p.Section].Name)} overlaps section {Quote(sections[last].Name)}; the lower one owns the overlap", SectionHeaderOffset(p.Section));
            long start = Math.Max(p.Start, cursor);
            if (start < p.End)
            {
                long skip = start - p.Start;
                result.Add(new Piece(start, p.End, p.FileOffset + skip, Math.Max(0, p.FileSize - skip), p.Section));
            }
            if (p.End > cursor)
            {
                cursor = p.End;
                last = p.Section;
            }
        }

        // Headers: SizeOfHeaders bytes from offset 0, never less than the section table.
        long headerSize = Optional.SizeOfHeaders;
        long tableEnd = SectionTableOffset + sections.Count * 40L;
        if (headerSize < tableEnd)
        {
            headerLog.Add($"SizeOfHeaders 0x{headerSize:X} ends before the section table (0x{tableEnd:X})", OptionalHeaderOffset + 60);
            headerSize = tableEnd;
        }
        long headerEnd = flat ? (result.Count > 0 ? result[0].Start : Math.Max(Optional.SizeOfImage, headerSize)) : AlignUp(headerSize, sa);
        if (result.Count > 0) headerEnd = Math.Min(headerEnd, result[0].Start);
        if (headerEnd > 0)
            result.Insert(0, new Piece(0, headerEnd, 0, Math.Min(Math.Min(headerSize, headerEnd), data.Length), -1));
        pieces = [.. result];
    }

    private long SectionHeaderOffset(int index) => SectionTableOffset + index * 40L;

    private static bool IsPowerOfTwo(uint v) => v != 0 && (v & (v - 1)) == 0;

    private static long AlignUp(long value, uint alignment) => (value + alignment - 1) & ~(long)(alignment - 1);

    private static string Quote(string name) => $"'{name}'";

    /// <summary>Index of the piece containing <paramref name="rva"/>, or -1.</summary>
    private int Locate(long rva)
    {
        int lo = 0, hi = pieces.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (pieces[mid].End <= rva) lo = mid + 1;
            else if (pieces[mid].Start > rva) hi = mid - 1;
            else return mid;
        }
        return -1;
    }

    public int Read(uint rva, Span<byte> destination)
    {
        int copied = 0;
        long at = rva;
        while (copied < destination.Length)
        {
            int index = Locate(at);
            if (index < 0) break;
            var p = pieces[index];
            int n = (int)Math.Min(p.End - at, destination.Length - copied);
            long delta = at - p.Start;
            int fromFile = (int)Math.Clamp(p.FileSize - delta, 0, n);
            if (fromFile > 0) data.AsSpan((int)(p.FileOffset + delta), fromFile).CopyTo(destination.Slice(copied));
            destination.Slice(copied + fromFile, n - fromFile).Clear();
            copied += n;
            at += n;
        }
        return copied;
    }

    public bool TryRvaToFileOffset(uint rva, out long fileOffset)
    {
        fileOffset = -1;
        int index = Locate(rva);
        if (index < 0) return false;
        var p = pieces[index];
        long delta = rva - p.Start;
        if (delta >= p.FileSize) return false;
        fileOffset = p.FileOffset + delta;
        return true;
    }

    public bool TryFileOffsetToRva(long fileOffset, out uint rva)
    {
        rva = 0;
        foreach (var p in pieces)
            if (fileOffset >= p.FileOffset && fileOffset - p.FileOffset < p.FileSize)
            {
                rva = (uint)(p.Start + fileOffset - p.FileOffset);
                return true;
            }
        return false;
    }

    /// <summary>Section whose mapped extent (rounded up to the section alignment) contains <paramref name="rva"/>.</summary>
    public NativeSection? SectionAt(uint rva)
    {
        int index = Locate(rva);
        return index >= 0 && pieces[index].Section >= 0 ? sections[pieces[index].Section] : null;
    }

    /// <summary>Whether [rva, rva + size) lies entirely inside the mapped image.</summary>
    public bool IsMapped(uint rva, uint size)
    {
        long at = rva, end = (long)rva + size;
        while (at < end)
        {
            int index = Locate(at);
            if (index < 0) return false;
            at = pieces[index].End;
        }
        return true;
    }

    /// <summary>File bytes behind [rva, rva + length) when they are contiguous in the file; empty otherwise.</summary>
    private ReadOnlySpan<byte> FileSpan(long rva, int length)
    {
        int index = Locate(rva);
        if (index < 0) return default;
        var p = pieces[index];
        long delta = rva - p.Start;
        return delta + length <= p.FileSize && rva + length <= p.End ? data.AsSpan((int)(p.FileOffset + delta), length) : default;
    }

    private bool TryU16(long rva, out ushort value)
    {
        var span = FileSpan(rva, 2);
        if (span.Length == 2) { value = BinaryPrimitives.ReadUInt16LittleEndian(span); return true; }
        Span<byte> buffer = stackalloc byte[2];
        bool ok = rva is >= 0 and <= uint.MaxValue && Read((uint)rva, buffer) == 2;
        value = ok ? BinaryPrimitives.ReadUInt16LittleEndian(buffer) : (ushort)0;
        return ok;
    }

    private bool TryU32(long rva, out uint value)
    {
        var span = FileSpan(rva, 4);
        if (span.Length == 4) { value = BinaryPrimitives.ReadUInt32LittleEndian(span); return true; }
        Span<byte> buffer = stackalloc byte[4];
        bool ok = rva is >= 0 and <= uint.MaxValue && Read((uint)rva, buffer) == 4;
        value = ok ? BinaryPrimitives.ReadUInt32LittleEndian(buffer) : 0;
        return ok;
    }

    private bool TryU64(long rva, out ulong value)
    {
        var span = FileSpan(rva, 8);
        if (span.Length == 8) { value = BinaryPrimitives.ReadUInt64LittleEndian(span); return true; }
        Span<byte> buffer = stackalloc byte[8];
        bool ok = rva is >= 0 and <= uint.MaxValue && Read((uint)rva, buffer) == 8;
        value = ok ? BinaryPrimitives.ReadUInt64LittleEndian(buffer) : 0;
        return ok;
    }

    /// <summary>Pointer-sized value: 8 bytes in PE32+, 4 in PE32.</summary>
    private bool TryPointer(long rva, out ulong value)
    {
        if (Is64Bit) return TryU64(rva, out value);
        bool ok = TryU32(rva, out uint v);
        value = v;
        return ok;
    }

    private int PointerSize => Is64Bit ? 8 : 4;

    /// <summary>How many <paramref name="size"/>-byte entries fit between <paramref name="rva"/> and the end of the mapped image.</summary>
    private uint FitCount(long rva, int size)
    {
        long end = pieces.Length > 0 ? pieces[^1].End : 0;
        return (uint)Math.Clamp((end - rva) / size, 0, uint.MaxValue);
    }

    /// <summary>Mapped bytes of [rva, rva + length), or null when any of it is unmapped.</summary>
    private byte[]? ReadBlock(long rva, int length)
    {
        if (length < 0 || rva < 0 || rva > uint.MaxValue || FitCount(rva, 1) < (uint)length) return null; // no allocation for what cannot be mapped
        var buffer = new byte[length];
        return Read((uint)rva, buffer) == length ? buffer : null;
    }

    /// <summary>
    /// Zero-terminated 8-bit string at <paramref name="rva"/> decoded as UTF-8; null when unmapped. A string that runs
    /// into an unmapped gap or past <paramref name="max"/> bytes is cut there and <paramref name="truncated"/> is set.
    /// </summary>
    private string? ReadCString(long rva, int max, out bool truncated)
    {
        truncated = false;
        if (rva < 0 || rva > uint.MaxValue) return null;
        int index = Locate(rva);
        if (index < 0) return null;
        var p = pieces[index];
        long delta = rva - p.Start;
        if (delta >= p.FileSize) return ""; // zero fill
        var span = data.AsSpan((int)(p.FileOffset + delta), (int)Math.Min(p.FileSize - delta, max + 1L));
        int len = span.IndexOf((byte)0);
        if (len >= 0) return Encoding.UTF8.GetString(span[..len]);
        if (span.Length > max)
        {
            truncated = true;
            return Encoding.UTF8.GetString(span[..max]);
        }
        if (p.End > p.Start + p.FileSize) return Encoding.UTF8.GetString(span); // ends at the zero fill

        // Continues into the next piece.
        var bytes = new List<byte>(span.ToArray());
        long at = p.End;
        Span<byte> one = stackalloc byte[1];
        while (bytes.Count <= max)
        {
            if (at > uint.MaxValue || Read((uint)at, one) != 1) { truncated = true; break; }
            if (one[0] == 0) break;
            bytes.Add(one[0]);
            at++;
        }
        if (bytes.Count > max)
        {
            truncated = true;
            bytes.RemoveRange(max, bytes.Count - max);
        }
        return Encoding.UTF8.GetString(bytes.ToArray());
    }

    /// <summary>
    /// <see cref="ReadCString"/> charged to <paramref name="budget"/>, with a truncation issue; null when unmapped or
    /// the budget is spent.
    /// </summary>
    private string? ReadName(long rva, WorkBudget budget, IssueLog log, string what)
    {
        var s = ReadCString(rva, PeLimits.MaxNameLength, out bool truncated);
        if (s == null) return null;
        if (truncated) log.Add($"{what} at RVA 0x{rva:X} is unterminated or longer than {PeLimits.MaxNameLength} bytes; cut", RvaToOffsetOrNull(rva));
        return budget.Chars(s.Length) ? s : null;
    }

    private long? RvaToOffsetOrNull(long rva) => rva is >= 0 and <= uint.MaxValue && TryRvaToFileOffset((uint)rva, out long o) ? o : null;
}
