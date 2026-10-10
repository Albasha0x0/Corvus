namespace NetDecompilerMcp.Native.MachO;

public sealed partial class MachOFile
{
    /// <summary>A non-overlapping mapped range [Start, End) in RVAs, backed by FileSize bytes at FileOffset, zero-filled after.</summary>
    private readonly record struct Piece(long Start, long End, long FileOffset, long FileSize, int Segment);

    private Piece[] pieces = [];
    private long[] sectionStarts = [];

    /// <summary>A segment that reserves address space without content (__PAGEZERO): not part of the image.</summary>
    private static bool IsReservation(MachOSegment s) => s.FileSize == 0 && s.InitProtection == 0 && s.MaxProtection == 0;

    private void BuildLayout()
    {
        var mapped = segments.Where(s => s.VmSize > 0 && !IsReservation(s)).ToList();
        if (mapped.Count == 0)
        {
            headerLog.Add("no mapped segments");
            return;
        }
        ImageBase = Segment("__TEXT") is { } text && !IsReservation(text) ? text.VmAddress : mapped.Min(s => s.VmAddress);
        ulong end = ImageBase;
        var list = new List<Piece>();
        foreach (var s in mapped)
        {
            ulong segEnd = s.VmAddress + s.VmSize;
            if (s.VmAddress < ImageBase || segEnd < s.VmAddress || segEnd - ImageBase > uint.MaxValue)
            {
                headerLog.Add($"segment {s.SegmentName} at 0x{s.VmAddress:X}+0x{s.VmSize:X} lies outside 4 GB above the image base; not mapped", s.Offset);
                continue;
            }
            end = Math.Max(end, segEnd);
            long fileOffset = (long)Math.Min(s.FileOffset, long.MaxValue / 2);
            long fileSize = (long)Math.Min(s.FileSize, s.VmSize);
            if (s.FileSize > s.VmSize) headerLog.Add($"segment {s.SegmentName}: filesize 0x{s.FileSize:X} exceeds vmsize 0x{s.VmSize:X}", s.Offset);
            if (fileSize > 0 && fileOffset + fileSize > data.Length)
            {
                headerLog.Add($"segment {s.SegmentName}: file data 0x{s.FileOffset:X}+0x{s.FileSize:X} extends past the end of the file; the rest reads as zeros", s.Offset);
                fileSize = Math.Clamp(data.Length - fileOffset, 0, fileSize);
            }
            list.Add(new Piece((long)(s.VmAddress - ImageBase), (long)(segEnd - ImageBase), fileOffset, fileSize, segments.IndexOf(s)));
        }
        SizeOfImage = (uint)(end - ImageBase);
        list.Sort((a, b) => a.Start.CompareTo(b.Start));
        var result = new List<Piece>(list.Count);
        long cursor = 0;
        foreach (var p in list)
        {
            if (p.Start < cursor) headerLog.Add($"segment {segments[p.Segment].SegmentName} overlaps a lower segment; the lower one owns the overlap");
            long start = Math.Max(p.Start, cursor);
            if (start < p.End)
            {
                long skip = start - p.Start;
                result.Add(new Piece(start, p.End, p.FileOffset + skip, Math.Max(0, p.FileSize - skip), p.Segment));
            }
            cursor = Math.Max(cursor, p.End);
        }
        pieces = [.. result];

        foreach (var p in pieces)
        {
            var seg = segments[p.Segment];
            var access = SectionAccess.None;
            if (seg.Readable) access |= SectionAccess.Read;
            if (seg.Writable) access |= SectionAccess.Write;
            if (seg.Sections.Count == 0)
            {
                if (seg.Executable) access |= SectionAccess.Execute | SectionAccess.Code;
                sections.Add(new NativeSection(seg.SegmentName, (uint)p.Start, (uint)(p.End - p.Start), (uint)Math.Min(p.FileOffset, uint.MaxValue), (uint)p.FileSize, access, seg.Flags));
                continue;
            }
            foreach (var s in seg.Sections)
            {
                if (s.Size == 0 || s.Address < seg.VmAddress || s.Address + s.Size > seg.VmAddress + seg.VmSize || s.Address + s.Size < s.Address)
                {
                    if (s.Size != 0) headerLog.Add($"section {s.FullName} at 0x{s.Address:X}+0x{s.Size:X} lies outside its segment; not listed", seg.Offset);
                    continue;
                }
                uint rva = (uint)(s.Address - ImageBase);
                // Code is what holds instructions: __TEXT also maps constants and strings.
                var sectionAccess = s.HasInstructions && seg.Executable ? access | SectionAccess.Execute | SectionAccess.Code : access;
                bool fileBacked = !s.IsZeroFill && TryRvaToFileOffset(rva, out _);
                sections.Add(new NativeSection(s.FullName, rva, (uint)s.Size, fileBacked ? s.Offset : 0, fileBacked ? (uint)this.FileBackedLength(rva, (long)s.Size) : 0, sectionAccess, s.Flags));
            }
        }
        sections.Sort((a, b) => a.Rva.CompareTo(b.Rva));
        sectionStarts = [.. sections.Select(s => (long)s.Rva)];
    }

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

    /// <summary>File bytes as mapped, without fixups applied.</summary>
    internal int ReadRaw(uint rva, Span<byte> destination)
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

    /// <summary>Mapped bytes with rebases applied (targets as addresses, PAC bits stripped) and bind slots read as 0.</summary>
    public int Read(uint rva, Span<byte> destination)
    {
        int n = ReadRaw(rva, destination);
        fixupArea.Value.Overlay.Apply(rva, destination[..n]);
        return n;
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

    /// <summary>File offset (within the slice) of a virtual address that has file data.</summary>
    public bool TryVmToFileOffset(ulong vm, out long fileOffset)
    {
        fileOffset = -1;
        return TryVaToRva(vm, out uint rva) && TryRvaToFileOffset(rva, out fileOffset);
    }

    public NativeSection? SectionAt(uint rva)
    {
        int i = Array.BinarySearch(sectionStarts, (long)rva);
        if (i < 0) i = ~i - 1;
        else while (i + 1 < sectionStarts.Length && sectionStarts[i + 1] == rva) i++;
        for (int k = i; k >= 0 && k > i - 8; k--)
            if (sections[k].Contains(rva)) return sections[k];
        return null;
    }

    /// <summary>The window of file bytes at [offset, offset + size), clipped to the file.</summary>
    private ByteView FileWindow(long offset, long size) => new(data, offset, size, BigEndian);
}
