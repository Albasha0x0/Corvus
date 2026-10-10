namespace NetDecompilerMcp.Native.Elf;

public sealed partial class ElfFile
{
    /// <summary>A non-overlapping mapped range [Start, End) in RVAs, backed by FileSize bytes at FileOffset, zero-filled after.</summary>
    private readonly record struct Piece(long Start, long End, long FileOffset, long FileSize, int Segment);

    private Piece[] pieces = [];
    private long[] sectionStarts = [];

    private void BuildLayout()
    {
        var loads = segments.Where(s => s.IsLoad && s.MemorySize > 0).OrderBy(s => s.VirtualAddress).ToList();
        if (loads.Count == 0)
        {
            if (Type is not (1 or 4)) headerLog.Add("no PT_LOAD segments: nothing is mapped");
            return;
        }
        ImageBase = loads[0].VirtualAddress & ~(PageSize - 1);
        ulong end = ImageBase;
        foreach (var s in loads)
        {
            ulong segEnd = s.VirtualAddress + s.MemorySize;
            if (segEnd < s.VirtualAddress || segEnd - ImageBase > uint.MaxValue)
            {
                headerLog.Add($"PT_LOAD {s.Index} at 0x{s.VirtualAddress:X}+0x{s.MemorySize:X} lies 4 GB or more above the image base; not mapped");
                continue;
            }
            end = Math.Max(end, segEnd);
        }
        SizeOfImage = (uint)(end - ImageBase);
        IsMappedDump = DetectMappedDump(loads);
        if (IsMappedDump) headerLog.Add("the file is a memory image (segments at file offset = address - base); read as mapped");

        var list = new List<Piece>();
        foreach (var s in loads)
        {
            ulong segEnd = s.VirtualAddress + s.MemorySize;
            if (segEnd < s.VirtualAddress || segEnd - ImageBase > uint.MaxValue) continue;
            if (s.FileSize > s.MemorySize) headerLog.Add($"PT_LOAD {s.Index}: p_filesz 0x{s.FileSize:X} exceeds p_memsz 0x{s.MemorySize:X}; the memory size bounds it");
            long start = (long)(s.VirtualAddress - ImageBase);
            long stop = (long)(segEnd - ImageBase);
            long fileOffset, fileSize;
            if (IsMappedDump)
            {
                fileOffset = start;
                fileSize = Math.Clamp(data.Length - start, 0, stop - start);
            }
            else
            {
                fileOffset = (long)Math.Min(s.Offset, long.MaxValue / 2);
                fileSize = (long)Math.Min(s.FileSize, s.MemorySize);
                // The loader maps whole pages: bytes before the segment on its first page come from the file too.
                long lead = start - (start & ~(long)(PageSize - 1));
                if (lead > 0 && fileOffset >= lead)
                {
                    start -= lead;
                    fileOffset -= lead;
                    fileSize += lead;
                }
                if (fileSize > 0 && fileOffset + fileSize > data.Length)
                {
                    headerLog.Add($"PT_LOAD {s.Index}: file data 0x{s.Offset:X}+0x{s.FileSize:X} extends past the end of the file; the rest reads as zeros");
                    fileSize = Math.Clamp(data.Length - fileOffset, 0, fileSize);
                }
            }
            list.Add(new Piece(start, stop, fileOffset, fileSize, s.Index));
        }
        list.Sort((a, b) => a.Start.CompareTo(b.Start));
        var result = new List<Piece>(list.Count);
        long cursor = 0;
        foreach (var p in list)
        {
            if (p.Start < cursor) headerLog.Add($"PT_LOAD {p.Segment} overlaps a lower segment; the lower one owns the overlap");
            long start = Math.Max(p.Start, cursor);
            if (start < p.End)
            {
                long skip = start - p.Start;
                result.Add(new Piece(start, p.End, p.FileOffset + skip, Math.Max(0, p.FileSize - skip), p.Segment));
            }
            cursor = Math.Max(cursor, p.End);
        }
        pieces = [.. result];
    }

    /// <summary>
    /// A memory dump keeps the original program headers, but its bytes sit at address - base. Decided by where the
    /// dynamic table reads as valid: at its p_offset (a file) or at its address (a dump).
    /// </summary>
    private bool DetectMappedDump(List<ElfSegment> loads)
    {
        if (loads.All(s => s.Offset == s.VirtualAddress - ImageBase)) return false;
        if (segments.FirstOrDefault(s => s.Type == 2) is { } dyn)
            return !ValidDynamic((long)Math.Min(dyn.Offset, long.MaxValue / 2)) && ValidDynamic((long)(dyn.VirtualAddress - ImageBase));
        // No dynamic table: a dump is as long as the image, and the file offsets do not fit it.
        return data.Length >= SizeOfImage && loads.Any(s => s.Offset + s.FileSize > (ulong)data.Length);
    }

    private bool ValidDynamic(long at)
    {
        int entry = Is64Bit ? 16 : 8;
        bool tables = false;
        for (int i = 0; i < 512; i++, at += entry)
        {
            if (!view.Has(at, entry)) return false;
            long tag = Is64Bit ? (long)view.U64(at) : (int)view.U32(at);
            ulong value = view.Word(at + entry / 2, Is64Bit);
            if (tag == 0) return tables;
            if (tag is 5 or 6) // DT_STRTAB, DT_SYMTAB: addresses inside the image
            {
                if (value < ImageBase || value - ImageBase >= SizeOfImage) return false;
                tables = true;
            }
            else if (tag < 0 || (tag > 0x7FFFFFFF && tag < 0x60000000)) return false;
        }
        return false;
    }

    private void BuildSections()
    {
        if (pieces.Length == 0) return;
        if (sectionHeaders.Count > 1)
        {
            int outside = 0;
            foreach (var s in sectionHeaders)
            {
                if (!s.IsAllocated || s.Size == 0 || s.Index == 0) continue;
                if (s.Type == 8 && (s.Flags & 0x400) != 0) continue; // .tbss takes no address space
                if (s.Address < ImageBase || s.Address - ImageBase >= SizeOfImage || s.Size > SizeOfImage - (s.Address - ImageBase))
                {
                    outside++;
                    continue;
                }
                uint rva = (uint)(s.Address - ImageBase);
                var access = SectionAccess.Read;
                if (s.IsWritable) access |= SectionAccess.Write;
                if (s.IsExecutable) access |= SectionAccess.Execute | SectionAccess.Code;
                long offset = 0;
                bool fileBacked = s.HasFileData && TryRvaToFileOffset(rva, out offset);
                long raw = fileBacked ? this.FileBackedLength(rva, (long)s.Size) : 0;
                sections.Add(new NativeSection(s.Name, rva, (uint)s.Size, fileBacked ? (uint)Math.Min(offset, uint.MaxValue) : 0, (uint)raw, access, (uint)s.Flags));
            }
            if (outside > 0) headerLog.Add($"{outside} allocated sections lie outside the loaded segments; they are not listed");
            if (sections.Count == 0) headerLog.Add("no usable section headers; sections are synthesized from the segments");
        }
        if (sections.Count == 0)
            foreach (var p in pieces)
            {
                var seg = segments[p.Segment];
                var access = SectionAccess.None;
                if (seg.Readable) access |= SectionAccess.Read;
                if (seg.Writable) access |= SectionAccess.Write;
                if (seg.Executable) access |= SectionAccess.Execute | SectionAccess.Code;
                sections.Add(new NativeSection($"LOAD{seg.Index}", (uint)p.Start, (uint)(p.End - p.Start), (uint)Math.Min(p.FileOffset, uint.MaxValue), (uint)p.FileSize, access, seg.Flags));
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

    /// <summary>File bytes as mapped, without relocations applied.</summary>
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

    /// <summary>Mapped bytes with the dynamic relocations applied: rebased pointers hold their targets, bound import slots read 0.</summary>
    public int Read(uint rva, Span<byte> destination)
    {
        int n = ReadRaw(rva, destination);
        relocations.Value.Overlay.Apply(rva, destination[..n]);
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

    public NativeSection? SectionAt(uint rva)
    {
        int i = Array.BinarySearch(sectionStarts, (long)rva);
        if (i < 0) i = ~i - 1;
        else while (i + 1 < sectionStarts.Length && sectionStarts[i + 1] == rva) i++;
        // Sections may overlap (damaged headers): look back a few for one that still contains the address.
        for (int k = i; k >= 0 && k > i - 8; k--)
            if (sections[k].Contains(rva)) return sections[k];
        return null;
    }

    /// <summary>The file range behind [va, va + size): its offset and how many of the bytes the file holds contiguously.</summary>
    private bool TryFileRange(ulong va, ulong size, out long offset, out long available)
    {
        offset = -1;
        available = 0;
        if (!TryVaToRva(va, out uint rva)) return false;
        int index = Locate(rva);
        if (index < 0) return false;
        var p = pieces[index];
        long delta = rva - p.Start;
        if (delta >= p.FileSize) return false;
        offset = p.FileOffset + delta;
        available = Math.Min(p.FileSize - delta, (long)Math.Min(size, long.MaxValue));
        return true;
    }

    /// <summary>The file window starting at <paramref name="va"/>, up to <paramref name="max"/> bytes or the end of its segment's file data.</summary>
    private ByteView ViewAt(ulong va, ulong max) =>
        TryFileRange(va, max, out long offset, out long available) ? new ByteView(data, offset, available, BigEndian) : new ByteView([], BigEndian);

    /// <summary>The table at [va, va + size) as file bytes, logging when it is not fully in the file.</summary>
    private ByteView TableAt(ulong va, ulong size, string what, Pe.IssueLog log)
    {
        if (!TryFileRange(va, size, out long offset, out long available))
        {
            log.Add($"{what} at 0x{va:X} is not in the file");
            return new ByteView([], BigEndian);
        }
        if ((ulong)available < size) log.Add($"{what} at 0x{va:X}+0x{size:X} is only partly in the file (0x{available:X} bytes)");
        return new ByteView(data, offset, available, BigEndian);
    }
}
