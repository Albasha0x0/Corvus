using System.Buffers.Binary;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>An import address table slot and the export it points at as <c>module!name</c>; the name is null when no export starts at the pointer.</summary>
public sealed record ImportSlot(uint Rva, string? Name);

/// <summary>Consecutive slots that point into one module, with the count of slots among them that no export names.</summary>
public sealed record ImportRun(string Module, IReadOnlyList<ImportSlot> Slots, int Unnamed);

/// <summary>Slots found for a module: <paramref name="Source"/> is <c>directory</c> or <c>scan</c>.</summary>
public sealed record ImportScanResult(string Source, IReadOnlyList<ImportRun> Runs)
{
    /// <summary>All slots in image order.</summary>
    public IEnumerable<ImportSlot> Slots => Runs.SelectMany(r => r.Slots);

    /// <summary>Slots holding a pointer no export names; they stay in <see cref="Runs"/>.</summary>
    public int Unnamed => Runs.Sum(r => r.Unnamed);
}

/// <summary>Finds the import address table of a mapped image that has no readable import directory.</summary>
public static class ImportScan
{
    private const int DirectoryIndex = 12;
    private const uint CodeFlags = 0x20000020;
    private const int MinNamed = 2;

    /// <summary>
    /// Reads the slots of data directory 12 when it is set, else scans non-code sections for runs of pointers
    /// that <paramref name="exports"/> names. Null when the header is unreadable, the directory holds no slot, or no run of
    /// at least 2 named pointers ends in a zero entry; pages that were not captured end a run.
    /// A pointer into the image itself is never named and ends a scanned run.
    /// A nonzero <paramref name="importRva"/>, the import directory of the file, limits the scan to the section that holds it.
    /// </summary>
    public static ImportScanResult? Find(byte[] mapped, CapturedImage captured, ExportMap exports, uint importRva = 0)
    {
        if (!TryHeader(mapped, out bool is64, out int dirs, out int sections, out int count)) return null;
        int width = is64 ? 8 : 4;
        var own = OwnRange(mapped, captured, is64, dirs - (is64 ? 112 : 96));
        int dir = dirs + DirectoryIndex * 8;
        uint rva = dir + 8 <= mapped.Length ? BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan(dir)) : 0;
        uint size = dir + 8 <= mapped.Length ? BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan(dir + 4)) : 0;
        if (rva != 0 && size != 0)
        {
            long end = Math.Min((long)rva + size, mapped.Length);
            var (slots, _, _) = ReadRun(mapped, captured, exports, width, rva, end, own, false);
            return slots.Count == 0 ? null : new ImportScanResult("directory", Split(slots));
        }

        List<ImportRun> runs = [];
        for (int i = 0; i < count; i++)
        {
            int h = sections + 40 * i;
            if (h + 40 > mapped.Length) break;
            uint characteristics = BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan(h + 36));
            if ((characteristics & CodeFlags) != 0) continue;
            uint va = BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan(h + 12));
            uint length = BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan(h + 8));
            if (length == 0) length = BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan(h + 16));
            if (importRva != 0 && (importRva < va || importRva - va >= length)) continue;
            long end = Math.Min((long)va + length, mapped.Length);
            long at = (va + (long)width - 1) / width * width;
            while (at + width <= end)
            {
                if (Entry(mapped, captured, (int)at, width) == 0) { at += width; continue; }
                var (slots, next, terminated) = ReadRun(mapped, captured, exports, width, (uint)at, end, own, true);
                if (terminated) runs.AddRange(Split(slots).Where(r => r.Slots.Count - r.Unnamed >= MinNamed));
                at = next;
            }
        }
        return runs.Count == 0 ? null : new ImportScanResult("scan", runs);
    }

    // Reads nonzero entries up to a zero entry, the range end or an uncaptured
    // page. A pointer into the image is an unnamed slot, or ends the run.
    private static (List<ImportSlot> Slots, long Next, bool Terminated) ReadRun(byte[] mapped, CapturedImage captured, ExportMap exports, int width, uint start, long end, Func<ulong, bool> own, bool stopAtOwn)
    {
        List<ImportSlot> slots = [];
        long at = start;
        while (at + width <= end)
        {
            ulong value = Entry(mapped, captured, (int)at, width);
            if (value == 0) return (slots, at + width, true);
            if (own(value))
            {
                if (stopAtOwn) return (slots, at + width, true);
                slots.Add(new ImportSlot((uint)at, null));
                at += width;
                continue;
            }
            slots.Add(new ImportSlot((uint)at, exports.NameAt(value)));
            at += width;
        }
        return (slots, at, false);
    }

    // Splits at a change of module; an unnamed slot stays with the segment
    // before it.
    private static List<ImportRun> Split(List<ImportSlot> slots)
    {
        List<ImportRun> runs = [];
        List<ImportSlot> current = [];
        string? module = null;
        void Flush()
        {
            if (current.Count > 0) runs.Add(new ImportRun(module ?? "", current, current.Count(s => s.Name is null)));
            current = [];
        }
        foreach (var slot in slots)
        {
            string? name = slot.Name is null ? null : slot.Name[..slot.Name.IndexOf('!')];
            if (name != null && module != null && name != module) Flush();
            if (name != null) module = name;
            current.Add(slot);
        }
        Flush();
        return runs;
    }

    // The image as loaded and as the header records it; the base can differ
    // after a relocation.
    private static Func<ulong, bool> OwnRange(byte[] mapped, CapturedImage captured, bool is64, int opt)
    {
        if (opt + 64 > mapped.Length) return _ => false;
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan(opt + 56));
        ulong header = is64 ? BinaryPrimitives.ReadUInt64LittleEndian(mapped.AsSpan(opt + 24)) : BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan(opt + 28));
        ulong loaded = captured.Target.Base;
        ulong length = Math.Max(size, captured.Target.Size);
        return value => (value >= loaded && value - loaded < length) || (value >= header && value - header < length);
    }

    // An uncaptured page reads as zero, which ends the run.
    private static ulong Entry(byte[] mapped, CapturedImage captured, int at, int width)
    {
        if (!captured.PageCaptured((uint)at) || !captured.PageCaptured((uint)(at + width - 1))) return 0;
        return width == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(mapped.AsSpan(at)) : BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan(at));
    }

    private static bool TryHeader(byte[] mapped, out bool is64, out int dirs, out int sections, out int count)
    {
        is64 = false;
        dirs = sections = count = 0;
        if (mapped.Length < 0x40) return false;
        long nt = BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan(0x3C));
        long opt = nt + 24;
        if (opt + 2 > mapped.Length) return false;
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(mapped.AsSpan((int)opt));
        if (magic != 0x10B && magic != 0x20B) return false;
        is64 = magic == 0x20B;
        dirs = (int)opt + (is64 ? 112 : 96);
        count = BinaryPrimitives.ReadUInt16LittleEndian(mapped.AsSpan((int)nt + 6));
        sections = (int)opt + BinaryPrimitives.ReadUInt16LittleEndian(mapped.AsSpan((int)nt + 20));
        return true;
    }
}
