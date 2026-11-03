using System.Buffers.Binary;
using System.Text;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Restores the import address table of a mapped image.</summary>
public static class PeImportRestore
{
    private const int DescriptorSize = 20;
    private const int MaxSlots = 64 * 1024;
    private const long MaxNameBytes = 16L << 20;

    private readonly record struct Slot(uint Rva, ulong Entry, bool Restored);

    private sealed record Descriptor(int At, List<Slot> Slots);

    /// <summary>
    /// Writes each import lookup table entry back over its address table slot in <paramref name="image"/>.
    /// Null, with a skipped check, when the image has no import directory or <paramref name="mode"/> keeps addresses.
    /// Slots named from exports stay in the result only; the image keeps its size.
    /// </summary>
    public static ImportSummary? Restore(byte[] image, CapturedImage captured, IProcessMemory memory, ImportMode mode, List<RebuildCheck> checks, CancellationToken ct) =>
        Run(ref image, ref captured, memory, mode, false, checks, ct);

    /// <summary>
    /// As the overload without ref, and the slots named from exports are written into a new <c>.idata2</c> section;
    /// <paramref name="image"/> and <paramref name="captured"/> are then replaced by larger copies.
    /// Without room in the section table, or past 64 K slots or 16 MB of names, the names stay in the result and the check is partial.
    /// An image with no readable import directory gets one in <c>.idata2</c> from the slots <see cref="ImportScan"/> finds,
    /// unless <paramref name="file"/>, the file of the same build, has no import directory either: the check is then skipped.
    /// A null <paramref name="file"/> means the file is unknown.
    /// </summary>
    public static ImportSummary? Restore(ref byte[] image, ref CapturedImage captured, IProcessMemory memory, ImportMode mode, List<RebuildCheck> checks, CancellationToken ct, byte[]? file = null)
    {
        // Tables are read first: restoring the directory overwrites their slots.
        var tables = mode == ImportMode.Restore && memory != null ? LateBound(image, captured, memory, file) : [];
        var summary = Run(ref image, ref captured, memory!, mode, true, checks, ct, file);
        return tables.Count == 0 ? summary : AddLateBound(ref image, ref captured, tables, summary, checks);
    }

    // Tables of two or more export addresses in data the file holds as zeros; none when the image cannot be parsed.
    private static IReadOnlyList<LateBoundRun> LateBound(byte[] image, CapturedImage captured, IProcessMemory memory, byte[]? file)
    {
        try
        {
            var pe = PeFile.FromBytes(file ?? image);
            return [.. LateBoundPointers.Find(image, captured, pe, memory, new ExportMap(memory)).Where(r => r.IsTable)];
        }
        catch (Exception e) when (e is InvalidDataException or ArgumentException or IOException or IndexOutOfRangeException)
        {
            return [];
        }
    }

    // Adds a descriptor for each table the directory does not cover, after the descriptors it keeps.
    private static ImportSummary? AddLateBound(ref byte[] image, ref CapturedImage captured, IReadOnlyList<LateBoundRun> tables, ImportSummary? summary, List<RebuildCheck> checks)
    {
        if (!TryDirectory(image, out bool is64, out uint dirRva, out uint dirSize)) return summary;
        int width = is64 ? 8 : 4;
        List<byte> kept = [];
        HashSet<uint> covered = [];
        if (dirRva != 0 && dirSize != 0)
        {
            for (long at = dirRva; at + DescriptorSize <= image.Length && at + DescriptorSize <= (long)dirRva + dirSize; at += DescriptorSize)
            {
                var d = image.AsSpan((int)at, DescriptorSize);
                if (!d.ContainsAnyExcept((byte)0)) break;
                kept.AddRange(d.ToArray());
                uint first = BinaryPrimitives.ReadUInt32LittleEndian(d[16..]);
                for (long slot = first; first != 0 && slot + width <= image.Length && covered.Count < MaxSlots && Read(image, (int)slot, width) != 0; slot += width)
                    covered.Add((uint)slot);
            }
        }

        List<(string Module, List<ImportSlot> Slots)> chunks = [];
        int slots = 0, count = 0;
        foreach (var run in tables.Where(t => !t.SlotRvas.Any(covered.Contains)))
        {
            count++;
            slots += run.SlotRvas.Count;
            string? module = null;
            for (int i = 0; i < run.SlotRvas.Count; i++)
            {
                string name = run.Names[i];
                string owner = name.Contains('!') ? name[..name.LastIndexOf('!')] : name;
                if (owner != module) chunks.Add((module = owner, []));
                chunks[^1].Slots.Add(new ImportSlot(run.SlotRvas[i], name));
            }
        }
        if (count == 0) return summary;

        var (added, note) = WriteDirectory(ref image, ref captured, chunks, is64, kept.ToArray());
        string tail = added
            ? $"{slots} late-bound slots in {count} tables added from memory"
            : $"{slots} late-bound slots in {count} tables not added" + (note is null ? "" : $": {note}");
        int index = checks.FindLastIndex(c => c.Name == "imports");
        if (index >= 0)
        {
            var check = checks[index];
            string state = check.State == "skipped" ? "partial" : check.State;
            checks[index] = new RebuildCheck("imports", state, $"{check.Detail}; {tail}");
        }
        else checks.Add(RebuildCheck.Partial("imports", tail));
        if (!added) return summary;

        var names = chunks.SelectMany(c => c.Slots).Select(s => new ResolvedImport($"0x{s.Rva:X}", s.Name!)).ToList();
        if (summary is null)
            return new ImportSummary(chunks.Select(c => c.Module).Distinct().Count(), 0, names.Count, 0, true) { Names = names };
        return summary with
        {
            Modules = summary.Modules + chunks.Select(c => c.Module).Distinct().Count(),
            Resolved = summary.Resolved + names.Count,
            DirectoryRebuilt = true,
            Names = [.. summary.Names, .. names],
        };
    }

    private static ImportSummary? Run(ref byte[] image, ref CapturedImage captured, IProcessMemory memory, ImportMode mode, bool grow, List<RebuildCheck> checks, CancellationToken ct, byte[]? file = null)
    {
        if (mode == ImportMode.Keep)
        {
            checks.Add(RebuildCheck.Skipped("imports", "kept as loaded"));
            return null;
        }
        if (!TryDirectory(image, out bool is64, out uint dirRva, out uint dirSize) || dirRva == 0 || dirSize == 0 || dirRva >= image.Length)
        {
            if (grow && memory != null && TryDirectory(image, out is64, out _, out _))
            {
                // Only what the file had is rebuilt.
                uint fileDirectory = 0;
                if (file != null && (!TryDirectory(file, out _, out fileDirectory, out uint fileSize) || fileDirectory == 0 || fileSize == 0))
                {
                    checks.Add(RebuildCheck.Skipped("imports", "the file has no import directory"));
                    return null;
                }
                return Rebuild(ref image, ref captured, memory, is64, fileDirectory, checks);
            }
            checks.Add(RebuildCheck.Skipped("imports", "no import directory"));
            return null;
        }

        int width = is64 ? 8 : 4;
        int modules = 0, restored = 0, unresolved = 0;
        List<(uint Rva, ulong Value)> pending = [];
        List<Descriptor> descriptors = [];
        string? stopped = null;
        long count = dirSize / DescriptorSize;
        for (long i = 0; i < count; i++)
        {
            ct.ThrowIfCancellationRequested();
            long at = dirRva + i * DescriptorSize;
            if (at + DescriptorSize > image.Length)
            {
                stopped = "import directory runs past the image";
                break;
            }
            var d = image.AsSpan((int)at, DescriptorSize);
            uint lookup = BinaryPrimitives.ReadUInt32LittleEndian(d), first = BinaryPrimitives.ReadUInt32LittleEndian(d[16..]);
            if (lookup == 0 && first == 0 && BinaryPrimitives.ReadUInt32LittleEndian(d[12..]) == 0) break;
            modules++;
            if (first == 0 || first >= image.Length) continue;

            var descriptor = new Descriptor((int)at, []);
            descriptors.Add(descriptor);
            bool tableUsable = lookup != 0 && lookup < image.Length;
            for (long slot = 0; ; slot++)
            {
                long slotAt = first + slot * width;
                if (slotAt + width > image.Length) break;
                long lookupAt = tableUsable ? lookup + slot * width : -1;
                bool lookupRead = lookupAt >= 0 && lookupAt + width <= image.Length && captured.PageCaptured((uint)lookupAt);
                ulong entry = lookupRead ? Read(image, (int)lookupAt, width) : 0;
                // Without a readable lookup table the loaded slot itself bounds the table.
                bool end = lookupRead ? entry == 0 : Read(image, (int)slotAt, width) == 0;
                if (end) break;
                if (lookupRead && captured.PageCaptured((uint)slotAt) && captured.PageCaptured((uint)(slotAt + width - 1)))
                {
                    Write(image, (int)slotAt, width, entry);
                    descriptor.Slots.Add(new Slot((uint)slotAt, entry, true));
                    restored++;
                }
                else
                {
                    unresolved++;
                    ulong value = Read(image, (int)slotAt, width);
                    pending.Add(((uint)slotAt, value));
                    descriptor.Slots.Add(new Slot((uint)slotAt, value, false));
                }
            }
        }

        var names = Name(pending, memory);
        unresolved -= names.Count;
        bool rebuilt = false;
        string? note = null;
        if (grow && names.Count > 0)
            (rebuilt, note) = AddSection(ref image, ref captured, descriptors, names, is64);
        var summary = new ImportSummary(modules, restored, names.Count, unresolved, rebuilt)
        {
            // Records compare lists by reference, so no names keeps the shared empty default.
            Names = names.Count == 0 ? [] : [.. names.Select(n => new ResolvedImport($"0x{n.Rva:X}", n.Name))],
        };
        string extra = (stopped == null ? "" : $"; {stopped}") + (note == null ? "" : $"; {note}");
        if (stopped == null && unresolved == 0 && names.Count == 0)
            checks.Add(RebuildCheck.Ok("imports", $"{restored} slots restored from {modules} modules"));
        else
            checks.Add(RebuildCheck.Partial("imports", $"{restored} slots restored, {names.Count} named from exports, {unresolved} unresolved in {modules} modules" + extra));
        return summary;
    }

    private static ImportSummary? Rebuild(ref byte[] image, ref CapturedImage captured, IProcessMemory memory, bool is64, uint fileDirectory, List<RebuildCheck> checks)
    {
        var found = ImportScan.Find(image, captured, new ExportMap(memory), fileDirectory);
        if (found == null)
        {
            checks.Add(RebuildCheck.Skipped("imports", "no import directory and no import address table found"));
            return null;
        }

        int total = found.Slots.Count(), unnamed = found.Unnamed;
        var (added, note) = AddDirectory(ref image, ref captured, found, is64);
        var named = found.Slots.Where(s => s.Name is not null).ToList();
        var summary = new ImportSummary(found.Runs.Select(r => r.Module).Distinct().Count(), 0, named.Count, unnamed, added)
        {
            Names = named.Count == 0 ? [] : [.. named.Select(s => new ResolvedImport($"0x{s.Rva:X}", s.Name!))],
        };
        string left = unnamed == 0 ? "" : $"; {unnamed} unnamed";
        if (added)
            checks.Add(RebuildCheck.Partial("imports", $"import directory rebuilt from {total} address table slots{left}"));
        else
            checks.Add(RebuildCheck.Partial("imports", $"{total} slots found, directory not rebuilt{left}" + (note is null ? "" : $"; {note}")));
        return summary;
    }

    // A descriptor is rewritten only when each of its slots is named or restored.
    private static (bool Added, string? Note) AddSection(ref byte[] image, ref CapturedImage captured, List<Descriptor> descriptors, List<(uint Rva, string Name)> names, bool is64)
    {
        var nameBy = names.ToDictionary(n => n.Rva, n => n.Name);
        var chosen = descriptors.Where(d => d.Slots.Any(s => nameBy.ContainsKey(s.Rva)) && d.Slots.All(s => s.Restored || nameBy.ContainsKey(s.Rva))).ToList();
        if (chosen.Count == 0) return (false, "no descriptor is fully named");

        int width = is64 ? 8 : 4;
        long slots = chosen.Sum(d => (long)d.Slots.Count + 1);
        if (slots > MaxSlots) return (false, $"import names past the bound of {MaxSlots} slots");
        long nameBytes = chosen.Sum(d => d.Slots.Where(s => nameBy.ContainsKey(s.Rva)).Sum(s => EntryBytes(nameBy[s.Rva])));
        if (nameBytes > MaxNameBytes) return (false, $"import names past the bound of {MaxNameBytes >> 20} MB");

        long size = slots * width + nameBytes;
        if (TryGrow(image, size, out var grown, out long start) is { } refusal) return (false, refusal);
        long lookupAt = start, nameAt = start + slots * width;
        foreach (var d in chosen)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(grown.AsSpan(d.At), (uint)lookupAt);
            foreach (var s in d.Slots)
            {
                ulong entry = s.Entry;
                if (nameBy.TryGetValue(s.Rva, out var name))
                {
                    if (TryOrdinal(name, out ushort ordinal)) entry = ordinal | (is64 ? 1UL << 63 : 1UL << 31);
                    else
                    {
                        entry = (ulong)nameAt;
                        Encoding.UTF8.GetBytes(Function(name)).CopyTo(grown, (int)nameAt + 2);
                        nameAt += EntryBytes(name);
                    }
                }
                Write(grown, (int)lookupAt, width, entry);
                Write(grown, (int)s.Rva, width, entry);
                lookupAt += width;
            }
            lookupAt += width;
        }

        Seal(grown, ref captured, start, size);
        image = grown;
        return (true, "names written to .idata2");
    }

    // No import directory: a descriptor is built for each run of named slots,
    // with the address table left in place.
    private static (bool Added, string? Note) AddDirectory(ref byte[] image, ref CapturedImage captured, ImportScanResult found, bool is64)
    {
        List<(string Module, List<ImportSlot> Slots)> chunks = [];
        foreach (var run in found.Runs)
        {
            List<ImportSlot> current = [];
            foreach (var slot in run.Slots)
            {
                if (slot.Name is not null) { current.Add(slot); continue; }
                if (current.Count > 0) chunks.Add((run.Module, current));
                current = [];
            }
            if (current.Count > 0) chunks.Add((run.Module, current));
        }
        return WriteDirectory(ref image, ref captured, chunks, is64, []);
    }

    // Appends a descriptor per chunk after the kept descriptors, in a new
    // section that holds the whole directory.
    private static (bool Added, string? Note) WriteDirectory(ref byte[] image, ref CapturedImage captured, List<(string Module, List<ImportSlot> Slots)> chunks, bool is64, byte[] kept)
    {
        int width = is64 ? 8 : 4;
        if (chunks.Count == 0) return (false, "no slot is named");

        long slots = chunks.Sum(c => (long)c.Slots.Count + 1);
        if (slots > MaxSlots) return (false, $"import names past the bound of {MaxSlots} slots");
        var modules = chunks.Select(c => c.Module).Distinct().ToList();
        long moduleBytes = modules.Sum(m => (Encoding.UTF8.GetByteCount(m) + 2) & ~1L);
        long nameBytes = chunks.Sum(c => c.Slots.Sum(s => EntryBytes(s.Name!)));
        if (nameBytes + moduleBytes > MaxNameBytes) return (false, $"import names past the bound of {MaxNameBytes >> 20} MB");

        int keptCount = kept.Length / DescriptorSize;
        long descriptorBytes = (keptCount + chunks.Count + 1L) * DescriptorSize;
        long lookupStart = (descriptorBytes + 7) & ~7L;
        long moduleStart = lookupStart + slots * width;
        long size = moduleStart + moduleBytes + nameBytes;
        if (TryGrow(image, size, out var grown, out long start) is { } refusal) return (false, refusal);

        kept.CopyTo(grown, (int)start);
        Dictionary<string, long> moduleAt = [];
        long nameAt = start + moduleStart;
        foreach (var m in modules)
        {
            moduleAt[m] = nameAt;
            Encoding.UTF8.GetBytes(m).CopyTo(grown, (int)nameAt);
            nameAt += (Encoding.UTF8.GetByteCount(m) + 2) & ~1L;
        }
        long lookupAt = start + lookupStart;
        for (int i = 0; i < chunks.Count; i++)
        {
            var (module, chunk) = chunks[i];
            var d = grown.AsSpan((int)(start + (keptCount + i) * (long)DescriptorSize), DescriptorSize);
            BinaryPrimitives.WriteUInt32LittleEndian(d, (uint)lookupAt);
            BinaryPrimitives.WriteUInt32LittleEndian(d[12..], (uint)moduleAt[module]);
            BinaryPrimitives.WriteUInt32LittleEndian(d[16..], chunk[0].Rva);
            foreach (var s in chunk)
            {
                ulong entry;
                if (TryOrdinal(s.Name!, out ushort ordinal)) entry = ordinal | (is64 ? 1UL << 63 : 1UL << 31);
                else
                {
                    entry = (ulong)nameAt;
                    Encoding.UTF8.GetBytes(Function(s.Name!)).CopyTo(grown, (int)nameAt + 2);
                    nameAt += EntryBytes(s.Name!);
                }
                Write(grown, (int)lookupAt, width, entry);
                Write(grown, (int)s.Rva, width, entry);
                lookupAt += width;
            }
            lookupAt += width;
        }

        int nt = BinaryPrimitives.ReadInt32LittleEndian(grown.AsSpan(0x3C));
        int dir = nt + 24 + (is64 ? 112 : 96) + 8;
        BinaryPrimitives.WriteUInt32LittleEndian(grown.AsSpan(dir), (uint)start);
        BinaryPrimitives.WriteUInt32LittleEndian(grown.AsSpan(dir + 4), (uint)descriptorBytes);
        Seal(grown, ref captured, start, size);
        image = grown;
        return (true, "directory written to .idata2");
    }

    // Checks the section table and size limit; null on success, else the
    // reason. The new section starts at start.
    private static string? TryGrow(byte[] image, long size, out byte[] grown, out long start)
    {
        grown = image;
        start = 0;
        int nt = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3C));
        int coff = nt + 4, opt = coff + 20;
        int sections = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(coff + 2));
        int table = opt + BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(coff + 16));
        long headerEnd = Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(opt + 60)), image.Length);
        for (int i = 0; i < sections && table + 40L * i + 40 <= image.Length; i++)
        {
            uint va = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(table + 40 * i + 12));
            if (va != 0) headerEnd = Math.Min(headerEnd, va);
        }
        if (sections >= PeLimits.MaxSections || table + 40L * (sections + 1) > headerEnd) return "no room for an import section";

        uint alignment = SectionAlignment(image);
        uint imageSize = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(opt + 56));
        start = Align(Math.Max(imageSize, (uint)image.Length), alignment);
        if (start + size > ModuleRebuild.MaxImageBytes) return $"import section would exceed {ModuleRebuild.MaxImageBytes >> 20} MB";

        grown = new byte[Align((uint)(start + size), 0x1000)];
        image.CopyTo(grown, 0);
        return null;
    }

    private static uint SectionAlignment(byte[] image)
    {
        int opt = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3C)) + 24;
        uint alignment = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(opt + 32));
        return alignment == 0 || (alignment & (alignment - 1)) != 0 || alignment > 0x10000 ? 0x1000 : alignment;
    }

    // Writes the .idata2 header, grows the image size and marks the new pages
    // captured.
    private static void Seal(byte[] grown, ref CapturedImage captured, long start, long size)
    {
        int nt = BinaryPrimitives.ReadInt32LittleEndian(grown.AsSpan(0x3C));
        int coff = nt + 4, opt = coff + 20;
        int sections = BinaryPrimitives.ReadUInt16LittleEndian(grown.AsSpan(coff + 2));
        int table = opt + BinaryPrimitives.ReadUInt16LittleEndian(grown.AsSpan(coff + 16));
        var h = grown.AsSpan(table + 40 * sections, 40);
        Encoding.ASCII.GetBytes(".idata2").CopyTo(h);
        BinaryPrimitives.WriteUInt32LittleEndian(h[8..], (uint)size);
        BinaryPrimitives.WriteUInt32LittleEndian(h[12..], (uint)start);
        BinaryPrimitives.WriteUInt32LittleEndian(h[16..], (uint)size);
        BinaryPrimitives.WriteUInt32LittleEndian(h[20..], (uint)start);
        BinaryPrimitives.WriteUInt32LittleEndian(h[36..], 0x40000040);
        BinaryPrimitives.WriteUInt16LittleEndian(grown.AsSpan(coff + 2), (ushort)(sections + 1));
        BinaryPrimitives.WriteUInt32LittleEndian(grown.AsSpan(opt + 56), (uint)Align((uint)(start + size), SectionAlignment(grown)));

        var pages = new bool[grown.Length / 0x1000];
        captured.Captured.AsSpan(0, Math.Min(captured.Captured.Length, pages.Length)).CopyTo(pages);
        for (long page = start / 0x1000; page < pages.Length; page++) pages[page] = true;
        captured = captured with { Image = grown, Captured = pages };
    }

    private static string Function(string name) => name[(name.LastIndexOf('!') + 1)..];

    // Bytes of one hint/name entry: hint, name, terminator, padded to even; none for an ordinal.
    private static long EntryBytes(string name) =>
        TryOrdinal(name, out _) ? 0 : (2 + Encoding.UTF8.GetByteCount(Function(name)) + 2) & ~1L;

    private static bool TryOrdinal(string name, out ushort ordinal)
    {
        ordinal = 0;
        string tail = Function(name);
        return tail.StartsWith('#') && ushort.TryParse(tail.AsSpan(1), out ordinal);
    }

    private static long Align(uint value, uint alignment) => ((long)value + alignment - 1) / alignment * alignment;

    // The map is built only when a slot is left, as it reads every module's exports.
    private static List<(uint Rva, string Name)> Name(List<(uint Rva, ulong Value)> pending, IProcessMemory memory)
    {
        if (pending.Count == 0 || memory == null) return [];
        var map = new ExportMap(memory);
        List<(uint, string)> named = [];
        foreach (var (rva, value) in pending)
            if (map.NameAt(value) is { } name) named.Add((rva, name));
        return named;
    }

    // The import directory of a PE image; false when its headers are not readable.
    internal static bool TryDirectory(byte[] image, out bool is64, out uint rva, out uint size)
    {
        is64 = false;
        rva = size = 0;
        if (image.Length < 0x40) return false;
        long opt = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(0x3C)) + 24L;
        if (opt + 2 > image.Length) return false;
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan((int)opt));
        if (magic != 0x10B && magic != 0x20B) return false;
        is64 = magic == 0x20B;
        long dir = opt + (is64 ? 112 : 96) + 8;
        if (dir + 8 > image.Length) return false;
        rva = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)dir));
        size = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)dir + 4));
        return true;
    }

    private static ulong Read(byte[] image, int at, int width) =>
        width == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan(at)) : BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(at));

    private static void Write(byte[] image, int at, int width, ulong value)
    {
        if (width == 8) BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(at), value);
        else BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(at), (uint)value);
    }
}
