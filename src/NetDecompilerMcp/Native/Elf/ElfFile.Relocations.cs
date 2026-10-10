using System.Buffers.Binary;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Native.Elf;

/// <summary>
/// A dynamic relocation, after RELR and Android packed tables are expanded. <see cref="Offset"/> is the location's
/// virtual address; <see cref="Addend"/> is explicit for RELA entries, otherwise the value stored at the location.
/// <see cref="Table"/> names where it came from (DT_RELA, DT_REL, DT_JMPREL, DT_RELR, APS2).
/// </summary>
public sealed record ElfRelocation(ulong Offset, uint Type, int SymbolIndex, string? Symbol, long Addend, bool ExplicitAddend, ElfRelocationKind Kind, string Table);

public sealed partial class ElfFile
{
    private sealed record RelocationInfo(List<ElfRelocation> All, FixupOverlay Overlay, List<NativeImport> Imports, List<uint> Rvas)
    {
        public static readonly RelocationInfo Empty = new([], FixupOverlay.Empty, [], []);
    }

    private ImageArea<RelocationInfo> relocations = null!;

    /// <summary>Every dynamic relocation in table order.</summary>
    public IReadOnlyList<ElfRelocation> Relocations => relocations.Value.All;
    /// <summary>GOT and PLT slots bound to undefined symbols; the module is the symbol version's library, or "*" when unversioned.</summary>
    public IReadOnlyList<NativeImport> Imports => relocations.Value.Imports;
    /// <summary>Locations of every rebased pointer (relative, absolute to defined symbols, IRELATIVE), sorted.</summary>
    public IReadOnlyList<uint> RelocationRvas => relocations.Value.Rvas;

    private RelocationInfo ParseRelocations(IssueLog log)
    {
        var d = dynamic.Value;
        var all = new List<ElfRelocation>();
        var budget = new WorkBudget(log);
        int word = Is64Bit ? 8 : 4;
        ulong? Tag(long t) => d.Tag(t);

        // DT_RELA / DT_REL may include the DT_JMPREL range (older linkers); that part is read once, as PLT relocations.
        ulong jmprel = Tag(23) ?? 0, pltSize = Tag(2) ?? 0;
        void Table(ulong? va, ulong? size, bool rela, string name, ulong entrySize)
        {
            if (va is not { } start || size is not { } length || length == 0) return;
            ulong end = start + length;
            if (name != "DT_JMPREL" && jmprel != 0 && jmprel >= start && jmprel < end) end = jmprel;
            ReadTable(start, end - start, rela, name, entrySize, all, log, budget);
        }
        Table(Tag(7), Tag(8), true, "DT_RELA", Tag(9) ?? 0);
        Table(Tag(17), Tag(18), false, "DT_REL", Tag(19) ?? 0);
        if (jmprel != 0) Table(jmprel, pltSize, Tag(20) is not 17, "DT_JMPREL", 0);
        if (Tag(36) is { } relr) ReadRelr(relr, Tag(35) ?? 0, "DT_RELR", all, log, budget);
        if (Tag(0x6FFFE000) is { } androidRelr) ReadRelr(androidRelr, Tag(0x6FFFE001) ?? 0, "DT_ANDROID_RELR", all, log, budget);
        if (Tag(0x60000011) is { } aps2a) ReadPacked(aps2a, Tag(0x60000012) ?? 0, true, all, log, budget);
        if (Tag(0x6000000F) is { } aps2) ReadPacked(aps2, Tag(0x60000010) ?? 0, false, all, log, budget);
        if (d.Entries.Count == 0)
            foreach (var s in sectionHeaders.Where(s => s.Type is 4 or 9 && s.IsAllocated && s.Size > 0))
                ReadTable(s.Address, s.Size, s.Type == 4, s.Name, s.EntrySize, all, log, budget);

        var fixups = new List<(uint, ulong, byte)>();
        var imports = new List<NativeImport>();
        var rvas = new List<uint>();
        var importSlots = new HashSet<uint>();
        bool lazy = !BindNow;
        Span<byte> slot = stackalloc byte[8];
        foreach (var r in all)
        {
            if (!TryVaToRva(r.Offset, out uint rva)) continue;
            var sym = r.SymbolIndex > 0 && r.SymbolIndex < d.Symbols.Count ? d.Symbols[r.SymbolIndex] : null;
            bool import = sym != null && !sym.IsDefined && sym.Name.Length > 0;
            int width = r.Kind == ElfRelocationKind.Absolute ? ElfNames.AbsoluteWidth(Machine, r.Type, Is64Bit) : word;
            ulong addend = (ulong)r.Addend;
            if (!r.ExplicitAddend && r.Kind == ElfRelocationKind.Absolute && !import)
                addend = ReadRaw(rva, slot[..width]) != width ? 0
                    : width == 8 ? (BigEndian ? BinaryPrimitives.ReadUInt64BigEndian(slot) : BinaryPrimitives.ReadUInt64LittleEndian(slot))
                    : BigEndian ? BinaryPrimitives.ReadUInt32BigEndian(slot) : BinaryPrimitives.ReadUInt32LittleEndian(slot);
            switch (r.Kind)
            {
                case ElfRelocationKind.Relative or ElfRelocationKind.IRelative:
                    if (r.ExplicitAddend) fixups.Add((rva, addend, (byte)word));
                    rvas.Add(rva);
                    break;
                case ElfRelocationKind.Absolute:
                    if (import) fixups.Add((rva, 0, (byte)width));
                    else
                    {
                        fixups.Add((rva, (sym?.Value ?? 0) + addend, (byte)width));
                        if (width == word) rvas.Add(rva);
                    }
                    break;
                case ElfRelocationKind.GlobalData or ElfRelocationKind.JumpSlot:
                    if (import) fixups.Add((rva, 0, (byte)word));
                    else if (sym != null) fixups.Add((rva, sym.Value + (r.ExplicitAddend ? addend : 0), (byte)word));
                    break;
            }
            if (import && r.Kind is ElfRelocationKind.Absolute or ElfRelocationKind.GlobalData or ElfRelocationKind.JumpSlot && importSlots.Add(rva))
                imports.Add(new NativeImport(sym!.VersionLibrary ?? "*", sym.Name, null, 0, rva, r.Kind == ElfRelocationKind.JumpSlot && lazy));
        }
        rvas.Sort();
        return new RelocationInfo(all, new FixupOverlay(fixups, BigEndian), imports, [.. rvas.Distinct()]);
    }

    private void ReadTable(ulong va, ulong size, bool rela, string name, ulong entrySize, List<ElfRelocation> all, IssueLog log, WorkBudget budget)
    {
        ulong standard = (ulong)(Is64Bit ? 16 : 8) + (rela ? (ulong)(Is64Bit ? 8 : 4) : 0);
        if (entrySize != 0 && entrySize != standard)
        {
            log.Add($"{name}: entry size {entrySize} is not {standard}; the standard size is used");
        }
        var t = TableAt(va, size, name, log);
        var symbols = dynamic.Value.Symbols;
        for (long at = 0; at + (long)standard <= t.Length; at += (long)standard)
        {
            if (!budget.Step()) return;
            if (all.Count >= PeLimits.MaxRelocations)
            {
                log.Add($"more than {PeLimits.MaxRelocations} relocations; the rest are not read");
                return;
            }
            ulong offset = t.Word(at, Is64Bit);
            ulong info = t.Word(at + (Is64Bit ? 8 : 4), Is64Bit);
            long addend = rela ? (Is64Bit ? (long)t.U64(at + 16) : (int)t.U32(at + 8)) : 0;
            all.Add(Make(offset, info, addend, rela, name, symbols));
        }
    }

    private ElfRelocation Make(ulong offset, ulong info, long addend, bool explicitAddend, string table, List<ElfSymbol> symbols)
    {
        uint type = Is64Bit ? (uint)info : (uint)(info & 0xFF);
        int sym = (int)Math.Min(Is64Bit ? info >> 32 : (info >> 8) & 0xFFFFFF, int.MaxValue);
        var kind = ElfNames.Kind(Machine, type);
        string? name = sym > 0 && sym < symbols.Count ? symbols[sym].Name : null;
        return new ElfRelocation(offset, type, sym, name, addend, explicitAddend, kind, table);
    }

    /// <summary>DT_RELR: an even word is an address to relocate; an odd word is a bitmap of the following words.</summary>
    private void ReadRelr(ulong va, ulong size, string name, List<ElfRelocation> all, IssueLog log, WorkBudget budget)
    {
        var t = TableAt(va, size, name, log);
        int word = Is64Bit ? 8 : 4, bits = word * 8 - 1;
        uint relative = RelativeType;
        ulong where = 0;
        for (long at = 0; at + word <= t.Length; at += word)
        {
            ulong entry = t.Word(at, Is64Bit);
            if ((entry & 1) == 0)
            {
                Add(entry);
                where = entry + (ulong)word;
            }
            else
            {
                for (int bit = 1; bit <= bits; bit++)
                    if (((entry >> bit) & 1) != 0) Add(where + (ulong)((bit - 1) * word));
                where += (ulong)(bits * word);
            }
            if (budget.Exhausted || all.Count >= PeLimits.MaxRelocations) break;
        }
        if (all.Count >= PeLimits.MaxRelocations) log.Add($"more than {PeLimits.MaxRelocations} relocations; the rest are not read");

        void Add(ulong offset)
        {
            if (budget.Step() && all.Count < PeLimits.MaxRelocations)
                all.Add(new ElfRelocation(offset, relative, 0, null, 0, false, ElfRelocationKind.Relative, name));
        }
    }

    private uint RelativeType => Machine switch
    {
        ElfNames.EmAarch64 => 1027,
        ElfNames.EmArm => 23,
        ElfNames.EmRiscV => 3,
        ElfNames.EmPpc or ElfNames.EmPpc64 => 22,
        _ => 8,
    };

    /// <summary>
    /// Android packed relocations ("APS2", SLEB128): groups sharing an offset delta, info or addend. Offsets and
    /// addends are running sums; a group without addends resets the addend to 0.
    /// </summary>
    private void ReadPacked(ulong va, ulong size, bool rela, List<ElfRelocation> all, IssueLog log, WorkBudget budget)
    {
        string name = rela ? "DT_ANDROID_RELA" : "DT_ANDROID_REL";
        var t = TableAt(va, size, name, log);
        var bytes = t.Span(0, t.Length);
        if (bytes.Length < 4 || bytes[0] != 'A' || bytes[1] != 'P' || bytes[2] != 'S' || bytes[3] != '2')
        {
            log.Add($"{name} does not start with the APS2 signature");
            return;
        }
        var r = new LebReader(bytes, 4);
        long count = r.Sleb();
        ulong offset = (ulong)r.Sleb();
        ulong info = 0;
        long addend = 0;
        var symbols = dynamic.Value.Symbols;
        long done = 0;
        while (done < count && !r.Failed)
        {
            long groupSize = r.Sleb();
            long flags = r.Sleb();
            bool byInfo = (flags & 1) != 0, byDelta = (flags & 2) != 0, byAddend = (flags & 4) != 0, hasAddend = (flags & 8) != 0;
            if (groupSize <= 0 || groupSize > count - done)
            {
                log.Add($"{name}: a group of {groupSize} relocations exceeds the {count - done} left");
                return;
            }
            if (hasAddend && !rela)
            {
                log.Add($"{name}: a REL group declares addends");
                return;
            }
            ulong groupDelta = byDelta ? (ulong)r.Sleb() : 0;
            if (byInfo) info = (ulong)r.Sleb();
            if (hasAddend && byAddend) addend += r.Sleb();
            else if (!hasAddend) addend = 0;
            for (long i = 0; i < groupSize && !r.Failed; i++)
            {
                offset += byDelta ? groupDelta : (ulong)r.Sleb();
                if (!byInfo) info = (ulong)r.Sleb();
                if (hasAddend && !byAddend) addend += r.Sleb();
                if (!budget.Step()) return;
                if (all.Count >= PeLimits.MaxRelocations)
                {
                    log.Add($"more than {PeLimits.MaxRelocations} relocations; the rest are not read");
                    return;
                }
                all.Add(Make(offset, info, addend, rela, "APS2", symbols));
            }
            done += groupSize;
        }
        if (r.Failed) log.Add($"{name} ends inside a relocation group ({done} of {count} read)");
    }
}
