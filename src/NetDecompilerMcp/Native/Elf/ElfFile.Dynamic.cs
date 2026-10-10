using System.Text;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Native.Elf;

/// <summary>
/// A symbol table entry. <see cref="Value"/> is the raw st_value (a virtual address for defined symbols, with the Thumb
/// bit for ARM Thumb functions). <see cref="Version"/> and <see cref="VersionLibrary"/> come from the GNU version tables.
/// </summary>
public sealed record ElfSymbol(int Index, string Name, ulong Value, ulong Size, byte Type, byte Binding, byte Visibility, ushort SectionIndex,
    string? Version = null, string? VersionLibrary = null)
{
    public const byte TypeNone = 0, TypeObject = 1, TypeFunction = 2, TypeSection = 3, TypeFile = 4, TypeCommon = 5, TypeTls = 6, TypeIndirectFunction = 10;
    public const byte BindLocal = 0, BindGlobal = 1, BindWeak = 2;
    public const ushort Undefined = 0, Absolute = 0xFFF1, CommonSection = 0xFFF2;

    public bool IsDefined => SectionIndex != Undefined;
    public bool IsFunction => Type is TypeFunction or TypeIndirectFunction;
}

public sealed partial class ElfFile
{
    private const int MaxSymbols = 1 << 22;
    private const int MaxDynamicEntries = 1 << 16;

    private sealed class DynamicInfo
    {
        public List<(long Tag, ulong Value)> Entries = [];
        public List<string> Needed = [];
        public string? SoName, RunPath;
        public ulong Flags, Flags1;
        public List<ElfSymbol> Symbols = [];
        public GnuHash? Gnu;
        public SysvHash? Sysv;
        public Dictionary<string, int>? ByName;

        public ulong? Tag(long tag)
        {
            foreach (var (t, v) in Entries) if (t == tag) return v;
            return null;
        }
    }

    private sealed record GnuHash(uint SymOffset, ulong[] Bloom, uint Shift, uint[] Buckets, uint[] Chains);
    private sealed record SysvHash(uint[] Buckets, uint[] Chains);

    private ImageArea<DynamicInfo> dynamic = null!;

    /// <summary>The dynamic table (PT_DYNAMIC) as (tag, value) pairs up to DT_NULL.</summary>
    public IReadOnlyList<(long Tag, ulong Value)> DynamicEntries => dynamic.Value.Entries;
    /// <summary>DT_NEEDED libraries in order.</summary>
    public IReadOnlyList<string> Dependencies => dynamic.Value.Needed;
    public string? SoName => dynamic.Value.SoName;
    /// <summary>DT_RUNPATH, or DT_RPATH when there is no DT_RUNPATH.</summary>
    public string? RunPath => dynamic.Value.RunPath;
    /// <summary>All symbols bound at load time (DF_BIND_NOW or DF_1_NOW): no lazy PLT binding.</summary>
    public bool BindNow => (dynamic.Value.Flags & 0x8) != 0 || (dynamic.Value.Flags1 & 0x1) != 0 || dynamic.Value.Tag(24) != null;
    /// <summary>.dynsym in table order (index 0, the null symbol, included).</summary>
    public IReadOnlyList<ElfSymbol> DynamicSymbols => dynamic.Value.Symbols;

    /// <summary>
    /// The dynamic symbol named <paramref name="name"/> (a defined one when several share it), found through
    /// DT_GNU_HASH or DT_HASH when present; null when there is none.
    /// </summary>
    public ElfSymbol? DynamicSymbol(string name)
    {
        var d = dynamic.Value;
        if (d.Gnu is { } gnu && LookupGnu(d, gnu, name) is { } g) return g;
        if (d.Sysv is { } sysv && LookupSysv(d, sysv, name) is { } s && s.IsDefined) return s;
        lock (d)
        {
            d.ByName ??= BuildIndex(d.Symbols);
            return d.ByName.TryGetValue(name, out int i) ? d.Symbols[i] : null;
        }
    }

    private static Dictionary<string, int> BuildIndex(List<ElfSymbol> symbols)
    {
        var map = new Dictionary<string, int>(StringComparer.Ordinal);
        for (int i = 1; i < symbols.Count; i++)
            if (symbols[i].Name.Length > 0 && (!map.TryGetValue(symbols[i].Name, out int prev) || !symbols[prev].IsDefined && symbols[i].IsDefined))
                map[symbols[i].Name] = i;
        return map;
    }

    private ElfSymbol? LookupGnu(DynamicInfo d, GnuHash gnu, string name)
    {
        uint h = GnuHashOf(name);
        int bits = Is64Bit ? 64 : 32;
        if (gnu.Bloom.Length > 0)
        {
            ulong word = gnu.Bloom[(h / (uint)bits) % (uint)gnu.Bloom.Length];
            if (((word >> (int)(h % (uint)bits)) & (word >> (int)((h >> (int)gnu.Shift) % (uint)bits)) & 1) == 0) return null;
        }
        if (gnu.Buckets.Length == 0) return null;
        uint index = gnu.Buckets[h % (uint)gnu.Buckets.Length];
        if (index < gnu.SymOffset) return null;
        for (int guard = 0; guard < MaxSymbols; guard++, index++)
        {
            long c = index - gnu.SymOffset;
            if (c >= gnu.Chains.Length || index >= d.Symbols.Count) return null;
            uint chain = gnu.Chains[c];
            if ((chain | 1) == (h | 1) && d.Symbols[(int)index].Name == name) return d.Symbols[(int)index];
            if ((chain & 1) != 0) return null;
        }
        return null;
    }

    private static ElfSymbol? LookupSysv(DynamicInfo d, SysvHash sysv, string name)
    {
        if (sysv.Buckets.Length == 0) return null;
        uint index = sysv.Buckets[ElfHashOf(name) % (uint)sysv.Buckets.Length];
        for (int guard = 0; index != 0 && guard < sysv.Chains.Length; guard++)
        {
            if (index >= d.Symbols.Count || index >= sysv.Chains.Length) return null;
            if (d.Symbols[(int)index].Name == name) return d.Symbols[(int)index];
            index = sysv.Chains[index];
        }
        return null;
    }

    internal static uint GnuHashOf(string name)
    {
        uint h = 5381;
        foreach (byte c in Encoding.UTF8.GetBytes(name)) h = h * 33 + c;
        return h;
    }

    internal static uint ElfHashOf(string name)
    {
        uint h = 0;
        foreach (byte c in Encoding.UTF8.GetBytes(name))
        {
            h = (h << 4) + c;
            uint g = h & 0xF0000000;
            if (g != 0) h ^= g >> 24;
            h &= ~g;
        }
        return h;
    }

    private DynamicInfo ParseDynamic(IssueLog log)
    {
        var d = new DynamicInfo();
        var seg = segments.FirstOrDefault(s => s.Type == 2);
        ulong va, size;
        if (seg != null) (va, size) = (seg.VirtualAddress, Math.Max(seg.FileSize, seg.MemorySize));
        else if (sectionHeaders.FirstOrDefault(s => s.Type == 6 && s.IsAllocated) is { } sec) (va, size) = (sec.Address, sec.Size);
        else return d; // static executable or object
        int entry = Is64Bit ? 16 : 8;
        var table = TableAt(va, Math.Min(size, (ulong)MaxDynamicEntries * (ulong)entry), "dynamic table", log);
        bool terminated = false;
        for (long at = 0; at + entry <= table.Length; at += entry)
        {
            long tag = Is64Bit ? (long)table.U64(at) : (int)table.U32(at);
            ulong value = table.Word(at + entry / 2, Is64Bit);
            if (tag == 0) { terminated = true; break; }
            d.Entries.Add((tag, value));
        }
        if (!terminated && table.Length > 0) log.Add("the dynamic table has no DT_NULL terminator");

        ulong strSize = d.Tag(10) ?? 0;
        var strtab = d.Tag(5) is not { } strVa ? new ByteView([], BigEndian)
            : strSize != 0 ? TableAt(strVa, strSize, "dynamic string table (DT_STRTAB)", log) : ViewAt(strVa, 1 << 24);
        string? Str(ulong offset) => offset < (ulong)strtab.Length ? strtab.CString((long)offset, MaxNameLength) : null;
        foreach (var (tag, value) in d.Entries)
        {
            switch (tag)
            {
                case 1:
                    if (Str(value) is { } lib) d.Needed.Add(lib);
                    else log.Add($"DT_NEEDED name offset 0x{value:X} is outside the string table");
                    break;
                case 14: d.SoName = Str(value); break;
                case 15: d.RunPath ??= Str(value); break;
                case 29: d.RunPath = Str(value); break;
                case 30: d.Flags = value; break;
                case 0x6FFFFFFB: d.Flags1 = value; break;
            }
        }

        if (d.Tag(6) is not { } symVa) return d;
        ulong symEnt = d.Tag(11) ?? 0;
        ulong standard = Is64Bit ? 24u : 16u;
        if (symEnt != standard)
        {
            if (symEnt != 0) log.Add($"DT_SYMENT {symEnt} is not {standard}; the standard size is used");
            symEnt = standard;
        }
        int count = Math.Clamp(SymbolCount(d, symVa, symEnt, log), 0, MaxSymbols);
        var symtab = TableAt(symVa, (ulong)count * symEnt, "dynamic symbol table (DT_SYMTAB)", log);
        var versions = ReadVersions(d, strtab, count, log);
        count = (int)Math.Min(count, symtab.Length / (long)symEnt);
        var budget = new WorkBudget(log);
        for (int i = 0; i < count && budget.Step(); i++)
        {
            var sym = ReadSymbol(symtab, i * (long)symEnt, i, strtab, log, budget);
            if (versions != null && i < versions.Length && versions[i] is { } v) sym = sym with { Version = v.Name, VersionLibrary = v.Library };
            d.Symbols.Add(sym);
        }
        return d;
    }

    private ElfSymbol ReadSymbol(ByteView table, long at, int index, ByteView strings, IssueLog log, WorkBudget budget)
    {
        uint nameOffset = table.U32(at);
        byte info, other;
        ushort shndx;
        ulong value, size;
        if (Is64Bit)
        {
            info = table.U8(at + 4); other = table.U8(at + 5); shndx = table.U16(at + 6); value = table.U64(at + 8); size = table.U64(at + 16);
        }
        else
        {
            value = table.U32(at + 4); size = table.U32(at + 8); info = table.U8(at + 12); other = table.U8(at + 13); shndx = table.U16(at + 14);
        }
        string name = "";
        if (nameOffset != 0)
        {
            if (strings.CString(nameOffset, MaxNameLength) is { } n && budget.Chars(n.Length)) name = n;
            else log.Add($"symbol {index}: name offset 0x{nameOffset:X} is outside the string table");
        }
        return new ElfSymbol(index, name, value, size, (byte)(info & 0xF), (byte)(info >> 4), (byte)(other & 3), shndx);
    }

    /// <summary>The number of .dynsym entries: DT_HASH nchain, else the DT_GNU_HASH chains, else the section header, else an estimate.</summary>
    private int SymbolCount(DynamicInfo d, ulong symVa, ulong symEnt, IssueLog log)
    {
        if (d.Tag(4) is { } hashVa)
        {
            var h = TableAt(hashVa, 8, "symbol hash table (DT_HASH)", log);
            uint nbucket = h.U32(0), nchain = h.U32(4);
            if (h.Length >= 8 && nchain <= MaxSymbols && nbucket <= MaxSymbols)
            {
                var full = TableAt(hashVa, 8 + 4 * ((ulong)nbucket + nchain), "symbol hash table (DT_HASH)", log);
                d.Sysv = new SysvHash(ReadWords(full, 8, nbucket), ReadWords(full, 8 + 4L * nbucket, nchain));
                if (d.Tag(0x6FFFFEF5) == null) return (int)nchain;
            }
            else log.Add($"DT_HASH has {nbucket} buckets and {nchain} chains; ignored");
        }
        if (d.Tag(0x6FFFFEF5) is { } gnuVa)
        {
            var h = TableAt(gnuVa, 16, "GNU hash table (DT_GNU_HASH)", log);
            uint nbuckets = h.U32(0), symOffset = h.U32(4), bloomSize = h.U32(8), shift = h.U32(12);
            if (h.Length >= 16 && nbuckets <= MaxSymbols && bloomSize <= MaxSymbols && symOffset <= MaxSymbols)
            {
                int word = Is64Bit ? 8 : 4;
                long bucketsAt = 16 + (long)bloomSize * word, chainsAt = bucketsAt + 4L * nbuckets;
                var head = TableAt(gnuVa, (ulong)chainsAt, "GNU hash table (DT_GNU_HASH)", log);
                var bloom = new ulong[head.Length >= bucketsAt ? bloomSize : 0];
                for (int i = 0; i < bloom.Length; i++) bloom[i] = head.Word(16 + (long)i * word, Is64Bit);
                var buckets = ReadWords(head, bucketsAt, nbuckets);
                uint last = buckets.Length > 0 ? buckets.Max() : 0;
                int count = (int)symOffset;
                uint[] chains = [];
                if (last >= MaxSymbols) log.Add($"DT_GNU_HASH bucket names symbol {last}; the chains are not read");
                else if (last >= symOffset)
                {
                    // Walk the last bucket's chain to its end marker to find the table size.
                    var rest = TableAt(gnuVa + (ulong)chainsAt, (ulong)(MaxSymbols - symOffset) * 4, "GNU hash chains", new IssueLog("unused"));
                    uint i = last;
                    while ((ulong)(i - symOffset) * 4 + 4 <= (ulong)rest.Length && (rest.U32((i - symOffset) * 4L) & 1) == 0 && i < MaxSymbols) i++;
                    count = (int)i + 1;
                    chains = ReadWords(rest, 0, (uint)(count - symOffset));
                }
                d.Gnu = new GnuHash(symOffset, bloom, shift, buckets, chains);
                if (d.Sysv == null || count > d.Sysv.Chains.Length) return count;
                return d.Sysv.Chains.Length;
            }
            log.Add($"DT_GNU_HASH header (buckets {nbuckets}, symbol offset {symOffset}, bloom {bloomSize}) is not usable");
        }
        if (d.Sysv != null) return d.Sysv.Chains.Length;
        if (sectionHeaders.FirstOrDefault(s => s.Type == 11 && s.Address == symVa) is { EntrySize: > 0 } section)
            return (int)Math.Min(section.Size / section.EntrySize, MaxSymbols);
        // No hash table: the symbol table usually ends where the string table starts.
        if (d.Tag(5) is { } strVa && strVa > symVa)
        {
            log.Add("no DT_HASH or DT_GNU_HASH: the symbol count is estimated from the string table address");
            return (int)Math.Min((strVa - symVa) / symEnt, MaxSymbols);
        }
        log.Add("no DT_HASH or DT_GNU_HASH and no section header: dynamic symbols are not read");
        return 0;
    }

    private static uint[] ReadWords(ByteView table, long at, uint count)
    {
        long available = Math.Max(0, (table.Length - at) / 4);
        var words = new uint[Math.Min(count, available)];
        for (int i = 0; i < words.Length; i++) words[i] = table.U32(at + 4L * i);
        return words;
    }

    private readonly record struct VersionName(string? Name, string? Library);

    /// <summary>Per dynamic symbol: its version and, for imports, the library that provides it (DT_VERSYM with DT_VERNEED / DT_VERDEF).</summary>
    private VersionName?[]? ReadVersions(DynamicInfo d, ByteView strtab, int count, IssueLog log)
    {
        if (d.Tag(0x6FFFFFF0) is not { } versymVa || count == 0) return null;
        var names = new Dictionary<int, VersionName>();
        string? Str(uint offset) => strtab.CString(offset, MaxNameLength);
        if (d.Tag(0x6FFFFFFE) is { } needVa)
        {
            var t = ViewAt(needVa, 1 << 20);
            long at = 0;
            for (ulong n = 0, total = d.Tag(0x6FFFFFFF) ?? 0; n < total && n < 4096 && t.Has(at, 16); n++)
            {
                string? library = Str(t.U32(at + 4));
                long aux = at + t.U32(at + 8);
                for (int a = 0, cnt = t.U16(at + 2); a < cnt && a < 4096 && t.Has(aux, 16); a++)
                {
                    names[t.U16(aux + 6) & 0x7FFF] = new VersionName(Str(t.U32(aux + 8)), library);
                    uint next = t.U32(aux + 12);
                    if (next == 0) break;
                    aux += next;
                }
                uint step = t.U32(at + 12);
                if (step == 0) break;
                at += step;
            }
        }
        if (d.Tag(0x6FFFFFFC) is { } defVa)
        {
            var t = ViewAt(defVa, 1 << 20);
            long at = 0;
            for (ulong n = 0, total = d.Tag(0x6FFFFFFD) ?? 0; n < total && n < 4096 && t.Has(at, 20); n++)
            {
                int index = t.U16(at + 4) & 0x7FFF;
                bool isBase = (t.U16(at + 2) & 1) != 0;
                long aux = at + t.U32(at + 12);
                if (!isBase && t.Has(aux, 8)) names[index] = new VersionName(Str(t.U32(aux)), null);
                uint step = t.U32(at + 16);
                if (step == 0) break;
                at += step;
            }
        }
        var versym = TableAt(versymVa, (ulong)count * 2, "symbol versions (DT_VERSYM)", log);
        var result = new VersionName?[count];
        for (int i = 0; i < count && (i + 1) * 2L <= versym.Length; i++)
        {
            int v = versym.U16(i * 2L) & 0x7FFF;
            if (v >= 2 && names.TryGetValue(v, out var name)) result[i] = name;
        }
        return result;
    }
}
