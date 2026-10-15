using System.Text;
using Corvus.Native.Elf;

namespace Corvus.Native.Dump;

/// <summary>An ELF image's header and program headers as mapped in process memory, with its load bias (runtime minus link-time address).</summary>
internal sealed class ElfMemoryHeader
{
    private const int MaxSegments = 256;

    private ElfMemoryHeader(bool is64, bool bigEndian, ushort type, ushort machine, List<ElfSegment> segments, ulong bias)
    {
        Is64 = is64;
        BigEndian = bigEndian;
        Type = type;
        Machine = machine;
        Segments = segments;
        Bias = bias;
    }

    public bool Is64 { get; }
    public bool BigEndian { get; }
    public ushort Type { get; }
    public ushort Machine { get; }
    public IReadOnlyList<ElfSegment> Segments { get; }
    public ulong Bias { get; }

    /// <summary>The header in <paramref name="header"/> (the first bytes of a mapping at <paramref name="start"/>); null when it is not ELF.</summary>
    public static ElfMemoryHeader? Read(byte[] header, ulong start)
    {
        if (header.Length < 52 || header[0] != 0x7F || header[1] != 'E' || header[2] != 'L' || header[3] != 'F' || header[4] is not (1 or 2)) return null;
        bool is64 = header[4] == 2, be = header[5] == 2;
        var v = new ByteView(header, be);
        long phoff = (long)Math.Min(is64 ? v.U64(32) : v.U32(28), int.MaxValue);
        int entry = is64 ? 56 : 32;
        int size = Math.Max(v.U16(is64 ? 54 : 42), entry);
        int count = Math.Min((int)v.U16(is64 ? 56 : 44), MaxSegments);
        var segments = new List<ElfSegment>();
        for (int i = 0; i < count; i++)
        {
            long at = phoff + (long)i * size;
            if (!v.Has(at, entry)) break;
            segments.Add(is64
                ? new ElfSegment(i, v.U32(at), v.U32(at + 4), v.U64(at + 8), v.U64(at + 16), v.U64(at + 32), v.U64(at + 40), v.U64(at + 48))
                : new ElfSegment(i, v.U32(at), v.U32(at + 24), v.U32(at + 4), v.U32(at + 8), v.U32(at + 16), v.U32(at + 20), v.U32(at + 28)));
        }
        var first = segments.Where(s => s.IsLoad).OrderBy(s => s.VirtualAddress).FirstOrDefault();
        ulong link = first != null ? first.VirtualAddress - first.Offset : 0;
        return new ElfMemoryHeader(is64, be, v.U16(16), v.U16(18), segments, start - link);
    }

    public delegate int ReadAt(ulong address, Span<byte> destination);

    /// <summary>NT_GNU_BUILD_ID from the PT_NOTE segments as mapped; null when absent or not captured.</summary>
    public string? BuildId(IProcessMemory memory) => NoteBuildId((a, d) => memory.ReadMemory(a, d), s => s.VirtualAddress + Bias);

    /// <summary>NT_GNU_BUILD_ID from the PT_NOTE segments, each read at <paramref name="where"/>.</summary>
    public string? NoteBuildId(ReadAt read, Func<ElfSegment, ulong> where)
    {
        foreach (var s in Segments.Where(s => s.Type == 4))
        {
            var bytes = new byte[(int)Math.Min(s.FileSize, 4096)];
            int n = read(where(s), bytes);
            var t = new ByteView(bytes, 0, n, BigEndian);
            long pad = s.Align == 8 ? 8 : 4;
            for (long at = 0; at + 12 <= t.Length;)
            {
                long nameSize = t.U32(at), descSize = t.U32(at + 4);
                long name = at + 12, desc = (name + nameSize + pad - 1) & ~(pad - 1);
                if (nameSize > 256 || descSize > 1024 || desc + descSize > t.Length) break;
                if (t.U32(at + 8) == 3 && nameSize == 4 && t.Span(name, 3).SequenceEqual("GNU"u8)) return Convert.ToHexStringLower(t.Span(desc, descSize));
                at = (desc + descSize + pad - 1) & ~(pad - 1);
            }
        }
        return null;
    }

    /// <summary>The machine and GNU build id of an ELF file on disk, from its first 64 KB and its notes; null when it is not ELF.</summary>
    public static (ushort Machine, string? BuildId)? Probe(string path)
    {
        try
        {
            using var f = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var head = new byte[0x10000];
            int n = RandomAccess.Read(f, head, 0);
            if (Read(head[..n], 0) is not { } h) return null;
            return (h.Machine, h.NoteBuildId((a, d) => a > long.MaxValue ? 0 : RandomAccess.Read(f, d, (long)a), s => s.Offset));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { return null; }
    }
}

/// <summary>A named function of a module, at its runtime address.</summary>
public readonly record struct ElfCoreSymbol(ulong Start, ulong Size, string Name, string Source);

/// <summary>
/// A module of a core as the unwinder and the namer read it: its .eh_frame (found through PT_GNU_EH_FRAME, or the
/// .eh_frame section of a file), and function symbols (.symtab and .dynsym of a file; .dynsym through PT_DYNAMIC in
/// memory). Bytes come from the matched file on disk, else from the core's memory. Built once per module and session.
/// </summary>
public sealed class ElfCoreImage
{
    private const int MaxEhFrameBytes = 32 << 20;
    private const int MaxHdrBytes = 16 << 20;
    private const int MaxDynamicSymbols = 1 << 16;

    private readonly IProcessMemory memory;
    private readonly ElfFile? file;
    private readonly IReadOnlyList<ElfSegment> segments;
    private readonly bool is64, bigEndian;
    private readonly Lazy<CfiIndex?> cfi;
    private readonly Lazy<List<ElfCoreSymbol>> symbols;

    private ElfCoreImage(DumpModule module, IProcessMemory memory, ElfFile? file, IReadOnlyList<ElfSegment> segments, bool is64, bool bigEndian, ulong bias,
        string source, string? localPath, string detail)
    {
        Module = module;
        this.memory = memory;
        this.file = file;
        this.segments = segments;
        this.is64 = is64;
        this.bigEndian = bigEndian;
        Bias = bias;
        Source = source;
        LocalPath = localPath;
        Detail = detail;
        cfi = new Lazy<CfiIndex?>(BuildCfi);
        symbols = new Lazy<List<ElfCoreSymbol>>(file != null ? FileSymbols : MemorySymbols);
    }

    public DumpModule Module { get; }
    /// <summary>Runtime address minus link-time address.</summary>
    public ulong Bias { get; }
    /// <summary>disk or core_memory.</summary>
    public string Source { get; }
    public string? LocalPath { get; }
    public string Detail { get; }
    public bool HasCfi => cfi.Value != null;
    public IReadOnlyList<ElfCoreSymbol> Symbols => symbols.Value;

    /// <summary>The module's file on disk, mapped at the module's base.</summary>
    public static ElfCoreImage FromFile(ElfFile file, DumpModule module, IProcessMemory memory, string path, string detail) =>
        new(module, memory, file, file.Segments, file.Is64Bit, file.BigEndian, module.Base - file.ImageBase, "disk", path, detail);

    /// <summary>The module as the core holds it; null when its ELF header is not captured.</summary>
    public static ElfCoreImage? FromMemory(IProcessMemory memory, DumpModule module, string detail)
    {
        var header = new byte[0x1000];
        int n = memory.ReadMemory(module.Base, header);
        if (ElfMemoryHeader.Read(header[..n], module.Base) is not { } h) return null;
        return new ElfCoreImage(module, memory, null, h.Segments, h.Is64, h.BigEndian, h.Bias, "core_memory", null, detail);
    }

    /// <summary>Process bytes at <paramref name="address"/>: the core's memory, the rest from the file.</summary>
    public int Read(ulong address, Span<byte> destination)
    {
        int n = memory.ReadMemory(address, destination);
        if (n == destination.Length || file == null) return n;
        ulong link = address + (ulong)n - Bias;
        if (link < file.ImageBase || link - file.ImageBase >= file.SizeOfImage) return n;
        return n + file.Read((uint)(link - file.ImageBase), destination[n..]);
    }

    private int ReadLink(ulong linkVa, Span<byte> destination)
    {
        if (file == null) return memory.ReadMemory(linkVa + Bias, destination);
        if (linkVa < file.ImageBase || linkVa - file.ImageBase >= file.SizeOfImage) return 0;
        return file.Read((uint)(linkVa - file.ImageBase), destination);
    }

    private byte[] ReadLink(ulong linkVa, ulong size, int max)
    {
        var buffer = new byte[(int)Math.Min(size, (ulong)max)];
        int n = ReadLink(linkVa, buffer);
        return n == buffer.Length ? buffer : buffer[..n];
    }

    /// <summary>The CFI row at <paramref name="pc"/> (a runtime address); null with a reason when the module has none for it.</summary>
    internal CfiRow? Row(ulong pc, out string? failure)
    {
        failure = null;
        if (cfi.Value is not { } index) { failure = "no .eh_frame"; return null; }
        ulong link = pc - Bias;
        if (index.Find(link) is not { } fde) { failure = $"no FDE covers {Module.FileName}+0x{pc - Module.Base:X}"; return null; }
        return EhFrame.Row(index.EhFrame, index.EhFrameVa, is64, fde, link, out failure);
    }

    /// <summary>The function holding <paramref name="address"/>: the symbol whose extent covers it, or the nearest unsized symbol below.</summary>
    public ElfCoreSymbol? SymbolAt(ulong address)
    {
        var list = symbols.Value;
        int lo = 0, hi = list.Count - 1, best = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (list[mid].Start <= address) { best = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        for (int i = best; i >= 0 && best - i < 8; i--)
        {
            var s = list[i];
            if (s.Size > 0 ? address - s.Start < s.Size : i == best) return s;
        }
        return null;
    }

    /// <summary>.eh_frame with its lookup: the .eh_frame_hdr search table, else every FDE sorted.</summary>
    private sealed class CfiIndex(ByteView ehFrame, ulong ehFrameVa, bool is64)
    {
        public ByteView EhFrame { get; } = ehFrame;
        public ulong EhFrameVa { get; } = ehFrameVa;
        private readonly Dictionary<long, CfiCie?> cies = [];
        public ByteView Hdr;
        public ulong HdrVa;
        public byte TableEncoding;
        public long TableAt, EntrySize, Count;
        public List<CfiFde>? Sorted;

        public CfiFde? Find(ulong pc)
        {
            if (Sorted != null)
            {
                int lo = 0, hi = Sorted.Count - 1, best = -1;
                while (lo <= hi)
                {
                    int mid = (lo + hi) >>> 1;
                    if (Sorted[mid].Start <= pc) { best = mid; lo = mid + 1; }
                    else hi = mid - 1;
                }
                return best >= 0 && pc - Sorted[best].Start < Sorted[best].Range ? Sorted[best] : null;
            }
            long l = 0, h = Count - 1, found = -1;
            ulong fdeVa = 0;
            while (l <= h)
            {
                long mid = (l + h) >>> 1;
                long pos = TableAt + mid * EntrySize;
                if (!Elf.EhFrame.TryReadPointer(Hdr, ref pos, TableEncoding, HdrVa, HdrVa, is64, out ulong start)
                    || !Elf.EhFrame.TryReadPointer(Hdr, ref pos, TableEncoding, HdrVa, HdrVa, is64, out ulong at)) return null;
                if (start <= pc) { found = mid; fdeVa = at; l = mid + 1; }
                else h = mid - 1;
            }
            if (found < 0 || fdeVa < EhFrameVa) return null;
            var fde = Elf.EhFrame.ReadFullFdeAt(EhFrame, (long)Math.Min(fdeVa - EhFrameVa, long.MaxValue), EhFrameVa, is64, cies);
            return fde != null && pc >= fde.Start && pc - fde.Start < fde.Range ? fde : null;
        }
    }

    private CfiIndex? BuildCfi()
    {
        var section = file?.Section(".eh_frame");
        ulong ehVa = section is { IsAllocated: true, Size: > 0 } ? section.Address : 0;
        ByteView hdr = default;
        ulong hdrVa = 0;
        byte tableEnc = EhFrame.Omit;
        long tableAt = 0;
        ulong count = 0;
        if (segments.FirstOrDefault(s => s.Type == 0x6474E550) is { } hdrSegment)
        {
            hdrVa = hdrSegment.VirtualAddress;
            var bytes = ReadLink(hdrVa, hdrSegment.MemorySize, MaxHdrBytes);
            hdr = new ByteView(bytes, bigEndian);
            if (hdr.Length >= 4 && hdr.U8(0) == 1)
            {
                long pos = 4;
                if (EhFrame.TryReadPointer(hdr, ref pos, hdr.U8(1), hdrVa, hdrVa, is64, out ulong fromHdr))
                {
                    ehVa = fromHdr;
                    if (EhFrame.TryReadPointer(hdr, ref pos, hdr.U8(2), hdrVa, hdrVa, is64, out count)) (tableEnc, tableAt) = (hdr.U8(3), pos);
                }
            }
        }
        if (ehVa == 0) return null;
        ulong size = section is { } sec && sec.Address == ehVa ? sec.Size
            : segments.FirstOrDefault(s => s.IsLoad && ehVa >= s.VirtualAddress && ehVa - s.VirtualAddress < s.MemorySize) is { } load
                ? load.VirtualAddress + load.MemorySize - ehVa : 0x10000;
        var eh = new ByteView(ReadLink(ehVa, size, MaxEhFrameBytes), bigEndian);
        if (eh.Length < 8) return null;
        var index = new CfiIndex(eh, ehVa, is64);
        long entrySize = (tableEnc & 0x0F) switch { 0x02 or 0x0A => 4, 0x03 or 0x0B => 8, 0x04 or 0x0C => 16, 0x00 => is64 ? 16 : 8, _ => 0 };
        if (tableEnc != EhFrame.Omit && entrySize > 0 && count > 0)
        {
            index.Hdr = hdr;
            index.HdrVa = hdrVa;
            index.TableEncoding = tableEnc;
            index.TableAt = tableAt;
            index.EntrySize = entrySize;
            index.Count = (long)Math.Min(count, (ulong)Math.Max(0, (hdr.Length - tableAt) / entrySize));
        }
        else
        {
            index.Sorted = EhFrame.WalkFull(eh, ehVa, is64, 1 << 20);
            index.Sorted.Sort((a, b) => a.Start.CompareTo(b.Start));
        }
        return index;
    }

    private List<ElfCoreSymbol> FileSymbols()
    {
        var f = file!;
        var exported = new HashSet<uint>(f.Exports.Select(e => e.Rva));
        var list = f.Symbols.Where(s => s.Kind == ImageSymbolKind.Function)
            .Select(s => new ElfCoreSymbol(f.ImageBase + s.Rva + Bias, s.Size, s.Name, exported.Contains(s.Rva) ? "export" : "symbol")).ToList();
        list.Sort((a, b) => a.Start.CompareTo(b.Start));
        return list;
    }

    /// <summary>.dynsym through PT_DYNAMIC: the count from DT_HASH, else the gap up to DT_STRTAB.</summary>
    private List<ElfCoreSymbol> MemorySymbols()
    {
        var result = new List<ElfCoreSymbol>();
        if (segments.FirstOrDefault(s => s.Type == 2) is not { } dyn) return result;
        int word = is64 ? 8 : 4;
        var table = new ByteView(ReadLink(dyn.VirtualAddress, dyn.MemorySize, 0x4000), bigEndian);
        ulong symtab = 0, strtab = 0, strsz = 0, hash = 0, syment = is64 ? 24u : 16u;
        ulong linkLow = segments.Where(s => s.IsLoad).Select(s => s.VirtualAddress).DefaultIfEmpty(0UL).Min();
        ulong linkHigh = segments.Where(s => s.IsLoad).Select(s => s.VirtualAddress + s.MemorySize).DefaultIfEmpty(0UL).Max();
        // glibc relocates d_ptr entries in place; Android's linker does not
        ulong Ptr(ulong v) => v >= linkLow && v < linkHigh ? v : v - Bias;
        for (long at = 0; at + 2 * word <= table.Length; at += 2 * word)
        {
            ulong tag = table.Word(at, is64), value = table.Word(at + word, is64);
            if (tag == 0) break;
            switch (tag)
            {
                case 4: hash = Ptr(value); break;
                case 5: strtab = Ptr(value); break;
                case 6: symtab = Ptr(value); break;
                case 10: strsz = value; break;
                case 11: if (value is 16 or 24) syment = value; break;
            }
        }
        if (symtab == 0 || strtab == 0) return result;
        ulong count = 0;
        if (hash != 0)
        {
            Span<byte> b = stackalloc byte[8];
            if (ReadLink(hash, b) == 8) count = new ByteView(b.ToArray(), bigEndian).U32(4);
        }
        if (count == 0 && strtab > symtab) count = (strtab - symtab) / syment;
        count = Math.Min(count, MaxDynamicSymbols);
        var syms = new ByteView(ReadLink(symtab, count * syment, (int)(MaxDynamicSymbols * syment)), bigEndian);
        var strings = new ByteView(ReadLink(strtab, strsz > 0 ? strsz : 1 << 20, 1 << 24), bigEndian);
        for (long at = 0; at + (long)syment <= syms.Length; at += (long)syment)
        {
            uint name = syms.U32(at);
            byte info = is64 ? syms.U8(at + 4) : syms.U8(at + 12);
            ushort shndx = is64 ? syms.U16(at + 6) : syms.U16(at + 14);
            ulong value = is64 ? syms.U64(at + 8) : syms.U32(at + 4);
            ulong size = is64 ? syms.U64(at + 16) : syms.U32(at + 8);
            if ((info & 0xF) is not (2 or 10) || shndx == 0 || value == 0) continue;
            if (strings.CString(name, 1024) is not { Length: > 0 } text) continue;
            result.Add(new ElfCoreSymbol(value + Bias, size, text, "export"));
        }
        result.Sort((a, b) => a.Start.CompareTo(b.Start));
        return result;
    }

    /// <summary>
    /// The module's file on disk: its recorded path, then each folder by file name and as a sysroot (folder + path).
    /// A file whose GNU build id equals the core's matches; without a build id in the core, the first ELF file of the
    /// core's machine matches by name. Path is the match, else the first file found (a mismatch), else null.
    /// </summary>
    public static (string? Path, bool Matches, string Detail) Find(ElfCoreModule module, IReadOnlyList<string> directories, ushort machine,
        Func<string, (ushort Machine, string? BuildId)?> probe)
    {
        string recorded = module.Module.Path.EndsWith(" (deleted)", StringComparison.Ordinal) ? module.Module.Path[..^10] : module.Module.Path;
        string name = recorded.Split('/')[^1];
        var candidates = new List<string>();
        void Add(Func<string> make)
        {
            try { candidates.Add(System.IO.Path.GetFullPath(make())); }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { }
        }
        if (recorded.StartsWith('/') && OperatingSystem.IsLinux()) Add(() => recorded);
        foreach (var dir in directories)
        {
            if (name.Length > 0) Add(() => System.IO.Path.Combine(dir, name));
            if (recorded.Length > 1) Add(() => System.IO.Path.Combine(dir, recorded.TrimStart('/').Replace('/', System.IO.Path.DirectorySeparatorChar)));
        }
        var why = new StringBuilder();
        string? existing = null;
        foreach (var path in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!File.Exists(path)) continue;
            existing ??= path;
            if (probe(path) is not var (fileMachine, buildId)) { why.Append($"{path}: not an ELF image; "); continue; }
            if (fileMachine != machine) { why.Append($"{path}: another machine ({ElfNames.Machine(fileMachine)}); "); continue; }
            if (module.BuildId == null) return (path, true, $"matched by name (the core does not hold the module's build id{(buildId != null ? $"; the file's is {buildId}" : "")})");
            if (string.Equals(buildId, module.BuildId, StringComparison.OrdinalIgnoreCase)) return (path, true, $"build id {module.BuildId} matches");
            why.Append($"{path}: build id {buildId ?? "none"}, the core's is {module.BuildId}; ");
        }
        string detail = why.Length > 0 ? why.ToString().TrimEnd(' ', ';') : name.Length > 0 ? $"no file named {name} in {string.Join(", ", directories)}" : "no file name";
        return (existing, false, detail);
    }
}
