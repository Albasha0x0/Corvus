using System.Buffers.Binary;

namespace Corvus.Native.Code;

/// <summary>Limits of a code analysis run; anything cut is reported as a truncation.</summary>
public sealed record CodeIndexOptions
{
    public int MaxFunctions { get; init; } = 4_000_000;
    public int MaxInstructionsPerFunction { get; init; } = 1_000_000;
    public long MaxXrefs { get; init; } = 200_000_000;
    public int MaxSwitchEntries { get; init; } = 16_384;
    public int MaxStringLength { get; init; } = 4096;
    /// <summary>Rounds of noreturn propagation; each re-walks only callers of newly found noreturn functions.</summary>
    public int MaxNoReturnRounds { get; init; } = 64;
    /// <summary>x86: search gaps between known code for prologues.</summary>
    public bool ScanPrologues { get; init; } = true;
    /// <summary>0 = one worker per processor.</summary>
    public int MaxParallelism { get; init; }
    /// <summary>PDB function starts used as roots, kept when they are in code.</summary>
    public IReadOnlyCollection<uint>? SymbolStarts { get; init; }
    /// <summary>Resolve virtual call sites through MSVC RTTI (<see cref="NativeCodeIndex.VirtualCalls"/>).</summary>
    public bool ResolveVirtualCalls { get; init; } = true;
    /// <summary>A virtual call site with more implementations than this gets no edges (too_many_targets).</summary>
    public int MaxVirtualTargets { get; init; } = 64;
    /// <summary>Weak candidate batch size from which verification runs in parallel; the result is the same.</summary>
    internal int ParallelVerifyBatch { get; init; } = 4096;
    /// <summary>Queued roots from which discovery explores in parallel; the result is the same.</summary>
    internal int ParallelExploreMin { get; init; } = 256;
}

/// <summary>What the analysis knows about the image while it runs: shared, read-only during each pass.</summary>
internal sealed class CodeContext
{
    public INativeImage Image { get; }
    public ImageCode Code { get; }
    public CodeIndexOptions Options { get; }
    public uint[] Relocations { get; }
    /// <summary>Import slot RVA -> import.</summary>
    public Dictionary<uint, NativeImport> ImportSlots { get; } = [];
    /// <summary>x64 .pdata: primary function start -> its ranges (primary and chained fragments).</summary>
    public Dictionary<uint, List<(uint Begin, uint End)>> PdataRanges { get; } = [];
    /// <summary>ARM64: .pdata entries of function parts without a prologue; they join the function whose flow reaches them.</summary>
    public HashSet<uint> PdataFragments { get; } = [];
    /// <summary>All .pdata ranges sorted by begin, with their primary start.</summary>
    public (uint Begin, uint End, uint Primary)[] PdataSorted { get; private set; } = [];

    /// <summary>x64: language-specific handlers named by unwind information.</summary>
    public HashSet<uint> ExceptionHandlers { get; } = [];
    /// <summary>Functions listed in the Control Flow Guard function table.</summary>
    public List<uint> GuardCfFunctions { get; } = [];

    /// <summary>Known function starts during a pass.</summary>
    public HashSet<uint> FunctionStarts { get; set; } = [];
    /// <summary>Functions (and import slots) known not to return.</summary>
    public HashSet<uint> NoReturn { get; set; } = [];
    /// <summary>Functions whose callers resume after the call although their own code shows no return (Go's morestack).</summary>
    public HashSet<uint> Returns { get; } = [];
    /// <summary>Call targets that are part of their only caller's function, such as x86 __finally blocks: not functions.</summary>
    public HashSet<uint> LocalSubroutines { get; } = [];
    /// <summary>Itanium landing pads by owning function: explored, never functions, attached as chunks.</summary>
    public List<(uint Function, uint Pad, bool Catches)> LandingPads { get; set; } = [];
    /// <summary>x86 functions that run in another function's frame (see <see cref="FunctionFlags.Funclet"/>).</summary>
    public HashSet<uint> Funclets { get; } = [];
    /// <summary>Thunk start -> import slot.</summary>
    public Dictionary<uint, uint> Thunks { get; } = [];
    /// <summary>The walk collects string lengths code loads beside addresses (Rust builds; <see cref="StringHints"/>).</summary>
    public bool RustStrings { get; set; }
    /// <summary>The walk collects Swift small strings from immediates (builds that load the Swift runtime).</summary>
    public bool SwiftStrings { get; set; }

    public CodeContext(INativeImage image, ImageCode code, CodeIndexOptions options)
    {
        Image = image;
        Code = code;
        Options = options;
        var relocs = image.RelocationRvas.ToArray();
        if (!IsSorted(relocs)) Array.Sort(relocs);
        Relocations = relocs;
        CodeRelocations = relocs.Where(code.IsCode).ToArray();
        bool underscore = image.Format == ImageFormat.MachO;
        foreach (var imp in image.Imports)
        {
            ImportSlots.TryAdd(imp.SlotRva, imp);
            if (imp.Name != null && NoReturnNames.IsNoReturn(imp.Name, underscore)) NoReturn.Add(imp.SlotRva);
        }
        foreach (var s in image.Symbols)
            if (s.Kind == ImageSymbolKind.Function && code.IsCode(s.Rva) && NoReturnNames.IsNoReturn(s.Name, underscore)) NoReturn.Add(s.Rva);
        foreach (var g in Go.GoFunctionTable.Of(image)?.Functions ?? [])
            if (g.Name != null && code.IsCode(g.Rva))
            {
                if (NoReturnNames.IsGoNoReturn(g.Name)) NoReturn.Add(g.Rva);
                else if (NoReturnNames.IsGoResumed(g.Name)) Returns.Add(g.Rva);
            }
        DataInCode = DataRanges(image);
        if (image.Arch == NativeArch.Arm) ArmModes = new Arm32Modes(image);
        if (image.Arch is NativeArch.X64 or NativeArch.Arm64 or NativeArch.Arm) ReadPdata();
        ReadGuardCfTable();
        IsKernelMode = KernelModeByName(image.Path)
            || image.Imports.Any(i => i.Module.Equals("ntoskrnl.exe", StringComparison.OrdinalIgnoreCase) || i.Module.Equals("hal.dll", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Byte ranges inside code sections that hold data (Mach-O LC_DATA_IN_CODE, ELF $d mapping symbols), sorted.</summary>
    public (uint Start, uint End)[] DataInCode { get; }

    /// <summary>32-bit ARM: the ARM or Thumb state of each function; null for other instruction sets.</summary>
    public Arm32Modes? ArmModes { get; }

    private static (uint Start, uint End)[] DataRanges(INativeImage image)
    {
        var ranges = new List<(uint, uint)>();
        switch (image)
        {
            case MachO.MachOFile m:
                foreach (var d in m.DataInCode) if (d.Length > 0) ranges.Add((d.Rva, d.Rva + d.Length));
                break;
            case Elf.ElfFile e:
                var marks = e.MappingSymbols;
                for (int i = 0; i < marks.Count; i++)
                {
                    if (marks[i].Kind != 'd') continue;
                    uint start = marks[i].Rva;
                    // A data run ends at the next mapping symbol or its section's end.
                    uint end = i + 1 < marks.Count ? marks[i + 1].Rva : image.SectionAt(start) is { } s ? s.Rva + s.MappedSize : start;
                    if (image.SectionAt(start) is { } sec && end > sec.Rva + sec.MappedSize) end = sec.Rva + sec.MappedSize;
                    if (end > start) ranges.Add((start, end));
                }
                break;
        }
        ranges.Sort();
        return [.. ranges];
    }

    private (uint Slot, long Bit, uint Target)[]? _relocatedCodePointers;

    /// <summary>Relocated pointers into code with the slot's code index bit (-1 outside code); ARM32 targets keep their Thumb bit.</summary>
    public (uint Slot, long Bit, uint Target)[] RelocatedCodePointers(CancellationToken ct)
    {
        if (_relocatedCodePointers != null) return _relocatedCodePointers;
        var result = new List<(uint, long, uint)>();
        int i = 0;
        foreach (var reloc in Relocations)
        {
            if ((++i & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
            if (!TryReadPointer(reloc, out uint target) || !Code.IsCode(target)) continue;
            result.Add((reloc, Code.BitIndex(reloc), target));
        }
        return _relocatedCodePointers = [.. result];
    }

    private (uint Slot, uint Target)[]? _unrelocatedPointers;

    /// <summary>Without relocations: aligned data values pointing into code in runs of two or more; empty when the image has relocations.</summary>
    public (uint Slot, uint Target)[] UnrelocatedPointers()
    {
        if (_unrelocatedPointers != null) return _unrelocatedPointers;
        var result = new List<(uint, uint)>();
        if (Relocations.Length == 0)
        {
            int size = PointerSize;
            var buffer = new byte[1 << 16];
            // Go offset tables can hold values that fall in code when the image base is low.
            var go = Go.GoFunctionTable.Of(Image);
            bool Skipped(uint slot) => ImportSlots.ContainsKey(slot) || (go != null && slot - go.Rva < go.Size);
            foreach (var s in Image.Sections)
            {
                if (s.IsExecutable || s.Rva == 0 || s.Rva >= Image.SizeOfImage || s.Name.EndsWith("typelink", StringComparison.Ordinal)) continue;
                long length = Image.FileBytesLength(s);
                uint start = (s.Rva + (uint)size - 1) & ~((uint)size - 1);
                uint previous = 0, previousTarget = 0;
                bool previousAdded = false;
                for (uint at = start; at + size <= s.Rva + length; at += (uint)buffer.Length)
                {
                    int n = Read(at, buffer.AsSpan(0, (int)Math.Min(buffer.Length, s.Rva + length - at))) / size * size;
                    for (int p = 0; p < n; p += size)
                    {
                        ulong va = size == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(p)) : BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(p));
                        if (va < Image.ImageBase || va - Image.ImageBase >= Image.SizeOfImage) continue;
                        uint target = (uint)(va - Image.ImageBase);
                        uint slot = at + (uint)p;
                        if (!Code.IsCode(target) || Skipped(slot)) continue;
                        if (previous != 0 && slot - previous == size)
                        {
                            if (!previousAdded) result.Add((previous, previousTarget));
                            result.Add((slot, target));
                            previousAdded = true;
                        }
                        else previousAdded = false;
                        previous = slot;
                        previousTarget = target;
                    }
                    if (n < size) break;
                }
            }
        }
        return _unrelocatedPointers = [.. result];
    }

    private (uint Start, uint End)[]? _declared;

    /// <summary>Inside, not at the start of, a function whose extent the image declares.</summary>
    public bool InsideDeclared(uint rva)
    {
        if (_declared == null)
        {
            var list = Image.DeclaredFunctions.Where(d => d.Size is > 0).Select(d => (d.Rva, d.Rva + d.Size!.Value)).ToList();
            if (Go.GoFunctionTable.Of(Image) is { } go) list.AddRange(go.Functions.Where(f => f.Size > 0).Select(f => (f.Rva, f.Rva + f.Size)));
            list.Sort();
            _declared = [.. list];
        }
        int lo = 0, hi = _declared.Length - 1, best = -1;
        while (lo <= hi) { int mid = (lo + hi) >>> 1; if (_declared[mid].Start <= rva) { best = mid; lo = mid + 1; } else hi = mid - 1; }
        // Extents may nest: look back over a few.
        for (int i = best; i >= 0 && i > best - 8; i--)
            if (rva > _declared[i].Start && rva < _declared[i].End) return true;
        return false;
    }

    /// <summary>The file name alone marks a kernel-mode image (a driver, or the kernel): the one input besides the bytes.</summary>
    public static bool KernelModeByName(string path) =>
        path.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) || System.IO.Path.GetFileName(path).Equals("ntoskrnl.exe", StringComparison.OrdinalIgnoreCase);

    private static bool IsSorted(uint[] a)
    {
        for (int i = 1; i < a.Length; i++) if (a[i - 1] > a[i]) return false;
        return true;
    }

    private void ReadPdata()
    {
        var entries = Image.RuntimeFunctions;
        var byBegin = new Dictionary<uint, RuntimeFunction>();
        foreach (var rf in entries) byBegin.TryAdd(rf.BeginRva, rf);
        // Chains are followed in parallel; handlers are added in entry order afterwards.
        var primaries = new uint[entries.Count];
        var handlers = new uint[entries.Count];
        var po = new ParallelOptions { MaxDegreeOfParallelism = Options.MaxParallelism > 0 ? Options.MaxParallelism : Environment.ProcessorCount };
        if (entries.Count > 0) Parallel.ForEach(System.Collections.Concurrent.Partitioner.Create(0, entries.Count, 4096), po, range =>
        {
            for (int i = range.Item1; i < range.Item2; i++)
            {
                var rf = entries[i];
                if (rf.EndRva <= rf.BeginRva) continue;
                // ARM and ARM64 .pdata have no chained entries: each one is a function.
                primaries[i] = Image.Arch == NativeArch.X64 ? PrimaryOf(rf, byBegin, out handlers[i]) : rf.BeginRva;
            }
        });
        if (Image.Arch == NativeArch.X64 && Image.Format == ImageFormat.Pe && NativeAot.NativeAotLocator.HasMarkers(Image)) FindAotFunclets(entries, primaries);
        var keys = new ulong[entries.Count];
        var sorted = new (uint, uint, uint)[entries.Count];
        int n = 0;
        for (int i = 0; i < entries.Count; i++)
        {
            var rf = entries[i];
            if (rf.EndRva <= rf.BeginRva) continue;
            if (handlers[i] != 0) ExceptionHandlers.Add(handlers[i]);
            if (rf.Fragment && Image.Arch == NativeArch.Arm64) PdataFragments.Add(rf.BeginRva);
            uint primary = primaries[i];
            if (!PdataRanges.TryGetValue(primary, out var list)) PdataRanges[primary] = list = [];
            list.Add((rf.BeginRva, rf.EndRva));
            keys[n] = (ulong)rf.BeginRva << 32 | (uint)n;
            sorted[n++] = (rf.BeginRva, rf.EndRva, primary);
        }
        // Entries sharing a begin stay in .pdata order.
        KeySort.Sort(ref keys, ref sorted, n, Options.MaxParallelism);
        PdataSorted = sorted[..n];
    }

    /// <summary>x64 NativeAOT: handler and filter funclet -> its method and kind.</summary>
    public Dictionary<uint, (uint Parent, Msvc.MsvcEhChildKind Kind)> AotFunclets { get; } = [];

    /// <summary>x64 NativeAOT: joins funclets to their method by the kind byte after the unwind codes (0 method, 1 handler, 2 filter).</summary>
    private void FindAotFunclets(IReadOnlyList<RuntimeFunction> entries, uint[] primaries)
    {
        var order = Enumerable.Range(0, entries.Count).Where(i => primaries[i] == entries[i].BeginRva && entries[i].EndRva > entries[i].BeginRva)
            .OrderBy(i => entries[i].BeginRva).ToArray();
        Span<byte> header = stackalloc byte[4];
        Span<byte> code = stackalloc byte[4];
        uint? parent = null;
        uint previousEnd = 0;
        foreach (int i in order)
        {
            var rf = entries[i];
            bool contiguous = rf.BeginRva == previousEnd;
            previousEnd = rf.EndRva;
            if (Read(rf.UnwindInfoRva, header) < 4) { parent = null; continue; }
            uint at = rf.UnwindInfoRva + 4 + 2u * header[2];
            if (((header[0] >> 3) & 3) != 0) at = ((at + 3) & ~3u) + 4;
            if (Read(at, code[..1]) < 1) { parent = null; continue; }
            int flags = code[0];
            if ((flags & 3) == 0)
            {
                // A method: no flag besides EH info, reverse P/Invoke and associated data.
                parent = (flags & 0xE0) == 0 ? rf.BeginRva : null;
                continue;
            }
            if (!contiguous || parent is not { } p || Read(rf.BeginRva, code) < 4 || !(code[0] == 0x48 && code[1] is 0x83 or 0x81 && code[2] == 0xEC))
            {
                parent = null;
                continue;
            }
            primaries[i] = p;
            AotFunclets[rf.BeginRva] = (p, (flags & 3) == 2 ? Msvc.MsvcEhChildKind.Filter : Msvc.MsvcEhChildKind.Catch);
        }
    }

    /// <summary>Follows UNW_FLAG_CHAININFO links to the primary function; <paramref name="handler"/> is the code handler named last, else 0.</summary>
    private uint PrimaryOf(RuntimeFunction rf, Dictionary<uint, RuntimeFunction> byBegin, out uint handler)
    {
        handler = 0;
        Span<byte> header = stackalloc byte[4];
        Span<byte> chained = stackalloc byte[12];
        var current = rf;
        for (int depth = 0; depth < 32; depth++)
        {
            uint unwind = current.UnwindInfoRva;
            if ((unwind & 1) != 0)
            {
                // Indirect: the unwind data field points at another RUNTIME_FUNCTION.
                if (Read(unwind & ~1u, chained) < 12) return current.BeginRva;
                uint begin = BinaryPrimitives.ReadUInt32LittleEndian(chained);
                if (begin == current.BeginRva || !byBegin.TryGetValue(begin, out var next)) return current.BeginRva;
                current = next;
                continue;
            }
            if (Read(unwind, header) < 4) return current.BeginRva;
            int flags = header[0] >> 3;
            int codes = header[2];
            uint at = unwind + 4 + (uint)(((codes + 1) & ~1) * 2);
            if ((flags & 4) == 0)
            {
                // UNW_FLAG_EHANDLER / UNW_FLAG_UHANDLER: the handler RVA follows the unwind codes.
                if ((flags & 3) != 0 && Read(at, chained[..4]) == 4)
                {
                    uint named = BinaryPrimitives.ReadUInt32LittleEndian(chained);
                    if (Code.IsCode(named)) handler = named;
                }
                return current.BeginRva;
            }
            if (Read(at, chained) < 12) return current.BeginRva;
            uint parent = BinaryPrimitives.ReadUInt32LittleEndian(chained);
            if (parent == current.BeginRva) return current.BeginRva;
            current = byBegin.TryGetValue(parent, out var p) ? p : new RuntimeFunction(parent, BinaryPrimitives.ReadUInt32LittleEndian(chained[4..]), BinaryPrimitives.ReadUInt32LittleEndian(chained[8..]));
        }
        return current.BeginRva;
    }

    /// <summary>Reads the load configuration's GuardCFFunctionTable: RVAs of every address-taken function.</summary>
    private void ReadGuardCfTable()
    {
        var b = new byte[8];
        uint U32(uint rva) => Read(rva, b.AsSpan(0, 4)) == 4 ? BinaryPrimitives.ReadUInt32LittleEndian(b) : 0;
        ulong U64(uint rva) => Read(rva, b) == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(b) : 0;
        uint nt = U32(0x3C);
        if (nt == 0 || nt > 0x10000 || U32(nt) != 0x4550) return;
        uint opt = nt + 24;
        bool pe64 = (U32(opt) & 0xFFFF) == 0x20B;
        uint dirCount = U32(opt + (pe64 ? 108u : 92u));
        if (dirCount <= 10) return;
        uint dir = opt + (pe64 ? 112u : 96u) + 10 * 8;
        uint lc = U32(dir), lcSize = U32(dir + 4);
        if (lc == 0 || lcSize == 0) return;
        if (U32(lc) < (pe64 ? 0x94u : 0x5Cu)) return; // the structure's own Size field
        ulong tableVa = pe64 ? U64(lc + 0x80) : U32(lc + 0x50);
        ulong count = pe64 ? U64(lc + 0x88) : U32(lc + 0x54);
        uint guardFlags = U32(lc + (pe64 ? 0x90u : 0x58u));
        if ((guardFlags & 0x400) == 0 || tableVa < Image.ImageBase || count == 0) return; // IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT
        uint table = (uint)(tableVa - Image.ImageBase);
        uint stride = 4 + ((guardFlags >> 28) & 0xF);
        count = Math.Min(count, (ulong)Options.MaxFunctions);
        var raw = new byte[checked((int)Math.Min(count * stride, int.MaxValue / 2))];
        int n = Read(table, raw) / (int)stride;
        for (int i = 0; i < n; i++)
        {
            uint rva = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(i * (int)stride));
            if (Image.Arch == NativeArch.Arm) rva &= ~1u; // Thumb bit
            if (Code.IsCode(rva)) GuardCfFunctions.Add(rva);
        }
    }

    /// <summary>The primary .pdata function whose ranges contain <paramref name="rva"/>, or null.</summary>
    public uint? PdataOwner(uint rva)
    {
        var a = PdataSorted;
        int lo = 0, hi = a.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (rva < a[mid].Begin) hi = mid - 1;
            else if (rva >= a[mid].End) lo = mid + 1;
            else return a[mid].Primary;
        }
        return null;
    }

    public bool IsRelocated(uint rva) => Array.BinarySearch(Relocations, rva) >= 0;

    /// <summary>A kernel-mode image (driver, kernel, HAL): privileged instructions are expected there.</summary>
    public bool IsKernelMode { get; }

    /// <summary>Relocations inside executable code (instruction operands, x86 tables): all a code decoder needs to look up.</summary>
    public uint[] CodeRelocations { get; }

    public ICodeDecoder NewDecoder(bool computeAccess)
    {
        X86Decoder X86() => new(Image, Code, CodeRelocations, is64: Image.Is64Bit)
        {
            ComputeAccess = computeAccess, RejectImplausible = !IsKernelMode, CheckRelocations = true, ImageHasRelocations = Relocations.Length > 0,
        };
        var primary = Image.Arch is NativeArch.X86 or NativeArch.X64 ? X86() : CodeDecoders.Create(Image, Code, Relocations, ImportSlotSet, DataInCode, ArmModes);
        if (Code.OtherRanges.Length == 0) return primary;
        ICodeDecoder other = Image.Arch == NativeArch.Arm64 ? X86() : new Arm64Decoder(Image, Code, Relocations, ImportSlotSet, DataInCode);
        return new HybridDecoder(primary, other, Code.OtherRanges);
    }

    private HashSet<uint>? _importSlotSet;
    private HashSet<uint> ImportSlotSet => _importSlotSet ??= [.. ImportSlots.Keys];

    private readonly Lock _readLock = new();

    /// <summary><see cref="INativeImage.Read"/>, serialized: walks run in parallel and the contract does not promise thread safety.</summary>
    public int Read(uint rva, Span<byte> destination)
    {
        lock (_readLock) return Image.Read(rva, destination);
    }

    public int PointerSize => Image.Is64Bit ? 8 : 4;

    /// <summary>Reads a pointer-sized value at <paramref name="rva"/> and converts it to an RVA inside the image.</summary>
    public bool TryReadPointer(uint rva, out uint target)
    {
        target = 0;
        Span<byte> b = stackalloc byte[8];
        int size = PointerSize;
        if (Read(rva, b[..size]) < size) return false;
        ulong va = size == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b);
        if (va < Image.ImageBase || va - Image.ImageBase >= Image.SizeOfImage) return false;
        target = (uint)(va - Image.ImageBase);
        return true;
    }

    /// <summary>The case targets of a matched switch; null with the reason when an entry is not valid code.</summary>
    public SwitchTable? ReadSwitch(uint jumpRva, SwitchMatch m, List<(uint Begin, uint End)>? ownRanges, out string reason)
    {
        reason = "";
        if (m.BaseAssumed && ownRanges == null) { reason = "image base register set outside the dispatch sequence"; return null; }
        uint count = m.Count;
        byte[]? index = null;
        if (m.IndexTableRva is { } it)
        {
            if (m.IndexTableCount == 0 || m.IndexTableCount > Options.MaxSwitchEntries) { reason = $"index table of {m.IndexTableCount} entries"; return null; }
            index = new byte[m.IndexTableCount];
            if (Read(it, index) < index.Length) { reason = "index table outside the image"; return null; }
            count = (uint)index.Max() + 1;
        }
        if (count == 0 || count > Options.MaxSwitchEntries) { reason = $"table of {count} entries (limit {Options.MaxSwitchEntries})"; return null; }
        int size = m.EntrySize;
        var raw = new byte[m.Direct ? 0 : count * size];
        if (Read(m.TableRva, raw) < raw.Length) { reason = "table outside the image"; return null; }
        var targets = new List<uint>((int)count);
        var entries = new uint[count];
        var seen = new HashSet<uint>();
        bool aligned = Image.Arch == NativeArch.Arm64;
        for (int i = 0; i < count; i++)
        {
            var e = m.Direct ? default : raw.AsSpan(i * size, size);
            long entry = m.Direct ? i : size switch
            {
                1 => m.Signed ? (sbyte)e[0] : e[0],
                2 => m.Signed ? BinaryPrimitives.ReadInt16LittleEndian(e) : BinaryPrimitives.ReadUInt16LittleEndian(e),
                8 => (long)BinaryPrimitives.ReadUInt64LittleEndian(e),
                _ => m.Signed ? BinaryPrimitives.ReadInt32LittleEndian(e) : BinaryPrimitives.ReadUInt32LittleEndian(e),
            };
            uint target;
            if (m.Absolute)
            {
                if (Relocations.Length > 0 && !IsRelocated(m.TableRva + (uint)(i * size))) { reason = $"entry {i} is not relocated"; return null; }
                ulong va = size == 8 ? (ulong)entry : (uint)entry;
                if (va < Image.ImageBase || va - Image.ImageBase >= Image.SizeOfImage) { reason = $"entry {i} points outside the image"; return null; }
                target = (uint)(va - Image.ImageBase);
            }
            else if (m.Base is { } b) target = (uint)(b + (entry << m.Shift));
            else if (m.RelativeToTable) target = (uint)(m.TableRva + (int)entry);
            else target = (uint)entry;
            // ARM32 entries may carry the Thumb bit.
            if (Image.Arch == NativeArch.Arm) target &= ~1u;
            if (!Code.IsCode(target)) { reason = $"entry {i} ({target:X}) is not in executable code"; return null; }
            if (aligned && (target & 3) != 0) { reason = $"entry {i} ({target:X}) is not an instruction address"; return null; }
            if (m.Window != 0 && (target > jumpRva ? target - jumpRva : jumpRva - target) > m.Window) { reason = $"entry {i} ({target:X}) is far from the dispatch"; return null; }
            if (m.BaseAssumed && !ownRanges!.Any(r => target >= r.Begin && target < r.End)) { reason = $"entry {i} ({target:X}) is outside the function"; return null; }
            entries[i] = target;
            if (seen.Add(target)) targets.Add(target);
        }
        return new SwitchTable(jumpRva, m.TableRva, (int)count, size, m.IndexTableRva, (int)m.IndexTableCount, targets)
        {
            Cases = Cases(entries, index, targets, m, out var defaultValues),
            DefaultValues = defaultValues,
            Default = m.Default,
            Bias = m.Bias,
            Kind = m.Direct ? SwitchTableKind.Indexed : m.Absolute ? SwitchTableKind.Absolute : m.Base != null ? SwitchTableKind.BaseRelative
                : m.RelativeToTable ? SwitchTableKind.TableRelative : SwitchTableKind.Rva,
            Base = m.Base,
            Shift = m.Shift,
            ValuesExact = !m.BoundByMask && !m.BaseAssumed && !m.BoundByRelocations,
        };
    }

    /// <summary>Switched values per target, in table order: entry i (or index table byte i) is value i + bias.</summary>
    private static List<SwitchCase> Cases(uint[] entries, byte[]? index, List<uint> targets, SwitchMatch m, out List<long> defaultValues)
    {
        var values = new Dictionary<uint, List<long>>();
        int n = index?.Length ?? entries.Length;
        for (int i = 0; i < n; i++)
        {
            uint t = entries[index != null ? index[i] : i];
            if (!values.TryGetValue(t, out var list)) values[t] = list = [];
            list.Add(i + m.Bias);
        }
        defaultValues = m.Default is { } d && values.TryGetValue(d, out var dv) ? dv : [];
        return [.. targets.Where(t => t != m.Default && values.ContainsKey(t)).Select(t => new SwitchCase(t, values[t]))];
    }
}

/// <summary>Second attempts at switch dispatches that the first path to reach them could not bound.</summary>
internal static class SwitchDispatch
{
    private const int MaxInstructions = 160;

    /// <summary>Decodes from <paramref name="from"/> with <paramref name="bound"/> known and matches the switch at <paramref name="jump"/> if reached straight-line.</summary>
    /// <param name="noReturn">Whether a call target never returns (default: the context's set).</param>
    public static SwitchTable? Redecode(ICodeDecoder dec, CodeContext ctx, uint from, IndexBound bound, uint jump, List<(uint Begin, uint End)>? own,
        Func<uint, bool>? noReturn = null)
    {
        dec.BeginRun(bound);
        uint a = from;
        for (int n = 0; n < MaxInstructions && a <= jump; n++)
        {
            if (!dec.Decode(a, out var insn) || insn.Flow == FlowKind.Invalid) return null;
            if (a == jump)
            {
                if (insn.Flow != FlowKind.IndirectJump) return null;
                var m = dec.MatchSwitch(out _);
                return m != null ? ctx.ReadSwitch(jump, m, own, out _) : null;
            }
            if (insn.Flow is FlowKind.Jump or FlowKind.Trap || insn.Flow is FlowKind.Return or FlowKind.IndirectJump && !insn.Conditional) return null;
            if (insn.Flow == FlowKind.Call && insn.HasTarget && (noReturn ?? ctx.NoReturn.Contains)(insn.Target)) return null;
            a = insn.Next;
        }
        return null;
    }
}

/// <summary>Imported and runtime functions that never return to the caller.</summary>
internal static class NoReturnNames
{
    private static readonly HashSet<string> Names = new(StringComparer.Ordinal)
    {
        "ExitProcess", "ExitThread", "FreeLibraryAndExitThread", "RtlExitUserProcess", "RtlExitUserThread",
        "RaiseFailFastException", "RtlFailFast", "RtlRaiseStatus",
        "abort", "exit", "_exit", "_Exit", "quick_exit", "__fastfail",
        "_CxxThrowException", "_invalid_parameter_noinfo_noreturn", "_invoke_watson",
        "__report_gsfailure", "__report_rangecheckfailure", "__std_terminate", "terminate", "_amsg_exit",
        "longjmp", "_longjmp", "__longjmp_chk", "__stack_chk_fail", "__assert_fail", "_assert", "_wassert",
        "siglongjmp", "__stack_chk_fail_local", "__assert", "__assert2", "__assert_rtn", "__chk_fail", "__fortify_fail", "__libc_fatal",
        "pthread_exit", "err", "errx", "verr", "verrx", "__cxa_throw", "__cxa_rethrow", "__cxa_bad_cast", "__cxa_bad_typeid",
        "__cxa_throw_bad_array_new_length", "__cxa_call_unexpected", "_Unwind_Resume", "_ZSt9terminatev", "__clang_call_terminate",
        "_ZSt17__throw_bad_allocv", "_ZSt20__throw_length_errorPKc", "_ZSt24__throw_out_of_range_fmtPKcz", "_ZSt20__throw_out_of_rangePKc",
        "_ZSt19__throw_logic_errorPKc", "_ZSt25__throw_bad_function_callv", "_ZSt16__throw_bad_castv",
        "_ZNSt3__120__throw_length_errorB8ne180000EPKc", "_ZNSt3__120__throw_out_of_rangeB8ne180000EPKc",
        "abort_message", "__libcpp_verbose_abort", "_ZNSt3__122__libcpp_verbose_abortEPKcz", "_ZNSt6__ndk122__libcpp_verbose_abortEPKcz", "__cxa_end_cleanup",
        "?terminate@@YAXXZ", "?_Xbad_alloc@std@@YAXXZ", "?_Xlength_error@std@@YAXPEBD@Z", "?_Xlength_error@std@@YAXPBD@Z",
        "?_Xout_of_range@std@@YAXPEBD@Z", "?_Xout_of_range@std@@YAXPBD@Z", "?_Xinvalid_argument@std@@YAXPEBD@Z",
        "?_Xinvalid_argument@std@@YAXPBD@Z", "?_Xbad_function_call@std@@YAXXZ", "?_Xruntime_error@std@@YAXPEBD@Z",
        "?_Xruntime_error@std@@YAXPBD@Z", "?_Xoverflow_error@std@@YAXPEBD@Z", "?_Xoverflow_error@std@@YAXPBD@Z",
        "?_Throw_Cpp_error@std@@YAXH@Z", "?_Throw_C_error@std@@YAXH@Z", "?_Xregex_error@std@@YAXW4error_type@regex_constants@1@@Z",
    };

    /// <param name="underscore">Mach-O: C names carry an extra leading underscore.</param>
    public static bool IsNoReturn(string name, bool underscore = false) =>
        Names.Contains(name) || (underscore && name.Length > 1 && name[0] == '_' && Names.Contains(name[1..]));

    private static readonly HashSet<string> GoNames = new(StringComparer.Ordinal)
    {
        "runtime.throw", "runtime.fatal", "runtime.fatalthrow", "runtime.fatalpanic", "runtime.gopanic", "runtime.abort", "runtime.exit",
        "runtime.Goexit", "runtime.goexit0", "runtime.goexit1", "runtime.gogo", "runtime.sigpanic", "runtime.morestackc", "runtime.badmorestackg0",
        "runtime.badmorestackgsignal", "runtime.unreachableMethod", "runtime.mstart", "os.Exit", "syscall.Exit",
    };

    /// <summary>Go runtime functions that never return (by their name in the Go function table).</summary>
    public static bool IsGoNoReturn(string name) =>
        GoNames.Contains(name) || (name.StartsWith("runtime.panic", StringComparison.Ordinal) && !name.StartsWith("runtime.panicCheck", StringComparison.Ordinal))
        || name.StartsWith("runtime.goPanic", StringComparison.Ordinal);

    /// <summary>Go's stack growth: the scheduler resumes the caller after the call.</summary>
    public static bool IsGoResumed(string name) => name is "runtime.morestack" or "runtime.morestack_noctxt";
}
