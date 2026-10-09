using System.Buffers.Binary;

namespace NetDecompilerMcp.Native.Code;

/// <summary>Limits of a code analysis run; anything cut is reported as a truncation.</summary>
public sealed record CodeIndexOptions
{
    public int MaxFunctions { get; init; } = 4_000_000;
    public int MaxInstructionsPerFunction { get; init; } = 1_000_000;
    public long MaxXrefs { get; init; } = 200_000_000;
    public int MaxSwitchEntries { get; init; } = 16_384;
    public int MaxStringLength { get; init; } = 4096;
    /// <summary>Rounds of noreturn propagation (each re-walks only the callers of newly found noreturn functions).</summary>
    public int MaxNoReturnRounds { get; init; } = 64;
    /// <summary>x86: search gaps between known code for prologues.</summary>
    public bool ScanPrologues { get; init; } = true;
    /// <summary>0 = one worker per processor.</summary>
    public int MaxParallelism { get; init; }
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
    /// <summary>Fragment start (chained entry) -> primary start.</summary>
    public Dictionary<uint, uint> PdataFragments { get; } = [];
    /// <summary>All .pdata ranges sorted by begin, with their primary start.</summary>
    public (uint Begin, uint End, uint Primary)[] PdataSorted { get; private set; } = [];

    /// <summary>Known function starts during a pass.</summary>
    public HashSet<uint> FunctionStarts { get; set; } = [];
    /// <summary>Functions (and import slots) known not to return.</summary>
    public HashSet<uint> NoReturn { get; set; } = [];
    /// <summary>Thunk start -> import slot.</summary>
    public Dictionary<uint, uint> Thunks { get; } = [];

    public CodeContext(INativeImage image, ImageCode code, CodeIndexOptions options)
    {
        Image = image;
        Code = code;
        Options = options;
        var relocs = image.RelocationRvas.ToArray();
        if (!IsSorted(relocs)) Array.Sort(relocs);
        Relocations = relocs;
        foreach (var imp in image.Imports)
        {
            ImportSlots.TryAdd(imp.SlotRva, imp);
            if (imp.Name != null && NoReturnNames.IsNoReturn(imp.Name)) NoReturn.Add(imp.SlotRva);
        }
        if (image.Arch == NativeArch.X64) ReadPdata();
        IsKernelMode = image.Path.EndsWith(".sys", StringComparison.OrdinalIgnoreCase)
            || image.Imports.Any(i => i.Module.Equals("ntoskrnl.exe", StringComparison.OrdinalIgnoreCase) || i.Module.Equals("hal.dll", StringComparison.OrdinalIgnoreCase))
            || System.IO.Path.GetFileName(image.Path).Equals("ntoskrnl.exe", StringComparison.OrdinalIgnoreCase);
    }

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
        var sorted = new List<(uint, uint, uint)>(entries.Count);
        foreach (var rf in entries)
        {
            if (rf.EndRva <= rf.BeginRva) continue;
            uint primary = PrimaryOf(rf, byBegin);
            if (primary != rf.BeginRva) PdataFragments.TryAdd(rf.BeginRva, primary);
            if (!PdataRanges.TryGetValue(primary, out var list)) PdataRanges[primary] = list = [];
            list.Add((rf.BeginRva, rf.EndRva));
            sorted.Add((rf.BeginRva, rf.EndRva, primary));
        }
        sorted.Sort((a, b) => a.Item1.CompareTo(b.Item1));
        PdataSorted = sorted.ToArray();
    }

    /// <summary>Follows UNW_FLAG_CHAININFO links (x64 UNWIND_INFO) to the function the entry is a fragment of.</summary>
    private uint PrimaryOf(RuntimeFunction rf, Dictionary<uint, RuntimeFunction> byBegin)
    {
        Span<byte> header = stackalloc byte[4];
        Span<byte> chained = stackalloc byte[12];
        var current = rf;
        for (int depth = 0; depth < 32; depth++)
        {
            uint unwind = current.UnwindInfoRva;
            if ((unwind & 1) != 0)
            {
                // indirect: the unwind data field points at another RUNTIME_FUNCTION
                if (Read(unwind & ~1u, chained) < 12) return current.BeginRva;
                uint begin = BinaryPrimitives.ReadUInt32LittleEndian(chained);
                if (begin == current.BeginRva || !byBegin.TryGetValue(begin, out var next)) return current.BeginRva;
                current = next;
                continue;
            }
            if (Read(unwind, header) < 4) return current.BeginRva;
            int flags = header[0] >> 3;
            if ((flags & 4) == 0) return current.BeginRva;
            int codes = header[2];
            uint at = unwind + 4 + (uint)(((codes + 1) & ~1) * 2);
            if (Read(at, chained) < 12) return current.BeginRva;
            uint parent = BinaryPrimitives.ReadUInt32LittleEndian(chained);
            if (parent == current.BeginRva) return current.BeginRva;
            current = byBegin.TryGetValue(parent, out var p) ? p : new RuntimeFunction(parent, BinaryPrimitives.ReadUInt32LittleEndian(chained[4..]), BinaryPrimitives.ReadUInt32LittleEndian(chained[8..]));
        }
        return current.BeginRva;
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

    public X86Decoder NewDecoder(bool computeAccess) =>
        new(Code, Relocations) { ComputeAccess = computeAccess, RejectImplausible = !IsKernelMode };

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

    /// <summary>
    /// Reads the case targets of a matched switch. Every entry must point into executable code (and, for absolute
    /// tables, be covered by a relocation when the image has relocations); otherwise null with the reason.
    /// </summary>
    public SwitchTable? ReadSwitch(uint jumpRva, X86Decoder.SwitchMatch m, List<(uint Begin, uint End)>? ownRanges, out string reason)
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
        var raw = new byte[count * 4];
        if (Read(m.TableRva, raw) < raw.Length) { reason = "table outside the image"; return null; }
        var targets = new List<uint>((int)count);
        var seen = new HashSet<uint>();
        for (int i = 0; i < count; i++)
        {
            uint entry = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(i * 4));
            uint target;
            if (m.Absolute)
            {
                if (Relocations.Length > 0 && !IsRelocated(m.TableRva + (uint)i * 4)) { reason = $"entry {i} is not relocated"; return null; }
                ulong va = entry;
                if (va < Image.ImageBase || va - Image.ImageBase >= Image.SizeOfImage) { reason = $"entry {i} points outside the image"; return null; }
                target = (uint)(va - Image.ImageBase);
            }
            else if (m.RelativeToTable) target = (uint)(m.TableRva + (int)entry);
            else target = entry;
            if (!Code.IsCode(target)) { reason = $"entry {i} ({target:X}) is not in executable code"; return null; }
            if (m.BaseAssumed && !ownRanges!.Any(r => target >= r.Begin && target < r.End)) { reason = $"entry {i} ({target:X}) is outside the function"; return null; }
            if (seen.Add(target)) targets.Add(target);
        }
        return new SwitchTable(jumpRva, m.TableRva, (int)count, 4, m.IndexTableRva, targets);
    }
}

/// <summary>Second attempts at switch dispatches that the first path to reach them could not bound.</summary>
internal static class SwitchDispatch
{
    private const int MaxInstructions = 160;

    /// <summary>
    /// Decodes linearly from <paramref name="from"/> with <paramref name="bound"/> known on entry; when that reaches
    /// the indirect jump at <paramref name="jump"/> without leaving the straight-line path, matches its switch table.
    /// </summary>
    public static SwitchTable? Redecode(X86Decoder dec, CodeContext ctx, uint from, IndexBound bound, uint jump, List<(uint Begin, uint End)>? own)
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
            if (insn.Flow is FlowKind.Jump or FlowKind.Return or FlowKind.IndirectJump or FlowKind.Trap) return null;
            if (insn.Flow == FlowKind.Call && insn.HasTarget && ctx.NoReturn.Contains(insn.Target)) return null;
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
        "?terminate@@YAXXZ", "?_Xbad_alloc@std@@YAXXZ", "?_Xlength_error@std@@YAXPEBD@Z", "?_Xlength_error@std@@YAXPBD@Z",
        "?_Xout_of_range@std@@YAXPEBD@Z", "?_Xout_of_range@std@@YAXPBD@Z", "?_Xinvalid_argument@std@@YAXPEBD@Z",
        "?_Xinvalid_argument@std@@YAXPBD@Z", "?_Xbad_function_call@std@@YAXXZ", "?_Xruntime_error@std@@YAXPEBD@Z",
        "?_Xruntime_error@std@@YAXPBD@Z", "?_Xoverflow_error@std@@YAXPEBD@Z", "?_Xoverflow_error@std@@YAXPBD@Z",
        "?_Throw_Cpp_error@std@@YAXH@Z", "?_Throw_C_error@std@@YAXH@Z", "?_Xregex_error@std@@YAXW4error_type@regex_constants@1@@Z",
    };

    public static bool IsNoReturn(string name) => Names.Contains(name);
}
