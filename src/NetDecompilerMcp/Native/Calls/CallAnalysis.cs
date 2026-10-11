using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Text;
using Iced.Intel;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Native.Calls;

/// <summary>What an argument value is.</summary>
public enum ArgKind : byte
{
    /// <summary>A number (decoded through the parameter's enumeration or flags when it has one).</summary>
    Immediate,
    /// <summary>The address of a string literal; the text is the string.</summary>
    String,
    /// <summary>An address in the image without a name or string (or a stack buffer).</summary>
    Address,
    /// <summary>An address with a name: a function, an export, an import (a function pointer).</summary>
    Name,
    /// <summary>The return value of an earlier call.</summary>
    Result,
    /// <summary>The contents of a global variable.</summary>
    Global,
    /// <summary>Not recovered; the derivation says why.</summary>
    Unknown,
}

/// <summary>How a call's target was found.</summary>
public enum CalleeKind : byte
{
    /// <summary>An imported function: call [slot], a thunk, or a register loaded from the slot.</summary>
    Import,
    Function,
    /// <summary>A function pointer from GetProcAddress (late-bound import).</summary>
    Dynamic,
    /// <summary>A pointer whose target is not known (virtual call, callback).</summary>
    Indirect,
    /// <summary>A virtual call with one implementation (resolved through RTTI, <see cref="Code.NativeCodeIndex.VirtualCalls"/>).</summary>
    VirtualExact,
    /// <summary>A virtual call with several possible implementations.</summary>
    VirtualPossible,
}

/// <param name="Location">rcx, xmm1, [sp+20h]: where the argument is passed.</param>
/// <param name="Derivation">The instructions it came from, use first ("mov edx, 3 @0x180001234"), or why it is unknown.</param>
public sealed record CallArgument(int Index, string? Name, string? Type, string Location, ArgKind Kind, ulong? Value, uint? Rva, string Text, string Derivation)
{
    /// <summary>The resolved value before formatting.</summary>
    internal Val Raw { get; init; }
}

/// <param name="Guessed">No signature is known: the arguments are the registers / stack slots set just before the call.</param>
public sealed record CallSiteInfo(uint Rva, NativeFunction Caller, string Callee, CalleeKind Kind, NativeImport? Import, uint? Target,
    DynamicImport? Dynamic, ApiSignature? Signature, bool Guessed, IReadOnlyList<CallArgument> Arguments, bool TailCall = false)
{
    /// <summary>"CreateFileW(L"config.ini", GENERIC_READ, ...)".</summary>
    public string Display
    {
        get
        {
            var sb = new StringBuilder(ShortCallee).Append('(');
            for (int i = 0; i < Arguments.Count; i++)
            {
                if (i > 0) sb.Append(", ");
                var a = Arguments[i];
                if (a.Location is "ecx" or "edx" && Guessed) sb.Append(a.Location).Append('=');
                sb.Append(a.Text.Length > 80 ? a.Text[..77] + "..." : a.Text);
                if (sb.Length > 400) { sb.Append(", ..."); break; }
            }
            return sb.Append(')').ToString();
        }
    }

    /// <summary>The callee without its module ("CreateFileW" for kernel32!CreateFileW).</summary>
    public string ShortCallee => Kind is CalleeKind.Import or CalleeKind.Dynamic && Callee.LastIndexOf('!') is var bang and >= 0 ? Callee[(bang + 1)..] : Callee;
}

/// <summary>
/// Call sites of a native image with their targets and argument values, recovered by backward constant propagation
/// (<see cref="ValueResolver"/>) under the platform calling conventions: x64 per <see cref="X64Abi"/> (Microsoft on PE,
/// System V on ELF and Mach-O); x86 the stack slots pushed (or stored) before the call. Known APIs
/// (<see cref="ApiSignatures"/>) give parameter names, counts and constant decoding; other callees get the
/// registers and slots set just before the call. One instance per code index (<see cref="For"/>), thread-safe.
/// </summary>
public sealed partial class CallAnalysis : ITraceHost
{
    private static readonly ConditionalWeakTable<NativeCodeIndex, CallAnalysis> Table = new();
    private const int MaxInstructionsPerFunction = 50_000;
    private const int MaxCachedFunctions = 512;
    private const int MaxGuessedArguments = 12;

    private readonly uint[] _relocs;
    private readonly Dictionary<uint, NativeImport> _slots = [];
    private readonly HashSet<uint> _checkSlots = [];
    private readonly HashSet<uint> _dispatchSlots = [];
    private readonly ConcurrentDictionary<uint, FunctionCode> _code = new();
    private readonly ConcurrentDictionary<uint, IReadOnlyList<CallSiteInfo>> _sites = new();
    private readonly ConcurrentDictionary<uint, int?> _pops = new();

    public NativeCodeIndex Index { get; }
    public INativeImage Image => Index.Image;
    public bool Is64 { get; }
    /// <summary>The x64 convention of the image (unused on x86).</summary>
    internal X64Abi Abi { get; }

    private CallAnalysis(NativeCodeIndex index)
    {
        Index = index;
        Is64 = index.Image.Arch == NativeArch.X64;
        Abi = X64Abi.Of(index.Image);
        _relocs = index.Image.RelocationRvas.ToArray();
        if (!IsSorted(_relocs)) Array.Sort(_relocs);
        foreach (var imp in index.Image.Imports) _slots.TryAdd(imp.SlotRva, imp);
        if (index.Image is PeFile { LoadConfig: { } lc })
        {
            void Add(HashSet<uint> set, ulong va)
            {
                if (va > index.Image.ImageBase && va - index.Image.ImageBase < index.Image.SizeOfImage) set.Add((uint)(va - index.Image.ImageBase));
            }
            Add(_checkSlots, lc.GuardCfCheckFunctionPointer);
            Add(_checkSlots, lc.GuardXfgCheckFunctionPointer);
            Add(_dispatchSlots, lc.GuardCfDispatchFunctionPointer);
            Add(_dispatchSlots, lc.GuardXfgDispatchFunctionPointer);
            Add(_dispatchSlots, lc.GuardXfgTableDispatchFunctionPointer);
        }
    }

    private static bool IsSorted(uint[] a)
    {
        for (int i = 1; i < a.Length; i++) if (a[i] < a[i - 1]) return false;
        return true;
    }

    /// <summary>The analysis of an index (created once per index).</summary>
    /// <exception cref="NotSupportedException">The index does not decode instructions (not x86 / x64).</exception>
    /// <summary>The analysis reads x86 / x64 code; other instruction sets have no call analysis yet.</summary>
    public static bool Supports(NativeCodeIndex index) => index.Support == CodeSupport.Full && index.Image.Arch is NativeArch.X86 or NativeArch.X64;

    public static CallAnalysis For(NativeCodeIndex index)
    {
        if (!Supports(index)) throw new NotSupportedException(index.SupportNote ?? $"call analysis reads x86 / x64 code, not {index.Image.Arch}");
        return Table.GetValue(index, i => new CallAnalysis(i));
    }

    /// <summary>Every call in <paramref name="f"/> (guard-check calls left out), in address order.</summary>
    public IReadOnlyList<CallSiteInfo> CallsIn(NativeFunction f, CancellationToken ct = default)
    {
        EnsureDynamic(ct);
        bool cache = DynamicReady;
        if (cache && _sites.TryGetValue(f.Start, out var hit)) return hit;
        var code = Code(f, ct);
        var result = new List<CallSiteInfo>();
        for (int b = 0; b < code.Blocks.Length; b++)
            for (int i = 0; i < code.Blocks[b].Length; i++)
            {
                ref readonly var d = ref code.Blocks[b][i];
                if (SiteKind(code, in d) == 0) continue;
                ct.ThrowIfCancellationRequested();
                result.Add(Site(code, b, i));
            }
        result.Sort((a, b) => a.Rva.CompareTo(b.Rva));
        // blocks can overlap: one row per call instruction
        var distinct = result.DistinctBy(s => s.Rva).ToList();
        if (cache)
        {
            if (_sites.Count > 4096) _sites.Clear();
            _sites[f.Start] = distinct;
        }
        return distinct;
    }

    /// <summary>The call at <paramref name="rva"/> (an instruction of a known function), or null.</summary>
    public CallSiteInfo? CallAt(uint rva, CancellationToken ct = default)
    {
        var f = Index.FunctionAt(rva);
        if (f == null) return null;
        EnsureDynamic(ct);
        if (DynamicReady && _sites.TryGetValue(f.Start, out var hit)) return hit.FirstOrDefault(s => s.Rva == rva);
        var code = Code(f, ct);
        var (b, i) = code.Position(rva);
        if (b < 0) return null;
        ref readonly var d = ref code.Blocks[b][i];
        if (SiteKind(code, in d) == 0) return null;
        return Site(code, b, i);
    }

    /// <summary>
    /// Every call to <paramref name="import"/>: through its slot, through thunks, and through registers loaded from the
    /// slot (x86 "mov esi, [__imp_X]; call esi").
    /// </summary>
    public List<CallSiteInfo> CallsTo(NativeImport import, int max = 100_000, CancellationToken ct = default)
    {
        var result = new Dictionary<uint, CallSiteInfo>();
        foreach (var c in Index.Callers(import))
        {
            if (result.Count >= max) break;
            ct.ThrowIfCancellationRequested();
            if (CallAt(c.From, ct) is { } s) result.TryAdd(s.Rva, s);
        }
        var viaRegister = new HashSet<uint>();
        foreach (var x in Index.RefsTo(import.SlotRva))
            if (x.Kind == XrefKind.Read && Index.FunctionAt(x.From) is { } f) viaRegister.Add(f.Start);
        foreach (var start in viaRegister)
        {
            if (result.Count >= max) break;
            ct.ThrowIfCancellationRequested();
            var f = Index.FunctionByStart(start)!;
            foreach (var s in CallsIn(f, ct))
                if (s.Import == import) result.TryAdd(s.Rva, s);
        }
        return result.Values.OrderBy(s => s.Rva).ToList();
    }

    internal FunctionCode Code(NativeFunction f, CancellationToken ct)
    {
        if (_code.TryGetValue(f.Start, out var c)) return c;
        var graph = Index.GetGraph(f, ct);
        c = FunctionCode.Decode(Index, graph, _relocs, MaxInstructionsPerFunction, ct);
        if (_code.Count >= MaxCachedFunctions) _code.Clear();
        _code[f.Start] = c;
        return c;
    }

    private readonly ConcurrentDictionary<uint, bool> _dispatchThunks = new();

    /// <summary>
    /// x64 CFG: a local function that is only "jmp rax" (__guard_dispatch_icall_nop, called directly once the dispatch
    /// pointer is bound at link time): a call or jump to it is a call through rax.
    /// </summary>
    internal bool IsDispatchThunk(uint target) => Is64 && _dispatchThunks.GetOrAdd(target, rva =>
    {
        Span<byte> b = stackalloc byte[6];
        for (int hop = 0; hop < 4; hop++)
        {
            int n = Image.Read(rva, b);
            if (n >= 2 && b[0] == 0xFF && b[1] == 0xE0 || n >= 3 && b[0] == 0x48 && b[1] == 0xFF && b[2] == 0xE0) return true;
            // jmp [__guard_dispatch_icall_fptr]
            if (n >= 6 && b[0] == 0xFF && b[1] == 0x25) return _dispatchSlots.Contains((uint)(rva + 6 + BinaryPrimitives.ReadInt32LittleEndian(b[2..])));
            // jmp rel32 / rel8 to the thunk (incremental linking, folded stubs)
            if (n >= 5 && b[0] == 0xE9) rva = (uint)(rva + 5 + BinaryPrimitives.ReadInt32LittleEndian(b[1..]));
            else if (n >= 2 && b[0] == 0xEB) rva = (uint)(rva + 2 + (sbyte)b[1]);
            else return false;
        }
        return false;
    });

    private OursSliceProvider? _slices;

    /// <summary>The built-in engine's per-function value slices of this image.</summary>
    internal OursSliceProvider Slices => LazyInitializer.EnsureInitialized(ref _slices, () => new OursSliceProvider(this));

    private ValueTraceCache? _traces;

    /// <summary>Value-trace graphs built on this image.</summary>
    public ValueTraceCache Traces => LazyInitializer.EnsureInitialized(ref _traces, () => new ValueTraceCache());

    IFunctionSliceProvider ITraceHost.Slices => Slices;
    string ITraceHost.ReturnLocation => "rax";
    string ITraceHost.ParameterLocation(int index) => Slices.LocationName(Slices.ParameterEntry(index));
    string ITraceHost.Va(uint rva) => Va(rva);
    bool ITraceHost.IsRelocated(uint rva) => IsRelocated(rva);
    (ArgKind Kind, ulong? Value, uint? Rva, string Text) ITraceHost.FormatAddress(uint rva, ApiParam? p) => FormatAddress(rva, p);

    string ITraceHost.AtCall(NativeFunction f, uint site, string entry, CancellationToken ct)
    {
        var code = Code(f, ct);
        var (b, i) = code.Position(site);
        bool tail = b >= 0 && SiteKindOf(code, in code.Blocks[b][i]) == 2;
        return OursSliceProvider.ParseLocation(entry, Is64) is { } loc ? Slices.LocationName(Slices.EntryToCall(loc, tail)) : entry;
    }

    ulong? ITraceHost.ConstantAfter(NativeFunction f, uint address, string location, CancellationToken ct)
    {
        var code = Code(f, ct);
        var (b, i) = code.Position(address);
        if (b < 0 || OursSliceProvider.ParseLocation(location, Is64) is not { } loc) return null;
        // just after the instruction: what it defines, else what it sees
        var v = new ValueResolver(this, code) { Budget = 2000 }.ValueBefore(loc, b, i + 1);
        return v.Kind == VKind.Const ? v.Num : null;
    }

    /// <summary>A base relocation applies at <paramref name="rva"/> (a pointer the loader fixes up).</summary>
    internal bool IsRelocated(uint rva) => Array.BinarySearch(_relocs, rva) >= 0;

    /// <summary>The import whose slot is at <paramref name="rva"/>, or null.</summary>
    internal NativeImport? ImportAtSlot(uint rva) => _slots.GetValueOrDefault(rva);

    /// <summary>The late-bound import whose GetProcAddress result is stored at <paramref name="rva"/>, or null.</summary>
    internal DynamicImport? LateBoundPointer(uint rva, CancellationToken ct)
    {
        EnsureDynamic(ct);
        return _dynamic?.ByGlobal.GetValueOrDefault(rva);
    }

    /// <summary>The callee of the call or tail jump at <paramref name="index"/> of <paramref name="block"/>.</summary>
    internal Callee CalleeAt(FunctionCode code, int block, int index) => ResolveCallee(code, block, index, new ValueResolver(this, code) { Budget = 1500 });

    /// <summary>0: not a call site; 1: a call; 2: a tail call.</summary>
    internal int SiteKindOf(FunctionCode code, in Decoded d) => SiteKind(code, in d);

    /// <summary>The signature of a resolved callee (an API by name), or null.</summary>
    internal static ApiSignature? SignatureOf(in Callee c) =>
        ApiSignatures.Find(c.Import?.Name ?? c.Dynamic?.Name ?? (c.Kind == CalleeKind.Function ? c.Name : null));

    /// <summary>Where the parameters of <paramref name="sig"/> are passed at a call.</summary>
    internal List<(Loc Loc, string Label)> ParameterLocations(ApiSignature sig, bool tail) => Locations([.. sig.Params], int.MaxValue, tail);

    internal bool IsTransparentCall(in Decoded d) => d.HasMem && d.I.Op0Kind == OpKind.Memory && _checkSlots.Contains(d.MemRva);

    /// <summary>Memory read at a confirmed data address: an import slot or writable data loads, read-only data is a constant.</summary>
    internal Val ReadMemory(uint rva, int bytes)
    {
        if (_slots.ContainsKey(rva)) return new Val(VKind.Load, 0, rva, 0, "");
        var section = Image.SectionAt(rva);
        if (section == null || (section.Access & SectionAccess.Write) != 0 || bytes is < 1 or > 8)
            return new Val(VKind.Load, 0, rva, 0, "");
        Span<byte> buffer = stackalloc byte[8];
        buffer.Clear();
        if (Image.Read(rva, buffer[..bytes]) != bytes) return new Val(VKind.Load, 0, rva, 0, "");
        ulong value = BinaryPrimitives.ReadUInt64LittleEndian(buffer);
        int ptr = Is64 ? 8 : 4;
        if (bytes == ptr && Array.BinarySearch(_relocs, rva) >= 0 && FunctionCode.TryRva(Image, Is64, value, out uint target))
            return new Val(VKind.Addr, 0, target, 0, "");
        return new Val(VKind.Const, value, 0, 0, "");
    }

    [ThreadStatic] private static int _nesting;

    /// <summary>
    /// x86: bytes the callee at a call removes from the stack (its stdcall arguments), or null when not known: 0 when an
    /// "add esp, n" follows (cdecl) or the API is cdecl; the signature's size for a known API; "ret n" for a local function;
    /// otherwise (stdcall assumed) the bytes pushed since the previous call.
    /// </summary>
    internal int? CalleePops(FunctionCode code, int block, int index)
    {
        var insns = code.Blocks[block];
        if (index + 1 < insns.Length && insns[index + 1].I is { Mnemonic: Mnemonic.Add, Op0Kind: OpKind.Register } next
            && next.Op0Register == Register.ESP) return 0;
        if (_nesting > 2) return null;
        _nesting++;
        try
        {
            var callee = ResolveCallee(code, block, index, new ValueResolver(this, code) { Budget = 1500 });
            var name = callee.Import != null ? callee.Import.Name : callee.Dynamic?.Name ?? (callee.Kind == CalleeKind.Function ? callee.Name : null);
            if (ApiSignatures.Find(name) is { } sig) return sig.Cdecl || sig.Variadic ? 0 : sig.Params.Sum(p => p.Slots32) * 4;
            if (callee.Import != null) return X86ImportArity.Pops(callee.Import, Image.Path);
            if (callee.Dynamic is { Module: { } module } dyn)
                return X86ImportArity.Pops(new NativeImport(module, dyn.Name, null, 0, 0, false), Image.Path);
            if (callee.Kind is CalleeKind.Function or CalleeKind.VirtualExact && callee.Target is { } t && Index.FunctionByStart(t) is { } f && f.ThunkImport == null)
                return LocalPops(f);
            return null;
        }
        finally { _nesting--; }
    }

    /// <summary>The n of the "ret n" instructions of a local x86 function (null when they disagree or none is found).</summary>
    private int? LocalPops(NativeFunction f) => _pops.GetOrAdd(f.Start, _ =>
    {
        int? found = null;
        int budget = 20_000;
        foreach (var (s, e) in Index.Ranges(f))
        {
            var bytes = new byte[Math.Min(e - s, 1u << 20)];
            int n = Image.Read(s, bytes);
            var decoder = Iced.Intel.Decoder.Create(32, new ByteArrayCodeReader(bytes, 0, n), Image.ImageBase + s);
            while (decoder.IP < Image.ImageBase + s + (ulong)n && budget-- > 0)
            {
                decoder.Decode(out var insn);
                if (insn.IsInvalid) break;
                if (insn.Mnemonic != Mnemonic.Ret) continue;
                int pops = insn.OpCount > 0 ? insn.Immediate16 : 0;
                if (found != null && found != pops) return null;
                found = pops;
            }
        }
        return found;
    });

    internal readonly record struct Callee(string Name, CalleeKind Kind, NativeImport? Import, uint? Target, DynamicImport? Dynamic, string? Why);

    internal Callee ResolveCallee(FunctionCode code, int block, int index, ValueResolver resolver)
    {
        ref readonly var d = ref code.Blocks[block][index];
        ref readonly var x = ref d.I;
        if (Index.VirtualCalls.SiteAt(d.Rva) is { Status: not VirtualCallStatus.Unresolved } site) return Virtual(site);
        if (x.Op0Kind is OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64)
        {
            if (!FunctionCode.TryRva(Image, Is64, x.NearBranchTarget, out uint t)) return new Callee($"0x{x.NearBranchTarget:X}", CalleeKind.Indirect, null, null, null, "outside the image");
            if (IsDispatchThunk(t)) return FromValue(resolver.ValueBefore(Loc.Of(Register.RAX), block, index), "through the CFG dispatch");
            return Direct(t);
        }
        if (x.Op0Kind == OpKind.Memory)
        {
            if (d.HasMem)
            {
                if (_slots.TryGetValue(d.MemRva, out var imp)) return FromImport(imp);
                if (_dispatchSlots.Contains(d.MemRva))
                    return FromValue(resolver.ValueBefore(Loc.Of(Register.RAX), block, index), "through the CFG dispatch");
                return FromValue(ReadMemory(d.MemRva, Is64 ? 8 : 4), null);
            }
            var text = x.ToString();
            int open = text.IndexOf('[');
            return new Callee(open >= 0 ? text[open..] : text, CalleeKind.Indirect, null, null, null, "pointer in memory (virtual call or callback)");
        }
        if (x.Op0Kind == OpKind.Register)
            return FromValue(resolver.ValueBefore(Loc.Of(x.Op0Register), block, index), null);
        return new Callee(x.ToString(), CalleeKind.Indirect, null, null, null, null);
    }

    /// <summary>A virtual call resolved through RTTI: the implementation, or "one of n: a | b | ...".</summary>
    private Callee Virtual(VirtualCallSite site)
    {
        var targets = Index.VirtualTargets(site.Rva);
        string Name(uint t) => Index.NameAt(t) ?? $"sub_{t:X}";
        if (site.Status == VirtualCallStatus.Exact && targets.Count == 1)
            return new Callee(Name(targets[0]), CalleeKind.VirtualExact, null, targets[0], null, $"virtual call through slot {site.Slot}, the only implementation");
        var names = string.Join(" | ", targets.Take(4).Select(Name)) + (targets.Count > 4 ? " | ..." : "");
        return new Callee($"<one of {targets.Count}: {names}>", CalleeKind.VirtualPossible, null, null, null, $"virtual call through slot {site.Slot}");
    }

    private Callee FromImport(NativeImport imp) => new(NativeCodeIndex.ImportName(imp), CalleeKind.Import, imp, imp.SlotRva, null, null);

    private Callee Direct(uint t)
    {
        var f = Index.FunctionByStart(t);
        if (f?.ThunkImport is { } imp) return FromImport(imp);
        return new Callee(Index.NameAt(t) ?? f?.Name ?? $"sub_{t:X}", CalleeKind.Function, null, t, null, null);
    }

    private Callee FromValue(Val v, string? how)
    {
        switch (v.Kind)
        {
            case VKind.Load when _slots.TryGetValue(v.Rva, out var imp):
                return FromImport(imp);
            case VKind.Load:
                if (_dynamic?.ByGlobal.GetValueOrDefault(v.Rva) is { } global) return FromDynamic(global);
                return new Callee($"[{Index.NameAt(v.Rva) ?? Va(v.Rva)}]", CalleeKind.Indirect, null, v.Rva, null, how ?? "function pointer in a global");
            case VKind.Addr when Index.FunctionByStart(v.Rva) != null:
                return Direct(v.Rva);
            case VKind.Result when _dynamic?.BySite.GetValueOrDefault(v.Site) is { } dyn:
                return FromDynamic(dyn);
            default:
                return new Callee(v.Kind == VKind.Result ? $"<result of the call at {Va(v.Site)}>" : "<unknown>", CalleeKind.Indirect, null, null, null, v.Why);
        }
    }

    private static Callee FromDynamic(DynamicImport dyn) => new(dyn.FullName, CalleeKind.Dynamic, null, dyn.PointerGlobal, dyn, null);

    internal string Va(uint rva) => $"0x{Image.ImageBase + rva:X}";

    /// <summary>
    /// 0: not a call site; 1: a call; 2: a tail call (jmp through an import slot, or to another function's start), whose
    /// stack arguments sit above the caller's return address. Guard-check calls and thunks are not call sites.
    /// </summary>
    private int SiteKind(FunctionCode code, in Decoded d)
    {
        ref readonly var x = ref d.I;
        if (x.FlowControl is FlowControl.Call or FlowControl.IndirectCall) return IsTransparentCall(in d) ? 0 : 1;
        if ((code.Function.Flags & FunctionFlags.Thunk) != 0) return 0;
        if (x.FlowControl == FlowControl.IndirectBranch && x.Op0Kind == OpKind.Memory && d.HasMem && _slots.ContainsKey(d.MemRva)) return 2;
        if (x.FlowControl == FlowControl.UnconditionalBranch && x.Op0Kind is OpKind.NearBranch32 or OpKind.NearBranch64
            && FunctionCode.TryRva(Image, Is64, x.NearBranchTarget, out uint t) && t != code.Function.Start && Index.FunctionByStart(t) != null)
            return 2;
        return 0;
    }

    private CallSiteInfo Site(FunctionCode code, int block, int index)
    {
        ref readonly var d = ref code.Blocks[block][index];
        bool tail = SiteKind(code, in d) == 2;
        var resolver = new ValueResolver(this, code);
        var callee = ResolveCallee(code, block, index, resolver);
        var apiName = callee.Import?.Name ?? callee.Dynamic?.Name ?? (callee.Kind == CalleeKind.Function ? callee.Name : null);
        var sig = ApiSignatures.Find(apiName);
        var args = new List<CallArgument>();
        bool guessed = sig == null;
        if (sig != null)
        {
            var ps = new List<ApiParam>(sig.Params);
            int fixedCount = ps.Count;
            var locs = Locations(ps, int.MaxValue, tail);
            for (int k = 0; k < ps.Count; k++)
                args.Add(Argument(resolver, block, index, k, ps[k], locs[k]));
            if (sig.Variadic && ps.LastOrDefault(p => p.Type is ApiParamType.AnsiFormat or ApiParamType.WideFormat) is { } fmt
                && args[ps.IndexOf(fmt)] is { Kind: ArgKind.String } fa && fa.Value == null)
            {
                var extra = ApiSignatures.FormatArguments(Unquote(fa.Text), fmt.Type == ApiParamType.WideFormat, 16);
                for (int k = 0; k < extra.Count; k++) ps.Add(new ApiParam($"arg{k + 1}", extra[k]));
                var all = Locations(ps, fixedCount, tail);
                for (int k = fixedCount; k < ps.Count; k++)
                    args.Add(Argument(resolver, block, index, k, ps[k], all[k]));
            }
        }
        else
        {
            foreach (var (k, loc, label) in tail ? [] : GuessLocations(code, block, index))
                args.Add(Argument(resolver, block, index, k, null, (loc, label)));
        }
        return new CallSiteInfo(d.Rva, code.Function, callee.Name, callee.Kind, callee.Import, callee.Target, callee.Dynamic, sig, guessed, args, tail);
    }

    private static string Unquote(string text)
    {
        int start = text.StartsWith("L\"", StringComparison.Ordinal) ? 2 : text.StartsWith('"') ? 1 : 0;
        int end = text.EndsWith('"') ? text.Length - 1 : text.Length;
        return end > start ? text[start..end] : "";
    }

    /// <summary>Where each parameter is passed (<see cref="X64Abi.Assign"/> on x64).</summary>
    private List<(Loc Loc, string Label)> Locations(List<ApiParam> ps, int variadicFrom, bool tail)
    {
        if (Is64) return Abi.Assign(ps.Select(p => p.IsFloat).ToList(), variadicFrom, tail);
        var result = new List<(Loc, string)>(ps.Count);
        int offset = 0;
        foreach (var p in ps)
        {
            result.Add((Loc.Stack(offset + (tail ? 4 : 0)), $"[esp+{offset + (tail ? 4 : 0):X}h]"));
            offset += 4 * p.Slots32;
        }
        return result;
    }

    /// <summary>
    /// Arguments of a call without a signature: the argument registers (x64) and stack slots set between the previous
    /// call (or the block start) and this call; on x86 also ecx / edx set there (thiscall / fastcall).
    /// </summary>
    private List<(int Index, Loc Loc, string Label)> GuessLocations(FunctionCode code, int block, int index)
    {
        var insns = code.Blocks[block];
        var result = new List<(int, Loc, string)>();
        if (Is64)
        {
            var regs = Abi.IntArgs;
            int home = Abi.HomeArea, highest = -1, highestSlot = -1;
            var written = new HashSet<int>();
            for (int i = index - 1; i >= 0; i--)
            {
                ref readonly var d = ref insns[i];
                if (d.I.FlowControl is FlowControl.Call or FlowControl.IndirectCall && !IsTransparentCall(in d)) break;
                for (int k = 0; k < regs.Length; k++)
                    if ((d.Writes & (1UL << FunctionCode.Bit(regs[k]))) != 0) highest = Math.Max(highest, k);
                if (d.I.Op0Kind == OpKind.Memory && d.I.MemoryBase == Register.RSP && d.I.MemoryIndex == Register.None
                    && d.I.Mnemonic is Mnemonic.Mov or Mnemonic.And or Mnemonic.Or)
                {
                    long disp = (long)d.I.MemoryDisplacement64;
                    if (disp >= home && disp < home + 8 * MaxGuessedArguments && (disp - home) % 8 == 0)
                        written.Add((int)(disp - home) / 8);
                }
            }
            // stack arguments fill the slots from the first one up; a store above a gap is a local (a saved cookie, a spill)
            while (written.Contains(highestSlot + 1)) highestSlot++;
            // System V: [rsp] also holds locals, so stack slots count only once every register argument is set
            if (Abi.IsSystemV && highest < regs.Length - 1) highestSlot = -1;
            int count = highestSlot >= 0 ? regs.Length + highestSlot + 1 : highest + 1;
            for (int k = 0; k < Math.Min(count, MaxGuessedArguments); k++)
            {
                int slot = home + 8 * (k - regs.Length);
                result.Add(k < regs.Length ? (k, Loc.Of(regs[k]), regs[k].ToString().ToLowerInvariant()) : (k, Loc.Stack(slot), $"[rsp+{slot:X}h]"));
            }
            return result;
        }
        // x86: pushes (and esp stores) since the previous call, contiguous from [esp]
        var slots = new HashSet<int>();
        bool ecx = false, edx = false;
        int off = 0;
        for (int i = index - 1; i >= 0; i--)
        {
            ref readonly var d = ref insns[i];
            ref readonly var x = ref d.I;
            if (x.FlowControl is FlowControl.Call or FlowControl.IndirectCall && !IsTransparentCall(in d)) break;
            if (!IsTransparentCall(in d))
            {
                if ((d.Writes & (1UL << FunctionCode.Bit(Register.RCX))) != 0 && x.Mnemonic != Mnemonic.Pop) ecx = true;
                if ((d.Writes & (1UL << FunctionCode.Bit(Register.RDX))) != 0 && x.Mnemonic != Mnemonic.Pop) edx = true;
            }
            // off: the stack pointer after this instruction minus the one at the call
            if (x.Mnemonic == Mnemonic.Push) { slots.Add(off); off += 4; continue; }
            if (x.Op0Kind == OpKind.Memory && x.MemoryBase == Register.ESP && x.MemoryIndex == Register.None && x.Mnemonic is Mnemonic.Mov)
                slots.Add(off + (int)(uint)x.MemoryDisplacement64);
            if (x.StackPointerIncrement != 0) { off -= x.StackPointerIncrement; continue; }
            if (x.Mnemonic is Mnemonic.Sub or Mnemonic.Add && x.Op0Kind == OpKind.Register && x.Op0Register == Register.ESP) break;
        }
        int n = 0;
        if (ecx) result.Add((n++, Loc.Of(Register.ECX), "ecx"));
        if (edx && ecx) result.Add((n++, Loc.Of(Register.EDX), "edx"));
        for (int s = 0; slots.Contains(s) && n < MaxGuessedArguments; s += 4)
            result.Add((n++, Loc.Stack(s), $"[esp+{s:X}h]"));
        return result;
    }

    private CallArgument Argument(ValueResolver resolver, int block, int index, int k, ApiParam? p, (Loc Loc, string Label) loc)
    {
        var v = resolver.ValueBefore(loc.Loc, block, index);
        var (kind, value, rva, text) = Format(v, p, resolver.Code);
        return new CallArgument(k, p?.Name, p?.TypeName, loc.Label, kind, value, rva, text, v.Why) { Raw = v };
    }

    /// <summary>The short name of the callee of the call at <paramref name="site"/> in <paramref name="code"/>.</summary>
    private string ResultName(FunctionCode code, uint site)
    {
        var (b, i) = code.Position(site);
        if (b < 0 || _nesting > 2) return $"the call at {Va(site)}";
        _nesting++;
        try
        {
            var c = ResolveCallee(code, b, i, new ValueResolver(this, code) { Budget = 1500 });
            if (c.Kind is CalleeKind.Indirect or CalleeKind.VirtualPossible) return $"the call at {Va(site)}";
            int bang = c.Name.LastIndexOf('!');
            return bang >= 0 ? c.Name[(bang + 1)..] : c.Name;
        }
        finally { _nesting--; }
    }

    private (ArgKind Kind, ulong? Value, uint? Rva, string Text) Format(Val v, ApiParam? p, FunctionCode code)
    {
        switch (v.Kind)
        {
            case VKind.Const:
                return (ArgKind.Immediate, v.Num, null, FormatNumber(v.Num, p));
            case VKind.Addr:
                return FormatAddress(v.Rva, p);
            case VKind.Load:
                if (_slots.TryGetValue(v.Rva, out var imp)) return (ArgKind.Name, null, v.Rva, NativeCodeIndex.ImportName(imp));
                if (_dynamic?.ByGlobal.GetValueOrDefault(v.Rva) is { } dyn) return (ArgKind.Name, null, v.Rva, dyn.FullName);
                return (ArgKind.Global, null, v.Rva, $"[{Index.NameAt(v.Rva) ?? Va(v.Rva)}]");
            case VKind.Result:
                return (ArgKind.Result, null, null, $"<result of {ResultName(code, v.Site)}>");
            case VKind.StackAddr:
                return (ArgKind.Address, null, null, "&local");
            default:
                return (ArgKind.Unknown, null, null, "?");
        }
    }

    internal static string FormatNumber(ulong n, ApiParam? p)
    {
        bool is32 = n <= uint.MaxValue || n >> 32 == 0xFFFFFFFF;
        long signed = n >> 32 == 0xFFFFFFFF ? (int)(uint)n : (long)n;
        switch (p?.Type)
        {
            case ApiParamType.Enum:
                return p.Enum!.Describe(n) ?? (p.Enum.IsFlags || n >= 0x10000 ? Hex(n) : n.ToString());
            case ApiParamType.Bool:
                return n switch { 0 => "FALSE", 1 => "TRUE", _ => Hex(n) };
            case ApiParamType.Pointer or ApiParamType.Guid or ApiParamType.AnsiString or ApiParamType.WideString
                or ApiParamType.AnsiFormat or ApiParamType.WideFormat:
                return n == 0 ? "NULL" : Hex(n);
            case ApiParamType.Handle or ApiParamType.Module:
                return n == 0 ? "NULL" : signed == -1 ? "INVALID_HANDLE_VALUE" : signed is < 0 and > -32 ? signed.ToString() : Hex(n);
            case ApiParamType.ProcName:
                return n < 0x10000 ? $"#{n}" : Hex(n);
            case ApiParamType.Int:
                return is32 ? ((int)(uint)n).ToString() : signed.ToString();
            case ApiParamType.Hex:
                return Hex(n);
            case ApiParamType.Float:
                return BitConverter.UInt32BitsToSingle((uint)n).ToString("R", System.Globalization.CultureInfo.InvariantCulture) + "f";
            case ApiParamType.Double:
                return BitConverter.UInt64BitsToDouble(n).ToString("R", System.Globalization.CultureInfo.InvariantCulture);
            case ApiParamType.UInt or ApiParamType.Size or ApiParamType.Int64:
                return n < 0x10000 ? n.ToString() : Hex(n);
            default:
                return signed is < 0 and > -0x10000 ? signed.ToString() : n < 10 ? n.ToString() : Hex(n);
        }
    }

    private static string Hex(ulong n) => n < 10 ? n.ToString() : $"0x{n:X}";

    internal (ArgKind Kind, ulong? Value, uint? Rva, string Text) FormatAddress(uint rva, ApiParam? p)
    {
        switch (p?.Type)
        {
            case ApiParamType.AnsiString or ApiParamType.AnsiFormat or ApiParamType.ProcName:
                if (ReadText(rva, wide: false) is { } a) return (ArgKind.String, null, rva, Quote(a, false));
                break;
            case ApiParamType.WideString or ApiParamType.WideFormat:
                if (ReadText(rva, wide: true) is { } w) return (ArgKind.String, null, rva, Quote(w, true));
                break;
            case ApiParamType.Guid:
                Span<byte> g = stackalloc byte[16];
                if (Image.Read(rva, g) == 16) return (ArgKind.Address, null, rva, new Guid(g).ToString("B").ToUpperInvariant());
                break;
        }
        if (p is null or { Type: ApiParamType.Pointer } && Index.StringAt(rva) is { } s)
        {
            var text = Index.ReadString(s, 200);
            return (ArgKind.String, null, rva, Quote(text, s.Encoding == StringEncoding.Utf16));
        }
        if (Index.NameAt(rva) is { } name) return (ArgKind.Name, null, rva, rva == 0 ? "__ImageBase" : name);
        if (rva == 0) return (ArgKind.Name, null, 0, "__ImageBase");
        return (ArgKind.Address, null, rva, Va(rva));
    }

    private static string Quote(string text, bool wide)
    {
        var sb = new StringBuilder(wide ? "L\"" : "\"");
        foreach (char c in text.Length > 120 ? text[..120] : text)
            sb.Append(c switch { '\\' => "\\\\", '"' => "\\\"", '\n' => "\\n", '\r' => "\\r", '\t' => "\\t", _ => c < ' ' ? $"\\x{(int)c:X2}" : c.ToString() });
        if (text.Length > 120) sb.Append("...");
        return sb.Append('"').ToString();
    }

    /// <summary>A NUL-terminated string of printable characters at <paramref name="rva"/> (may be empty), or null.</summary>
    internal string? ReadText(uint rva, bool wide, int max = 1024)
    {
        var buffer = new byte[(max + 1) * (wide ? 2 : 1)];
        int n = Image.Read(rva, buffer);
        var sb = new StringBuilder();
        for (int i = 0; wide ? i + 1 < n : i < n; i += wide ? 2 : 1)
        {
            char c = wide ? (char)(buffer[i] | buffer[i + 1] << 8) : (char)buffer[i];
            if (c == 0) return sb.ToString();
            if (c < ' ' && c is not ('\t' or '\r' or '\n')) return null;
            if (!wide && c > 0x7E) return null;
            if (wide && (char.IsSurrogate(c) || c is >= '￰' || (c >= 0x7F && c < 0xA0))) return null;
            sb.Append(c);
        }
        return null;
    }
}
