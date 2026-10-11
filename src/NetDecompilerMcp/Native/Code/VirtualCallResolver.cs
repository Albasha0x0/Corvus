using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using Iced.Intel;
using NetDecompilerMcp.Native.Msvc;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Native.Code;

/// <summary>
/// Resolves virtual call sites (x86 / x64) to implementations through MSVC RTTI. Each function with an indirect call
/// is run through a forward data flow over its blocks that tracks registers, stack slots (by offset from the entry stack
/// pointer, so spills and frame pointers are followed) and fields of objects: the entry this (rcx / ecx), objects a call
/// returns, constant addresses. A call through [[obj + o] + 8k] (directly, through a register, or through the CFG
/// dispatch with the target in rax) is a virtual call site on the subobject at o, slot k. The receiver's class:
/// <list type="bullet">
/// <item>a vftable stored into the object in the function (constructors, inlined construction), or by a constructor the
/// function calls on it (summaries: the vftables a function leaves in [this + o] on every return): the slot of that
/// vftable, exact;</item>
/// <item>this of a virtual method: the classes whose vftables hold the method; the slot in their vftable at the
/// subobject and in the vftables of every derived class at the same subobject (RTTI base class arrays give its
/// offset in each derived class). Pure virtual stubs (functions that do not return) are left out. One distinct
/// implementation is exact, several are possible targets.</item>
/// </list>
/// Calls whose receiver is neither are unresolved and counted. Merges of different values lose them; the flow is
/// iterated to a fixed point within a visit budget per function.
/// </summary>
internal sealed class VirtualCallResolver
{
    private const int MaxInstructions = 100_000;

    private readonly NativeCodeIndex _index;
    private readonly CodeContext _ctx;
    private readonly INativeImage _image;
    private readonly bool _is64;
    private readonly int _ptr;
    private readonly int _maxTargets;
    private readonly CancellationToken _ct;

    // RTTI model
    private readonly Dictionary<(uint Td, uint Offset), List<MsvcRttiVtable>> _vftablesAt = [];
    /// <summary>Non-virtual member functions by start, and their class (from the decorated export name).</summary>
    private readonly Dictionary<uint, MsvcRttiClass> _named = [];
    /// <summary>Functions and import slots whose decorated name returns a pointer to a class (index in <see cref="_classes"/>).</summary>
    private readonly Dictionary<uint, int> _returns = [];
    /// <summary>Functions whose decorated name passes class pointers: entry register (or stack slot) and class; class -1 is this on the stack.</summary>
    private readonly Dictionary<uint, (int Reg, int Slot, int Class)[]> _seeds = [];
    private List<MsvcRttiClass> _classes = [];
    private readonly Dictionary<uint, List<(MsvcRttiClass Class, uint Offset)>> _owners = [];
    private readonly Dictionary<uint, List<(MsvcRttiClass Class, int Offset, bool Virtual)>> _derived = [];
    private (uint Start, uint End, MsvcRttiClass Class, MsvcRttiVtable Vftable)[] _tables = [];
    private readonly HashSet<uint> _vftableStarts = [];
    private readonly HashSet<uint> _pure = [];
    private readonly HashSet<uint> _dispatchSlots = [];
    private readonly HashSet<uint> _dispatchThunks = [];
    private readonly Dictionary<uint, (int Offset, uint Vftable)[]> _summaries = [];
    private readonly ConcurrentDictionary<uint, int?> _pops = new();
    private int _pureExcluded, _notConverged, _analyzed;

    private VirtualCallResolver(NativeCodeIndex index, CodeContext ctx, CodeIndexOptions options, CancellationToken ct)
    {
        _index = index;
        _ctx = ctx;
        _image = index.Image;
        _is64 = _image.Arch == NativeArch.X64;
        _ptr = _is64 ? 8 : 4;
        _maxTargets = Math.Max(1, options.MaxVirtualTargets);
        _ct = ct;
    }

    /// <summary>The sites and the edges (sorted by source, then target) of <paramref name="index"/>.</summary>
    public static (VirtualCallSet Set, CodeXref[] Edges) Resolve(NativeCodeIndex index, CodeContext ctx, CodeIndexOptions options, MsvcRttiResult rtti,
        CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        if (index.Image.Arch is not (NativeArch.X86 or NativeArch.X64)) return (VirtualCallSet.Empty, []);
        var r = new VirtualCallResolver(index, ctx, options, ct);
        int classes = r.BuildModel(rtti);
        if (classes == 0)
            return (new VirtualCallSet([], VirtualCallStats.None with { Elapsed = sw.Elapsed }, ["no MSVC RTTI classes with vftables: virtual calls are not resolved"]), []);
        return r.Run(classes, options, sw);
    }

    private int BuildModel(MsvcRttiResult rtti)
    {
        var polymorphic = rtti.Classes.Where(c => c.Vtables.Count > 0).ToList();
        var byTd = new Dictionary<uint, MsvcRttiClass>();
        foreach (var c in polymorphic) byTd.TryAdd(c.TypeDescriptorRva, c);
        var tables = new List<(uint, uint, MsvcRttiClass, MsvcRttiVtable)>();
        foreach (var c in polymorphic)
        {
            foreach (var v in c.Vtables)
            {
                if (!_vftablesAt.TryGetValue((c.TypeDescriptorRva, v.Offset), out var list)) _vftablesAt[(c.TypeDescriptorRva, v.Offset)] = list = [];
                list.Add(v);
                tables.Add((v.VftableRva, v.VftableRva + (uint)(v.SlotRvas.Count * _ptr), c, v));
                _vftableStarts.Add(v.VftableRva);
                foreach (var s in v.SlotRvas.Distinct())
                {
                    if (!_owners.TryGetValue(s, out var owners)) _owners[s] = owners = [];
                    if (!owners.Any(o => ReferenceEquals(o.Class, c) && o.Offset == v.Offset)) owners.Add((c, v.Offset));
                }
            }
            // where each base sits in this class: non-virtual paths by member displacement; a virtual base anywhere on the path is not placed
            for (int i = 0; i < c.Bases.Count; i++)
            {
                var b = c.Bases[i];
                if (!byTd.ContainsKey(b.TypeDescriptorRva)) continue;
                bool viaVirtual = false;
                int? k = i;
                for (int guard = 0; k is int j && j >= 0 && j < c.Bases.Count && guard < 64; guard++)
                {
                    if (c.Bases[j].IsVirtual) { viaVirtual = true; break; }
                    k = c.Bases[j].Parent;
                }
                if (!_derived.TryGetValue(b.TypeDescriptorRva, out var placements)) _derived[b.TypeDescriptorRva] = placements = [];
                placements.Add((c, b.Mdisp, viaVirtual));
            }
        }
        tables.Sort((a, b) => a.Item1.CompareTo(b.Item1));
        _tables = [.. tables];

        // decorated names (exports, imports): the class of this in non-virtual member functions (at offset 0), class pointers passed
        // as parameters, class pointers returned
        _classes = polymorphic;
        var byName = new Dictionary<string, int>(StringComparer.Ordinal);
        for (int i = 0; i < polymorphic.Count; i++) byName.TryAdd(polymorphic[i].Name, i);
        var demangle = new MsvcDemangleOptions { X86 = !_is64 };
        int ClassOf(string? type) => PointerClass(type) is { } n && byName.TryGetValue(n, out int i) ? i : -1;
        foreach (var f in _index.Functions)
        {
            if ((f.Index & 0xFFF) == 0) _ct.ThrowIfCancellationRequested();
            if (f.KnownName is not { Length: > 3 } name || name[0] != '?' || Signature(name, demangle) is not { } sig) continue;
            if (sig.Member && !sig.Virtual && !_owners.ContainsKey(f.Start) && sig.Class != null && byName.TryGetValue(sig.Class, out int owner))
                _named[f.Start] = polymorphic[owner];
            if (ClassOf(sig.Return) is var ret and >= 0) _returns[f.Start] = ret;
            var seeds = new List<(int Reg, int Slot, int Class)>();
            foreach (var (reg, slot, type) in ParameterLocations(sig, _is64))
            {
                if (type == null) seeds.Add((reg, slot, -1));
                else if (ClassOf(type) is var c and >= 0) seeds.Add((reg, slot, c));
            }
            if (seeds.Count > 0) _seeds[f.Start] = [.. seeds];
        }
        foreach (var imp in _image.Imports)
            if (imp.Name is { Length: > 3 } name && name[0] == '?' && Signature(name, demangle) is { } sig && ClassOf(sig.Return) is var ret and >= 0)
                _returns[imp.SlotRva] = ret;

        // pure virtual stubs: functions that do not return, or thunks to an import named _purecall
        foreach (var target in _owners.Keys)
            if (_index.FunctionByStart(target) is { } f
                && ((f.Flags & FunctionFlags.NoReturn) != 0 || f.ThunkImport?.Name is "_purecall" or "purecall" || f.KnownName is "_purecall" or "__purecall"))
                _pure.Add(target);

        if (_image is PeFile { LoadConfig: { } lc })
            foreach (var va in new[] { lc.GuardCfDispatchFunctionPointer, lc.GuardXfgDispatchFunctionPointer, lc.GuardXfgTableDispatchFunctionPointer })
                if (va > _image.ImageBase && va - _image.ImageBase < _image.SizeOfImage) _dispatchSlots.Add((uint)(va - _image.ImageBase));
        if (_is64 && _dispatchSlots.Count > 0)
        {
            Span<byte> b = stackalloc byte[6];
            foreach (var f in _index.Functions)
                if (f.Size is >= 6 and <= 8 && _image.Read(f.Start, b) == 6 && b[0] == 0xFF && b[1] == 0x25
                    && _dispatchSlots.Contains((uint)(f.Start + 6 + BinaryPrimitives.ReadInt32LittleEndian(b[2..]))))
                    _dispatchThunks.Add(f.Start);
        }
        return polymorphic.Count;
    }

    /// <summary>A function's decorated name, decoded: a non-static member or not, virtual, its class, calling convention, return and parameter types.</summary>
    internal sealed record DecoratedSignature(bool Member, bool Virtual, string? Class, string Convention, string Return, IReadOnlyList<string> Params);

    private static readonly string[] Conventions = ["__cdecl", "__stdcall", "__thiscall", "__fastcall", "__vectorcall", "__clrcall"];

    /// <summary>
    /// The signature of a decorated function name ("public: class ns::B * __cdecl ns::A::get(void) const"), from its
    /// demangled text; null for other names.
    /// </summary>
    internal static DecoratedSignature? Signature(string decorated, MsvcDemangleOptions options)
    {
        var full = MsvcDemangler.Demangle(decorated, options);
        if (full.Kind != MsvcSymbolKind.Function || full.Text is not { } text) return null;
        bool member = false, isStatic = false, isVirtual = false;
        var rest = text;
        int colon = text.IndexOf(": ", StringComparison.Ordinal);
        if (colon > 0 && text[..colon] is "public" or "protected" or "private") { member = true; rest = text[(colon + 2)..]; }
        if (rest.StartsWith("static ", StringComparison.Ordinal)) { isStatic = true; rest = rest[7..]; }
        else if (rest.StartsWith("virtual ", StringComparison.Ordinal)) { isVirtual = true; rest = rest[8..]; }
        // the calling convention: the first one outside brackets
        int conv = -1, depth = 0;
        string convention = "";
        for (int i = 0; i < rest.Length && conv < 0; i++)
        {
            char ch = rest[i];
            if (ch is '<' or '(') depth++;
            else if (ch is '>' or ')') depth--;
            else if (depth == 0 && (i == 0 || rest[i - 1] == ' '))
                foreach (var c in Conventions)
                    if (rest.AsSpan(i).StartsWith(c + " ", StringComparison.Ordinal)) { conv = i; convention = c; break; }
        }
        if (conv < 0) return null;
        var tail = rest[(conv + convention.Length + 1)..];
        // the parameters: the last parenthesized group
        int close = tail.LastIndexOf(')'), open = -1;
        depth = 0;
        for (int i = close; i >= 0; i--)
        {
            if (tail[i] == ')') depth++;
            else if (tail[i] == '(' && --depth == 0) { open = i; break; }
        }
        if (open <= 0) return null;
        var name = tail[..open];
        var ps = SplitTopLevel(tail[(open + 1)..close]);
        if (ps is ["void"]) ps = [];
        string? cls = null;
        if (member)
        {
            int cut = -1;
            depth = 0;
            for (int i = 0; i + 1 < name.Length; i++)
            {
                if (name[i] == '<') depth++;
                else if (name[i] == '>') depth--;
                else if (name[i] == ':' && name[i + 1] == ':' && depth == 0) cut = i;
            }
            if (cut <= 0) return null;
            cls = name[..cut];
        }
        return new DecoratedSignature(member && !isStatic, isVirtual, cls, convention, rest[..conv].Trim(), ps);
    }

    private static List<string> SplitTopLevel(string text)
    {
        var parts = new List<string>();
        int depth = 0, start = 0;
        for (int i = 0; i < text.Length; i++)
        {
            char ch = text[i];
            if (ch is '<' or '(') depth++;
            else if (ch is '>' or ')') depth--;
            else if (ch == ',' && depth == 0) { parts.Add(text[start..i].Trim()); start = i + 1; }
        }
        if (text.Trim().Length > 0) parts.Add(text[start..].Trim());
        return parts;
    }

    /// <summary>"ns::C" for a pointer or reference to a class ("class ns::C const *", "struct S &amp;"), else null.</summary>
    internal static string? PointerClass(string? type)
    {
        if (type == null) return null;
        var t = type.Trim();
        if (t.EndsWith(" const", StringComparison.Ordinal)) t = t[..^6];
        string? core = t.EndsWith(" &&", StringComparison.Ordinal) ? t[..^3] : t.EndsWith(" *", StringComparison.Ordinal) || t.EndsWith(" &", StringComparison.Ordinal) ? t[..^2] : null;
        if (core == null) return null;
        core = core.Trim();
        while (core.EndsWith(" const", StringComparison.Ordinal) || core.EndsWith(" volatile", StringComparison.Ordinal)) core = core[..core.LastIndexOf(' ')];
        var n = core.StartsWith("class ", StringComparison.Ordinal) ? core[6..] : core.StartsWith("struct ", StringComparison.Ordinal) ? core[7..] : null;
        return n == null || n.Contains('*') || n.Contains('&') || n.Contains('(') ? null : n;
    }

    private static bool ByValueRecord(string type) =>
        type.StartsWith("class ", StringComparison.Ordinal) || type.StartsWith("struct ", StringComparison.Ordinal) || type.StartsWith("union ", StringComparison.Ordinal)
            ? PointerClass(type) == null : false;

    /// <summary>A type that takes one 4-byte stack slot on x86.</summary>
    private static bool Slot32(string type) =>
        type.EndsWith('*') || type.EndsWith('&') || type.EndsWith(" const", StringComparison.Ordinal) && (type.Contains('*') || type.Contains('&'))
        || type.StartsWith("enum ", StringComparison.Ordinal)
        || type is "int" or "unsigned int" or "long" or "unsigned long" or "bool" or "char" or "signed char" or "unsigned char" or "short" or "unsigned short"
            or "wchar_t" or "float";

    /// <summary>
    /// Where the arguments of <paramref name="sig"/> are at entry: a register (index from rax) or an entry stack slot, with their
    /// type; a null type marks this passed on the stack (x86 members that are not __thiscall). x64: this, a hidden return
    /// pointer for a record returned by value, then the parameters in rcx, rdx, r8, r9 and [rsp+28h]...; x86: the stack from
    /// [esp+4] while the parameters take one slot each.
    /// </summary>
    internal static List<(int Reg, int Slot, string? Type)> ParameterLocations(DecoratedSignature sig, bool is64)
    {
        var result = new List<(int, int, string?)>();
        bool hidden = ByValueRecord(sig.Return);
        if (hidden && !sig.Member) return result; // a small record may come back in rax: positions unknown
        if (is64)
        {
            int[] regs = [1, 2, 8, 9];
            int k = (sig.Member ? 1 : 0) + (hidden ? 1 : 0);
            foreach (var p in sig.Params)
            {
                if (p == "...") break;
                result.Add(k < 4 ? (regs[k], 0, p) : (-1, 8 * (k + 1), p));
                k++;
            }
            return result;
        }
        if (sig.Convention is "__fastcall" or "__vectorcall") return result;
        int at = 4;
        if (sig.Member && sig.Convention != "__thiscall") { result.Add((-1, 4, null)); at = 8; }
        if (hidden) at += 4;
        foreach (var p in sig.Params)
        {
            if (!Slot32(p)) break;
            result.Add((-1, at, p));
            at += 4;
        }
        return result;
    }

    private (MsvcRttiClass Class, MsvcRttiVtable Vftable, int Slot)? TableAt(uint rva)
    {
        int lo = 0, hi = _tables.Length - 1, best = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (_tables[mid].Start <= rva) { best = mid; lo = mid + 1; } else hi = mid - 1;
        }
        // tables may share a start (folded vftables); any one that holds the address serves
        for (int i = best; i >= 0 && i > best - 4; i--)
        {
            var t = _tables[i];
            if (rva >= t.Start && rva < t.End && (rva - t.Start) % (uint)_ptr == 0) return (t.Class, t.Vftable, (int)((rva - t.Start) / (uint)_ptr));
        }
        return null;
    }

    private (VirtualCallSet, CodeXref[]) Run(int classes, CodeIndexOptions options, Stopwatch sw)
    {
        var functions = _index.Functions;
        // constructors and destructors (functions that reference a vftable) first: their summaries are used at calls to them
        var storers = new List<NativeFunction>();
        var callers = new List<NativeFunction>();
        foreach (var f in functions)
        {
            _ct.ThrowIfCancellationRequested();
            if ((f.Flags & FunctionFlags.Thunk) != 0 || f.InstructionCount == 0) continue;
            bool stores = false, calls = false;
            foreach (var x in _index.RefsFrom(f))
            {
                if (x.Kind is XrefKind.Address or XrefKind.Write or XrefKind.Read && _vftableStarts.Contains(x.To)) stores = true;
                else if (x.Kind is XrefKind.Call && _dispatchThunks.Contains(x.To)) calls = true;
            }
            if (stores) storers.Add(f);
            if (calls || HasIndirectTransfer(f)) callers.Add(f);
        }
        var po = new ParallelOptions { CancellationToken = _ct, MaxDegreeOfParallelism = options.MaxParallelism > 0 ? options.MaxParallelism : Environment.ProcessorCount };
        var summaries = new ConcurrentDictionary<uint, (int, uint)[]>();
        Parallel.ForEach(storers, po, () => new Flow(this), (f, _, flow) =>
        {
            if (flow.Analyze(f, summarize: true, record: false) is { Length: > 0 } s) summaries[f.Start] = s;
            return flow;
        }, _ => { });
        foreach (var (k, v) in summaries) _summaries[k] = v;

        var perFunction = new ConcurrentBag<(uint Function, List<VirtualCallSite> Sites, List<CodeXref> Edges)>();
        Parallel.ForEach(callers, po, () => new Flow(this), (f, _, flow) =>
        {
            flow.Analyze(f, summarize: false, record: true);
            if (flow.Sites.Count > 0) perFunction.Add((f.Start, [.. flow.Sites], [.. flow.Edges]));
            Interlocked.Add(ref _pureExcluded, flow.PureExcluded);
            flow.PureExcluded = 0;
            Interlocked.Increment(ref _analyzed);
            return flow;
        }, _ => { });

        var all = perFunction.SelectMany(p => p.Sites).ToArray();
        // a site in code two functions share is reported once
        Array.Sort(all, (a, b) => a.Rva != b.Rva ? a.Rva.CompareTo(b.Rva) : a.Function.CompareTo(b.Function));
        var unique = new List<VirtualCallSite>(all.Length);
        foreach (var s in all)
            if (unique.Count == 0 || unique[^1].Rva != s.Rva) unique.Add(s);
        var sites = unique.ToArray();
        var kept = sites.ToDictionary(s => s.Rva, s => s.Function);
        var edges = perFunction.SelectMany(p => p.Edges.Where(e => kept.GetValueOrDefault(e.From) == p.Function)).Distinct().ToArray();
        Array.Sort(edges, (a, b) => a.From != b.From ? a.From.CompareTo(b.From) : a.To != b.To ? a.To.CompareTo(b.To) : a.Kind.CompareTo(b.Kind));
        var stats = new VirtualCallStats(sites.Length, sites.Count(s => s.Status == VirtualCallStatus.Exact), sites.Count(s => s.Status == VirtualCallStatus.Possible),
            sites.Count(s => s.Status == VirtualCallStatus.Unresolved), edges.Length, classes, _analyzed, _notConverged, _pureExcluded,
            sites.Count(s => s.Incomplete), sw.Elapsed);
        var notes = new List<string>();
        if (_notConverged > 0) notes.Add($"{_notConverged} functions with indirect calls were not analyzed to the end (visit budget)");
        return (new VirtualCallSet(sites, stats, notes), edges);
    }

    /// <summary>Any byte pair FF /2 (call r/m) or FF /4 (jmp r/m) in the function's code: a cheap filter, false positives are fine.</summary>
    private bool HasIndirectTransfer(NativeFunction f)
    {
        foreach (var (s, e) in _index.Ranges(f))
        {
            if (_ctx.Code.RegionAt(s) is not { } region) continue;
            int from = (int)(s - region.Rva), to = (int)Math.Min(e - region.Rva, (uint)region.Bytes.Length);
            var span = region.Bytes.AsSpan(from, Math.Max(0, to - from));
            for (int i = span.IndexOf((byte)0xFF); i >= 0 && i + 1 < span.Length; )
            {
                int reg = (span[i + 1] >> 3) & 7;
                if (reg is 2 or 4) return true;
                int next = span[(i + 1)..].IndexOf((byte)0xFF);
                if (next < 0) break;
                i += 1 + next;
            }
        }
        return false;
    }

    /// <summary>x86: bytes a function pops on return (ret n), when every return agrees; null when unknown.</summary>
    private int? PopsOf(uint target) => _pops.GetOrAdd(target, t =>
    {
        if (_index.FunctionByStart(t) is not { } f || (f.Flags & FunctionFlags.Thunk) != 0) return null;
        int? found = null;
        int budget = 20_000;
        foreach (var (s, e) in _index.Ranges(f))
        {
            if (_ctx.Code.RegionAt(s) is not { } region) return null;
            int from = (int)(s - region.Rva), to = (int)Math.Min(e - region.Rva, (uint)region.Bytes.Length);
            if (to <= from) continue;
            var decoder = Decoder.Create(32, new ByteArrayCodeReader(region.Bytes, from, to - from), _image.ImageBase + s);
            while (decoder.IP < _image.ImageBase + e && budget-- > 0)
            {
                decoder.Decode(out var x);
                if (x.IsInvalid) break;
                if (x.Mnemonic != Mnemonic.Ret) continue;
                int pops = x.OpCount > 0 ? x.Immediate16 : 0;
                if (found != null && found != pops) return null;
                found = pops;
            }
        }
        return found;
    });

    private readonly record struct Resolution(VirtualCallStatus Status, VirtualCallReason Reason, VirtualReceiver Receiver, uint ClassTd, uint Vftable,
        List<uint> Targets, bool Incomplete, int Pure = 0);

    /// <summary>A call through slot <paramref name="slot"/> of a known vftable.</summary>
    private Resolution FromVftable(MsvcRttiClass c, MsvcRttiVtable v, int slot)
    {
        var targets = new List<uint>();
        uint t = v.SlotRvas[slot];
        if (!_pure.Contains(t)) targets.Add(t);
        return Finish(VirtualReceiver.Vftable, c.TypeDescriptorRva, v.VftableRva, targets, VirtualCallReason.None, incomplete: false) with { Pure = 1 - targets.Count };
    }

    /// <summary>A call through this of <paramref name="function"/>, the vfptr at this + <paramref name="vfptr"/>, slot <paramref name="slot"/>.</summary>
    private Resolution FromThis(uint function, int vfptr, int slot)
    {
        var receiver = VirtualReceiver.This;
        if (!_owners.TryGetValue(function, out var owners))
        {
            if (!_named.TryGetValue(function, out var named))
                return new Resolution(VirtualCallStatus.Unresolved, VirtualCallReason.ReceiverUnknown, VirtualReceiver.Unknown, 0, 0, [], false);
            owners = [(named, 0)];
            receiver = VirtualReceiver.Name;
        }
        return FromOwners(owners, vfptr, slot, receiver);
    }

    /// <summary>A call through an object of class <paramref name="classIndex"/> (from a decorated name), the vfptr at + <paramref name="vfptr"/>.</summary>
    private Resolution FromClass(int classIndex, int vfptr, int slot) =>
        classIndex >= 0 && classIndex < _classes.Count
            ? FromOwners([(_classes[classIndex], 0)], vfptr, slot, VirtualReceiver.Name)
            : new Resolution(VirtualCallStatus.Unresolved, VirtualCallReason.ReceiverUnknown, VirtualReceiver.Unknown, 0, 0, [], false);

    /// <summary>The receiver is the subobject at s of one of <paramref name="owners"/> (or of a class derived from one).</summary>
    private Resolution FromOwners(List<(MsvcRttiClass Class, uint Offset)> owners, int vfptr, int slot, VirtualReceiver receiver)
    {
        var set = new HashSet<uint>();
        bool incomplete = false, any = false;
        var reason = VirtualCallReason.None;
        uint classTd = 0, vftable = 0;
        // the owner every other derives from names the receiver
        var root = owners.FirstOrDefault(o => owners.All(p => ReferenceEquals(p.Class, o.Class)
            || p.Class.Bases.Any(b => b.TypeDescriptorRva == o.Class.TypeDescriptorRva))).Class ?? owners[0].Class;
        foreach (var (c, s) in owners)
        {
            long x = (long)s + vfptr;
            if (x < 0 || x > uint.MaxValue) { reason = VirtualCallReason.NoVftableAtOffset; continue; }
            if (!Collect(c, (uint)x, slot, set, ref incomplete, ref reason, out var own)) continue;
            any = true;
            if (ReferenceEquals(c, root) || classTd == 0) (classTd, vftable) = (c.TypeDescriptorRva, own);
        }
        if (!any) return new Resolution(VirtualCallStatus.Unresolved, reason, receiver, root.TypeDescriptorRva, 0, [], false);
        var targets = new List<uint>(set.Count);
        foreach (var t in set)
            if (!_pure.Contains(t)) targets.Add(t);
        targets.Sort();
        return Finish(receiver, classTd, vftable, targets, VirtualCallReason.None, incomplete) with { Pure = set.Count - targets.Count };
    }

    /// <summary>Slot <paramref name="slot"/> of <paramref name="c"/>'s vftable at subobject <paramref name="x"/> and of the same subobject in every derived class.</summary>
    private bool Collect(MsvcRttiClass c, uint x, int slot, HashSet<uint> targets, ref bool incomplete, ref VirtualCallReason reason, out uint own)
    {
        own = 0;
        if (!_vftablesAt.TryGetValue((c.TypeDescriptorRva, x), out var vs)) { reason = VirtualCallReason.NoVftableAtOffset; return false; }
        bool inRange = false;
        foreach (var v in vs)
            if (slot < v.SlotRvas.Count) { targets.Add(v.SlotRvas[slot]); inRange = true; own = v.VftableRva; }
        if (!inRange) { reason = VirtualCallReason.SlotOutOfRange; return false; }
        if (_derived.TryGetValue(c.TypeDescriptorRva, out var placements))
            foreach (var (d, at, viaVirtual) in placements)
            {
                if (viaVirtual) { incomplete = true; continue; }
                long y = (long)at + x;
                if (y < 0 || y > uint.MaxValue || !_vftablesAt.TryGetValue((d.TypeDescriptorRva, (uint)y), out var dvs)) continue; // no vftable of its own there (abstract, novtable)
                foreach (var v in dvs)
                    if (slot < v.SlotRvas.Count) targets.Add(v.SlotRvas[slot]);
                    else incomplete = true;
            }
        return true;
    }

    private Resolution Finish(VirtualReceiver receiver, uint classTd, uint vftable, List<uint> targets, VirtualCallReason reason, bool incomplete)
    {
        if (targets.Count == 0)
            return new Resolution(VirtualCallStatus.Unresolved, reason == VirtualCallReason.None ? VirtualCallReason.OnlyPureTargets : reason, receiver, classTd, vftable, targets, incomplete);
        if (targets.Count > _maxTargets)
            return new Resolution(VirtualCallStatus.Unresolved, VirtualCallReason.TooManyTargets, receiver, classTd, vftable, targets, incomplete);
        var status = targets.Count == 1 && !incomplete ? VirtualCallStatus.Exact : VirtualCallStatus.Possible;
        return new Resolution(status, VirtualCallReason.None, receiver, classTd, vftable, targets, incomplete);
    }

    private enum VKind : byte
    {
        Unknown,
        /// <summary>The value 0 (a null pointer joins with any pointer).</summary>
        Zero,
        /// <summary>Entry stack pointer + Off.</summary>
        Stack,
        /// <summary>Entry this + Off.</summary>
        This,
        /// <summary>The object a call at Id returned, + Off.</summary>
        Obj,
        /// <summary>Address Id in the image.</summary>
        Const,
        /// <summary>Loaded from [Base object Id + Off]: a vfptr when the object has one there.</summary>
        Field,
        /// <summary>Loaded from [Field + Slot]: a vftable slot.</summary>
        FieldSlot,
        /// <summary>Loaded through a pointer the flow does not know.</summary>
        Opaque,
        /// <summary>Loaded from [Opaque + Slot].</summary>
        OpaqueSlot,
        /// <summary>Loaded from address Id in the image.</summary>
        FnConst,
        /// <summary>A pointer to an object of class Id (its static type, from a decorated name), + Off.</summary>
        Typed,
    }

    private readonly record struct Val(VKind Kind, uint Id = 0, int Off = 0, int Slot = 0, VKind Base = VKind.Unknown)
    {
        public static Val Unknown => default;
        public bool IsPointer => Kind is VKind.Stack or VKind.This or VKind.Obj or VKind.Const or VKind.Typed;
        public bool IsObject => Kind is VKind.This or VKind.Obj;
        public Val Plus(long delta) => delta is >= int.MinValue and <= int.MaxValue && (long)Off + delta is >= int.MinValue and <= int.MaxValue
            ? this with { Off = (int)(Off + delta) } : Unknown;

        public static Val Join(Val a, Val b) =>
            a == b ? a : a.Kind == VKind.Zero && b.IsPointer ? b : b.Kind == VKind.Zero && a.IsPointer ? a : Unknown;
    }

    /// <summary>Registers, stack slots and object fields known at a point.</summary>
    private sealed class State
    {
        public readonly Val[] Regs = new Val[16];
        public readonly Dictionary<int, Val> Slots = [];
        /// <summary>Fields of objects (This / Obj) holding a known value; an Obj field merged with a different value holds Unknown.</summary>
        public readonly Dictionary<(VKind Kind, uint Id, int Off), Val> Cells = [];

        /// <summary>Becomes a copy of <paramref name="o"/>, reusing this state's storage.</summary>
        public State CopyFrom(State o)
        {
            Array.Copy(o.Regs, Regs, Regs.Length);
            Slots.Clear();
            foreach (var (k, v) in o.Slots) Slots[k] = v;
            Cells.Clear();
            foreach (var (k, v) in o.Cells) Cells[k] = v;
            return this;
        }

        public void Reset()
        {
            Array.Clear(Regs);
            Slots.Clear();
            Cells.Clear();
            // clearing costs the capacity: do not carry one large function's tables into every later one
            if (Slots.EnsureCapacity(0) > 256) Slots.TrimExcess();
            if (Cells.EnsureCapacity(0) > 256) Cells.TrimExcess();
        }

        /// <summary>Merges <paramref name="other"/> in; true when this state changed.</summary>
        public bool Join(State other)
        {
            bool changed = false;
            for (int i = 0; i < Regs.Length; i++)
            {
                var j = Val.Join(Regs[i], other.Regs[i]);
                if (j != Regs[i]) { Regs[i] = j; changed = true; }
            }
            List<int>? dropSlots = null;
            foreach (var (k, v) in Slots)
            {
                var j = other.Slots.TryGetValue(k, out var o) ? Val.Join(v, o) : Val.Unknown;
                if (j.Kind == VKind.Unknown) (dropSlots ??= []).Add(k);
                else if (j != v) { Slots[k] = j; changed = true; }
            }
            if (dropSlots != null) { foreach (var k in dropSlots) Slots.Remove(k); changed = true; }
            // fields of this: known where every path agrees; fields of objects created here: from the paths that set them,
            // a disagreement leaves Unknown (so a later path cannot bring the value back)
            List<(VKind, uint, int)>? drop = null;
            List<((VKind, uint, int), Val)>? set = null;
            foreach (var (k, v) in Cells)
            {
                bool obj = k.Item1 == VKind.Obj;
                if (other.Cells.TryGetValue(k, out var o))
                {
                    if (o == v) continue;
                    if (obj) { if (v.Kind != VKind.Unknown) (set ??= []).Add((k, Val.Unknown)); }
                    else (drop ??= []).Add(k);
                }
                else if (!obj) (drop ??= []).Add(k);
            }
            foreach (var (k, v) in other.Cells)
                if (k.Item1 == VKind.Obj && !Cells.ContainsKey(k)) (set ??= []).Add((k, v));
            if (drop != null) foreach (var k in drop) { Cells.Remove(k); changed = true; }
            if (set != null) foreach (var (k, v) in set) { Cells[k] = v; changed = true; }
            return changed;
        }
    }

    /// <summary>One worker's analysis of functions: a walker for the graph, a decoder, scratch state.</summary>
    private sealed class Flow(VirtualCallResolver r)
    {
        private readonly FunctionWalker _walker = new(r._ctx);
        private readonly InstructionInfoFactory _info = new();
        private readonly Dictionary<uint, int> _blockOf = [];
        private readonly List<Instruction[]> _blocks = [];
        private readonly List<List<int>> _succs = [];
        public readonly List<VirtualCallSite> Sites = [];
        public readonly List<CodeXref> Edges = [];
        public int PureExcluded;
        private NativeFunction _f = null!;
        private bool _record;
        private Dictionary<int, uint>? _summary;
        private bool _summaryEmpty;

        private int Rsp => (int)(Register.RSP - Register.RAX);
        private int ThisReg => (int)(Register.RCX - Register.RAX);
        private int Rax => 0;

        public (int, uint)[]? Analyze(NativeFunction f, bool summarize, bool record)
        {
            Sites.Clear();
            Edges.Clear();
            _f = f;
            _record = false;
            _summary = summarize ? [] : null;
            _summaryEmpty = false;
            FunctionGraph? graph;
            try { graph = _walker.Walk(f, f.Start, buildGraph: true, r._ct, NativeCodeIndex.ChunkRoots(f)).Graph; }
            catch (Exception ex) when (ex is not OperationCanceledException) { return null; }
            if (graph == null || graph.Blocks.Count == 0 || !Decode(graph)) return null;

            _rented = 0;
            var entry = Rent();
            entry.Regs[Rsp] = new Val(VKind.Stack);
            entry.Regs[ThisReg] = new Val(VKind.This);
            // arguments whose class the decorated name gives (and x86 this passed on the stack)
            if (r._seeds.TryGetValue(f.Start, out var seeds))
                foreach (var (reg, slot, cls) in seeds)
                {
                    var v = cls < 0 ? new Val(VKind.This) : new Val(VKind.Typed, (uint)cls);
                    if (reg >= 0) entry.Regs[reg] = v;
                    else entry.Slots[slot] = v;
                }
            var ins = new State?[_blocks.Count];
            var queued = new bool[_blocks.Count];
            var work = new Queue<int>();
            void Seed(uint start, State s)
            {
                if (!_blockOf.TryGetValue(start, out int b) || ins[b] != null) return;
                ins[b] = s;
                queued[b] = true;
                work.Enqueue(b);
            }
            Seed(f.Start, entry);
            foreach (var c in f.Chunks) Seed(c.Start, Rent());
            int budget = 8 * _blocks.Count + 64;
            while (work.Count > 0)
            {
                if (--budget < 0)
                {
                    Interlocked.Increment(ref r._notConverged);
                    return null;
                }
                int b = work.Dequeue();
                queued[b] = false;
                var s = _scratch.CopyFrom(ins[b]!);
                foreach (ref readonly var x in _blocks[b].AsSpan()) Step(in x, s);
                foreach (int succ in _succs[b])
                {
                    bool changed;
                    if (ins[succ] == null) { ins[succ] = Rent().CopyFrom(s); changed = true; }
                    else changed = ins[succ]!.Join(s);
                    if (changed && !queued[succ]) { queued[succ] = true; work.Enqueue(succ); }
                }
            }
            if (summarize)
            {
                // the vftables this function leaves in [this + o] on every return
                for (int b = 0; b < _blocks.Count; b++)
                {
                    if (ins[b] == null) continue;
                    var s = _scratch.CopyFrom(ins[b]!);
                    foreach (ref readonly var x in _blocks[b].AsSpan())
                    {
                        if (x.FlowControl == FlowControl.Return) Returned(s);
                        Step(in x, s);
                    }
                }
                return _summaryEmpty || _summary!.Count == 0 ? null : _summary.Select(kv => (kv.Key, kv.Value)).OrderBy(p => p.Key).ToArray();
            }
            if (record)
            {
                _record = true;
                for (int b = 0; b < _blocks.Count; b++)
                {
                    if (ins[b] == null) continue;
                    var s = _scratch.CopyFrom(ins[b]!);
                    foreach (ref readonly var x in _blocks[b].AsSpan()) Step(in x, s);
                }
                _record = false;
            }
            return null;
        }

        private void Returned(State s)
        {
            if (_summaryEmpty) return;
            var here = new Dictionary<int, uint>();
            foreach (var (k, v) in s.Cells)
                if (k.Kind == VKind.This && k.Id == 0 && v.Kind == VKind.Const && r._vftableStarts.Contains(v.Id)) here[k.Off] = v.Id;
            if (_summary!.Count == 0 && !_seenReturn) { foreach (var (k, v) in here) _summary[k] = v; _seenReturn = true; }
            else
            {
                foreach (var k in _summary.Keys.ToList())
                    if (!here.TryGetValue(k, out var v) || v != _summary[k]) _summary.Remove(k);
            }
            if (_summary.Count == 0) _summaryEmpty = true;
        }

        private bool _seenReturn;

        // states of one analysis, reused by the next: a fresh state per block costs two dictionaries
        private readonly List<State> _pool = [];
        private readonly State _scratch = new();
        private int _rented;

        private State Rent()
        {
            if (_rented == _pool.Count) _pool.Add(new State());
            var s = _pool[_rented++];
            s.Reset();
            return s;
        }

        private bool Decode(FunctionGraph graph)
        {
            _blockOf.Clear();
            _blocks.Clear();
            _succs.Clear();
            _seenReturn = false;
            int total = 0;
            var list = new List<Instruction>();
            for (int i = 0; i < graph.Blocks.Count; i++)
            {
                var b = graph.Blocks[i];
                _blockOf[b.Start] = i;
                list.Clear();
                if (r._ctx.Code.RegionAt(b.Start) is { } region && b.End > b.Start)
                {
                    int from = (int)(b.Start - region.Rva), to = (int)Math.Min(b.End - region.Rva, (uint)region.Bytes.Length);
                    if (to > from)
                    {
                        var decoder = Decoder.Create(r._is64 ? 64 : 32, new ByteArrayCodeReader(region.Bytes, from, to - from), r._image.ImageBase + b.Start);
                        ulong end = r._image.ImageBase + b.Start + (ulong)(to - from);
                        while (decoder.IP < end)
                        {
                            decoder.Decode(out var x);
                            if (x.IsInvalid) break;
                            list.Add(x);
                            if (++total > MaxInstructions) return false;
                        }
                    }
                }
                _blocks.Add([.. list]);
            }
            foreach (var b in graph.Blocks)
            {
                var succ = new List<int>(b.Successors.Count);
                foreach (var e in b.Successors)
                    if (e.Kind != EdgeKind.TailCall && _blockOf.TryGetValue(e.To, out int t) && !succ.Contains(t)) succ.Add(t);
                _succs.Add(succ);
            }
            return true;
        }

        private int Reg(Register reg)
        {
            var full = reg.GetFullRegister();
            return full >= Register.RAX && full <= Register.R15 ? full - Register.RAX : -1;
        }

        /// <summary>The full register index of a pointer-sized register operand, else -1.</summary>
        private int PtrReg(Register reg) => reg.GetSize() == r._ptr ? Reg(reg) : -1;

        private uint Rva(in Instruction x) => (uint)(x.IP - r._image.ImageBase);

        private bool InImage(ulong va, out uint rva)
        {
            if (!r._is64) va &= 0xFFFFFFFF;
            rva = 0;
            if (va < r._image.ImageBase || va - r._image.ImageBase >= r._image.SizeOfImage) return false;
            rva = (uint)(va - r._image.ImageBase);
            return true;
        }

        /// <summary>An immediate operand as a constant: 0, or an address in the image (x86: covered by a relocation when the image has them).</summary>
        private Val Imm(in Instruction x, int operand)
        {
            ulong v = x.GetImmediate(operand);
            if (v == 0) return new Val(VKind.Zero);
            if (!InImage(v, out uint rva)) return Val.Unknown;
            // x86: the relocation sits on the immediate's 4 bytes, at the end of the instruction for the forms compilers emit
            if (!r._is64 && r._ctx.Relocations.Length > 0 && !r._ctx.IsRelocated(Rva(in x) + (uint)x.Length - 4)) return Val.Unknown;
            return new Val(VKind.Const, rva);
        }

        /// <summary>The address a memory operand names, as a value (lea).</summary>
        private Val Address(in Instruction x, State s)
        {
            if (x.IsIPRelativeMemoryOperand) return InImage(x.IPRelativeMemoryAddress, out uint t) ? new Val(VKind.Const, t) : Val.Unknown;
            if (x.MemoryIndex != Register.None) return Val.Unknown;
            long disp = r._is64 ? (long)x.MemoryDisplacement64 : (int)(uint)x.MemoryDisplacement64;
            if (x.MemoryBase == Register.None)
                return InImage(x.MemoryDisplacement64, out uint t) && (r._ctx.Relocations.Length == 0 || r._ctx.IsRelocated(Rva(in x) + (uint)x.Length - 4))
                    ? new Val(VKind.Const, t) : Val.Unknown;
            int b = PtrReg(x.MemoryBase);
            if (b < 0) return Val.Unknown;
            var v = s.Regs[b];
            return v.Kind is VKind.Stack or VKind.This or VKind.Obj or VKind.Typed ? v.Plus(disp) : Val.Unknown;
        }

        /// <summary>The value a pointer-sized load from the memory operand gives.</summary>
        private Val Load(in Instruction x, State s)
        {
            if (x.IsIPRelativeMemoryOperand || x.MemoryBase == Register.None || x.MemoryIndex != Register.None) return Val.Unknown;
            int b = PtrReg(x.MemoryBase);
            if (b < 0) return Val.Unknown;
            long disp = r._is64 ? (long)x.MemoryDisplacement64 : (int)(uint)x.MemoryDisplacement64;
            return LoadFrom(s.Regs[b], disp, s);
        }

        private Val LoadFrom(Val p, long disp, State s)
        {
            if (disp is < int.MinValue or > int.MaxValue) return Val.Unknown;
            int d = (int)disp;
            switch (p.Kind)
            {
                case VKind.Stack:
                    return (long)p.Off + d is >= int.MinValue and <= int.MaxValue && s.Slots.TryGetValue(p.Off + d, out var slot) ? slot : Val.Unknown;
                case VKind.This or VKind.Obj:
                    {
                        long off = (long)p.Off + d;
                        if (off is < int.MinValue or > int.MaxValue) return Val.Unknown;
                        if (s.Cells.TryGetValue((p.Kind, p.Id, (int)off), out var cell) && cell.Kind != VKind.Unknown) return cell;
                        return new Val(VKind.Field, p.Id, (int)off, 0, p.Kind);
                    }
                case VKind.Typed:
                    {
                        // objects of a static type share the class index: no fields are tracked
                        long off = (long)p.Off + d;
                        return off is < int.MinValue or > int.MaxValue ? Val.Unknown : new Val(VKind.Field, p.Id, (int)off, 0, VKind.Typed);
                    }
                case VKind.Const:
                    return d >= 0 && (long)p.Id + d < uint.MaxValue ? new Val(VKind.FnConst, (uint)(p.Id + d)) : Val.Unknown;
                case VKind.Field:
                    return new Val(VKind.FieldSlot, p.Id, p.Off, d, p.Base);
                case VKind.Zero:
                    return Val.Unknown;
                case VKind.Opaque:
                    return new Val(VKind.OpaqueSlot, 0, 0, d);
                default:
                    return new Val(VKind.Opaque);
            }
        }

        private void Store(in Instruction x, State s, Val value, int size)
        {
            if (x.IsIPRelativeMemoryOperand || x.MemoryBase == Register.None || x.MemoryIndex != Register.None) return;
            int b = PtrReg(x.MemoryBase);
            if (b < 0) return;
            long disp = r._is64 ? (long)x.MemoryDisplacement64 : (int)(uint)x.MemoryDisplacement64;
            var p = s.Regs[b];
            if (p.Kind is not (VKind.Stack or VKind.This or VKind.Obj)) return;
            long at = (long)p.Off + disp;
            if (at is < int.MinValue or > int.MaxValue - 16) return;
            if (size != r._ptr) value = Val.Unknown;
            if (p.Kind == VKind.Stack)
            {
                foreach (var k in s.Slots.Keys.Where(k => k != at && k < at + Math.Max(size, 1) && k + r._ptr > at).ToList()) s.Slots.Remove(k);
                if (value.Kind == VKind.Unknown) s.Slots.Remove((int)at);
                else s.Slots[(int)at] = value;
                return;
            }
            var key = (p.Kind, p.Id, (int)at);
            if (value.Kind == VKind.Const) s.Cells[key] = value;
            else if (p.Kind == VKind.Obj && s.Cells.ContainsKey(key)) s.Cells[key] = Val.Unknown;
            else s.Cells.Remove(key);
        }

        private void Step(in Instruction x, State s)
        {
            switch (x.FlowControl)
            {
                case FlowControl.Call:
                case FlowControl.IndirectCall:
                    Call(in x, s);
                    return;
                case FlowControl.IndirectBranch:
                    if (_record) Site(in x, s, tail: true);
                    return;
                case FlowControl.UnconditionalBranch or FlowControl.ConditionalBranch or FlowControl.Return:
                    return;
            }
            switch (x.Mnemonic)
            {
                case Mnemonic.Mov when x.OpCount == 2:
                    if (x.Op0Kind == OpKind.Register)
                    {
                        int d = Reg(x.Op0Register);
                        if (d < 0) return;
                        if (x.Op0Register.GetSize() != r._ptr)
                        {
                            s.Regs[d] = x.Op1Kind is OpKind.Immediate32 or OpKind.Immediate8to32 or OpKind.Immediate16 or OpKind.Immediate8 && x.GetImmediate(1) == 0
                                ? new Val(VKind.Zero) : Val.Unknown;
                            return;
                        }
                        s.Regs[d] = x.Op1Kind switch
                        {
                            OpKind.Register => PtrReg(x.Op1Register) is var src and >= 0 ? s.Regs[src] : Val.Unknown,
                            OpKind.Memory => Load(in x, s),
                            OpKind.Immediate32 or OpKind.Immediate64 or OpKind.Immediate32to64 or OpKind.Immediate8to32 or OpKind.Immediate8to64 => Imm(in x, 1),
                            _ => Val.Unknown,
                        };
                        return;
                    }
                    if (x.Op0Kind == OpKind.Memory)
                    {
                        var value = x.Op1Kind switch
                        {
                            OpKind.Register => PtrReg(x.Op1Register) is var src and >= 0 ? s.Regs[src] : Val.Unknown,
                            OpKind.Immediate32 or OpKind.Immediate32to64 or OpKind.Immediate8to32 => Imm(in x, 1),
                            _ => Val.Unknown,
                        };
                        Store(in x, s, value, x.MemorySize.GetSize());
                    }
                    return;
                case Mnemonic.Lea when x.Op0Kind == OpKind.Register:
                    {
                        int d = Reg(x.Op0Register);
                        if (d >= 0) s.Regs[d] = x.Op0Register.GetSize() == r._ptr ? Address(in x, s) : Val.Unknown;
                        return;
                    }
                case Mnemonic.Push when x.OpCount == 1:
                    {
                        var value = x.Op0Kind switch
                        {
                            OpKind.Register => PtrReg(x.Op0Register) is var src and >= 0 ? s.Regs[src] : Val.Unknown,
                            OpKind.Memory => Load(in x, s),
                            OpKind.Immediate32 or OpKind.Immediate8to32 or OpKind.Immediate32to64 or OpKind.Immediate8to64 => Imm(in x, 0),
                            _ => Val.Unknown,
                        };
                        var sp = s.Regs[Rsp];
                        if (sp.Kind != VKind.Stack) return;
                        sp = sp.Plus(-r._ptr);
                        s.Regs[Rsp] = sp;
                        if (sp.Kind != VKind.Stack) return;
                        if (value.Kind == VKind.Unknown) s.Slots.Remove(sp.Off); else s.Slots[sp.Off] = value;
                        return;
                    }
                case Mnemonic.Pop when x.OpCount == 1:
                    {
                        var sp = s.Regs[Rsp];
                        var value = sp.Kind == VKind.Stack && s.Slots.TryGetValue(sp.Off, out var v) ? v : Val.Unknown;
                        if (sp.Kind == VKind.Stack) s.Regs[Rsp] = sp.Plus(r._ptr);
                        if (x.Op0Kind == OpKind.Register && Reg(x.Op0Register) is var d and >= 0)
                            s.Regs[d] = x.Op0Register.GetSize() == r._ptr ? value : Val.Unknown;
                        else if (x.Op0Kind == OpKind.Memory) Store(in x, s, value, r._ptr);
                        return;
                    }
                case Mnemonic.Add or Mnemonic.Sub when x.Op0Kind == OpKind.Register && x.Op1Kind is OpKind.Immediate8to32 or OpKind.Immediate32 or OpKind.Immediate8to64 or OpKind.Immediate32to64:
                    {
                        int d = Reg(x.Op0Register);
                        if (d < 0) return;
                        var v = s.Regs[d];
                        long imm = (long)x.GetImmediate(1);
                        if (!r._is64) imm = (int)imm;
                        s.Regs[d] = x.Op0Register.GetSize() == r._ptr && v.Kind is VKind.Stack or VKind.This or VKind.Obj or VKind.Typed
                            ? v.Plus(x.Mnemonic == Mnemonic.Add ? imm : -imm) : Val.Unknown;
                        return;
                    }
                case Mnemonic.Xor or Mnemonic.Sub when x.Op0Kind == OpKind.Register && x.Op1Kind == OpKind.Register && x.Op0Register == x.Op1Register:
                    {
                        int d = Reg(x.Op0Register);
                        if (d >= 0) s.Regs[d] = new Val(VKind.Zero);
                        return;
                    }
                case Mnemonic.Xchg when x.Op0Kind == OpKind.Register && x.Op1Kind == OpKind.Register:
                    {
                        int a = PtrReg(x.Op0Register), b = PtrReg(x.Op1Register);
                        if (a >= 0 && b >= 0) (s.Regs[a], s.Regs[b]) = (s.Regs[b], s.Regs[a]);
                        else { if (Reg(x.Op0Register) is var ra and >= 0) s.Regs[ra] = Val.Unknown; if (Reg(x.Op1Register) is var rb and >= 0) s.Regs[rb] = Val.Unknown; }
                        return;
                    }
                case Mnemonic.Leave:
                    {
                        int bp = (int)(Register.RBP - Register.RAX);
                        var frame = s.Regs[bp];
                        if (frame.Kind == VKind.Stack)
                        {
                            s.Regs[bp] = s.Slots.TryGetValue(frame.Off, out var saved) ? saved : Val.Unknown;
                            s.Regs[Rsp] = frame.Plus(r._ptr);
                        }
                        else s.Regs[bp] = s.Regs[Rsp] = Val.Unknown;
                        return;
                    }
                case Mnemonic.Cmp or Mnemonic.Test or Mnemonic.Bt or Mnemonic.Nop or Mnemonic.Prefetchnta or Mnemonic.Prefetcht0 or Mnemonic.Prefetcht1 or Mnemonic.Prefetcht2:
                    return;
            }
            Clobber(in x, s);
        }

        /// <summary>Registers and memory an instruction the flow does not model writes become unknown.</summary>
        private void Clobber(in Instruction x, State s)
        {
            var info = _info.GetInfo(in x);
            foreach (var u in info.GetUsedRegisters())
                if (u.Access is OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite && Reg(u.Register) is var d and >= 0)
                    s.Regs[d] = Val.Unknown;
            foreach (var m in info.GetUsedMemory())
            {
                if (m.Access is not (OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite)) continue;
                if (m.Index != Register.None || PtrReg(m.Base) is not (var b and >= 0)) continue;
                var p = s.Regs[b];
                long at = (long)p.Off + (r._is64 ? (long)m.Displacement : (int)(uint)m.Displacement);
                if (at is < int.MinValue or > int.MaxValue) continue;
                int size = Math.Max(1, m.MemorySize.GetSize());
                if (p.Kind == VKind.Stack)
                {
                    foreach (var k in s.Slots.Keys.Where(k => k < at + size && k + r._ptr > at).ToList()) s.Slots.Remove(k);
                }
                else if (p.Kind is VKind.This or VKind.Obj)
                {
                    foreach (var k in s.Cells.Keys.Where(k => k.Kind == p.Kind && k.Id == p.Id && k.Off < at + size && k.Off + r._ptr > at).ToList())
                        if (p.Kind == VKind.Obj) s.Cells[k] = Val.Unknown; else s.Cells.Remove(k);
                }
            }
        }

        private void Call(in Instruction x, State s)
        {
            uint rva = Rva(in x);
            uint? direct = x.Op0Kind is OpKind.NearBranch32 or OpKind.NearBranch64 or OpKind.NearBranch16 && InImage(x.NearBranchTarget, out uint t) ? t : null;
            List<uint>? targets = null;
            if (_record || !r._is64) targets = Site(in x, s, tail: false);
            var thisArg = s.Regs[ThisReg];
            (int, uint)[]? summary = null;
            if (direct is uint d0) r._summaries.TryGetValue(d0, out summary);
            // the call: volatile registers lost, the result is a new object (a constructor returns this)
            int[] volatiles = r._is64 ? [0, 1, 2, 8, 9, 10, 11] : [0, 1, 2];
            foreach (int v in volatiles) s.Regs[v] = Val.Unknown;
            if (summary != null && thisArg.Kind is VKind.This or VKind.Obj or VKind.Stack)
            {
                foreach (var (off, vftable) in summary)
                {
                    long at = (long)thisArg.Off + off;
                    if (at is < int.MinValue or > int.MaxValue) continue;
                    if (thisArg.Kind == VKind.Stack) s.Slots[(int)at] = new Val(VKind.Const, vftable);
                    else s.Cells[(thisArg.Kind, thisArg.Id, (int)at)] = new Val(VKind.Const, vftable);
                }
                s.Regs[Rax] = thisArg;
            }
            else
            {
                // a function or import whose decorated name returns a class pointer
                uint? callee = direct;
                if (direct is uint d2 && r._index.FunctionByStart(d2)?.ThunkImport is { } thunked) callee = thunked.SlotRva;
                else if (direct == null && x.Op0Kind == OpKind.Memory && x.MemoryIndex == Register.None
                         && (x.IsIPRelativeMemoryOperand || x.MemoryBase == Register.None)
                         && InImage(x.IsIPRelativeMemoryOperand ? x.IPRelativeMemoryAddress : x.MemoryDisplacement64, out uint slot)) callee = slot;
                s.Regs[Rax] = callee is uint c && r._returns.TryGetValue(c, out int cls) ? new Val(VKind.Typed, (uint)cls) : new Val(VKind.Obj, rva);
            }
            if (!r._is64)
            {
                // the callee pops its stack arguments (stdcall, thiscall) when it returns with ret n
                int? pops = direct is uint d1 ? r.PopsOf(d1) : targets is { Count: > 0 } ? r.PopsOf(targets[0]) : null;
                var sp = s.Regs[Rsp];
                s.Regs[Rsp] = pops is int n && sp.Kind == VKind.Stack ? sp.Plus(n) : Val.Unknown;
            }
        }

        /// <summary>Records the virtual call site at <paramref name="x"/>, if it is one; returns its targets.</summary>
        private List<uint>? Site(in Instruction x, State s, bool tail)
        {
            Val fn;
            if (x.Op0Kind == OpKind.Memory)
            {
                if (x.IsIPRelativeMemoryOperand || x.MemoryBase == Register.None)
                {
                    if (x.MemoryIndex != Register.None) return null;
                    ulong va = x.IsIPRelativeMemoryOperand ? x.IPRelativeMemoryAddress : x.MemoryDisplacement64;
                    if (!InImage(va, out uint slot) || !r._dispatchSlots.Contains(slot)) return null;
                    fn = s.Regs[Rax];
                }
                else
                {
                    if (x.MemoryIndex != Register.None) return null;
                    int b = PtrReg(x.MemoryBase);
                    if (b < 0) return null;
                    long disp = r._is64 ? (long)x.MemoryDisplacement64 : (int)(uint)x.MemoryDisplacement64;
                    var p = s.Regs[b];
                    if (p.Kind is not (VKind.Field or VKind.Opaque or VKind.Const)) return null;
                    fn = LoadFrom(p, disp, s);
                }
            }
            else if (x.Op0Kind == OpKind.Register)
            {
                int b = PtrReg(x.Op0Register);
                if (b < 0) return null;
                fn = s.Regs[b];
            }
            else if (x.Op0Kind is OpKind.NearBranch32 or OpKind.NearBranch64 && InImage(x.NearBranchTarget, out uint t) && r._dispatchThunks.Contains(t))
                fn = s.Regs[Rax];
            else return null;

            Resolution res;
            int slotIndex, vfptr = 0;
            switch (fn.Kind)
            {
                case VKind.FnConst:
                    if (r.TableAt(fn.Id) is not var (c, v, k)) return null;
                    res = r.FromVftable(c, v, k);
                    slotIndex = k;
                    break;
                case VKind.FieldSlot or VKind.OpaqueSlot:
                    if (fn.Slot < 0 || fn.Slot % r._ptr != 0 || fn.Slot / r._ptr > 65_535) return null;
                    slotIndex = fn.Slot / r._ptr;
                    vfptr = fn.Kind == VKind.FieldSlot ? fn.Off : 0;
                    res = fn.Kind == VKind.FieldSlot && fn.Base == VKind.This ? r.FromThis(_f.Start, fn.Off, slotIndex)
                        : fn.Kind == VKind.FieldSlot && fn.Base == VKind.Typed ? r.FromClass((int)fn.Id, fn.Off, slotIndex)
                        : new Resolution(VirtualCallStatus.Unresolved, VirtualCallReason.ReceiverUnknown, VirtualReceiver.Unknown, 0, 0, [], false);
                    break;
                default:
                    return null;
            }
            if (!_record) return res.Status == VirtualCallStatus.Unresolved ? null : res.Targets;
            uint rva = Rva(in x);
            PureExcluded += res.Pure;
            Sites.Add(new VirtualCallSite(rva, _f.Start, slotIndex, vfptr, res.Status, res.Reason, res.Receiver, res.ClassTd, res.Vftable, res.Targets.Count, tail,
                res.Incomplete));
            if (res.Status != VirtualCallStatus.Unresolved)
            {
                var kind = res.Status == VirtualCallStatus.Exact ? XrefKind.VirtualExact : XrefKind.VirtualPossible;
                foreach (var target in res.Targets) Edges.Add(new CodeXref(rva, target, kind));
            }
            return res.Status == VirtualCallStatus.Unresolved ? null : res.Targets;
        }
    }
}
