using Corvus.Core;
using Iced.Intel;
using Corvus.Native.Code;

namespace Corvus.Native.Calls;

/// <summary>
/// A function resolved at run time: GetProcAddress with a constant name (or ordinal) and, when it can be traced, the
/// module the handle comes from.
/// </summary>
/// <param name="Module">The module ("kernel32.dll"), null when the handle could not be traced.</param>
/// <param name="Name">The function name, or "#ordinal".</param>
/// <param name="CallSite">The GetProcAddress call.</param>
/// <param name="How">How the name and the module were found.</param>
/// <param name="Confidence">high: name and module from constants in the calling function; medium: the module handle comes through a global written once or a local wrapper of LoadLibrary;
/// low: the module is unknown.</param>
/// <param name="PointerGlobal">The global the result is stored to, when it is stored right after the call.</param>
/// <param name="PointerCalls">Calls through that global (call [g], or mov reg, [g] then call reg); empty unless the global has this one store.</param>
public sealed record DynamicImport(string? Module, string Name, uint CallSite, NativeFunction Function, string How, string Confidence,
    uint? PointerGlobal, IReadOnlyList<uint> PointerCalls)
{
    /// <summary>"kernel32!FlsAlloc" (the import naming style), "?!FlsAlloc" when the module is unknown.</summary>
    public string FullName => $"{(Module == null ? "?" : Module.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? Module[..^4] : Module)}!{Name}";
}

/// <summary>A module loaded or looked up at run time with a constant name (LoadLibrary*, GetModuleHandle*).</summary>
public sealed record DynamicModule(string Module, uint CallSite, NativeFunction Function, string Api);

/// <summary>The late-bound imports of an image.</summary>
public sealed class DynamicImportSet
{
    public IReadOnlyList<DynamicImport> Imports { get; init; } = [];
    public IReadOnlyList<DynamicModule> Modules { get; init; } = [];
    /// <summary>GetProcAddress calls whose name is not a constant.</summary>
    public int UnresolvedSites { get; init; }
    public int GetProcAddressSites { get; init; }
    /// <summary>Pointer globals with a single store from a late-bound import.</summary>
    public IReadOnlyDictionary<uint, DynamicImport> ByGlobal { get; init; } = new Dictionary<uint, DynamicImport>();
    /// <summary>GetProcAddress call -> the import it resolves.</summary>
    public IReadOnlyDictionary<uint, DynamicImport> BySite { get; init; } = new Dictionary<uint, DynamicImport>();
    public IReadOnlyList<string> Notes { get; init; } = [];

    /// <summary>Function start -> the late-bound imports it calls through pointer globals.</summary>
    public IReadOnlyDictionary<uint, IReadOnlyList<(uint Site, DynamicImport Import)>> CallsByFunction { get; init; } =
        new Dictionary<uint, IReadOnlyList<(uint, DynamicImport)>>();

    /// <summary>Imports matching "name", "module!name" or "module.dll!name" (case-insensitive).</summary>
    public List<DynamicImport> Find(string text)
    {
        text = text.Trim();
        int bang = text.LastIndexOf('!');
        var name = bang >= 0 ? text[(bang + 1)..] : text;
        var module = bang >= 0 ? Path.GetFileNameWithoutExtension(text[..bang]) : null;
        return Imports.Where(i => i.Name.Equals(name, StringComparison.OrdinalIgnoreCase)
                                  && (module == null || i.Module != null && Path.GetFileNameWithoutExtension(i.Module).Equals(module, StringComparison.OrdinalIgnoreCase)))
            .ToList();
    }
}

public sealed partial class CallAnalysis
{
    private const int MaxDynamicSites = 5000;
    private static readonly string[] ModuleApis = ["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetModuleHandleA", "GetModuleHandleW",
        "GetModuleHandleExA", "GetModuleHandleExW", "dlopen"];
    private static readonly string[] ResolverApis = ["GetProcAddress", "dlsym", "dlvsym"];

    private DynamicImportSet? _dynamic;
    private readonly object _dynamicGate = new();
    private bool _computingDynamic;

    /// <summary>Whether site results may be cached (late-bound imports are known).</summary>
    private bool DynamicReady => _dynamic != null;

    private void EnsureDynamic(CancellationToken ct)
    {
        if (_dynamic == null && !Monitor.IsEntered(_dynamicGate)) DynamicImports(ct);
    }

    /// <summary>The late-bound imports (computed once; the call sites of GetProcAddress, dlsym, LoadLibrary*, GetModuleHandle* and dlopen).</summary>
    public DynamicImportSet DynamicImports(CancellationToken ct = default)
    {
        if (_dynamic != null) return _dynamic;
        using (AssemblyWorkspace.Lock(_dynamicGate))
        {
            if (_dynamic != null) return _dynamic;
            if (_computingDynamic) return new DynamicImportSet();
            _computingDynamic = true;
            try
            {
                var set = BuildDynamic(ct);
                _sites.Clear();
                _slices?.Clear();
                _dynamic = set;
                return set;
            }
            finally { _computingDynamic = false; }
        }
    }

    /// <summary>An API name without the Mach-O symbol underscore ("_dlsym" is dlsym).</summary>
    internal static string? ApiName(ImageFormat format, string? name) => name is ['_', _, ..] && format == ImageFormat.MachO ? name[1..] : name;

    private string? ApiName(string? name) => ApiName(Image.Format, name);

    /// <summary>
    /// The calls to each of <paramref name="apis"/>: through imports, and to local functions of that name (a statically
    /// linked platform layer such as GetProcAddress over dlsym).
    /// </summary>
    private IEnumerable<(string Api, IEnumerable<CallSiteInfo> Calls)> ApiCalls(string[] apis, CancellationToken ct)
    {
        foreach (var imp in Image.Imports)
            if (ApiName(imp.Name) is { } api && apis.Contains(api))
                yield return (api, CallsTo(imp, MaxDynamicSites, ct));
        foreach (var f in Index.Functions)
            if (f.ThunkImport == null && ApiName(f.KnownName) is { } api && apis.Contains(api))
                yield return (api, Index.Callers(f).Take(MaxDynamicSites).Select(c => CallAt(c.From, ct)).OfType<CallSiteInfo>().DistinctBy(s => s.Rva).ToList());
    }

    private DynamicImportSet BuildDynamic(CancellationToken ct)
    {
        var notes = new List<string>();
        var modules = new List<DynamicModule>();
        foreach (var (api, calls) in ApiCalls(ModuleApis, ct))
            foreach (var s in calls)
            {
                if (modules.Count >= MaxDynamicSites) break;
                int p = api.StartsWith("GetModuleHandleEx", StringComparison.Ordinal) ? 1 : 0;
                if (p < s.Arguments.Count && s.Arguments[p].Kind == ArgKind.String)
                    modules.Add(new DynamicModule(Unquote(s.Arguments[p].Text), s.Rva, s.Caller, api));
            }

        var imports = new List<DynamicImport>();
        int sites = 0, unresolved = 0;
        foreach (var (api, calls) in ApiCalls(ResolverApis, ct))
            foreach (var s in calls)
            {
                sites++;
                if (s.Arguments.Count < 2) { unresolved++; continue; }
                var nameArg = s.Arguments[1];
                string name, how;
                var code = Code(s.Caller, ct);
                var (module, moduleHow, medium) = ModuleOf(code, s.Arguments[0].Raw, ct, 0);
                var moduleText = module != null ? $"; module: {moduleHow}" : "; module: not traced";
                var confidence = module == null ? "low" : medium ? "medium" : "high";
                if (nameArg.Kind == ArgKind.String) { name = Unquote(nameArg.Text); how = "name: string literal"; }
                else if (api == "GetProcAddress" && nameArg.Kind == ArgKind.Immediate && nameArg.Value is < 0x10000 and > 0) { name = $"#{nameArg.Value}"; how = "name: ordinal"; }
                else
                {
                    var wrapped = Wrapped(s, ct);
                    if (wrapped.Count == 0) { unresolved++; continue; }
                    foreach (var (site, caller, passed) in wrapped)
                        imports.Add(new DynamicImport(module, passed, site, caller, $"name: string literal passed to {s.Caller.Name}, which returns {api}'s result" + moduleText,
                            confidence, StoreOfResult(Code(caller, ct), site), []));
                    continue;
                }
                imports.Add(new DynamicImport(module, name, s.Rva, s.Caller, how + moduleText, confidence, StoreOfResult(code, s.Rva), []));
            }

        // pointer globals with one store: the calls through them are calls to the import
        var byGlobal = new Dictionary<uint, DynamicImport>();
        var bySite = new Dictionary<uint, DynamicImport>();
        var final = new List<DynamicImport>(imports.Count);
        foreach (var d in imports)
        {
            var result = d;
            if (d.PointerGlobal is { } g)
            {
                var writes = Index.RefsTo(g).Where(x => x.Kind is XrefKind.Write).Select(x => x.From).Distinct().ToList();
                bool unique = writes.Count == 1 || writes.All(w => imports.Any(o => o.Name == d.Name && o.Module == d.Module && o.PointerGlobal == g
                                                                         && Index.FunctionAt(w) == o.Function));
                if (unique)
                {
                    result = d with { PointerCalls = PointerCalls(g, ct) };
                    byGlobal.TryAdd(g, result);
                }
                else notes.Add($"{d.FullName}: the pointer at {Va(g)} has {writes.Count} stores; calls through it are not attributed");
            }
            bySite.TryAdd(d.CallSite, result);
            final.Add(result);
        }
        var byFunction = new Dictionary<uint, List<(uint, DynamicImport)>>();
        foreach (var d in byGlobal.Values)
            foreach (var call in d.PointerCalls)
                if (Index.FunctionAt(call) is { } f)
                {
                    if (!byFunction.TryGetValue(f.Start, out var list)) byFunction[f.Start] = list = [];
                    list.Add((call, d));
                }
        if (sites >= MaxDynamicSites) notes.Add($"stopped at {MaxDynamicSites} GetProcAddress calls");
        return new DynamicImportSet
        {
            Imports = final, Modules = modules, UnresolvedSites = unresolved, GetProcAddressSites = sites, ByGlobal = byGlobal, BySite = bySite, Notes = notes,
            CallsByFunction = byFunction.ToDictionary(kv => kv.Key, kv => (IReadOnlyList<(uint, DynamicImport)>)kv.Value),
        };
    }

    /// <summary>
    /// The module a handle value comes from: the string argument of the LoadLibrary* / GetModuleHandle* call that returned
    /// it, a global written once with such a result, __ImageBase / GetModuleHandle(NULL) (this image), or one agreeing
    /// alternative of a merge (the usual "cached handle or load it" pattern).
    /// </summary>
    private (string? Module, string How, bool Medium) ModuleOf(FunctionCode code, Val v, CancellationToken ct, int depth)
    {
        if (depth > 3) return (null, "", false);
        switch (v.Kind)
        {
            case VKind.Result:
            {
                var (b, i) = code.Position(v.Site);
                if (b < 0) break;
                var c = ResolveCallee(code, b, i, new ValueResolver(this, code) { Budget = 1500 });
                var api = ApiName(c.Import?.Name ?? c.Dynamic?.Name ?? (c.Kind == CalleeKind.Function ? c.Name : null));
                if (api == null || !ModuleApis.Contains(api))
                {
                    // a local wrapper such as LoadSystemLibrary(L"x.dll"): the module-like string it is passed
                    if (c.Kind != CalleeKind.Function) break;
                    var wrapper = Site(code, b, i);
                    var arg = wrapper.Arguments.FirstOrDefault(a => a.Kind == ArgKind.String && ModuleLike(Unquote(a.Text)));
                    if (arg != null) return (Unquote(arg.Text), $"{wrapper.ShortCallee}({arg.Text}) at {Va(v.Site)}, a wrapper", true);
                    break;
                }
                var site = Site(code, b, i);
                int p = api.StartsWith("GetModuleHandleEx", StringComparison.Ordinal) ? 1 : 0;
                if (p >= site.Arguments.Count) break;
                var a = site.Arguments[p];
                if (a.Kind == ArgKind.String) return (Unquote(a.Text), $"{api}({a.Text}) at {Va(v.Site)}", false);
                if (a.Kind == ArgKind.Immediate && a.Value == 0 && (api.StartsWith("GetModuleHandle", StringComparison.Ordinal) || api == "dlopen"))
                    return (Path.GetFileName(Image.Path), $"{api}(NULL) at {Va(v.Site)}: this image", false);
                break;
            }
            case VKind.TakenLocal:
            {
                // GetModuleHandleEx(flags, L"x.dll", &local)
                foreach (var s in CallsIn(code.Function, ct))
                    if (s.Import?.Name is "GetModuleHandleExW" or "GetModuleHandleExA" && s.Arguments.Count == 3 && s.Arguments[1].Kind == ArgKind.String
                        && s.Arguments[2].Raw is { Kind: VKind.StackAddr } slot && slot.Num == v.Num && slot.Site == v.Site)
                        return (Unquote(s.Arguments[1].Text), $"{s.ShortCallee}({s.Arguments[1].Text}, &local) at {Va(s.Rva)}", false);
                break;
            }
            case VKind.Addr when v.Rva == 0:
                return (Path.GetFileName(Image.Path), "__ImageBase: this image", false);
            case VKind.Load when !_slots.ContainsKey(v.Rva):
            {
                // every store to the global (at most 4) must hold the same module
                var writes = Index.RefsTo(v.Rva).Where(x => x.Kind == XrefKind.Write).Select(x => x.From).Distinct().Take(5).ToList();
                if (writes.Count is 0 or > 4) break;
                string? module = null, how = null;
                foreach (var w in writes)
                {
                    if (Index.FunctionAt(w) is not { } wf) return (null, "", false);
                    var wcode = Code(wf, ct);
                    var (b, i) = wcode.Position(w);
                    if (b < 0) return (null, "", false);
                    var x = wcode.Blocks[b][i].I;
                    if (x.Mnemonic != Mnemonic.Mov || x.Op0Kind != OpKind.Memory || x.Op1Kind != OpKind.Register) return (null, "", false);
                    var stored = new ValueResolver(this, wcode) { Budget = 3000 }.ValueBefore(Loc.Of(x.Op1Register), b, i);
                    var (m, h, _) = ModuleOf(wcode, stored, ct, depth + 1);
                    if (m == null || module != null && !module.Equals(m, StringComparison.OrdinalIgnoreCase)) return (null, "", false);
                    module ??= m;
                    how ??= $"{h}, stored to {Va(v.Rva)} at {Va(w)}" + (writes.Count > 1 ? $" (all {writes.Count} stores agree)" : "");
                }
                return (module, how!, true);
            }
            case VKind.Unknown when v.Alternatives is { Length: > 0 } alternatives:
            {
                string? module = null, how = null;
                bool global = false;
                foreach (var alt in alternatives)
                {
                    var (m, h, g) = ModuleOf(code, alt, ct, depth + 1);
                    if (m == null) continue;
                    if (module != null && !module.Equals(m, StringComparison.OrdinalIgnoreCase)) return (null, "", false);
                    module ??= m;
                    how ??= h;
                    global |= g;
                }
                if (module != null) return (module, how + $" (one of {alternatives.Length} paths)", global);
                break;
            }
        }
        return (null, "", false);
    }

    /// <summary>
    /// A wrapper (resolve(name) { return GetProcAddress(h, name); }): the name is a parameter and the result is returned; each
    /// call of the wrapper with a constant name, as (that call, its function, the name).
    /// </summary>
    private List<(uint Site, NativeFunction Caller, string Name)> Wrapped(CallSiteInfo s, CancellationToken ct)
    {
        var result = new List<(uint, NativeFunction, string)>();
        var root = Slices.Backward(s.Caller, new SliceSeed(SliceSeedKind.Argument, s.Rva, Slices.LocationName(Slices.ParameterEntry(1))), ct);
        if (root.Nodes.Count <= root.Root || root.Nodes[root.Root] is not { Kind: SliceNodeKind.Parameter, Index: >= 0 and var k }) return result;
        if (!Slices.Forward(s.Caller, new SliceSeed(SliceSeedKind.Result, s.Rva, Is64 ? "rax" : "eax"), ct).Nodes.Any(n => n.Kind == SliceNodeKind.Return)) return result;
        var entry = Slices.EntryToCall(Slices.ParameterEntry(k), tail: false);
        foreach (var c in Index.Callers(s.Caller).Where(c => c.Kind == XrefKind.Call && c.Caller != null).DistinctBy(c => c.From).Take(256))
        {
            var code = Code(c.Caller!, ct);
            var (b, i) = code.Position(c.From);
            if (b < 0) continue;
            var v = new ValueResolver(this, code) { Budget = 1500 }.ValueBefore(entry, b, i);
            if (v.Kind == VKind.Addr && ReadText(v.Rva, wide: false) is { Length: > 0 } name) result.Add((c.From, c.Caller!, name));
        }
        return result;
    }

    private static bool ModuleLike(string text) =>
        text.Length is > 4 and < 260 && System.Text.RegularExpressions.Regex.IsMatch(text, @"^[\w\\:.\- ]+\.(?:dll|exe|drv|ocx|cpl|sys|mui)$",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>
    /// The writable global the result of the call at <paramref name="site"/> is stored to: rax (and registers it is
    /// copied to) followed forward through the block and up to 3 successors until "mov [global], reg".
    /// </summary>
    private uint? StoreOfResult(FunctionCode code, uint site)
    {
        var (b, i) = code.Position(site);
        if (b < 0) return null;
        return FollowResult(code, b, i + 1, 1UL << FunctionCode.Bit(Register.RAX), 0, 32);
    }

    private uint? FollowResult(FunctionCode code, int block, int index, ulong regs, int depth, int budget)
    {
        var insns = code.Blocks[block];
        for (int i = index; i < insns.Length && budget-- > 0; i++)
        {
            ref readonly var d = ref insns[i];
            ref readonly var x = ref d.I;
            if (x.FlowControl is FlowControl.Call or FlowControl.IndirectCall)
            {
                if (IsTransparentCall(in d)) continue;
                regs &= ~VolatileMask;
                if (regs == 0) return null;
                continue;
            }
            if (x.Mnemonic == Mnemonic.Mov && x.Op1Kind == OpKind.Register && (regs & RegBit(x.Op1Register)) != 0)
            {
                if (x.Op0Kind == OpKind.Memory && d.HasMem && Image.SectionAt(d.MemRva) is { } s && (s.Access & SectionAccess.Write) != 0
                    && x.Op1Register.GetSize() == (Is64 ? 8 : 4))
                    return d.MemRva;
                if (x.Op0Kind == OpKind.Register) { regs |= RegBit(x.Op0Register); continue; }
            }
            regs &= ~d.Writes;
            if (regs == 0) return null;
            if (x.FlowControl is FlowControl.Return or FlowControl.IndirectBranch) return null;
        }
        if (budget <= 0 || depth >= 3) return null;
        foreach (var e in code.Graph.Blocks[block].Successors)
        {
            if (e.Kind == EdgeKind.TailCall) continue;
            int next = code.BlockIndexOf(e.To);
            if (next < 0) continue;
            if (FollowResult(code, next, 0, regs, depth + 1, budget) is { } g) return g;
        }
        return null;
    }

    private static ulong RegBit(Register r) => FunctionCode.Bit(r.GetFullRegister()) is var b and >= 0 ? 1UL << b : 0;

    /// <summary>Calls through the pointer global <paramref name="g"/>: call [g], or a register loaded from it and then called.</summary>
    private List<uint> PointerCalls(uint g, CancellationToken ct)
    {
        var result = new List<uint>();
        foreach (var x in Index.RefsTo(g))
        {
            if (x.Kind != XrefKind.Read || Index.FunctionAt(x.From) is not { } f) continue;
            ct.ThrowIfCancellationRequested();
            var code = Code(f, ct);
            var (b, i) = code.Position(x.From);
            if (b < 0) continue;
            ref readonly var load = ref code.Blocks[b][i].I;
            if (load.FlowControl is FlowControl.IndirectCall or FlowControl.IndirectBranch) { result.Add(x.From); continue; }
            if (load.Mnemonic != Mnemonic.Mov || load.Op0Kind != OpKind.Register) continue;
            if (CallThrough(code, b, i + 1, RegBit(load.Op0Register), 0, 48) is { } call) result.Add(call);
        }
        return result.Distinct().ToList();
    }

    /// <summary>
    /// The first call through a register in <paramref name="regs"/> (copies followed) from <paramref name="index"/> on, through the
    /// block and up to 3 successors: call / jmp reg, or with rax the CFG dispatch (call [dispatch pointer] or a "jmp rax" thunk).
    /// </summary>
    private uint? CallThrough(FunctionCode code, int block, int index, ulong regs, int depth, int budget)
    {
        ulong rax = 1UL << FunctionCode.Bit(Register.RAX);
        var insns = code.Blocks[block];
        for (int i = index; i < insns.Length && budget-- > 0; i++)
        {
            ref readonly var d = ref insns[i];
            ref readonly var c = ref d.I;
            if (c.FlowControl is FlowControl.IndirectCall or FlowControl.IndirectBranch)
            {
                if (c.Op0Kind == OpKind.Register && (regs & RegBit(c.Op0Register)) != 0) return d.Rva;
                if ((regs & rax) != 0 && c.Op0Kind == OpKind.Memory && d.HasMem && _dispatchSlots.Contains(d.MemRva)) return d.Rva;
                if (IsTransparentCall(in d)) continue;
                if (c.FlowControl == FlowControl.IndirectBranch) return null;
                regs &= ~VolatileMask;
            }
            else if (c.FlowControl is FlowControl.Call or FlowControl.UnconditionalBranch && c.Op0Kind is OpKind.NearBranch32 or OpKind.NearBranch64)
            {
                if ((regs & rax) != 0 && FunctionCode.TryRva(Image, Is64, c.NearBranchTarget, out uint t) && IsDispatchThunk(t)) return d.Rva;
                if (c.FlowControl == FlowControl.Call) regs &= ~VolatileMask;
            }
            else if (c.Mnemonic == Mnemonic.Mov && c.Op0Kind == OpKind.Register && c.Op1Kind == OpKind.Register && (regs & RegBit(c.Op1Register)) != 0)
            {
                regs |= RegBit(c.Op0Register);
                continue;
            }
            else regs &= ~d.Writes;
            if (regs == 0 || c.FlowControl == FlowControl.Return) return null;
        }
        if (budget <= 0 || depth >= 3) return null;
        foreach (var e in code.Graph.Blocks[block].Successors)
        {
            if (e.Kind == EdgeKind.TailCall) continue;
            int next = code.BlockIndexOf(e.To);
            if (next >= 0 && CallThrough(code, next, 0, regs, depth + 1, budget) is { } site) return site;
        }
        return null;
    }

    private ulong VolatileMask
    {
        get
        {
            if (Is64) return Abi.VolatileMask;
            ulong m = 0;
            foreach (var r in new[] { Register.RAX, Register.RCX, Register.RDX }) m |= 1UL << FunctionCode.Bit(r);
            return m;
        }
    }
}
