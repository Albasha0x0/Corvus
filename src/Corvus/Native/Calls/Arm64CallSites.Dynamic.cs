using System.Buffers.Binary;
using AsmArm64;
using Corvus.Native.Code;

namespace Corvus.Native.Calls;

internal sealed partial class Arm64CallSites
{
    private const int MaxDynamicSites = 5000;
    private static readonly string[] ResolverApis = ["GetProcAddress", "dlsym", "dlvsym"];
    private static readonly string[] ModuleApis = ["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetModuleHandleA", "GetModuleHandleW", "dlopen"];

    private DynamicImportSet? _dynamic;
    private readonly object _dynamicGate = new();
    private bool _computingDynamic;

    private void EnsureDynamic(CancellationToken ct)
    {
        if (_dynamic == null && !Monitor.IsEntered(_dynamicGate)) DynamicImports(ct);
    }

    /// <summary>Functions resolved at run time by name: GetProcAddress, dlsym and dlvsym calls with a constant name (computed once).</summary>
    public DynamicImportSet DynamicImports(CancellationToken ct = default)
    {
        if (_dynamic != null) return _dynamic;
        lock (_dynamicGate)
        {
            if (_dynamic != null) return _dynamic;
            if (_computingDynamic) return new DynamicImportSet();
            _computingDynamic = true;
            try
            {
                var set = BuildDynamic(ct);
                _sites.Clear();
                Arm64Trace.For(_index).ClearSlices();
                _dynamic = set;
                return set;
            }
            finally { _computingDynamic = false; }
        }
    }

    private DynamicImportSet BuildDynamic(CancellationToken ct)
    {
        var imports = new List<DynamicImport>();
        int sites = 0, unresolved = 0;
        var format = _index.Image.Format;
        foreach (var api in _index.Image.Imports.Where(i => ResolverApis.Contains(CallAnalysis.ApiName(format, i.Name))))
            foreach (var s in CallsTo(api, MaxDynamicSites, ct))
            {
                sites++;
                if (s.Arguments.Count < 2) { unresolved++; continue; }
                var nameArg = s.Arguments[1];
                string name, how;
                var module = ModuleOf(s, ct);
                var moduleText = module != null ? $"; module: {module.Value.How}" : "; module: not traced";
                if (nameArg.Kind == ArgKind.String) { name = Unquote(nameArg.Text); how = "name: string literal"; }
                else if (CallAnalysis.ApiName(format, api.Name) == "GetProcAddress" && nameArg.Kind == ArgKind.Immediate && nameArg.Value is > 0 and < 0x10000) { name = $"#{nameArg.Value}"; how = "name: ordinal"; }
                else
                {
                    var wrapped = Wrapped(s, ct);
                    if (wrapped.Count == 0) { unresolved++; continue; }
                    foreach (var (site, caller, passed) in wrapped)
                        imports.Add(new DynamicImport(module?.Module, passed, site, caller, $"name: string literal passed to {s.Caller.Name}, which returns {api.Name}'s result" + moduleText,
                            module == null ? "low" : "high", null, []));
                    continue;
                }
                imports.Add(new DynamicImport(module?.Module, name, s.Rva, s.Caller, how + moduleText, module == null ? "low" : "high", StoredResult(s, ct), []));
            }
        var byGlobal = new Dictionary<uint, DynamicImport>();
        var notes = new List<string>();
        foreach (var d in imports)
            if (d.PointerGlobal is { } g)
            {
                int writes = _index.RefsTo(g).Where(x => x.Kind == XrefKind.Write).Select(x => x.From).Distinct().Count();
                if (writes == 1) byGlobal.TryAdd(g, d);
                else notes.Add($"{d.FullName}: the pointer at {Va(g)} has {writes} stores; calls through it are not attributed");
            }
        if (sites >= MaxDynamicSites) notes.Add($"stopped at {MaxDynamicSites} resolver calls");
        return new DynamicImportSet
        {
            Imports = imports, UnresolvedSites = unresolved, GetProcAddressSites = sites, ByGlobal = byGlobal,
            BySite = imports.GroupBy(d => d.CallSite).ToDictionary(g => g.Key, g => g.First()), Notes = notes,
        };
    }

    /// <summary>A wrapper returning the resolver's result for a name it is passed: each call of it with a constant name.</summary>
    private List<(uint Site, NativeFunction Caller, string Name)> Wrapped(CallSiteInfo s, CancellationToken ct)
    {
        var result = new List<(uint, NativeFunction, string)>();
        var trace = Arm64Trace.For(_index);
        var root = trace.Slices.Backward(s.Caller, new SliceSeed(SliceSeedKind.Argument, s.Rva, "x1"), ct);
        if (root.Nodes.Count <= root.Root || root.Nodes[root.Root] is not { Kind: SliceNodeKind.Parameter, Index: >= 0 and < Arguments and var k }) return result;
        if (!trace.Slices.Forward(s.Caller, new SliceSeed(SliceSeedKind.Result, s.Rva, "x0"), ct).Nodes.Any(n => n.Kind == SliceNodeKind.Return)) return result;
        foreach (var c in _index.Callers(s.Caller).Where(c => c.Kind == XrefKind.Call && c.Caller != null).DistinctBy(c => c.From).Take(256))
        {
            var code = trace.Code(c.Caller!, ct);
            var (b, i) = code.Position(c.From);
            if (b < 0) continue;
            var v = new Arm64Resolver(trace, code) { Budget = 1500 }.Before(A64Loc.Reg(k), b, i);
            if (v.Kind == A64Kind.Addr && ReadText(v.Rva, wide: false) is { Length: > 0 } name) result.Add((c.From, c.Caller!, name));
        }
        return result;
    }

    private static string Unquote(string text)
    {
        int start = text.StartsWith("L\"", StringComparison.Ordinal) ? 2 : text.StartsWith('"') ? 1 : 0;
        int end = text.EndsWith('"') ? text.Length - 1 : text.Length;
        return end > start ? text[start..end] : "";
    }

    /// <summary>The module a handle argument comes from: the string passed to the LoadLibrary* / GetModuleHandle* / dlopen call that returned it.</summary>
    private (string Module, string How)? ModuleOf(CallSiteInfo s, CancellationToken ct)
    {
        var trace = Arm64Trace.For(_index);
        var code = trace.Code(s.Caller, ct);
        var (b, i) = code.Position(s.Rva);
        if (b < 0) return null;
        var v = new Arm64Resolver(trace, code) { Budget = 1500 }.Before(A64Loc.Reg(0), b, i);
        if (v.Kind != A64Kind.Result || CallAt(v.Rva, ct) is not { Import.Name: { } api } loader || !ModuleApis.Contains(CallAnalysis.ApiName(_index.Image.Format, api)) || loader.Arguments.Count == 0) return null;
        var a = loader.Arguments[0];
        if (a.Kind == ArgKind.String) return (Unquote(a.Text), $"{api}({a.Text}) at {Va(loader.Rva)}");
        if (a.Kind == ArgKind.Immediate && a.Value == 0) return (Path.GetFileName(_index.Image.Path), $"{api}(NULL) at {Va(loader.Rva)}: this image");
        return null;
    }

    /// <summary>The writable global x0 is stored to right after the call (copies through registers followed in the block).</summary>
    private uint? StoredResult(CallSiteInfo s, CancellationToken ct)
    {
        var code = Arm64Trace.For(_index).Code(s.Caller, ct);
        var (b, i) = code.Position(s.Rva);
        if (b < 0) return null;
        var holding = new HashSet<int> { 0 };
        var steps = code.Blocks[b];
        for (int k = i + 1; k < steps.Length && holding.Count > 0; k++)
        {
            var x = steps[k];
            if (x.Facts.Flow is FlowKind.Call or FlowKind.IndirectCall) return null;
            if (Arm64Resolver.IsStore(x.I) && holding.Contains(A64Function.Gpr(x.I, 0)) && x.Facts.HasMem
                && _index.Image.SectionAt(x.Facts.MemTarget) is { } sec && (sec.Access & SectionAccess.Write) != 0)
                return x.Facts.MemTarget;
            if (A64Function.Dest(x.I) is { Kind: Arm64RegisterKind.X } d)
            {
                if (x.I.Mnemonic == Arm64Mnemonic.MOV && holding.Contains(A64Function.Gpr(x.I, 1))) holding.Add(d.Index);
                else holding.Remove(d.Index);
            }
        }
        return null;
    }

    private static bool IsVector(Arm64RegisterAny r) => A64Function.IsVector(r);

    /// <summary>
    /// Without a signature: the v registers set before the call, up to the highest one, with the width last written: in
    /// the call's block, then while no call intervenes in the blocks that alone lead to it.
    /// </summary>
    private List<(int Register, string Width)> GuessedFloats(NativeFunction caller, List<Step> steps, int k, CancellationToken ct)
    {
        var widths = new string?[Arguments];
        int highest = -1;
        bool Note(in Arm64Instruction i, bool call)
        {
            if (call) return false;
            if (Arm64Extensions.IsBranch(i.Id) || A64Function.Dest(i) is not { } d || !IsVector(d) || d.Index >= Arguments) return true;
            widths[d.Index] ??= d.VKind == Arm64RegisterVKind.S ? "s" : "d";
            highest = Math.Max(highest, d.Index);
            return true;
        }
        bool open = true;
        for (int j = k - 1; j >= 0 && open; j--) open = Note(steps[j].Instruction, steps[j].Facts.Flow is FlowKind.Call or FlowKind.IndirectCall);
        if (open)
        {
            var code = Arm64Trace.For(_index).Code(caller, ct);
            int b = code.Position(steps[k].Rva).Block;
            for (int hops = 0; open && hops < 4 && b >= 0 && code.Predecessors(b).ToList() is [var p]; hops++, b = p)
                for (int j = code.Blocks[p].Length - 1; j >= 0 && open; j--) open = Note(code.Blocks[p][j].I, A64Function.IsCall(code.Blocks[p][j].I));
        }
        return Enumerable.Range(0, highest + 1).Select(r => (r, widths[r] ?? "d")).ToList();
    }

    /// <summary>A floating-point argument in v<paramref name="reg"/> (its s or d view): from the call's block, else through the predecessors.</summary>
    private CallArgument Float(NativeFunction caller, List<Step> steps, int k, int index, int reg, string width, ApiParam? p, CancellationToken ct)
    {
        var type = p?.TypeName ?? (width == "s" ? "float" : "double");
        if (FloatBits(steps, k, reg, width == "s", 0) is not ({ } bits, var derivation))
        {
            var why = FloatWhy(steps, k, reg);
            if (why != "set before the block" || FloatAcross(caller, steps[k].Rva, reg, ct) is not { } across)
                return new CallArgument(index, p?.Name, type, width + reg, ArgKind.Unknown, null, null, "?", why);
            if (across.Kind != A64Kind.Const)
                return new CallArgument(index, p?.Name, type, width + reg, ArgKind.Unknown, null, null, "?", across.Why.Length > 0 ? across.Why : across.Kind.ToString().ToLowerInvariant());
            (bits, derivation) = (width == "s" ? across.Num & 0xFFFFFFFF : across.Num, across.Why);
        }
        var text = CallAnalysis.FormatNumber(bits, p ?? new ApiParam("", width == "s" ? ApiParamType.Float : ApiParamType.Double));
        return new CallArgument(index, p?.Name, type, width + reg, ArgKind.Immediate, bits, null, text, derivation);
    }

    /// <summary>The value v<paramref name="reg"/> holds before the call at <paramref name="site"/>, through the function's blocks.</summary>
    private A64Val? FloatAcross(NativeFunction caller, uint site, int reg, CancellationToken ct)
    {
        var trace = Arm64Trace.For(_index);
        var code = trace.Code(caller, ct);
        var (b, i) = code.Position(site);
        return b < 0 ? null : new Arm64Resolver(trace, code) { Budget = 1500 }.Before(A64Loc.Reg(A64Function.VBase + reg), b, i);
    }

    private string FloatWhy(List<Step> steps, int k, int reg)
    {
        for (int j = k - 1; j >= 0; j--)
        {
            if (steps[j].Facts.Flow is FlowKind.Call or FlowKind.IndirectCall) return $"clobbered by the call {steps[j].Instruction} @{Va(steps[j].Rva)}";
            if (A64Function.Dest(steps[j].Instruction) is { } d && IsVector(d) && d.Index == reg) return $"set by {steps[j].Instruction} @{Va(steps[j].Rva)}";
        }
        return "set before the block";
    }

    /// <summary>The bits v<paramref name="reg"/> holds before step <paramref name="k"/>: fmov of an immediate or a general register, a literal load, a conversion of a constant, movi #0, a copy.</summary>
    private (ulong? Bits, string Derivation) FloatBits(List<Step> steps, int k, int reg, bool single, int depth)
    {
        for (int j = k - 1; j >= 0 && depth < 8; j--)
        {
            var s = steps[j];
            var i = s.Instruction;
            if (s.Facts.Flow is FlowKind.Call or FlowKind.IndirectCall) return (null, "");
            if (Arm64Extensions.IsBranch(i.Id) || A64Function.Dest(i) is not { } d || !IsVector(d) || d.Index != reg) continue;
            string at = $"{i} @{Va(s.Rva)}";
            bool dSingle = d.VKind == Arm64RegisterVKind.S;
            ulong Bits(double value) => dSingle ? BitConverter.SingleToUInt32Bits((float)value) : BitConverter.DoubleToUInt64Bits(value);
            if (i.OperandCount < 2) return (null, "");
            var src = i.GetOperand(1);
            switch (i.Mnemonic)
            {
                case Arm64Mnemonic.FMOV when src.Kind == Arm64OperandKind.Immediate && ((Arm64ImmediateOperand)src).IsFloat:
                    return (Bits(((Arm64ImmediateOperand)src).ValueAsFloat), at);
                case Arm64Mnemonic.FMOV or Arm64Mnemonic.MOV or Arm64Mnemonic.ORR when src.Kind == Arm64OperandKind.Register:
                {
                    var r = ((Arm64RegisterOperand)src).Value;
                    if (IsVector(r))
                    {
                        var (bits, why) = FloatBits(steps, j, r.Index, single, depth + 1);
                        return (bits, bits == null ? "" : $"{at}; {why}");
                    }
                    if (((Arm64RegisterOperand)src).IsZeroRegister) return (0, at);
                    var (kind, value, _, _, derivation) = Resolve(steps, j, r.Index, null, depth + 1);
                    return kind == ArgKind.Immediate && value is { } v ? (dSingle ? v & 0xFFFFFFFF : v, $"{at}; {derivation}") : (null, "");
                }
                case Arm64Mnemonic.MOVI when A64Function.Imm(in i, 1) == 0:
                    return (0, at);
                case Arm64Mnemonic.SCVTF or Arm64Mnemonic.UCVTF when src.Kind == Arm64OperandKind.Register && !IsVector(((Arm64RegisterOperand)src).Value):
                {
                    var r = ((Arm64RegisterOperand)src).Value;
                    var (kind, value, _, _, derivation) = Resolve(steps, j, r.Index, null, depth + 1);
                    if (kind != ArgKind.Immediate || value is not { } n) return (null, "");
                    double converted = i.Mnemonic == Arm64Mnemonic.UCVTF ? r.Kind == Arm64RegisterKind.W ? (uint)n : (double)n
                        : r.Kind == Arm64RegisterKind.W ? (int)(uint)n : (long)n;
                    return (Bits(converted), $"{at}; {derivation}");
                }
                case Arm64Mnemonic.LDR or Arm64Mnemonic.LDUR when s.Facts.HasMem && _index.Image.SectionAt(s.Facts.MemTarget) is { } sec && (sec.Access & SectionAccess.Write) == 0:
                {
                    Span<byte> buffer = stackalloc byte[8];
                    int size = dSingle ? 4 : 8;
                    buffer.Clear();
                    if (_index.Image.Read(s.Facts.MemTarget, buffer[..size]) != size) return (null, "");
                    return (BinaryPrimitives.ReadUInt64LittleEndian(buffer), $"{at} (constant at {Va(s.Facts.MemTarget)})");
                }
                default:
                    return (null, "");
            }
        }
        return (null, "");
    }
}
