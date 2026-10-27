namespace Corvus.Core.Hermes;

/// <summary>How code refers to a function: a closure created from it, or a direct call.</summary>
public enum HermesRefKind : byte { Closure, Call }

/// <summary>A reference from code: the function and the bytecode offset in it of the instruction.</summary>
public readonly record struct HermesRef(int Function, int Offset, HermesRefKind Kind = HermesRefKind.Closure);

public enum HermesClosureKind : byte { Function, Generator, Async, GeneratorBody }

/// <summary>A Metro module defined in the global code: __d(factory, id, dependencies[, name]).</summary>
public sealed record HermesModule(long Id, int Function, IReadOnlyList<long> Dependencies, string? Name, int Offset);

/// <summary>Closure creators, string and function users, and the Metro module table of a bundle, in one pass.</summary>
public sealed class HermesIndex
{
    private readonly int[] _parent, _parentOffset, _envSource;
    private readonly HermesClosureKind[] _kind;
    private readonly int[] _fnStart, _strStart;
    private readonly HermesRef[] _fnRefs, _strRefs;
    private int[]? _envOwner;

    public HermesFile File { get; }
    public long Instructions { get; }
    public IReadOnlyList<HermesModule> Modules { get; }

    /// <summary>Module ids the global code runs (__r(id)).</summary>
    public IReadOnlyList<long> EntryModules { get; }
    public IReadOnlyList<string> Issues { get; }

    /// <summary>The module whose factory each function is, or that encloses it; -1 outside every module.</summary>
    private readonly Lazy<int[]> _moduleOf;

    public HermesIndex(HermesFile file, CancellationToken ct = default)
    {
        File = file;
        int n = file.Functions.Count;
        _parent = new int[n];
        _parentOffset = new int[n];
        _envSource = new int[n];
        _kind = new HermesClosureKind[n];
        Array.Fill(_parent, -1);
        Array.Fill(_envSource, int.MinValue);
        var fnRefs = new List<(int Target, HermesRef Ref)>();
        var strRefs = new List<(int Target, HermesRef Ref)>();
        var issues = new List<string>();
        long count = 0;
        var env = new Dictionary<long, int>();
        foreach (var f in file.Functions)
        {
            if ((f.Index & 255) == 0) ct.ThrowIfCancellationRequested();
            var code = HermesCode.Decode(file, f, issues.Count < 20 ? issues : null);
            count += code.Count;
            env.Clear();
            foreach (var ins in code)
            {
                var ops = ins.Op.Operands;
                switch (ins.Name)
                {
                    case "CreateEnvironment" or "CreateInnerEnvironment": env[ins.A] = -1; break;
                    case "GetEnvironment": env[ins.A] = (int)ins.B; break;
                }
                for (int i = 0; i < ops.Length; i++)
                {
                    if (ops[i].Id == HermesIdKind.String && ins[i] < file.StringCount) strRefs.Add(((int)ins[i], new HermesRef(f.Index, ins.Offset)));
                    else if (ops[i].Id == HermesIdKind.Function && ins[i] < n)
                    {
                        int target = (int)ins[i];
                        bool call = ins.Name.StartsWith("CallDirect", StringComparison.Ordinal);
                        fnRefs.Add((target, new HermesRef(f.Index, ins.Offset, call ? HermesRefKind.Call : HermesRefKind.Closure)));
                        if (!call && _parent[target] < 0 && target != f.Index)
                        {
                            _parent[target] = f.Index;
                            _parentOffset[target] = ins.Offset;
                            _envSource[target] = env.TryGetValue(ins.B, out var source) ? source : int.MinValue;
                            _kind[target] = ins.Name.StartsWith("CreateAsync", StringComparison.Ordinal) ? HermesClosureKind.Async
                                : ins.Name.StartsWith("CreateGeneratorClosure", StringComparison.Ordinal) ? HermesClosureKind.Generator
                                : ins.Name.StartsWith("CreateGenerator", StringComparison.Ordinal) ? HermesClosureKind.GeneratorBody : HermesClosureKind.Function;
                        }
                    }
                }
            }
        }
        Instructions = count;
        (_fnStart, _fnRefs) = Csr(fnRefs, n);
        (_strStart, _strRefs) = Csr(strRefs, file.StringCount);
        var (modules, entries) = (uint)file.GlobalCodeIndex < (uint)n ? MetroModules(file, file.Functions[file.GlobalCodeIndex]) : ([], []);
        Modules = modules;
        EntryModules = entries;
        Issues = issues;
        _moduleOf = new(() =>
        {
            var of = new int[n];
            Array.Fill(of, -2);
            for (int m = 0; m < Modules.Count; m++)
                if (Modules[m].Function < n) of[Modules[m].Function] = m;
            for (int i = 0; i < n; i++) Resolve(of, i);
            return of;
        });
    }

    private int Resolve(int[] of, int i)
    {
        var chain = new List<int>();
        int at = i;
        while (at >= 0 && of[at] == -2 && chain.Count < 10_000) { chain.Add(at); of[at] = -3; at = _parent[at]; }
        int result = at >= 0 && of[at] >= -1 ? of[at] : -1;
        foreach (var c in chain) of[c] = result;
        return result;
    }

    private static (int[] Start, HermesRef[] Refs) Csr(List<(int Target, HermesRef Ref)> list, int n)
    {
        var start = new int[n + 1];
        foreach (var (t, _) in list) start[t + 1]++;
        for (int i = 0; i < n; i++) start[i + 1] += start[i];
        var refs = new HermesRef[list.Count];
        var fill = (int[])start.Clone();
        foreach (var (t, r) in list) refs[fill[t]++] = r;
        return (start, refs);
    }

    /// <summary>The function whose code creates a closure of <paramref name="function"/> first, or -1 (the global code, an unused function).</summary>
    public int Parent(int function) => function >= 0 && function < _parent.Length ? _parent[function] : -1;
    /// <summary>How the function's closure is made: a plain function, a generator, an async function, or the body of one of those.</summary>
    public HermesClosureKind Kind(int function) => function >= 0 && function < _kind.Length ? _kind[function] : HermesClosureKind.Function;

    public int ParentOffset(int function) => function >= 0 && function < _parentOffset.Length ? _parentOffset[function] : 0;

    public ReadOnlySpan<HermesRef> FunctionRefs(int function) =>
        function >= 0 && function + 1 < _fnStart.Length ? _fnRefs.AsSpan(_fnStart[function], _fnStart[function + 1] - _fnStart[function]) : [];

    public ReadOnlySpan<HermesRef> StringRefs(long id) =>
        id >= 0 && id + 1 < _strStart.Length ? _strRefs.AsSpan(_strStart[id], _strStart[id + 1] - _strStart[id]) : [];

    /// <summary>The functions created in <paramref name="function"/>, in bytecode order.</summary>
    public IEnumerable<int> Children(int function)
    {
        for (int i = 0; i < _parent.Length; i++)
            if (_parent[i] == function) yield return i;
    }

    /// <summary>The Metro module <paramref name="function"/> belongs to (its factory or a closure inside it), or null.</summary>
    public HermesModule? ModuleOf(int function)
    {
        if (function < 0 || function >= _parent.Length) return null;
        int m = _moduleOf.Value[function];
        return m >= 0 ? Modules[m] : null;
    }

    /// <summary>The function owning the environment <paramref name="depth"/> levels up (-1 own, 0 captured); -1 when unknown.</summary>
    public int EnvironmentOwner(int function, int depth)
    {
        _envOwner ??= BuildEnvOwners();
        int at = function;
        for (int d = -1; d < depth && at >= 0; d++) at = at < _envOwner.Length ? _envOwner[at] : -1;
        return at;
    }

    private int[] BuildEnvOwners()
    {
        int n = _parent.Length;
        var owner = new int[n];
        Array.Fill(owner, -2);
        int Get(int f, int guard)
        {
            if (f < 0 || f >= n) return -1;
            if (owner[f] != -2) return owner[f];
            if (guard > 256) return -1;
            // A cycle reads as unknown.
            owner[f] = -1;
            int source = _envSource[f], creator = _parent[f];
            int result = creator < 0 || source == int.MinValue ? -1 : source == -1 ? creator : Up(creator, source, guard + 1);
            return owner[f] = result;
        }
        int Up(int f, int depth, int guard)
        {
            int at = Get(f, guard);
            for (int d = 0; d < depth && at >= 0; d++) at = Get(at, guard);
            return at;
        }
        for (int i = 0; i < n; i++) Get(i, 0);
        return owner;
    }

    /// <summary>The Metro module table: __d(factory, id, deps[, name]) calls and __r(id) entries of the global code, by register tracking.</summary>
    private static (List<HermesModule>, List<long>) MetroModules(HermesFile file, HermesFunction global)
    {
        var modules = new List<HermesModule>();
        var entries = new List<long>();
        var regs = new Dictionary<long, object?>();
        foreach (var ins in HermesCode.Decode(file, global))
        {
            switch (ins.Name)
            {
                case "GetGlobalObject": regs[ins.A] = Global.Value; continue;
                case "TryGetById" or "TryGetByIdLong" or "GetById" or "GetByIdLong" or "GetByIdShort":
                    regs[ins.A] = regs.GetValueOrDefault(ins.B) is Global ? new Property(file.String(ins.D) ?? "") : null; continue;
                case "CreateClosure" or "CreateClosureLongIndex": regs[ins.A] = new Closure((int)ins.C); continue;
                case "LoadConstZero": regs[ins.A] = 0.0; continue;
                case "LoadConstUInt8" or "LoadConstInt": regs[ins.A] = (double)(ins.Name == "LoadConstInt" ? (int)ins.B : ins.B); continue;
                case "LoadConstDouble": regs[ins.A] = ins.Double; continue;
                case "LoadConstString" or "LoadConstStringLongIndex": regs[ins.A] = file.String(ins.B); continue;
                case "NewArray": regs[ins.A] = new List<long>(); continue;
                case "NewArrayWithBuffer" or "NewArrayWithBufferLong":
                    regs[ins.A] = HermesLiterals.Read(file, file.ArrayBuffer, ins.D, ins.C).Where(l => l.Kind == HermesLiteralKind.Number).Select(l => (long)l.Number).ToList();
                    continue;
                case "PutOwnByIndex" or "PutOwnByIndexL":
                    if (regs.GetValueOrDefault(ins.A) is List<long> list && regs.GetValueOrDefault(ins.B) is double d) list.Add((long)d);
                    continue;
                case "Mov" or "MovLong": regs[ins.A] = regs.GetValueOrDefault(ins.B); continue;
            }
            if (ins.Name.StartsWith("Call", StringComparison.Ordinal) && !ins.Name.StartsWith("CallBuiltin", StringComparison.Ordinal)
                && !ins.Name.StartsWith("CallDirect", StringComparison.Ordinal))
            {
                var args = Arguments(ins, global.FrameSize);
                if (regs.GetValueOrDefault(ins.B) is Property p && args.Count >= 1)
                {
                    object? Arg(int i) => i < args.Count ? regs.GetValueOrDefault(args[i]) : null;
                    if (p.Name.EndsWith("__d", StringComparison.Ordinal) && Arg(0) is Closure c && Arg(1) is double id)
                        modules.Add(new HermesModule((long)id, c.Function, Arg(2) as List<long> ?? [], Arg(3) as string, ins.Offset));
                    else if (p.Name.EndsWith("__r", StringComparison.Ordinal) && Arg(0) is double entry)
                        entries.Add((long)entry);
                }
            }
            if (HermesCode.WritesFirst(ins.Op)) regs.Remove(ins.A);
        }
        return (modules, entries);
    }

    /// <summary>The argument registers of a call, after 'this': Call1–4 name them; Call, CallLong and Construct take the frame's last registers.</summary>
    internal static List<long> Arguments(in HermesInstruction ins, int frameSize) => ins.Name switch
    {
        "Call1" => [],
        "Call2" => [ins.D],
        "Call3" => [ins.D, ins.E],
        "Call4" => [ins.D, ins.E, ins.F],
        _ => [.. Enumerable.Range(1, (int)Math.Max(0, Math.Min(ins.C, 256) - 1)).Select(i => (long)(frameSize - 7 - i))],
    };

    private sealed class Global { public static readonly Global Value = new(); }
    private sealed record Property(string Name);
    private sealed record Closure(int Function);
}
