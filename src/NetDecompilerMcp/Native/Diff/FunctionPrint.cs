using System.Runtime.CompilerServices;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Native.Diff;

/// <summary>
/// Build-independent facts about one function: control-flow shape, instruction mix, masked bytes, what it calls and
/// references (imports by name, strings by text, constants) and its place in the call graph.
/// </summary>
public sealed class FunctionPrint
{
    public required NativeFunction Function { get; init; }
    public int Index { get; init; }
    public uint Start => Function.Start;
    public uint Size { get; init; }
    public int Instructions { get; init; }
    public int Blocks { get; init; }
    public int Edges { get; init; }
    public int BackEdges { get; init; }
    /// <summary>Bytes with addresses masked, in address order.</summary>
    public ulong BytesHash { get; init; }
    /// <summary>Canonical (depth-first from the entry) graph with each block's instruction shapes.</summary>
    public ulong StructHash { get; init; }
    /// <summary>Canonical graph shape only.</summary>
    public ulong GraphHash { get; init; }
    /// <summary>Imports, strings and constants together; 0 when the function references none.</summary>
    public ulong SignatureHash { get; init; }
    public int SignatureItems { get; init; }
    /// <summary>Mnemonic histogram: keys sorted, with counts.</summary>
    public int[] MnemonicKeys { get; init; } = [];
    public int[] MnemonicCounts { get; init; } = [];
    public string[] Imports { get; init; } = [];
    public string[] Strings { get; init; } = [];
    public ulong[] Constants { get; init; } = [];
    /// <summary>Called functions (indexes into the image's prints) in call-site order, each once.</summary>
    public int[] Callees { get; set; } = [];
    /// <summary>Calling functions (indexes), each once, by address.</summary>
    public int[] Callers { get; set; } = [];
    public int CallSites { get; init; }
    /// <summary>The import a thunk jumps to ("module!name"), or null.</summary>
    public string? ThunkImport { get; init; }
    /// <summary>The code could not be decoded (or graphed); only size facts are set.</summary>
    public bool Failed { get; init; }
}

/// <summary>The prints of every function of one code index; built once per index and cached.</summary>
public sealed class ImagePrints
{
    private static readonly ConditionalWeakTable<NativeCodeIndex, Lazy<ImagePrints>> Cache = new();

    public required NativeCodeIndex Index { get; init; }
    public required FunctionPrint[] Functions { get; init; }
    public required Dictionary<uint, int> ByStart { get; init; }
    public TimeSpan Elapsed { get; init; }
    public int Failed { get; init; }

    public FunctionPrint? At(uint start) => ByStart.TryGetValue(start, out var i) ? Functions[i] : null;

    /// <summary>The prints of <paramref name="index"/>, computed on first use (in parallel, cancellable).</summary>
    public static ImagePrints Of(NativeCodeIndex index, CancellationToken ct)
    {
        var lazy = Cache.GetValue(index, i => new Lazy<ImagePrints>(() => Build(i, CancellationToken.None), LazyThreadSafetyMode.ExecutionAndPublication));
        if (lazy.IsValueCreated) return lazy.Value;
        // Build outside the lazy when the caller can cancel, so a cancelled build is not cached.
        var built = Build(index, ct);
        Cache.AddOrUpdate(index, new Lazy<ImagePrints>(built));
        return built;
    }

    public static ImagePrints Build(NativeCodeIndex index, CancellationToken ct)
    {
        if (index.Support != CodeSupport.Full)
            throw new NotSupportedException(index.SupportNote ?? "Instructions are not decoded for this architecture.");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var functions = index.Functions;
        var byStart = new Dictionary<uint, int>(functions.Count);
        for (int i = 0; i < functions.Count; i++) byStart[functions[i].Start] = i;
        var slots = new Dictionary<uint, string>();
        foreach (var imp in index.Image.Imports) slots.TryAdd(imp.SlotRva, NativeCodeIndex.ImportName(imp));

        var prints = new FunctionPrint[functions.Count];
        int failed = 0;
        Parallel.For(0, functions.Count, new ParallelOptions { CancellationToken = ct, MaxDegreeOfParallelism = Math.Max(1, Environment.ProcessorCount) },
            () => new MaskedDecoder(index.Image, index),
            (i, _, decoder) =>
            {
                prints[i] = Print(index, decoder, functions[i], i, slots, ct);
                if (prints[i].Failed) Interlocked.Increment(ref failed);
                return decoder;
            }, _ => { });

        // call graph edges as print indexes
        Parallel.For(0, functions.Count, new ParallelOptions { CancellationToken = ct }, i =>
        {
            var f = functions[i];
            var callees = new List<int>();
            var seen = new HashSet<int>();
            foreach (var site in index.Callees(f, CallEdgeFilter.Direct))
                if (site.Function != null && byStart.TryGetValue(site.Function.Start, out var c) && seen.Add(c)) callees.Add(c);
            prints[i].Callees = callees.ToArray();
            var callers = new SortedSet<int>();
            foreach (var site in index.Callers(f, CallEdgeFilter.Direct))
                if (site.Caller != null && byStart.TryGetValue(site.Caller.Start, out var c)) callers.Add(c);
            prints[i].Callers = callers.ToArray();
        });
        return new ImagePrints { Index = index, Functions = prints, ByStart = byStart, Elapsed = sw.Elapsed, Failed = failed };
    }

    private static FunctionPrint Print(NativeCodeIndex index, MaskedDecoder decoder, NativeFunction f, int i, Dictionary<uint, string> slots, CancellationToken ct)
    {
        string? thunk = f.ThunkImport is { } ti ? NativeCodeIndex.ImportName(ti) : null;
        List<MaskedInsn> code;
        FunctionGraph graph;
        try { code = FunctionCode.Instructions(index, decoder, f, ct, out graph); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new FunctionPrint { Function = f, Index = i, Size = f.Size, Instructions = f.InstructionCount, Blocks = f.BlockCount, ThunkImport = thunk, Failed = true };
        }

        // masked bytes and mnemonic histogram
        var bytes = new Hash64();
        var histogram = new SortedDictionary<int, int>();
        var constants = new SortedSet<ulong>();
        foreach (var insn in code)
        {
            for (int b = 0; b < insn.Length; b++) bytes.AddByte(insn.IsWild(b) ? 0x100 : insn.Bytes[b]);
            histogram[insn.Mnemonic] = histogram.GetValueOrDefault(insn.Mnemonic) + 1;
            if (insn.Constant is { } k) constants.Add(k);
        }

        // canonical depth-first order of blocks from the entry
        var blocks = graph.Blocks;
        var blockIndex = new Dictionary<uint, int>(blocks.Count);
        for (int b = 0; b < blocks.Count; b++) blockIndex[blocks[b].Start] = b;
        var order = new int[blocks.Count];
        Array.Fill(order, -1);
        var sequence = new List<int>(blocks.Count);
        int backEdges = 0, edges = 0;
        var state = new byte[blocks.Count]; // 0 new, 1 on stack, 2 done
        var successors = new List<CfgEdge>[blocks.Count];
        for (int b = 0; b < blocks.Count; b++) successors[b] = Sorted(blocks[b].Successors);
        void Dfs(int root)
        {
            var stack = new Stack<(int Block, int Next)>();
            order[root] = sequence.Count; sequence.Add(root); state[root] = 1;
            stack.Push((root, 0));
            while (stack.Count > 0)
            {
                var (blk, next) = stack.Pop();
                var succ = successors[blk];
                if (next < succ.Count)
                {
                    stack.Push((blk, next + 1));
                    if (!blockIndex.TryGetValue(succ[next].To, out var to)) continue;
                    if (state[to] == 1) { backEdges++; continue; }
                    if (state[to] == 2) continue;
                    order[to] = sequence.Count; sequence.Add(to); state[to] = 1;
                    stack.Push((to, 0));
                }
                else state[blk] = 2;
            }
        }
        if (blockIndex.TryGetValue(f.Start, out var entry)) Dfs(entry);
        for (int b = 0; b < blocks.Count; b++) if (order[b] < 0) Dfs(b);

        // per-block instruction shapes
        var blockTokens = new ulong[blocks.Count];
        int at = 0;
        for (int b = 0; b < blocks.Count; b++)
        {
            var h = new Hash64();
            while (at < code.Count && code[at].Rva < blocks[b].Start) at++;
            for (int k = at; k < code.Count && code[k].Rva < blocks[b].End; k++) h.Add(code[k].Token);
            blockTokens[b] = h.Value;
        }
        var structure = new Hash64();
        var shape = new Hash64();
        foreach (var b in sequence)
        {
            structure.Add(blockTokens[b]);
            var succ = successors[b];
            structure.Add(succ.Count); shape.Add(succ.Count);
            foreach (var e in succ)
            {
                edges++;
                int to = blockIndex.TryGetValue(e.To, out var t) ? order[t] : -1;
                structure.Add((int)e.Kind); structure.Add(to);
                shape.Add((int)e.Kind); shape.Add(to);
            }
        }

        // imports, strings
        var imports = new SortedSet<string>(StringComparer.Ordinal);
        var strings = new SortedSet<string>(StringComparer.Ordinal);
        int calls = 0;
        foreach (var x in index.RefsFrom(f))
        {
            if (x.IsCallLike) calls++;
            if (slots.TryGetValue(x.To, out var imp)) imports.Add(imp);
            else if (x.Kind is XrefKind.Call or XrefKind.TailCall && index.FunctionByStart(x.To) is { ThunkImport: { } t2 }) imports.Add(NativeCodeIndex.ImportName(t2));
            else if (index.StringAt(x.To) is { } s && strings.Count < 64) strings.Add(index.ReadString(s, 200));
        }
        var signature = new Hash64();
        foreach (var s in imports) signature.Add(s);
        signature.Add(-1);
        foreach (var s in strings) signature.Add(s);
        signature.Add(-2);
        foreach (var k in constants) signature.Add((long)k);
        int items = imports.Count + strings.Count + constants.Count;

        return new FunctionPrint
        {
            Function = f,
            Index = i,
            Size = f.Size,
            Instructions = code.Count,
            Blocks = blocks.Count,
            Edges = edges,
            BackEdges = backEdges,
            BytesHash = bytes.Value,
            StructHash = structure.Value,
            GraphHash = shape.Value,
            SignatureHash = items == 0 ? 0 : signature.Value,
            SignatureItems = items,
            MnemonicKeys = histogram.Keys.ToArray(),
            MnemonicCounts = histogram.Values.ToArray(),
            Imports = imports.ToArray(),
            Strings = strings.ToArray(),
            Constants = constants.ToArray(),
            CallSites = calls,
            ThunkImport = thunk,
        };
    }

    private static List<CfgEdge> Sorted(List<CfgEdge> edges)
    {
        if (edges.Count <= 1) return edges;
        var copy = new List<CfgEdge>(edges);
        copy.Sort((a, b) => a.Kind != b.Kind ? a.Kind.CompareTo(b.Kind) : a.To.CompareTo(b.To));
        return copy;
    }
}

/// <summary>Deterministic 64-bit FNV-1a style hash (stable across processes, unlike HashCode).</summary>
public struct Hash64
{
    private ulong _h;
    private bool _started;

    public readonly ulong Value => _started ? _h : 14695981039346656037UL;

    public void Add(long v)
    {
        if (!_started) { _h = 14695981039346656037UL; _started = true; }
        ulong x = (ulong)v;
        for (int i = 0; i < 8; i++) { _h ^= x & 0xFF; _h *= 1099511628211UL; x >>= 8; }
    }

    public void Add(ulong v) => Add((long)v);

    public void AddByte(int v)
    {
        if (!_started) { _h = 14695981039346656037UL; _started = true; }
        _h ^= (uint)v; _h *= 1099511628211UL;
    }
    public void Add(int v) => Add((long)v);

    public void Add(string s)
    {
        Add(s.Length);
        foreach (var c in s) { _h ^= c; _h *= 1099511628211UL; }
    }
}
