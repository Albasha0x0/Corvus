using System.Runtime.CompilerServices;
using Corvus.Native.Code;

namespace Corvus.Native.Diff;

/// <summary>Build-independent facts about one function: graph shape, instruction mix, masked bytes, references and call graph place.</summary>
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
    /// <summary>Constants set up shortly before a direct call; paired by index with FedTargets.</summary>
    public ulong[] FedConstants { get; init; } = [];
    public uint[] FedTargets { get; init; } = [];
    /// <summary>The image these prints belong to; set when the image is built.</summary>
    internal ImagePrints? Image { get; set; }
    private sealed record Scored(int Version, ulong[] Constants);
    private Scored? _scored;

    /// <summary>Constants that count toward similarity; excludes those set up for an ignored callee.</summary>
    internal ulong[] ScoredConstants
    {
        get
        {
            if (FedConstants.Length == 0 || Image is not { } image) return Constants;
            int version = image.IgnoreVersion;
            if (_scored is { } known && known.Version == version) return known.Constants;
            var left = image.LeftOutConstants(this);
            var kept = left.Count == 0 ? Constants : Constants.Where(k => !left.Contains(k)).ToArray();
            _scored = new Scored(version, kept);
            return kept;
        }
    }
    /// <summary>Called functions (indexes into the image's prints) in call-site order, each once.</summary>
    public int[] Callees { get; set; } = [];
    /// <summary>Calling functions (indexes), each once, by address.</summary>
    public int[] Callers { get; set; } = [];
    public int CallSites { get; init; }
    /// <summary>The import a thunk jumps to ("module!name"), or null.</summary>
    public string? ThunkImport { get; init; }
    /// <summary>The code could not be decoded (or graphed); only size facts are set.</summary>
    public bool Failed { get; init; }
    /// <summary>MinHash of the instruction-shape n-grams (<see cref="CodeSketch"/>); null when there is no code.</summary>
    public ushort[]? Sketch { get; init; }
    /// <summary>Distinct instruction-shape n-grams.</summary>
    public int Shingles { get; init; }
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

    private int[]? _calleeFanIn;

    /// <summary>Per function index, how many functions of this image call it.</summary>
    internal int[] CalleeFanIn
    {
        get
        {
            if (_calleeFanIn is { } cached) return cached;
            // One thread computes; concurrent first queries wait instead of repeating the pass.
            lock (_tables) return _calleeFanIn ??= ComputeFanIn();
        }
    }

    private readonly object _tables = new();

    private int[] ComputeFanIn()
    {
        var counts = new int[Functions.Length];
        // Build stores each callee of a function once.
        foreach (var f in Functions)
            foreach (var c in f.Callees)
                if ((uint)c < (uint)counts.Length) counts[c]++;
        return counts;
    }

    /// <summary>Instructions after a constant within which a call counts as using it.</summary>
    internal const int FeedWindow = 4;

    private int _ignoreVersion;

    /// <summary>Changes whenever the ignored callees are recomputed.</summary>
    internal int IgnoreVersion => _ignoreVersion;

    /// <summary>Constants of <paramref name="p"/> left out of its score; empty when none.</summary>
    internal IReadOnlySet<ulong> LeftOutConstants(FunctionPrint p)
    {
        var ignored = IgnoredCallees;
        HashSet<ulong>? left = null;
        for (int i = 0; i < p.FedConstants.Length; i++)
            if (ByStart.TryGetValue(p.FedTargets[i], out var callee) && ignored[callee]) (left ??= []).Add(p.FedConstants[i]);
        return left ?? (IReadOnlySet<ulong>)EmptyConstants;
    }

    private static readonly HashSet<ulong> EmptyConstants = [];

    private IReadOnlyList<ulong>? _leftOut;

    /// <summary>Distinct constants left out of any function of the image, ascending.</summary>
    internal IReadOnlyList<ulong> LeftOutAll
    {
        get
        {
            if (_leftOut is { } cached) return cached;
            var all = new SortedSet<ulong>();
            foreach (var f in Functions)
                if (f.FedConstants.Length > 0) all.UnionWith(LeftOutConstants(f));
            return _leftOut = all.ToArray();
        }
    }

    /// <summary>Share of an image's functions that makes a callee common.</summary>
    internal const double CommonCalleeShare = 0.02;

    private bool[]? _ignored;
    private int _ignoredHelpers, _ignoredCommon;
    private IReadOnlySet<int> _helpers = new HashSet<int>();

    /// <summary>Whether <see cref="NameHelpers"/> has run for this image.</summary>
    internal bool HelpersNamed { get; private set; }

    /// <summary>Functions the runtime helper table or a Runtime_ name marks.</summary>
    internal IReadOnlySet<int> NamedHelpers
    {
        get => _helpers;
        set { _helpers = value; _ignored = null; _leftOut = null; _ignoreVersion++; }
    }

    /// <summary>Marks the functions at <paramref name="helperStarts"/> and those named Runtime_ as helpers; once per image.</summary>
    internal void NameHelpers(IEnumerable<uint> helperStarts)
    {
        var set = new HashSet<int>();
        foreach (var start in helperStarts)
            if (ByStart.TryGetValue(start, out var i)) set.Add(i);
        for (int i = 0; i < Functions.Length; i++)
            if (Index.NameAt(Functions[i].Start)?.StartsWith("Runtime_", StringComparison.Ordinal) == true) set.Add(i);
        NamedHelpers = set;
        HelpersNamed = true;
    }

    /// <summary>Callees that carry no similarity: named helpers and callees of over <see cref="CommonCalleeShare"/> of the functions.</summary>
    internal bool[] IgnoredCallees
    {
        get
        {
            if (_ignored is { } cached) return cached;
            lock (_tables)
            {
                if (_ignored is { } again) return again;
                var fanIn = CalleeFanIn;
                // Below 400 functions the floor is the fan-in discount threshold, not 2%.
                int floor = Math.Max(SimilarFunctions.CommonCalleeFanIn, (int)(Functions.Length * CommonCalleeShare));
                var ignored = new bool[Functions.Length];
                int helpers = 0, common = 0;
                for (int i = 0; i < ignored.Length; i++)
                {
                    bool helper = fanIn[i] > 0 && NamedHelpers.Contains(i);
                    ignored[i] = helper || fanIn[i] > floor;
                    if (helper) helpers++;
                    else if (ignored[i]) common++;
                }
                (_ignoredHelpers, _ignoredCommon) = (helpers, common);
                return _ignored = ignored;
            }
        }
    }

    /// <summary>How many callees <see cref="IgnoredCallees"/> marks.</summary>
    internal int IgnoredCalleeCount => IgnoredHelperCount + IgnoredCommonCount;

    /// <summary>Called named helpers that <see cref="IgnoredCallees"/> marks.</summary>
    internal int IgnoredHelperCount { get { _ = IgnoredCallees; return _ignoredHelpers; } }

    /// <summary>Other callees that <see cref="IgnoredCallees"/> marks for being common.</summary>
    internal int IgnoredCommonCount { get { _ = IgnoredCallees; return _ignoredCommon; } }

    private long _decodes;

    /// <summary>Functions of this image decoded again for exact similarity scores; the sketches need no decode.</summary>
    internal long Decodes => Interlocked.Read(ref _decodes);

    internal void CountDecode() => Interlocked.Increment(ref _decodes);

    /// <summary>The prints of <paramref name="index"/>, computed on first use (in parallel, cancellable).</summary>
    public static ImagePrints Of(NativeCodeIndex index, CancellationToken ct, IProgress<int>? progress = null)
    {
        var lazy = Cache.GetValue(index, i => new Lazy<ImagePrints>(() => Build(i, CancellationToken.None), LazyThreadSafetyMode.ExecutionAndPublication));
        if (lazy.IsValueCreated) return lazy.Value;
        // Build outside the lazy when the caller can cancel, so a cancelled build is not cached.
        var built = Build(index, ct, progress);
        Cache.AddOrUpdate(index, new Lazy<ImagePrints>(built));
        return built;
    }

    /// <param name="progress">Functions printed so far, reported every few thousand.</param>
    public static ImagePrints Build(NativeCodeIndex index, CancellationToken ct, IProgress<int>? progress = null)
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
        int failed = 0, done = 0;
        Parallel.For(0, functions.Count, new ParallelOptions { CancellationToken = ct, MaxDegreeOfParallelism = Math.Max(1, Environment.ProcessorCount) },
            () => new MaskedDecoder(index.Image, index),
            (i, _, decoder) =>
            {
                prints[i] = Print(index, decoder, functions[i], i, slots, ct);
                if (prints[i].Failed) Interlocked.Increment(ref failed);
                if (Interlocked.Increment(ref done) is var n && (n & 0xFFF) == 0) progress?.Report(n);
                return decoder;
            }, _ => { });

        // Call graph edges as print indexes.
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
        var built = new ImagePrints { Index = index, Functions = prints, ByStart = byStart, Elapsed = sw.Elapsed, Failed = failed };
        foreach (var p in prints) p.Image = built;
        return built;
    }

    // Instructions after a shift by 12 that may mask the card index: compilers
    // schedule a second shift, a bit mask and loads between them.
    private const int CardMaskWindow = 8;

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

        // Masked bytes and mnemonic histogram.
        var bytes = new Hash64();
        var histogram = new SortedDictionary<int, int>();
        var constants = new SortedSet<ulong>();
        var fedConstants = new List<ulong>();
        var fedTargets = new List<uint>();
        for (int n = 0; n < code.Count; n++)
        {
            if (code[n].Constant is not { } fed) continue;
            // The first call after the constant, with no branch between.
            for (int m = n + 1; m < code.Count && m <= n + FeedWindow; m++)
            {
                if (code[m].Flow == FlowKind.Call)
                {
                    if (code[m].Target is { } callee) { fedConstants.Add(fed); fedTargets.Add(callee); }
                    break;
                }
                if (code[m].Flow != FlowKind.Next) break;
            }
        }
        bool x86 = index.Image.Arch is NativeArch.X86 or NativeArch.X64;
        bool arm64 = index.Image.Arch == NativeArch.Arm64;
        int cardMask = -1;
        for (int n = 0; n < code.Count; n++)
        {
            var insn = code[n];
            for (int b = 0; b < insn.Length; b++) bytes.AddByte(insn.IsWild(b) ? 0x100 : insn.Bytes[b]);
            histogram[insn.Mnemonic] = histogram.GetValueOrDefault(insn.Mnemonic) + 1;
            // An inlined write barrier shifts an address by 12, then masks the
            // card index; its mask is shared by every storing function.
            if (x86 && insn.Mnemonic == (int)Iced.Intel.Mnemonic.Shr && insn.Bytes is [.., 0xC1, _, 0x0C]) cardMask = n + CardMaskWindow;
            // On ARM64 the shift is lsr #12: ubfm with immr 12 and imms 63
            // (64-bit) or 31 (32-bit).
            if (arm64 && insn.Bytes.Length == 4 && (System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(insn.Bytes) & 0xFFFFFC00) is 0xD34CFC00 or 0x530C7C00) cardMask = n + CardMaskWindow;
            bool mask = insn.Mnemonic == (x86 ? (int)Iced.Intel.Mnemonic.And : MaskedDecoder.Arm64Mnemonics + (int)AsmArm64.Arm64Mnemonic.AND);
            if (insn.Constant is { } k && !(n <= cardMask && mask)) constants.Add(k);
        }

        // Canonical depth-first order of blocks from the entry.
        var blocks = graph.Blocks;
        var blockIndex = new Dictionary<uint, int>(blocks.Count);
        for (int b = 0; b < blocks.Count; b++) blockIndex[blocks[b].Start] = b;
        var order = new int[blocks.Count];
        Array.Fill(order, -1);
        var sequence = new List<int>(blocks.Count);
        int backEdges = 0, edges = 0;
        // 0 new, 1 on stack, 2 done.
        var state = new byte[blocks.Count];
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

        // Per-block instruction shapes.
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

        // Imports and strings.
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
        var (sketch, shingles) = CodeSketch.Of(code);

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
            FedConstants = fedConstants.ToArray(),
            FedTargets = fedTargets.ToArray(),
            CallSites = calls,
            ThunkImport = thunk,
            Sketch = sketch,
            Shingles = shingles,
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
