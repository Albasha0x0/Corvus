using System.Collections.Concurrent;
using System.Diagnostics;

namespace Corvus.Native.Code;

/// <summary>Progress of <see cref="NativeCodeIndex.Build"/>: the phase, and work done / total when known (0 = unknown).</summary>
public readonly record struct CodeIndexProgress(string Phase, long Done, long Total);

/// <summary>Counts describing a built index.</summary>
public sealed record CodeIndexStats(
    int Functions,
    int Thunks,
    int NoReturnFunctions,
    long Instructions,
    long Blocks,
    long Xrefs,
    int Strings,
    int ResolvedSwitches,
    int UnresolvedJumps,
    int FunctionsWithInvalidCode,
    int DiscoveryPasses,
    int NoReturnRounds,
    TimeSpan Elapsed);

/// <summary>A call site: the instruction, what it reaches (function, import, or neither), and how.</summary>
public sealed record CallSite(uint From, uint Target, XrefKind Kind, NativeFunction? Caller, NativeFunction? Function, NativeImport? Import);

/// <summary>A node of a call tree; <see cref="Truncated"/> marks where the depth or node limit cut it.</summary>
public sealed class CallTreeNode
{
    public required NativeFunction? Function { get; init; }
    public NativeImport? Import { get; init; }
    public uint Address { get; init; }
    /// <summary>How the parent reaches this node (call, tail call, import call, VirtualExact, VirtualPossible).</summary>
    public XrefKind Via { get; init; }
    /// <summary>The call instruction the edge from the parent comes from (callers: in this node; callees: in the parent).</summary>
    public uint Site { get; init; }
    public List<CallTreeNode> Children { get; } = [];
    /// <summary>Already shown higher in the tree (recursion or repeated subtree): not expanded again.</summary>
    public bool Repeated { get; set; }
    public bool Truncated { get; set; }
}

/// <summary>
/// Code analysis of one native image, built once (on a background thread if wanted; every loop is cancellable):
/// functions, their code extents, cross-references (code -> code, calls through import slots, code -> data,
/// relocated data pointers, string references) and per-function control-flow graphs on demand. Immutable after
/// <see cref="Build"/>; queries are thread-safe.
/// </summary>
public sealed partial class NativeCodeIndex : ICodeSymbols
{
    private readonly CodeContext? _ctx;
    private readonly NativeFunction[] _functions;
    private readonly Dictionary<uint, NativeFunction> _byStart;
    private readonly Dictionary<string, uint[]> _discoveredByName;
    // per function code ranges, grouped by function (NativeFunction.FirstRange / RangeCount)
    private readonly uint[] _rangeStarts;
    private readonly uint[] _rangeEnds;
    // non-overlapping owner map: code range -> function index, sorted by start
    private readonly uint[] _ownerStarts;
    private readonly uint[] _ownerEnds;
    private readonly int[] _ownerFunctions;
    // cross-references sorted by (From, To, Kind), and an index sorted by (To, From)
    private readonly CodeXref[] _xrefs;
    private readonly int[] _byTo;
    private readonly StringLiteral[] _strings;
    private readonly Dictionary<uint, NativeImport> _imports = [];
    private readonly Dictionary<uint, string> _exportNames = [];

    public INativeImage Image { get; }
    public CodeSupport Support { get; }
    /// <summary>Why the analysis is limited (instruction set not supported), or null.</summary>
    public string? SupportNote { get; }
    /// <summary>Sorted by start.</summary>
    public IReadOnlyList<NativeFunction> Functions => _functions;
    /// <summary>Strings referenced by code or data, sorted by RVA.</summary>
    public IReadOnlyList<StringLiteral> Strings => _strings;
    /// <summary>Everything a limit cut short; empty when the index is complete.</summary>
    public IReadOnlyList<string> Truncations { get; }
    /// <summary>Where the analysis and what the image declares disagree (code walks past a Go function's own end).</summary>
    public IReadOnlyList<string> Issues { get; private set; } = [];
    public CodeIndexStats Stats { get; }
    /// <summary>Relocations in an x86 image are missing, so absolute operands were accepted by range alone.</summary>
    public bool AbsoluteRefsUnconfirmed { get; }
    /// <summary>
    /// The image has no relocations, so data pointers are pointer-sized values in data sections that are function starts and stand
    /// in runs of two or more, accepted by address range alone.
    /// </summary>
    public bool PointersUnconfirmed { get; }

    private NativeCodeIndex(INativeImage image, CodeSupport support, string? note, CodeContext? ctx, NativeFunction[] functions,
        uint[] rangeStarts, uint[] rangeEnds, CodeXref[] xrefs, StringLiteral[] strings, List<string> truncations, CodeIndexStats stats,
        int[]? byTo = null)
    {
        Image = image;
        Support = support;
        SupportNote = note;
        _ctx = ctx;
        _functions = functions;
        _byStart = functions.ToDictionary(f => f.Start);
        FindJumpThunks();
        // Known names here are the discovered ones; sources later override them per address only.
        _discoveredByName = functions.Where(f => f.KnownName != null).GroupBy(f => f.KnownName!, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.Select(f => f.Start).ToArray(), StringComparer.Ordinal);
        _rangeStarts = rangeStarts;
        _rangeEnds = rangeEnds;
        _xrefs = xrefs;
        _strings = strings;
        Truncations = truncations;
        Stats = stats;
        AbsoluteRefsUnconfirmed = image.Arch == NativeArch.X86 && image.RelocationRvas.Count == 0;
        PointersUnconfirmed = support == CodeSupport.Full && image.RelocationRvas.Count == 0;
        foreach (var imp in image.Imports) _imports.TryAdd(imp.SlotRva, imp);
        foreach (var e in image.Exports)
            if (e.ForwardedTo == null && e.Name != null) _exportNames.TryAdd(e.Rva, e.Name);

        // owner map: first function (lowest index) wins where ranges of several functions overlap
        var owners = new List<(uint S, uint E, int F)>(rangeStarts.Length);
        foreach (var f in functions)
            for (int r = f.FirstRange; r < f.FirstRange + f.RangeCount; r++) owners.Add((rangeStarts[r], rangeEnds[r], f.Index));
        owners.Sort((a, b) => a.S != b.S ? a.S.CompareTo(b.S) : a.F.CompareTo(b.F));
        var os = new List<uint>(owners.Count);
        var oe = new List<uint>(owners.Count);
        var of = new List<int>(owners.Count);
        uint covered = 0;
        foreach (var (s0, e, f) in owners)
        {
            uint s = Math.Max(s0, covered);
            if (s >= e) continue;
            os.Add(s); oe.Add(e); of.Add(f);
            covered = e;
        }
        _ownerStarts = os.ToArray();
        _ownerEnds = oe.ToArray();
        _ownerFunctions = of.ToArray();

        if (byTo != null) { _byTo = byTo; return; }
        _byTo = new int[xrefs.Length];
        var keys = new ulong[xrefs.Length];
        for (int i = 0; i < xrefs.Length; i++)
        {
            _byTo[i] = i;
            keys[i] = (ulong)xrefs[i].To << 32 | xrefs[i].From;
        }
        Array.Sort(keys, _byTo);
    }

    /// <summary>
    /// This analysis over <paramref name="image"/>, a patched copy of the indexed image: functions, extents and references
    /// as they were, instructions decoded from the new bytes. Cheap; for previews while the full index rebuilds.
    /// </summary>
    public NativeCodeIndex Rebase(INativeImage image)
    {
        CodeContext? ctx = null;
        if (_ctx != null)
        {
            ctx = new CodeContext(image, new ImageCode(image), _ctx.Options) { FunctionStarts = _ctx.FunctionStarts, NoReturn = _ctx.NoReturn };
            foreach (var s in _ctx.LocalSubroutines) ctx.LocalSubroutines.Add(s);
            foreach (var s in _ctx.Funclets) ctx.Funclets.Add(s);
            foreach (var (thunk, slot) in _ctx.Thunks) ctx.Thunks[thunk] = slot;
        }
        return new NativeCodeIndex(image, Support, SupportNote, ctx, _functions, _rangeStarts, _rangeEnds, _xrefs, _strings, [.. Truncations], Stats, _byTo)
        {
            Issues = Issues,
        };
    }

    /// <summary>Builds the index. Long-running for large images: run it on a background thread.</summary>
    public static NativeCodeIndex Build(INativeImage image, CodeIndexOptions? options = null, Action<CodeIndexProgress>? progress = null, CancellationToken ct = default)
    {
        options ??= new CodeIndexOptions();
        var report = new ProgressGate(progress);
        var (support, note) = InstructionSets.For(image.Arch);
        if (support != CodeSupport.Full) return DeclaredOnly(image, note, report, options.SymbolStarts);
        return new Builder(image, options, report, ct).Run();
    }

    public static Task<NativeCodeIndex> BuildAsync(INativeImage image, CodeIndexOptions? options = null, Action<CodeIndexProgress>? progress = null, CancellationToken ct = default) =>
        Task.Run(() => Build(image, options, progress, ct), ct);

    /// <summary>Instruction sets without a decoder: functions the image declares, no code analysis.</summary>
    private static NativeCodeIndex DeclaredOnly(INativeImage image, string? note, ProgressGate report, IReadOnlyCollection<uint>? symbolStarts)
    {
        var sw = Stopwatch.StartNew();
        var sources = new Dictionary<uint, FunctionSource>();
        void Add(uint rva, FunctionSource s) { if (image.SectionAt(rva) is { IsExecutable: true }) sources[rva] = sources.GetValueOrDefault(rva) | s; }
        foreach (var rf in image.RuntimeFunctions) Add(rf.BeginRva, FunctionSource.Pdata);
        foreach (var e in image.Exports) if (e.ForwardedTo == null) Add(e.Rva, FunctionSource.Export);
        if (image.EntryPointRva != 0) Add(image.EntryPointRva, FunctionSource.EntryPoint);
        foreach (var t in image.TlsCallbackRvas) Add(t, FunctionSource.TlsCallback);
        foreach (var t in symbolStarts ?? []) Add(t, FunctionSource.Symbol);
        foreach (var d in image.DeclaredFunctions) Add(d.Rva, FunctionDiscovery.Source(d.Source));
        var go = Go.GoFunctionTable.Of(image);
        foreach (var g in go?.Functions ?? []) Add(g.Rva, FunctionSource.GoTable);
        var ends = image.RuntimeFunctions.GroupBy(r => r.BeginRva).ToDictionary(g => g.Key, g => g.Max(r => r.EndRva));
        foreach (var d in image.DeclaredFunctions)
            if (d.Size is { } size && !ends.ContainsKey(d.Rva)) ends[d.Rva] = d.Rva + size;
        foreach (var g in go?.Functions ?? [])
            if (g.Size > 0) ends.TryAdd(g.Rva, g.Rva + g.Size);
        var functions = sources.OrderBy(kv => kv.Key).Select((kv, i) => new NativeFunction
        {
            Start = kv.Key, Sources = kv.Value, Index = i,
            End = ends.TryGetValue(kv.Key, out var end) && end > kv.Key ? end : kv.Key,
        }).ToArray();
        foreach (var f in functions) f.Size = f.End - f.Start;
        var names = FunctionNames(image);
        foreach (var f in functions) if (names.TryGetValue(f.Start, out var n)) f.KnownName = n;
        report.Done();
        var stats = new CodeIndexStats(functions.Length, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, sw.Elapsed);
        return new NativeCodeIndex(image, CodeSupport.DeclaredFunctionsOnly, note, null, functions, [], [], [], [], [], stats);
    }

    /// <summary>Names the image gives function starts: exports, function symbols (ELF .dynsym / .symtab, Mach-O nlist), then the Go function table.</summary>
    private static Dictionary<uint, string> FunctionNames(INativeImage image)
    {
        var names = new Dictionary<uint, string>();
        foreach (var e in image.Exports)
            if (e.ForwardedTo == null && e.Name != null) names.TryAdd(e.Rva, e.Name);
        foreach (var s in image.Symbols)
            if (s.Kind == ImageSymbolKind.Function && s.Name.Length > 0) names.TryAdd(s.Rva, s.Name);
        foreach (var g in Go.GoFunctionTable.Of(image)?.Functions ?? [])
            if (g.Name != null) names.TryAdd(g.Rva, g.Name);
        return names;
    }

    public NativeFunction? FunctionByStart(uint start) => _byStart.GetValueOrDefault(start);

    /// <summary>The function whose code contains <paramref name="rva"/> (first owner where functions share code), or null.</summary>
    public NativeFunction? FunctionAt(uint rva)
    {
        if (_byStart.TryGetValue(rva, out var exact)) return exact;
        int i = Array.BinarySearch(_ownerStarts, rva);
        if (i < 0) i = ~i - 1;
        if (i >= 0 && rva < _ownerEnds[i]) return _functions[_ownerFunctions[i]];
        if (Support != CodeSupport.Full)
        {
            // declared functions only: the nearest start whose .pdata range contains the address
            int lo = 0, hi = _functions.Length - 1, best = -1;
            while (lo <= hi) { int mid = (lo + hi) >>> 1; if (_functions[mid].Start <= rva) { best = mid; lo = mid + 1; } else hi = mid - 1; }
            if (best >= 0 && rva < _functions[best].End) return _functions[best];
        }
        return null;
    }

    /// <summary>Code ranges (start, exclusive end) of a function, sorted.</summary>
    public IEnumerable<(uint Start, uint End)> Ranges(NativeFunction f)
    {
        for (int r = f.FirstRange; r < f.FirstRange + f.RangeCount; r++) yield return (_rangeStarts[r], _rangeEnds[r]);
    }

    /// <summary>Cross-references to <paramref name="rva"/>, sorted by source.</summary>
    public List<CodeXref> RefsTo(uint rva, int max = int.MaxValue)
    {
        var result = new List<CodeXref>();
        int lo = 0, hi = _byTo.Length;
        while (lo < hi) { int mid = (lo + hi) >>> 1; if (_xrefs[_byTo[mid]].To < rva) lo = mid + 1; else hi = mid; }
        for (int i = lo; i < _byTo.Length && result.Count < max; i++)
        {
            var x = _xrefs[_byTo[i]];
            if (x.To != rva) break;
            result.Add(x);
        }
        return result;
    }

    /// <summary>Cross-references whose target is in [<paramref name="start"/>, <paramref name="end"/>), sorted by target.</summary>
    public List<CodeXref> RefsToRange(uint start, uint end)
    {
        var result = new List<CodeXref>();
        int lo = 0, hi = _byTo.Length;
        while (lo < hi) { int mid = (lo + hi) >>> 1; if (_xrefs[_byTo[mid]].To < start) lo = mid + 1; else hi = mid; }
        for (int i = lo; i < _byTo.Length && _xrefs[_byTo[i]].To < end; i++) result.Add(_xrefs[_byTo[i]]);
        return result;
    }

    /// <summary>Number of cross-references to <paramref name="rva"/>.</summary>
    public int CountRefsTo(uint rva)
    {
        int lo = 0, hi = _byTo.Length;
        while (lo < hi) { int mid = (lo + hi) >>> 1; if (_xrefs[_byTo[mid]].To < rva) lo = mid + 1; else hi = mid; }
        int n = 0;
        for (int i = lo; i < _byTo.Length && _xrefs[_byTo[i]].To == rva; i++) n++;
        return n;
    }

    /// <summary>Cross-references whose source is in [<paramref name="start"/>, <paramref name="end"/>).</summary>
    public List<CodeXref> RefsFrom(uint start, uint end)
    {
        var result = new List<CodeXref>();
        int lo = 0, hi = _xrefs.Length;
        while (lo < hi) { int mid = (lo + hi) >>> 1; if (_xrefs[mid].From < start) lo = mid + 1; else hi = mid; }
        for (int i = lo; i < _xrefs.Length && _xrefs[i].From < end; i++) result.Add(_xrefs[i]);
        return result;
    }

    /// <summary>Cross-references from the code of <paramref name="f"/>.</summary>
    public List<CodeXref> RefsFrom(NativeFunction f)
    {
        var result = new List<CodeXref>();
        foreach (var (s, e) in Ranges(f)) result.AddRange(RefsFrom(s, e));
        return result;
    }

    /// <summary>
    /// Calls and tail calls to <paramref name="f"/> (and, for a thunk, to its import), with the calling function; with
    /// <paramref name="edges"/> All or Virtual also the virtual call sites that may reach it. Sorted by source.
    /// </summary>
    public List<CallSite> Callers(NativeFunction f, CallEdgeFilter edges = CallEdgeFilter.All)
    {
        var result = new List<CallSite>();
        if (edges != CallEdgeFilter.Virtual)
            foreach (var x in RefsTo(f.Start))
                if (x.Kind is XrefKind.Call or XrefKind.TailCall)
                    result.Add(new CallSite(x.From, x.To, x.Kind, FunctionAt(x.From), f, null));
        if (edges != CallEdgeFilter.Direct && _virtualEdges.Length > 0)
        {
            foreach (var x in VirtualEdgesTo(f.Start)) result.Add(new CallSite(x.From, x.To, x.Kind, FunctionAt(x.From), f, null));
            result.Sort((a, b) => a.From.CompareTo(b.From));
        }
        return result;
    }

    /// <summary>Calls through the slot of <paramref name="import"/> and calls to thunks that jump through it.</summary>
    public List<CallSite> Callers(NativeImport import)
    {
        var result = new List<CallSite>();
        foreach (var x in RefsTo(import.SlotRva))
        {
            if (x.Kind is not (XrefKind.ImportCall or XrefKind.ImportJump)) continue;
            var caller = FunctionAt(x.From);
            if (x.Kind == XrefKind.ImportJump && caller is { } thunk && (thunk.Flags & FunctionFlags.Thunk) != 0)
            {
                foreach (var t in Callers(thunk)) result.Add(t with { Import = import });
                continue;
            }
            result.Add(new CallSite(x.From, x.To, x.Kind, caller, null, import));
        }
        return result;
    }

    /// <summary>
    /// Direct calls, tail calls and import calls made by <paramref name="f"/>, with <paramref name="edges"/> All or Virtual also
    /// the implementations its virtual call sites may reach; in address order.
    /// </summary>
    public List<CallSite> Callees(NativeFunction f, CallEdgeFilter edges = CallEdgeFilter.All)
    {
        var result = new List<CallSite>();
        if (edges != CallEdgeFilter.Virtual)
            foreach (var x in RefsFrom(f))
            {
                if (!x.IsCallLike) continue;
                if (x.Kind is XrefKind.ImportCall or XrefKind.ImportJump)
                    result.Add(new CallSite(x.From, x.To, x.Kind, f, null, _imports.GetValueOrDefault(x.To)));
                else
                {
                    var target = FunctionByStart(x.To);
                    result.Add(new CallSite(x.From, x.To, x.Kind, f, target, target?.ThunkImport));
                }
            }
        if (edges != CallEdgeFilter.Direct && _virtualEdges.Length > 0)
        {
            int before = result.Count;
            foreach (var (s, e) in Ranges(f))
                foreach (var x in VirtualEdgesFrom(s, e))
                {
                    var target = FunctionByStart(x.To);
                    result.Add(new CallSite(x.From, x.To, x.Kind, f, target, target?.ThunkImport));
                }
            if (result.Count > before) result.Sort((a, b) => a.From != b.From ? a.From.CompareTo(b.From) : a.Target.CompareTo(b.Target));
        }
        return result;
    }

    /// <summary>
    /// Callers (<paramref name="callers"/> = true) or callees of <paramref name="root"/> to <paramref name="depth"/> levels,
    /// at most <paramref name="maxNodes"/> nodes; repeated functions are listed once and not expanded again.
    /// </summary>
    public CallTreeNode CallTree(NativeFunction root, int depth, bool callers, int maxNodes = 2000, CallEdgeFilter edges = CallEdgeFilter.All)
    {
        var node = new CallTreeNode { Function = root, Address = root.Start };
        var expanded = new HashSet<uint> { root.Start };
        int count = 1;
        var queue = new Queue<(CallTreeNode Node, int Depth)>();
        queue.Enqueue((node, 0));
        while (queue.Count > 0)
        {
            var (n, d) = queue.Dequeue();
            if (n.Function == null) continue;
            var sites = callers ? Callers(n.Function, edges) : Callees(n.Function, edges);
            if (d >= depth) { if (sites.Count > 0) n.Truncated = true; continue; }
            var seenHere = new HashSet<(uint, bool)>();
            foreach (var s in sites)
            {
                var fn = callers ? s.Caller : s.Function;
                uint key = fn?.Start ?? s.Target;
                if (!seenHere.Add((key, fn != null))) continue;
                if (count >= maxNodes) { n.Truncated = true; break; }
                var child = new CallTreeNode { Function = fn, Import = callers ? null : s.Import, Address = callers ? s.From : s.Target, Via = s.Kind, Site = s.From };
                count++;
                n.Children.Add(child);
                if (fn == null) continue;
                if (!expanded.Add(fn.Start)) { child.Repeated = true; continue; }
                queue.Enqueue((child, d + 1));
            }
        }
        return node;
    }

    /// <summary>Basic blocks and edges of <paramref name="f"/> and its chunks (decoded again on each call).</summary>
    public FunctionGraph GetGraph(NativeFunction f, CancellationToken ct = default)
    {
        if (_ctx == null) throw new NotSupportedException(SupportNote);
        var walker = new FunctionWalker(_ctx);
        return walker.Walk(f, f.Start, buildGraph: true, ct, ChunkRoots(f)).Graph!;
    }

    /// <summary>Facts of the instruction at <paramref name="rva"/> (any mapped address), or null.</summary>
    public InstructionFacts? Decode(uint rva)
    {
        if (_ctx == null) return null;
        var d = Image.Arch is NativeArch.X86 or NativeArch.X64 ? CodeDecoders.Create(Image, _ctx.Code, _ctx.Relocations) : _ctx.NewDecoder(computeAccess: true);
        return d.DecodeMapped(rva, out var insn) ? NativeDisassembler.Facts(in insn) : null;
    }

    /// <summary>A decoder over this index's code (relocations, import slots, data in code), or null without one. One per caller.</summary>
    internal ICodeDecoder? NewDecoder() => _ctx?.NewDecoder(computeAccess: true);

    /// <summary>Sorted byte ranges inside code that hold data (Mach-O data in code, ELF $d mapping symbols).</summary>
    internal (uint Start, uint End)[] DataInCode => _ctx?.DataInCode ?? [];

    /// <summary>32-bit ARM: the ARM or Thumb state of each function; null otherwise.</summary>
    internal Arm32Modes? ArmModes => _ctx?.ArmModes;

    /// <summary>A disassembler that names targets through this index. Not thread-safe; create one per caller.</summary>
    public NativeDisassembler CreateDisassembler()
    {
        if (_ctx == null) throw new NotSupportedException(SupportNote);
        return new NativeDisassembler(Image, this, _ctx.Relocations, _ctx.ArmModes, _ctx.Code);
    }

    /// <summary>Linear disassembly from <paramref name="rva"/>.</summary>
    public List<DisasmLine> Disassemble(uint rva, int maxInstructions, uint end = uint.MaxValue) =>
        CreateDisassembler().Disassemble(rva, maxInstructions, end);

    /// <summary>
    /// Disassembly of a function's blocks in address order, each block preceded by its label line
    /// ("name:" for the entry, "loc_&lt;rva&gt;:" otherwise). At most <paramref name="maxInstructions"/> instructions;
    /// <paramref name="truncated"/> tells whether that cut the listing.
    /// </summary>
    public List<(string? Label, DisasmLine? Line)> DisassembleFunction(NativeFunction f, int maxInstructions, out bool truncated, CancellationToken ct = default)
    {
        var graph = GetGraph(f, ct);
        var labels = new Dictionary<uint, string>();
        foreach (var b in graph.Blocks) labels[b.Start] = b.Start == f.Start ? f.Name : ChunkLabel(f, b.Start) ?? $"loc_{b.Start:X}";
        var dis = CreateDisassembler();
        var result = new List<(string?, DisasmLine?)>();
        int count = 0;
        truncated = false;
        uint covered = 0;
        foreach (var b in graph.Blocks)
        {
            if (b.End <= covered) continue;
            result.Add((labels[b.Start] + ":", null));
            foreach (var line in dis.Disassemble(Math.Max(b.Start, covered), b.InstructionCount, b.End, labels))
            {
                if (count++ >= maxInstructions) { truncated = true; return result; }
                result.Add((null, line));
            }
            covered = b.End;
        }
        return result;
    }

    /// <summary>The string literal starting at <paramref name="rva"/>, if code or data references one there.</summary>
    public StringLiteral? StringAt(uint rva)
    {
        int lo = 0, hi = _strings.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (_strings[mid].Rva == rva) return _strings[mid];
            if (_strings[mid].Rva < rva) lo = mid + 1; else hi = mid - 1;
        }
        return null;
    }

    public string ReadString(StringLiteral s, int maxChars = 1024) => StringDetector.Read(Image, s, maxChars);

    // Names and comments by source (user annotations mirrored from NativeAnnotations, imported pdb / il2cpp layers);
    // the highest source wins over discovered names, and KnownName of the matching function is updated so
    // list_functions and labels show it.
    private readonly SourcedNames _sourced = new();
    private readonly Dictionary<uint, string?> _builtinNames = new();

    /// <summary>The names and comments set on this index by source.</summary>
    public SourcedNames Sourced => _sourced;

    /// <summary>Applies a user name (null clears it, restoring the imported or discovered name).</summary>
    public void SetUserName(uint rva, string? name) => SetSourceName(rva, name, NativeNameSource.User);

    public void SetUserComment(uint rva, string? text) => _sourced.SetComment(rva, text, NativeNameSource.User);

    /// <summary>Sets (null clears) one source's name at <paramref name="rva"/>.</summary>
    public void SetSourceName(uint rva, string? name, NativeNameSource source)
    {
        lock (_builtinNames) ApplyKnownName(rva, _sourced.SetName(rva, name, source));
    }

    /// <summary>Replaces every name and comment of an imported source (null clears the source).</summary>
    public void ReplaceSource(NativeNameSource source, IReadOnlyDictionary<uint, string>? names, IReadOnlyDictionary<uint, string>? comments)
    {
        lock (_builtinNames)
        {
            foreach (var (rva, name) in _sourced.ReplaceNames(source, names)) ApplyKnownName(rva, name);
            _sourced.ReplaceComments(source, comments);
        }
    }

    private void ApplyKnownName(uint rva, string? name)
    {
        if (!_byStart.TryGetValue(rva, out var f)) return;
        if (!_builtinNames.ContainsKey(rva)) _builtinNames[rva] = f.KnownName;
        f.KnownName = name ?? _builtinNames[rva];
        // jump thunks to it follow its name (j_<name>) unless a source named them
        foreach (uint t in _thunksTo.GetValueOrDefault(rva) ?? [])
            if (_sourced.NameAt(t) == null && _byStart.TryGetValue(t, out var thunk) && (thunk.KnownName == null || thunk.KnownName.StartsWith("j_", StringComparison.Ordinal)))
                ApplyKnownName(t, f.KnownName is { } target ? "j_" + target : null);
    }

    // jump thunk -> the function it jumps to, and back
    private readonly Dictionary<uint, List<uint>> _thunksTo = [];

    /// <summary>
    /// Functions that are one direct jump to another function (x86 / x64 jmp rel32 / rel8, ARM64 b, ARM32 b and veneers): incremental-link thunks
    /// and the like, named j_&lt;target&gt; as IDA names them while they have no name of their own. ELF PLT stubs of a
    /// function this image exports jump to it too.
    /// </summary>
    private void FindJumpThunks()
    {
        Span<byte> b = stackalloc byte[12];
        var localPlt = new Dictionary<uint, uint>();
        if (Image is Elf.ElfFile elf && ElfLocalSlots.Of(Image) is { Count: > 0 } local)
            foreach (var e in elf.PltEntries)
                if (local.TryGetValue(e.SlotRva, out uint fn)) localPlt.TryAdd(e.StubRva, fn & ~1u);
        foreach (var f in _functions)
        {
            if (f.ThunkImport != null) continue;
            if (localPlt.TryGetValue(f.Start, out uint plt) && _byStart.TryGetValue(plt, out var exported) && exported != f)
            {
                if (!_thunksTo.TryGetValue(plt, out var stubs)) _thunksTo[plt] = stubs = [];
                stubs.Add(f.Start);
                continue;
            }
            if (Image.Arch == NativeArch.Arm)
            {
                if (f.InstructionCount > 4 || f.Size > 12 || Image.Read(f.Start, b[..(int)f.Size]) < f.Size) continue;
            }
            else if (f.InstructionCount != 1 || f.Size is not (2 or 4 or 5) || Image.Read(f.Start, b[..(int)f.Size]) < f.Size) continue;
            long target = (Image.Arch, f.Size, b[0]) switch
            {
                (NativeArch.X86 or NativeArch.X64, 5, 0xE9) => f.Start + 5L + System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(b[1..]),
                (NativeArch.X86 or NativeArch.X64, 2, 0xEB) => f.Start + 2L + (sbyte)b[1],
                (NativeArch.Arm64, 4, _) when (System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(b) & 0xFC000000) == 0x14000000 =>
                    f.Start + ((long)((int)(System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(b) << 6) >> 6) << 2),
                (NativeArch.Arm, _, _) => Arm32JumpThunkTarget(f.Start, b[..(int)f.Size], _ctx?.ArmModes?.At(f.Start) ?? true),
                _ => -1,
            };
            if (target < 0 || target > uint.MaxValue || target == f.Start || !_byStart.TryGetValue((uint)target, out var to)) continue;
            if (!_thunksTo.TryGetValue(to.Start, out var list)) _thunksTo[to.Start] = list = [];
            list.Add(f.Start);
        }
        // thunks to thunks: named in chain order, as a saved index (which holds the names) reads them back
        bool changed = true;
        for (int guard = 0; changed && guard < 8; guard++)
        {
            changed = false;
            foreach (var (target, thunks) in _thunksTo)
                if (_byStart[target].KnownName is { } name)
                    foreach (uint t in thunks)
                        if (_byStart[t].KnownName == null) { _byStart[t].KnownName = "j_" + name; changed = true; }
        }
    }

    /// <summary>
    /// ARM32 jump thunks: Thumb b / b.w, ARM b, and the linker's Thumb long-branch veneer (movw ip / movt ip / add ip, pc / bx ip);
    /// -1 for anything else.
    /// </summary>
    internal static long Arm32JumpThunkTarget(uint start, ReadOnlySpan<byte> b, bool thumb)
    {
        static ushort H(ReadOnlySpan<byte> s, int at) => System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(s[at..]);
        static uint W(ReadOnlySpan<byte> s, int at) => System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(s[at..]);
        if (thumb)
        {
            if (b.Length == 2 && (H(b, 0) & 0xF800) == 0xE000) return start + 4L + ((int)((uint)H(b, 0) << 21) >> 20);
            if (b.Length == 4 && (H(b, 0) & 0xF800) == 0xF000 && (H(b, 2) & 0xD000) == 0x9000)
            {
                uint h1 = H(b, 0), h2 = H(b, 2), s = h1 >> 10 & 1;
                uint i1 = ~(h2 >> 13 ^ s) & 1, i2 = ~(h2 >> 11 ^ s) & 1;
                uint imm = s << 24 | i1 << 23 | i2 << 22 | (h1 & 0x3FF) << 12 | (h2 & 0x7FF) << 1;
                return start + 4L + ((int)(imm << 7) >> 7);
            }
            if (b.Length == 12 && (H(b, 0) & 0xFBF0) == 0xF240 && (H(b, 2) & 0x8F00) == 0x0C00 && (H(b, 4) & 0xFBF0) == 0xF2C0 && (H(b, 6) & 0x8F00) == 0x0C00
                && H(b, 8) == 0x44FC && H(b, 10) == 0x4760)
            {
                static uint Imm16(ushort h1, ushort h2) => (uint)((h1 & 0xF) << 12 | (h1 >> 10 & 1) << 11 | (h2 >> 12 & 7) << 8 | h2 & 0xFF);
                uint value = Imm16(H(b, 4), H(b, 6)) << 16 | Imm16(H(b, 0), H(b, 2));
                return (start + 8L + 4 + value) & 0xFFFFFFFEL;
            }
            return -1;
        }
        if (b.Length == 4 && W(b, 0) >> 24 == 0xEA) return start + 8L + ((int)(W(b, 0) << 8) >> 6);
        return -1;
    }

    /// <summary>
    /// Every address <paramref name="name"/> is in effect at: names set by a source (user, pdb, il2cpp, ida, ghidra), and the
    /// discovered names (exports, import thunks) of functions no source renamed.
    /// </summary>
    public IReadOnlyList<AddressCandidate> AddressesOfName(string name)
    {
        var found = _sourced.AddressesOf(name).Select(c => new AddressCandidate(c.Rva, c.Source.Id())).ToList();
        foreach (var rva in _discoveredByName.GetValueOrDefault(name) ?? [])
            if (_sourced.NameAt(rva) == null) found.Add(new(rva, _byStart[rva].ThunkImport != null ? "thunk" : "export"));
        return found;
    }

    /// <summary>The one address of <paramref name="name"/> (see <see cref="AddressesOfName"/>): null when none, an ambiguous error when several.</summary>
    public uint? AddressOfName(string name) => NativeAddress.WithoutJumpThunks(Image, AddressesOfName(name).ToList()) switch
    {
        [] => null,
        [var one] => one.Rva,
        var several => throw NativeAddress.Ambiguous(Image, name, several),
    };

    /// <summary>Import "module!name" (or "module!#ordinal"), function name, or export name at <paramref name="rva"/>.</summary>
    public string? NameAt(uint rva)
    {
        if (_sourced.NameAt(rva) is { } named) return named.Name;
        if (_imports.TryGetValue(rva, out var imp)) return ImportName(imp);
        if (_byStart.TryGetValue(rva, out var f)) return f.Name;
        return _exportNames.GetValueOrDefault(rva);
    }

    public string? CommentFor(uint rva)
    {
        if (_sourced.CommentAt(rva) is { } comment) return comment.Text;
        const int max = 120;
        if (StringAt(rva) is not { } s) return CfStringAt(rva) is { } cf ? "@" + StringDetector.Quote(ReadString(cf, max), cf.Length > max) : null;
        return (s.Encoding == StringEncoding.Utf16 ? "L" : "") + StringDetector.Quote(ReadString(s, max), s.Length > max);
    }

    /// <summary>The C string of a Mach-O CFString constant (__cfstring: isa, flags, chars, length) at <paramref name="rva"/>, or null.</summary>
    public StringLiteral? CfStringAt(uint rva)
    {
        if (Image.Format != ImageFormat.MachO || Image.SectionAt(rva) is not { } section || !section.Name.EndsWith(",__cfstring", StringComparison.Ordinal)) return null;
        int ptr = Image.Is64Bit ? 8 : 4;
        if ((rva - section.Rva) % (uint)(ptr * 4) != 0) return null;
        Span<byte> b = stackalloc byte[8];
        if (Image.Read(rva + (uint)(2 * ptr), b[..ptr]) < ptr) return null;
        ulong va = ptr == 8 ? System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(b) : System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(b);
        if (va < Image.ImageBase || va - Image.ImageBase >= Image.SizeOfImage) return null;
        uint chars = (uint)(va - Image.ImageBase);
        return StringAt(chars) ?? StringDetector.Detect(Image, chars, 4096, new byte[(4096 + 1) * 2]);
    }

    public static string ImportName(NativeImport imp)
    {
        string module = imp.Module.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? imp.Module[..^4] : imp.Module;
        return imp.Name != null ? $"{module}!{imp.Name}" : $"{module}!#{imp.Ordinal}";
    }

    /// <summary>The union of code ranges, merged and sorted for containment tests.</summary>
    private sealed class CodeCover
    {
        private readonly uint[] _starts;
        private readonly uint[] _ends;

        public CodeCover(uint[] starts, uint[] ends)
        {
            var order = Enumerable.Range(0, starts.Length).OrderBy(i => starts[i]).ToArray();
            var s = new List<uint>(order.Length);
            var e = new List<uint>(order.Length);
            foreach (int i in order)
            {
                if (e.Count > 0 && starts[i] <= e[^1]) { if (ends[i] > e[^1]) e[^1] = ends[i]; continue; }
                s.Add(starts[i]);
                e.Add(ends[i]);
            }
            _starts = s.ToArray();
            _ends = e.ToArray();
        }

        public bool Contains(uint rva)
        {
            int i = Array.BinarySearch(_starts, rva);
            if (i < 0) i = ~i - 1;
            return i >= 0 && rva < _ends[i];
        }
    }

    /// <summary>Forwards progress at most every 100 ms, plus the final update.</summary>
    private sealed class ProgressGate(Action<CodeIndexProgress>? sink)
    {
        private long _last = -1;
        private string _phase = "";

        public void Report(string phase, long done, long total)
        {
            if (sink == null) return;
            long now = Environment.TickCount64;
            if (phase == _phase && _last >= 0 && now - Interlocked.Read(ref _last) < 100) return;
            _phase = phase;
            Interlocked.Exchange(ref _last, now);
            sink(new CodeIndexProgress(phase, done, total));
        }

        public void Done() => sink?.Invoke(new CodeIndexProgress("done", 1, 1));
    }

    private sealed partial class Builder(INativeImage image, CodeIndexOptions options, ProgressGate report, CancellationToken ct)
    {
        private readonly Stopwatch _sw = Stopwatch.StartNew();
        private readonly List<string> _truncations = [];
        private CodeContext _ctx = null!;
        private int _passes, _rounds;

        public NativeCodeIndex Run()
        {
            var code = new ImageCode(image);
            _truncations.AddRange(code.Truncations);
            _ctx = new CodeContext(image, code, options);
            var baseNoReturn = new HashSet<uint>(_ctx.NoReturn);
            if (image.Format is ImageFormat.Elf or ImageFormat.MachO) ReadLandingPads();

            var starts = Discover();
            var results = WalkWithNoReturn(starts);
            bool demoted = DemoteLocalSubroutines(starts, results);
            if (demoted || CodeFollowsNoReturnCalls(results))
            {
                // again with the noreturn functions and local subroutines known: code after calls to noreturn
                // functions is no longer followed, so function starts found only there disappear and gaps open for
                // the gap scan; local subroutines are explored as part of their function
                starts = Discover();
                _ctx.NoReturn = new HashSet<uint>(baseNoReturn);
                foreach (var (start, slot) in _ctx.Thunks) if (_ctx.NoReturn.Contains(slot)) _ctx.NoReturn.Add(start);
                results = WalkWithNoReturn(starts);
            }
            var chunks = AttachExceptionChunks(ref starts, ref results);
            var index = Assemble(starts, results);
            index.Apply(chunks);
            index.Issues = GoExtentIssues(index);
            if (options.ResolveVirtualCalls && ResolvesVirtualCalls(image))
            {
                report.Report("resolving virtual calls", 0, 0);
                index.ResolveVirtualCalls(options, ct);
                report.Done();
            }
            return index;
        }

        /// <summary>
        /// Functions known only as call targets that their single calling function also runs into without a branch
        /// (x86 __finally blocks are called and fallen into): recorded as local subroutines of that function.
        /// </summary>
        private bool DemoteLocalSubroutines(uint[] starts, WalkResult[] results)
        {
            var callOnly = starts.Where(s => _sources[s] == FunctionSource.Call).ToHashSet();
            if (callOnly.Count == 0) return false;
            var callSites = new Dictionary<uint, List<uint>>();
            foreach (var r in results)
                foreach (var x in r.Xrefs)
                    if (x.Kind == XrefKind.Call && callOnly.Contains(x.To))
                    {
                        if (!callSites.TryGetValue(x.To, out var list)) callSites[x.To] = list = [];
                        list.Add(x.From);
                    }
            bool any = false;
            for (int g = 0; g < results.Length; g++)
                foreach (var f in results[g].FallsInto)
                {
                    if (!callOnly.Contains(f) || !callSites.TryGetValue(f, out var sites)) continue;
                    if (sites.All(s => InRanges(results[g], s)) && _ctx.LocalSubroutines.Add(f)) any = true;
                }
            return any;
        }

        private static bool InRanges(WalkResult r, uint rva)
        {
            int i = Array.BinarySearch(r.RangeStarts, rva);
            if (i < 0) i = ~i - 1;
            return i >= 0 && rva < r.RangeEnds[i];
        }

        /// <summary>
        /// Discovery followed some call to a function later found not to return into code that is not a known
        /// function start or padding: that code (and what it calls) may not be code at all.
        /// </summary>
        private bool CodeFollowsNoReturnCalls(WalkResult[] results)
        {
            var local = _ctx.NoReturn.Where(r => !_ctx.ImportSlots.ContainsKey(r) && !_ctx.Thunks.ContainsKey(r)).ToHashSet();
            if (local.Count == 0) return false;
            var dec = _ctx.NewDecoder(computeAccess: false);
            foreach (var r in results)
                foreach (var x in r.Xrefs)
                {
                    if (x.Kind != XrefKind.Call || !local.Contains(x.To) || !dec.Decode(x.From, out var call)) continue;
                    uint next = call.Next;
                    if (_ctx.FunctionStarts.Contains(next) || _ctx.Code.RegionAt(next) is not { } region) continue;
                    if (dec.IsPadding(region, next)) continue;
                    dec.Decode(region, next, out var after);
                    if (after.Flow is not (FlowKind.Trap or FlowKind.Invalid)) return true;
                }
            return false;
        }

        private Dictionary<uint, FunctionSource> _sources = [];

        private uint[] Discover()
        {
            _passes++;
            ct.ThrowIfCancellationRequested();
            _ctx.FunctionStarts = [];
            _ctx.Thunks.Clear();
            _ctx.ArmModes?.Open();
            var discovery = new FunctionDiscovery(_ctx, ct, n => report.Report("discovering functions", n, 0));
            _sources = discovery.Run();
            if (discovery.FunctionsTruncated) AddTruncation($"function limit {options.MaxFunctions} reached");
            var starts = _sources.Keys.ToArray();
            Array.Sort(starts);
            _ctx.FunctionStarts = new HashSet<uint>(starts);
            _ctx.ArmModes?.Seal(starts);
            return starts;
        }

        private void AddTruncation(string text)
        {
            if (!_truncations.Contains(text)) _truncations.Add(text);
        }

        /// <summary>Walks every function, then re-walks callers of functions found not to return until nothing changes.</summary>
        private WalkResult[] WalkWithNoReturn(uint[] starts)
        {
            var results = new WalkResult[starts.Length];
            var index = new Dictionary<uint, int>(starts.Length);
            for (int i = 0; i < starts.Length; i++) index[starts[i]] = i;
            WalkAll(starts, results, Enumerable.Range(0, starts.Length).ToArray(), "analyzing functions");
            for (int round = 0; ; round++)
            {
                var newly = new List<uint>();
                for (int i = 0; i < starts.Length; i++)
                    if (!results[i].Returns && !_ctx.NoReturn.Contains(starts[i]) && !_ctx.Returns.Contains(starts[i])) newly.Add(starts[i]);
                if (newly.Count == 0) break;
                if (round >= options.MaxNoReturnRounds) { AddTruncation($"noreturn propagation stopped after {round} rounds"); break; }
                _rounds++;
                foreach (var n in newly) _ctx.NoReturn.Add(n);
                var newlySet = new HashSet<uint>(newly);
                var affected = new List<int>();
                for (int i = 0; i < starts.Length; i++)
                    if (results[i].Callees.Any(newlySet.Contains)) affected.Add(i);
                if (affected.Count == 0) break;
                WalkAll(starts, results, affected.ToArray(), "propagating noreturn");
            }
            return results;
        }

        private void WalkAll(uint[] starts, WalkResult[] results, int[] which, string phase)
        {
            if (which.Length == 0) return;
            long done = 0;
            var po = new ParallelOptions { CancellationToken = ct, MaxDegreeOfParallelism = options.MaxParallelism > 0 ? options.MaxParallelism : Environment.ProcessorCount };
            var chunks = Partitioner.Create(0, which.Length, Math.Max(64, which.Length / (po.MaxDegreeOfParallelism * 8) + 1));
            Parallel.ForEach(chunks, po, () => new FunctionWalker(_ctx), (range, _, walker) =>
            {
                for (int k = range.Item1; k < range.Item2; k++)
                {
                    int i = which[k];
                    results[i] = walker.Walk(null, starts[i], buildGraph: false, ct);
                }
                report.Report(phase, Interlocked.Add(ref done, range.Item2 - range.Item1), which.Length);
                return walker;
            }, _ => { });
        }

        private NativeCodeIndex Assemble(uint[] starts, WalkResult[] results)
        {
            report.Report("indexing cross-references", 0, 0);
            var sources = _sources;
            var functions = new NativeFunction[starts.Length];
            var exportNames = FunctionNames(image);
            int totalRanges = results.Sum(r => r.RangeStarts.Length);
            var rangeStarts = new uint[totalRanges];
            var rangeEnds = new uint[totalRanges];
            int next = 0;
            long instructions = 0, blocks = 0, xrefCount = 0;
            int unresolved = 0, invalid = 0, thunks = 0, noReturn = 0;
            for (int i = 0; i < starts.Length; i++)
            {
                var r = results[i];
                var f = new NativeFunction { Start = starts[i], Index = i, Sources = sources[starts[i]], Flags = r.Flags, FirstRange = next, RangeCount = r.RangeStarts.Length };
                Array.Copy(r.RangeStarts, 0, rangeStarts, next, r.RangeStarts.Length);
                Array.Copy(r.RangeEnds, 0, rangeEnds, next, r.RangeEnds.Length);
                next += r.RangeStarts.Length;
                uint size = 0, end = f.Start;
                for (int k = 0; k < r.RangeStarts.Length; k++) { size += r.RangeEnds[k] - r.RangeStarts[k]; end = Math.Max(end, r.RangeEnds[k]); }
                f.Size = size;
                f.End = end;
                f.BlockCount = r.Blocks;
                f.InstructionCount = r.Instructions;
                if (_ctx.NoReturn.Contains(f.Start)) { f.Flags |= FunctionFlags.NoReturn; noReturn++; }
                if (_ctx.Funclets.Contains(f.Start)) f.Flags |= FunctionFlags.Funclet;
                if (_ctx.ArmModes?.IsUnsure(f.Start) == true) f.Flags |= FunctionFlags.StateGuessed;
                if (_ctx.Thunks.TryGetValue(f.Start, out var slot) && _ctx.ImportSlots.TryGetValue(slot, out var imp))
                {
                    f.Flags |= FunctionFlags.Thunk;
                    f.ThunkImport = imp;
                    f.KnownName = "j_" + (imp.Name ?? $"{Path.GetFileNameWithoutExtension(imp.Module)}_{imp.Ordinal}");
                    thunks++;
                }
                if (exportNames.TryGetValue(f.Start, out var exportName)) f.KnownName = exportName;
                if ((r.Flags & FunctionFlags.UnresolvedJumps) != 0) unresolved++;
                if ((r.Flags & FunctionFlags.InvalidCode) != 0) invalid++;
                instructions += r.Instructions;
                blocks += r.Blocks;
                xrefCount += r.Xrefs.Length;
                functions[i] = f;
            }
            ct.ThrowIfCancellationRequested();
            if (results.Any(r => (r.Flags & FunctionFlags.Truncated) != 0))
                AddTruncation($"functions over {options.MaxInstructionsPerFunction} instructions are cut ({results.Count(r => (r.Flags & FunctionFlags.Truncated) != 0)})");

            var functionCode = new CodeCover(rangeStarts, rangeEnds);
            var xrefs = CollectXrefs(results, xrefCount, functionCode);
            var strings = FindStrings(xrefs, functionCode);
            int switches = 0;
            foreach (var r in results) foreach (var x in r.Xrefs) if (x.Kind == XrefKind.JumpTable) switches++;
            var stats = new CodeIndexStats(functions.Length, thunks, noReturn, instructions, blocks, xrefs.Length, strings.Length,
                switches, unresolved, invalid, _passes, _rounds, _sw.Elapsed);
            report.Done();
            return new NativeCodeIndex(image, CodeSupport.Full, null, _ctx, functions, rangeStarts, rangeEnds, xrefs, strings, _truncations, stats);
        }

        /// <summary>
        /// Go functions whose decoded code runs past the end their own pc-value tables give. Walks ending short are not
        /// listed: trailing padding, literal pools and code after noreturn calls are in the table's extent only.
        /// </summary>
        private List<string> GoExtentIssues(NativeCodeIndex index)
        {
            if (Go.GoFunctionTable.Of(image) is not { } go) return [];
            var over = new List<(uint Rva, string? Name)>();
            var fs = go.Functions;
            for (int i = 0; i < fs.Count; i++)
            {
                var g = fs[i];
                if (!g.OwnSize || index.FunctionByStart(g.Rva) is not { } f) continue;
                // code between its own end and the next function: blocks shared with other functions elsewhere do not count
                uint end = g.Rva + g.Size, next = i + 1 < fs.Count ? fs[i + 1].Rva : uint.MaxValue;
                if (index.Ranges(f).Any(r => r.End > end && r.Start < next)) over.Add((g.Rva, g.Name));
            }
            if (over.Count == 0) return [];
            string first = string.Join(", ", over.Take(3).Select(o => $"{o.Name ?? "?"} at 0x{o.Rva:X}"));
            return [$"Go function table: {over.Count} of {go.Functions.Count} functions decode past their own end ({first}{(over.Count > 3 ? ", ..." : "")})"];
        }

        /// <summary>All walk cross-references plus relocated data pointers, sorted by (From, To, Kind), duplicates removed.</summary>
        private CodeXref[] CollectXrefs(WalkResult[] results, long fromWalks, CodeCover functionCode)
        {
            long total = fromWalks;
            var pointers = new List<CodeXref>();
            int i = 0;
            foreach (var reloc in _ctx.Relocations)
            {
                if ((++i & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
                // inside decoded functions a relocation is an instruction operand, already a cross-reference
                if (_ctx.Code.IsCode(reloc) && functionCode.Contains(reloc)) continue;
                if (!_ctx.TryReadPointer(reloc, out uint target)) continue;
                // 32-bit ARM: a Thumb code pointer points one byte past its function
                if (_ctx.ArmModes != null && (target & 1) != 0 && _ctx.Code.IsCode(target)) target &= ~1u;
                pointers.Add(new CodeXref(reloc, target, XrefKind.Pointer));
            }
            // no relocations (PointersUnconfirmed): runs of at least two values that are function starts. A value merely
            // inside code is too often a small integer or an offset where the image base is low. A Go function table lists
            // every Go function: other starts found only through such values, or inside a declared function, are not believed.
            bool go = Go.GoFunctionTable.Of(image) != null;
            var starts = new Dictionary<uint, uint>();
            foreach (var (slot, value) in _ctx.UnrelocatedPointers())
            {
                uint target = _ctx.ArmModes != null ? value & ~1u : value;
                if (_sources.TryGetValue(target, out var source) && (!go || (source & ~(FunctionSource.DataPointer | FunctionSource.CodeAddress)) != 0) && !_ctx.InsideDeclared(target))
                    starts[slot] = target;
            }
            uint size = (uint)_ctx.PointerSize;
            foreach (var (slot, target) in starts)
                if (starts.ContainsKey(slot - size) || starts.ContainsKey(slot + size)) pointers.Add(new CodeXref(slot, target, XrefKind.Pointer));
            total += pointers.Count;
            if (total > options.MaxXrefs)
            {
                AddTruncation($"cross-reference limit {options.MaxXrefs} reached ({total} found)");
                total = options.MaxXrefs;
            }
            var all = new CodeXref[total];
            var keys = new ulong[total];
            int n = 0;
            foreach (var r in results)
                foreach (var x in r.Xrefs)
                {
                    if (n >= total) break;
                    all[n] = x;
                    keys[n++] = (ulong)x.From << 32 | x.To;
                }
            foreach (var x in pointers)
            {
                if (n >= total) break;
                all[n] = x;
                keys[n++] = (ulong)x.From << 32 | x.To;
            }
            ct.ThrowIfCancellationRequested();
            Array.Sort(keys, all, 0, n);
            int w = 0;
            for (int k = 0; k < n; k++)
            {
                if (w > 0 && all[w - 1] == all[k]) continue;
                // same (From, To) with different kinds: keep each kind once
                bool dup = false;
                for (int j = w - 1; j >= 0 && all[j].From == all[k].From && all[j].To == all[k].To; j--)
                    if (all[j].Kind == all[k].Kind) { dup = true; break; }
                if (!dup) all[w++] = all[k];
            }
            Array.Resize(ref all, w);
            return all;
        }

        /// <summary>
        /// Strings at data addresses that code reads or takes, or that relocated pointers point at; in executable
        /// sections (data merged into code) only outside the decoded functions.
        /// </summary>
        private StringLiteral[] FindStrings(CodeXref[] xrefs, CodeCover functionCode)
        {
            report.Report("finding strings", 0, 0);
            var targets = new HashSet<uint>();
            foreach (var x in xrefs)
                if (x.Kind is XrefKind.Read or XrefKind.Address or XrefKind.Pointer && (!_ctx.Code.IsCode(x.To) || !functionCode.Contains(x.To))) targets.Add(x.To);
            var sorted = targets.ToArray();
            Array.Sort(sorted);
            var buffer = new byte[(options.MaxStringLength + 1) * 2];
            var result = new List<StringLiteral>();
            int i = 0;
            foreach (var t in sorted)
            {
                if ((++i & 0x3FFF) == 0) { ct.ThrowIfCancellationRequested(); report.Report("finding strings", i, sorted.Length); }
                if (StringDetector.Detect(image, t, options.MaxStringLength, buffer) is { } s) result.Add(s);
            }
            return result.ToArray();
        }
    }
}
