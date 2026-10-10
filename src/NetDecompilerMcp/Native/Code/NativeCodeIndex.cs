using System.Collections.Concurrent;
using System.Diagnostics;

namespace NetDecompilerMcp.Native.Code;

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
public sealed class NativeCodeIndex : ICodeSymbols
{
    private readonly CodeContext? _ctx;
    private readonly NativeFunction[] _functions;
    private readonly Dictionary<uint, NativeFunction> _byStart;
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
    public CodeIndexStats Stats { get; }
    /// <summary>Relocations in an x86 image are missing, so absolute operands were accepted by range alone.</summary>
    public bool AbsoluteRefsUnconfirmed { get; }

    private NativeCodeIndex(INativeImage image, CodeSupport support, string? note, CodeContext? ctx, NativeFunction[] functions,
        uint[] rangeStarts, uint[] rangeEnds, CodeXref[] xrefs, StringLiteral[] strings, List<string> truncations, CodeIndexStats stats)
    {
        Image = image;
        Support = support;
        SupportNote = note;
        _ctx = ctx;
        _functions = functions;
        _byStart = functions.ToDictionary(f => f.Start);
        _rangeStarts = rangeStarts;
        _rangeEnds = rangeEnds;
        _xrefs = xrefs;
        _strings = strings;
        Truncations = truncations;
        Stats = stats;
        AbsoluteRefsUnconfirmed = image.Arch == NativeArch.X86 && image.RelocationRvas.Count == 0;
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

        _byTo = new int[xrefs.Length];
        var keys = new ulong[xrefs.Length];
        for (int i = 0; i < xrefs.Length; i++)
        {
            _byTo[i] = i;
            keys[i] = (ulong)xrefs[i].To << 32 | xrefs[i].From;
        }
        Array.Sort(keys, _byTo);
    }

    /// <summary>Builds the index. Long-running for large images: run it on a background thread.</summary>
    public static NativeCodeIndex Build(INativeImage image, CodeIndexOptions? options = null, Action<CodeIndexProgress>? progress = null, CancellationToken ct = default)
    {
        options ??= new CodeIndexOptions();
        var report = new ProgressGate(progress);
        var (support, note) = InstructionSets.For(image.Arch);
        if (support != CodeSupport.Full) return DeclaredOnly(image, note, report);
        return new Builder(image, options, report, ct).Run();
    }

    public static Task<NativeCodeIndex> BuildAsync(INativeImage image, CodeIndexOptions? options = null, Action<CodeIndexProgress>? progress = null, CancellationToken ct = default) =>
        Task.Run(() => Build(image, options, progress, ct), ct);

    /// <summary>Instruction sets without a decoder: functions the image declares, no code analysis.</summary>
    private static NativeCodeIndex DeclaredOnly(INativeImage image, string? note, ProgressGate report)
    {
        var sw = Stopwatch.StartNew();
        var sources = new Dictionary<uint, FunctionSource>();
        void Add(uint rva, FunctionSource s) { if (image.SectionAt(rva) is { IsExecutable: true }) sources[rva] = sources.GetValueOrDefault(rva) | s; }
        foreach (var rf in image.RuntimeFunctions) Add(rf.BeginRva, FunctionSource.Pdata);
        foreach (var e in image.Exports) if (e.ForwardedTo == null) Add(e.Rva, FunctionSource.Export);
        if (image.EntryPointRva != 0) Add(image.EntryPointRva, FunctionSource.EntryPoint);
        foreach (var t in image.TlsCallbackRvas) Add(t, FunctionSource.TlsCallback);
        var ends = image.RuntimeFunctions.GroupBy(r => r.BeginRva).ToDictionary(g => g.Key, g => g.Max(r => r.EndRva));
        var functions = sources.OrderBy(kv => kv.Key).Select((kv, i) => new NativeFunction
        {
            Start = kv.Key, Sources = kv.Value, Index = i,
            End = ends.TryGetValue(kv.Key, out var end) && end > kv.Key ? end : kv.Key,
        }).ToArray();
        foreach (var f in functions) f.Size = f.End - f.Start;
        var exportNames = image.Exports.Where(e => e.ForwardedTo == null && e.Name != null).GroupBy(e => e.Rva).ToDictionary(g => g.Key, g => g.First().Name);
        foreach (var f in functions) if (exportNames.TryGetValue(f.Start, out var n)) f.KnownName = n;
        report.Done();
        var stats = new CodeIndexStats(functions.Length, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, sw.Elapsed);
        return new NativeCodeIndex(image, CodeSupport.DeclaredFunctionsOnly, note, null, functions, [], [], [], [], [], stats);
    }

    // ---- queries ----

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

    /// <summary>Calls and tail calls to <paramref name="f"/> (and, for a thunk, to its import), with the calling function.</summary>
    public List<CallSite> Callers(NativeFunction f)
    {
        var result = new List<CallSite>();
        foreach (var x in RefsTo(f.Start))
            if (x.Kind is XrefKind.Call or XrefKind.TailCall)
                result.Add(new CallSite(x.From, x.To, x.Kind, FunctionAt(x.From), f, null));
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

    /// <summary>Direct calls, tail calls and import calls made by <paramref name="f"/>, in address order.</summary>
    public List<CallSite> Callees(NativeFunction f)
    {
        var result = new List<CallSite>();
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
        return result;
    }

    /// <summary>
    /// Callers (<paramref name="callers"/> = true) or callees of <paramref name="root"/> to <paramref name="depth"/> levels,
    /// at most <paramref name="maxNodes"/> nodes; repeated functions are listed once and not expanded again.
    /// </summary>
    public CallTreeNode CallTree(NativeFunction root, int depth, bool callers, int maxNodes = 2000)
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
            var sites = callers ? Callers(n.Function) : Callees(n.Function);
            if (d >= depth) { if (sites.Count > 0) n.Truncated = true; continue; }
            var seenHere = new HashSet<(uint, bool)>();
            foreach (var s in sites)
            {
                var fn = callers ? s.Caller : s.Function;
                uint key = fn?.Start ?? s.Target;
                if (!seenHere.Add((key, fn != null))) continue;
                if (count >= maxNodes) { n.Truncated = true; break; }
                var child = new CallTreeNode { Function = fn, Import = callers ? null : s.Import, Address = callers ? s.From : s.Target };
                count++;
                n.Children.Add(child);
                if (fn == null) continue;
                if (!expanded.Add(fn.Start)) { child.Repeated = true; continue; }
                queue.Enqueue((child, d + 1));
            }
        }
        return node;
    }

    /// <summary>Basic blocks and edges of <paramref name="f"/> (decoded again on each call).</summary>
    public FunctionGraph GetGraph(NativeFunction f, CancellationToken ct = default)
    {
        if (_ctx == null) throw new NotSupportedException(SupportNote);
        var walker = new FunctionWalker(_ctx);
        return walker.Walk(f, f.Start, buildGraph: true, ct).Graph!;
    }

    /// <summary>Facts of the instruction at <paramref name="rva"/> (any mapped address), or null.</summary>
    public InstructionFacts? Decode(uint rva)
    {
        if (_ctx == null) return null;
        var d = new X86Decoder(Image, _ctx.Code, _ctx.Relocations);
        return d.DecodeMapped(rva, out var insn) ? NativeDisassembler.Facts(in insn) : null;
    }

    /// <summary>A disassembler that names targets through this index. Not thread-safe; create one per caller.</summary>
    public NativeDisassembler CreateDisassembler()
    {
        if (_ctx == null) throw new NotSupportedException(SupportNote);
        return new NativeDisassembler(Image, this, _ctx.Relocations);
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
        foreach (var b in graph.Blocks) labels[b.Start] = b.Start == f.Start ? f.Name : $"loc_{b.Start:X}";
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

    // User annotations (rename_native / comment_native), mirrored from the image's NativeAnnotations; names here win
    // over discovered names, and KnownName of the matching function is updated so list_functions and labels show them.
    private readonly Dictionary<uint, string> _userNames = new();
    private readonly Dictionary<uint, string> _userComments = new();
    private readonly Dictionary<uint, string?> _builtinNames = new();

    /// <summary>Applies a user name at a function start (null clears it, restoring the discovered name).</summary>
    public void SetUserName(uint rva, string? name)
    {
        lock (_userNames)
        {
            if (name == null) _userNames.Remove(rva);
            else _userNames[rva] = name;
            if (_byStart.TryGetValue(rva, out var f))
            {
                if (!_builtinNames.ContainsKey(rva)) _builtinNames[rva] = f.KnownName;
                f.KnownName = name ?? _builtinNames[rva];
            }
        }
    }

    public void SetUserComment(uint rva, string? text)
    {
        lock (_userComments)
        {
            if (string.IsNullOrEmpty(text)) _userComments.Remove(rva);
            else _userComments[rva] = text;
        }
    }

    /// <summary>Import "module!name" (or "module!#ordinal"), function name, or export name at <paramref name="rva"/>.</summary>
    public string? NameAt(uint rva)
    {
        lock (_userNames) if (_userNames.TryGetValue(rva, out var user)) return user;
        if (_imports.TryGetValue(rva, out var imp)) return ImportName(imp);
        if (_byStart.TryGetValue(rva, out var f)) return f.Name;
        return _exportNames.GetValueOrDefault(rva);
    }

    public string? CommentFor(uint rva)
    {
        lock (_userComments) if (_userComments.TryGetValue(rva, out var user)) return user;
        if (StringAt(rva) is not { } s) return null;
        const int max = 120;
        return (s.Encoding == StringEncoding.Utf16 ? "L" : "") + StringDetector.Quote(ReadString(s, max), s.Length > max);
    }

    public static string ImportName(NativeImport imp)
    {
        string module = imp.Module.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? imp.Module[..^4] : imp.Module;
        return imp.Name != null ? $"{module}!{imp.Name}" : $"{module}!#{imp.Ordinal}";
    }

    // ---- build ----

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

    private sealed class Builder(INativeImage image, CodeIndexOptions options, ProgressGate report, CancellationToken ct)
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
            return Assemble(starts, results);
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
                    byte first = region.Bytes[next - region.Rva];
                    if (first is 0xCC or 0x90 or 0x00) continue;
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
            var discovery = new FunctionDiscovery(_ctx, ct, n => report.Report("discovering functions", n, 0));
            _sources = discovery.Run();
            if (discovery.FunctionsTruncated) AddTruncation($"function limit {options.MaxFunctions} reached");
            var starts = _sources.Keys.ToArray();
            Array.Sort(starts);
            _ctx.FunctionStarts = new HashSet<uint>(starts);
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
                    if (!results[i].Returns && !_ctx.NoReturn.Contains(starts[i])) newly.Add(starts[i]);
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
            var exportNames = new Dictionary<uint, string>();
            foreach (var e in image.Exports)
                if (e.ForwardedTo == null && e.Name != null) exportNames.TryAdd(e.Rva, e.Name);
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
                if (_ctx.TryReadPointer(reloc, out uint target)) pointers.Add(new CodeXref(reloc, target, XrefKind.Pointer));
            }
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
