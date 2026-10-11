using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Native.Diff;

/// <summary>Options of <see cref="BuildMatcher"/>.</summary>
public sealed record MatchOptions
{
    /// <summary>Match on names from non-discovered sources (exports, PDB, user, Il2Cpp); thunks always match by their import.</summary>
    public bool UseNames { get; init; } = true;
    /// <summary>Least similarity a fuzzy match needs.</summary>
    public double MinScore { get; init; } = 0.7;
    /// <summary>Least lead of a fuzzy match over the runner-up, on both sides.</summary>
    public double Margin { get; init; } = 0.05;
    /// <summary>Least similarity of neighbors paired by call-graph propagation.</summary>
    public double NeighborScore { get; init; } = 0.5;
    /// <summary>Cap on similarity computations of the fuzzy tier (per round).</summary>
    public long MaxFuzzyComparisons { get; init; } = 40_000_000;

    public string Key => $"{UseNames}|{MinScore:R}|{Margin:R}|{NeighborScore:R}|{MaxFuzzyComparisons}";
}

/// <summary>A matched pair: indexes into the old and new prints, the tier (1-5), what matched, and the similarity.</summary>
public sealed record FunctionMatch(int Old, int New, int Tier, string Basis, double Score)
{
    /// <summary>How far an address mapping through this pair can be trusted (0-1).</summary>
    public double Confidence => Tier switch
    {
        1 => 1.0,
        2 => 0.95,
        3 => 0.9,
        4 => Math.Min(0.9, 0.5 + Score / 2),
        _ => Math.Min(0.85, Score),
    };
}

/// <summary>A function left unmatched because several candidates fit equally well.</summary>
public sealed record AmbiguousFunction(bool OldSide, int Index, string Reason, IReadOnlyList<(int Index, double Score)> Candidates);

/// <summary>The outcome of matching two builds.</summary>
public sealed class MatchResult
{
    public static readonly string[] TierNames = ["", "name_or_bytes", "structure", "signature", "call_graph", "fuzzy"];

    public required ImagePrints Old { get; init; }
    public required ImagePrints New { get; init; }
    public required MatchOptions Options { get; init; }
    public required FunctionMatch?[] ByOld { get; init; }
    public required FunctionMatch?[] ByNew { get; init; }
    public required List<FunctionMatch> Pairs { get; init; }
    public required Dictionary<(bool OldSide, int Index), AmbiguousFunction> Ambiguous { get; init; }
    /// <summary>Best similarity seen for an unmatched function (below the threshold), for unmatched reasons.</summary>
    public required Dictionary<(bool OldSide, int Index), double> BestSeen { get; init; }
    public required List<string> Notes { get; init; }
    public TimeSpan Elapsed { get; init; }

    public FunctionMatch? ForOldStart(uint start) => Old.ByStart.TryGetValue(start, out var i) ? ByOld[i] : null;
}

/// <summary>
/// Matches the functions of two builds of one image in tiers; each tier accepts a pair only when it is unique on both
/// sides among the functions still unmatched: (1) the same name from a non-discovered source, the same import for
/// thunks, or identical bytes after masking addresses; (2) the same canonical graph with the same instruction shapes;
/// (3) the same imports, strings and constants; (4) call-graph propagation from matched pairs to callees in the same
/// position, to mutually best callers / callees, by callers and callees in common, and to the same slot of matched tables
/// of function pointers (vtables), to a fixed point; (5) fuzzy similarity above a threshold with a
/// margin over the runner-up on both sides. Tiers 4 and 5 alternate until nothing changes; then identical code between matched
/// neighbors pairs by its place (tier 4).
/// </summary>
public sealed class BuildMatcher
{
    private readonly ImagePrints _old, _new;
    private readonly FunctionPrint[] _o, _n;
    private readonly MatchOptions _options;
    private readonly FunctionMatch?[] _byOld, _byNew;
    private readonly List<FunctionMatch> _pairs = [];
    private readonly Dictionary<(bool, int), AmbiguousFunction> _ambiguous = [];
    private readonly Dictionary<(bool, int), double> _bestSeen = [];
    private readonly List<string> _notes = [];
    private readonly CancellationToken _ct;
    private readonly Queue<FunctionMatch> _propagate = new();

    private BuildMatcher(ImagePrints old, ImagePrints @new, MatchOptions options, CancellationToken ct)
    {
        _old = old; _new = @new; _o = old.Functions; _n = @new.Functions; _options = options; _ct = ct;
        _byOld = new FunctionMatch?[_o.Length];
        _byNew = new FunctionMatch?[_n.Length];
    }

    public static MatchResult Match(ImagePrints old, ImagePrints @new, MatchOptions options, CancellationToken ct)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var m = new BuildMatcher(old, @new, options, ct);
        m.Run();
        return new MatchResult
        {
            Old = old, New = @new, Options = options, ByOld = m._byOld, ByNew = m._byNew, Pairs = m._pairs,
            Ambiguous = m._ambiguous.Where(kv => kv.Key.Item1 ? m._byOld[kv.Key.Item2] == null : m._byNew[kv.Key.Item2] == null)
                .ToDictionary(kv => kv.Key, kv => kv.Value),
            BestSeen = m._bestSeen, Notes = m._notes, Elapsed = sw.Elapsed,
        };
    }

    private void Run()
    {
        // tier 1
        UniqueKey(p => p.ThunkImport is { } t ? "thunk:" + t : null, 1, "import_thunk", null);
        if (_options.UseNames)
        {
            // each source on its own, so a user rename on one side does not hide the export or PDB name both share
            var oldExports = Exports(_old.Index);
            var newExports = Exports(_new.Index);
            UniqueKey(p => oldExports.GetValueOrDefault(p.Start), q => newExports.GetValueOrDefault(q.Start), 1, "name", null);
            foreach (var source in new[] { NativeNameSource.Pdb, NativeNameSource.NativeAot, NativeNameSource.Il2Cpp, NativeNameSource.User })
                UniqueKey(p => _old.Index.Sourced.NameAt(p.Start, source), q => _new.Index.Sourced.NameAt(q.Start, source), 1, "name", null);
        }
        UniqueKey(p => p.Failed || p.Instructions < 2 ? null : p.BytesHash, 1, "identical_bytes", "identical_code");
        // tier 2
        UniqueKey(p => p.Failed || p.Instructions < 3 ? null : p.StructHash, 2, "structure", "same_structure",
            (o, n) => Similarity(o, n) >= 0.6);
        // tier 3: needs a meaningful signature and a compatible shape
        UniqueKey(p => p.Failed || p.SignatureItems == 0 || (p.SignatureItems < 2 && p.Strings.Length == 0) ? null : p.SignatureHash, 3, "signature", "same_signature",
            (o, n) => Similarity(o, n) >= _options.NeighborScore);
        // tiers 4 and 5
        for (int round = 0; round < 4; round++)
        {
            _ct.ThrowIfCancellationRequested();
            foreach (var p in _pairs) _propagate.Enqueue(p);
            PropagateAll();
            if (Fuzzy() == 0) break;
        }
        PropagateAll();
        if (Sequence() > 0) PropagateAll();
    }

    /// <summary>
    /// Pairs the unmatched functions between two matched neighbors that moved by the same distance with the unmatched
    /// functions at that distance in the new build, when their code is identical or the same shape: identical copies
    /// (templates, folded helpers) no other tier tells apart keep their place in the layout.
    /// </summary>
    private int Sequence()
    {
        var order = Enumerable.Range(0, _o.Length).OrderBy(i => _o[i].Start).ToArray();
        int accepted = 0, prev = -1;
        for (int k = 0; k < order.Length; k++)
        {
            if (_byOld[order[k]] == null) continue;
            if (prev >= 0 && k - prev > 1)
            {
                long before = Shift(order[prev]), after = Shift(order[k]);
                if (before == after)
                    for (int g = prev + 1; g < k; g++)
                    {
                        int o = order[g];
                        long at = _o[o].Start + before;
                        if (at is < 0 or > uint.MaxValue || !_new.ByStart.TryGetValue((uint)at, out var n) || _byNew[n] != null) continue;
                        bool same = !_o[o].Failed && !_n[n].Failed && _o[o].Size == _n[n].Size
                                    && (_o[o].BytesHash == _n[n].BytesHash || _o[o].StructHash == _n[n].StructHash);
                        if (same && Accept(o, n, 4, "address_sequence", Similarity(o, n))) accepted++;
                    }
            }
            prev = k;
        }
        return accepted;
    }

    private long Shift(int o) => (long)_n[_byOld[o]!.New].Start - _o[o].Start;

    /// <summary>Propagation and context votes, alternated until neither adds a pair.</summary>
    private void PropagateAll()
    {
        for (int round = 0; round < 16; round++)
        {
            Propagate();
            if (Context() + TableSlots() == 0) break;
        }
    }

    private static Dictionary<uint, string> Exports(NativeCodeIndex index)
    {
        var result = new Dictionary<uint, string>();
        foreach (var e in index.Image.Exports)
            if (e.Name != null && e.ForwardedTo == null) result.TryAdd(e.Rva, e.Name);
        return result;
    }

    private bool Accept(int o, int n, int tier, string basis, double score)
    {
        if (_byOld[o] != null || _byNew[n] != null) return false;
        var m = new FunctionMatch(o, n, tier, basis, Math.Round(score, 3));
        _byOld[o] = m;
        _byNew[n] = m;
        _pairs.Add(m);
        _propagate.Enqueue(m);
        return true;
    }

    private void UniqueKey(Func<FunctionPrint, object?> key, int tier, string basis, string? ambiguousReason, Func<int, int, bool>? check = null) =>
        UniqueKey(key, key, tier, basis, ambiguousReason, check);

    private void UniqueKey(Func<FunctionPrint, object?> oldKey, Func<FunctionPrint, object?> newKey, int tier, string basis, string? ambiguousReason,
        Func<int, int, bool>? check = null)
    {
        var olds = Group(_o, _byOld, oldKey);
        var news = Group(_n, _byNew, newKey);
        foreach (var (k, os) in olds)
        {
            _ct.ThrowIfCancellationRequested();
            if (!news.TryGetValue(k, out var ns)) continue;
            if (os.Count == 1 && ns.Count == 1)
            {
                if (check == null || check(os[0], ns[0])) Accept(os[0], ns[0], tier, basis, tier == 1 ? 1.0 : Similarity(os[0], ns[0]));
            }
            else if (ambiguousReason != null && os.Count <= 16 && ns.Count <= 16)
            {
                foreach (var o in os) _ambiguous.TryAdd((true, o), new AmbiguousFunction(true, o, ambiguousReason, ns.Select(n => (n, 1.0)).ToList()));
                foreach (var n in ns) _ambiguous.TryAdd((false, n), new AmbiguousFunction(false, n, ambiguousReason, os.Select(o => (o, 1.0)).ToList()));
            }
        }
    }

    private static Dictionary<object, List<int>> Group(FunctionPrint[] prints, FunctionMatch?[] matched, Func<FunctionPrint, object?> key)
    {
        var groups = new Dictionary<object, List<int>>();
        for (int i = 0; i < prints.Length; i++)
        {
            if (matched[i] != null || key(prints[i]) is not { } k) continue;
            if (!groups.TryGetValue(k, out var list)) groups[k] = list = [];
            list.Add(i);
        }
        return groups;
    }

    // ---- tier 4: call-graph propagation ----

    private void Propagate()
    {
        while (_propagate.Count > 0)
        {
            _ct.ThrowIfCancellationRequested();
            var pair = _propagate.Dequeue();
            var (o, n) = (_o[pair.Old], _n[pair.New]);
            CalleePositions(o.Callees, n.Callees);
            Neighbors(o.Callees, n.Callees, "callee");
            Neighbors(o.Callers, n.Callers, "caller");
        }
    }

    /// <summary>
    /// Callees in the same position: matched callees that keep their order are anchors, and between two anchors (or
    /// the list ends) gaps of equal length are paired one for one when compatible.
    /// </summary>
    private void CalleePositions(int[] olds, int[] news)
    {
        if (olds.Length == 0 || news.Length == 0) return;
        var where = new Dictionary<int, int>(news.Length);
        for (int j = 0; j < news.Length; j++) where.TryAdd(news[j], j);
        var anchors = new List<(int I, int J)>();
        for (int i = 0; i < olds.Length; i++)
            if (_byOld[olds[i]] is { } m && where.TryGetValue(m.New, out var j)) anchors.Add((i, j));
        var chain = InstructionAlignment.IncreasingChain(anchors);
        int pi = -1, pj = -1;
        foreach (var (i, j) in chain.Append((olds.Length, news.Length)))
        {
            if (i - pi == j - pj)
                for (int k = 1; k < i - pi; k++)
                {
                    int a = olds[pi + k], b = news[pj + k];
                    if (_byOld[a] == null && _byNew[b] == null && Similarity(a, b) is var s && s >= _options.NeighborScore)
                        Accept(a, b, 4, "callee_position", s);
                }
            pi = i; pj = j;
        }
    }

    /// <summary>
    /// Context votes: an unmatched function gets a vote for each unmatched function of the other build that is called by
    /// the counterpart of one of its callers, or calls the counterpart of one of its callees. Mutually best candidates
    /// with a clear lead and a compatible shape are paired (this separates identical copies by where they are used).
    /// </summary>
    private int Context()
    {
        var votes = new Dictionary<(int O, int N), int>();
        for (int o = 0; o < _o.Length; o++)
        {
            if (_byOld[o] != null) continue;
            if ((o & 0xFFF) == 0) _ct.ThrowIfCancellationRequested();
            foreach (var c in _o[o].Callers)
                if (_byOld[c] is { } m)
                    foreach (var n in _n[m.New].Callees.Take(256))
                        if (_byNew[n] == null) votes[(o, n)] = votes.GetValueOrDefault((o, n)) + 1;
            foreach (var d in _o[o].Callees)
                if (_byOld[d] is { } m)
                    foreach (var n in _n[m.New].Callers.Take(256))
                        if (_byNew[n] == null) votes[(o, n)] = votes.GetValueOrDefault((o, n)) + 1;
        }
        if (votes.Count == 0) return 0;
        var bestOld = new Dictionary<int, (int N, int V1, int V2)>();
        var bestNew = new Dictionary<int, (int O, int V1, int V2)>();
        foreach (var ((o, n), v) in votes)
        {
            var bo = bestOld.TryGetValue(o, out var x) ? x : (N: -1, V1: 0, V2: 0);
            bestOld[o] = v > bo.V1 ? (n, v, bo.V1) : (bo.N, bo.V1, Math.Max(bo.V2, v));
            var bn = bestNew.TryGetValue(n, out var y) ? y : (O: -1, V1: 0, V2: 0);
            bestNew[n] = v > bn.V1 ? (o, v, bn.V1) : (bn.O, bn.V1, Math.Max(bn.V2, v));
        }
        int accepted = 0;
        foreach (var (o, (n, v1, v2)) in bestOld)
        {
            var bn = bestNew[n];
            if (v1 <= v2 || bn.O != o || bn.V1 <= bn.V2) continue;
            double s = Similarity(o, n);
            if (s >= (v1 >= 2 ? _options.NeighborScore : 0.75) && Accept(o, n, 4, "context", s)) accepted++;
        }
        return accepted;
    }

    // ---- tables of function pointers (vtables, dispatch tables) ----

    private sealed record PointerTable(uint Start, int[] Slots);
    private (List<PointerTable> Tables, Dictionary<uint, (int Table, int Slot)> At)? _oldTables, _newTables;

    /// <summary>Runs of consecutive relocated pointers to function starts in data.</summary>
    private static (List<PointerTable>, Dictionary<uint, (int, int)>) Tables(ImagePrints prints, CancellationToken ct)
    {
        var index = prints.Index;
        uint size = index.Image.Is64Bit ? 8u : 4u;
        var slots = new SortedDictionary<uint, int>();
        foreach (var p in prints.Functions)
        {
            if ((p.Index & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            foreach (var x in index.RefsTo(p.Start, 4096))
                if (x.Kind == XrefKind.Pointer) slots.TryAdd(x.From, p.Index);
        }
        var tables = new List<PointerTable>();
        var at = new Dictionary<uint, (int, int)>();
        var run = new List<int>();
        uint start = 0, next = 0;
        void Close()
        {
            if (run.Count >= 2)
            {
                for (int k = 0; k < run.Count; k++) at[start + (uint)k * size] = (tables.Count, k);
                tables.Add(new PointerTable(start, run.ToArray()));
            }
            run.Clear();
        }
        foreach (var (loc, fn) in slots)
        {
            if (run.Count == 0 || loc != next) { Close(); start = loc; }
            run.Add(fn);
            next = loc + size;
        }
        Close();
        return (tables, at);
    }

    /// <summary>
    /// Tables of function pointers matched by the matched functions in their slots (votes for a new table and a slot
    /// offset); unmatched functions in the same slot of matched tables are paired when compatible.
    /// </summary>
    private int TableSlots()
    {
        _oldTables ??= Tables(_old, _ct);
        _newTables ??= Tables(_new, _ct);
        var (oldTables, _) = _oldTables.Value;
        var (newTables, newAt) = _newTables.Value;
        if (oldTables.Count == 0 || newTables.Count == 0) return 0;
        uint size = _new.Index.Image.Is64Bit ? 8u : 4u;
        int accepted = 0;
        foreach (var t in oldTables)
        {
            _ct.ThrowIfCancellationRequested();
            if (t.Slots.All(f => _byOld[f] != null)) continue;
            var votes = new Dictionary<(int Table, int Delta), int>();
            for (int k = 0; k < t.Slots.Length; k++)
            {
                if (_byOld[t.Slots[k]] is not { } m) continue;
                foreach (var x in _new.Index.RefsTo(_n[m.New].Start, 256))
                    if (x.Kind == XrefKind.Pointer && newAt.TryGetValue(x.From, out var slot))
                        votes[(slot.Table, slot.Slot - k)] = votes.GetValueOrDefault((slot.Table, slot.Slot - k)) + 1;
            }
            if (votes.Count == 0) continue;
            var ranked = votes.OrderByDescending(v => v.Value).Take(2).ToList();
            if (ranked[0].Value < 2 || (ranked.Count > 1 && ranked[1].Value * 2 > ranked[0].Value)) continue;
            var (table, delta) = ranked[0].Key;
            var target = newTables[table];
            for (int k = 0; k < t.Slots.Length; k++)
            {
                int j = k + delta;
                if (j < 0 || j >= target.Slots.Length) continue;
                int a = t.Slots[k], b = target.Slots[j];
                if (_byOld[a] == null && _byNew[b] == null && Similarity(a, b) is var s && s >= _options.NeighborScore && Accept(a, b, 4, "table_slot", s))
                    accepted++;
            }
        }
        return accepted;
    }

    /// <summary>Pairs unmatched neighbors that are each other's best candidate by a margin.</summary>
    private void Neighbors(int[] olds, int[] news, string basis)
    {
        var os = olds.Where(a => _byOld[a] == null).Distinct().Take(64).ToList();
        var ns = news.Where(b => _byNew[b] == null).Distinct().Take(64).ToList();
        if (os.Count == 0 || ns.Count == 0) return;
        var scores = new double[os.Count, ns.Count];
        for (int i = 0; i < os.Count; i++)
            for (int j = 0; j < ns.Count; j++) scores[i, j] = Similarity(os[i], ns[j]);
        for (int i = 0; i < os.Count; i++)
        {
            int best = -1; double s1 = 0, s2 = 0;
            for (int j = 0; j < ns.Count; j++)
            {
                if (scores[i, j] > s1) { s2 = s1; s1 = scores[i, j]; best = j; }
                else if (scores[i, j] > s2) s2 = scores[i, j];
            }
            if (best < 0 || s1 < _options.NeighborScore || s1 - s2 < 0.1) continue;
            double r2 = 0;
            bool mutual = true;
            for (int k = 0; k < os.Count; k++)
            {
                if (k == i) continue;
                if (scores[k, best] >= s1) { mutual = false; break; }
                r2 = Math.Max(r2, scores[k, best]);
            }
            if (mutual && s1 - r2 >= 0.1) Accept(os[i], ns[best], 4, basis, s1);
        }
    }

    // ---- tier 5: fuzzy similarity ----

    private int Fuzzy()
    {
        var olds = Enumerable.Range(0, _o.Length).Where(i => _byOld[i] == null && !_o[i].Failed && _o[i].Instructions >= 3).ToList();
        var news = Enumerable.Range(0, _n.Length).Where(j => _byNew[j] == null && !_n[j].Failed && _n[j].Instructions >= 3)
            .OrderBy(j => _n[j].Instructions).ToArray();
        if (olds.Count == 0 || news.Length == 0) return 0;
        var counts = news.Select(j => _n[j].Instructions).ToArray();
        var oldTop = new Dictionary<int, List<(int, double)>>();
        var newBest = new Dictionary<int, (int Old, double S1, double S2)>();
        long comparisons = 0;
        bool capped = false;
        foreach (var o in olds)
        {
            _ct.ThrowIfCancellationRequested();
            int c = _o[o].Instructions;
            int lo = LowerBound(counts, (int)Math.Floor(c * 0.6));
            int hi = LowerBound(counts, (int)Math.Ceiling(c / 0.6) + 1);
            var top = new List<(int, double)>(4);
            for (int k = lo; k < hi; k++)
            {
                if (++comparisons > _options.MaxFuzzyComparisons) { capped = true; break; }
                int n = news[k];
                double s = Similarity(o, n);
                if (s < 0.3) continue;
                Insert(top, (n, s));
                var nb = newBest.GetValueOrDefault(n, (-1, 0, 0));
                if (s > nb.S1) newBest[n] = (o, s, nb.S1);
                else if (s > nb.S2) newBest[n] = nb with { S2 = s };
            }
            if (top.Count > 0) oldTop[o] = top;
            if (capped) break;
        }
        if (capped) _notes.Add($"fuzzy matching stopped after {_options.MaxFuzzyComparisons:N0} comparisons; some unmatched functions were not compared");

        int accepted = 0;
        foreach (var (o, top) in oldTop)
        {
            var (n, s1) = top[0];
            double s2 = top.Count > 1 ? top[1].Item2 : 0;
            _bestSeen[(true, o)] = Math.Max(_bestSeen.GetValueOrDefault((true, o)), s1);
            if (s1 < _options.MinScore) continue;
            var nb = newBest[n];
            if (s1 - s2 >= _options.Margin && nb.Old == o && nb.S1 - nb.S2 >= _options.Margin)
            {
                if (Accept(o, n, 5, "fuzzy", s1)) accepted++;
            }
            else
                _ambiguous[(true, o)] = new AmbiguousFunction(true, o, "close_scores", top.Take(3).ToList());
        }
        foreach (var (n, nb) in newBest) _bestSeen[(false, n)] = Math.Max(_bestSeen.GetValueOrDefault((false, n)), nb.S1);
        return accepted;
    }

    private static void Insert(List<(int, double)> top, (int, double) item)
    {
        int at = top.Count;
        while (at > 0 && top[at - 1].Item2 < item.Item2) at--;
        if (at >= 3) return;
        top.Insert(at, item);
        if (top.Count > 3) top.RemoveAt(3);
    }

    private static int LowerBound(int[] sorted, int value)
    {
        int lo = 0, hi = sorted.Length;
        while (lo < hi) { int mid = (lo + hi) >>> 1; if (sorted[mid] < value) lo = mid + 1; else hi = mid; }
        return lo;
    }

    /// <summary>Similarity (0-1) of old print <paramref name="o"/> and new print <paramref name="n"/>, using the current matches for the call graph.</summary>
    public double Similarity(int o, int n) => Similarity(_o[o], _n[n], _byOld, _byNew);

    public static double Similarity(FunctionPrint a, FunctionPrint b, FunctionMatch?[]? byOld = null, FunctionMatch?[]? byNew = null)
    {
        if (a.Failed || b.Failed) return 0;
        if (a.ThunkImport != null || b.ThunkImport != null) return a.ThunkImport == b.ThunkImport ? 1 : 0;
        double sum = 0, weight = 0;
        void Add(double value, double w) { sum += value * w; weight += w; }
        Add(Histogram(a, b), 3);
        Add(Ratio(a.Instructions, b.Instructions), 1);
        Add(Ratio(a.Size, b.Size), 1);
        Add(Ratio(a.Blocks, b.Blocks), 1);
        Add(Ratio(a.Edges, b.Edges), 0.5);
        Add(a.BackEdges == b.BackEdges ? 1 : 0, 0.5);
        Add(a.GraphHash == b.GraphHash ? 1 : 0, 1);
        Add(Ratio(a.Callees.Length, b.Callees.Length), 0.5);
        if (a.Imports.Length + b.Imports.Length > 0) Add(Jaccard(a.Imports, b.Imports, string.CompareOrdinal), 1.5);
        if (a.Strings.Length + b.Strings.Length > 0) Add(Jaccard(a.Strings, b.Strings, string.CompareOrdinal), 2);
        if (a.Constants.Length + b.Constants.Length > 0) Add(Jaccard(a.Constants, b.Constants, (x, y) => x.CompareTo(y)), 1.5);
        if (byOld != null && byNew != null)
        {
            var (agree, known) = Neighbors(a.Callees, b.Callees, byOld);
            var (agree2, known2) = Neighbors(a.Callers, b.Callers, byOld);
            if (known + known2 > 0) Add((double)(agree + agree2) / (known + known2), 2);
        }
        return weight == 0 ? 0 : sum / weight;
    }

    private static (int Agree, int Known) Neighbors(int[] olds, int[] news, FunctionMatch?[] byOld)
    {
        int agree = 0, known = 0;
        foreach (var a in olds)
        {
            if (byOld[a] is not { } m) continue;
            known++;
            if (Array.IndexOf(news, m.New) >= 0) agree++;
        }
        return (agree, known);
    }

    private static double Ratio(double a, double b) => a == b ? 1 : Math.Min(a, b) / Math.Max(a, b);

    private static double Histogram(FunctionPrint a, FunctionPrint b)
    {
        int i = 0, j = 0;
        long min = 0, max = 0;
        while (i < a.MnemonicKeys.Length || j < b.MnemonicKeys.Length)
        {
            if (j >= b.MnemonicKeys.Length || (i < a.MnemonicKeys.Length && a.MnemonicKeys[i] < b.MnemonicKeys[j])) max += a.MnemonicCounts[i++];
            else if (i >= a.MnemonicKeys.Length || b.MnemonicKeys[j] < a.MnemonicKeys[i]) max += b.MnemonicCounts[j++];
            else
            {
                min += Math.Min(a.MnemonicCounts[i], b.MnemonicCounts[j]);
                max += Math.Max(a.MnemonicCounts[i], b.MnemonicCounts[j]);
                i++; j++;
            }
        }
        return max == 0 ? 1 : (double)min / max;
    }

    private static double Jaccard<T>(T[] a, T[] b, Comparison<T> compare)
    {
        int i = 0, j = 0, both = 0;
        while (i < a.Length && j < b.Length)
        {
            int c = compare(a[i], b[j]);
            if (c == 0) { both++; i++; j++; }
            else if (c < 0) i++;
            else j++;
        }
        int union = a.Length + b.Length - both;
        return union == 0 ? 1 : (double)both / union;
    }
}
