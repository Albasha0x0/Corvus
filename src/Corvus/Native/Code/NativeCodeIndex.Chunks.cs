using Corvus.Native.Msvc;

namespace Corvus.Native.Code;

/// <summary>
/// Code that belongs to a function but that its own flow does not reach: a catch block, unwind funclet, SEH filter,
/// __except / __finally block, catch continuation or x86 __ehhandler$ stub, found through exception metadata.
/// </summary>
public readonly record struct FunctionChunk(uint Start, MsvcEhChildKind Kind);

public sealed partial class NativeCodeIndex
{
    // chunk start -> the function it was attached to (the first when the linker folded a funclet shared by several)
    private readonly Dictionary<uint, NativeFunction> _chunkOwners = [];

    /// <summary>
    /// MSVC exception handling metadata of the image (x64: every .pdata frame with a language-specific handler; x86:
    /// frames installed by prologues). Empty for other architectures or when nothing decodes.
    /// </summary>
    public MsvcEhResult ExceptionInfo { get; private set; } = MsvcEhResult.Empty;

    /// <summary>The function a chunk starting at <paramref name="start"/> was attached to, or null.</summary>
    public NativeFunction? ChunkOwner(uint start) => _chunkOwners.GetValueOrDefault(start);

    /// <summary>What the build attached: chunks per parent function and the decoded metadata.</summary>
    private sealed class ChunkPlan
    {
        public MsvcEhResult Eh = MsvcEhResult.Empty;
        public Dictionary<uint, List<FunctionChunk>> ByParent = [];
        /// <summary>Funclets kept as functions -> their parent.</summary>
        public Dictionary<uint, uint> Funclets = [];
    }

    private void Apply(ChunkPlan plan)
    {
        ExceptionInfo = plan.Eh;
        foreach (var (funclet, parent) in plan.Funclets)
            if (_byStart.TryGetValue(funclet, out var f) && _byStart.TryGetValue(parent, out var p)) f.Parent = p;
        foreach (var (parent, chunks) in plan.ByParent)
        {
            if (!_byStart.TryGetValue(parent, out var f)) continue;
            f.Chunks = chunks;
            foreach (var c in chunks) _chunkOwners.TryAdd(c.Start, f);
        }
    }

    /// <summary>Block label for a chunk start ("catch_&lt;rva&gt;", "unwind_&lt;rva&gt;", ...), or null.</summary>
    private static string? ChunkLabel(NativeFunction f, uint rva)
    {
        foreach (var c in f.Chunks)
            if (c.Start == rva) return $"{c.Kind.ToString().ToLowerInvariant()}_{rva:X}";
        return null;
    }

    /// <summary>Chunk starts of <paramref name="f"/> as extra walk roots, or null.</summary>
    internal static List<uint>? ChunkRoots(NativeFunction f) => f.Chunks.Count == 0 ? null : f.Chunks.Select(c => c.Start).ToList();

    /// <summary>Which function's code contains an address, from the walk results of the build (for the exception decoder).</summary>
    private sealed class WalkView : IMsvcEhCodeView
    {
        private readonly uint[] _starts;
        private readonly WalkResult[] _results;
        private readonly Dictionary<uint, int> _index;
        private readonly uint[] _ownerStarts, _ownerEnds;
        private readonly int[] _owners;

        public WalkView(uint[] starts, WalkResult[] results, Dictionary<uint, int> index, int parallelism)
        {
            _starts = starts;
            _results = results;
            _index = index;
            int total = 0;
            foreach (var r in results) total += r.RangeStarts.Length;
            var keys = new ulong[total];
            var ends = new uint[total];
            int at = 0;
            for (int i = 0; i < results.Length; i++)
                for (int r = 0; r < results[i].RangeStarts.Length; r++, at++) { keys[at] = (ulong)results[i].RangeStarts[r] << 32 | (uint)i; ends[at] = results[i].RangeEnds[r]; }
            (_ownerStarts, _ownerEnds, _owners) = KeySort.OwnerMap(keys, ends, parallelism);
        }

        public uint? FunctionContaining(uint rva)
        {
            if (_index.ContainsKey(rva)) return rva;
            int i = Array.BinarySearch(_ownerStarts, rva);
            if (i < 0) i = ~i - 1;
            return i >= 0 && rva < _ownerEnds[i] ? _starts[_owners[i]] : null;
        }

        public IReadOnlyList<(uint Start, uint End)> RangesOf(uint start)
        {
            if (!_index.TryGetValue(start, out int i)) return [];
            var r = _results[i];
            var list = new (uint, uint)[r.RangeStarts.Length];
            for (int k = 0; k < list.Length; k++) list[k] = (r.RangeStarts[k], r.RangeEnds[k]);
            return list;
        }
    }

    private sealed partial class Builder
    {
        /// <summary>Sources that make a function stand on its own even when exception metadata also reaches it.</summary>
        private const FunctionSource OwnSources = FunctionSource.Export | FunctionSource.EntryPoint | FunctionSource.TlsCallback
            | FunctionSource.Call | FunctionSource.ExceptionHandler;

        /// <summary>
        /// Decodes the exception metadata and attaches what it reaches to the owning functions: function starts that
        /// are only funclets (not exported, not called, not entry points) stop being functions and their code joins the
        /// parent; handler code that discovery never decoded (x64 __except blocks, x86 catch blocks, catch
        /// continuations) is walked and joins the parent too. A funclet the linker folded for several functions joins
        /// each of them.
        /// </summary>
        private ChunkPlan AttachExceptionChunks(ref uint[] starts, ref WalkResult[] results)
        {
            var plan = new ChunkPlan();
            if (image.Format is ImageFormat.Elf or ImageFormat.MachO)
            {
                AttachLandingPads(plan, starts, ref results);
                return plan;
            }
            if (image.Arch is not (NativeArch.X86 or NativeArch.X64)) return plan;
            report.Report("decoding exception metadata", 0, 0);
            var index = new Dictionary<uint, int>(starts.Length);
            for (int i = 0; i < starts.Length; i++) index[starts[i]] = i;
            var view = new WalkView(starts, results, index, options.MaxParallelism);
            try
            {
                plan.Eh = MsvcEh.Analyze(image, view, ct: ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                AddTruncation($"exception metadata not decoded ({ex.GetType().Name}: {ex.Message})");
                return plan;
            }
            var eh = plan.Eh;
            if (eh.Parents.Count == 0 && eh.Fragments.Count == 0) return plan;

            // children, and x64 chained fragments that discovery made functions of their own
            var relations = eh.Parents.Select(kv => (Child: kv.Key, Owners: kv.Value)).ToList();
            foreach (var (begin, primary) in eh.Fragments)
                if (index.ContainsKey(begin) && !eh.Parents.ContainsKey(begin))
                    relations.Add((begin, [(primary, MsvcEhChildKind.Fragment)]));
            relations.Sort((a, b) => a.Child.CompareTo(b.Child));
            var related = relations.Select(r => r.Child).ToHashSet();

            // functions that call or tail-call each child start (found on several threads, recorded in function order)
            var callers = new Dictionary<uint, HashSet<int>>();
            var calling = new bool[results.Length];
            var walked0 = results;
            ForEachIndex(results.Length, g =>
            {
                foreach (var x in walked0[g].Xrefs)
                    if (x.Kind is XrefKind.Call or XrefKind.TailCall && related.Contains(x.To)) { calling[g] = true; return; }
            });
            for (int g = 0; g < results.Length; g++)
                if (calling[g])
                    foreach (var x in results[g].Xrefs)
                        if (x.Kind is XrefKind.Call or XrefKind.TailCall && related.Contains(x.To))
                        {
                            if (!callers.TryGetValue(x.To, out var set)) callers[x.To] = set = [];
                            set.Add(g);
                        }

            var demoted = new HashSet<int>();
            var extra = new Dictionary<int, List<(uint Root, MsvcEhChildKind Kind, int Child)>>();
            var toWalk = new List<uint>();
            var keptCatches = new List<(int Parent, WalkResult Catch)>();
            void Attach(int parent, uint root, MsvcEhChildKind kind, int child)
            {
                if (!extra.TryGetValue(parent, out var list)) extra[parent] = list = [];
                if (!list.Any(x => x.Root == root)) list.Add((root, kind, child));
            }
            foreach (var (child, parents) in relations)
            {
                var owners = parents.Where(p => index.ContainsKey(p.Parent) && p.Parent != child).ToList();
                if (owners.Count == 0) continue;
                var ownerIdx = owners.Select(p => index[p.Parent]).ToHashSet();
                if (index.TryGetValue(child, out int ci))
                {
                    if ((_sources[child] & OwnSources) != 0) continue;
                    if (callers.TryGetValue(child, out var from) && from.Any(g => g != ci && !ownerIdx.Contains(g))) continue;
                    // x64 C++ catch and unwind funclets have their own .pdata entry and frame, and the linker folds identical
                    // ones across functions: they stay functions with a parent link (as IDA keeps them)
                    if (image.Arch == NativeArch.X64 && owners[0].Kind is MsvcEhChildKind.Catch or MsvcEhChildKind.Unwind)
                    {
                        plan.Funclets[child] = owners[0].Parent;
                        if (owners[0].Kind == MsvcEhChildKind.Catch) keptCatches.Add((index[owners[0].Parent], results[ci]));
                        continue;
                    }
                    demoted.Add(ci);
                    foreach (var (p, kind) in owners) Attach(index[p], child, kind, ci);
                }
                else if (_ctx.Code.IsCode(child))
                {
                    toWalk.Add(child);
                    foreach (var (p, kind) in owners) Attach(index[p], child, kind, -1);
                }
            }
            // a parent that is itself demoted (a catch funclet that owns nested handlers) passes its chunks to its owners
            foreach (int d in demoted) extra.Remove(d);

            // x64 chained .pdata fragments the primary's flow never reaches (code only an exception path enters): walked
            // from their begin, attached when that decodes cleanly (a fragment can begin with data)
            var fragments = new List<(int Primary, uint Begin)>();
            foreach (var (begin, primary) in eh.Fragments)
                if (index.TryGetValue(primary, out int pi) && !index.ContainsKey(begin) && view.FunctionContaining(begin) == null && _ctx.Code.IsCode(begin))
                {
                    fragments.Add((pi, begin));
                    toWalk.Add(begin);
                }
            var walked = WalkChunks(toWalk);
            foreach (var (pi, begin) in fragments)
                if (walked.TryGetValue(begin, out var w) && w.RangeStarts.Length > 0 && (w.Flags & FunctionFlags.InvalidCode) == 0)
                    Attach(pi, begin, MsvcEhChildKind.Fragment, -1);
            var catches = new List<(int Parent, WalkResult Catch)>(keptCatches);
            foreach (var (p, chunks) in extra)
                foreach (var (root, kind, child) in chunks)
                    if (kind == MsvcEhChildKind.Catch && (child >= 0 ? results[child] : walked.GetValueOrDefault(root)) is { } part) catches.Add((p, part));
            AddContinuations(starts, results, extra, walked, catches);

            // demoted starts stop being functions; each parent is walked again with its chunks as further roots
            var all = starts;
            if (demoted.Count > 0) _ctx.FunctionStarts = new HashSet<uint>(all.Where((_, i) => !demoted.Contains(i)));
            var merged = (WalkResult[])results.Clone();
            var walker = new FunctionWalker(_ctx);
            foreach (var (p, chunks) in extra.OrderBy(kv => kv.Key))
            {
                var list = new List<FunctionChunk>();
                foreach (var (root, kind, child) in chunks)
                    if ((child >= 0 ? results[child] : walked.GetValueOrDefault(root)) is { RangeStarts.Length: > 0 }) list.Add(new FunctionChunk(root, kind));
                if (list.Count == 0) continue;
                ct.ThrowIfCancellationRequested();
                list.Sort((a, b) => a.Start.CompareTo(b.Start));
                merged[p] = walker.Walk(null, all[p], buildGraph: false, ct, list.Select(c => c.Start).ToList());
                plan.ByParent[all[p]] = list;
            }
            if (demoted.Count > 0)
            {
                var keep = Enumerable.Range(0, all.Length).Where(i => !demoted.Contains(i)).ToArray();
                starts = keep.Select(i => all[i]).ToArray();
                results = keep.Select(i => merged[i]).ToArray();
            }
            else results = merged;
            return plan;
        }

        /// <summary>
        /// Itanium landing pads (.eh_frame / compact unwind LSDAs, ARM EHABI) that no function's flow reaches: chunks of the
        /// function whose tables name them (catch when a catch clause leads there, else unwind), walked with its body.
        /// They run in that function's frame, so they join it rather than become functions of their own.
        /// </summary>
        private void AttachLandingPads(ChunkPlan plan, uint[] starts, ref WalkResult[] results)
        {
            var pads = _ctx.LandingPads;
            if (pads.Count == 0) return;
            report.Report("attaching landing pads", 0, 0);
            var index = new Dictionary<uint, int>(starts.Length);
            for (int i = 0; i < starts.Length; i++) index[starts[i]] = i;
            var view = new WalkView(starts, results, index, options.MaxParallelism);
            var byOwner = new Dictionary<int, List<FunctionChunk>>();
            foreach (var (function, pad, catches) in pads)
            {
                if (view.FunctionContaining(function) is not { } owner || view.FunctionContaining(pad) != null || !_ctx.Code.IsCode(pad)) continue;
                int p = index[owner];
                if (!byOwner.TryGetValue(p, out var list)) byOwner[p] = list = [];
                int at = list.FindIndex(c => c.Start == pad);
                var kind = catches ? MsvcEhChildKind.Catch : MsvcEhChildKind.Unwind;
                if (at < 0) list.Add(new FunctionChunk(pad, kind));
                else if (catches) list[at] = new FunctionChunk(pad, kind);
            }
            if (byOwner.Count == 0) return;
            var walker = new FunctionWalker(_ctx);
            var merged = (WalkResult[])results.Clone();
            foreach (var (p, list) in byOwner.OrderBy(kv => kv.Key))
            {
                ct.ThrowIfCancellationRequested();
                list.Sort((a, b) => a.Start.CompareTo(b.Start));
                merged[p] = walker.Walk(null, starts[p], buildGraph: false, ct, list.Select(c => c.Start).ToList());
                plan.ByParent[starts[p]] = list;
            }
            results = merged;
        }

        private void ReadLandingPads()
        {
            try { _ctx.LandingPads = Itanium.ItaniumEh.LandingPads(image); }
            catch (Exception ex) when (ex is not OperationCanceledException) { AddTruncation($"landing pads not read ({ex.GetType().Name}: {ex.Message})"); }
        }

        /// <summary>Walks chunk roots discovery did not decode (each once).</summary>
        private Dictionary<uint, WalkResult> WalkChunks(IEnumerable<uint> roots)
        {
            var walked = new Dictionary<uint, WalkResult>();
            var walker = new FunctionWalker(_ctx);
            foreach (var root in roots)
            {
                if (walked.ContainsKey(root)) continue;
                ct.ThrowIfCancellationRequested();
                walked[root] = walker.Walk(null, root, buildGraph: false, ct);
            }
            return walked;
        }

        /// <summary>
        /// Where a catch block resumes the parent ("lea rax, [continuation]" / "mov eax, offset continuation" before
        /// its return): addresses its code takes inside the parent (x64: the parent's .pdata ranges; x86: between the
        /// parent's start and the end of its code and chunks) that the parent's code does not cover yet.
        /// </summary>
        private void AddContinuations(uint[] starts, WalkResult[] results, Dictionary<int, List<(uint Root, MsvcEhChildKind Kind, int Child)>> extra,
            Dictionary<uint, WalkResult> walked, List<(int Parent, WalkResult Catch)> catches)
        {
            var roots = new List<(int Parent, uint Root)>();
            var ends = new Dictionary<int, uint>();
            foreach (var (p, catchCode) in catches)
            {
                var parent = results[p];
                uint start = starts[p];
                var pdata = _ctx.PdataRanges.GetValueOrDefault(start);
                if (!ends.TryGetValue(p, out uint end))
                {
                    end = parent.RangeEnds.Length > 0 ? parent.RangeEnds.Max() : start;
                    foreach (var (root, _, child) in extra.GetValueOrDefault(p) ?? [])
                        if ((child >= 0 ? results[child] : walked.GetValueOrDefault(root)) is { RangeEnds.Length: > 0 } part) end = Math.Max(end, part.RangeEnds.Max());
                    ends[p] = end;
                }
                foreach (var x in catchCode.Xrefs)
                {
                    if (x.Kind != XrefKind.Address || !_ctx.Code.IsCode(x.To) || InRanges(parent, x.To) || _ctx.FunctionStarts.Contains(x.To)) continue;
                    bool inside = pdata != null ? pdata.Any(r => x.To >= r.Begin && x.To < r.End) : x.To > start && x.To < end;
                    if (inside) roots.Add((p, x.To));
                }
            }
            if (roots.Count == 0) return;
            foreach (var (root, result) in WalkChunks(roots.Select(r => r.Root).Distinct().Where(r => !walked.ContainsKey(r)))) walked[root] = result;
            foreach (var (p, root) in roots)
            {
                if (!extra.TryGetValue(p, out var list)) extra[p] = list = [];
                if (!list.Any(c => c.Root == root)) list.Add((root, MsvcEhChildKind.Continuation, -1));
            }
        }
    }
}
