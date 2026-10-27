using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using Corvus.Native.Code;

namespace Corvus.Native.Diff;

/// <summary>MinHash sketches of instruction-shape 3-grams, unchanged by renamed registers, moved code and other constants.</summary>
public static class CodeSketch
{
    public const int Size = 32;
    public const int Gram = 3;
    /// <summary>Locality-sensitive bands: 8 bands of 4 slots (each band one 64-bit key); pairs near Jaccard 0.6 and above share one.</summary>
    public const int Bands = 8;
    public const int Rows = Size / Bands;

    private static readonly ulong[] Salt = Enumerable.Range(1, Size).Select(k => (ulong)k * 0x9E3779B97F4A7C15UL).ToArray();

    /// <summary>The distinct 3-grams of instruction shapes in address order; a function shorter than that is one shingle.</summary>
    public static HashSet<ulong> Shingles(List<MaskedInsn> code)
    {
        var set = new HashSet<ulong>();
        if (code.Count == 0) return set;
        int gram = Math.Min(Gram, code.Count);
        for (int k = 0; k + gram <= code.Count; k++)
        {
            ulong h = 0x243F6A8885A308D3UL;
            for (int j = 0; j < gram; j++) h = Mix(h ^ (uint)code[k + j].Token);
            set.Add(h);
        }
        return set;
    }

    public static (ushort[]? Sketch, int Shingles) Of(List<MaskedInsn> code)
    {
        var shingles = Shingles(code);
        return shingles.Count == 0 ? (null, 0) : (Sketch(shingles), shingles.Count);
    }

    /// <summary>The minimum of each of <see cref="Size"/> hash functions over the shingles, low 16 bits kept (chance agreement 1 in 65,536).</summary>
    public static ushort[] Sketch(HashSet<ulong> shingles)
    {
        Span<ulong> min = stackalloc ulong[Size];
        min.Fill(ulong.MaxValue);
        foreach (var s in shingles)
            for (int k = 0; k < Size; k++)
            {
                ulong v = Mix(s + Salt[k]);
                if (v < min[k]) min[k] = v;
            }
        var sketch = new ushort[Size];
        for (int k = 0; k < Size; k++) sketch[k] = (ushort)min[k];
        return sketch;
    }

    /// <summary>Estimated Jaccard similarity of the two shingle sets.</summary>
    public static double Jaccard(ushort[] a, ushort[] b)
    {
        int same = 0;
        for (int k = 0; k < Size; k++) if (a[k] == b[k]) same++;
        return (double)same / Size;
    }

    public static ulong Band(ushort[] sketch, int band)
    {
        int at = band * Rows;
        return sketch[at] | (ulong)sketch[at + 1] << 16 | (ulong)sketch[at + 2] << 32 | (ulong)sketch[at + 3] << 48;
    }

    private static ulong Mix(ulong x)
    {
        x ^= x >> 30; x *= 0xBF58476D1CE4E5B9UL;
        x ^= x >> 27; x *= 0x94D049BB133111EBUL;
        return x ^ x >> 31;
    }
}

/// <summary>A function similar to the query, with what they share.</summary>
public sealed record SimilarHit(ImagePrints Image, int Index, double Score, string Kind, double Code, double Containment,
    string[] SharedStrings, ulong[] SharedConstants, string[] SharedImports, int[] SharedCallees);

/// <summary>Functions of one image that are copies (same shape) or near-copies of each other; members are print indexes by address.</summary>
public sealed record SimilarGroup(string Kind, int[] Members, double[] Scores);

/// <summary>Similar functions, duplicates and near-duplicate clusters within one image or across images of one architecture.</summary>
public static class SimilarFunctions
{
    /// <summary>A query's exact rescoring covers at most this many candidates.</summary>
    public const int MaxRescored = 2000;
    /// <summary>A band bucket larger than this compares each member only with its nearest sizes.</summary>
    private const int BucketAllPairs = 48;
    private const int BucketWindow = 16;

    private static readonly ConditionalWeakTable<ImagePrints, ConcurrentDictionary<string, (List<SimilarGroup> Groups, int Compared)>> ClusterCache = new();

    /// <summary>Weighted similarity 0-1: code (3-gram Jaccard) dominates; mnemonic mix, size, graph shape, imports, strings, constants and (same image) callees.</summary>
    public static double Score(FunctionPrint a, FunctionPrint b, double code, bool sameImage)
    {
        if (a.Failed || b.Failed) return 0;
        double sum = 0, weight = 0;
        void Add(double value, double w) { sum += value * w; weight += w; }
        Add(code, 4);
        Add(BuildMatcher.Histogram(a, b), 1.5);
        Add(BuildMatcher.Ratio(a.Instructions, b.Instructions), 1);
        Add((BuildMatcher.Ratio(a.Blocks, b.Blocks) + BuildMatcher.Ratio(a.Edges, b.Edges)) / 2, 1);
        Add(a.GraphHash == b.GraphHash ? 1 : 0, 0.5);
        if (a.Imports.Length + b.Imports.Length > 0) Add(BuildMatcher.Jaccard(a.Imports, b.Imports, string.CompareOrdinal), 1);
        if (a.Strings.Length + b.Strings.Length > 0) Add(BuildMatcher.Jaccard(a.Strings, b.Strings, string.CompareOrdinal), 1.5);
        if (a.Constants.Length + b.Constants.Length > 0) Add(BuildMatcher.Jaccard(a.Constants, b.Constants, (x, y) => x.CompareTo(y)), 1);
        if (sameImage && a.Callees.Length + b.Callees.Length > 0) Add(CalleeJaccard(a.Callees, b.Callees), 1);
        return sum / weight;
    }

    private static bool Eligible(FunctionPrint p, int minInstructions) =>
        !p.Failed && p.Sketch != null && p.ThunkImport == null && p.Instructions >= minInstructions;

    /// <summary>Functions in <paramref name="scope"/> similar to <paramref name="query"/>, best first, scoring at least <paramref name="minScore"/>.</summary>
    public static List<SimilarHit> Similar(ImagePrints home, int query, IReadOnlyList<ImagePrints> scope, double minScore, int minInstructions, int keep,
        CancellationToken ct, out int compared)
    {
        var q = home.Functions[query];
        if (q.Failed || q.Sketch == null) { compared = 0; return []; }
        keep = Math.Clamp(keep, 1, MaxRescored);
        // Pass 1: every function's sketch estimate and print features.
        var pre = new ConcurrentBag<(ImagePrints Image, int Index, double Score)>();
        int scanned = 0;
        foreach (var image in scope)
        {
            bool same = ReferenceEquals(image, home);
            Parallel.For(0, image.Functions.Length, new ParallelOptions { CancellationToken = ct }, () => (Hits: new List<(ImagePrints, int, double)>(), Seen: 0), (i, _, local) =>
            {
                var c = image.Functions[i];
                if ((same && i == query) || !Eligible(c, minInstructions)) return local;
                local.Seen++;
                double j = CodeSketch.Jaccard(q.Sketch, c.Sketch!);
                double code = Math.Max(j, 0.9 * EstimatedContainment(j, q.Shingles, c.Shingles));
                // Slack for the estimate's noise (about 0.09 at Jaccard 0.5).
                double s = Score(q, c, code, same);
                if (s >= minScore - 0.15) local.Hits.Add((image, i, s));
                return local;
            }, local => { foreach (var x in local.Hits) pre.Add(x); Interlocked.Add(ref scanned, local.Seen); });
        }
        compared = scanned;
        // Ties: the order of scope, then the address, so equal scores across identical images rank the same in every run.
        var rank = new Dictionary<ImagePrints, int>(ReferenceEqualityComparer.Instance);
        for (int k = 0; k < scope.Count; k++) rank.TryAdd(scope[k], k);
        var top = pre.OrderByDescending(x => x.Score).ThenBy(x => rank[x.Image]).ThenBy(x => x.Image.Functions[x.Index].Start).Take(keep).ToList();

        // Pass 2: exact 3-gram sets of the best candidates.
        var mine = ExactShingles(home, q, ct);
        var hits = new SimilarHit?[top.Count];
        Parallel.For(0, top.Count, new ParallelOptions { CancellationToken = ct }, () => new Dictionary<ImagePrints, MaskedDecoder>(), (k, _, decoders) =>
        {
            var (image, i, _) = top[k];
            var c = image.Functions[i];
            if (!decoders.TryGetValue(image, out var decoder)) decoders[image] = decoder = new MaskedDecoder(image.Index.Image, image.Index);
            var theirs = ExactShingles(image, c, ct, decoder);
            int both = 0;
            foreach (var s in mine) if (theirs.Contains(s)) both++;
            int union = mine.Count + theirs.Count - both;
            double jaccard = union == 0 ? 0 : (double)both / union;
            double containment = mine.Count == 0 ? 0 : (double)both / mine.Count;
            bool contains = containment >= 0.8 && mine.Count >= 8 && theirs.Count > mine.Count * 1.5;
            bool same = ReferenceEquals(image, home);
            double score = Score(q, c, contains ? Math.Max(jaccard, 0.9 * containment) : jaccard, same);
            if (score < minScore) return decoders;
            string kind = q.BytesHash == c.BytesHash ? "identical" : q.StructHash == c.StructHash ? "same_shape" : contains && jaccard < 0.6 ? "contains" : "similar";
            hits[k] = new SimilarHit(image, i, Math.Round(score, 3), kind, Math.Round(jaccard, 3), Math.Round(containment, 3),
                Shared(q.Strings, c.Strings, string.CompareOrdinal), Shared(q.Constants, c.Constants, (x, y) => x.CompareTo(y)),
                Shared(q.Imports, c.Imports, string.CompareOrdinal), same ? q.Callees.Where(c.Callees.Contains).ToArray() : []);
            return decoders;
        }, _ => { });
        return hits.Where(h => h != null).Select(h => h!)
            .OrderByDescending(h => h.Score).ThenByDescending(h => h.Code).ThenBy(h => rank[h.Image]).ThenBy(h => h.Image.Functions[h.Index].Start).ToList();
    }

    /// <summary>Containment of the smaller set in the larger estimated from Jaccard and the set sizes; 0 when the candidate is not larger.</summary>
    private static double EstimatedContainment(double jaccard, int query, int candidate)
    {
        // A single agreeing slot is noise at this sketch size.
        if (candidate <= query || jaccard < 2.0 / CodeSketch.Size) return 0;
        return Math.Min(1, jaccard * (query + candidate) / ((1 + jaccard) * query));
    }

    private static HashSet<ulong> ExactShingles(ImagePrints image, FunctionPrint p, CancellationToken ct, MaskedDecoder? decoder = null)
    {
        try
        {
            decoder ??= new MaskedDecoder(image.Index.Image, image.Index);
            image.CountDecode();
            return CodeSketch.Shingles(FunctionCode.Instructions(image.Index, decoder, p.Function, ct, out _));
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { return []; }
    }

    private static T[] Shared<T>(T[] a, T[] b, Comparison<T> compare)
    {
        var both = new List<T>();
        int i = 0, j = 0;
        while (i < a.Length && j < b.Length)
        {
            int c = compare(a[i], b[j]);
            if (c == 0) { both.Add(a[i]); i++; j++; }
            else if (c < 0) i++;
            else j++;
        }
        return both.ToArray();
    }

    private static double CalleeJaccard(int[] a, int[] b)
    {
        if (a.Length == 0 || b.Length == 0) return 0;
        int both = 0;
        var set = b.Length > 16 ? b.ToHashSet() : null;
        foreach (var x in a) if (set?.Contains(x) ?? Array.IndexOf(b, x) >= 0) both++;
        return (double)both / (a.Length + b.Length - both);
    }

    /// <summary>Groups of functions of one graph and instruction shape (identical or same_shape), most redundant bytes first.</summary>
    public static List<SimilarGroup> Duplicates(ImagePrints image, int minInstructions, CancellationToken ct)
    {
        var groups = new Dictionary<ulong, List<int>>();
        var f = image.Functions;
        for (int i = 0; i < f.Length; i++)
        {
            if ((i & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
            if (!Eligible(f[i], minInstructions)) continue;
            if (!groups.TryGetValue(f[i].StructHash, out var list)) groups[f[i].StructHash] = list = [];
            list.Add(i);
        }
        return groups.Values.Where(g => g.Count > 1)
            .Select(g =>
            {
                var members = g.OrderBy(i => f[i].Start).ToArray();
                bool identical = members.All(i => f[i].BytesHash == f[members[0]].BytesHash);
                return new SimilarGroup(identical ? "identical" : "same_shape", members, members.Select(i => Math.Round(Score(f[members[0]], f[i], 1, true), 3)).ToArray());
            })
            .OrderByDescending(Redundant).ThenBy(g => f[g.Members[0]].Start).ToList();

        long Redundant(SimilarGroup g) => g.Members.Skip(1).Sum(i => (long)f[i].Size);
    }

    /// <summary>Near-duplicate clusters linked through MinHash bands at <paramref name="minScore"/>, largest first; cached per image and settings.</summary>
    public static List<SimilarGroup> Clusters(ImagePrints image, double minScore, int minInstructions, CancellationToken ct, out int compared)
    {
        var cache = ClusterCache.GetValue(image, _ => new());
        string key = $"{minScore:R}|{minInstructions}";
        if (cache.TryGetValue(key, out var hit)) { compared = hit.Compared; return hit.Groups; }
        var f = image.Functions;
        var parent = Enumerable.Range(0, f.Length).ToArray();
        int Find(int x) { while (parent[x] != x) x = parent[x] = parent[parent[x]]; return x; }
        void Union(int a, int b) { a = Find(a); b = Find(b); if (a != b) parent[Math.Max(a, b)] = Math.Min(a, b); }

        // One representative per shape.
        var byShape = new Dictionary<ulong, int>();
        var reps = new List<int>();
        for (int i = 0; i < f.Length; i++)
        {
            if (!Eligible(f[i], minInstructions)) continue;
            if (byShape.TryGetValue(f[i].StructHash, out var first)) Union(first, i);
            else { byShape[f[i].StructHash] = i; reps.Add(i); }
        }

        int pairs = 0;
        void Compare(int a, int b)
        {
            if (Find(a) == Find(b)) return;
            var (x, y) = (f[a], f[b]);
            if (BuildMatcher.Ratio(x.Instructions, y.Instructions) < 0.5) return;
            pairs++;
            if (Score(x, y, CodeSketch.Jaccard(x.Sketch!, y.Sketch!), true) >= minScore) Union(a, b);
        }
        for (int band = 0; band < CodeSketch.Bands; band++)
        {
            ct.ThrowIfCancellationRequested();
            var buckets = new Dictionary<ulong, List<int>>();
            foreach (var r in reps)
            {
                var k = CodeSketch.Band(f[r].Sketch!, band);
                if (!buckets.TryGetValue(k, out var list)) buckets[k] = list = [];
                list.Add(r);
            }
            foreach (var members in buckets.Values)
            {
                if (members.Count < 2) continue;
                ct.ThrowIfCancellationRequested();
                if (members.Count <= BucketAllPairs)
                {
                    for (int i = 0; i < members.Count; i++)
                        for (int j = i + 1; j < members.Count; j++) Compare(members[i], members[j]);
                    continue;
                }
                // A crowded bucket (many small look-alikes) compares neighbours by size only.
                members.Sort((a, b) => f[a].Instructions.CompareTo(f[b].Instructions));
                for (int i = 0; i < members.Count; i++)
                    for (int j = i + 1; j < Math.Min(members.Count, i + 1 + BucketWindow); j++) Compare(members[i], members[j]);
            }
        }

        var clusters = new Dictionary<int, List<int>>();
        for (int i = 0; i < f.Length; i++)
        {
            if (!Eligible(f[i], minInstructions)) continue;
            int root = Find(i);
            if (!clusters.TryGetValue(root, out var list)) clusters[root] = list = [];
            list.Add(i);
        }
        var groups = clusters.Values.Where(c => c.Count > 1).Select(c =>
            {
                var members = c.OrderBy(i => f[i].Start).ToArray();
                var anchor = f[members[0]];
                bool identical = members.All(i => f[i].BytesHash == anchor.BytesHash);
                bool shape = members.All(i => f[i].StructHash == anchor.StructHash);
                return new SimilarGroup(identical ? "identical" : shape ? "same_shape" : "similar", members,
                    members.Select(i => Math.Round(Score(anchor, f[i], CodeSketch.Jaccard(anchor.Sketch!, f[i].Sketch!), true), 3)).ToArray());
            })
            .OrderByDescending(g => g.Members.Length).ThenByDescending(g => f[g.Members[0]].Instructions).ThenBy(g => f[g.Members[0]].Start).ToList();
        compared = pairs;
        if (cache.Count > 8) cache.Clear();
        cache[key] = (groups, pairs);
        return groups;
    }
}
