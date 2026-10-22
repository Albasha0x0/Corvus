using System.Diagnostics;
using System.Text.RegularExpressions;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Diff;
using Corvus.Native.NativeAot;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// find_similar_functions on production code: the NativeAOT-compiled ilc of the ILCompiler packages names every method
/// body, so instantiations of one generic method and one method in two releases are the ground truth.
/// </summary>
[Trait("Speed", "Slow")]
public partial class SimilarFunctionsRealTests(ITestOutputHelper output)
{
    private const int MinInstructions = 10;

    private sealed record Opened(ImagePrints Prints, Dictionary<int, NativeAotMethod> Names, TimeSpan Index, TimeSpan Sketch);

    private static readonly Dictionary<string, Opened> Cache = [];

    private static Opened Open(string rid, string version)
    {
        lock (Cache)
        {
            if (Cache.TryGetValue(rid + version, out var hit)) return hit;
            var path = RealPackages.File($"runtime.{rid}.Microsoft.DotNet.ILCompiler", version, "tools", rid.StartsWith("win-", StringComparison.Ordinal) ? "ilc.exe" : "ilc");
            var image = NativeImageLoader.Open(path);
            var aot = NativeAotImage.Open(image) ?? throw new InvalidOperationException($"{path}: no NativeAOT header");
            var sw = Stopwatch.StartNew();
            var index = NativeCodeIndex.Build(image, new CodeIndexOptions { SymbolStarts = aot.Names.MethodAt.Keys.ToList() });
            var indexed = sw.Elapsed;
            sw.Restart();
            var prints = ImagePrints.Build(index, default);
            var names = new Dictionary<int, NativeAotMethod>();
            foreach (var (rva, m) in aot.Names.MethodAt)
                if (prints.ByStart.TryGetValue(rva, out var i)) names[i] = m;
            return Cache[rid + version] = new Opened(prints, names, indexed, sw.Elapsed);
        }
    }

    [GeneratedRegex("<[^<>]*>")]
    private static partial Regex GenericArguments();

    /// <summary>A generic method's identity without its type arguments; null for a method that is not generic.</summary>
    private static string? Family(NativeAotMethod m)
    {
        string text = m.Name.Owner + "::" + m.Name.Name + m.Name.Instantiation;
        if (!text.Contains('<')) return null;
        string stripped = text;
        for (int k = 0; k < 8 && stripped.Contains('<'); k++) stripped = GenericArguments().Replace(stripped, "");
        return stripped;
    }

    private static bool Eligible(FunctionPrint p) => !p.Failed && p.Sketch != null && p.ThunkImport == null && p.Instructions >= MinInstructions;

    /// <summary>
    /// Instantiations of one generic method over different types (separate bodies): from a sample of them, how often
    /// another instantiation of the same method is the best hit or among the first five.
    /// </summary>
    [Theory]
    [InlineData("win-x64")]
    [InlineData("win-arm64")]
    [InlineData("win-x86")]
    [InlineData("linux-arm")]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public void Instantiations_of_one_generic_method_find_each_other(string rid)
    {
        var o = Open(rid, "10.0.11");
        var f = o.Prints.Functions;
        var families = o.Names.Where(kv => Eligible(f[kv.Key]) && Family(kv.Value) != null)
            .GroupBy(kv => Family(kv.Value)!).Where(g => g.Count() >= 2)
            .ToDictionary(g => g.Key, g => g.Select(kv => kv.Key).ToHashSet());
        var familyOf = families.SelectMany(kv => kv.Value.Select(i => (i, kv.Key))).ToDictionary(x => x.i, x => x.Key);
        // every k-th member: a fixed sample across the image
        var members = familyOf.Keys.Order().ToList();
        var sample = members.Where((_, k) => k % Math.Max(1, members.Count / 300) == 0).ToList();
        int top1 = 0, top5 = 0;
        var times = new List<double>();
        foreach (var q in sample)
        {
            long decodes = o.Prints.Decodes;
            var sw = Stopwatch.StartNew();
            var hits = SimilarFunctions.Similar(o.Prints, q, [o.Prints], 0.5, MinInstructions, 200, default, out int compared);
            times.Add(sw.Elapsed.TotalMilliseconds);
            // Sketches rank every function; only the query and at most 200 candidates are decoded for exact scores.
            Assert.InRange(o.Prints.Decodes - decodes, 1, 201);
            Assert.True(compared > 10 * 201, $"{compared} functions compared");
            var family = families[familyOf[q]];
            if (hits.Count > 0 && family.Contains(hits[0].Index)) top1++;
            if (hits.Take(5).Any(h => family.Contains(h.Index))) top5++;
        }
        double r1 = (double)top1 / sample.Count, r5 = (double)top5 / sample.Count;
        var csw = Stopwatch.StartNew();
        var clusters = SimilarFunctions.Clusters(o.Prints, 0.8, MinInstructions, default, out int pairs);
        var clusterTime = csw.Elapsed;
        var clusterOf = clusters.SelectMany((c, k) => c.Members.Select(i => (i, k))).ToDictionary(x => x.i, x => x.k);
        // members with an instantiation that a query scores 0.8 or more: how many share its cluster
        int near = 0, together = 0;
        foreach (var q in sample)
        {
            var family = families[familyOf[q]];
            var close = SimilarFunctions.Similar(o.Prints, q, [o.Prints], 0.8, MinInstructions, 200, default, out _).Where(h => family.Contains(h.Index)).ToList();
            if (close.Count == 0) continue;
            near++;
            if (clusterOf.TryGetValue(q, out var c) && close.Any(h => clusterOf.GetValueOrDefault(h.Index, -1) == c)) together++;
        }
        output.WriteLine($"{rid}: clusters hold {together} of {near} instantiation pairs scoring 0.8 or more");
        output.WriteLine($"{rid}: {f.Length:N0} functions, index {o.Index.TotalSeconds:F1} s, sketches {o.Sketch.TotalSeconds:F1} s; " +
                         $"{families.Count:N0} generic families, {sample.Count} queries: recall@1 {r1:P1}, recall@5 {r5:P1}; " +
                         $"query median {Median(times):F0} ms, max {times.Max():F0} ms; clusters {clusters.Count:N0} from {pairs:N0} pairs in {clusterTime.TotalSeconds:F2} s");
        Assert.True(sample.Count >= 100, $"only {sample.Count} sampled instantiations");
        Assert.True(r5 >= 0.7, $"recall@5 {r5:P1}");
        PerfBudget.AtMost($"native/similar-query-median/{rid}", Median(times), 1000, "ms", output);
    }

    /// <summary>One method in two releases (.NET 9 and 10 ilc): the same-named function of the other release among the cross-image hits.</summary>
    [Fact]
    public void A_method_finds_itself_in_the_other_release()
    {
        var (a, b) = (Open("win-x64", "9.0.19"), Open("win-x64", "10.0.11"));
        static Dictionary<string, int> Unique(Opened o) => o.Names.Where(kv => Eligible(o.Prints.Functions[kv.Key]))
            .GroupBy(kv => kv.Value.Name.Full).Where(g => g.Count() == 1).ToDictionary(g => g.Key, g => g.Single().Key);
        var (ua, ub) = (Unique(a), Unique(b));
        var both = ua.Keys.Where(ub.ContainsKey).Order(StringComparer.Ordinal).ToList();
        var sample = both.Where((_, k) => k % Math.Max(1, both.Count / 400) == 0).ToList();
        int top1 = 0, top5 = 0, identical = 0;
        var times = new List<double>();
        foreach (var name in sample)
        {
            var sw = Stopwatch.StartNew();
            var hits = SimilarFunctions.Similar(a.Prints, ua[name], [a.Prints, b.Prints], 0.5, MinInstructions, 200, default, out _)
                .Where(h => ReferenceEquals(h.Image, b.Prints)).ToList();
            times.Add(sw.Elapsed.TotalMilliseconds);
            if (hits.Count > 0 && hits[0].Index == ub[name]) top1++;
            if (hits.Take(5).Any(h => h.Index == ub[name])) top5++;
            if (a.Prints.Functions[ua[name]].BytesHash == b.Prints.Functions[ub[name]].BytesHash) identical++;
        }
        double r1 = (double)top1 / sample.Count, r5 = (double)top5 / sample.Count;
        output.WriteLine($"ilc 9.0.19 -> 10.0.11 win-x64: {both.Count:N0} methods named once in both, {sample.Count} queries ({identical} with identical code): " +
                         $"top-1 {r1:P1}, top-5 {r5:P1}; query median {Median(times):F0} ms, max {times.Max():F0} ms");
        Assert.True(r1 >= 0.6, $"top-1 {r1:P1}");
        Assert.True(r5 >= 0.75, $"top-5 {r5:P1}");
    }

    /// <summary>Speed on a large image (100 MB and more): sketches once, then sub-second queries; duplicates and clusters image-wide.</summary>
    [RequiresRealDataFact(RealData.LargeNativeImage)]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    [Trait("Tier", "Release")]
    public void Large_image_queries_stay_under_a_second()
    {
        var image = NativeImageLoader.Open(RealData.Path(RealData.LargeNativeImage));
        var sw = Stopwatch.StartNew();
        var index = NativeCodeIndex.Build(image);
        var indexed = sw.Elapsed;
        sw.Restart();
        var prints = ImagePrints.Build(index, default);
        var sketched = sw.Elapsed;
        var f = prints.Functions;
        var eligible = Enumerable.Range(0, f.Length).Where(i => Eligible(f[i])).ToList();
        var times = new List<double>();
        foreach (var q in eligible.Where((_, k) => k % Math.Max(1, eligible.Count / 50) == 0))
        {
            long decodes = prints.Decodes;
            var qsw = Stopwatch.StartNew();
            SimilarFunctions.Similar(prints, q, [prints], 0.5, 5, 200, default, out int compared);
            times.Add(qsw.Elapsed.TotalMilliseconds);
            Assert.InRange(prints.Decodes - decodes, 1, 201);
            Assert.True(compared > 10 * 201, $"{compared} functions compared");
        }
        sw.Restart();
        var duplicates = SimilarFunctions.Duplicates(prints, 5, default);
        var dupTime = sw.Elapsed;
        sw.Restart();
        var clusters = SimilarFunctions.Clusters(prints, 0.8, 5, default, out int pairs);
        var clusterTime = sw.Elapsed;
        long memory = GC.GetTotalMemory(false);
        output.WriteLine($"{Path.GetFileName(image.Path)} ({new FileInfo(image.Path).Length / 1e6:F0} MB, {image.Arch}): {f.Length:N0} functions; index {indexed.TotalSeconds:F1} s, " +
                         $"sketches {sketched.TotalSeconds:F1} s; {times.Count} queries median {Median(times):F0} ms, max {times.Max():F0} ms; " +
                         $"duplicates {duplicates.Count:N0} groups in {dupTime.TotalSeconds:F2} s; clusters {clusters.Count:N0} from {pairs:N0} pairs in {clusterTime.TotalSeconds:F2} s; heap {memory / 1e6:F0} MB");
        PerfBudget.AtMost("native/similar-query-slowest-large-image", times.Max(), 1000, "ms", output);
    }

    private static double Median(List<double> values)
    {
        var sorted = values.Order().ToList();
        return sorted[sorted.Count / 2];
    }
}
