using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Native;
using Corvus.Native.Code;
using Xunit.Abstractions;

namespace Corvus.Tests.Accuracy;

/// <summary>
/// Function discovery of our engine scored against symbol truth on stripped copies of unstripped ELF images from NuGet
/// packages (baseline.json: package, file, IDA / Ghidra scores captured with the research scorer, and our thresholds).
/// Thresholds only rise: a score above its threshold by more than 0.005 is reported so the baseline can be raised.
/// </summary>
[Trait("Speed", "Slow")]
public class AccuracyTests(ITestOutputHelper output)
{
    /// <summary>Research runs: score every image of this accuracy folder (images.json, work/samples) into results/ours.</summary>
    public const string ResearchDir = "CORVUS_ACCURACY_DIR";

    private static string BaselinePath([CallerFilePath] string source = "") => Path.Combine(Path.GetDirectoryName(source)!, "baseline.json");

    [Fact]
    public void Function_starts_hold_the_baseline()
    {
        var baseline = JsonNode.Parse(File.ReadAllText(BaselinePath()))!;
        var failures = new List<string>();
        int scored = 0;
        foreach (var entry in baseline["images"]!.AsArray())
        {
            string id = (string)entry!["id"]!;
            string package = (string)entry["package"]!, version = (string)entry["version"]!;
            string[] parts = entry["path"]!.AsArray().Select(p => (string)p!).ToArray();
            string path = PackagePath(package, version, parts);
            if (!File.Exists(path))
            {
                output.WriteLine($"{id}: {package} {version} not restored, skipped");
                continue;
            }
            var bytes = File.ReadAllBytes(path);
            var truth = ElfTruth.Read(path);
            var stripped = ElfStrip.Strip(bytes);
            var image = NativeImageLoader.FromBytes(stripped, path);
            var sw = Stopwatch.StartNew();
            var index = NativeCodeIndex.Build(image);
            var score = StartScore.Of(truth, index.Functions.Select(f => new EngineFunction(f.Start, MainEnd(index, f))), stripped, truth.FileOffset);
            scored++;
            output.WriteLine($"{id}: {sw.ElapsedMilliseconds} ms, truth {score.Truth}, ours {score.Engine}: precision {score.Precision:F4} recall {score.Recall:F4} " +
                $"F1 {score.F1:F4} | end exact {score.ExactEnd:F4} within 16 {score.End16:F4} | neutral {score.Neutral}" +
                $" | IDA F1 {entry["ida"]?["startF1"]} Ghidra F1 {entry["ghidra"]?["startF1"]}");
            var limits = entry["thresholds"]!;
            Check(id, "startF1", score.F1, limits, failures);
            Check(id, "precision", score.Precision, limits, failures);
            Check(id, "recall", score.Recall, limits, failures);
            Check(id, "end16", score.End16, limits, failures);
        }
        Assert.True(scored > 0, "no baseline image restored");
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    private void Check(string id, string metric, double value, JsonNode limits, List<string> failures)
    {
        if (limits[metric] is not { } node) return;
        double limit = (double)node;
        if (value < limit - 0.0005) failures.Add($"{id} {metric} {value:F4} fell below {limit:F4}");
        else if (value > limit + 0.005) output.WriteLine($"  {id} {metric} {value:F4} is above its threshold {limit:F4}: raise it in baseline.json");
    }

    private static string PackagePath(string id, string version, string[] parts)
    {
        var root = Environment.GetEnvironmentVariable("NUGET_PACKAGES") is { Length: > 0 } custom
            ? custom : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nuget", "packages");
        return Path.Combine([root, id.ToLowerInvariant(), version, .. parts]);
    }

    /// <summary>End of the main body: the code ranges chained from the start across gaps of at most 16 bytes.</summary>
    public static uint MainEnd(NativeCodeIndex index, NativeFunction f)
    {
        uint? end = null;
        foreach (var (s, e) in index.Ranges(f).OrderBy(r => r.Start))
        {
            if (end == null)
            {
                if (s <= f.Start && f.Start < e) end = e;
            }
            else if (s <= end + 16) end = Math.Max(end.Value, e);
            else break;
        }
        return end ?? f.End;
    }

    /// <summary>
    /// Research dump (runs only with CORVUS_ACCURACY_DIR): every image of images.json analysed by our engine, its
    /// functions and the references to the sampled targets written to results/ours/&lt;id&gt;.json for the scorer.
    /// </summary>
    [Fact]
    public void Research_dump()
    {
        if (Environment.GetEnvironmentVariable(ResearchDir) is not { Length: > 0 } dir) { output.WriteLine($"{ResearchDir} not set: skipped"); return; }
        var only = Environment.GetEnvironmentVariable("CORVUS_ACCURACY_IDS")?.Split(',', StringSplitOptions.RemoveEmptyEntries).ToHashSet();
        var images = JsonNode.Parse(File.ReadAllText(Path.Combine(dir, "images.json")))!.AsObject();
        var outDir = Directory.CreateDirectory(Path.Combine(dir, "results", "ours")).FullName;
        foreach (var (id, entry) in images)
        {
            if (only != null && !only.Contains(id)) continue;
            var path = Path.Combine(dir, (string)entry!["image"]!);
            var samplePath = Path.Combine(dir, "work", "samples", id + ".json");
            var targets = File.Exists(samplePath)
                ? JsonNode.Parse(File.ReadAllText(samplePath))!["all"]!.AsArray().Select(t => (uint)t!).ToList() : [];
            var sw = Stopwatch.StartNew();
            var image = NativeImageLoader.Open(path);
            var index = NativeCodeIndex.Build(image);
            sw.Stop();
            var funcs = new JsonArray();
            foreach (var f in index.Functions)
                funcs.Add(new JsonObject
                {
                    ["start"] = f.Start, ["end"] = MainEnd(index, f), ["maxEnd"] = f.End, ["size"] = f.Size,
                    ["noreturn"] = f.Flags.HasFlag(FunctionFlags.NoReturn), ["thunk"] = f.Flags.HasFlag(FunctionFlags.Thunk),
                    ["funclet"] = f.Flags.HasFlag(FunctionFlags.Funclet), ["chunks"] = f.Chunks.Count,
                    ["source"] = f.Sources.ToString(), ["flags"] = f.Flags.ToString(),
                });
            var xrefs = new JsonObject();
            foreach (var t in targets)
            {
                // a Thumb pointer (odd value) is recorded at the even function start
                var refs = image.Arch == NativeArch.Arm && (t & 1) != 0 ? index.RefsTo(t).Concat(index.RefsTo(t & ~1u)) : index.RefsTo(t);
                xrefs[t.ToString()] = new JsonArray(refs.Select(x => (JsonNode)new JsonArray(x.From, x.Kind.ToString())).ToArray());
            }
            var doc = new JsonObject
            {
                ["engine"] = "ours", ["id"] = id, ["base"] = 0, ["seconds"] = Math.Round(sw.Elapsed.TotalSeconds, 2),
                ["imageBase"] = image.ImageBase, ["functions"] = funcs, ["xrefs"] = xrefs,
            };
            File.WriteAllText(Path.Combine(outDir, id + ".json"), doc.ToJsonString());
            output.WriteLine($"{id}: {index.Functions.Count} functions, {sw.ElapsedMilliseconds} ms");
        }
    }
}
