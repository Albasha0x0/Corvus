using dnlib.DotNet;
using NetDecompilerMcp.Services.Simplify;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// simplify_methods over randomly generated method bodies (<see cref="IlBodyGenerator"/>). For every seed: the engine
/// never crashes and stays within its limits, every rewrite verifies and survives save / reload, two runs give the same
/// image, and the simplified methods JIT-compile and return what the originals return (or throw the same exception).
/// Seeds 1..NDM_FUZZ_COUNT (default 40) run by default; NDM_FUZZ_SEED=n runs one seed, NDM_FUZZ_SEED=random a fresh one.
/// A failure names its seed.
/// </summary>
[Trait("Speed", "Slow")]
[Collection(SweepCollection.Name)]
public sealed class SimplifyFuzzTests(ITestOutputHelper output) : IDisposable
{
    private const int MethodsPerSeed = 8;
    private static readonly object?[][] Arguments = [[0, 0L, ""], [7, -3L, "abc"], [-1, long.MaxValue, "xyz"], [123456, 42L, "q"]];

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void GeneratedBodiesSimplifySafely()
    {
        var failures = new List<string>();
        var stats = new Stats();
        foreach (int seed in Seeds())
        {
            // A fatal runtime error (a JIT crash) ends the process before xUnit can report: the host prints stderr then.
            Console.Error.WriteLine($"[fuzz] seed {seed}");
            try
            {
                CheckSeed(seed, stats);
            }
            catch (Exception ex)
            {
                failures.Add($"seed {seed}: {ex.GetType().Name}: {ex.Message}");
            }
        }
        output.WriteLine($"{stats.Seeds} seed(s), {stats.Methods} generated methods ({stats.Instructions:N0} instructions), " +
                         $"{stats.Changed} simplified, {stats.Executions} executions compared; fallbacks: " +
                         string.Join(", ", stats.Fallbacks.OrderByDescending(f => f.Value).Select(f => $"{f.Key} {f.Value}")));
        foreach (var f in failures) output.WriteLine(f);
        Assert.True(failures.Count == 0,
            $"{failures.Count} fuzz seed(s) failed (rerun one with NDM_FUZZ_SEED=<seed>):\n" + string.Join("\n", failures.Take(20)));
    }

    private sealed class Stats
    {
        public int Seeds, Methods, Instructions, Changed, Executions;
        public Dictionary<string, int> Fallbacks { get; } = new();
    }

    private static IEnumerable<int> Seeds()
    {
        var single = Environment.GetEnvironmentVariable("NDM_FUZZ_SEED");
        if (string.Equals(single, "random", StringComparison.OrdinalIgnoreCase))
            return [Random.Shared.Next(1, int.MaxValue)];
        if (int.TryParse(single, out int seed)) return [seed];
        int count = int.TryParse(Environment.GetEnvironmentVariable("NDM_FUZZ_COUNT"), out int n) ? n : 40;
        return Enumerable.Range(1, count);
    }

    private void CheckSeed(int seed, Stats stats)
    {
        var (image, methods) = new IlBodyGenerator(seed).Generate(MethodsPerSeed);
        var path = _dir.File($"Fuzz{seed}.dll");
        File.WriteAllBytes(path, image);

        // The generator's output must be valid IL, or the test checks nothing.
        using (var module = ModuleDefMD.Load(image))
        {
            foreach (var m in module.Find(IlBodyGenerator.TypeName, false)!.Methods)
            {
                bool hasReturn = m.MethodSig.RetType.ElementType != ElementType.Void;
                Assert.True(new BodyGraph(m.Body).Verify(hasReturn, out var error) != null, $"generator produced invalid IL in {m.Name}: {error}");
                stats.Instructions += m.Body.Instructions.Count;
            }
        }

        var first = SimplifyHarness.Run(path);
        Assert.True(first.Problems.Count == 0, string.Join("\n", first.Problems.Take(5)));
        var rejectedOriginals = first.Changes.Where(c => c.Rejected?.Reason == FallbackReason.OriginalUnverifiable).ToList();
        Assert.True(rejectedOriginals.Count == 0, $"generator produced a body the engine rejects as unverifiable: {rejectedOriginals.FirstOrDefault()?.Rejected}");

        var second = SimplifyHarness.Run(path);
        var differing = SimplifySweepTests.DeterminismFailures(first, second);
        Assert.True(differing.Count == 0, $"repeated runs differ in {string.Join(", ", differing)}");

        CompareExecution(image, first.Image!, methods, stats);

        stats.Seeds++;
        stats.Methods += methods.Count;
        stats.Changed += first.Changed;
        foreach (var (code, count) in first.Fallbacks()) stats.Fallbacks[code] = stats.Fallbacks.GetValueOrDefault(code) + count;
    }

    /// <summary>Every method JIT-compiles in both images and gives the same result or exception for each argument set.</summary>
    private static void CompareExecution(byte[] original, byte[] simplified, List<string> methods, Stats stats)
    {
        using var before = new IlLab.LabRunner(original);
        using var after = new IlLab.LabRunner(simplified);
        foreach (var name in methods)
        {
            Jit(before, name, "original");
            Jit(after, name, "simplified");
            foreach (var args in Arguments)
            {
                var expected = Describe(before.Call(IlBodyGenerator.TypeName, name, args));
                var actual = Describe(after.Call(IlBodyGenerator.TypeName, name, args));
                Assert.True(expected == actual, $"{name}({string.Join(", ", args)}): original {expected}, simplified {actual}");
                stats.Executions++;
            }
        }
    }

    private static void Jit(IlLab.LabRunner runner, string method, string which)
    {
        var error = runner.Prepare(IlBodyGenerator.TypeName, method);
        Assert.True(error == null, $"{which} {method} does not JIT-compile: {error?.GetType().Name}: {error?.Message}");
    }

    private static string Describe((object? Value, Exception? Error) result) =>
        result.Error is { } e ? $"throws {e.GetType().FullName}" : $"returns {result.Value}";
}
