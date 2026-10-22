using System.Diagnostics;
using dnlib.DotNet;
using Corvus.Core;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Timing-sensitive real-data tests run without parallelism so CPU contention cannot skew them.</summary>
[CollectionDefinition(nameof(SerialTimingTests), DisableParallelization = true)]
public class SerialTimingCollection;

[Trait("Speed", "Slow")]
[Collection(nameof(SerialTimingTests))]
public class SerialTimingTests(ITestOutputHelper output)
{
    /// <summary>Path search stays fast on a cyclic real call graph (target: CORVUS_CALLPATH_TARGET or auto-picked).</summary>
    [RequiresRealDataFact(RealData.AssemblyDir)]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public void PathSearchIsFastOnRealAssemblies()
    {
        using var ws = new AssemblyWorkspace();
        ws.LoadDirectory(RealData.Path(RealData.AssemblyDir), false);
        var graph = new CallGraphService(ws);
        ws.Read(() => { graph.EnsureBuilt(default); return 0; });
        var target = RealData.Get(RealData.CallPathTarget) is { } named
            ? ws.Read(() => (MethodDef)SymbolResolver.ResolveOne(ws, null, named).Member)
            : ws.Read(() => ws.Assemblies.Where(RealData.IsAppAssembly).MaxBy(a => a.Module.GetTypes().Count())!
                .Module.GetTypes().Where(t => !t.Name.String.Contains('<') && !t.HasGenericParameters).SelectMany(t => t.Methods)
                .Where(m => m.HasBody && !m.Name.String.Contains('<')).Take(2000)
                .FirstOrDefault(m => graph.Paths(null, m, 6, 1, default).Any(p => p.Count > 2)));
        Assert.True(target != null, "no app method is reachable from an entry point; set CORVUS_CALLPATH_TARGET");
        long visits = graph.SearchVisits;
        var sw = Stopwatch.StartNew();
        var paths = ws.Read(() => graph.Paths(null, target, 12, 5, default));
        var took = sw.Elapsed;
        // The backward search is linear: the direct and the virtual pass each take a method off the queue at most once.
        int methods = ws.Read(() => ws.Assemblies.Sum(a => a.Module.GetTypes().Sum(t => t.Methods.Count)));
        Assert.InRange(graph.SearchVisits - visits, 1, 2L * methods);
        PerfBudget.Time("dotnet/call-path-search", took, TimeSpan.FromSeconds(10), output);
        Assert.All(paths, p => Assert.Equal(target, p.Last()));
        Assert.NotEmpty(paths);
        foreach (var p in paths) // every step is a real call edge, direct or virtual
            for (int i = 0; i + 1 < p.Count; i++)
                Assert.Contains(Format.MemberLabel(p[i]),
                    ws.Read(() => graph.Tree(ws.Assemblies.First(), p[i + 1], true, 1, 5000, false, default)));
    }
}
