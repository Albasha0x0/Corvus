using System.Diagnostics;
using dnlib.DotNet;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

/// <summary>Timing-sensitive real-game checks run alone (after the parallel tests), so CPU contention can't skew them.</summary>
[CollectionDefinition(nameof(SerialTimingTests), DisableParallelization = true)]
public class SerialTimingCollection;

[Collection(nameof(SerialTimingTests))]
public class SerialTimingTests
{
    private const string GameDlls = @"C:\work\ModHost\dlls";

    /// <summary>A real game's call graph is full of cycles: the path search must stay linear, not enumerate every path.</summary>
    [RequiresPathFact(GameDlls)]
    public void PathSearchIsFastOnARealGame()
    {
        using var ws = new AssemblyWorkspace();
        ws.LoadDirectory(GameDlls, false);
        var graph = new CallGraphService(ws);
        ws.Read(() => { graph.EnsureBuilt(default); return 0; });
        var target = ws.Read(() => (MethodDef)SymbolResolver.ResolveOne(ws, null, "XDTGameSystem.GameplaySystem.Tool.ToolSystem::GetCurrentTool").Member);
        var sw = Stopwatch.StartNew();
        var paths = ws.Read(() => graph.Paths(null, target, 12, 5, default));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"{sw.Elapsed}");
        Assert.All(paths, p => Assert.Equal(target, p.Last()));
        Assert.NotEmpty(paths);
        foreach (var p in paths) // every step is a real call edge (direct or through a base/interface method)
            for (int i = 0; i + 1 < p.Count; i++)
                Assert.Contains($"{p[i].DeclaringType.FullName.Replace('/', '+')}::{p[i].Name}(",
                    ws.Read(() => graph.Tree(ws.Assemblies.First(), p[i + 1], true, 1, 5000, false, default)));
    }
}
