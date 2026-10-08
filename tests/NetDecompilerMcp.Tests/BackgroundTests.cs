using dnlib.DotNet;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

public class BackgroundTests
{
    [Fact]
    public void IndexingWarmsCachesAndBuildsTheCallGraph()
    {
        using var ws = new AssemblyWorkspace();
        var graph = new CallGraphService(ws);
        using var indexing = new IndexingService(ws, graph, new ServerOptions());
        ws.Load(typeof(ModuleDefMD).Assembly.Location); // large enough to keep indexing busy
        Assert.True(indexing.WaitForIdle(TimeSpan.FromMinutes(2)));
        Assert.Equal("done", indexing.Status);
        Assert.True(ws.Read(() => graph.IsBuilt));
    }

    [Fact]
    public void EditsAreNotBlockedOrBrokenByIndexing()
    {
        using var env = new Env(typeof(ModuleDefMD).Assembly.Location);
        var graph = new CallGraphService(env.Workspace);
        using var indexing = new IndexingService(env.Workspace, graph, new ServerOptions());
        indexing.Start();
        for (int i = 0; i < 5; i++)
            env.Edit(() => env.Edits.StubMethod(env.One("dnlib.DotNet.UTF8String::ToString()"), $"\"v{i}\""));
        Assert.True(indexing.WaitForIdle(TimeSpan.FromMinutes(2)));
        Assert.Equal(5, env.Fixture.Edits.Count);
    }

    [Fact]
    public async Task FileChangesReloadCleanAssembliesAndProtectEditedOnes()
    {
        using var dir = new TempDir();
        var path = dir.File("TestFixture.dll");
        File.Copy(Env.FixturePath, path);
        var patched = dir.File("patched.dll");
        using (var build = new Env())
        {
            build.Edit(() => build.Edits.Rename(build.One("Shop::Describe"), "DescribeV2"));
            build.Edits.Save(build.Fixture, patched, false);
        }

        using var ws = new AssemblyWorkspace();
        using var watcher = new FileWatchService(ws, new ServerOptions());
        ws.Load(path);
        File.Copy(patched, path, overwrite: true);
        Assert.True(await Eventually(() => ws.Read(() => ws.Assemblies.Single().Module.Find("Fixture.Model.Shop", false)?.FindMethod("DescribeV2") != null)));
        Assert.Contains(ws.DrainNotices(), n => n.Contains("reloaded"));

        // With unsaved edits the assembly is not reloaded; the client is told instead.
        var edits = new EditService(ws, new IlAssembler(ws), new CSharpPatcher(ws, new DecompilerService(ws, new ServerOptions())));
        ws.Write(() => edits.StubMethod(SymbolResolver.ResolveOne(ws, null, "Account::Score"), "1"));
        File.Copy(Env.FixturePath, path, overwrite: true);
        Assert.True(await Eventually(() => ws.DrainNotices() is { Count: > 0 } n && n.Any(x => x.Contains("unsaved edit"))));
        Assert.True(ws.Read(() => ws.Assemblies.Single().IsDirty));
    }

    private static async Task<bool> Eventually(Func<bool> condition)
    {
        for (int i = 0; i < 100; i++)
        {
            if (condition()) return true;
            await Task.Delay(100);
        }
        return false;
    }
}
