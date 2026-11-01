using dnlib.DotNet;
using Corvus.Core;
using Corvus.Services;

namespace Corvus.Tests;

public class BackgroundTests
{
    [Fact]
    public void Indexing_warms_caches_and_builds_the_call_graph()
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
    public void Indexing_then_get_call_tree_builds_the_call_graph_once()
    {
        using var env = new Env(typeof(ModuleDefMD).Assembly.Location);
        var graph = new CallGraphService(env.Workspace);
        using var indexing = new IndexingService(env.Workspace, graph, new ServerOptions());
        indexing.Start();
        var method = env.One("dnlib.DotNet.UTF8String::ToString()");
        env.Workspace.Read(() => graph.Tree(method.Assembly, (MethodDef)method.Member, true, 1, 50, false, default));
        Assert.True(indexing.WaitForIdle(TimeSpan.FromMinutes(2)));
        Assert.Equal(1, graph.BuildCount);
    }

    [Fact]
    public async Task A_cancelled_lock_holder_leaves_the_build_to_the_other_waiter()
    {
        using var env = new Env(typeof(ModuleDefMD).Assembly.Location);
        var graph = new CallGraphService(env.Workspace);
        var other = Task.Run(() => graph.EnsureBuilt(default));
        using var cts = new CancellationTokenSource();
        var holder = Task.Run(() =>
        {
            try { env.Workspace.Read(() => graph.EnsureBuilt(cts.Token)); }
            catch (OperationCanceledException) { }
        });
        cts.CancelAfter(TimeSpan.FromMilliseconds(50));
        await holder.WaitAsync(TimeSpan.FromMinutes(2));
        Assert.True(await other.WaitAsync(TimeSpan.FromMinutes(2)));
    }

    [Fact]
    public void A_finished_pass_notifies_once()
    {
        using var env = new Env(typeof(ModuleDefMD).Assembly.Location);
        var graph = new CallGraphService(env.Workspace);
        using var indexing = new IndexingService(env.Workspace, graph, new ServerOptions());
        indexing.Start();
        Assert.True(indexing.WaitForIdle(TimeSpan.FromMinutes(2)));
        var notices = env.Workspace.DrainNotices();
        Assert.Single(notices, n => n.StartsWith("Indexing done", StringComparison.Ordinal));
    }

    [Fact]
    public void A_failed_pass_notifies_with_the_reason()
    {
        using var env = new Env(typeof(ModuleDefMD).Assembly.Location);
        var graph = new CallGraphService(env.Workspace);
        using var indexing = new IndexingService(env.Workspace, graph, new ServerOptions())
        {
            PassProbe = _ => throw new InvalidOperationException("probe"),
        };
        indexing.Start();
        Assert.True(indexing.WaitForIdle(TimeSpan.FromMinutes(2)));
        Assert.Single(env.Workspace.DrainNotices(), n => n.StartsWith("Indexing failed (probe)", StringComparison.Ordinal));
    }

    [Fact]
    public void A_superseded_pass_sends_no_notice()
    {
        using var env = new Env(typeof(ModuleDefMD).Assembly.Location);
        var graph = new CallGraphService(env.Workspace);
        using var indexing = new IndexingService(env.Workspace, graph, new ServerOptions());
        var started = new ManualResetEventSlim();
        // The first pass blocks until the second Start cancels it.
        indexing.PassProbe = ct =>
        {
            indexing.PassProbe = null;
            started.Set();
            ct.WaitHandle.WaitOne();
        };
        indexing.Start();
        Assert.True(started.Wait(TimeSpan.FromMinutes(1)));
        indexing.Start();
        Assert.True(indexing.WaitForIdle(TimeSpan.FromMinutes(2)));
        var notice = Assert.Single(env.Workspace.DrainNotices());
        Assert.StartsWith("Indexing done", notice, StringComparison.Ordinal);
    }

    [Fact]
    public void Edits_are_not_blocked_or_broken_by_indexing()
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
    public async Task File_changes_reload_clean_assemblies_and_protect_edited_ones()
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
        // The notice follows the reload, so the new assembly can be seen a moment before it.
        var notices = new List<string>();
        Assert.True(await Eventually(() => { notices.AddRange(ws.DrainNotices()); return notices.Any(n => n.Contains("reloaded")); }), string.Join("\n", notices));

        // With unsaved edits the assembly is not reloaded; the client is told instead.
        var edits = new EditService(ws, new IlAssembler(ws), new CSharpPatcher(ws, new DecompilerService(ws)));
        ws.Write(() => edits.StubMethod(SymbolResolver.ResolveOne(ws, null, "Account::Score"), "1"));
        File.Copy(Env.FixturePath, path, overwrite: true);
        Assert.True(await Eventually(() => ws.DrainNotices() is { Count: > 0 } n && n.Any(x => x.Contains("unsaved edit"))));
        Assert.True(ws.Read(() => ws.Assemblies.Single().IsDirty));
    }

    [WindowsFact]
    public async Task Native_images_reload_on_change_unless_patched()
    {
        using var dir = new TempDir();
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var wow = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
        var path = dir.File("version.dll");
        File.Copy(Path.Combine(system, "version.dll"), path);
        using var ws = new AssemblyWorkspace();
        using var watcher = new FileWatchService(ws, new ServerOptions());
        var native = ws.LoadAny(path).Native!;
        Assert.Equal(Corvus.Native.NativeArch.X64, native.Image.Arch);

        // Same content: no reload. Different content: reloaded.
        File.SetLastWriteTimeUtc(path, DateTime.UtcNow);
        File.Copy(Path.Combine(wow, "version.dll"), path, overwrite: true);
        Assert.True(await Eventually(() => ws.Read(() => ws.FindNative(path)?.Image.Arch == Corvus.Native.NativeArch.X86)));
        var notices = new List<string>();
        Assert.True(await Eventually(() => { notices.AddRange(ws.DrainNotices()); return notices.Any(n => n.Contains("reloaded")); }), string.Join("\n", notices));

        // With unsaved patches the image is not reloaded; the client is told instead.
        var current = ws.Read(() => ws.FindNative(path)!);
        var code = new NativeCodeService(ws, new ServerOptions { BackgroundIndexing = false }, annotations: new Corvus.Native.Annotations.AnnotationStore(dir.File("ann")));
        var edits = new NativeEditService(ws, code);
        var index = await code.Index(current, null, default);
        var prepared = edits.PreparePatch(index, current.Image.EntryPointRva, [0xC3], force: true, "ret");
        ws.Write(() => edits.ApplyPatch(current, index, prepared, dryRun: false));
        File.Copy(Path.Combine(system, "version.dll"), path, overwrite: true);
        Assert.True(await Eventually(() => ws.DrainNotices() is { Count: > 0 } n && n.Any(x => x.Contains("unsaved patches"))));
        Assert.Equal(Corvus.Native.NativeArch.X86, ws.Read(() => ws.FindNative(path)!.Image.Arch));
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
