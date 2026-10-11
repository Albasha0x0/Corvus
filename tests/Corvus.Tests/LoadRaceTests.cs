using System.Collections.Concurrent;
using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>load, reload and unload of the same file race each other; only typed tool errors may come out.</summary>
public class LoadRaceTests
{
    [Fact]
    public async Task LoadReloadUnloadOfOneFileRaceSafely()
    {
        using var dir = new TempDir();
        var managed = dir.File("TestFixture.Consumer.dll");
        File.Copy(Env.ConsumerPath, managed);
        File.Copy(Env.FixturePath, dir.File("TestFixture.dll"));
        var native = dir.File("native.dll");
        File.WriteAllBytes(native, NativePeTests.KitchenSink(is64: true));

        using var ws = new AssemblyWorkspace();
        var options = new ServerOptions { BackgroundIndexing = false, WatchFiles = false };
        var il2cpp = new Il2CppService(ws);
        var tools = new WorkspaceTools(ws, il2cpp, new AssemblyReport(ws, il2cpp), new IndexingService(ws, new CallGraphService(ws), options), new UnpackService(ws));
        var unexpected = new ConcurrentBag<Exception>();
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(1);

        Task Loop(Func<Task> body) => Task.Run(async () =>
        {
            while (DateTime.UtcNow < deadline)
            {
                try { await body(); }
                catch (ToolError) { /* not loaded, replaced by another call: expected */ }
                catch (Exception ex) { unexpected.Add(ex); }
            }
        });

        await Task.WhenAll(
            Loop(() => tools.LoadAssembly(managed)), Loop(() => tools.LoadAssembly(managed)),
            Loop(() => tools.ReloadAssembly("TestFixture.Consumer")), Loop(() => tools.UnloadAssembly("TestFixture.Consumer")),
            Loop(() => tools.LoadAssembly(native)), Loop(() => tools.ReloadAssembly("native.dll")), Loop(() => tools.UnloadAssembly("native.dll")),
            Loop(() => tools.ListAssemblies()));
        Assert.Empty(unexpected.Select(e => e.ToString()));

        // Native code tools racing reloads of their image: typed errors or results, nothing else.
        var code = new NativeCodeTools(ws, new NativeCodeService(ws, new ServerOptions()), new OutputPager(options));
        await tools.LoadAssembly(native);
        deadline = DateTime.UtcNow + TimeSpan.FromSeconds(1);
        await Task.WhenAll(
            Loop(() => code.ListFunctions(native)), Loop(() => code.Disassemble(native, "First")), Loop(() => code.FindXrefs(native, "First")),
            Loop(() => tools.ReloadAssembly("native.dll")), Loop(() => tools.UnloadAssembly("native.dll")), Loop(() => tools.LoadAssembly(native)));
        Assert.Empty(unexpected.Select(e => e.ToString()));
        // Never two entries for one file.
        Assert.True(ws.Read(() => ws.Assemblies.Count(a => a.FilePath == managed) <= 1 && ws.Natives.Count(n => n.FilePath == native) <= 1));
    }
}
