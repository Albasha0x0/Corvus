using System.Collections.Concurrent;
using System.Diagnostics;
using Corvus.Core;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Parallel native calls while images load, unload and reload: no deadlock, no unexpected exception, no orphan index build (CORVUS_NATIVE_STRESS_SECONDS, default 30).</summary>
[Trait("Speed", "Slow")]
public class NativeConcurrencyTests(ITestOutputHelper output)
{
    private static readonly TimeSpan Hang = TimeSpan.FromSeconds(120);

    /// <summary>Errors a call may get when its image is unloaded or replaced under it.</summary>
    private static bool Expected(ErrorCode code) => code is ErrorCode.NotLoaded or ErrorCode.NotFound or ErrorCode.Conflict;

    [WindowsFact]
    public async Task Tools_loads_unloads_and_reloads_run_in_parallel()
    {
        var seconds = int.TryParse(Environment.GetEnvironmentVariable("CORVUS_NATIVE_STRESS_SECONDS"), out var s) ? s : 30;
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var files = new[]
        {
            Path.Combine(windows, "System32", "kernel32.dll"), Path.Combine(windows, "SysWOW64", "kernel32.dll"),
            Path.Combine(windows, "System32", "msvcp_win.dll"), Path.Combine(windows, "System32", "user32.dll"),
            Path.Combine(windows, "SysWOW64", "msvcp_win.dll"),
            // Large enough that unloads land during its index build.
            Path.Combine(windows, "System32", "windows.storage.dll"), Path.Combine(windows, "SysWOW64", "windows.storage.dll"),
        }.Where(File.Exists).ToArray();
        Assert.NotEmpty(files);

        using var harness = new NativeToolHarness();
        var ws = harness.Workspace;
        var failures = new ConcurrentBag<string>();
        var holders = new ConcurrentDictionary<object, string>(ReferenceEqualityComparer.Instance);
        var counts = new ConcurrentDictionary<string, int>();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));

        async Task Guard(string what, Func<Task> call)
        {
            var task = call();
            try
            {
                await task.WaitAsync(Hang);
                counts.AddOrUpdate("ok", 1, (_, n) => n + 1);
            }
            catch (ToolError e) when (Expected(e.Code) || e.Code is ErrorCode.Unsupported or ErrorCode.InvalidArgument)
            {
                counts.AddOrUpdate(e.Code.ToString(), 1, (_, n) => n + 1);
            }
            catch (TimeoutException) { failures.Add($"{what}: no result after {Hang.TotalSeconds} s (deadlock or hang)"); }
            catch (Exception e) { failures.Add($"{what}: {e.GetType().Name}: {e.Message}\n{e.StackTrace}"); }
        }

        // Remembers every analysis object (index builds) so that the end can check none is still running.
        void Snapshot()
        {
            foreach (var n in ws.Read(() => ws.Natives))
                foreach (var a in n.Analysis.Values) holders.TryAdd(a, n.Id);
        }

        var callers = Enumerable.Range(0, 24).Select(w => Task.Run(async () =>
        {
            var rng = new Random(w);
            while (!stop.IsCancellationRequested)
            {
                var file = files[rng.Next(files.Length)];
                var id = ws.Read(() => ws.FindNative(file)?.Id) ?? file; // a path loads the image when it is not loaded
                switch (rng.Next(9))
                {
                    case 0: await Guard($"get_pe_info {id}", () => harness.Native.GetPeInfo(id)); break;
                    case 1: await Guard($"list_functions {id}", () => harness.CodeTools.ListFunctions(id, sort: "callers", limit: 20)); break;
                    case 2: await Guard($"disassemble {id}", () => harness.CodeTools.Disassemble(id, "rva:0x1000")); break;
                    case 3: await Guard($"find_xrefs {id}", () => harness.CodeTools.FindXrefs(id, "rva:0x1000")); break;
                    case 4: await Guard($"native_call_tree {id}", () => harness.CodeTools.NativeCallTree(id, "rva:0x1000", direction: rng.Next(2) == 0 ? "callers" : "callees")); break;
                    case 5: await Guard($"search_native_strings {id}", () => harness.CodeTools.SearchNativeStrings(id, "dll", limit: 10)); break;
                    case 6: await Guard($"list_cpp_classes {id}", () => harness.Analysis.ListCppClasses(id, filter: "exception")); break;
                    case 7: await Guard($"search_bytes {id}", () => harness.Native.SearchBytes(id, "48 8B ?? ?? C3", limit: 5)); break;
                    default: await Guard($"get_resource {id}", () => harness.Resources.GetResource(id, "VERSION/1")); break;
                }
                Snapshot();
            }
        })).ToList();
        var loaders = Enumerable.Range(0, 4).Select(w => Task.Run(async () =>
        {
            var rng = new Random(100 + w);
            while (!stop.IsCancellationRequested)
            {
                var file = files[rng.Next(files.Length)];
                switch (rng.Next(3))
                {
                    case 0: await Guard($"load_assembly {file}", () => harness.WorkspaceTools.LoadAssembly(file)); break;
                    case 1: await Guard($"unload_assembly {file}", () => harness.WorkspaceTools.UnloadAssembly(file)); break;
                    default: await Guard($"reload_assembly {file}", () => harness.WorkspaceTools.ReloadAssembly(file)); break;
                }
                Snapshot();
                await Task.Delay(rng.Next(50, 400));
            }
        })).ToList();
        var all = Task.WhenAll(callers.Concat(loaders));
        if (await Task.WhenAny(all, Task.Delay(TimeSpan.FromSeconds(seconds) + Hang + Hang)) != all)
            Assert.Fail("the stress tasks did not finish: deadlock");
        await all;

        // Unload everything: every index build seen must end (cancelled or done) and leave nothing behind.
        var remaining = ws.Read(() => ws.Natives);
        foreach (var n in remaining) ws.UnloadNative(n);
        var builds = holders.Keys.Select(h => h.GetType().GetProperty("Task")?.GetValue(h) as Task).OfType<Task>().ToList();
        var settled = Task.WhenAll(builds.Select(t => t.ContinueWith(_ => { }, TaskScheduler.Default)));
        bool ended = await Task.WhenAny(settled, Task.Delay(TimeSpan.FromSeconds(30))) == settled;
        output.WriteLine($"{seconds} s, {files.Length} images: " + string.Join(", ", counts.OrderByDescending(c => c.Value).Select(c => $"{c.Key} {c.Value}")) +
                         $"; {holders.Count} analysis objects, {builds.Count} index builds ({builds.Count(t => t.IsCanceled)} cancelled, {builds.Count(t => t.IsCompletedSuccessfully)} done)");
        foreach (var f in failures.Take(20)) output.WriteLine("FAIL " + f);
        Assert.True(failures.IsEmpty, $"{failures.Count} failures; first: {failures.FirstOrDefault()}");
        Assert.True(ended, $"{builds.Count(t => !t.IsCompleted)} index builds still running 30 s after every image was unloaded");
        Assert.Empty(ws.Read(() => ws.Natives));
        Assert.All(remaining, n => Assert.Empty(n.Analysis));
    }

    /// <summary>Unloading an image ends its IDA auto-analysis: the waiting decompile_native gets a conflict at once.</summary>
    [WindowsFact]
    public async Task Unload_ends_an_IDA_analysis_in_progress()
    {
        using var harness = new NativeToolHarness(backgroundIndexing: false);
        if (!harness.Engines.Providers[0].CheckAvailability().IsAvailable) return; // IDA not installed here
        var file = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64", "edgehtml.dll");
        if (!File.Exists(file)) file = Path.Combine(Environment.SystemDirectory, "windows.storage.dll");
        var native = harness.Workspace.LoadAny(file).Native!;
        var call = harness.Analysis.DecompileNative(native.Id, $"0x{native.Image.ImageBase + native.Image.EntryPointRva:X}");
        await Task.WhenAny(call, Task.Delay(TimeSpan.FromSeconds(5)));
        if (call.IsCompleted) { output.WriteLine("analysis was already saved: nothing to cancel"); return; }
        var sw = System.Diagnostics.Stopwatch.StartNew();
        harness.Workspace.UnloadNative(native);
        var e = await Assert.ThrowsAsync<ToolError>(() => call.WaitAsync(TimeSpan.FromSeconds(30)));
        Assert.Equal(ErrorCode.Conflict, e.Code);
        output.WriteLine($"decompile_native ended {sw.ElapsedMilliseconds} ms after the unload");
    }
}
