using System.Collections.Concurrent;
using System.Diagnostics;
using Corvus.Native.Pe;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Every native tool on real Windows images, in process: System32, SysWOW64, Program Files and the largest native images
/// found. Each call must succeed or fail with a typed error that fits the input, within its time limit, with a bounded
/// result; memory must return to the baseline after the images are unloaded.
/// NDM_NATIVE_TOOL_SWEEP_LIMIT caps the files per directory (default 120; 0 = all); NDM_NATIVE_TOOL_SWEEP_IDA the number of
/// images also decompiled through IDA (default 2, when IDA is installed). Images of 64 MB and more run one at a time with their memory sampled.
/// </summary>
[Trait("Speed", "Slow")]
[Collection(SweepCollection.Name)]
public class NativeToolSweepTests(ITestOutputHelper output)
{
    private static int Limit => int.TryParse(Environment.GetEnvironmentVariable("NDM_NATIVE_TOOL_SWEEP_LIMIT"), out var l) ? l : 120;
    /// <summary>Program Files holds tens of thousands of images: NDM_NATIVE_TOOL_SWEEP_PF_LIMIT per root (default 120; 0 = all).</summary>
    private static int ProgramFilesLimit => int.TryParse(Environment.GetEnvironmentVariable("NDM_NATIVE_TOOL_SWEEP_PF_LIMIT"), out var l) ? l : 120;
    private static int IdaSample => int.TryParse(Environment.GetEnvironmentVariable("NDM_NATIVE_TOOL_SWEEP_IDA"), out var n) ? n : 2;
    private static readonly string Windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    /// <summary>Images from this size on run alone, with their memory sampled.</summary>
    private const long LargeImage = 64L << 20;
    /// <summary>Runaway bound of a large image: GC heap (live and not yet collected) at most this many bytes per file byte, plus 1 GB.</summary>
    private const long MaxHeapPerFileByte = 16;

    public static List<string> Sample(IEnumerable<string> files, int limit)
    {
        var all = files.Order(StringComparer.OrdinalIgnoreCase).ToList();
        if (limit <= 0 || all.Count <= limit) return all;
        double step = (double)all.Count / limit;
        return Enumerable.Range(0, limit).Select(i => all[(int)(i * step)]).ToList();
    }

    [WindowsFact]
    public Task System32() => Sweep("System32", Sample(NativeToolHarness.NativeFiles(Path.Combine(Windows, "System32")), Limit), IdaSample);

    [WindowsFact]
    public Task System32_Drivers() => Sweep("System32\\drivers", Sample(NativeToolHarness.NativeFiles(Path.Combine(Windows, "System32", "drivers")), Limit / 3), 0);

    [WindowsFact]
    public Task SysWow64() => Sweep("SysWOW64", Sample(NativeToolHarness.NativeFiles(Path.Combine(Windows, "SysWOW64")), Limit), IdaSample > 0 ? 1 : 0);

    [WindowsFact]
    public Task ProgramFiles()
    {
        var files = new List<string>();
        foreach (var folder in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 }.Select(Environment.GetFolderPath).Distinct())
            if (folder.Length > 0) files.AddRange(Sample(NativeToolHarness.NativeFiles(folder, recursive: true), ProgramFilesLimit));
        return Sweep("Program Files", files, 0);
    }

    /// <summary>The three largest native images under Program Files and System32 (up to the parser's file size limit).</summary>
    [WindowsFact]
    public Task Largest()
    {
        var roots = new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Path.Combine(Windows, "System32") }.Where(r => r.Length > 0).Distinct();
        var candidates = roots.SelectMany(r => EnumerateLarge(r, 8_000_000)).Where(f => NativeToolHarness.IsNativePe(f))
            .DistinctBy(f => Path.GetFileName(f).ToLowerInvariant())
            .OrderByDescending(f => new FileInfo(f).Length).Take(15).ToList();
        // The three largest files, and the two with the most code among the fifteen largest (huge DLLs are often mostly data).
        var largest = candidates.Take(3).ToList();
        largest.AddRange(candidates.Skip(3).OrderByDescending(CodeBytes).Take(2));
        return Sweep("largest", largest, IdaSample > 0 ? 1 : 0, workers: 1, indexLimit: TimeSpan.FromMinutes(5));
    }

    private static long CodeBytes(string path)
    {
        try { return PeFile.Open(path).Sections.Where(s => s.IsExecutable).Sum(s => (long)Math.Min(s.RawSize, s.MappedSize)); }
        catch (Core.ToolError) { return 0; }
    }

    private static IEnumerable<string> EnumerateLarge(string root, long minSize)
    {
        var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        IEnumerable<FileInfo> files;
        try { files = new DirectoryInfo(root).EnumerateFiles("*", options).ToList(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
        return files.Where(f => f.Length >= minSize && f.Length <= PeLimits.MaxFileSize && f.Extension.ToLowerInvariant() is ".dll" or ".exe").Select(f => f.FullName);
    }

    private async Task Sweep(string label, List<string> files, int ida, int workers = 0, TimeSpan? indexLimit = null)
    {
        if (files.Count == 0) { output.WriteLine($"{label}: no native images found"); return; }
        workers = workers > 0 ? workers : Math.Clamp(Environment.ProcessorCount / 2, 2, 12);
        GC.Collect();
        GC.WaitForPendingFinalizers();
        long baseline = GC.GetTotalMemory(true);
        // Large images run one at a time after the others, with memory sampled while their tools run.
        var queue = new ConcurrentQueue<(string File, bool Ida)>(files.Where(f => SafeLength(f) < LargeImage).Select((f, i) => (f, i < ida)));
        var large = files.Where(f => SafeLength(f) >= LargeImage).ToList();
        var calls = new ConcurrentBag<NativeToolHarness.Call>();
        var perFile = new ConcurrentBag<(string File, long Bytes, TimeSpan Elapsed, long Heap)>();
        long peakHeap = 0, peakWorkingSet = 0;
        string peakHeapFile = "";
        var clock = Stopwatch.StartNew();
        await Task.WhenAll(Enumerable.Range(0, workers).Select(_ => Task.Run(async () =>
        {
            using var harness = new NativeToolHarness();
            while (queue.TryDequeue(out var item))
            {
                var sw = Stopwatch.StartNew();
                try { await harness.Exercise(item.File, item.Ida, indexLimit: indexLimit); }
                catch (Exception ex) { calls.Add(new(item.File, "harness", "", sw.Elapsed, 0, null, null, ex, false)); }
                long heap = GC.GetGCMemoryInfo().HeapSizeBytes;
                long ws = Process.GetCurrentProcess().WorkingSet64;
                lock (perFile)
                {
                    if (heap > peakHeap) { peakHeap = heap; peakHeapFile = item.File; }
                    peakWorkingSet = Math.Max(peakWorkingSet, ws);
                }
                perFile.Add((item.File, SafeLength(item.File), sw.Elapsed, heap));
            }
            foreach (var c in harness.Calls) calls.Add(c);
        })));
        var runaway = new List<string>();
        foreach (var file in large)
        {
            // The previous image's garbage is collected first so the sample counts this image only.
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            using var harness = new NativeToolHarness();
            // Live data, not the heap: garbage awaiting collection grows with how late the GC runs on a busy machine.
            // Each full collection's survivors are a lower bound of the peak, so a reading never exceeds what the image kept alive.
            long fileHeap = 0, filePrivate = 0;
            void Survivors(GCKind kind)
            {
                var gc = GC.GetGCMemoryInfo(kind);
                if (gc.Index > 0 && gc.Generation == 2) fileHeap = Math.Max(fileHeap, gc.PromotedBytes);
            }
            using var sampling = new CancellationTokenSource();
            var sampler = Task.Run(async () =>
            {
                while (!sampling.IsCancellationRequested)
                {
                    Survivors(GCKind.FullBlocking);
                    Survivors(GCKind.Background);
                    filePrivate = Math.Max(filePrivate, Process.GetCurrentProcess().PrivateMemorySize64);
                    try { await Task.Delay(100, sampling.Token); } catch (OperationCanceledException) { }
                }
            });
            var sw = Stopwatch.StartNew();
            try { await harness.Exercise(file, ida: false, indexLimit: indexLimit ?? TimeSpan.FromMinutes(5)); }
            catch (Exception ex) { calls.Add(new(file, "harness", "", sw.Elapsed, 0, null, null, ex, false)); }
            sampling.Cancel();
            await sampler;
            fileHeap = Math.Max(fileHeap, GC.GetTotalMemory(true));
            foreach (var c in harness.Calls) calls.Add(c);
            long bytes = SafeLength(file);
            var index = harness.Calls.FirstOrDefault(c => c.Tool == "list_functions" && c.Args == "");
            output.WriteLine($"  large: {Path.GetFileName(file)} {bytes >> 20} MB: all tools {sw.Elapsed.TotalSeconds:0.0} s, index wait {index?.Elapsed.TotalSeconds:0.0} s, " +
                             $"peak live heap {fileHeap >> 20} MB, peak private bytes {filePrivate >> 20} MB");
            perFile.Add((file, bytes, sw.Elapsed, fileHeap));
            peakWorkingSet = Math.Max(peakWorkingSet, filePrivate);
            if (fileHeap > peakHeap) { peakHeap = fileHeap; peakHeapFile = file; }
            if (fileHeap > MaxHeapPerFileByte * bytes + (1L << 30)) runaway.Add($"{Path.GetFileName(file)}: {fileHeap >> 20} MB heap for {bytes >> 20} MB");
        }
        clock.Stop();
        GC.Collect();
        GC.WaitForPendingFinalizers();
        // Index builds cancelled by the last unloads stop at their next cancellation check (seconds on the largest images).
        long retained = GC.GetTotalMemory(true) - baseline;
        for (int wait = 0; wait < 30 && retained >= 400L << 20; wait++)
        {
            await Task.Delay(1000);
            retained = GC.GetTotalMemory(true) - baseline;
        }

        var all = calls.ToList();
        var failures = all.Where(c => c.Failed).ToList();
        var oversize = all.Where(c => c.Chars > NativeToolHarness.MaxChars).ToList();
        output.WriteLine($"{label}: {files.Count} images, {all.Count} tool calls, {workers} workers, {clock.Elapsed.TotalSeconds:0.0} s");
        output.WriteLine($"  outcomes: ok {all.Count(c => c.Error == null && c.Unexpected == null)}, " +
                         string.Join(", ", all.Where(c => c.Error != null).GroupBy(c => c.Tool + ":" + c.Error).OrderByDescending(g => g.Count()).Select(g => $"{g.Key} {g.Count()}")));
        output.WriteLine($"  peak GC heap {peakHeap >> 20} MB (after {Path.GetFileName(peakHeapFile)}), peak working set {peakWorkingSet >> 20} MB, retained after unload {retained >> 20} MB");
        output.WriteLine("  slowest images: " + string.Join(", ", perFile.OrderByDescending(p => p.Elapsed).Take(5).Select(p => $"{Path.GetFileName(p.File)} ({p.Bytes >> 20} MB) {p.Elapsed.TotalSeconds:0.0} s")));
        foreach (var c in all.OrderByDescending(c => c.Elapsed).Take(10)) output.WriteLine($"  slow call: {Path.GetFileName(c.File)} {c.Tool}({c.Args}) {c.Elapsed.TotalSeconds:0.00} s");
        foreach (var c in all.Where(c => c.Tool == "list_functions" && c.Args == "").OrderByDescending(c => c.Elapsed).Take(3))
            output.WriteLine($"  index wait: {Path.GetFileName(c.File)} {c.Elapsed.TotalSeconds:0.0} s");
        foreach (var c in oversize.Take(20)) output.WriteLine($"OVERSIZE {c.Tool}({c.Args}) on {Path.GetFileName(c.File)}: {c.Chars} chars");
        foreach (var c in failures.Take(60)) output.WriteLine("FAIL " + c);
        foreach (var g in all.Where(c => c.Error != null && !c.Failed).GroupBy(c => (c.Tool, c.Error)).Take(40))
            output.WriteLine($"  typed {g.Key.Tool} {g.Key.Error}: e.g. {g.First().ErrorText?.Split('\n')[0]} ({Path.GetFileName(g.First().File)} {g.First().Args})");
        Assert.True(failures.Count == 0, $"{failures.Count} failed calls; first: {failures.FirstOrDefault()}");
        Assert.Empty(oversize);
        Assert.True(runaway.Count == 0, "memory: " + string.Join("; ", runaway));
        Assert.True(retained < 400L << 20, $"{retained >> 20} MB retained after unloading every image");
    }

    private static long SafeLength(string path)
    {
        try { return new FileInfo(path).Length; }
        catch (IOException) { return 0; }
    }
}
