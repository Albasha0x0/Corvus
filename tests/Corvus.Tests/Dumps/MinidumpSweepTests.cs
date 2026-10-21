using System.Diagnostics;
using Corvus.Core;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Every crash dump found on this machine (WER and CrashDumps folders): read, summarized and walked without an internal error.</summary>
[Trait("Speed", "Slow")]
[Collection(SweepCollection.Name)]
public sealed class MinidumpSweepTests(ITestOutputHelper output)
{
    private static IEnumerable<string> Dumps()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var common = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string[] roots =
        [
            local.Length > 0 ? Path.Combine(local, "CrashDumps") : "",
            common.Length > 0 ? Path.Combine(common, "Microsoft", "Windows", "WER") : "",
            windows.Length > 0 ? Path.Combine(windows, "Minidump") : "",
        ];
        return roots.Where(r => r.Length > 0 && Directory.Exists(r))
            .SelectMany(r => MsvcCorpus.SafeFiles(r, "*", recursive: true))
            .Where(f => f.EndsWith(".dmp", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".mdmp", StringComparison.OrdinalIgnoreCase))
            .Take(60);
    }

    [Fact]
    public async Task LocalCrashDumpsAreReadAndWalked() => await Sweep(Dumps().ToList());

    [Fact]
    public async Task A_dump_deleted_during_the_sweep_is_counted_not_failed()
    {
        using var dir = new TempDir();
        var core = dir.File("app.core");
        File.WriteAllBytes(core, SyntheticCore.Core(arm64: false));
        var (dumps, disappeared) = await Sweep([core, dir.File("pruned.dmp")]);
        Assert.Equal((1, 1), (dumps, disappeared));
        // a sweep that reads none of the dumps still there fails
        File.WriteAllBytes(dir.File("unreadable.dmp"), new byte[64]);
        await Assert.ThrowsAsync<Xunit.Sdk.TrueException>(() => Sweep([dir.File("unreadable.dmp"), dir.File("pruned.dmp")]));
    }

    /// <summary>Summarizes and walks each dump: the dumps read and the dumps gone by the time they were opened.</summary>
    private async Task<(int Dumps, int Disappeared)> Sweep(List<string> found)
    {
        using var service = new MinidumpService();
        int dumps = 0, rejected = 0, disappeared = 0, threads = 0, frames = 0, heuristic = 0, withException = 0;
        var stops = new Dictionary<string, int>();
        var sw = Stopwatch.StartNew();
        foreach (var path in found)
        {
            MinidumpService.DumpReport summary;
            try { summary = await service.Summarize(path, null, default); }
            // Windows Error Reporting prunes these folders on its own: a dump deleted mid-sweep is skipped, not failed
            catch (ToolError) when (!File.Exists(path)) { disappeared++; continue; }
            catch (ToolError e) when (e.Code is ErrorCode.MalformedInput or ErrorCode.Unsupported or ErrorCode.IoError)
            {
                rejected++;
                output.WriteLine($"rejected {Path.GetFileName(path)}: {e.Message}");
                continue;
            }
            dumps++;
            if (summary.Exception is { } e2)
            {
                withException++;
                output.WriteLine($"{Path.GetFileName(path)}: {summary.System?.Architecture} {e2.Name ?? e2.Code} {e2.Description} at {e2.Symbol} [{e2.SymbolSource}] {e2.Instruction}");
            }
            foreach (var issue in summary.Issues!) output.WriteLine($"  issue: {issue}");
            for (int i = 0; i < Math.Min(summary.Counts!.Threads, 64); i++)
            {
                MinidumpService.StackReport stack;
                try { stack = await service.Stack(path, $"#{i}", true, 256, 0, 256, null, default); }
                catch (ToolError) when (!File.Exists(path)) { disappeared++; dumps--; break; }
                threads++;
                frames += stack.Items.Count;
                heuristic += stack.ScannedFrames;
                stops[stack.Stop] = stops.GetValueOrDefault(stack.Stop) + 1;
                if (summary.Exception != null && stack.ThreadId == summary.Exception.ThreadId)
                    output.WriteLine("  " + string.Join(" > ", stack.Items.Take(8).Select(f => f.Symbol ?? f.Address)));
            }
        }
        if (disappeared > 0) output.WriteLine($"{disappeared} dumps disappeared during the sweep");
        Assert.True(found.Count == disappeared || dumps > 0, $"none of the {found.Count - disappeared} dumps found could be read");
        output.WriteLine($"{dumps} dumps ({withException} with an exception, {rejected} rejected), {threads} threads, {frames} frames ({heuristic} heuristic) in {sw.ElapsedMilliseconds} ms; " +
                         "stops: " + string.Join(", ", stops.OrderByDescending(kv => kv.Value).Select(kv => $"{kv.Key} {kv.Value}")));
        return (dumps, disappeared);
    }
}
