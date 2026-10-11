using System.Diagnostics;
using Corvus.Core;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Every crash dump found on this machine (WER and CrashDumps folders): read, summarized and walked without an internal error.</summary>
[Trait("Speed", "Slow")]
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
    public async Task LocalCrashDumpsAreReadAndWalked()
    {
        var service = new MinidumpService();
        int dumps = 0, rejected = 0, threads = 0, frames = 0, heuristic = 0, withException = 0;
        var stops = new Dictionary<string, int>();
        var sw = Stopwatch.StartNew();
        foreach (var path in Dumps())
        {
            MinidumpService.DumpSummary summary;
            try { summary = await service.Summarize(path, null, 0, 1000, 0, 1000, default); }
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
            foreach (var issue in summary.Issues) output.WriteLine($"  issue: {issue}");
            for (int i = 0; i < Math.Min(summary.ThreadCount, 64); i++)
            {
                var stack = await service.Stack(path, $"#{i}", true, 256, 0, 256, null, default);
                threads++;
                frames += stack.Frames.Count;
                heuristic += stack.HeuristicFrames;
                stops[stack.Stop] = stops.GetValueOrDefault(stack.Stop) + 1;
                if (summary.Exception != null && stack.ThreadId == summary.Exception.ThreadId)
                    output.WriteLine("  " + string.Join(" > ", stack.Frames.Take(8).Select(f => f.Symbol ?? f.Address)));
            }
        }
        output.WriteLine($"{dumps} dumps ({withException} with an exception, {rejected} rejected), {threads} threads, {frames} frames ({heuristic} heuristic) in {sw.ElapsedMilliseconds} ms; " +
                         "stops: " + string.Join(", ", stops.OrderByDescending(kv => kv.Value).Select(kv => $"{kv.Key} {kv.Value}")));
    }
}
