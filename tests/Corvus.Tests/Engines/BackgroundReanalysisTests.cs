using System.Diagnostics;
using Xunit.Abstractions;
using static Corvus.Tests.ToolRealDataTests;

namespace Corvus.Tests;

/// <summary>reanalyze_native wait=false: returns at once, other engine calls get conflict with retryAfterMs, status shows the result.</summary>
[Trait("Speed", "Slow")]
public sealed class BackgroundReanalysisTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [GhidraFact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public async Task A_background_reanalysis_holds_the_engine_until_it_ends()
    {
        var image = _dir.File("jitinterface_x64.dll");
        File.Copy(RealPackages.File("runtime.win-x64.Microsoft.DotNet.ILCompiler", "10.0.11", "tools", "jitinterface_x64.dll"), image);
        await using var c = await McpProtocolTests.StartServerAsync(_dir.Path, null, [],
            new Dictionary<string, string?> { [Corvus.Native.Providers.AnalysisCache.RootVariable] = _dir.File("cache") });
        await Call(c, "load_assembly", new() { ["path"] = image });
        var (_, functions) = await Call(c, "list_functions", new() { ["image"] = "jitinterface_x64.dll", ["engine"] = "ghidra", ["limit"] = 1 });
        var function = functions.GetProperty("items")[0].GetProperty("address").GetString()!;
        var clock = Stopwatch.StartNew();
        var (started, _) = await Call(c, "reanalyze_native", new() { ["image"] = "jitinterface_x64.dll", ["engine"] = "ghidra", ["preset"] = "full", ["background"] = true });
        output.WriteLine($"{clock.Elapsed.TotalSeconds:0.0} s: {started}");
        PerfBudget.Check(clock.Elapsed < TimeSpan.FromSeconds(2), $"wait=false took {clock.Elapsed.TotalSeconds:0.0} s", output);
        Assert.Contains("WindowsResourceReference=true", started);
        var busy = await c.CallToolAsync("find_xrefs", new Dictionary<string, object?> { ["image"] = "jitinterface_x64.dll", ["address"] = function, ["engine"] = "ghidra" });
        var text = string.Concat(busy.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(b => b.Text));
        output.WriteLine(text);
        Assert.True(busy.IsError);
        Assert.Contains("conflict", text);
        Assert.Contains("retryAfterMs", text);
        string status = "";
        for (var wait = Stopwatch.StartNew(); wait.Elapsed < TimeSpan.FromMinutes(5);)
        {
            (status, _) = await Call(c, "get_engine_status", new() { ["image"] = "jitinterface_x64.dll", ["engine"] = "ghidra" });
            if (status.Contains("background reanalysis ended")) break;
            await Task.Delay(1000);
        }
        output.WriteLine(status);
        Assert.Contains("background reanalysis ended", status);
        Assert.Contains("complete", status);
        await Call(c, "find_xrefs", new() { ["image"] = "jitinterface_x64.dll", ["address"] = function, ["engine"] = "ghidra" });
    }
}
