using System.Diagnostics;
using System.Text.RegularExpressions;
using Xunit.Abstractions;
using static Corvus.Tests.ToolRealDataTests;

namespace Corvus.Tests;

/// <summary>
/// The completion pass after a standard-profile Ghidra open: it runs while the worker is idle, a request during it is
/// answered without waiting for the pass, and status ends at standard→full. A private analysis cache: the pass stamps the project.
/// </summary>
[Trait("Speed", "Slow")]
public sealed class CompletionPassTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [GhidraFact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public async Task The_pass_yields_to_requests_and_ends_full()
    {
        var image = _dir.File("jitinterface_x64.dll");
        File.Copy(RealPackages.File("runtime.win-x64.Microsoft.DotNet.ILCompiler", "10.0.11", "tools", "jitinterface_x64.dll"), image);
        await using var c = await McpProtocolTests.StartServerAsync(_dir.Path, null, [],
            new Dictionary<string, string?> { ["CORVUS_GHIDRA_COMPLETION"] = "on", [Corvus.Native.Providers.AnalysisCache.RootVariable] = _dir.File("cache") });
        await Call(c, "load_assembly", new() { ["path"] = image });
        var (_, functions) = await Call(c, "list_functions", new() { ["image"] = "jitinterface_x64.dll", ["engine"] = "ghidra", ["limit"] = 400 });
        var addresses = functions.GetProperty("items").EnumerateArray().Select(f => f.GetProperty("address").GetString()!).ToList();
        string status = "";
        var clock = Stopwatch.StartNew();
        double slowest = 0;
        int beside = 0;
        for (int i = 0; clock.Elapsed < TimeSpan.FromMinutes(5); i++)
        {
            var call = Stopwatch.StartNew();
            await Call(c, "find_xrefs", new() { ["image"] = "jitinterface_x64.dll", ["address"] = addresses[i % addresses.Count], ["engine"] = "ghidra" });
            slowest = Math.Max(slowest, call.Elapsed.TotalSeconds);
            (status, _) = await Call(c, "get_engine_status", new() { ["image"] = "jitinterface_x64.dll" });
            if (Regex.Match(status, @"([\d,]+) requests ran beside a slice") is { Success: true } m) beside = Math.Max(beside, int.Parse(m.Groups[1].Value.Replace(",", "")));
            if (status.Contains("standard→full")) break;
            await Task.Delay(2000);
        }
        output.WriteLine($"{clock.Elapsed.TotalSeconds:0} s; slowest find_xrefs during the pass {slowest:0.00} s\n{status}");
        Assert.Contains("profile standard→full", status);
        // Reads share the program with a running slice instead of waiting for it.
        Assert.True(beside > 0, "no request ran beside a slice of the pass");
        PerfBudget.AtMost("engines/completion-pass-request", slowest, 5, "s", output, $"{beside} requests beside a slice");
    }
}
