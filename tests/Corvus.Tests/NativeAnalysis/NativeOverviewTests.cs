using System.Text.RegularExpressions;
using Corvus.Services.Analysis;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Checks the summarize_file overview of a native PE against get_pe_info.</summary>
public class NativeOverviewTests
{
    private const string AwaitingProjection = "Awaiting the native PE highlights of F-SUM-1.";

    // The sample is a PE with a TLS callback, a debug directory and KERNEL32 and USER32 imports.
    private static async Task<(PeSummary Pe, List<string> Highlights)> Read()
    {
        using var env = new Env();
        using var dir = new TempDir();
        var path = McpProtocolTests.NativeSample(dir);
        using var harness = new NativeToolHarness(backgroundIndexing: false);
        var peCollector = Corvus.Mcp.ToolOutput.Collect();
        await harness.Native.GetPeInfo(path);
        var pe = Assert.IsType<PeSummary>(peCollector.Value);
        var tools = new InspectionTools(new InspectionService(env.Workspace), env.Workspace);
        var collector = Corvus.Mcp.ToolOutput.Collect();
        await tools.SummarizeFile(path: path);
        var record = Assert.IsType<FileSummaryRecord>(collector.Value);
        return (pe, [.. record.Highlights ?? []]);
    }

    private static bool Names(List<string> lines, string value) =>
        lines.Any(l => l.Contains(value, StringComparison.OrdinalIgnoreCase));

    [Fact(Skip = AwaitingProjection)]
    public async Task The_native_overview_names_every_section_and_the_section_count()
    {
        var (pe, lines) = await Read();
        Assert.NotEmpty(pe.Sections);
        foreach (var s in pe.Sections)
            Assert.True(Names(lines, s.Name), $"section {s.Name} missing from:\n{string.Join("\n", lines)}");
        Assert.True(Names(lines, $"{pe.Sections.Count} sections"), $"count missing from:\n{string.Join("\n", lines)}");
    }

    [Fact(Skip = AwaitingProjection)]
    public async Task The_native_overview_names_the_mitigations_get_pe_info_reports()
    {
        var (pe, lines) = await Read();
        var reported = pe.MitigationsOn.Concat(pe.MitigationsOff).ToList();
        Assert.NotEmpty(reported);
        foreach (var m in reported)
            Assert.True(Names(lines, m), $"mitigation {m} missing from:\n{string.Join("\n", lines)}");
    }

    [Fact(Skip = AwaitingProjection)]
    public async Task The_native_overview_names_the_pdb_path()
    {
        var (pe, lines) = await Read();
        Assert.False(string.IsNullOrEmpty(pe.PdbPath));
        Assert.True(Names(lines, pe.PdbPath!), $"PDB path missing from:\n{string.Join("\n", lines)}");
    }

    [Fact(Skip = AwaitingProjection)]
    public async Task The_native_overview_counts_the_tls_callbacks()
    {
        var (pe, lines) = await Read();
        Assert.True(pe.TlsCallbacks > 0);
        Assert.True(Names(lines, $"{pe.TlsCallbacks} TLS callback"), $"TLS count missing from:\n{string.Join("\n", lines)}");
    }

    [Fact(Skip = AwaitingProjection)]
    public async Task The_native_overview_names_the_imported_modules()
    {
        var (_, lines) = await Read();
        Assert.True(Names(lines, "KERNEL32"), $"KERNEL32 missing from:\n{string.Join("\n", lines)}");
        Assert.True(Names(lines, "USER32"), $"USER32 missing from:\n{string.Join("\n", lines)}");
    }

    [Fact(Skip = AwaitingProjection)]
    public async Task The_native_overview_points_to_get_pe_info_and_a_second_view()
    {
        var (_, lines) = await Read();
        var hints = lines.Where(l => l.StartsWith("Next", StringComparison.OrdinalIgnoreCase)).ToList();
        var tools = hints.SelectMany(h => Regex.Matches(h, @"\b[a-z]+(?:_[a-z]+)+\b").Select(m => m.Value)).Distinct().ToList();
        Assert.Contains("get_pe_info", tools);
        Assert.True(tools.Count >= 2, $"one next view only; highlights were:\n{string.Join("\n", lines)}");
    }
}
