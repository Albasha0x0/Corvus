namespace Corvus.Tests;

public static partial class ContractSweep
{
    private static Dictionary<string, string[]> LiveFileWriters() => new()
    {
        ["live_session"] = ["outputPath"],
        ["live_events"] = ["outputPath"],
        ["live_coverage"] = ["outputPath"],
        ["live_timeline"] = ["outputPath"],
    };
}