namespace Corvus.Tests;

public static partial class ContractSweep
{
    private static Dictionary<string, string[]> DotnetFileWriters() => new()
    {
        ["export_project"] = ["outputDirectory"],
        ["get_resource"] = ["outputPath"],
    };
}
