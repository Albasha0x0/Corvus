namespace Corvus.Tests;

public static partial class ContractSweep
{
    private static Dictionary<string, string[]> EditFileWriters() => new()
    {
        ["export_edits"] = ["outputPath"],
        ["save_assembly"] = ["outputPath"],
    };
}
