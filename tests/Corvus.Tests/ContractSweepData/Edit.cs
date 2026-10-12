namespace Corvus.Tests;

public static partial class ContractSweep
{
    private static Dictionary<string, string[]> EditFileWriters() => new()
    {
        ["export_edits"] = ["path"],
        ["save_assembly"] = ["outputPath"],
    };
}
