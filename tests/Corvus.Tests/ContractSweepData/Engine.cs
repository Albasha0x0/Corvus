namespace Corvus.Tests;

public static partial class ContractSweep
{
    private static Dictionary<string, string[]> EngineFileWriters() => new()
    {
        ["export_engine_database"] = ["outputPath"],
    };
}
