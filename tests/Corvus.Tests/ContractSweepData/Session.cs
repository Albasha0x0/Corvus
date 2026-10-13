namespace Corvus.Tests;

public static partial class ContractSweep
{
    private static Dictionary<string, string[]> SessionFileWriters() => new()
    {
        ["save_session"] = ["outputPath"],
        ["read_result"] = ["outputPath"],
    };
}
