namespace Corvus.Tests;

public static partial class ContractSweep
{
    private static Dictionary<string, string[]> AotFileWriters() => new()
    {
        ["export_method_symbols"] = ["outputDirectory"],
    };
}
