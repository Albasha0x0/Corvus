namespace Corvus.Tests;

public static partial class ContractSweep
{
    private static Dictionary<string, string[]> ContainersFileWriters() => new()
    {
        ["extract_embedded"] = ["outputDirectory"],
        ["unpack_container"] = ["outputDirectory"],
    };
}
