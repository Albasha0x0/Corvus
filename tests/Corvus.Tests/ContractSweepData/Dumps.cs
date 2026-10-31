namespace Corvus.Tests;

public static partial class ContractSweep
{
    private static Dictionary<string, string[]> DumpsFileWriters() => new() { ["open_minidump"] = ["outputPath"] };
}
