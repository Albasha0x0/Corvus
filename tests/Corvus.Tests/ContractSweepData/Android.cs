namespace Corvus.Tests;

public static partial class ContractSweep
{
    private static Dictionary<string, string[]> AndroidFileWriters() => new()
    {
        ["get_android_resource"] = ["outputPath"],
        ["pull_android_package"] = ["outputDirectory"],
        ["pull_android_file"] = ["outputPath"],
    };
}
