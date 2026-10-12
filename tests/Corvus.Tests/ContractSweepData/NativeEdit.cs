namespace Corvus.Tests;

public static partial class ContractSweep
{
    private static Dictionary<string, string[]> NativeEditFileWriters() => new()
    {
        ["export_native_annotations"] = ["outputPath"],
        ["save_native"] = ["outputPath"],
        ["export_native_patches"] = ["outputPath"],
    };
}
