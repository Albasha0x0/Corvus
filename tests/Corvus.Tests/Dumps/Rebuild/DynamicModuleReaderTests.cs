using Corvus.Native.Dump;
using Corvus.Native.Dump.Managed;

namespace Corvus.Tests;

/// <summary>What the runtime keeps of a dynamic module in a dump.</summary>
public sealed class DynamicModuleReaderTests
{
    /// <summary>A fact skipped, with the reason, where the dump cannot be written.</summary>
    [Xunit.Sdk.XunitTestCaseDiscoverer(RunTimeSkips.FactDiscoverer, RunTimeSkips.Assembly)]
    private sealed class DumpFactAttribute : FactAttribute, IRunTimeSkip
    {
        public string? RunTimeSkip() => DynamicAssemblyProgram.Unavailable;
    }

    private static async Task<DynamicModuleRead> ReadEmitted()
    {
        using var dir = new TempDir();
        using var dump = MinidumpFile.Open(DynamicAssemblyProgram.WriteDump(dir));
        using var decoder = (await ClrDecoder.Open(dump, _ => null, [], new DacRequest(), default))!;
        var runtime = decoder.Runtime!;
        return DynamicModuleReader.Read(runtime.EnumerateModules().Single(m => m.IsDynamic), runtime);
    }

    [DumpFact]
    public async Task A_dynamic_module_yields_its_metadata_and_both_method_bodies()
    {
        var read = await ReadEmitted();
        // The runtime holds no flat metadata image for this module: the reason
        // is named.
        if (read.Metadata != null) Assert.NotNull(ClrReads.ReadMvid(read.Metadata));
        else Assert.StartsWith("metadata_unknown", read.MetadataUnknown);
        var bodies = read.Methods.Where(m => m.Type == DynamicAssemblyProgram.EmittedType).ToDictionary(m => m.Name);
        Assert.Null(bodies["Value"].Unknown);
        Assert.Null(bodies["Describe"].Unknown);
        // The body is ldc.i4 20212 then ret.
        Assert.Equal(new byte[] { 0x20, 0xF4, 0x4E, 0x00, 0x00, 0x2A }, bodies["Value"].Code);
        Assert.True(bodies["Describe"].CodeSize > bodies["Value"].CodeSize);
    }

    [DumpFact]
    public async Task A_method_without_a_readable_body_is_reported_unknown()
    {
        var read = await ReadEmitted();
        // The type's inherited object methods have no IL in the module.
        var inherited = read.Methods.Single(m => m.Name == "GetHashCode");
        Assert.Null(inherited.Code);
        Assert.StartsWith("il_unknown", inherited.Unknown);
    }
}
