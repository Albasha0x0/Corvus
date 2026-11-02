using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Elf;

namespace Corvus.Tests;

/// <summary>Modules of a synthetic ELF core rebuilt into files.</summary>
public sealed class ElfRebuildTests
{
    private static RebuiltModule Rebuild(bool moduleCode)
    {
        using var core = CoreFile.FromBytes(SyntheticCore.Core(arm64: false, moduleCode), "app.core");
        var target = Assert.Single(ModuleRebuild.Select(core, "libcrash.so", default));
        return ModuleRebuild.Rebuild(core, target, RebuildOptions.Default, default);
    }

    [Fact]
    public void An_ELF_module_is_rebuilt_from_its_core_segments()
    {
        var rebuilt = Rebuild(moduleCode: true);
        Assert.Null(rebuilt.Refused);
        Assert.Equal("elf", rebuilt.Format);
        Assert.Equal(100, rebuilt.CapturedPercent);
        Assert.Equal("ok", rebuilt.Checks.Single(c => c.Name == "layout").State);
        Assert.Equal("skipped", rebuilt.Checks.Single(c => c.Name == "relocations").State);
        Assert.Equal("ok", rebuilt.Checks.Single(c => c.Name == "parse").State);
        var original = SyntheticCore.Module(arm64: false);
        var elf = ElfFile.FromBytes(rebuilt.Bytes!);
        Assert.Equal(4, elf.Segments.Count);
        Assert.Equal(original.AsSpan(0x1000, 0x1000).ToArray(), rebuilt.Bytes!.AsSpan(0x1000, 0x1000).ToArray());
        Assert.Equal(0UL, BitConverter.ToUInt64(rebuilt.Bytes!, 0x28));
        Assert.Equal(0, BitConverter.ToUInt16(rebuilt.Bytes!, 0x3C));
        Assert.Equal(0, BitConverter.ToUInt16(rebuilt.Bytes!, 0x3E));
    }

    [Fact]
    public void A_segment_the_core_omits_is_written_as_zeros_and_reported_partial()
    {
        var rebuilt = Rebuild(moduleCode: false);
        Assert.Null(rebuilt.Refused);
        var layout = rebuilt.Checks.Single(c => c.Name == "layout");
        Assert.Equal("partial", layout.State);
        Assert.Contains("4096", layout.Detail);
        Assert.All(rebuilt.Bytes!.AsSpan(0x1000, 0x1000).ToArray(), b => Assert.Equal(0, b));
        Assert.Equal(50, rebuilt.CapturedPercent);
    }
}
