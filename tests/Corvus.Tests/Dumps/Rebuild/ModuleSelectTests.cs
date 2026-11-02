using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>Modules of a synthetic minidump rebuilt into files through every stage.</summary>
public sealed class ModuleSelectTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private MinidumpFile Dump(Action<MinidumpBuilder>? change = null)
    {
        var b = SyntheticCrash.Builder();
        change?.Invoke(b);
        var path = _dir.File("crash.dmp");
        File.WriteAllBytes(path, b.Build());
        return MinidumpFile.Open(path);
    }

    [Fact]
    public void A_listed_module_is_selected_by_name_by_base_and_by_all()
    {
        using var dump = Dump();
        Assert.Equal("synth.dll", Assert.Single(ModuleRebuild.Select(dump, "synth.dll", default)).Name);
        Assert.Equal("synth.dll", Assert.Single(ModuleRebuild.Select(dump, "synth", default)).Name);
        Assert.Equal("synth.dll", Assert.Single(ModuleRebuild.Select(dump, $"0x{SyntheticCrash.Base + 0x10:X}", default)).Name);
        Assert.Single(ModuleRebuild.Select(dump, "all", default));
        Assert.Empty(ModuleRebuild.Select(dump, "other.dll", default));
    }

    [Fact]
    public void A_rebuilt_module_reads_back_as_a_PE_file_with_its_checks()
    {
        using var dump = Dump();
        var rebuilt = ModuleRebuild.Rebuild(dump, Assert.Single(ModuleRebuild.Select(dump, "synth.dll", default)), RebuildOptions.Default, default);
        Assert.Null(rebuilt.Refused);
        Assert.Equal(100, rebuilt.CapturedPercent);
        Assert.Contains(rebuilt.Checks, c => c.Name == "parse" && c.State == "ok");
        Assert.Equal((uint)SyntheticCrash.Image().Length, PeFile.FromBytes(rebuilt.Bytes!).SizeOfImage);
    }

    [Fact]
    public void A_module_whose_headers_were_not_captured_is_refused_with_the_reason()
    {
        using var dump = Dump(b => b.Memory.RemoveAll(m => m.Start == SyntheticCrash.Base));
        var rebuilt = ModuleRebuild.Rebuild(dump, RebuildTarget.Of(dump.Modules[0]), RebuildOptions.Default, default);
        Assert.Null(rebuilt.Bytes);
        Assert.Equal("the memory does not hold the image headers", rebuilt.Refused);
    }
}
