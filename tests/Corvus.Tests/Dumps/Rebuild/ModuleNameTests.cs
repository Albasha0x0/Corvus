using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>The file name a rebuilt module gets under an output folder.</summary>
public sealed class ModuleNameTests
{
    private static string Name(string file, ulong at, HashSet<string> used) => ModuleFileName.NameFor(file, at, used);

    [Fact]
    public void A_plain_module_name_is_kept()
    {
        Assert.Equal("synth.dll", Name("synth.dll", 0x1000, new(StringComparer.OrdinalIgnoreCase)));
    }

    [Fact]
    public void A_reserved_device_name_becomes_module_bin()
    {
        Assert.Equal("module.bin", Name("con.dll", 0x1000, new(StringComparer.OrdinalIgnoreCase)));
    }

    [Fact]
    public void A_name_with_a_directory_part_becomes_module_bin()
    {
        Assert.Equal("module.bin", Name(@"Z:\other\synth.dll", 0x1000, new(StringComparer.OrdinalIgnoreCase)));
    }

    [Fact]
    public void A_taken_name_gets_the_base_address_and_then_a_counter()
    {
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Assert.Equal("synth.dll", Name("synth.dll", 0x1000, used));
        Assert.Equal("synth-2000.dll", Name("synth.dll", 0x2000, used));
        Assert.Equal("synth-2000-2.dll", Name("synth.dll", 0x2000, used));
    }

    [Fact]
    public void A_name_that_ends_in_its_extension_twice_keeps_it_once()
    {
        Assert.Equal("payload.dll", Name("payload.dll.dll", 0x1000, new(StringComparer.OrdinalIgnoreCase)));
    }
}
