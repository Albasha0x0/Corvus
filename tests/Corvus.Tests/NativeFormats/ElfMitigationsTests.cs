using Corvus.Native.Elf;

namespace Corvus.Tests.NativeFormats;

/// <summary>ELF hardening as get_pe_info reports it: stack protector, FORTIFY and the GNU property note's CET and BTI/PAC bits.</summary>
public sealed class ElfMitigationsTests
{
    private static Dictionary<string, bool> Of(ElfWriter w) => ElfMitigations.Of(ElfFile.FromBytes(w.Build(), "lib.so")).ToDictionary(m => m.Name, m => m.On);

    [Fact]
    public void Stack_protector_and_fortify_come_from_imports()
    {
        var m = Of(new ElfWriter { PltImports = ["__stack_chk_fail", "__memcpy_chk"] });
        Assert.True(m["stack protector"]);
        Assert.True(m["FORTIFY_SOURCE"]);
        var none = Of(new ElfWriter { PltImports = ["__stack_chk_fail", "memcpy"] });
        Assert.False(none["FORTIFY_SOURCE"]);
    }

    [Fact]
    public void Aarch64_property_note_gives_bti_and_pac()
    {
        var m = Of(new ElfWriter { GnuProperties = [(0xC0000000, 3)] });
        Assert.True(m["BTI"] && m["PAC"]);
        Assert.False(m.ContainsKey("CET IBT"));
        var bare = Of(new ElfWriter());
        Assert.False(bare["BTI"] || bare["PAC"]);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void X86_property_note_gives_ibt_and_shadow_stack(bool is64)
    {
        var m = Of(new ElfWriter
        {
            Is64 = is64, Machine = is64 ? ElfWriter.EmX64 : ElfWriter.EmX86, Text = [0xC3],
            GnuProperties = [(0xC0008002, 1), (0xC0000002, 2)],
        });
        Assert.False(m["CET IBT"]);
        Assert.True(m["CET shadow stack"]);
    }
}
