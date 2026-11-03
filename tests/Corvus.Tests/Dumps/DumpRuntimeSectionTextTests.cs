using Corvus.Native.Pe;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>open_minidump view=modules names the sections a module wrote at run time.</summary>
public sealed class DumpRuntimeSectionTextTests
{
    private static byte[] Tail(int length) => Enumerable.Repeat((byte)0x90, length).ToArray();

    private static async Task<string> Modules(string dump)
    {
        using var service = new MinidumpService();
        return await new MinidumpTools(service).OpenMinidump(dump, "modules");
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task The_modules_text_names_sections_written_at_run_time(bool is64)
    {
        using var dir = new TempDir();
        var noRaw = RuntimeSectionFixtures.NoRawData(dir, is64, ".rt", Tail(0x2000), true, false);
        var shortRaw = RuntimeSectionFixtures.ShortRawData(dir, is64, ".rt", [0x55, 0xC3], Tail(0x300));

        Assert.Contains("sections written at run time: .rt (code, 8 KB)", await Modules(noRaw.DumpPath));
        Assert.Contains("sections written at run time: .rt (code, 258 bytes)", await Modules(shortRaw.DumpPath));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Uncaptured_bytes_are_named_on_the_line(bool is64)
    {
        using var dir = new TempDir();
        var probe = RuntimeSectionFixtures.NoRawData(dir, is64, ".rt", Tail(0x2000), false, true);
        int page = (int)(probe.SectionRva / 0x1000);
        var image = RuntimeSectionFixtures.NoRawData(dir, is64, ".rt", Tail(0x2000), false, true, [page + 1]);

        Assert.Contains("(data, 4 KB, 4 KB unknown)", await Modules(image.DumpPath));
    }

    [Fact]
    public async Task A_module_without_them_has_no_line()
    {
        using var dir = new TempDir();
        var file = RebuildFixtures.Pe(new PeSpec(true, [new SectionSpec(".text", 0x60000020, [0x90, 0xC3])]));
        var mapped = RebuildFixtures.Mapped(file);
        var b = new MinidumpBuilder { ProcessorArchitecture = 9 };
        b.Modules.Add(new MinidumpBuilder.Module(0x1_8000_0000, (uint)mapped.Length, 0, @"Z:\app\one.dll"));
        b.Memory.Add((0x1_8000_0000, mapped));
        var dump = dir.File("plain.dmp");
        File.WriteAllBytes(dump, b.Build());

        Assert.DoesNotContain("written at run time", await Modules(dump));
    }

    [Fact]
    public async Task A_module_whose_header_page_is_not_captured_reports_its_sections_as_unknown()
    {
        using var dir = new TempDir();
        var image = RuntimeSectionFixtures.NoRawData(dir, true, ".rt", Tail(0x40), true, false, [0]);

        Assert.Contains("sections written at run time: unknown", await Modules(image.DumpPath));
    }
}
