using Corvus.Native.Pe;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>open_minidump view=modules with outputPath names what it wrote and what it left out.</summary>
public sealed class OpenMinidumpWrittenTextTests : IDisposable
{
    private const ulong First = 0x1_8000_0000;
    private const ulong Second = 0x1_9000_0000;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private string TwoImages()
    {
        var file = RebuildFixtures.Pe(new PeSpec(true, [new SectionSpec(".text", 0x60000020, [0x90, 0xC3])], ImageBase: First));
        var mapped = RebuildFixtures.Mapped(file);
        var b = new MinidumpBuilder { ProcessorArchitecture = 9 };
        b.Modules.Add(new MinidumpBuilder.Module(First, (uint)mapped.Length, 0, @"Z:\app\one.dll"));
        b.Modules.Add(new MinidumpBuilder.Module(Second, (uint)mapped.Length, 0, @"Z:\app\two.dll"));
        b.Memory.Add((First, mapped));
        b.Memory.Add((Second, mapped));
        var dump = _dir.File("two.dmp");
        File.WriteAllBytes(dump, b.Build());
        return dump;
    }

    [Fact]
    public async Task A_single_named_module_is_counted_against_the_listed_modules()
    {
        using var service = new MinidumpService();
        var text = await new MinidumpTools(service).OpenMinidump(TwoImages(), "modules", outputPath: _dir.File("one"), modules: "one.dll");

        Assert.Contains("1 written module of 2:", text);
        Assert.Contains("1 not written:", text);
        Assert.True(File.Exists(Path.Combine(_dir.File("one"), "one.dll")));
    }

    [Fact]
    public async Task Code_regions_with_no_region_list_name_why_nothing_was_written()
    {
        var b = new MinidumpBuilder { ProcessorArchitecture = 9 };
        b.Modules.Add(new MinidumpBuilder.Module(First, 0x1000, 0, @"Z:\app\one.dll"));
        var dump = _dir.File("bare.dmp");
        File.WriteAllBytes(dump, b.Build());

        using var service = new MinidumpService();
        var text = await new MinidumpTools(service).OpenMinidump(dump, "modules", outputPath: _dir.File("code"), modules: "code");

        Assert.DoesNotContain("written module", text);
        Assert.DoesNotContain(" code size  stamp ", text);
        Assert.Contains("Nothing written: unknown", text);
    }
}
