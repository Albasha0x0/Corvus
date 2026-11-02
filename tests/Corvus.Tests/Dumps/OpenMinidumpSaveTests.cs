using Corvus.Native.Dump;
using Corvus.Native.Pe;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>open_minidump view=modules with outputPath saves modules rebuilt as PE files.</summary>
public sealed class OpenMinidumpSaveTests : IDisposable
{
    private const ulong Base = 0x1_8000_0000;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public async Task open_minidump_saves_a_module_that_reloads_as_a_PE_file()
    {
        var file = RebuildFixtures.Pe(new PeSpec(true, [new SectionSpec(".text", 0x60000020, Enumerable.Range(1, 0x300).Select(i => (byte)i).ToArray())], ImageBase: Base));
        var mapped = RebuildFixtures.Mapped(file);
        var b = new MinidumpBuilder { ProcessorArchitecture = 9 };
        b.Modules.Add(new MinidumpBuilder.Module(Base, (uint)mapped.Length, 0, @"Z:\app\saved.dll"));
        b.Memory.Add((Base, mapped));
        var dump = _dir.File("saved.dmp");
        File.WriteAllBytes(dump, b.Build());
        var folder = _dir.File("modules");

        using var service = new MinidumpService();
        var text = await new MinidumpTools(service).OpenMinidump(dump, "modules", outputPath: folder);

        Assert.Contains("saved.dll", text);
        var saved = PeFile.FromBytes(File.ReadAllBytes(Path.Combine(folder, "saved.dll")));
        Assert.True(saved.Is64Bit);
        var row = Assert.Single(service.Modules(dump, null, 0, 10, _dir.File("again")).Rows);
        Assert.Equal(64, row.ImageSha256!.Length);
        Assert.Equal(100, row.ImageCaptured);
        Assert.Contains(row.ImageChecks!, c => c.Name == "parse");
    }

    [Fact]
    public async Task An_unlisted_image_gets_a_row_with_its_checks_and_a_text_line()
    {
        var file = RebuildFixtures.Pe(new PeSpec(true, [new SectionSpec(".text", 0x60000020, [0x90, 0xC3])], ImageBase: Base));
        var mapped = RebuildFixtures.Mapped(file);
        var b = new MinidumpBuilder { ProcessorArchitecture = 9 };
        b.Modules.Add(new MinidumpBuilder.Module(Base, (uint)mapped.Length, 0, @"Z:\app\listed.dll"));
        b.Memory.Add((Base, mapped));
        b.Memory.Add((Base + 0x100000, mapped));
        b.Memory.Sort((x, y) => x.Start.CompareTo(y.Start));
        var dump = _dir.File("hidden.dmp");
        File.WriteAllBytes(dump, b.Build());

        using var service = new MinidumpService();
        var rows = service.Modules(dump, null, 0, 10, _dir.File("out"), default, MinidumpService.ModuleOptions.Default with { Module = "unlisted" }).Rows;

        var row = Assert.Single(rows, r => r.ImageFile != null);
        Assert.StartsWith("image-", row.ImageFile);
        Assert.Equal(64, row.ImageSha256!.Length);
        Assert.NotNull(row.ImageCaptured);
        Assert.Contains(row.ImageChecks!, c => c.Name == "parse");
        Assert.Contains("image image-", Corvus.Tools.DumpText.Module(row));
    }

    private string TwoModuleDump()
    {
        var first = RebuildFixtures.Pe(new PeSpec(true, [new SectionSpec(".text", 0x60000020, new byte[0x300])], ImageBase: Base));
        var second = RebuildFixtures.Pe(new PeSpec(true, [new SectionSpec(".text", 0x60000020, new byte[0x300])], ImageBase: Base + 0x100000));
        var b = new MinidumpBuilder { ProcessorArchitecture = 9 };
        foreach (var (name, file, at) in new[] { ("one.dll", first, Base), ("two.dll", second, Base + 0x100000) })
        {
            var mapped = RebuildFixtures.Mapped(file);
            b.Modules.Add(new MinidumpBuilder.Module(at, (uint)mapped.Length, 0, @"Z:\app\" + name));
            b.Memory.Add((at, mapped));
        }
        var dump = _dir.File("two.dmp");
        File.WriteAllBytes(dump, b.Build());
        return dump;
    }

    [Fact]
    public async Task The_module_option_saves_only_the_named_module()
    {
        var dump = TwoModuleDump();
        var folder = _dir.File("named");

        using var service = new MinidumpService();
        await new MinidumpTools(service).OpenMinidump(dump, "modules", outputPath: folder, modules: "two.dll");

        Assert.Equal(["two.dll"], Directory.GetFiles(folder).Select(Path.GetFileName));
    }

    [Fact]
    public async Task The_mapped_layout_option_keeps_section_offsets_at_their_RVAs()
    {
        var dump = TwoModuleDump();
        var folder = _dir.File("mapped");

        using var service = new MinidumpService();
        await new MinidumpTools(service).OpenMinidump(dump, "modules", outputPath: folder, modules: "one.dll", layout: "mapped");

        var text = PeFile.FromBytes(File.ReadAllBytes(Path.Combine(folder, "one.dll"))).Sections.Single(s => s.Name == ".text");
        Assert.Equal(text.Rva, text.RawOffset);
    }
}
