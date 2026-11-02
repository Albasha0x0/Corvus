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
}
