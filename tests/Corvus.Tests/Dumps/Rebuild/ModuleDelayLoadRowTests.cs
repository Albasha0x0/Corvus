using Corvus.Native.Dump;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>The modules report names the delay-load modules a rebuilt image resolved.</summary>
public sealed class ModuleDelayLoadRowTests : IDisposable
{
    private const ulong Base = 0x1_8000_0000UL;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void The_module_row_names_the_delay_load_modules_it_resolved()
    {
        var spec = new PeSpec(true, [new SectionSpec(".text", 0x60000020, [0x90, 0xC3])], ImageBase: 0x1_4000_0000UL);
        var built = DelayImportFixtures.Build(spec, [new("one.dll", [DelayFunction.Named("Alpha")])]);
        var mapped = RebuildFixtures.Mapped(built.Bytes);
        DelayImportFixtures.WriteResolved(mapped, true, built.Slot("one.dll!Alpha"), Base + 0x1000);
        var exporter = RebuildFixtures.Build(new PeSpec(true, [new SectionSpec(".text", 0x60000020, [0x90, 0xC3])], Exports: [new ExportSpec("Func", 0x1000)]));
        var b = new MinidumpBuilder { ProcessorArchitecture = 9 };
        b.Modules.Add(new MinidumpBuilder.Module(0x1_4000_0000UL, (uint)mapped.Length, 0, @"Z:\app\app.dll"));
        b.Memory.Add((0x1_4000_0000UL, mapped));
        var lib = RebuildFixtures.Mapped(exporter.Bytes);
        b.Modules.Add(new MinidumpBuilder.Module(Base, (uint)lib.Length, 0, @"Z:\app\lib.dll"));
        b.Memory.Add((Base, lib));
        var path = _dir.File("delay.dmp");
        File.WriteAllBytes(path, b.Build());

        using var service = new MinidumpService();
        var rows = service.Modules(path, null, 0, 10, _dir.File("out"),
            default, MinidumpService.ModuleOptions.Default with { Module = "app.dll" }).Rows;

        var row = rows.First(r => r.Name == "app.dll");
        Assert.Equal(["lib.dll"], row.DelayImportModules);
    }
}
