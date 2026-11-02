using System.Buffers.Binary;
using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>Import slots without a lookup table, named from the exports they point at.</summary>
public sealed class ImportResolveTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeBuilt Library() => RebuildFixtures.Build(new PeSpec(
        true, [new SectionSpec(".text", 0x60000020, new byte[0x40])], Exports: [new ExportSpec("Alpha", 0x1000)]));

    // The first descriptor's lookup table field is zeroed in the file bytes.
    private static PeBuilt WithoutLookupTable(PeBuilt built)
    {
        var bytes = (byte[])built.Bytes.Clone();
        uint idata = PeFile.FromBytes(bytes).Sections.First(s => s.Name == ".idata").Rva;
        int nt = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3C));
        int table = nt + 24 + BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(nt + 20));
        int count = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(nt + 6));
        for (int i = 0; i < count; i++)
        {
            int h = table + 40 * i;
            if (BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(h + 12)) != idata) continue;
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan((int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(h + 20))), 0);
        }
        return new PeBuilt(bytes, built.IatSlots);
    }

    private static PeBuilt App() => WithoutLookupTable(RebuildFixtures.Build(new PeSpec(
        true, [new SectionSpec(".text", 0x60000020, new byte[0x40])], Imports: [new ImportSpec("lib.dll", ["Alpha"])])));

    private RebuiltModule Rebuild(Placed app, Placed lib)
    {
        using var dump = RebuildFixtures.Dump(_dir, app, lib);
        var target = RebuildTarget.Of(dump.Modules.First(m => m.FileName == "app.exe"));
        return ModuleRebuild.Rebuild(dump, target, new RebuildOptions(CompareWithDisk: false, Layout: OutputLayout.Mapped), CancellationToken.None);
    }

    [Fact]
    public void An_import_slot_without_a_lookup_table_is_named_from_the_export_it_points_at()
    {
        var app = App();
        var lib = Library();

        var result = Rebuild(new Placed("app.exe", app, 0x140000000), new Placed("lib.dll", lib, 0x180000000));

        uint slot = app.IatSlots["lib.dll!Alpha"];
        Assert.Equal(1, result.Imports!.Resolved);
        Assert.Equal(0, result.Imports.Unresolved);
        Assert.Equal([new ResolvedImport($"0x{slot:X}", "lib.dll!Alpha")], result.Imports.Names);
        Assert.Equal("partial", result.Checks.Single(c => c.Name == "imports").State);
    }

    [Fact]
    public void A_slot_pointing_outside_every_module_stays_unresolved()
    {
        var app = App();
        var lib = Library();
        var values = new Dictionary<string, ulong> { ["lib.dll!Alpha"] = 0x7FF000001000UL };

        var result = Rebuild(new Placed("app.exe", app, 0x140000000, IatValues: values), new Placed("lib.dll", lib, 0x180000000));

        Assert.Equal(0, result.Imports!.Resolved);
        Assert.Equal(1, result.Imports.Unresolved);
        Assert.Empty(result.Imports.Names);
    }
}
