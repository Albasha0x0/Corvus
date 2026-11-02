using System.Buffers.Binary;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Import address table slots restored from the lookup table.</summary>
public sealed class ImportRestoreTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeSpec Spec(bool is64, IReadOnlyList<ImportSpec>? imports = null, IReadOnlyList<ExportSpec>? exports = null) => new(is64,
        [new SectionSpec(".text", 0x60000020, [0x90, 0xC3, 0xCC, 0xCC])], Imports: imports, Exports: exports);

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Import_slots_written_by_the_loader_are_restored_from_the_lookup_table(bool is64)
    {
        var lib = RebuildFixtures.Build(Spec(is64, exports: [new ExportSpec("alpha", 0x1000), new ExportSpec("beta", 0x1001)]));
        var app = RebuildFixtures.Build(Spec(is64, imports: [new ImportSpec("lib.dll", ["alpha", "beta"])]));
        ulong appBase = is64 ? 0x140000000UL : 0x10000000UL, libBase = is64 ? 0x180000000UL : 0x20000000UL;
        using var dump = RebuildFixtures.Dump(_dir, new Placed("app.exe", app, appBase), new Placed("lib.dll", lib, libBase));
        var target = RebuildTarget.Of(dump.Modules.First(m => m.FileName == "app.exe"));

        var result = ModuleRebuild.Rebuild(dump, target, new RebuildOptions(CompareWithDisk: false, Layout: OutputLayout.Mapped), CancellationToken.None);

        var original = RebuildFixtures.Mapped(app.Bytes);
        int width = is64 ? 8 : 4;
        foreach (var slot in app.IatSlots.Values)
            Assert.Equal(original.AsSpan((int)slot, width).ToArray(), result.Bytes!.AsSpan((int)slot, width).ToArray());
        Assert.Equal(new ImportSummary(1, 2, 0, 0, false), result.Imports);
        Assert.Equal("ok", result.Checks.Single(c => c.Name == "imports").State);
    }

    [Fact]
    public void A_descriptor_without_a_lookup_table_counts_its_slots_unresolved()
    {
        var app = RebuildFixtures.Build(Spec(true, imports: [new ImportSpec("lib.dll", ["alpha", "beta"])]));
        var image = RebuildFixtures.Mapped(app.Bytes);
        int nt = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3C));
        uint dirRva = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(nt + 24 + 112 + 8));
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan((int)dirRva), 0);
        foreach (var slot in app.IatSlots.Values)
            BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan((int)slot), 0x7FF000001000UL);
        var captured = new CapturedImage(new RebuildTarget("app.exe", 0x140000000UL, (uint)image.Length, ModuleOrigin.Listed),
            image, Enumerable.Repeat(true, image.Length / 0x1000).ToArray(), "mapped");
        var checks = new List<RebuildCheck>();

        var summary = PeImportRestore.Restore(image, captured, null!, ImportMode.Restore, checks, CancellationToken.None);

        Assert.Equal(new ImportSummary(1, 0, 0, 2, false), summary);
        Assert.Equal("partial", checks.Single().State);
        foreach (var slot in app.IatSlots.Values)
            Assert.Equal(0x7FF000001000UL, BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan((int)slot)));
    }
}
