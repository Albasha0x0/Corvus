using System.Buffers.Binary;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Resolved delay-load slots are copied from the file of the same build, or kept and named from exports.</summary>
public sealed class DelayImportRestoreTests : IDisposable
{
    private const ulong ExporterBase = 0x1_8000_0000UL;
    private const ulong Resolved = ExporterBase + 0x1000;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeSpec Spec() => new(true, [new SectionSpec(".text", 0x60000020, [0x90, 0xC3])]);

    private MinidumpFile ExporterDump()
    {
        var exporter = new PeSpec(true, [new SectionSpec(".text", 0x60000020, [0x90, 0xC3])], Exports: [new ExportSpec("Func", 0x1000)]);
        return RebuildFixtures.Dump(_dir, new Placed("lib.dll", RebuildFixtures.Build(exporter), ExporterBase));
    }

    private static CapturedImage Capture(PeSpec spec, byte[] mapped, ulong loadedBase)
    {
        var pages = Enumerable.Repeat(true, mapped.Length / 0x1000).ToArray();
        return new CapturedImage(new RebuildTarget("app.exe", loadedBase, (uint)mapped.Length, ModuleOrigin.Listed), mapped, pages, "mapped");
    }

    private static ulong Slot(byte[] mapped, DelaySlot slot) => BinaryPrimitives.ReadUInt64LittleEndian(mapped.AsSpan((int)slot.SlotRva));

    [Theory]
    [InlineData(BaseMode.Loaded, 0x10000UL)]
    [InlineData(BaseMode.Preferred, 0UL)]
    public void A_resolved_delay_load_slot_is_restored_from_the_file(BaseMode mode, ulong delta)
    {
        var spec = Spec();
        var built = DelayImportFixtures.Build(spec, [new("one.dll", [DelayFunction.Named("Alpha"), DelayFunction.Named("Beta")])]);
        var mapped = RebuildFixtures.Mapped(built.Bytes);
        var alpha = built.Slot("one.dll!Alpha");
        var beta = built.Slot("one.dll!Beta");
        DelayImportFixtures.WriteResolved(mapped, true, alpha, Resolved);
        // The unresolved slot reads as a loader leaves it: the stub address at
        // the loaded base, or at the preferred base once undone.
        DelayImportFixtures.WriteResolved(mapped, true, beta, spec.Base + beta.StubRva + delta);
        using var dump = ExporterDump();
        var checks = new List<RebuildCheck>();

        var names = PeDelayImports.Restore(mapped, Capture(spec, mapped, spec.Base + 0x10000), built.Bytes, mode, dump, checks);

        Assert.Empty(names);
        Assert.Equal(spec.Base + alpha.StubRva + delta, Slot(mapped, alpha));
        Assert.Equal(spec.Base + beta.StubRva + delta, Slot(mapped, beta));
        var check = Assert.Single(checks);
        Assert.Equal(("delay imports", "ok", "1 slots restored"), (check.Name, check.State, check.Detail));
    }

    [Fact]
    public void Without_a_file_the_resolved_slots_are_kept_and_named()
    {
        var spec = Spec();
        var built = DelayImportFixtures.Build(spec, [new("one.dll", [DelayFunction.Named("Alpha"), DelayFunction.Named("Beta")])]);
        var mapped = RebuildFixtures.Mapped(built.Bytes);
        var alpha = built.Slot("one.dll!Alpha");
        DelayImportFixtures.WriteResolved(mapped, true, alpha, Resolved);
        using var dump = ExporterDump();
        var checks = new List<RebuildCheck>();

        var names = PeDelayImports.Restore(mapped, Capture(spec, mapped, spec.Base), null, BaseMode.Loaded, dump, checks);

        Assert.Equal(Resolved, Slot(mapped, alpha));
        var named = Assert.Single(names);
        Assert.Equal(($"0x{alpha.SlotRva:X}", "lib.dll!Func"), (named.Slot, named.Name));
        var check = Assert.Single(checks);
        Assert.Equal(("delay imports", "unknown", "1 resolved slots kept: no file of the same build"), (check.Name, check.State, check.Detail));
    }

    [Fact]
    public void An_image_without_delay_load_imports_reports_skipped()
    {
        var spec = Spec();
        var file = RebuildFixtures.Pe(spec);
        var mapped = RebuildFixtures.Mapped(file);
        using var dump = ExporterDump();
        var checks = new List<RebuildCheck>();

        var names = PeDelayImports.Restore(mapped, Capture(spec, mapped, spec.Base), file, BaseMode.Loaded, dump, checks);

        Assert.Empty(names);
        var check = Assert.Single(checks);
        Assert.Equal(("delay imports", "skipped", "no delay-load imports"), (check.Name, check.State, check.Detail));
    }
}