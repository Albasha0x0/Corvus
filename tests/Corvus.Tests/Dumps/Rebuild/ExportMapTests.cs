using System.Buffers.Binary;
using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>Exports of the modules of a dump named by address.</summary>
public sealed class ExportMapTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeBuilt Library(params ExportSpec[] exports) => RebuildFixtures.Build(new PeSpec(
        true, [new SectionSpec(".text", 0x60000020, new byte[0x40])], Exports: exports));

    private static uint EdataRva(PeBuilt image) => PeFile.FromBytes(image.Bytes).Sections.First(s => s.Name == ".edata").Rva;

    [Fact]
    public void An_address_at_an_export_is_named_with_its_module()
    {
        var image = Library(new ExportSpec("Alpha", 0x1000), new ExportSpec("Beta", 0x1010));
        using var dump = RebuildFixtures.Dump(_dir, new Placed("fixture.dll", image, 0x180000000));

        var map = new ExportMap(dump);

        Assert.Equal("fixture.dll!Alpha", map.NameAt(0x180001000));
        Assert.Equal("fixture.dll!Beta", map.NameAt(0x180001010));
        Assert.Null(map.NameAt(0x180001004));
        Assert.Equal(0, map.SkippedModules);
    }

    [Fact]
    public void An_ordinal_only_export_is_named_by_ordinal()
    {
        var built = Library(new ExportSpec("Alpha", 0x1000), new ExportSpec("Beta", 0x1010));
        // The name count is cut to one, so Beta keeps its address and has only ordinal 2.
        var bytes = (byte[])built.Bytes.Clone();
        int nt = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3C));
        int sections = nt + 24 + BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(nt + 20));
        int count = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(nt + 6));
        uint edata = EdataRva(built);
        for (int i = 0; i < count; i++)
        {
            int h = sections + 40 * i;
            if (BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(h + 12)) != edata) continue;
            int raw = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(h + 20));
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(raw + 24), 1);
        }
        using var dump = RebuildFixtures.Dump(_dir, new Placed("fixture.dll", new PeBuilt(bytes, built.IatSlots), 0x180000000));

        var map = new ExportMap(dump);

        Assert.Equal("fixture.dll!Alpha", map.NameAt(0x180001000));
        Assert.Equal("fixture.dll!#2", map.NameAt(0x180001010));
    }

    [Fact]
    public void A_module_whose_export_directory_was_not_captured_is_counted_skipped()
    {
        var image = Library(new ExportSpec("Alpha", 0x1000));
        using var dump = RebuildFixtures.Dump(_dir, new Placed("fixture.dll", image, 0x180000000, OmittedPages: [EdataRva(image)]));

        var map = new ExportMap(dump);

        Assert.Equal(1, map.SkippedModules);
        Assert.Null(map.NameAt(0x180001000));
    }

    [Fact]
    public void A_shared_map_is_reused_while_the_module_list_is_unchanged()
    {
        using var dump = RebuildFixtures.Dump(_dir, new Placed("fixture.dll", Library(new ExportSpec("Alpha", 0x1000)), 0x180000000));
        var memory = new Listed(dump, dump.Modules);

        Assert.Same(ExportMap.For(memory), ExportMap.For(memory));
    }

    [Fact]
    public void A_changed_module_list_builds_a_new_map()
    {
        using var dump = RebuildFixtures.Dump(_dir,
            new Placed("fixture.dll", Library(new ExportSpec("Alpha", 0x1000)), 0x180000000),
            new Placed("other.dll", Library(new ExportSpec("Beta", 0x1000)), 0x190000000));
        var memory = new Listed(dump, [dump.Modules[0]]);
        var first = ExportMap.For(memory);
        memory.Modules = dump.Modules;

        var second = ExportMap.For(memory);

        Assert.NotSame(first, second);
        Assert.Null(first.NameAt(0x190001000));
        Assert.Equal("other.dll!Beta", second.NameAt(0x190001000));
    }

    /// <summary>A process whose module list the test sets.</summary>
    private sealed class Listed(IProcessMemory inner, IReadOnlyList<DumpModule> modules) : IProcessMemory
    {
        public NativeArch Arch => inner.Arch;
        public bool Is64Bit => inner.Is64Bit;
        public string Identity => inner.Identity;
        public IReadOnlyList<DumpModule> Modules { get; set; } = modules;
        public IReadOnlyList<DumpUnloadedModule> UnloadedModules => inner.UnloadedModules;
        public int ReadMemory(ulong address, Span<byte> destination) => inner.ReadMemory(address, destination);
        public DumpModule? ModuleAt(ulong address) => Modules.FirstOrDefault(m => address >= m.Base && address - m.Base < m.Size);
        public DumpMemoryRegion? RegionAt(ulong address) => inner.RegionAt(address);
        public ulong ReadableExtent(ulong start, ulong size) => inner.ReadableExtent(start, size);
    }
}
