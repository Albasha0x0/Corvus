using System.Buffers.Binary;
using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Pointer values decoded from a changed data range.</summary>
public sealed class DataChangeValuesTests : IDisposable
{
    private const ulong Library = 0x180000000;
    private const ulong Heap = 0x2000000;

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static byte[] Pointer(ulong value)
    {
        var b = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(b, value);
        return b;
    }

    [Fact]
    public void A_changed_pointer_into_a_module_is_named_by_its_export()
    {
        var image = RebuildFixtures.Build(new PeSpec(true, [new SectionSpec(".text", 0x60000020, new byte[0x40])],
            Exports: [new ExportSpec("Alpha", 0x1000)]));
        using var dump = RebuildFixtures.Dump(_dir, new Placed("fixture.dll", image, Library));

        var rows = DataChangeValues.Decode(Pointer(Library + 0x1000), Pointer(0x1234), 0x5000, true, dump);

        var row = Assert.Single(rows);
        Assert.Equal(0x5000UL, row.Address);
        Assert.Equal(0x1234UL, row.Old);
        Assert.Equal(Library + 0x1000, row.New);
        Assert.Equal("fixture.dll!Alpha", row.Target);
        Assert.Equal("fixture.dll+0x1004", Assert.Single(DataChangeValues.Decode(Pointer(Library + 0x1004), Pointer(0), 0x5000, true, dump)).Target);
    }

    [Fact]
    public void A_pointer_into_executable_memory_with_no_image_is_reported_unbacked()
    {
        var process = new Regions([new DumpMemoryRegion(Heap, Heap, 0x40, 0x10000, 0x1000, 0x40, 0x20000)]);

        var row = Assert.Single(DataChangeValues.Decode(Pointer(Heap + 0x10), Pointer(0), 0, true, process));

        Assert.Equal("unbacked", row.Target);
    }

    [Fact]
    public void A_value_that_points_nowhere_is_not_a_pointer()
    {
        var process = new Regions([new DumpMemoryRegion(Heap, Heap, 0x04, 0x10000, 0x1000, 0x04, 0x20000)]);

        Assert.Equal("committed memory", Assert.Single(DataChangeValues.Decode(Pointer(Heap + 8), Pointer(0), 0, true, process)).Target);
        Assert.Equal("not a pointer", Assert.Single(DataChangeValues.Decode(Pointer(0x41), Pointer(0), 0, true, process)).Target);
    }

    /// <summary>A process of memory regions only, with no modules.</summary>
    private sealed class Regions(IReadOnlyList<DumpMemoryRegion> regions) : IProcessMemory
    {
        public NativeArch Arch => NativeArch.X64;
        public bool Is64Bit => true;
        public string Identity => "regions";
        public IReadOnlyList<DumpModule> Modules => [];
        public IReadOnlyList<DumpUnloadedModule> UnloadedModules => [];
        public int ReadMemory(ulong address, Span<byte> destination) => 0;
        public DumpModule? ModuleAt(ulong address) => null;
        public DumpMemoryRegion? RegionAt(ulong address) => ProcessMemoryExtensions.RegionAt(regions, address);
        public ulong ReadableExtent(ulong start, ulong size) => 0;
    }
}
