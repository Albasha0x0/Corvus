using System.Buffers.Binary;
using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Decoding many changed ranges reads the module list once when the caller shares an export map.</summary>
public sealed class DataChangeValuesSharedMapTests : IDisposable
{
    private const ulong Library = 0x180000000;

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static byte[] Pointer(ulong value)
    {
        var b = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(b, value);
        return b;
    }

    [Fact]
    public void A_shared_export_map_is_not_built_again_for_each_range()
    {
        var image = RebuildFixtures.Build(new PeSpec(true, [new SectionSpec(".text", 0x60000020, new byte[0x40])],
            Exports: [new ExportSpec("Alpha", 0x1000)]));
        using var dump = RebuildFixtures.Dump(_dir, new Placed("fixture.dll", image, Library));
        var counted = new CountingMemory(dump);
        var exports = new ExportMap(counted);
        int built = counted.ModuleListReads;

        for (int i = 0; i < 50; i++)
            Assert.Equal("fixture.dll!Alpha", Assert.Single(DataChangeValues.Decode(Pointer(Library + 0x1000), Pointer(0x1234), 0x5000, true, counted, exports)).Target);

        Assert.Equal(1, built);
        Assert.Equal(built, counted.ModuleListReads);
    }

    [Fact]
    public void Each_call_without_a_map_builds_its_own()
    {
        var image = RebuildFixtures.Build(new PeSpec(true, [new SectionSpec(".text", 0x60000020, new byte[0x40])],
            Exports: [new ExportSpec("Alpha", 0x1000)]));
        using var dump = RebuildFixtures.Dump(_dir, new Placed("fixture.dll", image, Library));
        var counted = new CountingMemory(dump);

        for (int i = 0; i < 3; i++) DataChangeValues.Decode(Pointer(Library + 0x1000), Pointer(0x1234), 0x5000, true, counted);

        Assert.Equal(3, counted.ModuleListReads);
    }

    /// <summary>A process that counts how often its module list is read.</summary>
    private sealed class CountingMemory(IProcessMemory inner) : IProcessMemory
    {
        public int ModuleListReads { get; private set; }
        public NativeArch Arch => inner.Arch;
        public bool Is64Bit => inner.Is64Bit;
        public string Identity => inner.Identity;
        public IReadOnlyList<DumpModule> Modules { get { ModuleListReads++; return inner.Modules; } }
        public IReadOnlyList<DumpUnloadedModule> UnloadedModules => inner.UnloadedModules;
        public int ReadMemory(ulong address, Span<byte> destination) => inner.ReadMemory(address, destination);
        public DumpModule? ModuleAt(ulong address) => inner.ModuleAt(address);
        public DumpMemoryRegion? RegionAt(ulong address) => inner.RegionAt(address);
        public ulong ReadableExtent(ulong start, ulong size) => inner.ReadableExtent(start, size);
    }
}
