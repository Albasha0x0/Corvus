using System.Buffers.Binary;
using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>ARM64 jump stubs are followed to the code control reaches.</summary>
public sealed class StubChainsArm64Tests
{
    private const ulong Export = 0x180001000;
    private const uint Ret = 0xD65F03C0;

    private static byte[] Words(params uint[] words)
    {
        var b = new byte[words.Length * 4];
        for (int i = 0; i < words.Length; i++) BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(i * 4), words[i]);
        return b;
    }

    private static uint Br(uint reg) => 0xD61F0000 | reg << 5;

    private static uint Branch(ulong from, ulong to) => 0x14000000 | (uint)((long)(to - from) / 4) & 0x3FFFFFF;

    private static uint Adrp(uint reg, ulong from, ulong to)
    {
        long pages = ((long)to >> 12) - ((long)from >> 12);
        return 0x90000000 | ((uint)pages & 3) << 29 | ((uint)(pages >> 2) & 0x7FFFF) << 5 | reg;
    }

    private static byte[] Literal(ulong from, ulong slot) =>
        Words(0x58000000 | ((uint)((long)(slot - from) / 4) & 0x7FFFF) << 5 | 16, Br(16));

    private static byte[] PageLoad(ulong from, ulong slot) =>
        Words(Adrp(16, from, slot), 0xF9400000 | (uint)(slot & 0xFFF) / 8 << 10 | 16 << 5 | 16, Br(16));

    private static byte[] PageAdd(ulong from, ulong to) =>
        Words(Adrp(16, from, to), 0x91000000 | (uint)(to & 0xFFF) << 10 | 16 << 5 | 16, Br(16));

    private static byte[] Value(ulong v)
    {
        var b = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(b, v);
        return b;
    }

    private static StubChain Run(ulong start, params (ulong At, byte[] Bytes)[] placed)
    {
        using var dir = new TempDir();
        var image = RebuildFixtures.Build(new PeSpec(
            true, [new SectionSpec(".text", 0x60000020, new byte[0x40])],
            Exports: [new ExportSpec("Target", 0x1000)]));
        using var dump = RebuildFixtures.Dump(dir, new Placed("fixture.dll", image, 0x180000000));
        var memory = new Overlay(dump, placed);
        return StubChains.Follow(memory, start, NativeArch.Arm64, new ExportMap(dump));
    }

    [Fact]
    public void A_branch_stub_is_followed_to_its_target()
    {
        var chain = Run(0x70000000, (0x70000000, Words(Branch(0x70000000, 0x70001000))), (0x70001000, Words(Ret)));
        Assert.Equal("final", chain.End);
        Assert.Equal(0x70001000UL, chain.Address);
        Assert.Equal("near", Assert.Single(chain.Hops).Form);
    }

    [Fact]
    public void A_backward_branch_stub_is_followed_to_its_target()
    {
        var chain = Run(0x70002000, (0x70002000, Words(Branch(0x70002000, 0x70001000))), (0x70001000, Words(Ret)));
        Assert.Equal(0x70001000UL, chain.Address);
    }

    [Fact]
    public void A_literal_load_stub_is_followed_through_the_pointer()
    {
        var chain = Run(0x70000000,
            (0x70000000, Literal(0x70000000, 0x70000100)), (0x70000100, Value(0x70002000)), (0x70002000, Words(Ret)));
        Assert.Equal("final", chain.End);
        Assert.Equal(0x70002000UL, chain.Address);
        Assert.Equal("pointer", Assert.Single(chain.Hops).Form);
    }

    [Fact]
    public void A_page_load_stub_is_followed_through_the_pointer()
    {
        var chain = Run(0x70000000,
            (0x70000000, PageLoad(0x70000000, 0x70003018)), (0x70003018, Value(0x70005000)), (0x70005000, Words(Ret)));
        Assert.Equal("final", chain.End);
        Assert.Equal(0x70005000UL, chain.Address);
        Assert.Equal("pointer", Assert.Single(chain.Hops).Form);
    }

    [Fact]
    public void A_page_add_stub_is_followed_to_its_target()
    {
        var chain = Run(0x70000000, (0x70000000, PageAdd(0x70000000, 0x70004120)), (0x70004120, Words(Ret)));
        Assert.Equal("final", chain.End);
        Assert.Equal(0x70004120UL, chain.Address);
        Assert.Equal("register", Assert.Single(chain.Hops).Form);
    }

    [Fact]
    public void An_arm64_chain_of_two_stubs_ends_at_the_export()
    {
        var chain = Run(0x180002000,
            (0x180002000, Words(Branch(0x180002000, 0x180003000))), (0x180003000, Words(Branch(0x180003000, Export))));
        Assert.Equal("final", chain.End);
        Assert.Equal(Export, chain.Address);
        Assert.Equal(2, chain.Hops.Count);
    }

    [Fact]
    public void An_arm64_loop_of_stubs_ends_as_a_loop()
    {
        var chain = Run(0x70000000,
            (0x70000000, Words(Branch(0x70000000, 0x70001000))), (0x70001000, Words(Branch(0x70001000, 0x70000000))));
        Assert.Equal("loop", chain.End);
        Assert.Equal(0x70000000UL, chain.Address);
    }

    [Fact]
    public void An_arm64_chain_past_8_hops_names_the_limit()
    {
        var placed = Enumerable.Range(0, 10)
            .Select(i => (At: 0x70000000UL + (ulong)i * 0x100,
                Bytes: Words(Branch(0x70000000UL + (ulong)i * 0x100, 0x70000000UL + (ulong)(i + 1) * 0x100))))
            .ToArray();
        var chain = Run(0x70000000, placed);
        Assert.Equal("limit", chain.End);
        Assert.Equal(StubChains.MaxHops, chain.Hops.Count);
    }

    [Fact]
    public void An_arm64_stub_on_a_page_not_held_ends_as_unreadable()
    {
        var chain = Run(0x70000000, (0x70000000, Words(Branch(0x70000000, 0x70009000))));
        Assert.Equal("unreadable", chain.End);
        Assert.Equal(0x70009000UL, chain.Address);
    }

    [Fact]
    public void An_arm64_pointer_not_held_ends_as_unreadable_at_the_pointer()
    {
        var chain = Run(0x70000000, (0x70000000, Literal(0x70000000, 0x70008000)));
        Assert.Equal("unreadable", chain.End);
        Assert.Equal(0x70008000UL, chain.Address);
    }

    [Fact]
    public void A_load_that_does_not_end_in_a_branch_is_not_a_stub()
    {
        var chain = Run(0x70000000, (0x70000000, Words(0x58000000 | 16, Ret)));
        Assert.Equal("final", chain.End);
        Assert.Empty(chain.Hops);
    }

    private sealed class Overlay(IProcessMemory inner, (ulong At, byte[] Bytes)[] placed) : IProcessMemory
    {
        public NativeArch Arch => NativeArch.Arm64;
        public bool Is64Bit => true;
        public string Identity => "overlay";
        public IReadOnlyList<DumpModule> Modules => inner.Modules;
        public IReadOnlyList<DumpUnloadedModule> UnloadedModules => [];

        public int ReadMemory(ulong address, Span<byte> destination)
        {
            foreach (var (at, bytes) in placed)
            {
                if (address < at || address >= at + (ulong)bytes.Length) continue;
                int n = Math.Min(destination.Length, bytes.Length - (int)(address - at));
                bytes.AsSpan((int)(address - at), n).CopyTo(destination);
                return n;
            }
            return 0;
        }

        public DumpModule? ModuleAt(ulong address) => inner.ModuleAt(address);
        public DumpMemoryRegion? RegionAt(ulong address) => inner.RegionAt(address);
        public ulong ReadableExtent(ulong start, ulong size) => 0;
    }
}
