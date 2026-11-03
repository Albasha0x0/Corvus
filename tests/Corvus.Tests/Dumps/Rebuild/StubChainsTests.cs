using System.Buffers.Binary;
using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Jump stubs are followed to the code control reaches.</summary>
public sealed class StubChainsTests
{
    private const ulong Export = 0x180001000;

    private static byte[] Near(ulong from, ulong to)
    {
        var b = new byte[5];
        b[0] = 0xE9;
        BinaryPrimitives.WriteInt32LittleEndian(b.AsSpan(1), (int)(to - (from + 5)));
        return b;
    }

    private static byte[] Pointer64(ulong from, ulong slot)
    {
        var b = new byte[6];
        b[0] = 0xFF;
        b[1] = 0x25;
        BinaryPrimitives.WriteInt32LittleEndian(b.AsSpan(2), (int)(slot - (from + 6)));
        return b;
    }

    private static byte[] Pointer32(ulong slot)
    {
        var b = new byte[6];
        b[0] = 0xFF;
        b[1] = 0x25;
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(2), (uint)slot);
        return b;
    }

    private static byte[] Value(ulong v, int size)
    {
        var b = new byte[size];
        if (size == 8) BinaryPrimitives.WriteUInt64LittleEndian(b, v);
        else BinaryPrimitives.WriteUInt32LittleEndian(b, (uint)v);
        return b;
    }

    private static byte[] Register64(ulong to) => [0x48, 0xB8, .. Value(to, 8), 0xFF, 0xE0];

    private static byte[] PushReturn(ulong to) => [0x68, .. Value(to, 4), 0xC3];

    private static StubChain Run(NativeArch machine, ulong start, params (ulong At, byte[] Bytes)[] placed)
    {
        using var dir = new TempDir();
        var image = RebuildFixtures.Build(new PeSpec(
            true, [new SectionSpec(".text", 0x60000020, new byte[0x40])],
            Exports: [new ExportSpec("Target", 0x1000)]));
        using var dump = RebuildFixtures.Dump(dir, new Placed("fixture.dll", image, 0x180000000));
        var memory = new Overlay(dump, machine, placed);
        return StubChains.Follow(memory, start, machine, new ExportMap(dump));
    }

    [Theory]
    [InlineData(NativeArch.X64)]
    [InlineData(NativeArch.X86)]
    public void A_near_jump_stub_is_followed_to_its_target(NativeArch machine)
    {
        var chain = Run(machine, 0x70000000, (0x70000000, Near(0x70000000, 0x70001000)), (0x70001000, [0x90, 0xC3]));
        Assert.Equal("final", chain.End);
        Assert.Equal(0x70001000UL, chain.Address);
        Assert.Equal("near", Assert.Single(chain.Hops).Form);
    }

    [Fact]
    public void A_rip_relative_pointer_stub_x64_is_followed_through_the_pointer()
    {
        var chain = Run(NativeArch.X64, 0x70000000,
            (0x70000000, Pointer64(0x70000000, 0x70000100)), (0x70000100, Value(0x70002000, 8)), (0x70002000, [0xC3]));
        Assert.Equal("final", chain.End);
        Assert.Equal(0x70002000UL, chain.Address);
        Assert.Equal("pointer", Assert.Single(chain.Hops).Form);
    }

    [Fact]
    public void An_absolute_pointer_stub_x86_is_followed_through_the_pointer()
    {
        var chain = Run(NativeArch.X86, 0x70000000,
            (0x70000000, Pointer32(0x70000100)), (0x70000100, Value(0x70002000, 4)), (0x70002000, [0xC3]));
        Assert.Equal("final", chain.End);
        Assert.Equal(0x70002000UL, chain.Address);
        Assert.Equal("pointer", Assert.Single(chain.Hops).Form);
    }

    [Fact]
    public void A_load_and_jump_stub_x64_is_followed_to_its_target()
    {
        var chain = Run(NativeArch.X64, 0x70000000, (0x70000000, Register64(0x70003000)), (0x70003000, [0xC3]));
        Assert.Equal("final", chain.End);
        Assert.Equal(0x70003000UL, chain.Address);
        Assert.Equal("register", Assert.Single(chain.Hops).Form);
    }

    [Theory]
    [InlineData(NativeArch.X64)]
    [InlineData(NativeArch.X86)]
    public void A_push_and_return_stub_is_followed_to_its_target(NativeArch machine)
    {
        var chain = Run(machine, 0x70000000, (0x70000000, PushReturn(0x70004000)), (0x70004000, [0xC3]));
        Assert.Equal("final", chain.End);
        Assert.Equal(0x70004000UL, chain.Address);
        Assert.Equal("push-return", Assert.Single(chain.Hops).Form);
    }

    [Fact]
    public void A_chain_of_two_stubs_ends_at_the_export_it_reaches()
    {
        var chain = Run(NativeArch.X64, 0x180002000,
            (0x180002000, Near(0x180002000, 0x180003000)), (0x180003000, Near(0x180003000, Export)));
        Assert.Equal("final", chain.End);
        Assert.Equal(Export, chain.Address);
        Assert.Equal(2, chain.Hops.Count);
    }

    [Fact]
    public void A_loop_of_stubs_ends_as_a_loop()
    {
        var chain = Run(NativeArch.X86, 0x70000000,
            (0x70000000, Near(0x70000000, 0x70001000)), (0x70001000, Near(0x70001000, 0x70000000)));
        Assert.Equal("loop", chain.End);
        Assert.Equal(0x70000000UL, chain.Address);
    }

    [Fact]
    public void A_stub_on_a_page_not_held_ends_as_unreadable()
    {
        var chain = Run(NativeArch.X64, 0x70000000, (0x70000000, Near(0x70000000, 0x70009000)));
        Assert.Equal("unreadable", chain.End);
        Assert.Equal(0x70009000UL, chain.Address);
    }

    [Fact]
    public void A_pointer_not_held_ends_as_unreadable_at_the_pointer()
    {
        var chain = Run(NativeArch.X64, 0x70000000, (0x70000000, Pointer64(0x70000000, 0x70008000)));
        Assert.Equal("unreadable", chain.End);
        Assert.Equal(0x70008000UL, chain.Address);
    }

    [Fact]
    public void A_chain_past_8_hops_names_the_limit()
    {
        var placed = Enumerable.Range(0, 10)
            .Select(i => (At: 0x70000000UL + (ulong)i * 0x100,
                Bytes: Near(0x70000000UL + (ulong)i * 0x100, 0x70000000UL + (ulong)(i + 1) * 0x100)))
            .ToArray();
        var chain = Run(NativeArch.X64, 0x70000000, placed);
        Assert.Equal("limit", chain.End);
        Assert.Equal(StubChains.MaxHops, chain.Hops.Count);
        Assert.Contains("8", chain.Detail);
    }

    [Fact]
    public void Another_machine_ends_as_unknown_and_names_the_machine()
    {
        var chain = Run(NativeArch.Arm, 0x70000000);
        Assert.Equal("unknown", chain.End);
        Assert.Equal("Arm stubs are not followed", chain.Detail);
    }

    private sealed class Overlay(IProcessMemory inner, NativeArch arch, (ulong At, byte[] Bytes)[] placed) : IProcessMemory
    {
        public NativeArch Arch => arch;
        public bool Is64Bit => arch != NativeArch.X86;
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
