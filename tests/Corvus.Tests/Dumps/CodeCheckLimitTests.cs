using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>The per-module code check at its byte limit.</summary>
public sealed class CodeCheckLimitTests
{
    private const ulong Base = 0x1_8000_0000;
    private const long Limit = 1 << 20;

    private static CodeComparison Compare(int sectionBytes)
    {
        var raw = Enumerable.Range(0, sectionBytes).Select(i => (byte)(i * 7)).ToArray();
        var file = RebuildFixtures.Pe(new PeSpec(true, [new SectionSpec(".text", 0x60000020, raw)], ImageBase: Base));
        var mapped = RebuildFixtures.Mapped(file);
        var module = new DumpModule(Base, (uint)mapped.Length, 0, 0, @"Z:\app\m.dll", null, null, null);
        return ModuleChecks.CompareCode(new Flat(mapped), module, PeFile.FromBytes(file), Limit);
    }

    [Fact]
    public void A_section_equal_to_the_limit_is_compared_whole()
    {
        var result = Compare((int)Limit);

        Assert.Equal("same", result.State);
        Assert.DoesNotContain("limit", result.Detail);
    }

    [Fact]
    public void A_section_one_page_over_the_limit_names_the_left_out_pages()
    {
        var result = Compare((int)Limit + 0x1000);

        Assert.Equal("partial", result.State);
        Assert.Contains("256 of 257 page(s)", result.Detail);
        Assert.Contains("the rest is past the 1 MB limit", result.Detail);
    }

    private sealed class Flat(byte[] bytes) : IProcessMemory
    {
        public NativeArch Arch => NativeArch.X64;
        public bool Is64Bit => true;
        public string Identity => "flat";
        public IReadOnlyList<DumpModule> Modules => [];
        public IReadOnlyList<DumpUnloadedModule> UnloadedModules => [];
        public int ReadMemory(ulong address, Span<byte> destination)
        {
            long at = (long)(address - Base);
            if (at < 0 || at >= bytes.Length) return 0;
            int n = (int)Math.Min(destination.Length, bytes.Length - at);
            bytes.AsSpan((int)at, n).CopyTo(destination);
            return n;
        }
        public DumpModule? ModuleAt(ulong address) => null;
        public DumpMemoryRegion? RegionAt(ulong address) => null;
        public ulong ReadableExtent(ulong start, ulong size) => 0;
    }
}
