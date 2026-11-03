using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>A code row that jumps to a stub names where the stub chain ends.</summary>
public sealed class DumpChangeChainTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    public static TheoryData<ushort, StubForm, int> Forms()
    {
        var data = new TheoryData<ushort, StubForm, int>();
        foreach (int hops in new[] { 1, 2 })
        {
            data.Add(0x8664, StubForm.X64MovJmp, hops);
            data.Add(0x8664, StubForm.X64PushRet, hops);
            data.Add(0x8664, StubForm.X64JmpRip, hops);
            data.Add(0x14C, StubForm.X86JmpAbs, hops);
            data.Add(0x14C, StubForm.X86Jmp32, hops);
            data.Add(0x14C, StubForm.X86PushRet, hops);
        }
        return data;
    }

    private static string Description(StubDump set)
    {
        using var service = new MinidumpService();
        var rows = service.Changes(set.DumpPath, set.ImageFolder, "main.dll", 0, 50, CancellationToken.None).Rows;
        return Assert.Single(rows, r => r.Kind == "code").Description!;
    }

    [Theory]
    [MemberData(nameof(Forms))]
    public void A_patched_function_names_the_export_its_stub_chain_reaches(ushort machine, StubForm form, int hops)
    {
        var set = StubFixtures.Chain(_dir, machine, form, hops);

        string text = Description(set);

        Assert.StartsWith("jump ", text);
        Assert.EndsWith($", then provider.dll!Target ({hops} hop{(hops == 1 ? "" : "s")})", text);
    }

    [Theory]
    [InlineData(0xAA64, StubForm.Arm64LdrBr, 1)]
    [InlineData(0x8664, StubForm.X64JmpRip, 1)]
    [InlineData(0x14C, StubForm.X86JmpAbs, 1)]
    [InlineData(0x8664, StubForm.X64JmpRip, 2)]
    [InlineData(0x14C, StubForm.X86JmpAbs, 2)]
    [InlineData(0xAA64, StubForm.Arm64B, 1)]
    [InlineData(0xAA64, StubForm.Arm64LdrBr, 2)]
    [InlineData(0xAA64, StubForm.Arm64B, 2)]
    public void A_chain_from_its_first_stub_names_the_export_it_reaches(ushort machine, StubForm form, int hops)
    {
        var set = StubFixtures.Chain(_dir, machine, form, hops);
        using var memory = MinidumpFile.Open(set.DumpPath);

        string text = MinidumpService.ChainText(memory, new ExportMap(memory), set.Stubs[0], machine == 0xAA64 ? NativeArch.Arm64 : machine == 0x14C ? NativeArch.X86 : NativeArch.X64);

        Assert.Equal($", then provider.dll!Target ({hops} hop{(hops == 1 ? "" : "s")})", text);
    }

    [Fact]
    public void A_stub_loop_is_named_on_the_row()
    {
        var set = StubFixtures.Loop(_dir, 0x8664, StubForm.X64MovJmp);

        Assert.EndsWith(", then a loop", Description(set));
    }

    [Fact]
    public void A_direct_jump_to_an_export_keeps_its_wording()
    {
        var set = StubFixtures.Chain(_dir, 0x8664, StubForm.X64MovJmp, 1);
        using var memory = MinidumpFile.Open(set.DumpPath);

        Assert.Equal("", MinidumpService.ChainText(memory, new ExportMap(memory), set.Export, NativeArch.X64));
    }
}
