using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>ARM64 on Windows: .pdata fragments, entries shrink-wrapped before the prologue, inline import tails, code pointers that read as text.</summary>
public class NativeArm64PdataTests
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;

    /// <summary>
    /// f (prologue; cbz x0, cold; epilogue) at 0x1000, g at 0x1020, a cold fragment of f at 0x1040 and a fragment nothing
    /// reaches at 0x1060: the cold one is part of f, the unreached one stays a function.
    /// </summary>
    [Fact]
    public void Fragments_join_the_function_that_branches_into_them()
    {
        var a = new A64(Code);
        a.Word(A64.StpFpLrPre).Word(A64.MovFpSp).Later(at => A64.Cbz(at, Code + 0x40, 0)).Word(A64.LdpFpLrPost).Word(A64.Ret);
        while (a.Here < Code + 0x20) a.Word(A64.Nop);
        a.Word(A64.MovW(0, 7)).Word(A64.Ret);
        while (a.Here < Code + 0x40) a.Word(A64.Nop);
        a.Word(A64.MovW(0, 1)).Word(A64.LdpFpLrPost).Word(A64.Ret);
        while (a.Here < Code + 0x60) a.Word(A64.Nop);
        a.Word(A64.MovW(0, 2)).Word(A64.Ret);
        var image = CodeTestImage.Synthetic(NativeArch.Arm64, a.Bytes(), pdata:
        [
            new RuntimeFunction(Code, Code + 0x14, 0),
            new RuntimeFunction(Code + 0x20, Code + 0x28, 0),
            new RuntimeFunction(Code + 0x40, Code + 0x4C, 0) { Fragment = true },
            new RuntimeFunction(Code + 0x60, Code + 0x68, 0) { Fragment = true },
        ]);
        var index = NativeCodeIndex.Build(image);

        Assert.Equal([Code, Code + 0x20, Code + 0x60], index.Functions.Select(f => f.Start));
        Assert.Equal(Code, index.FunctionAt(Code + 0x44)!.Start);
        Assert.DoesNotContain(index.RefsTo(Code + 0x40), x => x.Kind == XrefKind.TailCall);
    }

    private static byte[] Pointer(uint rva, int at = 0)
    {
        var data = new byte[0x100];
        BitConverter.GetBytes(0x10000000UL + rva).CopyTo(data, at);
        return data;
    }

    /// <summary>
    /// MSVC shrink-wrapping: the entry (ldr x8, [x0, #8]; cbz x8, ret) runs into the .pdata entry of the prologue: the entry,
    /// reached through a pointer, is the function, and the .pdata start joins it.
    /// </summary>
    [Fact]
    public void A_head_before_the_prologue_is_the_start()
    {
        var a = new A64(Code);
        a.Word(A64.LdrX(8, 0, 8)).Later(at => A64.Cbz(at, Code + 0x14, 8));
        a.Word(A64.StpFpLrPre).Word(A64.MovFpSp).Word(A64.LdpFpLrPost).Word(A64.Ret);
        var image = CodeTestImage.Synthetic(NativeArch.Arm64, a.Bytes(), Pointer(Code), pdata: [new RuntimeFunction(Code + 8, Code + 0x14, 0)],
            relocations: [CodeTestImage.SyntheticDataRva]);
        var index = NativeCodeIndex.Build(image);

        Assert.Equal([Code], index.Functions.Select(f => f.Start));
        Assert.Equal(Code, index.FunctionAt(Code + 0x10)!.Start);
    }

    /// <summary>An import stub the code runs on into (cbz x0, stub; mov w0, #1; stub: adrp; ldr; br) is the function's own tail, not a thunk.</summary>
    [Fact]
    public void An_inline_import_tail_is_no_thunk()
    {
        const uint Slot = CodeTestImage.SyntheticDataRva + 0x40;
        var a = new A64(Code);
        uint stub = Code + 8;
        a.Later(at => A64.Cbz(at, stub, 0)).Word(A64.MovW(0, 1));
        a.Later(at => A64.Adrp(at, Slot, 16, 0x10000000UL)).Word(A64.LdrX(17, 16, Slot & 0xFFF)).Word(A64.Br(17));
        var image = CodeTestImage.Synthetic(NativeArch.Arm64, a.Bytes(), imports: [new NativeImport("python312.dll", "PyLong_FromLong", null, 0, Slot, false)], entry: Code);
        var index = NativeCodeIndex.Build(image);

        Assert.Equal([Code], index.Functions.Select(f => f.Start));
        Assert.Equal(Code, index.FunctionAt(stub)!.Start);
    }

    /// <summary>Code a relocated pointer names is tried even when its bytes read as UTF-16 text (cbz x0; str x1, [x0, #240]; ret).</summary>
    [Fact]
    public void A_code_pointer_target_that_reads_as_text_is_a_function()
    {
        var a = new A64(Code);
        a.Word(A64.Ret).Word(0).Word(0).Word(0);
        uint setter = a.Here;
        a.Word(0xB4000040).Word(0xF9007801).Word(A64.Ret).Word(0);
        var image = CodeTestImage.Synthetic(NativeArch.Arm64, a.Bytes(), Pointer(setter), relocations: [CodeTestImage.SyntheticDataRva], entry: Code);
        Assert.NotNull(Corvus.Native.Code.StringDetector.Detect(image, setter, 64, new byte[160]));
        var index = NativeCodeIndex.Build(image);

        Assert.True((index.FunctionByStart(setter)?.Sources & FunctionSource.DataPointer) != 0);
    }

    /// <summary>Packed flag 2 and .xdata whose unwind codes begin with end_c (after the epilogue scopes) mark fragments.</summary>
    [Fact]
    public void Fragments_are_read_from_packed_flag_2_and_end_c()
    {
        var b = new PeBuilder { Machine = 0xAA64 };
        var text = b.Add(".text", new byte[0x100], 0x60000020);
        b.EntryPoint = text.Rva;
        uint pdata = 0;
        b.Add(".pdata", rva =>
        {
            var blob = new PeBlob(rva);
            uint prologue = blob.U32(0x04 | 1u << 27);                     // 4 words, one code word: save_fplr_x
            blob.U32(0xE4E10081);
            uint endC = blob.U32(0x04 | 1u << 27);                         // one code word starting with end_c
            blob.U32(0xE4E1E1E5);
            uint scoped = blob.U32(0x04 | 1u << 22 | 1u << 27);            // one epilogue scope word, then end_c
            blob.U32(0x00000002);
            blob.U32(0xE4E1E1E5);
            pdata = blob.U32(text.Rva);
            blob.U32(prologue);
            blob.U32(text.Rva + 0x10);
            blob.U32(endC);
            blob.U32(text.Rva + 0x20);
            blob.U32(scoped);
            blob.U32(text.Rva + 0x30);
            blob.U32(2 | (4 << 2));                                          // packed, flag 2: no prologue
            blob.U32(text.Rva + 0x40);
            blob.U32(1 | (4 << 2));                                          // packed, flag 1
            return blob.ToArray();
        });
        b.Directories[PeDirectory.Exception] = (pdata, 40);
        var pe = PeFile.FromBytes(b.Build(), "frag.dll");
        Assert.Equal([false, true, true, true, false], pe.RuntimeFunctions.Select(r => r.Fragment));
    }
}
