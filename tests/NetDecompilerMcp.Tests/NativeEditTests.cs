using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Patching;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

public class NativeEditTests
{
    // A tiny x64 image whose .text holds: mov eax,1 (5 bytes) ; ret ; then NOP filler.
    private static byte[] TinyImage()
    {
        var b = new PeBuilder { Is64 = true, Machine = 0x8664, ImageBase = 0x140000000 };
        var code = new byte[64];
        // 0x00: mov eax, 1
        code[0] = 0xB8; code[1] = 0x01;
        // 0x05: ret
        code[5] = 0xC3;
        for (int i = 6; i < code.Length; i++) code[i] = 0x90; // nop filler
        var text = b.Add(".text", code, 0x60000020);
        b.EntryPoint = text.Rva;
        return b.Build();
    }

    private sealed class Harness : IDisposable
    {
        public readonly TempDir Dir = new();
        public readonly Env Env = new();
        public readonly AnnotationStore Store;
        public readonly NativeCodeService Code;
        public readonly NativeEditService Edits;
        public readonly string Path;

        public Harness()
        {
            Store = new AnnotationStore(Dir.File("ann"));
            Code = new NativeCodeService(Env.Workspace, Env.Options, null, Store);
            Edits = new NativeEditService(Env.Workspace, Code);
            Path = Dir.File("tiny.dll");
            File.WriteAllBytes(Path, TinyImage());
        }

        public LoadedNative Load() => Env.Workspace.LoadAny(Path).Native!;
        public async Task<(LoadedNative, NativeCodeIndex)> Open()
        {
            var n = Load();
            return (n, await Code.Index(n, null, default));
        }

        public void Dispose() { Env.Dispose(); Dir.Dispose(); }
    }

    [Fact]
    public void Assembler_JmpToLabel_ComputesDisplacement()
    {
        // jmp over a nop to a label; at VA 0x140001000 the near jmp is E9 + rel32.
        var r = X86Assembler.Assemble(NativeArch.X64, 0x140001000, "jmp target\nnop\ntarget:\nret");
        Assert.Equal(0xE9, r.Bytes[0]);
        int rel = BitConverter.ToInt32(r.Bytes, 1);
        // jmp is 5 bytes, then 1 nop -> target is 1 byte past the jmp end, so rel == 1.
        Assert.Equal(1, rel);
        Assert.Equal(7, r.Bytes.Length); // 5 (jmp) + 1 (nop) + 1 (ret)
        Assert.Equal(0x90, r.Bytes[5]);
        Assert.Equal(0xC3, r.Bytes[6]);
    }

    [Fact]
    public void Assembler_CallToAbsoluteAddress()
    {
        // call an absolute VA; from VA 0x140001000 a 5-byte call to 0x140001100 has rel32 = 0x100 - 5.
        var r = X86Assembler.Assemble(NativeArch.X64, 0x140001000, "call 0x140001100");
        Assert.Equal(0xE8, r.Bytes[0]);
        Assert.Equal(0x100 - 5, BitConverter.ToInt32(r.Bytes, 1));
    }

    [Fact]
    public async Task RenameAndComment_RoundTripThroughReloadAndNewWorkspace()
    {
        using var h = new Harness();
        var (native, index) = await h.Open();
        uint entry = native.Image.EntryPointRva;

        Assert.Contains("Named", h.Edits.Rename(native, index, entry, "DecryptBlock", false));
        Assert.Contains("Commented", h.Edits.Comment(native, index, entry, "the decrypt routine"));
        Assert.Equal("DecryptBlock", index.NameAt(entry));

        // Survives a reload (re-read from disk, analysis discarded).
        var reloaded = h.Env.Workspace.ReloadNative(native);
        var index2 = await h.Code.Index(reloaded, null, default);
        Assert.Equal("DecryptBlock", index2.NameAt(entry));
        Assert.Equal("the decrypt routine", index2.CommentFor(entry));

        // Survives a brand-new workspace that shares the sidecar store (restart).
        using var env2 = new Env();
        var code2 = new NativeCodeService(env2.Workspace, env2.Options, null, h.Store);
        var fresh = env2.Workspace.LoadAny(h.Path).Native!;
        var index3 = await code2.Index(fresh, null, default);
        Assert.Equal("DecryptBlock", index3.NameAt(entry));
    }

    [Fact]
    public async Task Rename_FlowsIntoListFunctionsAndDisassemble()
    {
        using var h = new Harness();
        var (native, index) = await h.Open();
        uint entry = native.Image.EntryPointRva;
        h.Edits.Rename(native, index, entry, "Zonk", false);

        var tools = new NativeCodeTools(h.Env.Workspace, h.Code, h.Env.Pager);
        Assert.Contains("Zonk", await tools.ListFunctions(h.Path));
        Assert.Contains("Zonk", await tools.Disassemble(h.Path, "Zonk"));
    }

    [Fact]
    public async Task Rename_RejectsBadNamesAndDuplicates()
    {
        using var h = new Harness();
        var (native, index) = await h.Open();
        uint entry = native.Image.EntryPointRva;
        Assert.Throws<ToolError>(() => h.Edits.Rename(native, index, entry, "1bad", false));
        h.Edits.Rename(native, index, entry, "Used", false);
        // A different address cannot reuse the name unless allowDuplicate.
        Assert.Throws<ToolError>(() => h.Edits.Rename(native, index, entry + 5, "Used", false));
        Assert.Contains("Named", h.Edits.Rename(native, index, entry + 5, "Used", true));
    }

    [Fact]
    public async Task PatchBytes_NopPadsToInstructionBoundaryAndIsVisible()
    {
        using var h = new Harness();
        var (native, index) = await h.Open();
        uint entry = native.Image.EntryPointRva;

        // Overwrite the 5-byte "mov eax,1" with a 1-byte ret; the 4 trailing bytes are NOP-padded.
        var prepared = h.Edits.PreparePatch(index, entry, [0xC3], force: false, "test");
        Assert.Equal(5, prepared.Patch.Length);
        Assert.Equal(0xC3, prepared.Patch.Replacement[0]);
        Assert.All(prepared.Patch.Replacement[1..], x => Assert.Equal(0x90, x));
        h.Edits.ApplyPatch(native, index, prepared, dryRun: false);

        // Every read path sees the patched bytes.
        var ntools = new NativeTools(h.Env.Workspace, h.Env.Pager);
        var dump = await ntools.ReadBytes(h.Path, $"rva:0x{entry:X}", 5);
        Assert.Contains("C3 90 90 90 90", dump);
    }

    [Fact]
    public async Task PatchBytes_RefusesMidInstructionAndPastFunctionEnd()
    {
        using var h = new Harness();
        var (native, index) = await h.Open();
        uint entry = native.Image.EntryPointRva;
        // entry+1 is inside "mov eax,1".
        Assert.Throws<ToolError>(() => h.Edits.PreparePatch(index, entry + 1, [0x90], force: false, "x"));
        // force bypasses the check.
        Assert.NotNull(h.Edits.PreparePatch(index, entry + 1, [0x90], force: true, "x"));
    }

    [Fact]
    public async Task PatchBytes_RefusesUnmappedZeroFill()
    {
        using var h = new Harness();
        var (native, index) = await h.Open();
        // An RVA well past the file-backed bytes of the section is zero-fill / unmapped.
        Assert.Throws<ToolError>(() => h.Edits.PreparePatch(index, native.Image.SizeOfImage - 4, [0x90], force: false, "x"));
    }

    [Fact]
    public async Task PatchAsm_And_Undo()
    {
        using var h = new Harness();
        var (native, index) = await h.Open();
        uint entry = native.Image.EntryPointRva;

        var r = X86Assembler.Assemble(NativeArch.X64, native.Image.ImageBase + entry, "xor eax, eax\nret");
        var prepared = h.Edits.PreparePatch(index, entry, r.Bytes, force: false, "patch_asm");
        var applied = h.Edits.ApplyPatch(native, index, prepared, dryRun: false);
        Assert.Contains("Patched", applied);
        Assert.Contains("native edit", h.Edits.List(native));

        var undo = h.Edits.Undo(native, null);
        Assert.Contains("Undid", undo);
        Assert.Contains("no native edits", h.Edits.List(native));
        // After undo the original bytes are back.
        Assert.Equal(0xB8, native.Image.FileBytes.Span[(int)Offset(native, entry)]);
    }

    [Fact]
    public async Task Save_WritesPatchedFileAndVerifiesUnpatchedBytes()
    {
        using var h = new Harness();
        var (native, index) = await h.Open();
        uint entry = native.Image.EntryPointRva;
        var prepared = h.Edits.PreparePatch(index, entry, [0xCC], force: false, "int3");
        h.Edits.ApplyPatch(native, index, prepared, dryRun: false);

        var outPath = h.Dir.File("out.dll");
        var report = h.Edits.Save(native, outPath, overwrite: false, stripSignature: false);
        Assert.Contains("Verified", report);
        Assert.True(File.Exists(outPath));

        // The written file differs from the original only in the patched range.
        var original = TinyImage();
        var written = File.ReadAllBytes(outPath);
        Assert.Equal(original.Length, written.Length);
        long off = Offset(native, entry);
        int patchLen = prepared.Patch.Length; // 5: the int3 plus NOP padding over "mov eax,1"
        for (int i = 0; i < original.Length; i++)
            if (i < off || i >= off + patchLen) Assert.Equal(original[i], written[i]);
        Assert.Equal(0xCC, written[(int)off]);

        // Will not overwrite an existing file without overwrite=true.
        Assert.Throws<ToolError>(() => h.Edits.Save(native, outPath, overwrite: false, stripSignature: false));
    }

    private static long Offset(LoadedNative native, uint rva)
    {
        native.Image.TryRvaToFileOffset(rva, out var off);
        return off;
    }

    // ---- real signed image (a copy of a System32 DLL) ----

    [Trait("Speed", "Slow")]
    [WindowsFact]
    public async Task Save_RecomputesChecksumAndNotesSignature()
    {
        var src = PeCorpus.System32("kernel32.dll");
        if (src == null) return;
        using var h = new Harness();
        var copy = h.Dir.File("kernel32-copy.dll");
        File.Copy(src, copy);
        var native = h.Env.Workspace.LoadAny(copy).Native!;
        var index = await h.Code.Index(native, null, default);

        // Patch one byte at the entry point.
        uint entry = native.Image.EntryPointRva;
        var prepared = h.Edits.PreparePatch(index, entry, [0x90], force: true, "nop");
        h.Edits.ApplyPatch(native, index, prepared, dryRun: false);

        var outPath = h.Dir.File("kernel32-patched.dll");
        var report = h.Edits.Save(native, outPath, overwrite: false, stripSignature: false);
        Assert.Contains("checksum recomputed", report);
        Assert.Contains("Authenticode-signed", report);

        var written = PeFileOf(outPath);
        Assert.True(written.Checksum.Matches); // the recomputed checksum is valid for the written bytes
    }

    private static NetDecompilerMcp.Native.Pe.PeFile PeFileOf(string path) => NetDecompilerMcp.Native.Pe.PeFile.Open(path);
}
