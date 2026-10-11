using System.Buffers.Binary;
using System.Diagnostics;
using Iced.Intel;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Code;
using Corvus.Native.Patching;
using Corvus.Native.Pe;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Native patches and base relocations: entries under a patch are kept / neutralized, new absolute addresses get an
/// entry in an ABSOLUTE slot of their page's block, undo restores the table, save_native re-checks it, and the patched
/// code decodes to the intended operation after the image is rebased exactly as the loader does it.
/// </summary>
public class NativeRelocationPatchTests(ITestOutputHelper output)
{
    private const ulong Base32 = 0x10000000;

    // x86 DLL: .text @0x1000 = push offset g0 ; mov eax,[g1] ; nops ; ret (at 0x103F)
    //          .data @0x2000 = g0, g1, a pointer to .text at +8
    //          .reloc @0x3000: page 0x1000 {HIGHLOW 0x001, HIGHLOW 0x006, ABS, ABS}, page 0x2000 {HIGHLOW 0x008, ABS}
    internal static byte[] X86Image()
    {
        var b = new PeBuilder { Is64 = false, Machine = 0x14C, ImageBase = Base32, Characteristics = 0x2102, DllCharacteristics = 0x0140 };
        var code = new byte[0x40];
        code[0] = 0x68; BinaryPrimitives.WriteUInt32LittleEndian(code.AsSpan(1), (uint)Base32 + 0x2000);
        code[5] = 0xA1; BinaryPrimitives.WriteUInt32LittleEndian(code.AsSpan(6), (uint)Base32 + 0x2004);
        for (int i = 10; i < 0x3F; i++) code[i] = 0x90;
        code[0x3F] = 0xC3;
        var text = b.Add(".text", code, 0x60000020);
        var data = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(8), (uint)Base32 + 0x1000);
        b.Add(".data", data, 0xC0000040);
        var reloc = new byte[16 + 12];
        Block(reloc, 0, 0x1000, 0x3001, 0x3006, 0, 0);
        Block(reloc, 16, 0x2000, 0x3008, 0);
        var r = b.Add(".reloc", reloc, 0x42000040);
        b.Directories[5] = (r.Rva, (uint)reloc.Length);
        b.EntryPoint = text.Rva;
        return b.Build();
    }

    private static void Block(byte[] into, int at, uint page, params ushort[] entries)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(into.AsSpan(at), page);
        BinaryPrimitives.WriteUInt32LittleEndian(into.AsSpan(at + 4), (uint)(8 + entries.Length * 2));
        for (int i = 0; i < entries.Length; i++) BinaryPrimitives.WriteUInt16LittleEndian(into.AsSpan(at + 8 + i * 2), entries[i]);
    }

    private sealed class Harness : IDisposable
    {
        public readonly TempDir Dir = new();
        public readonly Env Env = new();
        public readonly NativeCodeService Code;
        public readonly NativeEditService Edits;
        public readonly string Path;

        public Harness(byte[] image)
        {
            Code = new NativeCodeService(Env.Workspace, Env.Options, null, new AnnotationStore(Dir.File("ann")));
            Edits = new NativeEditService(Env.Workspace, Code);
            Path = Dir.File("reloc.dll");
            File.WriteAllBytes(Path, image);
        }

        public async Task<(LoadedNative, NativeCodeIndex)> Open()
        {
            var n = Env.Workspace.LoadAny(Path).Native!;
            return (n, await Code.Index(n, null, default));
        }

        public void Dispose() { Env.Dispose(); Dir.Dispose(); }
    }

    private static NativeEditService.PatchResult Asm(NativeEditService edits, NativeCodeIndex index, uint rva, string text, bool force = false, RelocationMode mode = RelocationMode.Auto)
    {
        var r = X86Assembler.Assemble(index.Image.Arch, index.Image.ImageBase + rva, text);
        return edits.PreparePatch(index, rva, r.Bytes, force, "patch_asm", mode, r.Constants);
    }

    private static string Actions(RelocationPlan? plan) =>
        string.Join(", ", (plan?.Changes ?? []).Select(c => $"{c.Action} 0x{c.TargetRva:X}"));

    [Fact]
    public async Task X86_patches_keep_neutralize_and_add_relocations_and_survive_a_rebase()
    {
        using var h = new Harness(X86Image());
        var (native, index) = await h.Open();

        // A numeric push over 'push offset g0': the entry would add the load delta into 0x1234.
        var push = Asm(h.Edits, index, 0x1000, "push 0x1234");
        Assert.Equal("neutralized 0x1001", Actions(push.Patch.Relocations));
        // A copied instruction keeps its entry; relocations=keep keeps it whatever the bytes.
        Assert.Equal("kept 0x1001", Actions(Asm(h.Edits, index, 0x1000, "push 0x10002000").Patch.Relocations));
        Assert.Equal("kept 0x1001", Actions(h.Edits.PreparePatch(index, 0x1000, [0x68, 0x34, 0x12, 0, 0], false, "raw", RelocationMode.Keep).Patch.Relocations));

        // A new absolute operand one byte further on: both old entries go, one freed slot carries the new address.
        var moved = Asm(h.Edits, index, 0x1000, "nop\nmov eax, dword ptr [0x10002004]");
        Assert.Equal("neutralized 0x1001, added 0x1002, neutralized 0x1006", Actions(moved.Patch.Relocations));
        var report = h.Edits.ApplyPatch(native, index, moved, dryRun: false);
        Assert.Contains("added", report);
        Assert.Contains("(entry at rva 0x3008)", report);
        Assert.Equal(new uint[] { 0x1002, 0x2008 }, native.Image.RelocationRvas.ToArray());
        Assert.Contains("neutralized", h.Edits.List(native));

        // Rebased by +0x01000000 the new operand points at the moved g1, and nothing else in the patch moved.
        var rebased = Rebase(native.Pe!, native.Patches.PatchedBytes(), Base32 + 0x01000000);
        var mov = DecodeAt(native.Pe!, rebased, 0x1001, Base32 + 0x01000000);
        Assert.Equal(Mnemonic.Mov, mov.Mnemonic);
        Assert.Equal(0x11002004u, mov.MemoryDisplacement32);
        Assert.Equal(0x90, rebased[(int)Offset(native.Image, 0x1006)]);

        // Saved: bytes outside the patch and the two entry rewrites match, and the table re-parses consistently.
        var save = h.Edits.Save(native, h.Dir.File("out.dll"), overwrite: false, stripSignature: false);
        Assert.Contains("Verified", save);
        Assert.Contains("Relocations verified", save);

        // Four new addresses in one page: three ABSOLUTE slots (the one neutralized above and two padding), so the fourth has none.
        var index2 = await h.Code.Index(native, null, default);
        var four = "mov eax, dword ptr [0x10002000]\nmov ecx, dword ptr [0x10002004]\nmov edx, dword ptr [0x10002008]\nmov ebx, dword ptr [0x1000200C]";
        var ex = Assert.Throws<ToolError>(() => Asm(h.Edits, index2, 0x1010, four));
        Assert.Contains("no_relocation_slot", ex.Message);
        Assert.Contains("force=true", ex.Remediation);
        var forced = Asm(h.Edits, index2, 0x1010, four, force: true);
        Assert.Equal("added 0x1011, added 0x1017, added 0x101D, unrelocated 0x1023", Actions(forced.Patch.Relocations));

        // Undo restores the original table.
        h.Edits.Undo(native, null);
        Assert.Equal(new uint[] { 0x1001, 0x1006, 0x2008 }, native.Image.RelocationRvas.ToArray());
        output.WriteLine(report);
    }

    [Fact]
    public void X64_imm64_addresses_are_kept_moved_and_data_pointers_follow_the_new_value()
    {
        // .text @0x1000: mov rax, 0x140002000 (DIR64 at 0x1002); .data @0x2000: a pointer (DIR64 at 0x2000).
        var b = new PeBuilder { Is64 = true, ImageBase = 0x140000000 };
        var code = new byte[0x20];
        code[0] = 0x48; code[1] = 0xB8; BinaryPrimitives.WriteUInt64LittleEndian(code.AsSpan(2), 0x140002000);
        for (int i = 10; i < code.Length; i++) code[i] = 0x90;
        var text = b.Add(".text", code, 0x60000020);
        var data = new byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(data, 0x140001000);
        b.Add(".data", data, 0xC0000040);
        var reloc = new byte[24];
        Block(reloc, 0, 0x1000, 0xA002, 0);
        Block(reloc, 12, 0x2000, 0xA000, 0);
        var r = b.Add(".reloc", reloc, 0x42000040);
        b.Directories[5] = (r.Rva, (uint)reloc.Length);
        b.EntryPoint = text.Rva;
        var pe = PeFile.FromBytes(b.Build(), "x64.dll");
        var original = code[..11];

        RelocationPlan Plan(string asm)
        {
            var a = X86Assembler.Assemble(NativeArch.X64, 0x140001000, asm);
            var replacement = a.Bytes.Concat(Enumerable.Repeat((byte)0x90, Math.Max(0, 11 - a.Bytes.Length))).ToArray();
            return PatchRelocations.Plan(pe, 0x1000, original[..replacement.Length], replacement, a.Constants, false, RelocationMode.Auto, false);
        }

        Assert.Equal("kept 0x1002", Actions(Plan("mov rcx, 0x140002008")));       // imm64 inside the image
        Assert.Equal("neutralized 0x1002", Actions(Plan("mov rcx, 0x12345678ABCD"))); // a plain number
        var moved = Plan("nop\nmov rax, 0x140002000");
        Assert.Equal("neutralized 0x1002, added 0x1003", Actions(moved));
        Assert.Equal((ushort)0xA003, moved.Edits.Single().Replacement); // the same slot, retargeted

        // Data: the entry stays while the new value is still an in-image pointer.
        var keep = PatchRelocations.Plan(pe, 0x2000, data[..8], BitConverter.GetBytes(0x140001010UL), null, true, RelocationMode.Auto, false);
        Assert.Equal("kept 0x2000", Actions(keep));
        var drop = PatchRelocations.Plan(pe, 0x2000, data[..8], BitConverter.GetBytes(42UL), null, true, RelocationMode.Auto, false);
        Assert.Equal("neutralized 0x2000", Actions(drop));

        // An image without a relocation directory: nothing to plan.
        b.Directories[5] = (0, 0);
        var fixedImage = PeFile.FromBytes(b.Build(), "fixed.dll");
        var a2 = X86Assembler.Assemble(NativeArch.X64, 0x140001000, "mov rax, 0x140002000");
        var none = PatchRelocations.Plan(fixedImage, 0x1000, original[..10], a2.Bytes, a2.Constants, false, RelocationMode.Auto, false);
        Assert.Empty(none.Changes);
        Assert.Contains("not relocatable", none.Notes.Single());
    }

    // ---- real images (Slow) ----

    /// <summary>
    /// A copy of SysWOW64 DLLs: (a) a 'push offset X' overwritten by a numeric push, (b) a 'push offset X' replaced by
    /// 'nop ; mov eax, [X]' (the old entry neutralized, its slot retargeted one byte on). The patched file is rebased in
    /// memory as the loader would and the patched instructions decode to the intended operation at the new base.
    /// </summary>
    [Trait("Speed", "Slow")]
    [WindowsFact]
    public async Task SysWow64_patches_are_correct_after_a_rebase()
    {
        var wow = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");
        if (!Directory.Exists(wow)) return;
        int done = 0;
        var sw = Stopwatch.StartNew();
        foreach (var name in new[] { "version.dll", "msvcrt.dll", "shlwapi.dll", "comdlg32.dll", "user32.dll", "kernelbase.dll" })
        {
            var src = Path.Combine(wow, name);
            if (!File.Exists(src)) continue;
            var pe = PeFile.Open(src);
            if (pe.Arch != NativeArch.X86 || !PatchRelocations.IsRelocatable(pe)) continue;
            using var h = new Harness(File.ReadAllBytes(src));
            var (native, index) = await h.Open();
            var sites = PushOffsetSites(index).Take(400).ToList();
            output.WriteLine($"{name}: {sites.Count} 'push offset' sites with a relocation");
            uint? a = null, bSite = null;
            foreach (var s in sites)
            {
                if (a == null && Try(() => Asm(h.Edits, index, s.Rva, "push 0x1234")) is { } pa
                    && Actions(pa.Patch.Relocations) == $"neutralized 0x{s.Rva + 1:X}")
                {
                    h.Edits.ApplyPatch(native, index, pa, false);
                    a = s.Rva;
                    index = await h.Code.Index(native, null, default);
                    continue;
                }
                if (bSite == null && a != null && s.Rva > a + 16 && ((s.Rva + 1) & 0xFFF) < 0xFF0
                    && Try(() => Asm(h.Edits, index, s.Rva, $"nop\nmov eax, dword ptr [0x{s.Target:X}]")) is { } pb
                    && pb.Patch.Relocations!.Changes.Any(c => c.Action == "added" && c.TargetRva == s.Rva + 2))
                {
                    output.WriteLine($"  b at 0x{s.Rva:X}: {Actions(pb.Patch.Relocations)}");
                    h.Edits.ApplyPatch(native, index, pb, false);
                    bSite = s.Rva;
                    break;
                }
            }
            if (a == null || bSite == null) continue;

            var outPath = h.Dir.File("patched-" + name);
            var save = h.Edits.Save(native, outPath, false, false);
            Assert.Contains("Relocations verified", save);
            Assert.DoesNotContain("WARNING: relocations", save);
            var written = PeFile.Open(outPath);
            ulong newBase = written.ImageBase + 0x00A30000;
            var rebased = Rebase(written, File.ReadAllBytes(outPath), newBase);
            var push = DecodeAt(written, rebased, a.Value, newBase);
            Assert.Equal(Mnemonic.Push, push.Mnemonic);
            Assert.Equal(0x1234u, push.Immediate32);
            var mov = DecodeAt(written, rebased, bSite.Value + 1, newBase);
            Assert.Equal(Mnemonic.Mov, mov.Mnemonic);
            var target = PushOffsetTarget(pe, bSite.Value);
            Assert.Equal((uint)(target - written.ImageBase + newBase), mov.MemoryDisplacement32);
            output.WriteLine($"{name}: (a) at 0x{a:X}, (b) at 0x{bSite:X}, rebased +0xA30000 and verified; {written.BaseRelocations.Count:N0} entries; {sw.ElapsedMilliseconds} ms");
            done++;
            if (done >= 2) break;
        }
        Assert.True(done > 0 || !Directory.Exists(wow), "no SysWOW64 DLL had usable 'push offset' sites");
    }

    /// <summary>
    /// An MSVC x86 DLL (/DYNAMICBASE, /Od): GetValue's 'mov eax, [g_value]' is replaced by 'mov eax, [g_other] ; ret' at
    /// the function start (the old entry neutralized, its slot retargeted), GetText's 'mov eax, offset str' by a number.
    /// After an in-memory rebase GetValue reads g_other at its new address and GetText returns the number unchanged.
    /// </summary>
    [Trait("Speed", "Slow")]
    [WindowsFact]
    public async Task Msvc_x86_dll_patches_are_correct_after_a_rebase()
    {
        using var dir = new TempDir();
        var dll = BuildDll(dir);
        if (dll == null) return;
        using var h = new Harness(File.ReadAllBytes(dll));
        var (native, index) = await h.Open();
        var pe = native.Pe!;
        Assert.True(PatchRelocations.IsRelocatable(pe));
        uint getValue = pe.Exports.Single(e => e.Name == "GetValue").Rva;
        uint getText = pe.Exports.Single(e => e.Name == "GetText").Rva;
        uint gOther = pe.Exports.Single(e => e.Name == "g_other").Rva;

        var p1 = Asm(h.Edits, index, getValue, $"mov eax, dword ptr [0x{pe.ImageBase + gOther:X}]\nret");
        output.WriteLine("GetValue: " + Actions(p1.Patch.Relocations));
        Assert.Contains(p1.Patch.Relocations!.Changes, c => c.Action == "added" && c.TargetRva == getValue + 1);
        Assert.Contains(p1.Patch.Relocations!.Changes, c => c.Action == "neutralized");
        h.Edits.ApplyPatch(native, index, p1, false);
        index = await h.Code.Index(native, null, default);

        // GetText: find 'mov eax, offset str' (B8 imm32 with a relocation at +1) and make it 'mov eax, 0x1234'.
        uint movAt = Enumerable.Range(0, 32).Select(i => getText + (uint)i).First(r => pe.RelocationRvas.Contains(r + 1) && Byte(native.Image, r) == 0xB8);
        var p2 = Asm(h.Edits, index, movAt, "mov eax, 0x1234");
        Assert.Equal($"neutralized 0x{movAt + 1:X}", Actions(p2.Patch.Relocations));
        h.Edits.ApplyPatch(native, index, p2, false);

        var outPath = h.Dir.File("patched.dll");
        var save = h.Edits.Save(native, outPath, false, false);
        output.WriteLine(save);
        Assert.Contains("Relocations verified", save);
        var written = PeFile.Open(outPath);
        ulong newBase = written.ImageBase + 0x0F0000;
        var rebased = Rebase(written, File.ReadAllBytes(outPath), newBase);
        var mov = DecodeAt(written, rebased, getValue, newBase);
        Assert.Equal(Mnemonic.Mov, mov.Mnemonic);
        Assert.Equal((uint)(newBase + gOther), mov.MemoryDisplacement32);
        var mov2 = DecodeAt(written, rebased, movAt, newBase);
        Assert.Equal(0x1234u, mov2.Immediate32);
        // The rest of the table still rebases the untouched code: GetText's string pointers etc. are intact.
        Assert.Equal(pe.BaseRelocations.Count - 1, written.BaseRelocations.Count);
    }

    private const string DllSource = """
        __declspec(dllexport) int g_value = 42;
        __declspec(dllexport) int g_other = 7;
        __declspec(dllexport) int __cdecl GetValue(void) { return g_value; }
        __declspec(dllexport) const char* __cdecl GetText(void) { return "hello"; }
        """;

    private static string? BuildDll(TempDir dir)
    {
        var vcvars = VisualStudio.VcVarsAll();
        if (vcvars == null) return null;
        File.WriteAllText(dir.File("relocdll.c"), DllSource);
        var psi = new ProcessStartInfo("cmd.exe")
        {
            WorkingDirectory = dir.Path,
            Arguments = $"/s /c \"\"{vcvars}\" x86 >nul && cl /nologo /Od /GS- /MD /LD relocdll.c /link /DYNAMICBASE /OUT:relocdll.dll\"",
        };
        var (code, log) = Tools.Run(psi, 300_000);
        Assert.True(code == 0 && File.Exists(dir.File("relocdll.dll")), log);
        return dir.File("relocdll.dll");
    }

    // ---- helpers ----

    private static T? Try<T>(Func<T> f) where T : class
    {
        try { return f(); } catch (ToolError) { return null; }
    }

    private static IEnumerable<(uint Rva, ulong Target)> PushOffsetSites(NativeCodeIndex index)
    {
        var image = index.Image;
        var relocs = image.RelocationRvas.ToHashSet();
        foreach (var f in index.Functions)
        {
            uint at = f.Start;
            for (int n = 0; n < 200 && at < f.End; n++)
            {
                if (index.Decode(at) is not { Length: > 0 } insn) break;
                if (insn.Length == 5 && Byte(image, at) == 0x68 && relocs.Contains(at + 1) && at + 12 <= f.End)
                    yield return (at, PushOffsetTarget(image, at));
                at += (uint)insn.Length;
            }
        }
    }

    private static ulong PushOffsetTarget(INativeImage image, uint rva)
    {
        Span<byte> b = stackalloc byte[4];
        image.Read(rva + 1, b);
        return BinaryPrimitives.ReadUInt32LittleEndian(b);
    }

    private static byte Byte(INativeImage image, uint rva)
    {
        Span<byte> b = stackalloc byte[1];
        image.Read(rva, b);
        return b[0];
    }

    private static long Offset(INativeImage image, uint rva) => image.TryRvaToFileOffset(rva, out var o) ? o : -1;

    /// <summary>Applies every base relocation of <paramref name="image"/> to a copy of its file bytes for a load at <paramref name="newBase"/>, as the loader does.</summary>
    private static byte[] Rebase(PeFile image, byte[] file, ulong newBase)
    {
        var bytes = (byte[])file.Clone();
        ulong delta = newBase - image.ImageBase;
        foreach (var r in image.BaseRelocations)
        {
            if (!image.TryRvaToFileOffset(r.Rva, out long off)) continue; // zero-fill: nothing in the file
            var span = bytes.AsSpan((int)off);
            switch (r.Type)
            {
                case PeRelocationType.HighLow: BinaryPrimitives.WriteUInt32LittleEndian(span, BinaryPrimitives.ReadUInt32LittleEndian(span) + (uint)delta); break;
                case PeRelocationType.Dir64: BinaryPrimitives.WriteUInt64LittleEndian(span, BinaryPrimitives.ReadUInt64LittleEndian(span) + delta); break;
                case PeRelocationType.High: BinaryPrimitives.WriteUInt16LittleEndian(span, (ushort)(BinaryPrimitives.ReadUInt16LittleEndian(span) + (ushort)(delta >> 16))); break;
                case PeRelocationType.Low: BinaryPrimitives.WriteUInt16LittleEndian(span, (ushort)(BinaryPrimitives.ReadUInt16LittleEndian(span) + (ushort)delta)); break;
            }
        }
        return bytes;
    }

    private static Instruction DecodeAt(PeFile image, byte[] bytes, uint rva, ulong newBase)
    {
        long off = Offset(image, rva);
        var decoder = Iced.Intel.Decoder.Create(image.Is64Bit ? 64 : 32, new ByteArrayCodeReader(bytes, (int)off, 16), newBase + rva);
        decoder.Decode(out var instr);
        return instr;
    }
}
