using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Patching;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

public class NativeEditTests(ITestOutputHelper output)
{
    private readonly ITestOutputHelper _output = output;

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
        // jmp over a nop to a label; BlockEncoder picks the short form (EB rel8) since the target is in range.
        var r = X86Assembler.Assemble(NativeArch.X64, 0x140001000, "jmp target\nnop\ntarget:\nret");
        Assert.Equal(0xEB, r.Bytes[0]);
        // jmp is 2 bytes, then 1 nop -> target is 1 byte past the jmp end, so rel8 == 1.
        Assert.Equal(1, (sbyte)r.Bytes[1]);
        Assert.Equal(4, r.Bytes.Length); // 2 (jmp) + 1 (nop) + 1 (ret)
        Assert.Equal(0x90, r.Bytes[2]);
        Assert.Equal(0xC3, r.Bytes[3]);
    }

    [Fact]
    public void Assembler_CallToAbsoluteAddress()
    {
        // call an absolute VA; from VA 0x140001000 a 5-byte call to 0x140001100 has rel32 = 0x100 - 5.
        var r = X86Assembler.Assemble(NativeArch.X64, 0x140001000, "call 0x140001100");
        Assert.Equal(0xE8, r.Bytes[0]);
        Assert.Equal(0x100 - 5, BitConverter.ToInt32(r.Bytes, 1));
    }

    // ---- MASM-syntax round trip (assemble a line our disassembler prints, get the same instruction back) ----

    // A curated table across the instruction classes. Each entry assembles, disassembles, and re-assembles: the two
    // byte strings must be identical (copy a line, edit it, patch it back). Kept small so the quick set stays fast.
    [Theory]
    [InlineData(NativeArch.X64, "nop", "90")]
    [InlineData(NativeArch.X64, "ret", "C3")]
    [InlineData(NativeArch.X64, "int3", "CC")]
    [InlineData(NativeArch.X64, "leave", "C9")]
    [InlineData(NativeArch.X64, "push rbp", "55")]
    [InlineData(NativeArch.X64, "pop r15", "415F")]
    [InlineData(NativeArch.X64, "mov eax, 1", "B801000000")]
    [InlineData(NativeArch.X64, "mov rax, rcx", null)]
    [InlineData(NativeArch.X64, "xor eax, eax", null)]
    [InlineData(NativeArch.X64, "add rsp, 28h", "4883C428")]
    [InlineData(NativeArch.X64, "sub rsp, 0F8h", "4881ECF8000000")]
    [InlineData(NativeArch.X64, "mov rax, qword ptr [rsp+40h]", "488B442440")]
    [InlineData(NativeArch.X64, "mov dword ptr [rcx+rdx*4+10h], eax", "89449110")]
    [InlineData(NativeArch.X64, "lea rcx, [rsp+20h]", "488D4C2420")]
    [InlineData(NativeArch.X64, "movzx eax, byte ptr [rcx]", "0FB601")]
    [InlineData(NativeArch.X64, "movsxd rax, dword ptr [rcx]", "4863 01")]
    [InlineData(NativeArch.X64, "imul rax, rcx, 8", "486BC108")]
    [InlineData(NativeArch.X64, "test rax, rax", "4885C0")]
    [InlineData(NativeArch.X64, "cmp dword ptr [rax], 0", null)]
    [InlineData(NativeArch.X64, "movaps xmm0, xmm1", null)]
    [InlineData(NativeArch.X64, "vxorps xmm0, xmm0, xmm0", null)]
    [InlineData(NativeArch.X64, "vmovdqu ymm1, ymmword ptr [rdx]", null)]
    [InlineData(NativeArch.X64, "mov rax, gs:[60h]", null)]
    [InlineData(NativeArch.X64, "shl eax, cl", "D3E0")]
    [InlineData(NativeArch.X64, "sete al", "0F94C0")]
    [InlineData(NativeArch.X64, "cmovne rax, rcx", "480F45C1")]
    [InlineData(NativeArch.X64, "bt dword ptr [rcx], 5", "0FBA2105")]
    [InlineData(NativeArch.X64, "mov dword ptr [rax], 1", "C70001000000")]
    [InlineData(NativeArch.X64, "fld qword ptr [rcx]", "DD01")]
    [InlineData(NativeArch.X64, "faddp st(1), st(0)", "DEC1")]
    [InlineData(NativeArch.X64, "vaddps ymm0, ymm1, ymm2", "C5F458C2")]
    [InlineData(NativeArch.X64, "vmovaps zmm0, zmm1", "62F17C4828C1")]
    [InlineData(NativeArch.X64, "db 0F 1F 40 00", "0F1F4000")]
    [InlineData(NativeArch.X86, "push ebp", "55")]
    // Immediates keep the mode's operand size: a shorter 66-prefixed pushw would push 2 bytes or truncate the value.
    [InlineData(NativeArch.X86, "push 3ECh", "68EC030000")]
    [InlineData(NativeArch.X86, "push 80000001h", "6801000080")]
    [InlineData(NativeArch.X64, "push 0C4h", "68C4000000")]
    [InlineData(NativeArch.X86, "push 1", "6A01")]
    [InlineData(NativeArch.X86, "push word ptr [eax]", "66FF30")]
    [InlineData(NativeArch.X86, "push ax", "6650")]
    [InlineData(NativeArch.X64, "int 3", "CC")]
    [InlineData(NativeArch.X86, "int 3", "CC")]
    [InlineData(NativeArch.X64, "int 29h", "CD29")]
    [InlineData(NativeArch.X64, "xchg ax, ax", "6690")]
    [InlineData(NativeArch.X64, "monitorx rax, rcx, rdx", "0F01FA")]
    [InlineData(NativeArch.X64, "mwaitx rax, rcx, rbx", "0F01FB")]
    [InlineData(NativeArch.X86, "mov ebp, esp", "8BEC")]
    [InlineData(NativeArch.X86, "mov eax, dword ptr [ebp+8]", "8B4508")]
    [InlineData(NativeArch.X86, "mov eax, dword ptr [esi+edi*2+4]", null)]
    [InlineData(NativeArch.X86, "rep movsd", "F3A5")]
    public void RoundTrip_Curated(NativeArch arch, string text, string? expectedHex)
    {
        if (expectedHex != null)
        {
            // Authoritative encoding: the text assembles to exactly these bytes.
            var want = Convert.FromHexString(expectedHex.Replace(" ", ""));
            var got = X86Assembler.Assemble(arch, StartVa(arch), text).Bytes;
            Assert.Equal(Convert.ToHexString(want), Convert.ToHexString(got));
            return;
        }
        // Copy-edit-patch: disassembling the bytes and re-assembling that text reproduces them byte for byte.
        var (bytes, disasm) = RoundTripOne(arch, text);
        var again = X86Assembler.Assemble(arch, StartVa(arch), disasm).Bytes;
        Assert.Equal(Convert.ToHexString(bytes), Convert.ToHexString(again));
    }

    [Fact]
    public void RoundTrip_ReportsClearErrors()
    {
        // Operand size ambiguous without a specifier.
        var ex = Assert.Throws<ToolError>(() => X86Assembler.Assemble(NativeArch.X64, 0x140001000, "inc [rax]"));
        Assert.Contains("ambiguous", ex.Message);
        // Unknown mnemonic.
        Assert.Throws<ToolError>(() => X86Assembler.Assemble(NativeArch.X64, 0x140001000, "frobnicate rax"));
        // A 32-bit-only form in 64-bit mode (push of a segment pair etc.) and bad operands are rejected, not thrown raw.
        Assert.Throws<ToolError>(() => X86Assembler.Assemble(NativeArch.X64, 0x140001000, "mov rax, xmm0"));
    }

    private static ulong StartVa(NativeArch arch) => (arch == NativeArch.X64 ? 0x140000000UL : 0x10000000UL) + CodeTestImage.SyntheticCodeRva;

    /// <summary>Assembles one line, then disassembles it back through a synthetic image; returns the bytes and the text.</summary>
    private static (byte[] Bytes, string Text) RoundTripOne(NativeArch arch, string text)
    {
        ulong va = StartVa(arch);
        var bytes = X86Assembler.Assemble(arch, va, text).Bytes;
        var image = CodeTestImage.Synthetic(arch, bytes);
        var dis = new NativeDisassembler(image);
        var line = dis.DecodeOne(CodeTestImage.SyntheticCodeRva)!;
        Assert.NotNull(line);
        return (bytes, line.Text);
    }

    // The big sweep: round-trip every instruction our disassembler prints for a set of real System32 / SysWOW64
    // functions, and report the exact-byte and equivalent (same text) rates per instruction class.
    [Trait("Speed", "Slow")]
    [WindowsFact]
    public void RoundTrip_System32Functions()
    {
        var targets = new (string Name, NativeArch Arch)[]
        {
            ("kernel32.dll", NativeArch.X64), ("ntdll.dll", NativeArch.X64), ("user32.dll", NativeArch.X64),
            ("gdi32.dll", NativeArch.X64), ("ole32.dll", NativeArch.X64),
        };
        var wow = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");

        long total = 0, exact = 0, equiv = 0, failed = 0;
        var perClass = new SortedDictionary<string, (long Total, long Exact, long Equiv)>();
        var sampleFailures = new List<string>();
        var failClasses = new SortedDictionary<string, int>();

        void Sweep(string path, NativeArch arch, int maxFunctions)
        {
            if (!File.Exists(path)) return;
            var image = CodeTestImage.Load(path);
            if (image.Arch != arch) return;
            var index = NativeCodeIndex.Build(image);
            if (index.Support != CodeSupport.Full) return;
            var dis = new NativeDisassembler(image);
            int fn = 0;
            foreach (var f in index.Functions)
            {
                if (fn++ >= maxFunctions) break;
                foreach (var line in dis.Disassemble(f.Start, 400, f.End))
                {
                    if (line.Facts.Flow == FlowKind.Invalid || line.Text.StartsWith("(bad)")) continue;
                    var orig = Convert.FromHexString(line.Bytes);
                    total++;
                    var cls = line.Text.Split(' ', '\t')[0];
                    var pc = perClass.GetValueOrDefault(cls);
                    pc.Total++;
                    byte[]? asm = null;
                    try { asm = X86Assembler.Assemble(arch, line.Address, line.Text).Bytes; }
                    catch (ToolError) { }
                    if (asm == null)
                    {
                        failed++;
                        if (sampleFailures.Count < 40) sampleFailures.Add($"[not assembled] {line.Text}");
                    }
                    else if (asm.AsSpan().SequenceEqual(orig)) { exact++; pc.Exact++; equiv++; pc.Equiv++; }
                    else
                    {
                        // Equivalent when the assembled bytes disassemble to the same text at the same address and decode
                        // to the same operation: mnemonic, operand and address size, operands, immediates and prefixes.
                        var synth = new ByteImage(image, line.Rva, asm);
                        var back = new NativeDisassembler(synth, null, []).DecodeOne(line.Rva);
                        int bitness = arch == NativeArch.X64 ? 64 : 32;
                        if (back != null && back.Text == line.Text && SameOperation(bitness, line.Address, orig, asm)) { equiv++; pc.Equiv++; }
                        else
                        {
                            failClasses[cls] = failClasses.GetValueOrDefault(cls) + 1;
                            // Up to 3 samples per mnemonic, 40 in all.
                            if (sampleFailures.Count < 40 && sampleFailures.Count(s => s.Contains("] " + cls)) < 3)
                                sampleFailures.Add($"[{line.Bytes} -> {Convert.ToHexString(asm)}] {line.Text}  =>  {back?.Text}");
                        }
                    }
                    perClass[cls] = pc;
                }
            }
        }

        foreach (var (name, arch) in targets)
            if (PeCorpus.System32(name) is { } p) Sweep(p, arch, 150);
        foreach (var name in new[] { "kernel32.dll", "user32.dll" })
            Sweep(Path.Combine(wow, name), NativeArch.X86, 150);

        if (total == 0) return; // not on Windows / no corpus

        _output.WriteLine($"instructions: {total}, exact bytes: {exact} ({100.0 * exact / total:F1}%), " +
                          $"equivalent: {equiv} ({100.0 * equiv / total:F1}%), not assembled: {failed}");
        foreach (var (cls, c) in perClass.OrderByDescending(kv => kv.Value.Total).Take(40))
            _output.WriteLine($"  {cls,-10} n={c.Total,-6} exact={100.0 * c.Exact / c.Total,5:F1}%  equiv={100.0 * c.Equiv / c.Total,5:F1}%");
        _output.WriteLine("not equivalent, by mnemonic: " + string.Join(", ", failClasses.OrderByDescending(kv => kv.Value).Select(kv => $"{kv.Key} {kv.Value}")));
        _output.WriteLine("sample gaps:");
        foreach (var s in sampleFailures) _output.WriteLine("  " + s);

        // Every printed instruction must assemble back to an equivalent one: a non-equivalent result is a wrong patch.
        Assert.True(equiv == total, $"{total - equiv} of {total} instructions did not round-trip:\n" + string.Join("\n", sampleFailures));
    }

    /// <summary>
    /// Two encodings do the same thing: same mnemonic, operand size (a 66-prefixed push is not a push), address size,
    /// prefixes, memory size and operands (registers, memory base / index / scale / displacement / segment, immediate values).
    /// The opcode form may differ (8B vs 89 for reg,reg; imm8 vs imm32 for the same value).
    /// </summary>
    internal static bool SameOperation(int bitness, ulong ip, byte[] a, byte[] b)
    {
        static Iced.Intel.Instruction Decode(int bitness, ulong ip, byte[] bytes)
        {
            var decoder = Iced.Intel.Decoder.Create(bitness, new Iced.Intel.ByteArrayCodeReader(bytes), ip);
            decoder.Decode(out var instr);
            return instr;
        }
        var x = Decode(bitness, ip, a);
        var y = Decode(bitness, ip, b);
        if (x.IsInvalid || y.IsInvalid || x.Length != a.Length || y.Length != b.Length) return false;
        var ox = Iced.Intel.EncoderCodeExtensions.ToOpCode(x.Code);
        var oy = Iced.Intel.EncoderCodeExtensions.ToOpCode(y.Code);
        if (x.Mnemonic != y.Mnemonic || x.OpCount != y.OpCount || ox.OperandSize != oy.OperandSize || ox.AddressSize != oy.AddressSize
            || x.HasLockPrefix != y.HasLockPrefix || x.HasRepPrefix != y.HasRepPrefix || x.HasRepnePrefix != y.HasRepnePrefix
            || x.SegmentPrefix != y.SegmentPrefix)
            return false;
        // The decoder reports a memory size for r/m forms even when the operand is a register.
        bool hasMemory = Enumerable.Range(0, x.OpCount).Any(i => x.GetOpKind(i) == Iced.Intel.OpKind.Memory);
        if (hasMemory && x.MemorySize != y.MemorySize) return false;
        // Immediates compare at the operation's width: 0FFFFh as imm16 equals a sign-extended imm8 -1.
        ulong mask = ox.OperandSize switch { 16 => 0xFFFF, 32 => 0xFFFF_FFFF, _ => ulong.MaxValue };
        for (int i = 0; i < x.OpCount; i++)
        {
            var kx = x.GetOpKind(i);
            var ky = y.GetOpKind(i);
            switch (kx)
            {
                case Iced.Intel.OpKind.Register:
                    if (ky != kx || x.GetOpRegister(i) != y.GetOpRegister(i)) return false;
                    break;
                case Iced.Intel.OpKind.Memory:
                    if (ky != kx || x.MemoryBase != y.MemoryBase || x.MemoryIndex != y.MemoryIndex || x.MemoryIndexScale != y.MemoryIndexScale
                        || x.MemorySegment != y.MemorySegment
                        || (x.IsIPRelativeMemoryOperand ? x.IPRelativeMemoryAddress : x.MemoryDisplacement64)
                           != (y.IsIPRelativeMemoryOperand ? y.IPRelativeMemoryAddress : y.MemoryDisplacement64))
                        return false;
                    break;
                case Iced.Intel.OpKind.NearBranch16 or Iced.Intel.OpKind.NearBranch32 or Iced.Intel.OpKind.NearBranch64:
                    if (ky is not (Iced.Intel.OpKind.NearBranch16 or Iced.Intel.OpKind.NearBranch32 or Iced.Intel.OpKind.NearBranch64)
                        || x.NearBranchTarget != y.NearBranchTarget) return false;
                    break;
                default:
                    if (IsImmediate(kx))
                    {
                        if (!IsImmediate(ky) || (x.GetImmediate(i) & mask) != (y.GetImmediate(i) & mask)) return false;
                    }
                    else if (kx != ky) return false;
                    break;
            }
        }
        return true;

        static bool IsImmediate(Iced.Intel.OpKind k) => k is Iced.Intel.OpKind.Immediate8 or Iced.Intel.OpKind.Immediate8_2nd or Iced.Intel.OpKind.Immediate16
            or Iced.Intel.OpKind.Immediate32 or Iced.Intel.OpKind.Immediate64 or Iced.Intel.OpKind.Immediate8to16 or Iced.Intel.OpKind.Immediate8to32
            or Iced.Intel.OpKind.Immediate8to64 or Iced.Intel.OpKind.Immediate32to64;
    }

    [Fact]
    public void SameOperationTellsOperandSizeApart()
    {
        // push 3ECh (68 imm32) vs pushw 3ECh (66 68 imm16): same text without the suffix, different operation.
        Assert.False(SameOperation(32, 0x1000, Convert.FromHexString("68EC030000"), Convert.FromHexString("6668EC03")));
        // mov eax, ecx as 8B C1 and as 89 C8: the same operation.
        Assert.True(SameOperation(32, 0x1000, Convert.FromHexString("8BC1"), Convert.FromHexString("89C8")));
        // push 1 as imm8 and as imm32: the same operation.
        Assert.True(SameOperation(32, 0x1000, Convert.FromHexString("6A01"), Convert.FromHexString("6801000000")));
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
    public async Task Export_Header_UsesTheCurrentFunctionName()
    {
        using var h = new Harness();
        var (native, index) = await h.Open();
        uint entry = native.Image.EntryPointRva;
        h.Edits.Rename(native, index, entry, "Start", false);
        h.Edits.Annotations(native).ChangeUserTypes(l => l.WithDeclarations("struct Ctx { int n; };").WithType(entry, "int __stdcall(struct Ctx *c)"));
        var tools = new NativeEditTools(h.Env.Workspace, h.Code, h.Edits);
        var output = h.Dir.File("tiny.h");
        Assert.Contains("(Header format)", await tools.ExportNativeAnnotations(h.Path, output, "header"));
        var header = File.ReadAllText(output);
        Assert.Contains("struct Ctx { int n; };", header);
        Assert.Contains($"int __stdcall Start(struct Ctx *c); // rva 0x{entry:X}", header);
    }

    [Fact]
    public async Task CommentNative_Scopes_AppendWithDedupe_AndPseudocodeCommentsPersistAndExport()
    {
        using var h = new Harness();
        var (native, index) = await h.Open();
        uint entry = native.Image.EntryPointRva, inside = entry + 5;
        string At(uint rva) => $"rva:0x{rva:X}";
        var tools = new NativeEditTools(h.Env.Workspace, h.Code, h.Edits);
        var ann = h.Code.Annotations(native);

        // auto: a function start takes the function comment, any other address the line and the pseudocode comment
        Assert.Contains("function", await tools.CommentNative(h.Path, At(entry), "decrypts"));
        Assert.Equal(("decrypts", null), (ann.CommentAt(entry), ann.PseudoCommentAt(entry)));
        var both = await tools.CommentNative(h.Path, At(inside), "returns 1");
        _output.WriteLine(both);
        Assert.Contains("reach the engine at its next use", both);
        Assert.Equal(("returns 1", "returns 1"), (ann.CommentAt(inside), ann.PseudoCommentAt(inside)));
        Assert.Equal("returns 1", index.CommentFor(inside));

        // append, deduped by line; scope function from inside the function
        Assert.Contains("already has this line", await tools.CommentNative(h.Path, At(inside), " returns 1 ", scope: "pseudocode", append: true));
        await tools.CommentNative(h.Path, At(inside), "checked", scope: "pseudocode", append: true);
        await tools.CommentNative(h.Path, At(inside), "checked", scope: "pseudocode", append: true, dedupe: false);
        Assert.Equal(("returns 1", "returns 1\nchecked\nchecked"), (ann.CommentAt(inside), ann.PseudoCommentAt(inside)));
        await tools.CommentNative(h.Path, At(inside), "second", scope: "function", append: true);
        Assert.Equal("decrypts\nsecond", ann.CommentAt(entry));
        await tools.CommentNative(h.Path, At(inside), "", scope: "line");
        Assert.Equal((null, "returns 1\nchecked\nchecked"), (ann.CommentAt(inside), ann.PseudoCommentAt(inside)));
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.CommentNative(h.Path, At(inside), "x", scope: "everywhere"))).Code);

        // kept in the sidecar (format 3), and exported by every format
        using (var env2 = new Env())
        {
            var code2 = new NativeCodeService(env2.Workspace, env2.Options, null, h.Store);
            var fresh = env2.Workspace.LoadAny(h.Path).Native!;
            Assert.Equal("returns 1\nchecked\nchecked", code2.Annotations(fresh).PseudoCommentAt(inside));
        }
        Assert.Contains("\"formatVersion\": 3", File.ReadAllText(Directory.GetFiles(h.Store.Root, "*.json").Single()));
        foreach (var (format, expected) in new[] { ("ida", $"ndm_pseudo(0x{inside:X}, \"returns 1\\nchecked\\nchecked\")"), ("ghidra", "setPreComment"), ("json", "pseudoComments") })
        {
            var file = h.Dir.File("export." + format);
            Assert.Contains("1 pseudocode comment(s)", await tools.ExportNativeAnnotations(h.Path, file, format));
            Assert.Contains(expected, File.ReadAllText(file));
        }
        await tools.CommentNative(h.Path, At(inside), "", scope: "pseudocode");
        Assert.Equal(0, ann.PseudoCommentCount);
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
        Assert.Equal(0xB8, native.Pe!.FileBytes.Span[(int)Offset(native, entry)]);
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
