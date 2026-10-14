using Iced.Intel;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Code;
using Corvus.Native.Diff;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>find_similar_functions: copies, renamed registers, inlined bodies and instantiations on all four architectures; duplicates and clusters.</summary>
public class SimilarFunctionsTests
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;

    private sealed record Sample(ImagePrints Prints, Dictionary<string, uint> At)
    {
        public int Of(string name) => Prints.ByStart[At[name]];
        public string NameOf(int index) => At.First(kv => kv.Value == Prints.Functions[index].Start).Key;
    }

    private static Sample Make(NativeArch arch, byte[] code, Dictionary<string, uint> at)
    {
        var exports = at.Select((kv, i) => new NativeExport(kv.Key, (uint)i + 1, kv.Value, null)).ToList();
        var image = CodeTestImage.Synthetic(arch, code, exports: exports, entry: at.Values.Min());
        return new Sample(ImagePrints.Build(NativeCodeIndex.Build(image), default), at);
    }

    /// <summary>
    /// x64: H (16 instructions), HCopy (the same bytes), HRegs (other registers), Inl (H's body inlined between two calls),
    /// T1 / T2 (one loop over 8- and 16-byte elements, T2 sign-extends), U (unrelated), Other (a leaf).
    /// </summary>
    private static Sample X64()
    {
        var a = new Assembler(64);
        var labels = new Dictionary<string, Label>();
        Label L(string name) => labels.TryGetValue(name, out var l) ? l : labels[name] = a.CreateLabel(name);
        void Here(string name) { var l = L(name); a.Label(ref l); labels[name] = l; }
        void Body(AssemblerRegister32 x, AssemblerRegister32 y, AssemblerRegister64 y64)
        {
            a.mov(eax, x); a.imul(eax, eax, 0x2F); a.xor(eax, 0x5A5A5A); a.add(eax, y);
            a.shr(eax, 3); a.lea(eax, __[rax + y64 * 2]); a.sub(eax, 0x777); a.rol(eax, 5);
            a.and(eax, 0xFFFF0); a.or(eax, y); a.not(eax); a.neg(eax);
            a.add(eax, 0x1357); a.imul(eax, y); a.xor(eax, x);
        }
        void Loop(bool wide)
        {
            var loop = a.CreateLabel(); var done = a.CreateLabel();
            a.push(rbx); a.xor(eax, eax); a.mov(r8d, 0x01000193); a.mov(ebx, 0x811C9DC5); a.test(edx, edx); a.jle(done);
            a.Label(ref loop);
            if (wide) a.movsxd(r9, __dword_ptr[rcx + 8]); else a.mov(r9d, __dword_ptr[rcx + 4]);
            a.add(eax, r9d); a.xor(ebx, eax); a.imul(ebx, r8d); a.add(rcx, wide ? 16 : 8); a.dec(edx); a.jne(loop);
            a.Label(ref done);
            a.mov(ecx, ebx); a.shr(ecx, 15); a.xor(ebx, ecx); a.imul(ebx, ebx, 0x2C1B3C6D); a.mov(ecx, ebx); a.shr(ecx, 12);
            a.xor(ebx, ecx); a.mov(eax, ebx); a.pop(rbx); a.ret();
        }
        Here("H"); Body(ecx, edx, rdx); a.ret(); a.int3();
        Here("HCopy"); Body(ecx, edx, rdx); a.ret(); a.int3();
        Here("HRegs"); Body(r8d, r9d, r9); a.ret(); a.int3();
        Here("Inl");
        a.push(rbx); a.sub(rsp, 0x20); a.mov(ebx, ecx); a.call(L("Other")); a.mov(ecx, ebx);
        Body(ecx, edx, rdx);
        a.mov(ebx, eax); a.call(L("Other")); a.add(eax, ebx); a.add(rsp, 0x20); a.pop(rbx); a.ret(); a.int3();
        Here("T1"); Loop(false); a.int3();
        Here("T2"); Loop(true); a.int3();
        Here("U");
        var top = a.CreateLabel(); var end = a.CreateLabel();
        a.xor(edx, edx);
        a.Label(ref top);
        a.movzx(eax, __byte_ptr[rcx]); a.test(al, al); a.je(end); a.cmp(al, 0x2C); a.cmove(edx, eax); a.inc(rcx); a.jmp(top);
        a.Label(ref end);
        a.mov(eax, edx); a.ret(); a.int3();
        Here("Other"); a.mov(eax, 1); a.ret();
        var stream = new MemoryStream();
        var result = a.Assemble(new StreamCodeWriter(stream), 0x140000000UL + Code, BlockEncoderOptions.ReturnNewInstructionOffsets);
        return Make(NativeArch.X64, stream.ToArray(), labels.ToDictionary(kv => kv.Key, kv => (uint)(result.GetLabelRIP(kv.Value) - 0x140000000UL)));
    }

    private static readonly Lazy<Sample> X64Sample = new(X64);

    private static List<SimilarHit> Similar(Sample s, string name, double minScore = 0.5) =>
        SimilarFunctions.Similar(s.Prints, s.Of(name), [s.Prints], minScore, 5, 200, default, out _);

    [Fact]
    public void Copies_and_renamed_registers_rank_first_and_unrelated_code_does_not_match()
    {
        var s = X64Sample.Value;
        var hits = Similar(s, "H");
        Assert.Equal(["HCopy", "HRegs"], hits.Take(2).Select(h => s.NameOf(h.Index)).Order());
        var copy = hits.Single(h => s.NameOf(h.Index) == "HCopy");
        Assert.Equal(("identical", 1.0), (copy.Kind, copy.Code));
        var regs = hits.Single(h => s.NameOf(h.Index) == "HRegs");
        Assert.Equal(("same_shape", 1.0), (regs.Kind, regs.Code));
        Assert.True(regs.Score >= 0.95, $"renamed registers scored {regs.Score}");
        Assert.DoesNotContain(hits, h => s.NameOf(h.Index) is "U" or "T1" or "T2" or "Other");
    }

    [Fact]
    public void An_inlined_copy_is_found_by_containment()
    {
        var s = X64Sample.Value;
        var inl = Assert.Single(Similar(s, "H", 0.4), h => s.NameOf(h.Index) == "Inl");
        Assert.Equal("contains", inl.Kind);
        Assert.True(inl.Containment >= 0.8, $"containment {inl.Containment}");
        Assert.True(inl.Code < inl.Containment);
        // and from the other side, H is a part of Inl (low Jaccard, so only at a low threshold)
        Assert.Contains(Similar(s, "Inl", 0.3), h => s.NameOf(h.Index) == "H");
    }

    [Fact]
    public void Instantiations_for_other_element_types_are_similar_with_shared_constants_as_evidence()
    {
        var s = X64Sample.Value;
        var t2 = Similar(s, "T1")[0];
        Assert.Equal("T2", s.NameOf(t2.Index));
        Assert.Equal("similar", t2.Kind);
        Assert.True(t2.Score >= 0.7, $"T2 scored {t2.Score}");
        Assert.Contains(0x01000193UL, t2.SharedConstants);
    }

    [Fact]
    public void Duplicates_group_one_shape_and_clusters_link_near_duplicates()
    {
        var s = X64Sample.Value;
        var dup = Assert.Single(SimilarFunctions.Duplicates(s.Prints, 5, default));
        Assert.Equal("same_shape", dup.Kind);
        Assert.Equal(["H", "HCopy", "HRegs"], dup.Members.Select(s.NameOf));

        var clusters = SimilarFunctions.Clusters(s.Prints, 0.7, 5, default, out _);
        Assert.Contains(clusters, c => c.Members.Select(s.NameOf).SequenceEqual(["H", "HCopy", "HRegs"]));
        var t = Assert.Single(clusters, c => c.Members.Select(s.NameOf).Contains("T1"));
        Assert.Equal("similar", t.Kind);
        Assert.Equal(["T1", "T2"], t.Members.Select(s.NameOf));
        Assert.DoesNotContain(clusters, c => c.Members.Select(s.NameOf).Contains("U"));
        Assert.Same(clusters, SimilarFunctions.Clusters(s.Prints, 0.7, 5, default, out _));
    }

    [Fact]
    public void Scope_over_two_images_finds_the_copies_in_the_other()
    {
        var (a, b) = (X64Sample.Value, X64());
        var hits = SimilarFunctions.Similar(a.Prints, a.Of("H"), [a.Prints, b.Prints], 0.5, 5, 200, default, out _);
        var other = hits.Where(h => ReferenceEquals(h.Image, b.Prints)).ToDictionary(h => b.NameOf(h.Index));
        Assert.Equal(("identical", "identical", "same_shape"), (other["H"].Kind, other["HCopy"].Kind, other["HRegs"].Kind));
        Assert.Equal(5, hits.Count(h => h.Kind is "identical" or "same_shape"));
    }

    [Fact]
    public void Ties_across_identical_images_rank_by_scope_order_in_every_run()
    {
        var (a, b) = (X64Sample.Value, X64());
        List<(bool, uint, double)> Run() => SimilarFunctions.Similar(a.Prints, a.Of("H"), [a.Prints, b.Prints], 0.0, 1, 200, default, out _)
            .Select(h => (ReferenceEquals(h.Image, b.Prints), h.Image.Functions[h.Index].Start, h.Score)).ToList();
        var first = Run();
        for (int i = 0; i < 10; i++) Assert.Equal(first, Run());
        // b's copies of a's functions score the same; with equal score and code, a's come first
        var hits = SimilarFunctions.Similar(a.Prints, a.Of("H"), [a.Prints, b.Prints], 0.0, 1, 200, default, out _);
        for (int i = 1; i < hits.Count; i++)
            if (hits[i].Score == hits[i - 1].Score && hits[i].Code == hits[i - 1].Code && !ReferenceEquals(hits[i].Image, hits[i - 1].Image))
                Assert.Same(b.Prints, hits[i].Image);
        var reversed = SimilarFunctions.Similar(a.Prints, a.Of("H"), [b.Prints, a.Prints], 0.0, 1, 200, default, out _);
        Assert.Contains(reversed.Zip(reversed.Skip(1)), p => p.First.Score == p.Second.Score && p.First.Code == p.Second.Code
                                                            && ReferenceEquals(p.First.Image, b.Prints) && ReferenceEquals(p.Second.Image, a.Prints));
    }

    [Fact]
    public void Sketch_estimates_follow_the_exact_jaccard()
    {
        var rnd = new Random(7);
        var shared = Enumerable.Range(0, 300).Select(_ => (ulong)rnd.NextInt64()).ToList();
        foreach (var keep in new[] { 300, 200, 100 })
        {
            var a = shared.ToHashSet();
            var b = shared.Take(keep).Concat(Enumerable.Range(0, 300 - keep).Select(_ => (ulong)rnd.NextInt64())).ToHashSet();
            double exact = (double)keep / (600 - keep);
            Assert.InRange(CodeSketch.Jaccard(CodeSketch.Sketch(a), CodeSketch.Sketch(b)), exact - 0.25, exact + 0.25);
        }
    }

    /// <summary>x86: F and its copy with other registers; G unrelated.</summary>
    [Fact]
    public void X86_renamed_registers()
    {
        var a = new Assembler(32);
        var labels = new Dictionary<string, Label>();
        void Here(string name) { var l = a.CreateLabel(name); a.Label(ref l); labels[name] = l; }
        void F(AssemblerRegister32 x, AssemblerRegister32 y)
        {
            a.mov(x, __dword_ptr[esp + 4]); a.mov(y, __dword_ptr[esp + 8]); a.imul(x, y); a.add(x, 0x4321); a.xor(x, y);
            a.shl(x, 3); a.sub(x, y); a.mov(eax, x); a.ret();
        }
        Here("F"); F(ecx, edx); a.int3();
        Here("F2"); F(esi, edi); a.int3();
        Here("G");
        var g = a.CreateLabel();
        a.push(ebx); a.xor(eax, eax); a.mov(ebx, 10); a.Label(ref g); a.add(eax, ebx); a.dec(ebx); a.jnz(g); a.pop(ebx); a.ret();
        var stream = new MemoryStream();
        var result = a.Assemble(new StreamCodeWriter(stream), 0x10000000UL + Code, BlockEncoderOptions.ReturnNewInstructionOffsets);
        var s = Make(NativeArch.X86, stream.ToArray(), labels.ToDictionary(kv => kv.Key, kv => (uint)(result.GetLabelRIP(kv.Value) - 0x10000000UL)));
        AssertRenamedPair(s, "F", "F2", "G");
    }

    /// <summary>ARM64: F and its copy with other registers; G unrelated.</summary>
    [Fact]
    public void Arm64_renamed_registers()
    {
        var a = new A64(Code);
        var at = new Dictionary<string, uint>();
        static uint Eor(int d, int n, int m) => 0xCA000000 | (uint)m << 16 | (uint)n << 5 | (uint)d;
        static uint Mul(int d, int n, int m) => 0x9B007C00 | (uint)m << 16 | (uint)n << 5 | (uint)d;
        void F(int x, int y)
        {
            a.Word(A64.StpFpLrPre).Word(A64.MovFpSp).Word(A64.LdrX(x, 0, 8)).Word(A64.LdrX(y, 0, 16)).Word(Mul(x, x, y)).Word(A64.AddImm(x, x, 0x321))
             .Word(Eor(x, x, y)).Word(A64.MovW(y, 0x4242)).Word(Mul(0, x, y)).Word(A64.LdpFpLrPost).Word(A64.Ret);
        }
        at["F"] = a.Here; F(9, 10);
        at["F2"] = a.Here; F(11, 12);
        at["G"] = a.Here;
        a.Word(A64.MovW(0, 1)).Word(A64.MovW(1, 2)).Word(0x8B010000 /* add x0, x0, x1 */).Word(A64.Nop).Word(A64.Nop).Word(A64.Ret);
        AssertRenamedPair(Make(NativeArch.Arm64, a.Bytes(), at), "F", "F2", "G");
    }

    /// <summary>ARM32 (Thumb): F and its copy with other low registers; G unrelated.</summary>
    [Fact]
    public void Arm32_renamed_registers()
    {
        var a = new A32Code(Code);
        var at = new Dictionary<string, uint>();
        static ushort Adds(int d, int n, int m) => (ushort)(0x1800 | m << 6 | n << 3 | d);
        static ushort Eors(int dn, int m) => (ushort)(0x4040 | m << 3 | dn);
        static ushort Lsls(int d, int m, int imm) => (ushort)(imm << 6 | m << 3 | d);
        void F(int x, int y)
        {
            a.H(A32Code.PushLr(0x30)).H(A32Code.LdrImm(x, 0, 4)).H(A32Code.LdrImm(y, 0, 8)).H(Adds(x, x, y)).H(Eors(x, y)).H(Lsls(x, x, 3))
             .H(A32Code.MovImm(y, 0x55)).H(Adds(0, x, y)).H(A32Code.PopPc(0x30));
        }
        at["F"] = a.Here; F(4, 5);
        at["F2"] = a.Here; F(2, 3);
        at["G"] = a.Here;
        a.H(A32Code.MovImm(0, 1)).H(A32Code.CmpImm(0, 3)).H(A32Code.It(0)).H(A32Code.MovImm(0, 2)).H(A32Code.Nop).H(A32Code.BxLr);
        AssertRenamedPair(Make(NativeArch.Arm, a.Bytes(), at), "F", "F2", "G");
    }

    private static void AssertRenamedPair(Sample s, string f, string copy, string unrelated)
    {
        var hits = Similar(s, f);
        var top = Assert.Single(hits);
        Assert.Equal((copy, "same_shape", 1.0), (s.NameOf(top.Index), top.Kind, top.Code));
        Assert.DoesNotContain(hits, h => s.NameOf(h.Index) == unrelated);
        Assert.Equal([f, copy], Assert.Single(SimilarFunctions.Duplicates(s.Prints, 5, default)).Members.Select(s.NameOf));
    }

    [Fact]
    public async Task Tool_views_paging_and_argument_checks()
    {
        using var dir = new TempDir();
        using var env = new Env();
        var code = new Corvus.Services.NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(dir.File("ann")));
        var tools = new Corvus.Tools.NativeSimilarityTools(env.Workspace, code);
        var path = dir.File("a.dll");
        File.WriteAllBytes(path, NativePeTests.KitchenSink(is64: true));
        var collector = Corvus.Mcp.ToolOutput.Collect();
        async Task<Corvus.Tools.NativeSimilarityTools.SimilarityReport> Find(string? address = null, string? view = null, double? minScore = null, int minInstructions = 5,
            int offset = 0, int limit = 20)
        {
            await tools.FindSimilarFunctions(path, address, view, minScore: minScore, minInstructions: minInstructions, offset: offset, limit: limit);
            return Assert.IsType<Corvus.Tools.NativeSimilarityTools.SimilarityReport>(collector.Value);
        }
        var text = await tools.FindSimilarFunctions(path, "First", minScore: 0, minInstructions: 1, limit: 2);
        Assert.Matches(@"\n  \d\.\d\d  \w+ +0x[0-9A-F]+  ", text);
        var similar = await Find("First", minScore: 0, minInstructions: 1, limit: 2);
        Assert.Equal(("similar", "First"), (similar.View, similar.Function));
        Assert.True(similar.Compared > 0);
        Assert.True(similar.Items.Count <= 2);
        Assert.Equal(similar.Total > 2, similar.Truncated);
        Assert.All(similar.Items, m => Assert.Equal("a.dll", Assert.IsType<Corvus.Tools.NativeSimilarityTools.SimilarMatch>(m).Image));
        // pages of one query share one candidate pool: a walk sees every match once
        var all = await Find("First", minScore: 0, minInstructions: 1, limit: 500);
        var walked = new List<string>();
        for (int at = 0; at < all.Total; at += 2)
        {
            var page = await Find("First", minScore: 0, minInstructions: 1, offset: at, limit: 2);
            Assert.Equal(all.Total, page.Total);
            walked.AddRange(page.Items.Cast<Corvus.Tools.NativeSimilarityTools.SimilarMatch>().Select(m => m.Address));
        }
        Assert.Equal(all.Items.Cast<Corvus.Tools.NativeSimilarityTools.SimilarMatch>().Select(m => m.Address), walked);
        var clusters = await Find(minInstructions: 1);
        Assert.Equal("clusters", clusters.View);
        Assert.Equal("duplicates", (await Find(view: "duplicates")).View);

        async Task<ErrorCode> Error(Func<Task> call) => (await Assert.ThrowsAsync<ToolError>(call)).Code;
        Assert.Equal(ErrorCode.InvalidArgument, await Error(() => tools.FindSimilarFunctions(path, view: "similar")));
        Assert.Equal(ErrorCode.InvalidArgument, await Error(() => tools.FindSimilarFunctions(path, "First", view: "clusters")));
        Assert.Equal(ErrorCode.InvalidArgument, await Error(() => tools.FindSimilarFunctions(path, view: "duplicates", scope: "all")));
        Assert.Equal(ErrorCode.InvalidArgument, await Error(() => tools.FindSimilarFunctions(path, "First", minScore: 2)));
        Assert.Equal(ErrorCode.InvalidArgument, await Error(() => tools.FindSimilarFunctions(path, "First", minInstructions: 0)));
        Assert.Equal(ErrorCode.InvalidArgument, await Error(() => tools.FindSimilarFunctions(path, "First", view: "near")));
    }
}
