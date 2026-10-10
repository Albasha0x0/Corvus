using System.Text;
using Iced.Intel;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Diff;
using static Iced.Intel.AssemblerRegisters;

namespace NetDecompilerMcp.Tests;

/// <summary>Build matching, address mapping, name migration and code patterns on two synthetic builds of one image.</summary>
public class NativeDiffTests
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;
    private const uint Data = CodeTestImage.SyntheticDataRva;
    private const ulong Base = 0x140000000UL;

    /// <summary>The functions of a build and where they are.</summary>
    private sealed record Build(NativeCodeIndex Index, Dictionary<string, uint> At, uint Cmp, uint Global, uint Text);

    /// <summary>
    /// main calls (X,) A, B, C; A reads a global and adds a constant; B passes a string and calls A; C loops and calls D; D multiplies by a
    /// constant. The new build inserts X before everything (every address moves), changes C by one instruction, and moves the data.
    /// </summary>
    private static Build Make(bool newer)
    {
        uint dataShift = newer ? 0x40u : 0;
        uint global = Data + 0x10 + dataShift, text = Data + 0x100 + dataShift;
        var a = new Assembler(64);
        var labels = new Dictionary<string, Label>();
        Label L(string name) => labels.TryGetValue(name, out var l) ? l : labels[name] = a.CreateLabel(name);
        void Here(string name) { var l = L(name); a.Label(ref l); labels[name] = l; }
        Instruction Rip(Iced.Intel.Code code, Register reg, uint rva) => Instruction.Create(code, reg, new MemoryOperand(Register.RIP, (long)(Base + rva), 8));
        var cmp = a.CreateLabel();
        var loop = a.CreateLabel();

        Here("main");
        a.sub(rsp, 0x28);
        if (newer) a.call(L("X"));
        a.call(L("A")); a.call(L("B")); a.call(L("C"));
        a.add(rsp, 0x28);
        a.ret();
        a.int3(); a.int3();
        if (newer)
        {
            Here("X");
            a.mov(eax, 0x7777); a.imul(eax, eax, 0x13); a.xor(eax, 0x5A5A); a.ret();
            a.int3(); a.int3();
        }
        Here("A");
        a.AddInstruction(Rip(Iced.Intel.Code.Mov_r32_rm32, Register.EAX, global));
        a.add(eax, 0x1234);
        a.ret();
        a.int3(); a.int3();
        Here("B");
        a.sub(rsp, 0x28);
        a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RCX, text));
        a.call(L("A"));
        a.add(rsp, 0x28);
        a.ret();
        a.int3(); a.int3();
        Here("C");
        a.push(rbx);
        a.xor(ebx, ebx);
        a.Label(ref loop);
        a.mov(ecx, ebx);
        a.call(L("D"));
        if (newer) a.add(ebx, 2); else a.inc(ebx);
        a.Label(ref cmp);
        a.cmp(ebx, 100);
        a.jl(loop);
        a.pop(rbx);
        a.ret();
        a.int3(); a.int3();
        Here("D");
        a.imul(ecx, ecx, 0x5555);
        a.mov(eax, ecx);
        a.ret();
        var stream = new MemoryStream();
        var result = a.Assemble(new StreamCodeWriter(stream), Base + Code, BlockEncoderOptions.ReturnNewInstructionOffsets);
        var data = new byte[0x200];
        Encoding.ASCII.GetBytes("hello build\0").CopyTo(data, (int)(text - Data));
        var image = CodeTestImage.Synthetic(NativeArch.X64, stream.ToArray(), data, entry: Code);
        var at = labels.ToDictionary(kv => kv.Key, kv => (uint)(result.GetLabelRIP(kv.Value) - Base));
        return new Build(NativeCodeIndex.Build(image), at, (uint)(result.GetLabelRIP(cmp) - Base), global, text);
    }

    private static readonly Lazy<(Build Old, Build New, MatchResult Match)> Pair = new(() =>
    {
        var (o, n) = (Make(false), Make(true));
        var match = BuildMatcher.Match(ImagePrints.Build(o.Index, default), ImagePrints.Build(n.Index, default), new MatchOptions { UseNames = false }, default);
        return (o, n, match);
    });

    private static FunctionMatch? MatchOf(string name)
    {
        var (o, n, m) = Pair.Value;
        var match = m.ForOldStart(o.At[name]);
        return match;
    }

    [Fact]
    public void Matches_moved_and_changed_functions_and_reports_the_inserted_one()
    {
        var (o, n, m) = Pair.Value;
        foreach (var name in new[] { "main", "A", "B", "C", "D" })
        {
            var pair = MatchOf(name);
            Assert.True(pair != null, $"{name} unmatched");
            Assert.Equal(n.At[name], m.New.Functions[pair!.New].Start);
        }
        Assert.Equal(1, MatchOf("A")!.Tier);
        Assert.Equal("identical_bytes", MatchOf("D")!.Basis);
        Assert.True(MatchOf("C")!.Tier >= 2, "C changed, so its bytes differ");
        Assert.NotEqual(m.Old.Functions[MatchOf("main")!.Old].BytesHash, m.New.Functions[MatchOf("main")!.New].BytesHash);
        Assert.Null(m.ByNew[m.New.ByStart[n.At["X"]]]);
    }

    [Fact]
    public void Maps_instructions_strings_and_data_between_builds()
    {
        var (o, n, m) = Pair.Value;
        var mapper = new AddressMapper(m);
        var start = mapper.Map(o.At["C"], default);
        Assert.Equal(("function_start", n.At["C"]), (start.Reason, start.NewRva!.Value));
        var cmp = mapper.Map(o.Cmp, default);
        Assert.Equal(("aligned_instruction", n.Cmp), (cmp.Reason, cmp.NewRva!.Value));
        var text = mapper.Map(o.Text, default);
        Assert.Equal(("same_string", n.Text), (text.Reason, text.NewRva!.Value));
        var global = mapper.Map(o.Global, default);
        Assert.Equal(("followed_references", n.Global), (global.Reason, global.NewRva!.Value));
        // the changed instruction of C ("inc ebx" became "add ebx, 2") maps one for one
        uint inc = o.Index.Disassemble(o.Cmp - 2, 1)[0].Rva;
        var replaced = mapper.Map(inc, default);
        Assert.Equal(("replaced_instruction", n.Cmp - 3), (replaced.Reason, replaced.NewRva!.Value));
        Assert.True(replaced.Confidence < cmp.Confidence);
    }

    [Fact]
    public void Migration_sets_names_and_reports_conflicts()
    {
        var (o, n, m) = Pair.Value;
        using var dir = new TempDir();
        var store = new AnnotationStore(dir.File("ann"));
        var newAnn = new NativeAnnotations(store, dir.File("new.dll"), "11", Base);
        newAnn.SetName(n.At["D"], "MineAlready");
        newAnn.SetName(n.At["main"], "TakenName");
        var items = new List<MigrationSource>
        {
            new("name", NativeNameSource.User, o.At["C"], "LoopOverD"),
            new("name", NativeNameSource.User, o.At["D"], "Multiply"),
            new("name", NativeNameSource.User, o.At["A"], "TakenName"),
            new("comment", NativeNameSource.User, o.Cmp, "loop bound"),
            new("name", NativeNameSource.Pdb, o.At["B"], "Ns::Greeter::Run"),
        };
        var steps = NameMigration.Plan(new AddressMapper(m), items, n.Index, newAnn, new MigrationOptions(), default);
        MigrationStep Of(uint rva, string kind) => steps.Single(s => s.Item.OldRva == rva && s.Item.Kind == kind);
        Assert.Equal((true, n.At["C"]), (Of(o.At["C"], "name").Set, Of(o.At["C"], "name").NewRva!.Value));
        Assert.Equal("user_name_exists", Of(o.At["D"], "name").Reason);
        Assert.Equal("name_in_use", Of(o.At["A"], "name").Reason);
        Assert.Equal((true, n.Cmp), (Of(o.Cmp, "comment").Set, Of(o.Cmp, "comment").NewRva!.Value));
        Assert.Equal(("Ns_Greeter_Run", true), (Of(o.At["B"], "name").Value, Of(o.At["B"], "name").Set));

        var strict = NameMigration.Plan(new AddressMapper(m), items, n.Index, newAnn, new MigrationOptions { MinTier = 1 }, default);
        Assert.Equal("below_min_tier", strict.Single(s => s.Item.OldRva == o.At["C"] && s.Item.Kind == "name").Reason);
    }

    [Fact]
    public void Code_patterns_mask_addresses_and_find_the_function_in_the_new_build()
    {
        var (o, n, _) = Pair.Value;
        var made = CodePatterns.Make(o.Index, o.At["B"], 64, allowReference: true, referenceOnly: false, default);
        Assert.True(made.Unique, made.Note);
        Assert.Equal("address", made.Anchor);
        Assert.Equal("48 83 EC 28 48 8D 0D", made.Pattern.ToString()); // unique with enough fixed bytes; trailing wildcards trimmed
        Assert.True(made.Pattern.FixedBytes >= CodePatterns.MinFixedBytes);
        var hits = CodePatterns.Find(CodePatterns.CodeSections(n.Index.Image), made.Pattern, 10, out int total, default);
        Assert.Equal(1, total);
        Assert.Equal(n.At["B"], hits[0]);

        // a reference anchor: the pattern sits at a call to A, and the operand recovers A's address
        var byRef = CodePatterns.Make(o.Index, o.At["A"], 64, allowReference: true, referenceOnly: true, default);
        Assert.True(byRef.Unique, byRef.Note);
        Assert.Equal(("reference", "relative"), (byRef.Anchor, byRef.OperandKind));
        var refHits = CodePatterns.Find(CodePatterns.CodeSections(n.Index.Image), byRef.Pattern, 10, out int refTotal, default);
        Assert.Equal(1, refTotal);
        var bytes = new byte[4];
        n.Index.Image.Read(refHits[0] + (uint)byRef.OperandOffset!.Value, bytes);
        Assert.Equal(n.At["A"], refHits[0] + (uint)byRef.InstructionEnd!.Value + (uint)BitConverter.ToInt32(bytes));
    }

    [Fact]
    public void Patterns_at_every_reference_each_recover_the_address_in_the_new_build()
    {
        var (o, n, _) = Pair.Value;
        // A is called from main and from B: one signature per call site, each unique, shortest first
        var made = CodePatterns.MakeAtReferences(o.Index, o.At["A"], 64, 8, [], default);
        Assert.Equal(2, made.Count);
        Assert.True(made[0].Pattern.Length <= made[1].Pattern.Length);
        Assert.Equal(2, made.Select(p => p.Start + (uint)p.ReferenceOffset!.Value).Distinct().Count());
        var sections = CodePatterns.CodeSections(n.Index.Image);
        foreach (var p in made)
        {
            Assert.True(p.Unique, p.Note);
            var hits = CodePatterns.Find(sections, p.Pattern, 10, out int total, default);
            Assert.Equal(1, total);
            var bytes = new byte[4];
            n.Index.Image.Read(hits[0] + (uint)p.OperandOffset!.Value, bytes);
            Assert.Equal(n.At["A"], hits[0] + (uint)p.InstructionEnd!.Value + (uint)BitConverter.ToInt32(bytes));
        }
        Assert.Single(CodePatterns.MakeAtReferences(o.Index, o.At["A"], 64, 1, [], default));
        // an engine's reference that is not code adds nothing
        Assert.Equal(2, CodePatterns.MakeAtReferences(o.Index, o.At["A"], 64, 8, [o.Text], default).Count);
    }

    [Fact]
    public async Task Migrate_tool_writes_the_new_builds_user_layer_and_a_dry_run_does_not()
    {
        using var dir = new TempDir();
        using var env = new Env();
        var code = new NetDecompilerMcp.Services.NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(dir.File("ann")));
        var tools = new NetDecompilerMcp.Tools.NativeDiffTools(env.Workspace, code);
        var (v1, v2) = (dir.File("a.dll"), dir.File("b.dll"));
        File.WriteAllBytes(v1, NativePeTests.KitchenSink(is64: true));
        File.WriteAllBytes(v2, [.. NativePeTests.KitchenSink(is64: true), 0]);
        var oldNative = env.Workspace.LoadAny(v1).Native!;
        var newNative = env.Workspace.LoadAny(v2).Native!;
        var oldIndex = await code.Index(oldNative, null, default);
        uint first = oldIndex.AddressOfName("First")!.Value;
        code.Annotations(oldNative).SetName(first, "Renamed");
        oldIndex.SetUserName(first, "Renamed");

        var dry = await tools.MigrateNativeNames(v1, v2, dryRun: true);
        Assert.Equal("would_set", Assert.Single(dry.Entries).Action);
        Assert.Null(code.Annotations(newNative).NameAt(first));

        var done = await tools.MigrateNativeNames(v1, v2);
        Assert.Equal(1, done.Set);
        Assert.Equal("Renamed", code.Annotations(newNative).NameAt(first));
        Assert.Equal("Renamed", (await code.Index(newNative, null, default)).NameAt(first));
        Assert.Equal("same_name", Assert.Single((await tools.MigrateNativeNames(v1, v2)).Entries).Reason);
    }

    [Fact]
    public void Alignment_keeps_order_around_insertions()
    {
        var map = InstructionAlignment.Align([1, 2, 3, 4, 5], [1, 2, 9, 9, 3, 4, 5]);
        Assert.Equal([0, 1, 4, 5, 6], map);
        Assert.Equal([-1, -1], InstructionAlignment.Align([7, 8], [1, 2]));
    }
}
