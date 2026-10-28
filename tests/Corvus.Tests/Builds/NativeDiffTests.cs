using System.Text;
using Iced.Intel;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Code;
using Corvus.Native.Diff;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

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

    /// <summary>P, two identical uncalled copies T1 and T2, and Q; the new build inserts X before them, so everything moves.</summary>
    private static (NativeCodeIndex Index, Dictionary<string, uint> At) Copies(bool newer)
    {
        var a = new Assembler(64);
        var at = new Dictionary<string, Label>();
        void Here(string name) { var l = a.CreateLabel(name); a.Label(ref l); at[name] = l; }
        if (newer) { Here("X"); a.mov(eax, 0x4242); a.imul(eax, eax, 3); a.ret(); a.int3(); }
        Here("P"); a.mov(eax, 0x1111); a.xor(eax, 0x2222); a.add(eax, 0x3333); a.ret(); a.int3();
        Here("T1"); a.mov(eax, 7); a.add(eax, ecx); a.ret(); a.int3();
        Here("T2"); a.mov(eax, 7); a.add(eax, ecx); a.ret(); a.int3();
        Here("Q"); a.mov(eax, 0x5555); a.sub(eax, 0x6666); a.imul(eax, eax, 9); a.ret();
        var stream = new MemoryStream();
        var result = a.Assemble(new StreamCodeWriter(stream), Base + Code, BlockEncoderOptions.ReturnNewInstructionOffsets);
        var exports = new[] { "P", "T1", "T2", "Q" }.Select((n, i) => new NativeExport(n, (uint)i + 1, (uint)(result.GetLabelRIP(at[n]) - Base), null)).ToList();
        var image = CodeTestImage.Synthetic(NativeArch.X64, stream.ToArray(), exports: exports, entry: (uint)(result.GetLabelRIP(at["P"]) - Base));
        return (NativeCodeIndex.Build(image), at.ToDictionary(kv => kv.Key, kv => (uint)(result.GetLabelRIP(kv.Value) - Base)));
    }

    [Fact]
    public void Identical_copies_between_matched_neighbors_pair_by_their_place()
    {
        var (o, oldAt) = Copies(false);
        var (n, newAt) = Copies(true);
        var m = BuildMatcher.Match(ImagePrints.Build(o, default), ImagePrints.Build(n, default), new MatchOptions { UseNames = false }, default);
        foreach (var name in new[] { "P", "T1", "T2", "Q" })
        {
            var pair = m.ForOldStart(oldAt[name]);
            Assert.True(pair != null, $"{name} unmatched");
            Assert.Equal(newAt[name], m.New.Functions[pair!.New].Start);
        }
        Assert.Equal("address_sequence", m.ForOldStart(oldAt["T2"])!.Basis);
        Assert.Empty(m.Ambiguous);
    }

    [Fact]
    public void Function_diff_shows_logic_changes_not_moved_addresses()
    {
        var (_, _, m) = Pair.Value;
        var diff = new FunctionDiff(m);

        // main gains a call to the new X; its calls to A, B and C moved but name the same matched functions
        var main = diff.Diff(MatchOf("main")!, context: 8, maxRows: 100, default);
        var added = Assert.Single(main.Rows, r => r.Op == "+");
        Assert.StartsWith("call", added.NewText);
        Assert.Contains("new:", added.NewText);
        Assert.Equal((0, 0, 1), (main.Changed, main.Removed, main.Added));
        Assert.Equal(3, main.Rows.Count(r => r is { Op: "=", OldText: var t } && t!.StartsWith("call", StringComparison.Ordinal)));

        // C: inc ebx became add ebx, 2; the loop branch keeps its aligned label and the call to D its matched name.
        var c = diff.Diff(MatchOf("C")!, context: 8, maxRows: 100, default);
        Assert.Equal((1, 1), (c.Removed, c.Added));
        Assert.Contains(c.Rows, r => r is { Op: "-", OldText: "inc    ebx" });
        Assert.Contains(c.Rows, r => r is { Op: "+", NewText: "add    ebx, 2" });
        Assert.Contains(c.Rows, r => r is { Op: "=" } && r.OldText!.StartsWith("jl", StringComparison.Ordinal) && r.OldText.EndsWith("L2", StringComparison.Ordinal));

        // A reads a global that moved, B a string that moved: no change after masking.
        foreach (var name in new[] { "A", "B", "D" })
        {
            var same = diff.Diff(MatchOf(name)!, context: 4, maxRows: 100, default);
            Assert.True(same.Changed + same.Removed + same.Added == 0, $"{name}: {string.Join(" | ", same.Rows.Select(r => $"{r.Op} {r.OldText} / {r.NewText}"))}");
            Assert.True(same.Rows.Count <= 1); // one … row
        }
        Assert.Contains("\"hello build\"", string.Join("\n", diff.Diff(MatchOf("B")!, context: 0, maxRows: 100, default).Rows.Select(r => r.OldText)) +
            diff.Name(m.Old.Index, Pair.Value.Old.Text, old: true, default));

        var cut = diff.Diff(MatchOf("C")!, context: 8, maxRows: 2, default);
        Assert.True(cut.Truncated);
        Assert.Equal(2, cut.Rows.Count);
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
        // The changed instruction of C ("inc ebx" became "add ebx, 2") maps one for one.
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

        // A reference anchor: the pattern sits at a call to A, and the operand recovers A's address.
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
        // A is called from main and from B: one signature per call site, each unique, shortest first.
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
        // An engine's reference that is not code adds nothing.
        Assert.Equal(2, CodePatterns.MakeAtReferences(o.Index, o.At["A"], 64, 8, [o.Text], default).Count);
    }

    [Fact]
    public async Task Migrate_tool_writes_the_new_builds_user_layer_and_a_dry_run_does_not()
    {
        using var dir = new TempDir();
        using var env = new Env();
        var code = new Corvus.Services.NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(dir.File("ann")));
        var tools = new Corvus.Tools.NativeDiffTools(env.Workspace, code);
        var (v1, v2) = (dir.File("a.dll"), dir.File("b.dll"));
        File.WriteAllBytes(v1, NativePeTests.KitchenSink(is64: true));
        File.WriteAllBytes(v2, [.. NativePeTests.KitchenSink(is64: true), 0]);
        var oldNative = env.Workspace.LoadAny(v1).Native!;
        var newNative = env.Workspace.LoadAny(v2).Native!;
        var oldIndex = await code.Index(oldNative, null, default);
        uint first = oldIndex.AddressOfName("First")!.Value;
        code.Annotations(oldNative).SetName(first, "Renamed");
        oldIndex.SetUserName(first, "Renamed");

        // D7: a call without dryRun is a preview
        var (dry, dryText) = await BuildToolCalls.Collected<Corvus.Tools.NativeDiffTools.MigrationReport>(() => tools.MigrateNativeNames(v1, v2));
        Assert.Equal(("would_set", "name"), (Assert.Single(dry.Items).Action, dry.Items[0].Kind));
        Assert.Empty(dry.EditIds);
        Assert.StartsWith("Dry run: 1 of 1 item(s) would carry", dryText);
        Assert.Contains("1 item (showing 1-1):", dryText);
        Assert.Null(code.Annotations(newNative).NameAt(first));

        var (done, doneText) = await BuildToolCalls.Collected<Corvus.Tools.NativeDiffTools.MigrationReport>(() => tools.MigrateNativeNames(v1, v2, dryRun: false));
        Assert.Equal((1, true), (done.Set, done.Applied));
        var id = Assert.Single(done.EditIds);
        Assert.Contains($"Recorded as {id} (undo_native_edit editId={id})", doneText);
        Assert.Equal("Renamed", code.Annotations(newNative).NameAt(first));
        Assert.Equal("Renamed", (await code.Index(newNative, null, default)).NameAt(first));
        Assert.Equal("same_name", Assert.Single((await tools.CarryNames(v1, v2, true, 5, 0, null, false, false, default, default)).Items).Reason);

        // One undo takes the migration back.
        await new Corvus.Services.NativeEditJournal(env.Workspace, code).UndoAsync(newNative, id, default);
        Assert.Null(code.Annotations(newNative).NameAt(first));
    }

    [Fact]
    public async Task Code_pattern_formats_and_a_range_pattern()
    {
        using var dir = new TempDir();
        using var env = new Env();
        var code = new Corvus.Services.NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(dir.File("ann")));
        var tools = new Corvus.Tools.NativeDiffTools(env.Workspace, code);
        var path = dir.File("a.dll");
        File.WriteAllBytes(path, NativePeTests.KitchenSink(is64: true));
        var ida = await tools.MakePattern(path, "First", anchor: "address");
        var tokens = ida.Pattern.Split(' ');
        Assert.Equal(ida.Pattern, (await tools.MakePattern(path, "First", anchor: "address", format: "x64dbg")).Pattern);
        var mask = (await tools.MakePattern(path, "First", anchor: "address", format: "mask")).Pattern;
        Assert.Equal(string.Concat(tokens.Select(t => t == "??" ? "\\x00" : "\\x" + t)) + " " + string.Concat(tokens.Select(t => t == "??" ? '?' : 'x')), mask);
        var bits = (await tools.MakePattern(path, "First", anchor: "address", format: "bitmask")).Pattern;
        Assert.Equal(string.Join(", ", tokens.Select(t => t == "??" ? "0x00" : "0x" + t)) + " 0b" + string.Concat(tokens.Reverse().Select(t => t == "??" ? '0' : '1')), bits);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.MakePattern(path, "First", format: "yara"))).Code);

        // Range: the instructions inside [start, end) only, unique or not.
        var range = await tools.MakePattern(path, "First", anchor: "range", end: "+0x4");
        Assert.Equal("range", range.Anchor);
        Assert.InRange(range.Length, 1, 4);
        Assert.Equal(range.Hits == 1, range.Unique);
        Assert.Equal(tokens.Take(range.Length), range.Pattern.Split(' ').Take(tokens.Length));
        var e = await Assert.ThrowsAsync<ToolError>(() => tools.MakePattern(path, "First", anchor: "range"));
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.MakePattern(path, "First", end: "+4"))).Code);
        Assert.Equal(ErrorCode.LimitExceeded, (await Assert.ThrowsAsync<ToolError>(() => tools.MakePattern(path, "First", anchor: "range", end: "+0x10000"))).Code);

        // The tool: addresses[] with a bad one is a success with a per-item error.
        var (batch, text) = await BuildToolCalls.Collected<Corvus.Tools.NativeDiffTools.CodePatternResults>(() => tools.MakeCodePattern(path, addresses: ["First", "no_such_name"], anchor: "address"));
        Assert.Equal((1, "ida"), (batch.Failed, batch.Format));
        Assert.Equal(("First", ida.Pattern), (batch.Results[0].Target, batch.Results[0].Pattern));
        Assert.Equal("not_found", batch.Results[1].Error!.Code);
        Assert.StartsWith($"2 addresses, 1 failed.\nFirst: {ida.Pattern}\n", text);
        var (one, oneText) = await BuildToolCalls.Collected<Corvus.Tools.NativeDiffTools.CodePatternResults>(() => tools.MakeCodePattern(path, "First", anchor: "address"));
        Assert.Null(Assert.Single(one.Results).Target);
        Assert.Contains(" fixed, ", oneText);
        Assert.Contains(", address at ", oneText);
    }

    [Fact]
    public void Alignment_keeps_order_around_insertions()
    {
        var map = InstructionAlignment.Align([1, 2, 3, 4, 5], [1, 2, 9, 9, 3, 4, 5]);
        Assert.Equal([0, 1, 4, 5, 6], map);
        Assert.Equal([-1, -1], InstructionAlignment.Align([7, 8], [1, 2]));
    }
}
