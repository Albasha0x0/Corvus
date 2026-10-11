using System.Buffers.Binary;
using System.Text;
using Corvus.Native;
using Corvus.Native.Calls;
using Corvus.Native.Code;
using Corvus.Tests.NativeFormats;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>trace_native_values and resolve_call_targets on ARM64 (AAPCS64) synthetic code.</summary>
public class Arm64TraceTests
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;
    private const uint Data = CodeTestImage.SyntheticDataRva;
    private const ulong Base = 0x10000000UL;
    private const uint Fopen = Data, Callback = Data + 0x40, Table = Data + 0x80, Hello = Data + 0x100, World = Data + 0x120;
    private const uint Hi = 8;

    private static uint StrX(int t, int n, uint off) => 0xF9000000 | (off / 8) << 10 | (uint)n << 5 | (uint)t;
    private static uint LdrXIndexed(int t, int n, int m) => 0xF8607800 | (uint)m << 16 | (uint)n << 5 | (uint)t;
    private static uint CmpImm(int n, uint imm) => 0x7100001F | imm << 10 | (uint)n << 5;
    private const uint StpFrame32 = 0xA9BE7BFD, LdpFrame32 = 0xA8C27BFD;

    [Fact]
    public void Cycle_check_walks_shared_merge_inputs_once()
    {
        // 200 levels of merges whose two inputs are the same value: 2^200 paths for a plain walk
        var v = new A64Val(A64Kind.Const, 0, "") { Num = 1 };
        for (int i = 0; i < 200; i++) v = new A64Val(A64Kind.Merge, 0, "") { Inputs = [v, v with { Why = "b" }] };
        var watch = System.Diagnostics.Stopwatch.StartNew();
        Assert.False(Arm64Resolver.ContainsCycle(v, new(ReferenceEqualityComparer.Instance)));
        Assert.True(Arm64Resolver.ContainsCycle(new A64Val(A64Kind.Merge, 0, "") { Inputs = [v, new A64Val(A64Kind.Cycle, 0, "")] }, new(ReferenceEqualityComparer.Instance)));
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5));
    }

    private sealed record Sample(NativeCodeIndex Index, Dictionary<string, uint> At);

    /// <summary>
    /// main: worker("Hello", 0x10); other: worker("World", 0x20). worker(name, n): spills name to [sp+16], reloads it and
    /// calls fopen(name, "Hello") through the GOT; returns 7. store: callback = target. dispatch: callback(); constant:
    /// adr x8, target; blr x8. virtual: x0->vtable[2](). param: x0(). table: entries[w0] for w0 &lt;= 1. target, second: leaves.
    /// </summary>
    private static Sample Build()
    {
        var at = new Dictionary<string, uint>();
        var a = new A64(Code);
        void Here(string name) => at[name] = a.Here;

        Here("main");
        a.Word(A64.StpFpLrPre).Word(A64.MovFpSp);
        a.Word(A64.Adrp(a.Here, Hello, 0, Base)).Word(A64.AddImm(0, 0, Hello & 0xFFF));
        a.Word(A64.MovW(1, 0x10));
        Here("mainCall"); a.Later(x => A64.Bl(x, at["worker"]));
        a.Word(A64.LdpFpLrPost).Word(A64.Ret);

        Here("other");
        a.Word(A64.StpFpLrPre).Word(A64.MovFpSp);
        a.Word(A64.Adrp(a.Here, World, 0, Base)).Word(A64.AddImm(0, 0, World & 0xFFF));
        a.Word(A64.MovW(1, 0x20));
        a.Later(x => A64.Bl(x, at["worker"]));
        a.Word(A64.LdpFpLrPost).Word(A64.Ret);

        Here("worker");
        a.Word(StpFrame32).Word(A64.MovFpSp);
        Here("spill"); a.Word(StrX(0, 31, 16));
        a.Word(0xF9400BE0); // ldr x0, [sp, #16]
        a.Word(A64.Adrp(a.Here, Hello, 1, Base)).Word(A64.AddImm(1, 1, Hello & 0xFFF));
        a.Word(A64.Adrp(a.Here, Fopen, 16, Base)).Word(A64.LdrX(17, 16, Fopen & 0xFFF));
        Here("fopen"); a.Word(A64.Blr(17));
        a.Word(A64.MovW(0, 7));
        a.Word(LdpFrame32).Word(A64.Ret);

        Here("store");
        a.Word(A64.Adrp(a.Here, at.GetValueOrDefault("target"), 8, Base)); // patched below once target is known
        a.Word(0);
        a.Word(A64.Adrp(a.Here, Callback, 9, Base)).Word(StrX(8, 9, Callback & 0xFFF)).Word(A64.Ret);

        Here("dispatch");
        a.Word(A64.Adrp(a.Here, Callback, 8, Base)).Word(A64.LdrX(8, 8, Callback & 0xFFF));
        Here("dispatchCall"); a.Word(A64.Br(8));

        Here("constant");
        a.Later(x => A64.Adr(x, at["target"], 8));
        Here("constantCall"); a.Word(A64.Br(8));

        Here("virtual");
        a.Word(A64.LdrX(8, 0, 0)).Word(A64.LdrX(8, 8, 16));
        Here("virtualCall"); a.Word(A64.Br(8));

        Here("param");
        Here("paramCall"); a.Word(A64.Br(0));

        Here("table");
        a.Word(CmpImm(0, 1)).Later(x => A64.BCond(x, at["tableDefault"], Hi));
        a.Word(A64.Adrp(a.Here, Table, 9, Base)).Word(A64.AddImm(9, 9, Table & 0xFFF));
        a.Word(LdrXIndexed(8, 9, 0));
        Here("tableCall"); a.Word(A64.Blr(8));
        Here("tableDefault"); a.Word(A64.Ret);

        Here("passer");
        a.Word(A64.StpFpLrPre).Word(A64.MovFpSp);
        a.Later(x => A64.Adr(x, at["second"], 0));
        a.Later(x => A64.Bl(x, at["param"]));
        a.Word(A64.LdpFpLrPost).Word(A64.Ret);

        Here("target"); a.Word(A64.MovW(0, 1)).Word(A64.Ret);
        Here("second"); a.Word(A64.MovW(0, 2)).Word(A64.Ret);

        var code = a.Bytes();
        // store: adrp x8, target; add x8, x8, #lo12
        BinaryPrimitives.WriteUInt32LittleEndian(code.AsSpan((int)(at["store"] - Code)), A64.Adrp(at["store"], at["target"], 8, Base));
        BinaryPrimitives.WriteUInt32LittleEndian(code.AsSpan((int)(at["store"] - Code + 4)), A64.AddImm(8, 8, at["target"] & 0xFFF));

        var data = new byte[0x200];
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan((int)(Table - Data)), Base + at["target"]);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan((int)(Table - Data + 8)), Base + at["second"]);
        Encoding.ASCII.GetBytes("Hello\0").CopyTo(data, (int)(Hello - Data));
        Encoding.ASCII.GetBytes("World\0").CopyTo(data, (int)(World - Data));
        string[] exported = ["main", "other", "worker", "store", "dispatch", "constant", "virtual", "param", "table", "passer", "target", "second"];
        var image = CodeTestImage.Synthetic(NativeArch.Arm64, code, data, [new NativeImport("libc.so", "fopen", null, 0, Fopen, false)],
            relocations: [Table, Table + 8], entry: Code, exports: exported.Select((n, i) => new NativeExport(n, (uint)i + 1, at[n], null)));
        return new Sample(NativeCodeIndex.Build(image), at);
    }

    private static ValueTraceGraph Trace(Sample s, TraceSeed seed, TraceDirection direction = TraceDirection.Backward) =>
        ValueTrace.Build(Arm64Trace.For(s.Index), seed, new ValueTraceOptions(direction));

    [Fact]
    public void An_argument_is_traced_through_a_stack_slot_and_the_parameter_into_every_caller()
    {
        var s = Build();
        var a = Arm64Trace.For(s.Index);
        var seed = NativeTraceTools.Arm64Seed(a, $"0x{Base + s.At["fopen"]:X}", null, "1", default);
        Assert.Equal(("x0", TraceSeedKind.Argument), (seed.Location, seed.Kind));
        Assert.Contains("fopen", seed.Description);
        var g = Trace(s, seed);
        Assert.Equal(["\"Hello\"", "\"World\""], g.Values.Select(v => v.Text).Order());
        Assert.Contains(g.Nodes, n => n.Kind == TraceNodeKind.Parameter && n.Text.StartsWith("parameter 1 (x0)", StringComparison.Ordinal));
        Assert.Contains(g.Edges, e => e.Kind == "argument");
        Assert.Contains(g.Nodes, n => n.Derivation.Contains("str x0, [sp, #16]", StringComparison.Ordinal));

        var mode = NativeTraceTools.Arm64Seed(a, $"0x{Base + s.At["fopen"]:X}", null, "mode", default);
        Assert.Equal(["\"Hello\""], Trace(s, mode).Values.Select(v => v.Text));
    }

    [Fact]
    public void A_call_result_is_bound_to_the_callee_returns()
    {
        var s = Build();
        var seed = NativeTraceTools.Arm64Seed(Arm64Trace.For(s.Index), $"0x{Base + s.At["mainCall"]:X}", "result", null, default);
        var g = Trace(s, seed);
        Assert.Equal(["7"], g.Values.Select(v => v.Text));
        Assert.Contains(g.Edges, e => e.Kind == "return");
    }

    [Fact]
    public void A_value_is_followed_forward_into_the_callee_and_its_api_call()
    {
        var s = Build();
        var seed = NativeTraceTools.Arm64Seed(Arm64Trace.For(s.Index), $"0x{Base + s.At["main"] + 12:X}", "x0", null, default);
        var g = Trace(s, seed, TraceDirection.Forward);
        Assert.Contains(g.Nodes, n => n.Kind == TraceNodeKind.Argument && n.Text.Contains("argument 1 of worker", StringComparison.Ordinal));
        Assert.Contains(g.Values, v => v.Kind == TraceNodeKind.Sink && v.Text.Contains("fopen", StringComparison.Ordinal));
    }

    [Fact]
    public void Stack_slots_are_named_relative_to_sp_at_the_instruction()
    {
        var s = Build();
        var a = Arm64Trace.For(s.Index);
        var seed = NativeTraceTools.Arm64Seed(a, $"0x{Base + s.At["spill"]:X}", "op2", null, default);
        Assert.Equal("[sp+10h]", seed.Location);
        var g = Trace(s, seed, TraceDirection.Forward);
        Assert.Contains(g.Values, v => v.Text.Contains("fopen", StringComparison.Ordinal));
    }

    private static CallTargetSite Site(Sample s, string name, bool deep = false) =>
        Arm64CallTargets.At(Arm64Trace.For(s.Index), s.At[name], deep) ?? throw new InvalidOperationException($"{name} is no call site");

    [Fact]
    public void Call_targets_through_got_slots_constants_globals_and_tables_are_resolved()
    {
        var s = Build();
        var got = Site(s, "fopen");
        Assert.Equal(("import_slot", "import", "libc.so!fopen"), (got.Mechanism, got.Status, got.Targets.Single().Name));

        var direct = Site(s, "mainCall");
        Assert.Equal(("direct", "direct", s.At["worker"]), (direct.Mechanism, direct.Status, direct.Targets.Single().Address));

        var constant = Site(s, "constantCall");
        Assert.Equal(("register", "resolved", "constant_pointer", s.At["target"]), (constant.Mechanism, constant.Status, constant.Targets.Single().Basis, constant.Targets.Single().Address));

        var global = Site(s, "dispatchCall");
        Assert.Equal(("memory_pointer", "resolved", "global_writers", s.At["target"]), (global.Mechanism, global.Status, global.Targets.Single().Basis, global.Targets.Single().Address));

        var table = Site(s, "tableCall");
        Assert.Equal(("pointer_table", "resolved"), (table.Mechanism, table.Status));
        Assert.Equal([s.At["target"], s.At["second"]], table.Targets.Select(t => t.Address));
    }

    [Fact]
    public void Field_loads_and_parameters_stay_unresolved_with_a_trace_hint_and_deep_follows_callers()
    {
        var s = Build();
        var vcall = Site(s, "virtualCall");
        Assert.Equal(("memory_pointer", "unresolved"), (vcall.Mechanism, vcall.Status));
        Assert.Contains("field +0x10", vcall.Reason);
        Assert.Contains("location=x8", vcall.Hint);

        var param = Site(s, "paramCall");
        Assert.Equal("unresolved", param.Status);
        Assert.Contains("parameter 1", param.Reason);
        var deep = Site(s, "paramCall", deep: true);
        Assert.Equal(("resolved", s.At["second"], "caller_argument"), (deep.Status, deep.Targets.Single().Address, deep.Targets.Single().Basis));

        var image = Arm64CallTargets.Image(Arm64Trace.For(s.Index), deep: false);
        Assert.All(image, x => Assert.True(x.IsIndirect));
        Assert.Contains(image, x => x.Rva == s.At["virtualCall"]);
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public async Task Real_arm64_image_traces_and_resolves_through_the_tools()
    {
        using var h = new NativeToolHarness(backgroundIndexing: false);
        var path = NativeFixtures.LinuxArm64DbgShim;
        var calls = new NativeCallTargetTools(h.Workspace, h.Code);
        var report = await calls.ResolveCallTargets(path, scope: "image", limit: 1000);
        Assert.Contains("Call targets in", report);
        Assert.Contains("import_slot", report);
        var trace = new NativeTraceTools(h.Workspace, h.Code);
        var text = await trace.TraceNativeValues(path, "RegisterForRuntimeStartup", argument: "1");
        Assert.Contains("Value trace (backward) of parameter 1 (x0)", text);
    }
}
