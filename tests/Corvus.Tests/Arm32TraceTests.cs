using System.Text;
using Corvus.Native;
using Corvus.Native.Calls;
using Corvus.Native.Code;

namespace Corvus.Tests;

/// <summary>trace_native_values, get_call_arguments and resolve_call_targets on 32-bit ARM (AAPCS) synthetic Thumb code.</summary>
public class Arm32TraceTests
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;
    private const uint Data = CodeTestImage.SyntheticDataRva;
    private const ulong Base = 0x10000000UL;
    private const uint Fopen = Data, Callback = Data + 0x40, Hello = Data + 0x100, World = Data + 0x120;

    private sealed record Sample(NativeCodeIndex Index, Dictionary<string, uint> At);

    [Fact]
    public void Cycle_check_walks_shared_merge_inputs_once()
    {
        // 200 levels of merges whose two inputs are the same value: 2^200 paths for a plain walk
        var v = new A32Val(A64Kind.Const, 0, "") { Num = 1 };
        for (int i = 0; i < 200; i++) v = new A32Val(A64Kind.Merge, 0, "") { Inputs = [v, v with { Why = "b" }] };
        var watch = System.Diagnostics.Stopwatch.StartNew();
        Assert.False(Arm32Resolver.ContainsCycle(v, new(ReferenceEqualityComparer.Instance)));
        Assert.True(Arm32Resolver.ContainsCycle(new A32Val(A64Kind.Merge, 0, "") { Inputs = [v, new A32Val(A64Kind.Cycle, 0, "")] }, new(ReferenceEqualityComparer.Instance)));
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5));
    }

    /// <summary>
    /// main: worker("Hello", 0x10); other: worker("World", 0x20). worker(name, n): spills name to the stack, reloads it and
    /// calls fopen(name, "Hello") through its GOT slot; returns 7. store: callback = target (a Thumb pointer). dispatch:
    /// callback() as a tail call. virtual: r0->vtable[2](). param: r0(). target, second: leaves. Literal pools hold
    /// PC-relative offsets (ldr rX, [pc, #x]; add rX, pc).
    /// </summary>
    private static Sample Build()
    {
        var at = new Dictionary<string, uint>();
        var a = new A32Code(Code);
        void Here(string name) => at[name] = a.Here;
        var literals = new List<(string Name, Func<uint> Value)>();
        int literalCount = 0;
        // ldr rX, [pc, #lit]; add rX, pc: rX = address
        void Address(int reg, Func<uint> target)
        {
            string lit = $"lit{literalCount++}";
            uint add = a.Here + 2;
            a.Later(2, x => A32Code.LdrLit(reg, x, at[lit]));
            a.H(A32Code.AddPc(reg));
            literals.Add((lit, () => target() - (add + 4)));
        }
        void Pool()
        {
            a.Align4();
            foreach (var (name, value) in literals) { Here(name); a.Later(4, _ => value()); }
            literals.Clear();
        }

        Here("main");
        a.H(A32Code.PushLr(0x80));
        Address(0, () => Hello);
        a.H(A32Code.MovImm(1, 0x10));
        Here("mainCall"); a.Later(-4, x => A32Code.Bl(x, at["worker"]));
        a.H(A32Code.PopPc(0x80));
        Pool();

        Here("other");
        a.H(A32Code.PushLr(0x80));
        Address(0, () => World);
        a.H(A32Code.MovImm(1, 0x20));
        a.Later(-4, x => A32Code.Bl(x, at["worker"]));
        a.H(A32Code.PopPc(0x80));
        Pool();

        Here("worker");
        a.H(A32Code.PushLr(0x10)).H(0xB082);              // sub sp, #8
        Here("spill"); a.H(0x9001);                        // str r0, [sp, #4]
        a.H(0x9801);                                       // ldr r0, [sp, #4]
        Address(1, () => Hello);
        Address(3, () => Fopen);
        a.H(A32Code.LdrImm(3, 3, 0));
        Here("fopen"); a.H(A32Code.BlxReg(3));
        a.H(A32Code.MovImm(0, 7)).H(0xB002).H(A32Code.PopPc(0x10));   // add sp, #8
        Pool();

        Here("store");
        Address(3, () => at["target"] | 1);
        Address(2, () => Callback);
        a.H(0x6013).H(A32Code.BxLr);                       // str r3, [r2]
        Pool();

        Here("dispatch");
        Address(3, () => Callback);
        a.H(A32Code.LdrImm(3, 3, 0));
        Here("dispatchCall"); a.H(0x4718);                 // bx r3
        Pool();

        Here("virtual");
        a.H(0x6803).H(0x689B);                             // ldr r3, [r0]; ldr r3, [r3, #8]
        Here("virtualCall"); a.H(0x4718);
        a.Align4();

        Here("param");
        Here("paramCall"); a.H(0x4700);                    // bx r0
        a.Align4();

        Here("target"); a.H(A32Code.MovImm(0, 1)).H(A32Code.BxLr);
        Here("second"); a.H(A32Code.MovImm(0, 2)).H(A32Code.BxLr);

        var data = new byte[0x200];
        Encoding.ASCII.GetBytes("Hello\0").CopyTo(data, (int)(Hello - Data));
        Encoding.ASCII.GetBytes("World\0").CopyTo(data, (int)(World - Data));
        string[] exported = ["main", "other", "worker", "store", "dispatch", "virtual", "param", "target", "second"];
        var image = CodeTestImage.Synthetic(NativeArch.Arm, a.Bytes(), data, [new NativeImport("libc.so", "fopen", null, 0, Fopen, false)],
            entry: Code, exports: exported.Select((n, i) => new NativeExport(n, (uint)i + 1, at[n], null)));
        return new Sample(NativeCodeIndex.Build(image), at);
    }

    private static string Va(uint rva) => $"0x{Base + rva:X}";

    private static TraceSeed Seed(Sample s, uint rva, string? location, string? argument) =>
        Arm32Trace.Seed(Arm32Trace.For(s.Index), Va(rva), rva, location, argument, default);

    private static ValueTraceGraph Trace(Sample s, TraceSeed seed, TraceDirection direction = TraceDirection.Backward) =>
        ValueTrace.Build(Arm32Trace.For(s.Index), seed, new ValueTraceOptions(direction));

    [Fact]
    public void An_argument_is_traced_through_a_stack_slot_and_the_parameter_into_every_caller()
    {
        var s = Build();
        Assert.All(s.Index.Functions, f => Assert.Equal(0, (int)(f.Flags & FunctionFlags.InvalidCode)));
        var seed = Seed(s, s.At["fopen"], null, "1");
        Assert.Equal(("r0", TraceSeedKind.Argument), (seed.Location, seed.Kind));
        Assert.Contains("fopen", seed.Description);
        var g = Trace(s, seed);
        Assert.Equal(["\"Hello\"", "\"World\""], g.Values.Select(v => v.Text).Order());
        Assert.Contains(g.Nodes, n => n.Kind == TraceNodeKind.Parameter && n.Text.StartsWith("parameter 1 (r0)", StringComparison.Ordinal));
        Assert.Contains(g.Nodes, n => n.Derivation.Contains("str    r0, [sp, #4]", StringComparison.Ordinal));
        Assert.Equal(["\"Hello\""], Trace(s, Seed(s, s.At["fopen"], null, "mode")).Values.Select(v => v.Text));
    }

    [Fact]
    public void A_call_result_is_bound_to_the_callee_returns()
    {
        var s = Build();
        var g = Trace(s, Seed(s, s.At["mainCall"], "result", null));
        Assert.Equal(["7"], g.Values.Select(v => v.Text));
    }

    [Fact]
    public void A_value_is_followed_forward_into_the_callee_and_its_api_call()
    {
        var s = Build();
        var g = Trace(s, Seed(s, s.At["main"] + 4, "r0", null), TraceDirection.Forward);
        Assert.Contains(g.Nodes, n => n.Kind == TraceNodeKind.Argument && n.Text.Contains("argument 1 of worker", StringComparison.Ordinal));
        Assert.Contains(g.Values, v => v.Kind == TraceNodeKind.Sink && v.Text.Contains("fopen", StringComparison.Ordinal));
    }

    [Fact]
    public void Call_arguments_are_recovered_from_literal_pools_and_constants()
    {
        var s = Build();
        var call = Arm32CallSites.For(s.Index).CallAt(s.At["mainCall"])!;
        Assert.Equal("worker", call.Callee);
        Assert.Equal([(ArgKind.String, "\"Hello\""), (ArgKind.Immediate, "16")], call.Arguments.Select(x => (x.Kind, x.Text)));
        var fopen = Arm32CallSites.For(s.Index).CallAt(s.At["fopen"])!;
        Assert.Equal(("libc.so!fopen", CalleeKind.Import), (fopen.Callee, fopen.Kind));
        Assert.Equal("\"Hello\"", fopen.Arguments[1].Text);
    }

    private static CallTargetSite Site(Sample s, string name) =>
        Arm32CallTargets.At(Arm32Trace.For(s.Index), s.At[name], false) ?? throw new InvalidOperationException($"{name} is no call site");

    [Fact]
    public void Call_targets_through_got_slots_globals_and_fields()
    {
        var s = Build();
        var got = Site(s, "fopen");
        Assert.Equal(("import_slot", "import", "libc.so!fopen"), (got.Mechanism, got.Status, got.Targets.Single().Name));
        var direct = Site(s, "mainCall");
        Assert.Equal(("direct", "direct", s.At["worker"]), (direct.Mechanism, direct.Status, direct.Targets.Single().Address));
        var global = Site(s, "dispatchCall");
        Assert.Equal(("memory_pointer", "resolved", "global_writers", s.At["target"]), (global.Mechanism, global.Status, global.Targets.Single().Basis, global.Targets.Single().Address));
        var vcall = Site(s, "virtualCall");
        Assert.Equal(("memory_pointer", "unresolved"), (vcall.Mechanism, vcall.Status));
        Assert.Contains("field +0x8", vcall.Reason);
        Assert.Contains("location=r3", vcall.Hint);
        var param = Site(s, "paramCall");
        Assert.Equal("unresolved", param.Status);
        Assert.Contains("parameter 1", param.Reason);
    }
}
