using Iced.Intel;
using Corvus.Native;
using Corvus.Native.Calls;
using Corvus.Native.Code;
using Corvus.Tools;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>trace_native_values seeded at floating-point registers: xmm on x86 / x64, d / s on ARM64.</summary>
public class FloatTraceTests
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;
    private const uint Data = CodeTestImage.SyntheticDataRva;
    private const uint Pow = Data;
    private static readonly ulong OneAndHalf = BitConverter.DoubleToUInt64Bits(1.5), Three = BitConverter.DoubleToUInt64Bits(3.0);

    private sealed record Sample(NativeCodeIndex Index, Dictionary<string, uint> At, ulong Base);

    /// <summary>main: helper(1.5); helper(3.0 from scvtf of w8 = 3). helper(x): pow(x, 2.0) through the GOT, and returns its result.</summary>
    private static Sample Arm64()
    {
        const ulong Base = 0x10000000UL;
        var at = new Dictionary<string, uint>();
        var a = new A64(Code);
        void Here(string name) => at[name] = a.Here;
        Here("main");
        a.Word(A64.StpFpLrPre).Word(A64.MovFpSp);
        a.Word(0x1E6F1000); // fmov d0, #1.5
        Here("call1"); a.Later(x => A64.Bl(x, at["helper"]));
        a.Word(A64.MovW(8, 3)).Word(0x1E620100); // scvtf d0, w8
        Here("call2"); a.Later(x => A64.Bl(x, at["helper"]));
        a.Word(A64.LdpFpLrPost).Word(A64.Ret);
        Here("helper");
        a.Word(A64.StpFpLrPre).Word(A64.MovFpSp);
        a.Word(0x1E601001); // fmov d1, #2.0
        a.Word(A64.Adrp(a.Here, Pow, 16, Base)).Word(A64.LdrX(17, 16, Pow & 0xFFF));
        Here("pow"); a.Word(A64.Blr(17));
        a.Word(A64.LdpFpLrPost);
        Here("ret"); a.Word(A64.Ret);
        var image = CodeTestImage.Synthetic(NativeArch.Arm64, a.Bytes(), new byte[0x100], [new NativeImport("libm.so.6", "pow", null, 0, Pow, false)], entry: Code,
            exports: [new NativeExport("main", 1, at["main"], null), new NativeExport("helper", 2, at["helper"], null)]);
        return new Sample(NativeCodeIndex.Build(image), at, Base);
    }

    private static ValueTraceGraph Arm64Trace(Sample s, string at, string location, TraceDirection direction = TraceDirection.Backward)
    {
        var host = Native.Calls.Arm64Trace.For(s.Index);
        return ValueTrace.Build(host, NativeTraceTools.Arm64Seed(host, $"0x{s.Base + s.At[at]:X}", location, null, default), new ValueTraceOptions(direction));
    }

    [Fact]
    public void Arm64_d_register_is_traced_back_through_the_parameter_to_each_caller()
    {
        var g = Arm64Trace(Arm64(), "pow", "d0");
        Assert.Contains(g.Nodes, n => n.Kind == TraceNodeKind.Parameter && n.Text.Contains("incoming d0", StringComparison.Ordinal));
        Assert.Equal([OneAndHalf, Three], g.Nodes.Where(v => v.Kind == TraceNodeKind.Const).Select(v => v.Value ?? 0).Order());
        Assert.Contains(g.Nodes, n => n.Derivation.Contains("scvtf", StringComparison.Ordinal));

        var second = Arm64Trace(Arm64(), "pow", "d1");
        Assert.Equal([BitConverter.DoubleToUInt64Bits(2.0)], second.Nodes.Where(v => v.Kind == TraceNodeKind.Const).Select(v => v.Value ?? 0));
    }

    [Fact]
    public void Arm64_float_result_and_forward_uses()
    {
        var s = Arm64();
        var result = Arm64Trace(s, "ret", "d0");
        Assert.Contains(result.Nodes, n => n.Kind is TraceNodeKind.ApiResult or TraceNodeKind.CallResult && n.Text.Contains("pow", StringComparison.Ordinal));

        var forward = Arm64Trace(s, "call1", "d0", TraceDirection.Forward);
        Assert.Contains(forward.Nodes, n => n.Kind == TraceNodeKind.Argument && n.Text.Contains("argument in d0 of", StringComparison.Ordinal));
        Assert.Contains(forward.Values, v => v.Text.Contains("pow", StringComparison.Ordinal));
        Assert.Equal("d2", A64Function.Name(A64Function.Parse("s2", null)!.Value, null));
        Assert.Null(A64Function.Parse("d32", null));
    }

    [Fact]
    public void X64_xmm_register_is_traced_back_through_the_parameter_and_the_call_result()
    {
        const ulong Base = 0x140000000UL;
        var a = new Assembler(64);
        var helper = a.CreateLabel();
        var call = a.CreateLabel();
        var ret = a.CreateLabel();
        a.sub(rsp, 0x28);
        a.mov(rax, OneAndHalf);
        a.movq(xmm0, rax);
        a.call(helper);
        a.add(rsp, 0x28);
        a.ret();
        a.Label(ref helper);
        a.sub(rsp, 0x28);
        a.Label(ref call);
        a.AddInstruction(Instruction.Create(Iced.Intel.Code.Call_rm64, new MemoryOperand(Register.RIP, (long)(Base + Pow), 8)));
        a.add(rsp, 0x28);
        a.Label(ref ret);
        a.ret();
        var stream = new MemoryStream();
        var r = a.Assemble(new StreamCodeWriter(stream), Base + Code, BlockEncoderOptions.ReturnNewInstructionOffsets);
        var image = CodeTestImage.Synthetic(NativeArch.X64, stream.ToArray(), new byte[0x100], [new NativeImport("ucrtbase.dll", "pow", null, 0, Pow, false)], entry: Code);
        var analysis = CallAnalysis.For(NativeCodeIndex.Build(image));
        string Va(Label l) => $"0x{r.GetLabelRIP(l):X}";

        var back = ValueTrace.Build(analysis, NativeTraceTools.Seed(analysis, Va(call), "xmm0", null, default), new ValueTraceOptions());
        Assert.Equal([OneAndHalf], back.Nodes.Where(v => v.Kind == TraceNodeKind.Const).Select(v => v.Value ?? 0));

        var result = ValueTrace.Build(analysis, NativeTraceTools.Seed(analysis, Va(ret), "xmm0", null, default), new ValueTraceOptions());
        Assert.Contains(result.Nodes, n => n.Kind is TraceNodeKind.ApiResult or TraceNodeKind.CallResult && n.Text.Contains("pow", StringComparison.Ordinal));
    }
}
