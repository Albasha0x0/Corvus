using System.Text;
using Iced.Intel;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Calls;
using Corvus.Native.Code;
using Corvus.Tools;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>trace_native_values: backward and forward slices across functions on synthetic x64 code.</summary>
public class ValueTraceTests
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;
    private const uint Data = CodeTestImage.SyntheticDataRva;
    private const ulong Base = 0x140000000UL;
    private const uint CreateFileW = Data, Sleep = Data + 8, Global = Data + 0x40;

    private static Instruction Rip(Iced.Intel.Code code, Register reg, uint rva) =>
        Instruction.Create(code, reg, new MemoryOperand(Register.RIP, (long)(Base + rva), 8));

    private static Instruction CallSlot(uint slot) => Instruction.Create(Iced.Intel.Code.Call_rm64, new MemoryOperand(Register.RIP, (long)(Base + slot), 8));

    /// <summary>
    /// main: helper(L"config.ini"); helper(L"save.dat"); Sleep(five()); [Global] = 7 or 9 by path; Sleep([Global]).
    /// helper(name): CreateFileW(name, GENERIC_READ or GENERIC_READ|GENERIC_WRITE by path, ...).
    /// </summary>
    private static (CallAnalysis Analysis, Dictionary<string, uint> At) Sample()
    {
        var at = new Dictionary<string, uint>();
        var a = new Assembler(64);
        var helper = a.CreateLabel();
        var five = a.CreateLabel();
        var join = a.CreateLabel();
        var other = a.CreateLabel();
        var create = a.CreateLabel();
        var sleepResult = a.CreateLabel();
        var sleepGlobal = a.CreateLabel();
        var storeSeven = a.CreateLabel();
        var storeNine = a.CreateLabel();

        // main
        a.sub(rsp, 0x38);
        a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RCX, Data + 0x100));
        a.call(helper);
        a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RCX, Data + 0x120));
        a.call(helper);
        a.call(five);
        a.mov(ecx, eax);
        a.Label(ref sleepResult);
        a.AddInstruction(CallSlot(Sleep));
        a.test(eax, eax);
        a.jz(other);
        a.mov(eax, 7);
        a.Label(ref storeSeven);
        a.AddInstruction(Instruction.Create(Iced.Intel.Code.Mov_rm64_r64, new MemoryOperand(Register.RIP, (long)(Base + Global), 8), Register.RAX));
        a.jmp(join);
        a.Label(ref other);
        a.mov(eax, 9);
        a.Label(ref storeNine);
        a.AddInstruction(Instruction.Create(Iced.Intel.Code.Mov_rm64_r64, new MemoryOperand(Register.RIP, (long)(Base + Global), 8), Register.RAX));
        a.Label(ref join);
        a.AddInstruction(Rip(Iced.Intel.Code.Mov_r64_rm64, Register.RCX, Global));
        a.Label(ref sleepGlobal);
        a.AddInstruction(CallSlot(Sleep));
        a.add(rsp, 0x38);
        a.ret();

        // helper(name)
        var read = a.CreateLabel();
        a.Label(ref helper);
        a.sub(rsp, 0x38);
        a.mov(edx, 0x80000000);
        a.test(eax, eax);
        a.jz(read);
        var setBoth = a.CreateLabel();
        a.Label(ref setBoth);
        a.mov(edx, 0xC0000000);
        a.Label(ref read);
        a.xor(r9d, r9d);
        a.mov(r8d, 1);
        a.mov(__dword_ptr[rsp + 0x20], 3);
        a.mov(__dword_ptr[rsp + 0x28], 0x80);
        a.mov(__qword_ptr[rsp + 0x30], 0);
        a.Label(ref create);
        a.AddInstruction(CallSlot(CreateFileW));
        a.add(rsp, 0x38);
        a.ret();

        // five()
        a.Label(ref five);
        a.mov(eax, 5);
        a.ret();

        var stream = new MemoryStream();
        var result = a.Assemble(new StreamCodeWriter(stream), Base + Code, BlockEncoderOptions.ReturnNewInstructionOffsets);
        uint Rva(Label l) => (uint)(result.GetLabelRIP(l) - Base);
        at["helper"] = Rva(helper);
        at["five"] = Rva(five);
        at["create"] = Rva(create);
        at["setBoth"] = Rva(setBoth);
        at["sleepResult"] = Rva(sleepResult);
        at["sleepGlobal"] = Rva(sleepGlobal);

        var data = new byte[0x200];
        Encoding.Unicode.GetBytes("config.ini\0").CopyTo(data, 0x100);
        Encoding.Unicode.GetBytes("save.dat\0").CopyTo(data, 0x120);
        var image = CodeTestImage.Synthetic(NativeArch.X64, stream.ToArray(), data,
            [new NativeImport("KERNEL32.dll", "CreateFileW", null, 0, CreateFileW, false), new NativeImport("KERNEL32.dll", "Sleep", null, 0, Sleep, false)], entry: Code);
        return (CallAnalysis.For(NativeCodeIndex.Build(image)), at);
    }

    private static string Va(uint rva) => $"0x{Base + rva:X}";

    private static ValueTraceGraph Trace(CallAnalysis a, string address, string? location = null, string? argument = null, ValueTraceOptions? options = null) =>
        ValueTrace.Build(a, NativeTraceTools.Seed(a, address, location, argument, default), options ?? new ValueTraceOptions());

    [Fact]
    public void Backward_parameter_is_bound_to_every_callers_argument()
    {
        var (a, at) = Sample();
        var g = Trace(a, Va(at["create"]), argument: "lpFileName");
        var values = g.Values.Select(v => v.Text).ToList();
        Assert.Contains("L\"config.ini\"", values);
        Assert.Contains("L\"save.dat\"", values);
        Assert.Contains(g.Nodes, n => n.Kind == TraceNodeKind.Parameter && n.Text.StartsWith("parameter 1 (rcx)", StringComparison.Ordinal));
        Assert.Equal(2, g.Edges.Count(e => e.Kind == "argument" && g.Nodes[e.To].Kind == TraceNodeKind.Parameter));
        Assert.Empty(g.Frontier);
    }

    [Fact]
    public void A_jump_thunk_between_caller_and_function_costs_no_depth()
    {
        var a = new Assembler(64);
        var thunk = a.CreateLabel();
        var f = a.CreateLabel();
        a.sub(rsp, 0x28);
        a.mov(ecx, 7);
        a.call(thunk);
        a.add(rsp, 0x28);
        a.ret();
        a.Label(ref thunk);
        a.jmp(f);
        a.Label(ref f);
        a.lea(eax, __[rcx + 1]);
        a.ret();
        var stream = new MemoryStream();
        var result = a.Assemble(new StreamCodeWriter(stream), Base + Code, BlockEncoderOptions.ReturnNewInstructionOffsets);
        uint fRva = (uint)(result.GetLabelRIP(f) - Base);
        var analysis = CallAnalysis.For(NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, stream.ToArray(), entry: Code)));
        var g = Trace(analysis, Va(fRva), argument: "1", options: new ValueTraceOptions(MaxDepth: 1));
        Assert.Equal(["7"], g.Values.Select(v => v.Text));
    }

    [Fact]
    public void Backward_merge_keeps_both_values_decoded_through_the_api_parameter()
    {
        var (a, at) = Sample();
        var g = Trace(a, Va(at["create"]), argument: "2");
        // The merge sits at its join block, inside its function.
        var merge = Assert.Single(g.Nodes, n => n.Kind == TraceNodeKind.Merge);
        Assert.True(merge.Function != null && merge.Address >= merge.Function.Start && merge.Address < merge.Function.End, $"merge at 0x{merge.Address:X}");
        var values = g.Values.Select(v => v.Text).ToList();
        Assert.Contains("0x80000000 = GENERIC_READ", values);
        Assert.Contains("0xC0000000 = GENERIC_READ|GENERIC_WRITE", values);
    }

    [Fact]
    public void Backward_call_result_comes_from_the_callee_return_summary()
    {
        var (a, at) = Sample();
        var g = Trace(a, Va(at["sleepResult"]), argument: "1");
        Assert.Contains(g.Nodes, n => n.Kind == TraceNodeKind.CallResult);
        Assert.Equal(["5"], g.Values.Select(v => v.Text));
        Assert.Contains(g.Edges, e => e.Kind == "return");
    }

    [Fact]
    public void Backward_global_follows_its_writers()
    {
        var (a, at) = Sample();
        var g = Trace(a, Va(at["sleepGlobal"]), argument: "1");
        Assert.Contains(g.Nodes, n => n.Kind == TraceNodeKind.Global);
        Assert.Equal(2, g.Edges.Count(e => e.Kind == "store"));
        var values = g.Values.Select(v => v.Text).ToList();
        Assert.Contains("7", values);
        Assert.Contains("9", values);
        // The global alone as the seed: its writers.
        var direct = Trace(a, Va(Global));
        Assert.Equal(TraceSeedKind.Global, direct.Seed.Kind);
        Assert.Contains("7", direct.Values.Select(v => v.Text));
    }

    [Fact]
    public void Forward_constant_reaches_the_api_parameter_decoded()
    {
        var (a, at) = Sample();
        var g = Trace(a, Va(at["setBoth"]), location: "rdx", options: new ValueTraceOptions(TraceDirection.Forward));
        var sink = Assert.Single(g.Nodes, n => n.Kind == TraceNodeKind.Sink);
        Assert.Contains("dwDesiredAccess", sink.Text);
        Assert.Equal("GENERIC_READ|GENERIC_WRITE", sink.Decoded);
        Assert.Contains(g.Values, v => v.Text.Contains("GENERIC_READ|GENERIC_WRITE", StringComparison.Ordinal));
    }

    [Fact]
    public void Forward_parameter_flows_into_the_api_and_back_through_callers_results()
    {
        var (a, at) = Sample();
        var g = Trace(a, Va(at["helper"]), argument: "1", options: new ValueTraceOptions(TraceDirection.Forward));
        Assert.Contains(g.Nodes, n => n.Kind == TraceNodeKind.Sink && n.Text.Contains("lpFileName", StringComparison.Ordinal));
        var r = Trace(a, Va(at["five"]), location: "rax", options: new ValueTraceOptions(TraceDirection.Forward));
        Assert.Contains(r.Nodes, n => n.Kind == TraceNodeKind.Return);
        Assert.Contains(r.Nodes, n => n.Kind == TraceNodeKind.Sink && n.Text.Contains("Sleep", StringComparison.Ordinal));
    }

    [Fact]
    public void Depth_budget_puts_the_parameter_in_the_frontier_with_the_follow_up_call()
    {
        var (a, at) = Sample();
        var g = Trace(a, Va(at["create"]), argument: "1", options: new ValueTraceOptions(MaxDepth: 0));
        var f = Assert.Single(g.Frontier);
        Assert.Equal("depth", f.Reason);
        Assert.Equal($"trace_native_values address={Va(at["helper"])} argument=1", f.Next);
        Assert.Empty(g.Values);
    }

    [Fact]
    public void Node_budget_never_drops_items_silently()
    {
        var (a, at) = Sample();
        var g = Trace(a, Va(at["create"]), argument: "1", options: new ValueTraceOptions(MaxNodes: 3));
        Assert.True(g.Nodes.Count <= 4);
        Assert.Contains(g.Frontier, f => f.Reason == "nodes" && f.Next.StartsWith("trace_native_values", StringComparison.Ordinal));
    }

    [Fact]
    public void Pages_are_served_from_the_cached_graph()
    {
        var (a, at) = Sample();
        var first = Trace(a, Va(at["create"]), argument: "1");
        var again = Trace(a, Va(at["create"]), argument: "1");
        Assert.Same(first, again);
        Assert.Equal(1, a.Traces.Builds);
        Trace(a, Va(at["create"]), argument: "2");
        Assert.Equal(2, a.Traces.Builds);
    }

    /// <summary>main: sw(5); sw(20). sw(x): an MSVC switch on x - 3 over five cases (values 3..7) and a default.</summary>
    private static (CallAnalysis Analysis, Dictionary<string, uint> At) Switch()
    {
        var a = new Assembler(64);
        Label sw = a.CreateLabel(), dflt = a.CreateLabel(), five = a.CreateLabel(), twenty = a.CreateLabel();
        var cases = Enumerable.Range(0, 5).Select(_ => a.CreateLabel()).ToArray();
        const uint table = Data + 0x40;
        a.sub(rsp, 0x28);
        a.Label(ref five);
        a.mov(ecx, 5);
        a.call(sw);
        a.Label(ref twenty);
        a.mov(ecx, 20);
        a.call(sw);
        a.add(rsp, 0x28);
        a.ret();
        a.Label(ref sw);
        a.lea(eax, __[rcx - 3]);
        a.cmp(eax, 4);
        a.ja(dflt);
        a.AddInstruction(Instruction.Create(Iced.Intel.Code.Lea_r64_m, Register.RDX, new MemoryOperand(Register.RIP, (long)Base, 8)));
        a.movsxd(rax, eax);
        a.mov(ecx, __dword_ptr[rdx + rax * 4 + (int)table]);
        a.add(rcx, rdx);
        a.jmp(rcx);
        for (int i = 0; i < 5; i++)
        {
            a.Label(ref cases[i]);
            a.mov(eax, 100 + i);
            a.ret();
        }
        a.Label(ref dflt);
        a.xor(eax, eax);
        a.ret();
        var stream = new MemoryStream();
        var result = a.Assemble(new StreamCodeWriter(stream), Base + Code, BlockEncoderOptions.ReturnNewInstructionOffsets);
        uint Rva(Label l) => (uint)(result.GetLabelRIP(l) - Base);
        var data = new byte[0x100];
        for (int i = 0; i < 5; i++) System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x40 + 4 * i), Rva(cases[i]));
        var image = CodeTestImage.Synthetic(NativeArch.X64, stream.ToArray(), data, entry: Code);
        var at = new Dictionary<string, uint> { ["five"] = Rva(five), ["twenty"] = Rva(twenty), ["case2"] = Rva(cases[2]), ["default"] = Rva(dflt) };
        return (CallAnalysis.For(NativeCodeIndex.Build(image)), at);
    }

    [Fact]
    public void Forward_constant_reports_the_switch_case_it_selects()
    {
        var (a, at) = Switch();
        var g = Trace(a, Va(at["five"]), location: "rcx", options: new ValueTraceOptions(TraceDirection.Forward));
        var sw = Assert.Single(g.Nodes, n => n.Kind == TraceNodeKind.Switch);
        Assert.Equal($"selects case 5 -> {Va(at["case2"])}", sw.Decoded);
        Assert.Contains(g.Values, v => v.Kind == TraceNodeKind.Switch && v.Text.EndsWith($"selects case 5 -> {Va(at["case2"])}", StringComparison.Ordinal));
        var other = Trace(a, Va(at["twenty"]), location: "rcx", options: new ValueTraceOptions(TraceDirection.Forward));
        Assert.Equal($"selects the default -> {Va(at["default"])} (value 20)", Assert.Single(other.Nodes, n => n.Kind == TraceNodeKind.Switch).Decoded);
    }

    [Fact]
    public void Seeds_reject_bad_arguments_with_reasons()
    {
        var (a, at) = Sample();
        Assert.Contains("1-based", Assert.Throws<ToolError>(() => Trace(a, Va(at["create"]), argument: "0")).Message);
        Assert.Contains("dwDesiredAccess", Assert.Throws<ToolError>(() => Trace(a, Va(at["create"]), argument: "nope")).Remediation);
        Assert.Throws<ToolError>(() => Trace(a, Va(at["create"]), location: "bogus"));
        Assert.Contains("location", Assert.Throws<ToolError>(() => Trace(a, Va(at["create"]))).Message);
    }
}
