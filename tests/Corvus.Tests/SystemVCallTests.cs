using System.Text;
using Iced.Intel;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Calls;
using Corvus.Native.Code;
using Corvus.Services;
using Corvus.Tests.NativeFormats;
using Corvus.Tools;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>The System V x64 calling convention on ELF and Mach-O: call arguments, value traces, late-bound names and the dossier.</summary>
public class SystemVCallTests
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;
    private const uint Data = CodeTestImage.SyntheticDataRva;
    private const ulong Base = 0x140000000UL;
    private const uint Printf = Data, Pow = Data + 8, Dlopen = Data + 0x10, Dlsym = Data + 0x18, Sleep = Data + 0x20, Free = Data + 0x28, Global = Data + 0x30;
    private const uint Format = Data + 0x100, Name = Data + 0x140, Libm = Data + 0x160, Cos = Data + 0x180, Two = Data + 0x1A0;

    private static Instruction Rip(Iced.Intel.Code code, Register reg, uint rva) => Instruction.Create(code, reg, new MemoryOperand(Register.RIP, (long)(Base + rva), 8));
    private static Instruction CallSlot(uint rva) => Instruction.Create(Iced.Intel.Code.Call_rm64, new MemoryOperand(Register.RIP, (long)(Base + rva), 8));

    private static (NativeCodeIndex Index, CallAnalysis Calls) Build(ImageFormat format)
    {
        var a = new Assembler(64);
        var helper = a.CreateLabel();
        a.sub(rsp, 0x18);
        // printf("%s %d %d %d %d %d %f", "name", 1, 2, 3, 4, 5, 2.0): the sixth integer goes to the stack, the double to xmm0
        a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RDI, Format));
        a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RSI, Name));
        a.mov(edx, 1);
        a.mov(ecx, 2);
        a.mov(r8d, 3);
        a.mov(r9d, 4);
        a.mov(__dword_ptr[rsp], 5);
        a.AddInstruction(Rip(Iced.Intel.Code.Movsd_xmm_xmmm64, Register.XMM0, Two));
        a.mov(eax, 1);
        a.AddInstruction(CallSlot(Printf));
        // pow(x, y): both in xmm registers
        a.AddInstruction(Rip(Iced.Intel.Code.Movsd_xmm_xmmm64, Register.XMM0, Two));
        a.AddInstruction(Rip(Iced.Intel.Code.Movsd_xmm_xmmm64, Register.XMM1, Two));
        a.AddInstruction(CallSlot(Pow));
        // dlsym(dlopen("libm.so.6", 2), "cos"), stored and called through the global
        a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RDI, Libm));
        a.mov(esi, 2);
        a.AddInstruction(CallSlot(Dlopen));
        a.mov(rdi, rax);
        a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RSI, Cos));
        a.AddInstruction(CallSlot(Dlsym));
        a.AddInstruction(Instruction.Create(Iced.Intel.Code.Mov_rm64_r64, new MemoryOperand(Register.RIP, (long)(Base + Global), 8), Register.RAX));
        a.AddInstruction(CallSlot(Global));
        // rsi is volatile under System V, rbx is not
        a.mov(esi, 7);
        a.mov(ebx, 9);
        a.mov(edi, 1);
        a.AddInstruction(CallSlot(Sleep));
        a.mov(edi, esi);
        a.AddInstruction(CallSlot(Free));
        a.mov(edi, ebx);
        a.AddInstruction(CallSlot(Free));
        // a local call without a signature: the registers set before it
        a.mov(edi, 10);
        a.mov(esi, 11);
        a.call(helper);
        a.add(rsp, 0x18);
        a.ret();
        a.Label(ref helper);
        a.lea(eax, __[rdi + rsi]);
        a.ret();
        var stream = new MemoryStream();
        a.Assemble(new StreamCodeWriter(stream), Base + Code);
        var data = new byte[0x200];
        Encoding.ASCII.GetBytes("%s %d %d %d %d %d %f\0").CopyTo(data, 0x100);
        Encoding.ASCII.GetBytes("name\0").CopyTo(data, 0x140);
        Encoding.ASCII.GetBytes("libm.so.6\0").CopyTo(data, 0x160);
        Encoding.ASCII.GetBytes("cos\0").CopyTo(data, 0x180);
        BitConverter.GetBytes(2.0).CopyTo(data, 0x1A0);
        string prefix = format == ImageFormat.MachO ? "_" : "";
        NativeImport Import(string name, uint slot) => new("libc.so.6", prefix + name, null, 0, slot, false);
        var image = CodeTestImage.Synthetic(NativeArch.X64, stream.ToArray(), data,
            [Import("printf", Printf), Import("pow", Pow), Import("dlopen", Dlopen), Import("dlsym", Dlsym), Import("sleep", Sleep), Import("free", Free)],
            entry: Code, format: format);
        var index = NativeCodeIndex.Build(image);
        return (index, CallAnalysis.For(index));
    }

    [Theory]
    [InlineData(ImageFormat.Elf)]
    [InlineData(ImageFormat.MachO)]
    public void Arguments_follow_the_register_classes_and_the_stack(ImageFormat format)
    {
        var (index, analysis) = Build(format);
        var calls = analysis.CallsIn(index.FunctionByStart(Code)!);

        var printf = calls[0];
        Assert.Equal(["rdi", "rsi", "rdx", "rcx", "r8", "r9", "[rsp+0h]", "xmm0"], printf.Arguments.Select(a => a.Location));
        Assert.Equal("\"name\"", printf.Arguments[1].Text);
        Assert.Equal([1UL, 2, 3, 4, 5], printf.Arguments.Skip(2).Take(5).Select(a => a.Value ?? 0));
        Assert.Equal(["xmm0", "xmm1"], calls[1].Arguments.Select(a => a.Location));
        Assert.Equal(["rdi", "rsi"], calls[2].Arguments.Select(a => a.Location));
        Assert.Equal("\"libm.so.6\"", calls[2].Arguments[0].Text);

        var cos = Assert.Single(analysis.DynamicImports().Imports);
        Assert.Equal("cos", cos.Name);
        Assert.Equal("libm.so.6", cos.Module);
        Assert.Equal(Global, cos.PointerGlobal);
        Assert.Contains(calls, c => c.Kind == CalleeKind.Dynamic && c.Callee == cos.FullName);

        var frees = calls.Where(c => c.ShortCallee.EndsWith("free", StringComparison.Ordinal)).ToList();
        Assert.Equal(ArgKind.Unknown, frees[0].Arguments[0].Kind);
        Assert.Contains("clobbered", frees[0].Arguments[0].Derivation);
        Assert.Equal(9UL, frees[1].Arguments[0].Value);

        var local = calls.Last();
        Assert.True(local.Guessed);
        Assert.Equal(["rdi", "rsi"], local.Arguments.Select(a => a.Location));
        Assert.Equal([10UL, 11], local.Arguments.Select(a => a.Value ?? 0));
    }

    private static (NativeCodeIndex Index, CallAnalysis Calls) Assemble(Action<Assembler> body, byte[]? data = null, params NativeImport[] imports)
    {
        var a = new Assembler(64);
        body(a);
        var stream = new MemoryStream();
        a.Assemble(new StreamCodeWriter(stream), Base + Code);
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, stream.ToArray(), data ?? new byte[0x200], imports, entry: Code, format: ImageFormat.Elf));
        return (index, CallAnalysis.For(index));
    }

    [Fact]
    public void A_struct_return_buffer_in_rdi_shifts_the_arguments()
    {
        // make(&local, 1, 2): the callee stores both and returns its rdi, as a function returning a 24-byte struct does
        var (index, analysis) = Assemble(a =>
        {
            var make = a.CreateLabel();
            a.sub(rsp, 0x28);
            a.lea(rdi, __[rsp + 8]);
            a.mov(esi, 1);
            a.mov(edx, 2);
            a.call(make);
            a.add(rsp, 0x28);
            a.ret();
            a.Label(ref make);
            a.mov(__qword_ptr[rdi], rsi);
            a.mov(__qword_ptr[rdi + 8], rdx);
            a.mov(__qword_ptr[rdi + 16], 0);
            a.mov(rax, rdi);
            a.ret();
        });
        var call = Assert.Single(analysis.CallsIn(index.FunctionByStart(Code)!));
        Assert.Equal(["sret", null, null], call.Arguments.Select(x => x.Name));
        Assert.Equal(["rdi", "rsi", "rdx"], call.Arguments.Select(x => x.Location));
        Assert.Equal(("&local", 1UL, 2UL), (call.Arguments[0].Text, call.Arguments[1].Value!.Value, call.Arguments[2].Value!.Value));
        Assert.Equal([0, 1, 2], call.Arguments.Select(x => x.Index));
    }

    [Fact]
    public void A_variadic_call_counts_its_vector_arguments_in_al()
    {
        // log_values(fmt, 7, 1.5, 2.0) to a local variadic function: al = 2 vector registers
        uint fmt = Data + 0x100;
        var data = new byte[0x200];
        Encoding.ASCII.GetBytes("%d %f %f\0").CopyTo(data, 0x100);
        var (index, analysis) = Assemble(a =>
        {
            var log = a.CreateLabel();
            a.sub(rsp, 8);
            a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RDI, fmt));
            a.mov(esi, 7);
            a.mov(rax, BitConverter.DoubleToInt64Bits(1.5));
            a.movq(xmm0, rax);
            a.mov(rax, BitConverter.DoubleToInt64Bits(2.0));
            a.movq(xmm1, rax);
            a.mov(eax, 2);
            a.call(log);
            a.xor(eax, eax);
            a.mov(edi, 3);
            a.call(log);
            a.add(rsp, 8);
            a.ret();
            a.Label(ref log);
            a.ret();
        }, data);
        var calls = analysis.CallsIn(index.FunctionByStart(Code)!);
        Assert.Equal(["rdi", "rsi", "xmm0", "xmm1"], calls[0].Arguments.Select(x => x.Location));
        Assert.Equal(["1.5", "2"], calls[0].Arguments.Skip(2).Select(x => x.Text));
        Assert.Equal(["rdi"], calls[1].Arguments.Select(x => x.Location));
    }

    [Fact]
    public void Small_structs_take_two_registers_of_their_class()
    {
        // cpow(z1, z2): each double _Complex in two xmm registers under System V; by reference under Microsoft x64
        uint cpow = Data + 0x10;
        var (index, analysis) = Assemble(a =>
        {
            a.sub(rsp, 8);
            for (int k = 0; k < 4; k++)
            {
                a.mov(rax, BitConverter.DoubleToInt64Bits(k + 1.0));
                a.AddInstruction(Instruction.Create(Iced.Intel.Code.Movq_xmm_rm64, Register.XMM0 + k, Register.RAX));
            }
            a.AddInstruction(CallSlot(cpow));
            a.add(rsp, 8);
            a.ret();
        }, null, new NativeImport("libm.so.6", "cpow", null, 0, cpow, false));
        var call = Assert.Single(analysis.CallsIn(index.FunctionByStart(Code)!));
        Assert.Equal(["xmm0:xmm1", "xmm2:xmm3"], call.Arguments.Select(x => x.Location));
        Assert.Equal(["{1, 2}", "{3, 4}"], call.Arguments.Select(x => x.Text));

        var cabs = new ApiParam("z", ApiParamType.FloatPair);
        var pair = new ApiParam("s", ApiParamType.IntPair);
        var n = new ApiParam("n", ApiParamType.Int);
        // integer pairs take two of rdi..r9, or two stack slots once fewer than two are left; the next integer still takes a register
        Assert.Equal(["rdi", "rsi:rdx", "rcx:r8", "[rsp+0h]:[rsp+8h]", "r9", "xmm0:xmm1"],
            X64Abi.SystemV.Assign([n, pair, pair, pair, n, cabs], int.MaxValue, tail: false).Select(x => x.Label));
        Assert.Equal(["rcx", "rdx"], X64Abi.Microsoft.Assign([cabs, cabs], int.MaxValue, tail: false).Select(x => x.Label));
        Assert.Equal(["rsi", "xmm0:xmm1"], X64Abi.SystemV.Assign([n, cabs], int.MaxValue, tail: false, structReturn: true).Select(x => x.Label));
    }

    [Fact]
    public void Entry_locations_map_to_parameter_positions()
    {
        var (index, analysis) = Build(ImageFormat.Elf);
        var slices = analysis.Slices;
        Assert.Equal(0, slices.ParameterIndex(Loc.Of(Register.RDI)));
        Assert.Equal(5, slices.ParameterIndex(Loc.Of(Register.R9)));
        Assert.Equal(7, slices.ParameterIndex(Loc.Of(Register.XMM7)));
        Assert.Equal(6, slices.ParameterIndex(Loc.Stack(8)));
        Assert.Equal("[rsp+10h]", slices.LocationName(slices.ParameterEntry(7)));
        Assert.Equal("xmm2", slices.LocationName(slices.ParameterEntry(2, isFloat: true)));

        // the helper's parameters come from the caller's rdi and rsi
        var helper = index.Functions.Single(f => f.Start != Code);
        var incoming = NativeFunctionTools.IncomingParameters(index, helper, default);
        Assert.Equal([(0, "rdi"), (1, "rsi")], incoming);
    }

    [Fact]
    public void Real_libraries_name_late_bound_functions_and_pass_arguments_in_system_v_registers()
    {
        var mac = NativeCodeIndex.Build(NativeImageLoader.Open(NativeFixtures.OsxX64DbgShim));
        var macCalls = CallAnalysis.For(mac);
        var names = macCalls.DynamicImports().Imports.Select(d => d.Name).ToHashSet();
        Assert.Contains("CoreCLRCreateCordbObject3", names); // through the statically linked GetProcAddress
        Assert.Contains("PAL_RegisterModule", names); // dlsym, imported as _dlsym

        var linux = NativeCodeIndex.Build(NativeImageLoader.Open(NativeFixtures.LinuxX64DbgShim));
        var dlsym = linux.Image.Imports.First(i => i.Name == "dlsym");
        var sites = CallAnalysis.For(linux).CallsTo(dlsym);
        Assert.NotEmpty(sites);
        Assert.All(sites, s => Assert.Equal(["rdi", "rsi"], s.Arguments.Select(a => a.Location)));
        Assert.Contains(sites, s => s.Arguments[1].Text == "\"PAL_RegisterModule\"");
    }

    [Fact]
    public async Task A_callee_named_without_the_mach_o_underscore_is_found()
    {
        using var dir = new TempDir();
        var options = new ServerOptions { BackgroundIndexing = false };
        using var ws = new AssemblyWorkspace(options);
        var code = new NativeCodeService(ws, options, null, new AnnotationStore(dir.File("ann")));
        var collector = Corvus.Mcp.ToolOutput.Collect();
        await new NativeCallTools(ws, code).GetCallArguments(NativeFixtures.OsxX64DbgShim, callee: "dlsym");
        var report = Assert.IsType<NativeCallTools.CallArgumentsReport>(collector.Value);
        Assert.True(report.Total > 0);
        Assert.Equal("calls to _dlsym", report.Scope);
    }

    [Fact]
    public async Task The_dossier_reads_system_v_argument_registers()
    {
        using var dir = new TempDir();
        var options = new ServerOptions { BackgroundIndexing = false };
        using var ws = new AssemblyWorkspace(options);
        var code = new NativeCodeService(ws, options, null, new AnnotationStore(dir.File("ann")));
        var tools = new NativeFunctionTools(ws, code, new OutputPager(options));
        var text = await tools.AnalyzeNativeFunction(NativeFixtures.LinuxX64DbgShim, "RegisterForRuntimeStartup", sections: "signature");
        // a wrapper that passes the pid (rdi) on unchanged and reads the other three
        Assert.Contains("parameters read at entry: 2 (rsi), 3 (rdx), 4 (rcx)", text);
        Assert.Contains("argument registers read before written: rcx, rdx, rsi", text);
    }
}
