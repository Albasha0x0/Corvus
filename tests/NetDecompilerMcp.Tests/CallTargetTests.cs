using Iced.Intel;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Calls;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Tools;
using static Iced.Intel.AssemblerRegisters;

namespace NetDecompilerMcp.Tests;

/// <summary>resolve_call_targets layers on synthetic x64 code.</summary>
public class CallTargetTests
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;
    private const uint Data = CodeTestImage.SyntheticDataRva;
    private const ulong Base = 0x140000000UL;
    private const uint Sleep = Data, One = Data + 0x40, Two = Data + 0x48, Unknown = Data + 0x50, Table = Data + 0x80;

    private static Instruction StoreRax(uint g) => Instruction.Create(Iced.Intel.Code.Mov_rm64_r64, new MemoryOperand(Register.RIP, (long)(Base + g), 8), Register.RAX);
    private static Instruction LoadRax(uint g) => Instruction.Create(Iced.Intel.Code.Mov_r64_rm64, Register.RAX, new MemoryOperand(Register.RIP, (long)(Base + g), 8));

    private static (CallAnalysis Analysis, Dictionary<string, uint> At) Build()
    {
        var a = new Assembler(64);
        var l = new Dictionary<string, Label>();
        Label L(string name) => l.TryGetValue(name, out var x) ? x : l[name] = a.CreateLabel(name);
        void Mark(string name) { var x = L(name); a.Label(ref x); l[name] = x; }

        a.sub(rsp, 0x28);
        a.call(L("fnA"));
        a.call(L("fnB"));
        a.call(L("fnC"));
        Mark("import");
        a.AddInstruction(Instruction.Create(Iced.Intel.Code.Call_rm64, new MemoryOperand(Register.RIP, (long)(Base + Sleep), 8)));
        a.lea(rax, __[L("fnA")]);
        Mark("register");
        a.call(rax);
        a.lea(rax, __[L("fnA")]);
        a.AddInstruction(StoreRax(One));
        a.AddInstruction(StoreRax(Two));
        a.lea(rax, __[L("fnB")]);
        a.AddInstruction(StoreRax(Two));
        a.mov(rax, rcx);
        a.AddInstruction(StoreRax(Unknown));
        a.AddInstruction(LoadRax(One));
        Mark("one");
        a.call(rax);
        a.AddInstruction(LoadRax(Two));
        Mark("two");
        a.call(rax);
        a.AddInstruction(LoadRax(Unknown));
        Mark("unknown");
        a.call(rax);
        a.AddInstruction(Instruction.Create(Iced.Intel.Code.Lea_r64_m, Register.RDX, new MemoryOperand(Register.RIP, (long)(Base + Table), 8)));
        a.cmp(rcx, 2);
        a.ja(L("skip"));
        Mark("table_call");
        a.call(__qword_ptr[rdx + rcx * 8]);
        Mark("skip");
        a.lea(rcx, __[L("fnB")]);
        a.call(L("helper"));
        a.add(rsp, 0x28);
        a.ret();

        Mark("helper");
        a.sub(rsp, 0x28);
        Mark("parameter");
        a.call(rcx);
        a.add(rsp, 0x28);
        a.ret();

        Mark("fnA"); a.mov(eax, 1); a.ret();
        Mark("fnB"); a.mov(eax, 2); a.ret();
        Mark("fnC"); a.mov(eax, 3); a.ret();

        var stream = new MemoryStream();
        var result = a.Assemble(new StreamCodeWriter(stream), Base + Code, BlockEncoderOptions.ReturnNewInstructionOffsets);
        var at = l.ToDictionary(kv => kv.Key, kv => (uint)(result.GetLabelRIP(kv.Value) - Base));

        var data = new byte[0x100];
        uint[] entries = [at["fnA"], at["fnB"], at["fnC"], at["fnA"]];
        var relocations = new List<uint>();
        for (int k = 0; k < entries.Length; k++)
        {
            BitConverter.GetBytes(Base + entries[k]).CopyTo(data, (int)(Table - Data) + 8 * k);
            relocations.Add(Table + (uint)(8 * k));
        }
        var image = CodeTestImage.Synthetic(NativeArch.X64, stream.ToArray(), data, [new NativeImport("KERNEL32.dll", "Sleep", null, 0, Sleep, false)],
            relocations: relocations, entry: Code);
        return (CallAnalysis.For(NativeCodeIndex.Build(image)), at);
    }

    private static CallTargetSite Site(CallAnalysis a, uint rva, bool deep = false) => CallTargets.At(a, rva, deep) ?? throw new InvalidOperationException("no site");

    [Fact]
    public void Direct_import_and_constant_register_calls()
    {
        var (a, at) = Build();
        var direct = CallTargets.In(a, a.Index.FunctionByStart(Code)!, deep: false).First();
        Assert.Equal(("direct", "direct"), (direct.Mechanism, direct.Status));
        var import = Site(a, at["import"]);
        Assert.Equal(("import_slot", "import"), (import.Mechanism, import.Status));
        Assert.EndsWith("Sleep", import.Targets.Single().Name);
        var register = Site(a, at["register"]);
        Assert.Equal(("register", "resolved"), (register.Mechanism, register.Status));
        Assert.Equal(at["fnA"], register.Targets.Single().Address);
        Assert.Equal("constant_pointer", register.Targets.Single().Basis);
    }

    [Fact]
    public void Global_function_pointers_resolve_through_their_writers()
    {
        var (a, at) = Build();
        var one = Site(a, at["one"]);
        Assert.Equal("resolved", one.Status);
        Assert.Equal(("global_writers", "exact"), (one.Targets.Single().Basis, one.Targets.Single().Confidence));

        var two = Site(a, at["two"]);
        Assert.Equal("possible", two.Status);
        Assert.Equal([at["fnA"], at["fnB"]], two.Targets.Select(t => t.Address).Order());
        Assert.All(two.Targets, t => Assert.Equal("possible", t.Confidence));

        var unknown = Site(a, at["unknown"]);
        Assert.Equal("unresolved", unknown.Status);
        Assert.Contains("written by 1 stores, 1 unknown", unknown.Reason);
        Assert.StartsWith("trace_native_values address=0x", unknown.Hint);
    }

    [Fact]
    public void Pointer_table_is_cut_at_its_index_bound()
    {
        var (a, at) = Build();
        var s = Site(a, at["table_call"]);
        Assert.Equal(("pointer_table", "resolved"), (s.Mechanism, s.Status));
        Assert.Equal(3, s.TargetCount);
        Assert.All(s.Targets, t => Assert.Equal(("pointer_table", "exact"), (t.Basis, t.Confidence)));
    }

    [Fact]
    public void Deep_follows_a_parameter_into_its_callers()
    {
        var (a, at) = Build();
        var shallow = Site(a, at["parameter"]);
        Assert.Equal("unresolved", shallow.Status);
        Assert.Equal($"trace_native_values address=0x{Base + at["parameter"]:X} location=rcx", shallow.Hint);
        var deep = Site(a, at["parameter"], deep: true);
        Assert.Equal("resolved", deep.Status);
        Assert.Equal((at["fnB"], "caller_argument", "exact"), (deep.Targets.Single().Address, deep.Targets.Single().Basis, deep.Targets.Single().Confidence));
    }

    [Fact]
    public void Image_scope_lists_indirect_sites_only()
    {
        var (a, at) = Build();
        var sites = CallTargets.Image(a, deep: false);
        Assert.All(sites, s => Assert.True(s.IsIndirect));
        Assert.Contains(sites, s => s.Rva == at["unknown"] && s.Status == "unresolved");
        Assert.Contains(sites, s => s.Rva == at["parameter"] && s.Status == "unresolved");
        Assert.Same(sites, CallTargets.Image(a, deep: false));
    }

    [Fact]
    public void Ida_rows_are_merged_and_a_disagreement_is_ambiguous()
    {
        var (a, at) = Build();
        var one = Site(a, at["one"]);
        var agree = NativeCallTargetTools.Merge(a.Index, one, [new NativeCallTarget(one.Rva, "xref", at["fnA"], null, null)]);
        Assert.Equal("resolved", agree.Status);
        var disagree = NativeCallTargetTools.Merge(a.Index, one, [new NativeCallTarget(one.Rva, "direct", at["fnC"], null, null)]);
        Assert.Equal("ambiguous", disagree.Status);
        Assert.Contains(disagree.Targets, t => t.Basis == "hexrays_direct" && t.Address == at["fnC"]);
        var unresolved = NativeCallTargetTools.Merge(a.Index, Site(a, at["parameter"]), [new NativeCallTarget(at["parameter"], "xref", at["fnB"], null, null)]);
        Assert.Equal("possible", unresolved.Status);
        Assert.Equal("ida_xref", unresolved.Targets.Single().Basis);
    }
}
