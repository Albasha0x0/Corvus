using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;
using dnlib.DotNet.Writer;
using dnlib.PE;
using Corvus.Core;
using Corvus.Services.Simplify;
using static Corvus.Tests.IlLab;

namespace Corvus.Tests;

/// <summary>x86 integer code in native method bodies (<see cref="NativeRoutine"/>) runs on concrete values; anything else declines with native-code.</summary>
public sealed class SimplifyNativeTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>The routine shape a post-build tool emits: save registers, tell 32- from 64-bit by three pushes, compute, restore and return.</summary>
    private static byte[] ToolShaped(params byte[] body) =>
    [
        0x89, 0xE0, 0x53, 0x57, 0x56, 0x29, 0xE0, 0x83, 0xF8, 0x18, 0x74, 0x07, 0x8B, 0x44, 0x24, 0x10, 0x50, 0xEB, 0x01, 0x51,
        .. body,
        0x5E, 0x5F, 0x5B, 0xC3,
    ];

    // pop ecx; xor ecx, 0x1234; imul ecx, ecx, 7; add ecx, 5; neg ecx; not ecx; mov eax, ecx
    private static readonly byte[] KeyBody =
        [0x59, 0x81, 0xF1, 0x34, 0x12, 0x00, 0x00, 0x69, 0xC9, 0x07, 0x00, 0x00, 0x00, 0x81, 0xC1, 0x05, 0x00, 0x00, 0x00, 0xF7, 0xD9, 0xF7, 0xD1, 0x89, 0xC8];

    private static int Key(int x) => unchecked(~-((x ^ 0x1234) * 7 + 5));

    private static int Run(byte[] code, params int[] args) => NativeRoutine.Run(code, args, () => { });

    [Theory]
    [InlineData(0)]
    [InlineData(41)]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    public void A_generated_key_routine_computes_its_key(int x) => Assert.Equal(Key(x), Run(ToolShaped(KeyBody), x));

    [Fact]
    public void A_frame_pointer_routine_with_two_arguments_and_a_branch_runs()
    {
        // push ebp; mov ebp, esp; mov eax, [ebp+8]; sub eax, [ebp+12]; jge +2; neg eax; shl eax, 3; sar eax, 1; lea eax, [eax+eax*2+1]; pop ebp; ret 8
        byte[] code =
        [
            0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x2B, 0x45, 0x0C, 0x7D, 0x02, 0xF7, 0xD8, 0xC1, 0xE0, 0x03, 0xD1, 0xF8,
            0x8D, 0x44, 0x40, 0x01, 0x5D, 0xC2, 0x08, 0x00,
        ];
        foreach (var (a, b) in new[] { (10, 3), (3, 10), (-5, 7), (0, 0) })
            Assert.Equal(Math.Abs(a - b) * 4 * 3 + 1, Run(code, a, b));
    }

    [Fact]
    public void Loops_run_within_the_budget()
    {
        // mov eax, [esp+4]; xor ecx, ecx; L: add ecx, eax; dec eax; jnz L; mov eax, ecx; ret  (sum 1..n)
        byte[] code = [0x8B, 0x44, 0x24, 0x04, 0x31, 0xC9, 0x01, 0xC1, 0x48, 0x75, 0xFB, 0x89, 0xC8, 0xC3];
        Assert.Equal(5050, Run(code, 100));
        int ticks = 0;
        Assert.Throws<BudgetDone>(() => NativeRoutine.Run(code, [1_000_000], () => { if (++ticks > 1000) throw new BudgetDone(); }));
    }

    private sealed class BudgetDone : Exception;

    [Theory]
    [InlineData(new byte[] { 0x8B, 0x44, 0x24, 0x04, 0xF7, 0xF1, 0xC3 }, "F7 /6")] // div ecx
    [InlineData(new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3 }, "E8")] // call
    [InlineData(new byte[] { 0x8B, 0x05, 0x00, 0x10, 0x40, 0x00, 0xC3 }, "absolute address")] // mov eax, [0x401000]
    [InlineData(new byte[] { 0x89, 0xD8, 0xC3 }, "depends on registers")] // mov eax, ebx: the caller's ebx
    [InlineData(new byte[] { 0x85, 0xDB, 0x74, 0x00, 0xC3 }, "branches on a flag")] // test ebx, ebx; je
    [InlineData(new byte[] { 0x8B, 0x44, 0x24, 0x08, 0xC3 }, "outside its stack frame")] // the second argument of a one-argument routine
    [InlineData(new byte[] { 0x50, 0x31, 0xC0, 0xC3 }, "esp not at the return address")] // push eax; xor eax, eax; ret
    [InlineData(new byte[] { 0x66, 0x31, 0xC0, 0xC3 }, "66")] // operand-size prefix
    [InlineData(new byte[] { 0x31, 0xC0 }, "runs past the code")]
    public void Code_outside_the_subset_is_declined(byte[] code, string expected)
    {
        var declined = Assert.Throws<NativeRoutine.Declined>(() => Run(code, 5));
        Assert.Contains(expected, declined.Message);
    }

    [Fact]
    public void XOR_of_a_register_with_itself_is_zero_whatever_it_held() => Assert.Equal(0, Run([0x31, 0xDB, 0x89, 0xD8, 0xC3], 5));


    /// <summary>A module whose native Lab.P::Key runs <paramref name="code"/>; Lab.P::Folds returns 1 when Key(41) gives the expected key, else 2.</summary>
    private string NativeModule(byte[] code, bool x86 = true)
    {
        var lab = new IlLab(x86 ? "Native32" : "NativeAny");
        var native = new MethodDefUser("Key", MethodSig.CreateStatic(lab.T.Int32, lab.T.Int32),
            MethodImplAttributes.Native | MethodImplAttributes.Unmanaged | MethodImplAttributes.PreserveSig,
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl | MethodAttributes.HideBySig);
        lab.Type.Methods.Add(native);
        var other = Ldc(2);
        lab.Method("Folds", lab.T.Int32, Ldc(41), new Instruction(OpCodes.Call, native), Ldc(Key(41)), new Instruction(OpCodes.Bne_Un, other),
            Ldc(1), Ret(), other, Ret());
        if (x86)
        {
            lab.Module.Machine = Machine.I386;
            lab.Module.Cor20HeaderFlags = ComImageFlags.Bit32Required;
        }

        // The body goes in with the IL bodies; its RVA is set once the writer has placed it.
        var options = new ModuleWriterOptions(lab.Module);
        dnlib.DotNet.Writer.MethodBody? chunk = null;
        options.WriterEvent += (sender, e) =>
        {
            var writer = (ModuleWriterBase)sender!;
            if (e.Event == ModuleWriterEvent.MDEndWriteMethodBodies) chunk = writer.MethodBodies.Add(new dnlib.DotNet.Writer.MethodBody(code));
            else if (e.Event == ModuleWriterEvent.EndCalculateRvasAndFileOffsets)
            {
                uint rid = writer.Metadata.GetRid(native);
                var row = writer.Metadata.TablesHeap.MethodTable[rid];
                writer.Metadata.TablesHeap.MethodTable[rid] = new RawMethodRow((uint)chunk!.RVA, row.ImplFlags, row.Flags, row.Name, row.Signature, row.ParamList);
            }
        };
        var path = _dir.File(lab.Module.Name);
        lab.Module.Write(path, options);
        return path;
    }

    [Fact]
    public void Branch_on_a_native_routine_folds()
    {
        using var module = ModuleDefMD.Load(NativeModule(ToolShaped(KeyBody)));
        var change = new MethodSimplifier(module, new SimplifyOptions()).Simplify(module.Find("Lab.P", false)!.FindMethod("Folds"))!;
        Assert.Null(change.Rejected);
        Assert.Equal(1, change.ConstantBranches);
        var code = change.NewBody!.Instructions;
        Assert.DoesNotContain(code, i => i.OpCode.FlowControl is FlowControl.Call or FlowControl.Cond_Branch);
        Assert.Equal([1], code.Where(i => i.IsLdcI4()).Select(i => i.GetLdcI4Value()));
    }

    /// <summary>What evaluating Key(41) of the module stops with.</summary>
    private static EvaluationBailout Declines(string path)
    {
        using var module = ModuleDefMD.Load(path);
        var key = module.Find("Lab.P", false)!.FindMethod("Key");
        return Assert.Throws<EvaluationBailout>(() => new IlEvaluator(module, new EvaluationLimits()).EvaluateSlice([Ldc(41), new Instruction(OpCodes.Call, key)]));
    }

    [Fact]
    public void Native_code_of_an_image_that_may_run_as_64_bit_is_not_run()
    {
        var bail = Declines(NativeModule(ToolShaped(KeyBody), x86: false));
        Assert.Equal(FallbackReason.NativeCode, bail.Reason);
        Assert.Contains("32-bit x86 process", bail.Message);
    }

    [Fact]
    public void Native_code_outside_the_subset_is_reported_with_its_offset()
    {
        var bail = Declines(NativeModule(ToolShaped(0x59, 0xF7, 0xF1, 0x89, 0xC8))); // pop ecx; div ecx
        Assert.Equal(FallbackReason.NativeCode, bail.Reason);
        Assert.Contains("F7 /6 at +0x15", bail.Message);
    }
}
