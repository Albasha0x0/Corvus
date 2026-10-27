using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;
using Corvus.Services.Simplify;
using static Corvus.Tests.IlLab;

namespace Corvus.Tests;

/// <summary>Minimal inputs from the simplify fuzz test and library sweep, kept as permanent fixtures.</summary>
public sealed class SimplifyRegressionTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static Instruction I(OpCode op, object? operand = null) => operand == null ? op.ToInstruction() : new Instruction(op, operand);

    /// <summary>Regression: a stub for a missing generic reference re-read the body being read ("Recursive locks aren't supported").</summary>
    [Fact]
    public void Missing_generic_reference_does_not_reenter_the_body_being_read()
    {
        var lab = new IlLab("UsesMissing");
        var module = lab.Module;
        var box = new TypeRefUser(module, "Gone", "Box`1", new AssemblyRefUser("Gone", new Version(1, 0, 0, 0)));
        var boxOfInt = new TypeSpecUser(new GenericInstSig(new ClassSig(box), lab.T.Int32));
        var get = new MemberRefUser(module, "Get", MethodSig.CreateStatic(lab.T.Int32), boxOfInt);
        lab.Method("UsesGone", lab.T.Int32, I(OpCodes.Call, get), Ret());
        var zero = Ldc(0);
        lab.Method("Folds", lab.T.Int32, Ldc(1), I(OpCodes.Brfalse, zero), Ldc(2), Ret(), zero, Ret());
        var path = _dir.File("UsesMissing.dll");
        File.WriteAllBytes(path, lab.Write());

        using var workspace = new AssemblyWorkspace(new ServerOptions { BackgroundIndexing = false, WatchFiles = false });
        var asm = workspace.Load(path);
        var methods = workspace.Read(() => asm.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).ToList());
        Assert.Equal(2, methods.Count);
        var changes = workspace.Write(() => new MethodSimplifier(asm.Module, new SimplifyOptions()).Run(methods, default));
        Assert.DoesNotContain(changes, c => c.Rejected != null);
        Assert.Contains(changes, c => c.Method.Name == "Folds" && c.Changed);
    }

    /// <summary>Regression: a leave into the next try block, which ECMA allows, was refused as entering a protected region.</summary>
    [Fact]
    public void Leave_into_the_next_try_block_verifies()
    {
        var lab = new IlLab("BackToBack");
        var exception = lab.Module.CorLibTypes.GetTypeRef("System", "Exception");
        Instruction try1 = I(OpCodes.Nop), handler1 = I(OpCodes.Pop), try2 = Ldc(1), handler2 = I(OpCodes.Pop), end = Ldc(7), skip = I(OpCodes.Nop);
        var method = lab.Method("Run", lab.T.Int32, [],
        [
            try1, I(OpCodes.Leave, try2),
            handler1, I(OpCodes.Leave, try2),
            try2, I(OpCodes.Brfalse, skip), I(OpCodes.Nop), skip, I(OpCodes.Leave, end),
            handler2, I(OpCodes.Leave, end),
            end, Ret(),
        ], handlers:
        [
            new ExceptionHandler(ExceptionHandlerType.Catch) { TryStart = try1, TryEnd = handler1, HandlerStart = handler1, HandlerEnd = try2, CatchType = exception },
            new ExceptionHandler(ExceptionHandlerType.Catch) { TryStart = try2, TryEnd = handler2, HandlerStart = handler2, HandlerEnd = end, CatchType = exception },
        ]);

        Assert.NotNull(new BodyGraph(method.Body).Verify(hasReturnValue: true, out var error));
        Assert.Null(error);
        var change = new MethodSimplifier(lab.Module, new SimplifyOptions()).Simplify(method)!;
        Assert.Null(change.Rejected);
        Assert.True(change.Changed);

        method.Body = change.NewBody!;
        using var runner = new LabRunner(lab.Write());
        Assert.Equal(((object?)7, (Exception?)null), runner.Call("Lab.P", "Run"));
    }

    /// <summary>Regression (fuzz seed 468): a conditional branch to its own fall-through crashes the .NET 10 JIT at nested try regions; it now becomes pops.</summary>
    [Fact]
    public void Conditional_branch_to_next_becomes_pops()
    {
        var lab = new IlLab("CondToNext");
        var exception = lab.Module.CorLibTypes.GetTypeRef("System", "Exception");
        Instruction tryStart = Ldc(1), skip = I(OpCodes.Nop), fin = I(OpCodes.Endfinally), handler = I(OpCodes.Pop), end = Ldc(0);
        Instruction leaveOuter = I(OpCodes.Leave, end), leaveInner = I(OpCodes.Leave, leaveOuter);
        var method = lab.Method("Run", lab.T.Int32, [lab.T.Int32],
        [
            I(OpCodes.Ldarg_0), Ldc(1), I(OpCodes.Blt, tryStart), I(OpCodes.Br, tryStart),
            tryStart, I(OpCodes.Brfalse, skip), I(OpCodes.Nop), skip, leaveInner,
            fin,
            leaveOuter,
            handler, I(OpCodes.Leave, end),
            end, Ret(),
        ], handlers:
        [
            new ExceptionHandler(ExceptionHandlerType.Finally) { TryStart = tryStart, TryEnd = fin, HandlerStart = fin, HandlerEnd = leaveOuter },
            new ExceptionHandler(ExceptionHandlerType.Catch) { TryStart = tryStart, TryEnd = handler, HandlerStart = handler, HandlerEnd = end, CatchType = exception },
        ]);

        var change = new MethodSimplifier(lab.Module, new SimplifyOptions()).Simplify(method)!;
        Assert.True(change.Changed);
        var code = change.NewBody!.Instructions;
        for (int i = 0; i + 1 < code.Count; i++)
            Assert.False(code[i].OpCode.FlowControl == FlowControl.Cond_Branch && code[i].Operand == code[i + 1], $"conditional branch to the next instruction at {i}");

        // Checked structurally first: if the shape came back, preparing the method would crash the test process.
        method.Body = change.NewBody;
        using var runner = new LabRunner(lab.Write());
        Assert.Null(runner.Prepare("Lab.P", "Run"));
        Assert.Equal(((object?)0, (Exception?)null), runner.Call("Lab.P", "Run", 0));
        Assert.Equal(((object?)0, (Exception?)null), runner.Call("Lab.P", "Run", 5));
    }

    /// <summary>Regression: a virtual call reached every method of its name; it now reaches same-signature methods of derived types, or any type for an interface.</summary>
    [Fact]
    public void Virtual_calls_reach_only_what_they_can_dispatch_to()
    {
        const string source = """
            public interface IRun { int Run(); }
            public class Base { public virtual int Run() => 1; }
            public class Derived : Base, IRun { }
            public class Unrelated { public virtual int Run() => 3; }
            public static class X { public static readonly int V; static X() { IRun r = new Derived(); V = r.Run(); } }

            public class Base2 { public virtual int M() => 1; }
            public class Sub2 : Base2 { public override int M() => 2; }
            public class Unrelated2 { public virtual int M() => 3; }
            public static class Y { public static readonly int V; static Y() { Base2 b = new Sub2(); V = b.M(); } }
            """;
        using var module = ModuleDefMD.Load(Roslyn.Compile("Dispatch", source,
            new Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions(Microsoft.CodeAnalysis.OutputKind.DynamicallyLinkedLibrary)));
        TypeDef T(string name) => module.Find(name, false)!;
        var facts = new ModuleFacts(module);

        Assert.True(facts.RunsDuringInitialization(T("X"), T("Base").FindMethod("Run")));      // IRun.Run implemented by the inherited Base.Run
        Assert.True(facts.RunsDuringInitialization(T("Y"), T("Sub2").FindMethod("M")));        // the override
        Assert.False(facts.RunsDuringInitialization(T("Y"), T("Unrelated2").FindMethod("M"))); // same name and signature, unrelated type
    }

    /// <summary>Regression: an initializer run inside a failed one kept its mark after the rollback erased its state.</summary>
    [Fact]
    public void Initializations_inside_a_failed_one_are_forgotten_with_it()
    {
        var lab = new IlLab("Rollback");
        var t = lab.T;
        var b = lab.NewType("Lab", "B", abstractSealed: true, beforeFieldInit: false);
        var x = lab.StaticField(b, "X", t.Int32, readOnly: true);
        lab.StaticConstructor(b, Ldc(5), I(OpCodes.Stsfld, x), Ret());
        var a = lab.NewType("Lab", "A", abstractSealed: true, beforeFieldInit: false);
        var y = lab.StaticField(a, "Y", t.Int32, readOnly: true);
        var exists = lab.Module.Import(typeof(File).GetMethod(nameof(File.Exists), [typeof(string)]));
        lab.StaticConstructor(a, I(OpCodes.Ldsfld, x), I(OpCodes.Stsfld, y), I(OpCodes.Ldstr, "x"), I(OpCodes.Call, exists), I(OpCodes.Pop), Ret());

        var touchEnd = Ldc(0);
        var touch = lab.Method("Touch", t.Int32, I(OpCodes.Ldsfld, y), Ldc(0), I(OpCodes.Bgt, touchEnd), Ldc(1), Ret(), touchEnd, Ret());
        var ok = Ldc(1);
        var uses = lab.Method("Uses", t.Int32, I(OpCodes.Ldsfld, x), Ldc(5), I(OpCodes.Beq, ok), Ldc(2), Ret(), ok, Ret());

        var evaluator = new IlEvaluator(lab.Module, new EvaluationLimits());
        Assert.Throws<EvaluationBailout>(() => evaluator.EvaluateSlice([I(OpCodes.Ldsfld, y)]));
        Assert.Equal(5, evaluator.EvaluateSlice([I(OpCodes.Ldsfld, x)]).Single());

        // Through the passes, in that order, with one simplifier: Uses must still return 1.
        var changes = new MethodSimplifier(lab.Module, new SimplifyOptions()).Run([touch, uses], default);
        foreach (var c in changes.Where(c => c.Changed)) c.Method.Body = c.NewBody!;
        using var runner = new LabRunner(lab.Write());
        Assert.Equal(((object?)1, (Exception?)null), runner.Call("Lab.P", "Uses"));
    }

    /// <summary>Regression (fuzz seed 16): a one-endfinally fault handler at the end of the body did not survive dnlib's save; such results are refused.</summary>
    [Fact]
    public void One_instruction_handler_at_the_end_is_refused()
    {
        var lab = new IlLab("FaultAtEnd");
        var ctor = lab.Module.Import(typeof(InvalidOperationException).GetConstructor([typeof(string)]));
        Instruction tryStart = I(OpCodes.Ldstr, "always"), handler = Ldc(1), end = I(OpCodes.Endfinally);
        var method = lab.Method("Run", lab.T.Int32, [],
        [
            tryStart, I(OpCodes.Newobj, ctor), I(OpCodes.Throw),
            handler, I(OpCodes.Brtrue, end), I(OpCodes.Nop), end,
        ], handlers:
        [
            new ExceptionHandler(ExceptionHandlerType.Fault) { TryStart = tryStart, TryEnd = handler, HandlerStart = handler, HandlerEnd = null },
        ]);

        var change = new MethodSimplifier(lab.Module, new SimplifyOptions()).Simplify(method)!;
        Assert.False(change.Changed);
        Assert.Equal(FallbackReason.ResultUnverifiable, change.Rejected?.Reason);
        Assert.Contains("a one-instruction handler ends the body (dnlib reads it back without the handler)", change.Rejected!.Detail);

        // What the refusal guards against: dnlib drops the handler when it reads such a body back.
        var body = method.Body;
        body.Instructions.Clear();
        foreach (var ins in new[] { tryStart, I(OpCodes.Newobj, ctor), I(OpCodes.Throw), end }) body.Instructions.Add(ins);
        body.ExceptionHandlers[0].TryEnd = end;
        body.ExceptionHandlers[0].HandlerStart = end;
        using var module = ModuleDefMD.Load(lab.Write());
        Assert.Empty(module.Find("Lab.P", false)!.FindMethod("Run").Body.ExceptionHandlers);
    }

    /// <summary>Regression: a switch target outside the body crashed the simplifier instead of rejecting the body.</summary>
    [Fact]
    public void A_branch_target_dnlib_could_not_place_is_rejected_not_a_crash()
    {
        var lab = new IlLab("NotIl");
        var ret = Ret();
        var method = lab.Method("Run", lab.T.Int32, [], [Ldc(0), I(OpCodes.Switch, new Instruction?[] { ret, null }), Ldc(1), ret]);
        var change = new MethodSimplifier(lab.Module, new SimplifyOptions()).Run([method], default).Single();
        Assert.Equal(FallbackReason.OriginalUnverifiable, change.Rejected?.Reason);
        Assert.Contains("branch target outside the body", change.Rejected!.Detail);
    }

    /// <summary>With a quarter or more of the bodies unreadable nothing is rewritten; a lone unreadable body does not stop the others.</summary>
    [Theory]
    [InlineData(6, true)]
    [InlineData(1, false)]
    public void Unreadable_bodies_are_not_rewritten(int corrupted, bool refused)
    {
        var lab = new IlLab("Unreadable");
        for (int k = 0; k < 8; k++)
        {
            var zero = Ldc(0);
            lab.Method("M" + k, lab.T.Int32, Ldc(1), I(OpCodes.Brfalse, zero), Ldc(k), Ret(), zero, Ret());
        }
        var image = lab.Write();
        using (var pe = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(image)))
        {
            var md = System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe);
            int done = 0;
            foreach (var handle in md.MethodDefinitions)
            {
                var def = md.GetMethodDefinition(handle);
                if (!md.GetString(def.Name).StartsWith('M') || done == corrupted) continue;
                pe.PEHeaders.TryGetDirectoryOffset(new System.Reflection.PortableExecutable.DirectoryEntry(def.RelativeVirtualAddress, 0), out int offset);
                image[offset] = 0x00; // neither a tiny (..10) nor a fat (..11) header
                done++;
            }
            Assert.Equal(corrupted, done);
        }
        var path = _dir.File($"Unreadable{corrupted}.dll");
        File.WriteAllBytes(path, image);
        using var env = new Env(path);
        var asm = env.One("Lab.P::M7").Assembly;
        var report = env.Edit(() => env.Edits.SimplifyMethods(asm, null, SimplifyOptions.Parse(null, null, null), false, default));
        Assert.DoesNotContain("[unexpected]", report);
        if (refused)
        {
            Assert.Contains("Nothing is rewritten: 6 of 8 method bodies", report);
            Assert.Contains("[unreadable-bodies]", report);
            Assert.Empty(env.Fixture.Edits);
        }
        else
        {
            Assert.DoesNotContain("unreadable-bodies", report);
            Assert.Contains("7 of 8 method(s) changed", report);
        }
    }
}
