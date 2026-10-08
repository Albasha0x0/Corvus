using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services.Simplify;
using static NetDecompilerMcp.Tests.IlLab;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Minimal inputs that misbehaved in the simplify_methods fuzz test or library sweep, kept as permanent fixtures.
/// </summary>
public sealed class SimplifyRegressionTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static Instruction I(OpCode op, object? operand = null) => operand == null ? op.ToInstruction() : new Instruction(op, operand);

    /// <summary>
    /// Sweep (Microsoft.CodeAnalysis.VisualBasic and others): reading a body resolved a member of a generic type from a
    /// missing assembly; the reference stub built for it read every loaded body through dnlib, including the one being
    /// read, and dnlib threw "Recursive locks aren't supported" out of MethodDef.HasBody.
    /// </summary>
    [Fact]
    public void MissingGenericReferenceDoesNotReenterTheBodyBeingRead()
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

    /// <summary>
    /// Fuzz: <c>try {} catch {} try {} ...</c> — the first region's leave targets the first instruction of the next try,
    /// which ECMA allows (and C# emits). The verifier refused it as "leave enters a protected region", so such methods
    /// were reported original-unverifiable and never simplified.
    /// </summary>
    [Fact]
    public void LeaveIntoTheNextTryBlockVerifies()
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

    /// <summary>
    /// Fuzz seed 468: folding a constant branch at the start of two nested try regions and dropping <c>br L</c> left
    /// <c>blt L; L:</c>, a conditional branch whose target is its own fall-through. Valid IL, but it crashes the .NET 10
    /// JIT (access violation) when L starts nested try regions. Such branches now become pops.
    /// </summary>
    [Fact]
    public void ConditionalBranchToNextBecomesPops()
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

    /// <summary>
    /// Real application (RebornBuddy): virtual calls were taken to reach every method of the same name, and obfuscators
    /// give hundreds of unrelated methods the same short names, so nearly every method seemed able to run during every
    /// type initializer and no static state could be used. A virtual call now reaches the methods of its name and
    /// signature in the types deriving from the class it names, and in any type for an interface (an interface method
    /// may be implemented by a method inherited from a base class that lists no interface).
    /// </summary>
    [Fact]
    public void VirtualCallsReachOnlyWhatTheyCanDispatchTo()
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
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Where(p => p.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)).Select(p => Microsoft.CodeAnalysis.MetadataReference.CreateFromFile(p));
        var compilation = Microsoft.CodeAnalysis.CSharp.CSharpCompilation.Create("Dispatch", [Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree.ParseText(source)], references,
            new Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions(Microsoft.CodeAnalysis.OutputKind.DynamicallyLinkedLibrary));
        using var ms = new MemoryStream();
        Assert.True(compilation.Emit(ms).Success);
        using var module = ModuleDefMD.Load(ms.ToArray());
        TypeDef T(string name) => module.Find(name, false)!;
        var facts = new ModuleFacts(module);

        Assert.True(facts.RunsDuringInitialization(T("X"), T("Base").FindMethod("Run")));      // IRun.Run implemented by the inherited Base.Run
        Assert.True(facts.RunsDuringInitialization(T("Y"), T("Sub2").FindMethod("M")));        // the override
        Assert.False(facts.RunsDuringInitialization(T("Y"), T("Unrelated2").FindMethod("M"))); // same name and signature, unrelated type
    }

    /// <summary>
    /// Real application (RebornBuddy): a type initializer that ran inside another one whose evaluation then failed kept
    /// its "initialized" mark while the failed one's rollback erased its static state, so later reads saw default values:
    /// B.X (set to 5 by B's initializer, run from A's) read back as 0 and a branch on it folded the wrong way.
    /// </summary>
    [Fact]
    public void InitializationsInsideAFailedOneAreForgottenWithIt()
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

    /// <summary>
    /// Fuzz seed 16: simplifying a method that always throws left a fault handler of one endfinally at the very end of
    /// the body. Valid IL, but dnlib reads a region ending at the end of the code as ending at the last instruction, so
    /// the saved image read back without the handler. Such results are refused; the method is left unchanged.
    /// </summary>
    [Fact]
    public void OneInstructionHandlerAtTheEndIsRefused()
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
}
