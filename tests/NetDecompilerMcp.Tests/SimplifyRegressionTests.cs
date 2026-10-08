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
}
