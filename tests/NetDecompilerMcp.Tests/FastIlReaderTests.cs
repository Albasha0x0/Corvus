using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

/// <summary>The fast System.Reflection.Metadata decoder must agree with dnlib's own body reader on every method.</summary>
public class FastIlReaderTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MatchesDnlibOnEveryMethod(bool largeRealAssembly)
    {
        using var env = new Env(largeRealAssembly ? typeof(ModuleDefMD).Assembly.Location : null);
        int methods = 0;
        foreach (var method in env.Fixture.Module.GetTypes().SelectMany(t => t.Methods))
        {
            var reference = MetadataUtil.SafeBody(method);
            var fast = FastIlReader.Read(env.Fixture, method);
            if (reference == null)
            {
                Assert.Null(fast);
                continue;
            }
            Assert.NotNull(fast);
            methods++;
            Assert.Equal(reference.Instructions.Count, fast!.Instructions.Count);
            for (int i = 0; i < reference.Instructions.Count; i++)
            {
                var expected = reference.Instructions[i];
                var actual = fast.Instructions[i];
                Assert.Equal(expected.Offset, actual.Offset);
                Assert.Equal(expected.OpCode, actual.OpCode);
                Assert.Equal(Describe(expected), Describe(actual));
            }
            Assert.Equal(reference.Variables.Select(v => v.Type.FullName), fast.LocalTypes.Select(t => t.FullName));
            Assert.Equal(reference.ExceptionHandlers.Where(h => h.CatchType != null).Select(h => h.CatchType.FullName), fast.Catches.Select(c => c.CatchType.FullName));
        }
        Assert.True(methods > (largeRealAssembly ? 5_000 : 30), $"only {methods} bodies compared");
    }

    /// <summary>Operand identity independent of representation (dnlib gives Local/Parameter objects, the fast reader indexes).</summary>
    private static string Describe(Instruction instr) => instr.OpCode.OperandType is OperandType.InlineVar or OperandType.ShortInlineVar
        ? "var " + instr.Operand switch { Local l => l.Index, Parameter p => p.Index, var o => Convert.ToInt32(o) }
        : Describe(instr.Operand);

    private static string Describe(object? operand) => operand switch
    {
        null => "null",
        Instruction target => $"->{target.Offset}",
        Instruction[] targets => "->" + string.Join(",", targets.Select(t => t.Offset)),
        IMDTokenProvider member => $"token {member.MDToken.Raw:X8}",
        string s => $"\"{s}\"",
        _ => $"{operand.GetType().Name} {operand}",
    };

    [Fact]
    public void EditedAssembliesUseTheDnlibModule()
    {
        using var env = new Env();
        env.Edit(() => env.Edits.StubMethod(env.One("Account::Score"), "7"));
        var body = FastIlReader.Read(env.Fixture, env.Def<MethodDef>("Account::Score"));
        Assert.Equal([Code.Ldc_I4, Code.Ret], body!.Instructions.Select(i => i.OpCode.Code).Take(2).Select(c => c == Code.Ldc_I4_7 ? Code.Ldc_I4 : c));
    }
}
