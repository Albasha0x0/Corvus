using System.Runtime.Loader;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Corvus.Core;
using Corvus.Services.Simplify;
using SymbolKind = Corvus.Core.SymbolKind;

namespace Corvus.Tests;

/// <summary>
/// simplify_methods: string folding by IL evaluation, control-flow cleanup and forwarder inlining. Fixtures are compiled
/// in memory (C#) or built with dnlib; simplified images are executed next to the originals to check they still load,
/// JIT-compile and compute the same results.
/// </summary>
public sealed class SimplifyTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const string ObfSource = """
        using System;
        using System.IO;
        using System.Text;

        namespace Obf
        {
            public static class Strings
            {
                // "Hello, World!" + "secret-key", XOR 0x5A
                private static readonly byte[] Data =
                {
                    0x12, 0x3F, 0x36, 0x36, 0x35, 0x76, 0x7A, 0x0D, 0x35, 0x28, 0x36, 0x3E, 0x7B,
                    0x29, 0x3F, 0x39, 0x28, 0x3F, 0x2E, 0x77, 0x31, 0x3F, 0x23,
                };

                public static string Get(int offset, int length)
                {
                    var chars = new char[length];
                    for (int i = 0; i < length; i++) chars[i] = (char)(Data[offset + i] ^ 0x5A);
                    return new string(chars);
                }

                public static string Built()
                {
                    var sb = new StringBuilder();
                    for (int i = 0; i < 5; i++) sb.Append((char)('a' + i * 2));
                    sb.Append('-');
                    sb.Append(Encoding.UTF8.GetString(Convert.FromBase64String("b2s=")));
                    return sb.ToString();
                }

                public static string Calc(int v)
                {
                    long wide = v;
                    ulong zero = (uint)v;
                    int high = (int)(zero >> 28);
                    int rem = v % 3;
                    double d = v / 2.0;
                    var sb = new StringBuilder();
                    sb.Append((char)('A' + high));
                    sb.Append((char)('m' + rem));
                    sb.Append(d < 0 ? 'n' : 'p');
                    sb.Append((char)('0' + (int)((ulong)wide >> 62)));
                    return sb.ToString();
                }

                public static string Greeting() => Get(0, 13);
                public static string UseAll() => Greeting() + "|" + Get(13, 10) + Built();
                public static string CalcUse() => Calc(-1);
            }

            public static class App
            {
                public static string Title() => Strings.Get(0, 5);
                public static string Config() => Io.ReadConfig();
            }

            public static class Io
            {
                public static string ReadConfig() => File.ReadAllText("settings-that-does-not-exist.ini");
            }

            public static class Deep
            {
                public static string D1() => D2() + "1";
                public static string D2() => D3() + "2";
                public static string D3() => D4() + "3";
                public static string D4() => D5() + "4";
                public static string D5() => D6() + "5";
                public static string D6() => "6";
                public static string Top() => D1();
            }

            public static class Spin
            {
                public static string Forever()
                {
                    int i = 0;
                    while (true)
                    {
                        i++;
                        if (i < 0) return "wrapped";
                    }
                }

                public static string Use() => Forever();
            }

            public static class Counter
            {
                private static int _n;
                public static string Next() { _n++; return "n"; }
                public static string Use() => Next();
            }

            public class Real
            {
                private readonly int _k = 3;
                public static int Add(int a, int b) => a + b;
                public int Scale(int x) => x * _k;
                private static int Secret(int x) => x * 7;
                public static int Exposed(int x) => Secret(x);
            }

            public static class Fwd
            {
                public static int AddW(int a, int b) => Real.Add(a, b);
                public static int AddWW(int a, int b) => AddW(a, b);
                public static int ScaleW(Real r, int x) => r.Scale(x);
                public static Real Make() => new Real();
            }

            public class Shape
            {
                public virtual int Area(int x) => Real.Add(x, x);
            }

            public sealed class Box
            {
                public int Inner(int x) => Compute(x);
                internal int Compute(int x) => x + 40;
            }

            public static class Noisy
            {
                public static int Initialized;
                static Noisy() { Initialized = 1; }
                public static int AddN(int a, int b) => Real.Add(a, b);
            }

            public static class SelfInit
            {
                private static readonly string Prefix;
                public static readonly string Name;
                static SelfInit()
                {
                    Name = Join();
                    Prefix = "p";
                }
                private static string Join() => (Prefix ?? "none") + "-x";
                public static string GetName() => Name;
            }

            public static class Callers
            {
                public static int UseNoisy() => Noisy.AddN(1, 2);

                public static int Use()
                {
                    var r = new Real();
                    return Fwd.AddW(1, 2) + Fwd.ScaleW(r, 4) + Fwd.AddWW(5, 6) + new Box().Inner(2) + new Shape().Area(3)
                         + Real.Exposed(2) + Fwd.Make().Scale(1);
                }
            }
        }
        """;

    /// <summary>Flattened control flow as C#: a loop over a switch on a state variable.</summary>
    private const string FlatSource = """
        namespace Flat
        {
            public static class Steps
            {
                public static int Run(int x)
                {
                    int state = 0;
                    int acc = x;
                    while (true)
                    {
                        switch (state)
                        {
                            case 0: acc += 3; state = 2; break;
                            case 1: return acc;
                            case 2: acc *= 5; state = acc > 50 ? 3 : 1; break;
                            case 3: acc -= 7; state = 1; break;
                            default: return -1;
                        }
                    }
                }

                // Case 0 computes the next state at run time; the other transitions are constant.
                public static int Dynamic(int x)
                {
                    int state = x & 1;
                    while (true)
                    {
                        switch (state)
                        {
                            case 0: x += 10; state = x & 3; break;
                            case 1: return x;
                            case 2: x *= 2; state = 3; break;
                            default: x--; state = 1; break;
                        }
                    }
                }
            }
        }
        """;

    private string FlatFixture()
    {
        var path = _dir.File("Flat.dll");
        if (!File.Exists(path)) File.WriteAllBytes(path, CompileRelease("Flat", FlatSource));
        return path;
    }

    private string ObfFixture()
    {
        var path = _dir.File("Obf.dll");
        if (!File.Exists(path)) File.WriteAllBytes(path, CompileRelease("Obf", ObfSource));
        return path;
    }

    private static SimplifyOptions Options(string? passes = null, int? maxDepth = null, int? budget = null) =>
        SimplifyOptions.Parse(passes, maxDepth, budget);

    private static string Simplify(Env env, string symbol, SimplifyOptions? options = null, bool dryRun = false)
    {
        var sym = env.One(symbol);
        return dryRun
            ? env.Workspace.Read(() => env.Edits.SimplifyMethods(sym.Assembly, sym, options ?? Options(), true, default))
            : env.Edit(() => env.Edits.SimplifyMethods(sym.Assembly, sym, options ?? Options(), false, default));
    }

    private static List<Instruction> Body(Env env, string method) => env.Def<MethodDef>(method, SymbolKind.Method).Body.Instructions.ToList();

    private static string Il(Env env, string method) => string.Join("\n", Body(env, method));

    // ---- 1. evaluation engine

    [Fact]
    public void StringBuildingHelperFoldsToKnownConstant()
    {
        using var env = new Env(ObfFixture());
        var report = Simplify(env, "Obf.Strings::UseAll");

        Assert.Contains("folded Obf.Strings::Greeting() -> \"Hello, World!\"", report);
        Assert.Contains("folded Obf.Strings::Get(int, int) -> \"secret-key\"", report);
        Assert.Contains("folded Obf.Strings::Built() -> \"acegi-ok\"", report);
        var code = Body(env, "Obf.Strings::UseAll");
        Assert.Equal(["ldstr", "ret"], code.Select(i => i.OpCode.Name));
        Assert.Equal("Hello, World!|secret-keyacegi-ok", code[0].Operand);
        Assert.Equal(code[0].Operand, Run(env.Fixture.OriginalBytes, "Obf.Strings", "UseAll"));
        Assert.Contains("return \"Hello, World!|secret-keyacegi-ok\";", env.Decompile("Obf.Strings::UseAll"));
    }

    [Fact]
    public void IntegerAndFloatSemanticsMatchTheRuntime()
    {
        using var env = new Env(ObfFixture());
        Simplify(env, "Obf.Strings::CalcUse");
        var code = Body(env, "Obf.Strings::CalcUse");
        Assert.Equal(Code.Ldstr, code[0].OpCode.Code);
        Assert.Equal(Run(env.Fixture.OriginalBytes, "Obf.Strings", "CalcUse"), code[0].Operand);
    }

    [Fact]
    public void CallSitesInOtherTypesFoldAndTheHelperStays()
    {
        using var env = new Env(ObfFixture());
        Simplify(env, "Obf.App");
        Assert.Equal("Hello", Body(env, "Obf.App::Title")[0].Operand);
        Assert.Contains(Body(env, "Obf.Strings::Get"), i => i.OpCode.Code == Code.Ldsfld); // helpers are not rewritten
    }

    [Fact]
    public void NestedCallsFoldUpToTheDepthCapAndBailBeyondIt()
    {
        // Top() -> D1() -> ... -> D6(): evaluating the call in Top needs 6 frames.
        using (var env = new Env(ObfFixture()))
        {
            var report = Simplify(env, "Obf.Deep::Top", Options(maxDepth: 6));
            Assert.Contains("-> \"654321\"", report);
            Assert.Equal("654321", Body(env, "Obf.Deep::Top")[0].Operand);
        }
        using (var env = new Env(ObfFixture()))
        {
            var before = Il(env, "Obf.Deep::Top");
            var report = Simplify(env, "Obf.Deep::Top", Options(maxDepth: 5));
            Assert.Contains("call depth exceeds the limit of 5", report);
            Assert.Equal(before, Il(env, "Obf.Deep::Top"));
            Assert.Empty(env.Fixture.Edits);
        }
    }

    [Fact]
    public void IoCallsBailOutAndLeaveTheMethodUnchanged()
    {
        using var env = new Env(ObfFixture());
        var config = Il(env, "Obf.App::Config");
        var read = Il(env, "Obf.Io::ReadConfig");

        var report = Simplify(env, "Obf.App::Config", Options("fold"));
        Assert.Contains("0 of 1 method(s) changed", report);
        Assert.Contains("Obf.App::Config() IL_0000 Obf.Io::ReadConfig(): calls System.IO.File::ReadAllText(string): files and the network differ between runs [external-io]", report);
        Assert.Contains("Nothing to simplify", Simplify(env, "Obf.Io::ReadConfig")); // a framework call is not reported

        Assert.Equal(read, Il(env, "Obf.Io::ReadConfig"));
        Assert.Equal(config, Il(env, "Obf.App::Config"));
        Assert.Empty(env.Fixture.Edits);
    }

    [Fact]
    public void BudgetExhaustionAndStaticSideEffectsBailOut()
    {
        using var env = new Env(ObfFixture());
        Assert.Contains("instruction budget of 5,000 exhausted", Simplify(env, "Obf.Spin::Use", Options(budget: 5_000)));
        Assert.Contains("reads mutable static field Obf.Counter::_n", Simplify(env, "Obf.Counter::Use"));
        Assert.Equal(Code.Call, Body(env, "Obf.Spin::Use")[0].OpCode.Code);
        Assert.Equal(Code.Call, Body(env, "Obf.Counter::Use")[0].OpCode.Code);
    }

    // ---- 2. control flow (dnlib-built fixture: the C# compiler would already fold these)

    [Fact]
    public void ConstantBranchesCollapse()
    {
        using var env = new Env(FlowFixture());
        var report = Simplify(env, "Paths.Flow::ConstIf");
        Assert.Contains("folded 2 constant branch(es)", report);
        Assert.Equal(["ldc.i4", "ret"], Body(env, "Paths.Flow::ConstIf").Select(i => i.OpCode.Name));
        Assert.Equal(222, Body(env, "Paths.Flow::ConstIf")[0].GetLdcI4Value());

        Simplify(env, "Paths.Flow::Switch");
        Assert.Equal(20, Body(env, "Paths.Flow::Switch")[0].GetLdcI4Value());
        Assert.Equal(2, Body(env, "Paths.Flow::Switch").Count);
    }

    [Fact]
    public void UnreachableBlocksVanish()
    {
        using var env = new Env(FlowFixture());
        var report = Simplify(env, "Paths.Flow::Dead");
        Assert.Contains("removed 2 unreachable block(s) (7 instructions)", report);
        var code = Body(env, "Paths.Flow::Dead");
        Assert.Equal(6, code.Count);
        Assert.DoesNotContain(code, i => i.OpCode.Code == Code.Ldstr);
    }

    [Fact]
    public void BranchChainsCollapse()
    {
        using var env = new Env(FlowFixture());
        Assert.Contains("collapsed 2 branch chain(s)", Simplify(env, "Paths.Flow::Chain")); // brtrue L1 and L1: br L2 both reach L3 directly
        var code = Body(env, "Paths.Flow::Chain");
        Assert.DoesNotContain(code, i => i.OpCode.Code is Code.Br or Code.Br_S);
        Assert.Equal(6, code.Count);
        Assert.Equal(code[4], code[1].Operand); // brtrue goes straight to the final block
    }

    [Fact]
    public void EmptyTryRegionsAreRemoved()
    {
        using var env = new Env(FlowFixture());
        Assert.Contains("removed 1 exception handler(s)", Simplify(env, "Paths.Flow::Guarded"));
        var guarded = env.Def<MethodDef>("Paths.Flow::Guarded").Body;
        Assert.Empty(guarded.ExceptionHandlers);
        Assert.DoesNotContain(guarded.Instructions, i => i.OpCode.Code == Code.Ldc_I4 && i.GetLdcI4Value() == 100); // dead update removed

        Simplify(env, "Paths.Flow::EmptyFinally");
        Assert.Empty(env.Def<MethodDef>("Paths.Flow::EmptyFinally").Body.ExceptionHandlers);
        Simplify(env, "Paths.Flow::DeadCatch");
        Assert.Equal(["ldc.i4", "ret"], Body(env, "Paths.Flow::DeadCatch").Select(i => i.OpCode.Name));

        // A finally that runs inline must still run: results match the original.
        var image = env.Fixture.GetImageBytes();
        foreach (var (name, args) in FlowCalls)
            Assert.Equal(Run(env.Fixture.OriginalBytes, "Paths.Flow", name, args), Run(image, "Paths.Flow", name, args));
    }

    [Fact]
    public void FlattenedSwitchLoopBecomesSequentialCode()
    {
        using var env = new Env(FlatFixture());
        Assert.Contains("switch", env.Decompile("Flat.Steps::Run"));
        var preview = env.Workspace.Read(() => env.Decompiler.DecompileSimplified(env.Fixture, [env.One("Flat.Steps::Run").Member], new SimplifyOptions(), default));
        Assert.Contains("1 switch dispatcher(s) normalized", preview);
        Assert.DoesNotContain("switch (", preview);

        var report = Simplify(env, "Flat.Steps::Run", Options("cfg"));
        Assert.Contains("normalized 1 switch dispatcher(s) (5 transition(s) go straight to their case)", report);

        var run = env.Def<MethodDef>("Flat.Steps::Run").Body;
        Assert.DoesNotContain(run.Instructions, i => i.OpCode.Code == Code.Switch);
        Assert.DoesNotContain(run.Instructions, i => (i.IsLdloc() || i.IsStloc()) && i.GetLocal(run.Variables).Index == 0);
        var csharp = env.Decompile("Flat.Steps::Run");
        Assert.DoesNotContain("switch", csharp);
        Assert.DoesNotContain("while", csharp);
        Assert.DoesNotContain("return -1", csharp); // the default case is never selected
        Assert.DoesNotContain("state", csharp);

        var image = env.Fixture.GetImageBytes();
        foreach (var x in new[] { 0, 5, 7, 8, 20, -3, int.MaxValue })
            Assert.Equal(Run(env.Fixture.OriginalBytes, "Flat.Steps", "Run", x), Run(image, "Flat.Steps", "Run", x));
    }

    [Fact]
    public void ComputedStateKeepsTheDispatcher()
    {
        // Nothing else in Dynamic simplifies, so keeping the dispatcher leaves the method as it was.
        using var env = new Env(FlatFixture());
        var before = Il(env, "Flat.Steps::Dynamic");
        var report = Simplify(env, "Flat.Steps::Dynamic");
        Assert.Contains("0 of 1 method(s) changed", report);
        Assert.Matches(@"Flat\.Steps::Dynamic\(int\) switch dispatcher at IL_\w{4}: the state on the way into the dispatcher at IL_\w{4} is not known; " +
                       @"the dispatcher is kept \[flattened-shape\]", report);
        Assert.Equal(before, Il(env, "Flat.Steps::Dynamic"));
        Assert.Empty(env.Fixture.Edits);

        var preview = env.Workspace.Read(() => env.Decompiler.DecompileSimplified(env.Fixture, [env.One("Flat.Steps::Dynamic").Member], new SimplifyOptions(), default));
        Assert.Contains("0 of 1 method(s) simplified", preview);
        Assert.Contains("1 switch dispatcher(s) kept", preview);
    }

    [Fact]
    public void KeyedDispatcherEnteredByFallThroughIsNormalized()
    {
        using var env = new Env(FlowFixture());
        var report = Simplify(env, "Paths.Flow::Keyed");
        Assert.Contains("normalized 1 switch dispatcher(s) (3 transition(s) go straight to their case)", report);
        var code = Body(env, "Paths.Flow::Keyed");
        Assert.DoesNotContain(code, i => i.OpCode.Code is Code.Switch or Code.Xor || i.IsLdloc() || i.IsStloc());
        Assert.Equal(15, Run(env.Fixture.GetImageBytes(), "Paths.Flow", "Keyed", 4));
        Assert.Contains("x++;\n\tx *= 3;\n\treturn x;", env.Decompile("Paths.Flow::Keyed").ReplaceLineEndings("\n"));
    }

    [Theory]
    [InlineData("AddressTaken", @"the address of the state local V_0 is taken at IL_\w{4}")]
    [InlineData("Mixed", @"the state on the way into the dispatcher at IL_\w{4} is not known")]
    public void DispatcherOutsideTheCleanFormIsKept(string method, string why)
    {
        using var env = new Env(FlowFixture());
        var report = Simplify(env, "Paths.Flow::" + method);
        Assert.Contains("Not rewritten (the code is kept; the other passes still apply):", report);
        Assert.Matches($@"Paths\.Flow::{method}\(\w*\) switch dispatcher at IL_\w{{4}}: {why}; the dispatcher is kept \[flattened-shape\]", report);
        Assert.Single(Body(env, "Paths.Flow::" + method), i => i.OpCode.Code == Code.Switch);
    }

    [Fact]
    public void PathDependentReadNoDispatcherStoreReachesIsKept()
    {
        // Varies: the case shared by states 1 and 2 reads the state, 1 the first time and 2 the second. The dispatcher
        // stores nothing, so going straight to the cases leaves every store, and that read, as it was.
        using var env = new Env(FlowFixture());
        var report = Simplify(env, "Paths.Flow::Varies");
        Assert.Contains("normalized 1 switch dispatcher(s)", report);
        Assert.DoesNotContain(Body(env, "Paths.Flow::Varies"), i => i.OpCode.Code == Code.Switch);
        var image = env.Fixture.GetImageBytes();
        foreach (var x in new[] { 0, 4, -9 })
            Assert.Equal(Run(env.Fixture.OriginalBytes, "Paths.Flow", "Varies", x), Run(image, "Paths.Flow", "Varies", x));
    }

    [Fact]
    public void DispatcherOutsideTheCleanFormKeepsTheOtherSimplifications()
    {
        // Mixed: the state is read in a case, so its dispatcher stays; the string fold, the forwarder call and the
        // constant branch around it are simplified as in any other method.
        using var env = new Env(FlowFixture());
        var report = Simplify(env, "Paths.Flow::Mixed");
        Assert.Contains("1 of 1 method(s) changed", report);
        Assert.Contains("-> \"ab\"", report);
        Assert.Contains("inlined Paths.Flow::PlainW(int) -> Paths.Flow::Plain(int)", report);
        Assert.Contains("folded 1 constant branch(es)", report);
        Assert.Matches(@"Paths\.Flow::Mixed\(int\) switch dispatcher at IL_\w{4}: the state on the way into the dispatcher at IL_\w{4} is not known; " +
                       @"the dispatcher is kept \[flattened-shape\]", report);

        var code = Body(env, "Paths.Flow::Mixed");
        Assert.Single(code, i => i.OpCode.Code == Code.Switch);
        Assert.DoesNotContain(code, i => i.Operand is IMethod { Name.String: "PlainW" or "Concat" });
        Assert.Contains(code, i => i.OpCode.Code == Code.Ldstr && "ab".Equals(i.Operand));
        Assert.DoesNotContain(code, i => i.IsLdcI4() && i.GetLdcI4Value() == 99); // the branch that skipped it is gone

        var image = env.Fixture.GetImageBytes();
        foreach (var x in new[] { 0, 5, -9 })
            Assert.Equal(Run(env.Fixture.OriginalBytes, "Paths.Flow", "Mixed", x), Run(image, "Paths.Flow", "Mixed", x));
    }

    [Fact]
    public void SwitchOnALocalWithoutALoopIsNotFlattenedCode()
    {
        using var env = new Env(FlowFixture());
        Assert.Contains("Nothing to simplify", Simplify(env, "Paths.Flow::LocalSwitch"));
    }

    [Theory]
    [InlineData("CondEntry", 3)]
    [InlineData("ReadElsewhere", 1)] // case 0 only transitions: the state is run through it
    public void DispatcherOutsideTheCleanFormIsNormalizedPerState(string method, int transitions)
    {
        using var env = new Env(FlowFixture());
        var report = Simplify(env, "Paths.Flow::" + method);
        Assert.Contains($"normalized 1 switch dispatcher(s) ({transitions} transition(s) go straight to their case)", report);
        Assert.DoesNotContain("flattened-shape", report);
        var code = Body(env, "Paths.Flow::" + method);
        Assert.DoesNotContain(code, i => i.OpCode.Code == Code.Switch || i.IsLdloc() || i.IsStloc());
        var image = env.Fixture.GetImageBytes();
        foreach (var x in new[] { 0, 1, 5, -9 })
            Assert.Equal(Run(env.Fixture.OriginalBytes, "Paths.Flow", method, x), Run(image, "Paths.Flow", method, x));
    }

    /// <summary>
    /// Flattening as ConfuserEx emits it, written in C#: the dispatcher switches on <c>(num2 = num ^ K) % 5</c>, and each
    /// case computes the next state from num2 (<c>num = num2 * A ^ B</c>), so no transition stores a constant. The
    /// constants chain the cases: S(c) selects case c, and B(c, d) leads from case c to case d.
    /// </summary>
    private static string ConfusedSource()
    {
        const uint K = 0x9E3779B9, A = 0x2545F491;
        static uint S(int c) => (uint)(c + 5000) ^ K;
        static string B(int from, int to) => "0x" + (unchecked((uint)(from + 5000) * A) ^ S(to)).ToString("X8");
        string Dispatch(string cases) => $$"""
                    uint num = 0x{{S(2):X8}}u;
                    while (true)
                    {
                        uint num2;
                        switch ((num2 = num ^ 0x{{K:X8}}u) % 5u)
                        {
            {{cases}}
                        }
                    }
            """;
        return $$"""
            namespace Confused
            {
                public static class C
                {
                    // 2 -> 0 -> 3 -> 1 -> 4: ((x + 11) * 3 + 1 ^ 0x55) - 7
                    public static int Chain(int x)
                    {
            {{Dispatch($$"""
                            case 0u: x = x * 3 + 1; num = num2 * 0x{{A:X8}}u ^ {{B(0, 3)}}u; continue;
                            case 1u: x -= 7; num = num2 * 0x{{A:X8}}u ^ {{B(1, 4)}}u; continue;
                            case 2u: x += 11; num = num2 * 0x{{A:X8}}u ^ {{B(2, 0)}}u; continue;
                            case 3u: x ^= 0x55; num = num2 * 0x{{A:X8}}u ^ {{B(3, 1)}}u; continue;
                            default: return x;
            """)}}
                    }

                    // 2 -> 0 -> (x > 10 ? 1 : 3) -> 4: a conditional transition through a shared tail
                    public static int Branchy(int x)
                    {
            {{Dispatch($$"""
                            case 0u: x += 2; num = x > 10 ? num2 * 0x{{A:X8}}u ^ {{B(0, 1)}}u : num2 * 0x{{A:X8}}u ^ {{B(0, 3)}}u; continue;
                            case 1u: x *= 5; num = num2 * 0x{{A:X8}}u ^ {{B(1, 4)}}u; continue;
                            case 2u: x -= 1; num = num2 * 0x{{A:X8}}u ^ {{B(2, 0)}}u; continue;
                            case 3u: x = -x; num = num2 * 0x{{A:X8}}u ^ {{B(3, 4)}}u; continue;
                            default: return x;
            """)}}
                    }

                    // 2 -> 1 -> 1 ... -> 4: case 1 loops on itself, always with the same state
                    public static int Loop(int x)
                    {
            {{Dispatch($$"""
                            case 0u: return -1;
                            case 1u: x = x * 2 + 1; num = x < 1000 && x > -1000 ? num2 * 0x{{A:X8}}u ^ {{B(1, 1)}}u : num2 * 0x{{A:X8}}u ^ {{B(1, 4)}}u; continue;
                            case 2u: x += 3; num = num2 * 0x{{A:X8}}u ^ {{B(2, 1)}}u; continue;
                            case 3u: return -3;
                            default: return x;
            """)}}
                    }

                    // Case 0 runs with two states (num2 = 5000 and 5005) and adds num2 to x: its value depends on the path.
                    public static int Varies(int x)
                    {
            {{Dispatch($$"""
                            case 0u: x += (int)num2; num = x > 20000 ? num2 * 0x{{A:X8}}u ^ {{B(0, 4)}}u : 0x{{(uint)5005 ^ K:X8}}u; continue;
                            case 1u: return -1;
                            case 2u: x += 3; num = num2 * 0x{{A:X8}}u ^ {{B(2, 0)}}u; continue;
                            case 3u: return -3;
                            default: return x;
            """)}}
                    }
                }
            }
            """;
    }

    private string ConfusedFixture()
    {
        var path = _dir.File("Confused.dll");
        if (!File.Exists(path)) File.WriteAllBytes(path, CompileRelease("Confused", ConfusedSource()));
        return path;
    }

    [Theory]
    [InlineData("Chain")]
    [InlineData("Branchy")]
    [InlineData("Loop")]
    public void TransitionsComputedFromThePreviousStateAreNormalized(string method)
    {
        using var env = new Env(ConfusedFixture());
        Assert.Contains("switch", env.Decompile("Confused.C::" + method));
        var report = Simplify(env, "Confused.C::" + method, dryRun: true);
        Assert.Contains("1 of 1 method(s) would change", report);
        Assert.Contains("normalized 1 switch dispatcher(s)", report);
        Assert.DoesNotContain("flattened-shape", report);

        Simplify(env, "Confused.C::" + method);
        var code = Body(env, "Confused.C::" + method);
        Assert.DoesNotContain(code, i => i.OpCode.Code == Code.Switch);
        var csharp = env.Decompile("Confused.C::" + method);
        Assert.DoesNotContain("num", csharp);
        Assert.DoesNotContain("switch", csharp);

        var image = env.Fixture.GetImageBytes();
        foreach (var x in new[] { 0, 1, 7, 11, 12, 300, -5, 999, int.MaxValue })
            Assert.Equal(Run(env.Fixture.OriginalBytes, "Confused.C", method, x), Run(image, "Confused.C", method, x));
    }

    [Fact]
    public void ComputedTransitionsThatDependOnThePathKeepTheDispatcher()
    {
        using var env = new Env(ConfusedFixture());
        var before = Il(env, "Confused.C::Varies");
        var report = Simplify(env, "Confused.C::Varies");
        Assert.Matches(@"Confused\.C::Varies\(int\) switch dispatcher at IL_\w{4}: the state on the way into the dispatcher at IL_\w{4} depends on the path taken; " +
                       @"the dispatcher is kept \[flattened-shape\]", report);
        Assert.Equal(before, Il(env, "Confused.C::Varies"));
    }

    [Fact]
    public void ReportOfManyMethodsStartsWithTotals()
    {
        using var env = new Env(FlatFixture());
        var report = Simplify(env, "Flat.Steps", Options("cfg"), dryRun: true);
        Assert.Equal("Totals: 1 of 2 method(s) changed; 1 dispatcher(s) normalized (5 transition(s)), 3 unreachable block(s) removed. " +
                     "Fallbacks: flattened-shape 1.", report.Split('\n')[1]); // after the header line
        Assert.DoesNotContain("Totals:", Simplify(env, "Flat.Steps::Run", Options("cfg"), dryRun: true));
    }

    // ---- 2b. conditions constant through locals (the C# compiler does not propagate locals)

    private const string PredsSource = """
        namespace Preds
        {
            public static class P
            {
                private static readonly int Seed = 12;
                private static int Mutable = 3;

                public static int Local(int x)
                {
                    int k = 7;
                    int m = k * k + k; // k stays a local: Roslyn keeps single-use locals on the stack
                    if (m % 4 == 3) x += 100; else x -= 1;
                    return x;
                }

                public static int Joined(int x)
                {
                    int k;
                    if (x > 0) { k = 5; x++; } else { k = 5; x--; }
                    if (k == 5) return x;
                    return -x;
                }

                public static int Loop(int x)
                {
                    int k = 3;
                    int acc = 0;
                    for (int i = 0; i < 4; i++)
                    {
                        if (k > 2) acc += x; else acc -= x;
                    }
                    return acc;
                }

                public static int Selector(int x)
                {
                    int sel = (Seed ^ 10) - 4;
                    switch (sel)
                    {
                        case 0: return x;
                        case 1: return x * 2;
                        case 2: return x * 3;
                        default: return 0;
                    }
                }

                public static int Wide(int x)
                {
                    long w = 1L << 40;
                    double d = 0.5;
                    if ((w >> 40) == 1 && d * 4 == 2.0) return x + 1;
                    return x;
                }

                public static int Unknown(int x)
                {
                    int k = x & 1;
                    if (k == 0) return 1;
                    return 2;
                }

                public static int MutableRead(int x)
                {
                    if (Mutable == 3) return x;
                    return -x;
                }

                public static void SetMutable(int value) => Mutable = value;

                public static int Differs(int x)
                {
                    int k = 1;
                    if (x > 5) k = 2;
                    if (k == 1) return 10;
                    return 20;
                }

                public static int AddressTaken(int x)
                {
                    int k = 1;
                    Bump(ref k, x);
                    if (k == 1) return 10;
                    return 20;
                }

                private static void Bump(ref int k, int by) => k += by;
            }
        }
        """;

    private string PredsFixture()
    {
        var path = _dir.File("Preds.dll");
        if (!File.Exists(path)) File.WriteAllBytes(path, CompileRelease("Preds", PredsSource));
        return path;
    }

    private static readonly int[] PredsInputs = [0, 1, 5, 6, -7, 1000];

    [Theory]
    [InlineData("Local", 1, "x += 100")]
    [InlineData("Joined", 1, "-x")]
    [InlineData("Loop", 1, "acc -= x")]
    [InlineData("Selector", 1, "switch")]
    [InlineData("Wide", 2, "return x;")]
    public void ConditionsConstantThroughLocalsFold(string method, int branches, string gone)
    {
        using var env = new Env(PredsFixture());
        var report = Simplify(env, "Preds.P::" + method, Options("cfg"));
        Assert.Contains("1 of 1 method(s) changed", report);
        Assert.Contains($"folded {branches} constant branch(es)", report);

        Assert.DoesNotContain(Body(env, "Preds.P::" + method), i => i.OpCode.Code == Code.Switch);
        Assert.DoesNotContain(gone, env.Decompile("Preds.P::" + method));

        var image = env.Fixture.GetImageBytes();
        foreach (var x in PredsInputs)
            Assert.Equal(Run(env.Fixture.OriginalBytes, "Preds.P", method, x), Run(image, "Preds.P", method, x));
    }

    [Fact]
    public void LocalsFoldedAwayLoseTheirStores()
    {
        using var env = new Env(PredsFixture());
        var report = Simplify(env, "Preds.P::Local", Options("cfg"));
        Assert.Contains("removed 1 dead store(s)", report);
        Assert.DoesNotContain(Body(env, "Preds.P::Local"), i => i.IsStloc());
        Assert.Equal("x--;\nreturn x;", Statements(env.Decompile("Preds.P::Local")));
        Simplify(env, "Preds.P::Selector", Options("cfg"));
        Assert.Equal("return x * 3;", Statements(env.Decompile("Preds.P::Selector")));
    }

    /// <summary>The method body's statements, one per line, without the signature and braces.</summary>
    private static string Statements(string csharp)
    {
        var lines = csharp.ReplaceLineEndings("\n").Split('\n');
        int open = Array.FindIndex(lines, l => l.Trim() == "{");
        int close = Array.FindLastIndex(lines, l => l.Trim() == "}");
        return string.Join("\n", lines[(open + 1)..close].Select(l => l.Trim()).Where(l => l.Length > 0));
    }

    [Theory]
    [InlineData("Unknown")]
    [InlineData("MutableRead")]
    [InlineData("Differs")]
    [InlineData("AddressTaken")]
    public void ConditionsThatVaryStay(string method)
    {
        using var env = new Env(PredsFixture());
        var before = Il(env, "Preds.P::" + method);
        var report = Simplify(env, "Preds.P::" + method, Options("cfg"));
        Assert.Contains("0 of 1 method(s) changed", report);
        Assert.Equal(before, Il(env, "Preds.P::" + method));
    }

    // ---- 3. forwarders

    [Fact]
    public void ForwarderCallSitesAreRetargeted()
    {
        using var env = new Env(ObfFixture());
        var report = Simplify(env, "Obf.Callers::Use", Options("inline"));
        Assert.Contains("inlined Obf.Fwd::AddW(int, int) -> Obf.Real::Add(int, int)", report);
        Assert.Contains("inlined Obf.Fwd::AddWW(int, int) -> Obf.Real::Add(int, int)", report);
        Assert.Contains("inlined Obf.Fwd::ScaleW(Real, int) -> Obf.Real::Scale(int)", report);
        Assert.Contains("inlined Obf.Box::Inner(int) -> Obf.Box::Compute(int)", report);
        Assert.Contains("inlined Obf.Fwd::Make() -> Obf.Real::.ctor()", report);

        var calls = Body(env, "Obf.Callers::Use").Where(i => i.Operand is IMethod).Select(i => $"{i.OpCode.Name} {((IMethod)i.Operand).DeclaringType.Name}::{((IMethod)i.Operand).Name}").ToList();
        Assert.DoesNotContain(calls, c => c.Contains("Fwd::"));
        Assert.Equal(2, calls.Count(c => c == "call Real::Add"));
        Assert.Contains("callvirt Real::Scale", calls);
        Assert.Contains(calls, c => c.EndsWith(" Box::Compute")); // callvirt when the site was callvirt: the null check stays
        Assert.Contains("callvirt Shape::Area", calls);   // virtual wrapper: target not certain
        Assert.Contains("call Real::Exposed", calls);     // its target is private to Real
        Assert.Equal(2, calls.Count(c => c == "newobj Real::.ctor"));

        Assert.Equal(Run(env.Fixture.OriginalBytes, "Obf.Callers", "Use"), Run(env.Fixture.GetImageBytes(), "Obf.Callers", "Use"));
    }

    [Fact]
    public void ForwardersWhoseCallRunsAStaticConstructorAreKept()
    {
        using var env = new Env(ObfFixture());
        Simplify(env, "Obf.Callers::UseNoisy", Options("inline"));
        Assert.Contains(Body(env, "Obf.Callers::UseNoisy"), i => i.Operand is IMethod { Name.String: "AddN" });
    }

    [Fact]
    public void StaticConstructorsFoldWithTheStateAtTheCallNotTheirFinalState()
    {
        // While the static constructor runs, Prefix is still null: Join() returns "none-x", not "p-x".
        using var env = new Env(ObfFixture());
        var report = Simplify(env, "Obf.SelfInit::.cctor");
        Assert.Contains("-> \"none-x\"", report);
        Assert.DoesNotContain("p-x", report);
        Assert.DoesNotContain(Body(env, "Obf.SelfInit::.cctor"), i => i.Operand is IMethod { Name.String: "Join" });
        Assert.Equal("none-x", Run(env.Fixture.GetImageBytes(), "Obf.SelfInit", "GetName"));
    }

    // ---- 4. dry run, view, round trip, undo

    [Fact]
    public void DryRunReportsWithoutModifyingTheModule()
    {
        using var env = new Env(ObfFixture());
        var asm = env.Fixture;
        var bodies = asm.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody)
            .ToDictionary(m => m, m => (Body: m.Body, Il: string.Join("\n", m.Body.Instructions)));
        int version = asm.Version;

        var report = env.Workspace.Read(() => env.Edits.SimplifyMethods(asm, null, Options(), dryRun: true, default));

        Assert.StartsWith("Dry run — simplify Obf", report);
        Assert.Contains("would change", report);
        Assert.Contains("folded Obf.Strings::Get(int, int) -> \"Hello\"", report);
        Assert.Contains("inlined Obf.Fwd::AddW(int, int)", report);
        Assert.Empty(asm.Edits);
        Assert.Equal(version, asm.Version);
        Assert.Same(asm.OriginalBytes, asm.GetImageBytes());
        foreach (var (m, before) in bodies)
        {
            Assert.Same(before.Body, m.Body);
            Assert.Equal(before.Il, string.Join("\n", m.Body.Instructions));
        }

        var flow = new Env(FlowFixture());
        using (flow)
        {
            var flowReport = flow.Workspace.Read(() => flow.Edits.SimplifyMethods(flow.Fixture, null, Options(), dryRun: true, default));
            Assert.Contains("removed 2 unreachable block(s)", flowReport);
            Assert.Same(flow.Fixture.OriginalBytes, flow.Fixture.GetImageBytes());
        }
    }

    [Fact]
    public void DecompiledViewShowsTheSimplifiedFormWithoutEditing()
    {
        using var env = new Env(ObfFixture());
        var title = env.One("Obf.App::Title");
        var view = env.Workspace.Read(() => env.Decompiler.DecompileSimplified(env.Fixture, [title.Member], new SimplifyOptions(), default));
        Assert.Contains("return \"Hello\";", view);
        Assert.Contains("1 call(s) folded", view);
        Assert.Contains("Strings.Get(0, 5)", env.Decompile("Obf.App::Title"));

        var type = env.Workspace.Read(() => env.Decompiler.DecompileSimplified(env.Fixture, [env.One("Obf.Callers").Member], new SimplifyOptions(), default));
        Assert.Contains("Real.Add(1, 2)", type);
        Assert.Empty(env.Fixture.Edits);
    }

    /// <summary>The Obf assembly XALZ-compressed in the assembly store of an APK, unpacked and loaded from there.</summary>
    [Fact]
    public void An_assembly_unpacked_from_an_apk_assembly_store_is_simplified_and_saved()
    {
        var store = ContainerFixtures.AssemblyStore(ContainerFixtures.Module("StoreRaw"), CompileRelease("Obf", ObfSource));
        var apk = _dir.File("app.apk");
        File.WriteAllBytes(apk, ContainerFixtures.Zip(
            ("AndroidManifest.xml", [0x03, 0x00, 0x08, 0x00]), ("lib/arm64-v8a/libassemblies.arm64-v8a.blob.so", store), ("classes.dex", "dex\n035"u8.ToArray())));
        using var env = new Env();
        var unpacked = new Corvus.Services.Analysis.UnpackService(env.Workspace).Unpack(apk, _dir.File("out"), load: true, AnalysisLimits.Default, default);
        Assert.Contains(unpacked.Files, f => f.LoadedAs == "Obf");

        Assert.Contains("folded Obf.Strings::Greeting() -> \"Hello, World!\"", Simplify(env, "Obf.Strings::UseAll"));
        var saved = _dir.File("Obf.simplified.dll");
        env.Edits.Save(env.One("Obf.Strings::UseAll").Assembly, saved, overwrite: false);
        using var module = ModuleDefMD.Load(saved);
        var body = module.Find("Obf.Strings", false).FindMethod("UseAll").Body.Instructions;
        Assert.Equal("Hello, World!|secret-keyacegi-ok", Assert.Single(body, i => i.OpCode == OpCodes.Ldstr).Operand);
    }

    [Fact]
    public void The_transforms_view_counts_restored_and_kept_sites_without_editing()
    {
        using var env = new Env(ObfFixture());
        var before = Il(env, "Obf.Strings::UseAll");
        Corvus.Services.AssemblyReport.Summary summary = null!;
        var text = env.Workspace.Read(() => env.Report.Build(env.Fixture, "transforms", out summary));

        // Io.ReadConfig reads a file and Calc builds a string from arithmetic: neither has a decoder shape, so neither counts.
        var constants = Assert.Single(summary.Transformers!, t => t.Name == "layer: " + TransformLayers.Constants);
        Assert.Equal("restored", constants.Confidence);
        Assert.Matches(@"^(\d+) site\(s\), \1 restored$", constants.Evidence[0]);
        Assert.DoesNotContain(constants.Evidence, e => e.StartsWith("external-io", StringComparison.Ordinal));
        Assert.Contains("Transforms (a simplify_methods dry run; nothing is changed):", text);
        Assert.Empty(env.Fixture.Edits);
        Assert.Equal(before, Il(env, "Obf.Strings::UseAll"));
    }

    private const string HelperSource = """
        using System.IO;

        namespace Helpers
        {
            public static class Labels
            {
                public static string Item(int n) => "Item " + n;
                public static string Pair() => string.Concat("a", "b") + Item(3);
            }

            public static class Keyed
            {
                public static string Get(int salt)
                {
                    var key = File.ReadAllBytes("key-that-does-not-exist.bin");
                    var chars = new char[4];
                    for (int i = 0; i < 4; i++) chars[i] = (char)(key[i] ^ salt);
                    return new string(chars);
                }

                public static string Use() => Get(7);
            }
        }
        """;

    [Fact]
    public void Only_helpers_with_a_decoder_shape_make_a_constants_layer()
    {
        var path = _dir.File("Helpers.dll");
        File.WriteAllBytes(path, CompileRelease("Helpers", HelperSource));
        using var env = new Env(path);
        var constants = Assert.Single(env.Workspace.Read(() => TransformLayers.Read(env.Fixture, default)), l => l.Layer == TransformLayers.Constants);
        Assert.Equal("unknown", constants.State);
        Assert.Equal((1, 0), (constants.Sites, constants.Restored));
        Assert.Equal("external-io: 1", constants.Reasons[0]);
        Assert.Contains("Keyed::Use", constants.Evidence);
    }

    private const string LoaderSource = """
        using System;
        using System.IO;
        using System.Reflection;

        namespace Loader
        {
            public static class Boot
            {
                public static void Start() => AppDomain.CurrentDomain.AssemblyResolve += (_, e) => FromResource(e.Name);

                public static Assembly FromResource(string name)
                {
                    using var s = typeof(Boot).Assembly.GetManifestResourceStream(name)!;
                    var bytes = new byte[s.Length];
                    s.ReadExactly(bytes);
                    return Assembly.Load(bytes);
                }
            }
        }
        """;

    [Fact]
    public void Assemblies_loaded_from_bytes_and_resolve_handlers_are_counted_as_present()
    {
        var path = _dir.File("Loader.dll");
        File.WriteAllBytes(path, CompileRelease("Loader", LoaderSource));
        using var env = new Env(path);
        var loads = Assert.Single(env.Workspace.Read(() => TransformLayers.Read(env.Fixture, default)), l => l.Layer == TransformLayers.LoadedAssemblies);
        Assert.Equal(("present", 2, 0, "counted-only"), (loads.State, loads.Sites, loads.Restored, Assert.Single(loads.Reasons)));
        Assert.Contains("an AssemblyResolve handler in Loader.Boot::Start", loads.Evidence);
        Assert.Contains("Assembly.Load(byte[]) in Loader.Boot::FromResource", loads.Evidence);
        Assert.EndsWith("(bytes from a manifest resource)", loads.Evidence);
    }

    [Fact]
    public void Bodies_that_are_not_il_are_counted_as_an_encoded_bodies_layer()
    {
        var path = _dir.File("Helpers.dll");
        // The two methods of Keyed get bytes that are not IL; Labels keeps its bodies.
        File.WriteAllBytes(path, IlHealthTests.Corrupt(CompileRelease("Helpers", HelperSource), type => type == "Keyed"));
        using var env = new Env(path);
        var layers = env.Workspace.Read(() => TransformLayers.Read(env.Fixture, default));
        var encoded = Assert.Single(layers, l => l.Layer == TransformLayers.EncodedBodies);
        Assert.Equal(("present", 2, "counted-only"), (encoded.State, encoded.Sites, Assert.Single(encoded.Reasons)));
        Assert.StartsWith("2 of ", encoded.Evidence, StringComparison.Ordinal);
        Assert.DoesNotContain(layers, l => l.Layer == TransformLayers.LoadedAssemblies);
    }

    [Fact]
    public void Layers_the_time_limit_stops_are_unknown_and_name_the_limit()
    {
        using var env = new Env(ObfFixture());
        var layers = env.Workspace.Read(() => TransformLayers.Read(env.Fixture, default, TimeSpan.Zero));
        Assert.Equal([TransformLayers.Constants, TransformLayers.Proxies, TransformLayers.ControlFlow], layers.Select(l => l.Layer));
        Assert.All(layers, l => Assert.Equal("unknown", l.State));
        Assert.All(layers, l => Assert.Matches(@"^time-limit: \d+ method\(s\) not reached within 0 s$", Assert.Single(l.Reasons)));
    }

    [Fact]
    public void SimplifiedAssembliesSaveAndReloadCleanly()
    {
        foreach (var (fixture, type, methods) in new[]
                 {
                     (ObfFixture(), "Obf.Callers", new[] { ("Use", Array.Empty<object?>()) }),
                     (FlowFixture(), "Paths.Flow", FlowCalls),
                     (FlatFixture(), "Flat.Steps", new[] { ("Run", new object?[] { 9 }), ("Dynamic", new object?[] { 4 }) }),
                 })
        {
            string saved;
            byte[] original;
            using (var env = new Env(fixture))
            {
                original = env.Fixture.OriginalBytes;
                var report = env.Edit(() => env.Edits.SimplifyMethods(env.Fixture, null, Options(), false, default));
                Assert.DoesNotContain("would not verify", report);
                Assert.Single(env.Fixture.Edits);
                saved = _dir.File(Path.GetFileNameWithoutExtension(fixture) + ".simplified.dll");
                env.Edits.Save(env.Fixture, saved, overwrite: true);
            }

            using (var module = ModuleDefMD.Load(saved))
            {
                foreach (var m in module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
                {
                    bool hasReturn = m.MethodSig.RetType.RemovePinnedAndModifiers().ElementType != ElementType.Void;
                    Assert.True(new BodyGraph(m.Body).Verify(hasReturn, out var error) != null, $"{m.FullName}: {error}");
                }
            }
            using (var reloaded = new Env(saved))
            {
                Assert.DoesNotContain("decompilation failed", reloaded.Decompiler.DecompileType(reloaded.Fixture, reloaded.Def<TypeDef>(type), default));
                var bytes = File.ReadAllBytes(saved);
                foreach (var (name, args) in methods)
                    Assert.Equal(Run(original, type, name, args), Run(bytes, type, name, args));
            }
        }
        using var obf = new Env(_dir.File("Obf.simplified.dll"));
        Assert.Equal("Hello", Body(obf, "Obf.App::Title")[0].Operand);
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public void RealLibrarySimplifiesSavesAndReverifies()
    {
        using var env = new Env(RealPackages.Lib("NLog", "6.1.4", "netstandard2.1", "NLog.dll"));
        var report = env.Edit(() => env.Edits.SimplifyMethods(env.Fixture, null, Options(), false, default));
        Assert.DoesNotContain("would not verify", report);
        Assert.DoesNotContain("original body does not verify", report);
        // A real string fold: the getter returns a constant escape sequence.
        Assert.Contains("NLog.Targets.ColoredConsoleAnsiPrinter::get_TerminalDefaultColorEscapeCode() -> \"\\u001b[0m\"", report);

        var saved = _dir.File("NLog.simplified.dll");
        env.Edits.Save(env.Fixture, saved, overwrite: false);
        using var module = ModuleDefMD.Load(saved);
        foreach (var m in module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
        {
            bool hasReturn = m.MethodSig.RetType.RemovePinnedAndModifiers().ElementType != ElementType.Void;
            Assert.True(new BodyGraph(m.Body).Verify(hasReturn, out var error) != null, $"{m.FullName}: {error}");
        }
        using var reloaded = new Env(saved);
        Assert.Contains("\"\\u001b[0m\"", reloaded.Decompile("NLog.Targets.ColoredConsoleAnsiPrinter::ResetDefaultColors"));
    }

    [Fact]
    public void SimplifyIsAnEditThatUndoAndReplayRespect()
    {
        using var env = new Env(ObfFixture());
        Simplify(env, "Obf.App::Title");
        env.Edit(() => env.Edits.Rename(env.One("Obf.Deep"), "Chain"));
        Assert.Equal("simplify_methods", env.Fixture.Edits[0].Kind);

        env.Edit(() => env.Edits.Undo(env.Fixture, 2, default)); // rebuilds from the original and replays the simplify edit
        Assert.Equal("Hello", Body(env, "Obf.App::Title")[0].Operand);
        env.Edit(() => env.Edits.Undo(env.Fixture, null, default));
        Assert.Equal(Code.Call, Body(env, "Obf.App::Title").First(i => i.OpCode.FlowControl == FlowControl.Call).OpCode.Code);
    }

    [Fact]
    public void UnknownPassIsRejected()
    {
        var error = Assert.Throws<ToolError>(() => SimplifyOptions.Parse("fold,unroll", null, null));
        Assert.Contains("unroll", error.Message);
        Assert.Equal("fold,inline", SimplifyOptions.Parse("inline, fold", null, null).Describe());
    }

    // ---- fixtures and helpers

    private static readonly (string Name, object?[] Args)[] FlowCalls =
    [
        ("ConstIf", []), ("Switch", []), ("Dead", [0]), ("Dead", [5]), ("Chain", [0]), ("Chain", [1]),
        ("Guarded", []), ("EmptyFinally", [41]), ("DeadCatch", []), ("Keyed", [4]), ("Keyed", [-1]), ("AddressTaken", []),
        ("ReadElsewhere", [5]), ("CondEntry", [0]), ("CondEntry", [3]), ("LocalSwitch", [1]), ("Mixed", [5]),
    ];

    /// <summary>Methods whose control flow only an IL writer (or a code transformer) would produce.</summary>
    private string FlowFixture()
    {
        var path = _dir.File("FlowFixture.dll");
        if (File.Exists(path)) return path;

        var module = new ModuleDefUser("FlowFixture.dll", new Guid("0f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8"), AssemblyRefUser.CreateMscorlibReferenceCLR40())
        {
            Kind = ModuleKind.Dll,
            RuntimeVersion = dnlib.DotNet.MD.MDHeaderRuntimeVersion.MS_CLR_40,
        };
        new AssemblyDefUser("FlowFixture", new Version(1, 0, 0, 0)).Modules.Add(module);
        var flow = new TypeDefUser("Paths", "Flow", module.CorLibTypes.Object.TypeDefOrRef)
        {
            Attributes = TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class,
        };
        module.Types.Add(flow);
        var hits = new FieldDefUser("Hits", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public | FieldAttributes.Static);
        flow.Fields.Add(hits);
        var writeLine = module.Import(typeof(Console).GetMethod(nameof(Console.WriteLine), [typeof(string)]));
        var exception = module.CorLibTypes.GetTypeRef("System", "Exception");
        var i4 = module.CorLibTypes.Int32;

        MethodDef Method(string name, params TypeSig[] parameters)
        {
            var m = new MethodDefUser(name, MethodSig.CreateStatic(i4, parameters), MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig);
            for (int p = 0; p < parameters.Length; p++) m.ParamDefs.Add(new ParamDefUser("x", (ushort)(p + 1)));
            flow.Methods.Add(m);
            m.Body = new CilBody();
            return m;
        }
        static Instruction Ldc(int v) => OpCodes.Ldc_I4.ToInstruction(v);
        static Instruction Ret() => OpCodes.Ret.ToInstruction();
        static void Emit(CilBody body, params Instruction[] code) { foreach (var i in code) body.Instructions.Add(i); }

        // ConstIf: if (1) { if (6 * 7 == 42) return 222; return 333; } return 111;
        {
            var m = Method("ConstIf");
            var b = m.Body;
            var l1 = Ldc(6);
            var bad = Ldc(333);
            Emit(b, Ldc(1), OpCodes.Brtrue.ToInstruction(l1), Ldc(111), Ret(),
                l1, Ldc(7), OpCodes.Mul.ToInstruction(), Ldc(42), OpCodes.Bne_Un.ToInstruction(bad), Ldc(222), Ret(),
                bad, Ret());
        }
        // Switch: switch (1) { 0: 10, 1: 20, 2: 30, default: 0 }
        {
            var m = Method("Switch");
            var b = m.Body;
            Instruction a = Ldc(10), bb = Ldc(20), c = Ldc(30);
            Emit(b, Ldc(1), OpCodes.Switch.ToInstruction(new[] { a, bb, c }), Ldc(0), Ret(), a, Ret(), bb, Ret(), c, Ret());
        }
        // Dead: two unreachable blocks, one after a ret, one looping on itself.
        {
            var m = Method("Dead", i4);
            var b = m.Body;
            var zero = Ldc(0);
            var loop = Ldc(5);
            Emit(b, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Brfalse.ToInstruction(zero), Ldc(1), Ret(),
                OpCodes.Ldstr.ToInstruction("dead"), OpCodes.Call.ToInstruction(writeLine), Ldc(-1), Ret(),
                zero, Ret(),
                loop, OpCodes.Pop.ToInstruction(), OpCodes.Br.ToInstruction(loop));
        }
        // Chain: brtrue L1; L1: br L2; L2: br L3; L3: return 3
        {
            var m = Method("Chain", i4);
            var b = m.Body;
            var l3 = Ldc(3);
            var l2 = OpCodes.Br.ToInstruction(l3);
            var l1 = OpCodes.Br.ToInstruction(l2);
            Emit(b, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Brtrue.ToInstruction(l1), Ldc(2), Ret(), l1, l2, l3, Ret());
        }
        // Guarded: try { if (0 == 0) goto skip; Hits += 100; skip: } finally { Hits++; } return Hits;
        {
            var m = Method("Guarded");
            var b = m.Body;
            var end = OpCodes.Ldsfld.ToInstruction(hits);
            var leave = OpCodes.Leave.ToInstruction(end);
            var tryStart = Ldc(0);
            var handlerStart = OpCodes.Ldsfld.ToInstruction(hits);
            Emit(b, tryStart, OpCodes.Brfalse.ToInstruction(leave),
                OpCodes.Ldsfld.ToInstruction(hits), Ldc(100), OpCodes.Add.ToInstruction(), OpCodes.Stsfld.ToInstruction(hits),
                leave,
                handlerStart, Ldc(1), OpCodes.Add.ToInstruction(), OpCodes.Stsfld.ToInstruction(hits), OpCodes.Endfinally.ToInstruction(),
                end, Ret());
            b.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
            {
                TryStart = tryStart, TryEnd = handlerStart, HandlerStart = handlerStart, HandlerEnd = end,
            });
        }
        // EmptyFinally: try { x++; } finally { } return x;
        {
            var m = Method("EmptyFinally", i4);
            var b = m.Body;
            var end = OpCodes.Ldarg_0.ToInstruction();
            var tryStart = OpCodes.Ldarg_0.ToInstruction();
            var handler = OpCodes.Endfinally.ToInstruction();
            Emit(b, tryStart, Ldc(1), OpCodes.Add.ToInstruction(), OpCodes.Starg.ToInstruction(m.Parameters[0]), OpCodes.Leave.ToInstruction(end),
                handler, end, Ret());
            b.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
            {
                TryStart = tryStart, TryEnd = handler, HandlerStart = handler, HandlerEnd = end,
            });
        }
        // DeadCatch: try { if (1) goto ok; throw null; ok: } catch (Exception) { } return 7;
        {
            var m = Method("DeadCatch");
            var b = m.Body;
            var end = Ldc(7);
            var tryStart = Ldc(1);
            var ok = OpCodes.Leave.ToInstruction(end);
            var handler = OpCodes.Pop.ToInstruction();
            Emit(b, tryStart, OpCodes.Brtrue.ToInstruction(ok), OpCodes.Ldnull.ToInstruction(), OpCodes.Throw.ToInstruction(), ok,
                handler, OpCodes.Leave.ToInstruction(end), end, Ret());
            b.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart, TryEnd = handler, HandlerStart = handler, HandlerEnd = end, CatchType = exception,
            });
        }
        // Keyed: flattened (x + 1) * 3. The dispatcher switches on state ^ 0x5A; the entry falls into it.
        {
            var m = Method("Keyed", i4);
            var b = m.Body;
            b.InitLocals = true;
            var state = new Local(i4);
            b.Variables.Add(state);
            var head = OpCodes.Ldloc.ToInstruction(state);
            Instruction c0 = OpCodes.Ldarg_0.ToInstruction(), c1 = OpCodes.Ldarg_0.ToInstruction(), c2 = OpCodes.Ldarg_0.ToInstruction();
            Emit(b, Ldc(0 ^ 0x5A), OpCodes.Stloc.ToInstruction(state),
                head, Ldc(0x5A), OpCodes.Xor.ToInstruction(), OpCodes.Switch.ToInstruction(new[] { c0, c1, c2 }), Ldc(-1), Ret(),
                c0, Ldc(1), OpCodes.Add.ToInstruction(), OpCodes.Starg.ToInstruction(m.Parameters[0]),
                Ldc(2 ^ 0x5A), OpCodes.Stloc.ToInstruction(state), OpCodes.Br.ToInstruction(head),
                c1, Ret(),
                c2, Ldc(3), OpCodes.Mul.ToInstruction(), OpCodes.Starg.ToInstruction(m.Parameters[0]),
                Ldc(1 ^ 0x5A), OpCodes.Stloc.ToInstruction(state), OpCodes.Br.ToInstruction(head));
        }
        // AddressTaken: the state is written through a pointer, so its value at the dispatcher is not known from the stores.
        {
            var m = Method("AddressTaken");
            var b = m.Body;
            b.InitLocals = true;
            var state = new Local(i4);
            b.Variables.Add(state);
            var head = OpCodes.Ldloc.ToInstruction(state);
            Instruction c0 = Ldc(1), c1 = Ldc(7);
            Emit(b, OpCodes.Ldloca.ToInstruction(state), Ldc(0), OpCodes.Stind_I4.ToInstruction(),
                head, OpCodes.Switch.ToInstruction(new[] { c0, c1 }), Ldc(-1), Ret(),
                c0, OpCodes.Stloc.ToInstruction(state), OpCodes.Br.ToInstruction(head),
                c1, Ret());
        }
        // ReadElsewhere: x + 1, but case 1 reads the state; case 0 has a constant branch.
        {
            var m = Method("ReadElsewhere", i4);
            var b = m.Body;
            b.InitLocals = true;
            var state = new Local(i4);
            b.Variables.Add(state);
            var head = OpCodes.Ldloc.ToInstruction(state);
            Instruction c0 = Ldc(1), c1 = OpCodes.Ldloc.ToInstruction(state), skip = Ldc(1);
            Emit(b, Ldc(0), OpCodes.Stloc.ToInstruction(state),
                head, OpCodes.Switch.ToInstruction(new[] { c0, c1 }), Ldc(-1), Ret(),
                c0, OpCodes.Brtrue.ToInstruction(skip), Ldc(99), Ret(),
                skip, OpCodes.Stloc.ToInstruction(state), OpCodes.Br.ToInstruction(head),
                c1, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Add.ToInstruction(), Ret());
        }
        // CondEntry: x == 0 ? 5 : x, the dispatcher entered by a conditional branch.
        {
            var m = Method("CondEntry", i4);
            var b = m.Body;
            b.InitLocals = true;
            var state = new Local(i4);
            b.Variables.Add(state);
            var head = OpCodes.Ldloc.ToInstruction(state);
            Instruction c0 = OpCodes.Ldarg_0.ToInstruction(), c1 = OpCodes.Ldarg_0.ToInstruction();
            Emit(b, Ldc(1), OpCodes.Stloc.ToInstruction(state),
                OpCodes.Ldarg_0.ToInstruction(), OpCodes.Brtrue.ToInstruction(head),
                Ldc(0), OpCodes.Stloc.ToInstruction(state), OpCodes.Br.ToInstruction(head),
                head, OpCodes.Switch.ToInstruction(new[] { c0, c1 }), Ldc(-1), Ret(),
                c0, Ldc(5), OpCodes.Add.ToInstruction(), OpCodes.Starg.ToInstruction(m.Parameters[0]),
                Ldc(1), OpCodes.Stloc.ToInstruction(state), OpCodes.Br.ToInstruction(head),
                c1, Ret());
        }
        // Varies: x + 3; the case shared by states 1 and 2 reads the state, which is 1 the first time and 2 the second.
        {
            var m = Method("Varies", i4);
            var b = m.Body;
            b.InitLocals = true;
            var state = new Local(i4);
            b.Variables.Add(state);
            var head = OpCodes.Ldloc.ToInstruction(state);
            Instruction c0 = Ldc(7), c1 = OpCodes.Ldloc.ToInstruction(state), done = OpCodes.Ldarg_0.ToInstruction();
            Emit(b, Ldc(1), OpCodes.Stloc.ToInstruction(state),
                head, OpCodes.Switch.ToInstruction(new[] { c0, c1, c1 }), Ldc(-1), Ret(),
                c0, Ret(),
                c1, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Add.ToInstruction(), OpCodes.Starg.ToInstruction(m.Parameters[0]),
                OpCodes.Ldloc.ToInstruction(state), Ldc(2), OpCodes.Beq.ToInstruction(done),
                Ldc(2), OpCodes.Stloc.ToInstruction(state), OpCodes.Br.ToInstruction(head),
                done, Ret());
        }
        // LocalSwitch: switch (local) as a debug build emits it; no loop, so not flattened control flow.
        {
            var m = Method("LocalSwitch", i4);
            var b = m.Body;
            b.InitLocals = true;
            var copy = new Local(i4);
            b.Variables.Add(copy);
            Instruction c0 = Ldc(10), c1 = Ldc(20);
            Emit(b, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Stloc.ToInstruction(copy), OpCodes.Ldloc.ToInstruction(copy),
                OpCodes.Switch.ToInstruction(new[] { c0, c1 }), Ldc(-1), Ret(), c0, Ret(), c1, Ret());
        }
        // Plain: nothing to simplify.
        var plain = Method("Plain", i4);
        Emit(plain.Body, OpCodes.Ldarg_0.ToInstruction(), Ldc(1), OpCodes.Add.ToInstruction(), Ret());
        // PlainW: a forwarder to Plain.
        var plainW = Method("PlainW", i4);
        Emit(plainW.Body, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(plain), Ret());
        // Mixed: a dispatcher whose state depends on the argument (kept), around a constant branch, a forwarder call and
        // a string fold: x = PlainW(x); state = (x > 0) + 1 in case 0, then x += state; "ab".Length + x in cases 1 and 2.
        {
            var m = Method("Mixed", i4);
            var b = m.Body;
            b.InitLocals = true;
            var state = new Local(i4);
            b.Variables.Add(state);
            var head = OpCodes.Ldloc.ToInstruction(state);
            Instruction c0 = Ldc(1), c1 = OpCodes.Ldloc.ToInstruction(state), work = OpCodes.Ldarg_0.ToInstruction();
            var concat = module.Import(typeof(string).GetMethod(nameof(string.Concat), [typeof(string), typeof(string)]));
            var length = module.Import(typeof(string).GetProperty(nameof(string.Length))!.GetGetMethod());
            Emit(b, Ldc(0), OpCodes.Stloc.ToInstruction(state),
                head, OpCodes.Switch.ToInstruction(new[] { c0, c1, c1 }), Ldc(-1), Ret(),
                c0, OpCodes.Brtrue.ToInstruction(work), Ldc(99), Ret(),
                work, OpCodes.Call.ToInstruction(plainW), OpCodes.Starg.ToInstruction(m.Parameters[0]),
                OpCodes.Ldarg_0.ToInstruction(), Ldc(0), OpCodes.Cgt.ToInstruction(), Ldc(1), OpCodes.Add.ToInstruction(),
                OpCodes.Stloc.ToInstruction(state), OpCodes.Br.ToInstruction(head),
                c1, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Add.ToInstruction(), OpCodes.Starg.ToInstruction(m.Parameters[0]),
                OpCodes.Ldstr.ToInstruction("a"), OpCodes.Ldstr.ToInstruction("b"),
                OpCodes.Call.ToInstruction(concat), OpCodes.Callvirt.ToInstruction(length), OpCodes.Ldarg_0.ToInstruction(),
                OpCodes.Add.ToInstruction(), Ret());
        }

        using var ms = new MemoryStream();
        module.Write(ms);
        File.WriteAllBytes(path, ms.ToArray());
        return path;
    }

    /// <summary>Release build: the optimizer leaves the minimal IL patterns the passes look for.</summary>
    private static byte[] CompileRelease(string name, string source) => Roslyn.Release(name, source);

    /// <summary>Runs a static method of an image in a throwaway load context (JIT compilation rejects invalid IL).</summary>
    private static object? Run(byte[] image, string type, string method, params object?[] args)
    {
        var context = new AssemblyLoadContext(null, isCollectible: true);
        try
        {
            var asm = context.LoadFromStream(new MemoryStream(image));
            var m = asm.GetType(type, throwOnError: true)!.GetMethod(method)!;
            return m.Invoke(null, args);
        }
        finally
        {
            context.Unload();
        }
    }
}
