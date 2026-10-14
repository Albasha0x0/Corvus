using System.Runtime.Loader;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Corvus.Services.Simplify;

namespace Corvus.Tests;

/// <summary>
/// The extended tier for type initializers: a static constructor that builds a large table runs past the instruction
/// budget while it commits new state, and calls reading what it computed fold; one that loops without committing new
/// state (a running sum, the same element written again) stops at the budget as before, and so does an ordinary method.
/// The ceiling stops a run; a stopped run is remembered; the run is not charged to the method's total budget.
/// </summary>
public sealed class SimplifyProgressTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const string Source = """
        using System.Text;

        namespace Big
        {
            // 40,000 elements, each written once: about 600,000 instructions.
            public static class Table
            {
                private static readonly int Last;
                static Table()
                {
                    var t = new int[40000];
                    for (int i = 0; i < t.Length; i++) t[i] = i * 7 + (i > 0 ? t[i - 1] & 3 : 0);
                    Last = t[t.Length - 1];
                }
                public static string Get() => Last.ToString();
            }

            // A builder that grows by a character per step.
            public static class Text
            {
                private static readonly string Built;
                static Text()
                {
                    var sb = new StringBuilder();
                    for (int i = 0; i < 25000; i++) sb.Append((char)('a' + i % 26));
                    Built = sb.ToString();
                }
                public static string Get() => Built.Substring(24990, 5);
            }

            // Passes over a buffer filled before: each changes the values of locations the run already wrote.
            public static class Passes
            {
                private static readonly int Check;
                static Passes()
                {
                    var b = new byte[8000];
                    for (int i = 0; i < b.Length; i++) b[i] = (byte)i;
                    for (int p = 1; p <= 6; p++)
                        for (int i = 0; i < b.Length; i++) b[i] = (byte)(b[i] ^ (p * 37 + i));
                    int s = 0;
                    for (int i = 0; i < 800; i++) s = s * 31 + b[i * 10];
                    Check = s & 0x7FFFFFFF;
                }
                public static string Get() => Check.ToString();
            }

            // Only locals change: nothing is committed.
            public static class Spin
            {
                private static readonly int Value;
                static Spin()
                {
                    int x = 0;
                    for (int i = 0; i < 1000000; i++) x += i;
                    Value = x;
                }
                public static string Get() => Value.ToString();
            }

            // The same element over and over.
            public static class Rewrite
            {
                private static readonly int Value;
                static Rewrite()
                {
                    var cell = new int[1];
                    for (int i = 0; i < 1000000; i++) cell[0] = i;
                    Value = cell[0];
                }
                public static string Get() => Value.ToString();
            }

            public static class Plain
            {
                public static string Get()
                {
                    var t = new int[40000];
                    for (int i = 0; i < t.Length; i++) t[i] = i;
                    return t[5].ToString();
                }
            }

            public static class Use
            {
                public static string Table1() => Table.Get();
                public static string Table2() => Table.Get();
                public static string Text1() => Text.Get();
                public static string Passes1() => Passes.Get();
                public static string Spin1() => Spin.Get();
                public static string Rewrite1() => Rewrite.Get();
                public static string Plain1() => Plain.Get();
                public static string All() => string.Join("|", Table1(), Text1(), Spin1(), Rewrite1(), Plain1(), Passes1());
            }
        }
        """;

    private string Fixture()
    {
        var path = _dir.File("Big.dll");
        if (File.Exists(path)) return path;
        File.WriteAllBytes(path, Roslyn.Release("Big", Source));
        return path;
    }

    private static string Run(byte[] image)
    {
        var context = new AssemblyLoadContext(null, isCollectible: true);
        try
        {
            var asm = context.LoadFromStream(new MemoryStream(image));
            return (string)asm.GetType("Big.Use", throwOnError: true)!.GetMethod("All")!.Invoke(null, [])!;
        }
        finally
        {
            context.Unload();
        }
    }

    /// <summary>The default instruction budgets with time limits a loaded machine cannot reach: the outcomes these tests check are the budgets'.</summary>
    private static readonly EvaluationLimits Unhurried = new(MethodTimeLimitMs: 600_000, InitializerTimeLimitMs: 600_000);

    private static string Simplify(Env env, EvaluationLimits? limits = null, bool dryRun = true) =>
        env.Edit(() => env.Edits.SimplifyMethods(env.One("Big.Use").Assembly, env.One("Big.Use"), new SimplifyOptions(Limits: limits ?? Unhurried), dryRun, default));

    [Fact]
    public void InitializersThatCommitStateRunPastTheBudget()
    {
        using var env = new Env(Fixture());
        var expected = Run(env.Fixture.OriginalBytes).Split('|');

        var report = Simplify(env);
        Assert.Contains($"Big.Table::Get() -> \"{expected[0]}\"", report);
        Assert.Contains($"Big.Text::Get() -> \"{expected[1]}\"", report);
        Assert.Matches(@"Big\.Table: [\d,]+ instructions, completed", report);
        Assert.Matches(@"Big\.Text: [\d,]+ instructions, completed", report);
        Assert.Contains($"Big.Passes::Get() -> \"{expected[5]}\"", report);
        Assert.Matches(@"Big\.Passes: [\d,]+ instructions, completed", report);
        Assert.Contains("3 type initializer(s) completed in the extended tier", report);
        // The table is built once: every call (Table1, Table2, and All through Table1) folds on the state the one run left.
        Assert.Single(report.Split('\n'), l => l.Contains("Big.Table: "));
        Assert.Equal(3, report.Split('\n').Count(l => l.Contains($"Big.Table::Get() -> \"{expected[0]}\"")));
    }

    [Fact]
    public void LoopsThatCommitNothingStopAtTheBudget()
    {
        using var env = new Env(Fixture());
        var report = Simplify(env);
        // They run one observed window past the budget, commit nothing there, and fail as without the tier.
        Assert.Contains("Big.Spin::Get(): static constructor of Big.Spin cannot be evaluated: instruction budget of 100,000 exhausted [instruction-budget]", report);
        Assert.Contains("Big.Rewrite::Get(): static constructor of Big.Rewrite cannot be evaluated: instruction budget of 100,000 exhausted [instruction-budget]", report);
        Assert.Contains("Big.Plain::Get(): instruction budget of 100,000 exhausted [instruction-budget]", report);
        Assert.DoesNotContain("Big.Spin: ", report);
        Assert.DoesNotContain("Big.Rewrite: ", report);
        Assert.DoesNotContain("Big.Plain: ", report);
    }

    [Fact]
    public void TheCeilingStopsARunAndTheStopIsRemembered()
    {
        using var env = new Env(Fixture());
        var report = Simplify(env, Unhurried with { InitializerInstructionCeiling = 300_000 });
        Assert.Matches(@"Big\.Table::Get\(\): static constructor of Big\.Table cannot be evaluated: the type initializer ran past the instruction budget in the extended tier for initializers that make progress, and stopped: it reached the ceiling of 300,000 instructions \[instruction-budget\]", report);
        Assert.Matches(@"Big\.Table: [\d,]+ instructions, stopped: it reached the ceiling of 300,000 instructions", report);
        // Table1 and Table2 both need it: the stopped run is not repeated.
        Assert.Single(report.Split('\n'), l => l.Contains("Big.Table: "));
        Assert.DoesNotContain("completed in the extended tier", report.Split('\n').Last(l => l.StartsWith("Totals")));
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public void TheRunIsNotChargedToTheMethodsTotalBudget()
    {
        using var env = new Env(Fixture());
        var expected = Run(env.Fixture.OriginalBytes).Split('|');
        // A method budget far below the run's instructions, and a 1 s method time limit.
        var report = Simplify(env, new EvaluationLimits(MethodInstructionBudget: 300_000, MethodTimeLimitMs: 1_000));
        Assert.Contains($"Big.Table::Get() -> \"{expected[0]}\"", report);
        Assert.Contains($"Big.Text::Get() -> \"{expected[1]}\"", report);
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public void TheFoldedResultRunsTheSame()
    {
        using var env = new Env(Fixture());
        var before = Run(env.Fixture.OriginalBytes);
        var report = Simplify(env, dryRun: false);
        Assert.Contains("Big.Table::Get()", report);
        Assert.Equal(before, Run(env.Fixture.GetImageBytes()));
    }
}
