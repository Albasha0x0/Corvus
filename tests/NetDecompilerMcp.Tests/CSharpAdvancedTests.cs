using System.Reflection;
using System.Runtime.Loader;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Tests;

/// <summary>Executes patched assemblies to prove the merged IL runs, not just that it compiles.</summary>
public sealed class Runner : IDisposable
{
    private readonly AssemblyLoadContext _context;
    private readonly TempDir _dir = new();

    public Assembly Assembly { get; }

    public Runner(Env env)
    {
        var path = _dir.File(Path.GetFileName(env.Fixture.FilePath));
        env.Edits.Save(env.Fixture, path, overwrite: false);
        _context = new AssemblyLoadContext("run-" + Guid.NewGuid().ToString("N"), isCollectible: true);
        Assembly = _context.LoadFromStream(new MemoryStream(File.ReadAllBytes(path)));
    }

    public object New(string type, params object?[] args) => Activator.CreateInstance(Assembly.GetType(type, throwOnError: true)!, args)!;

    public object? Call(object instance, string method, params object?[] args)
    {
        var m = instance.GetType().GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            .First(x => x.Name == method && x.GetParameters().Length == args.Length);
        return m.Invoke(instance, args);
    }

    public object? CallStatic(string type, string method, params object?[] args) =>
        Assembly.GetType(type, throwOnError: true)!.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
            .First(x => x.Name == method && x.GetParameters().Length == args.Length).Invoke(null, args);

    public void Dispose()
    {
        _context.Unload();
        _dir.Dispose();
    }
}

public class CSharpAdvancedTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    private string Patch(string method, string code) => _env.Edit(() => _env.Edits.PatchMethodCSharp(_env.One(method), code, false, default));

    private string AddMembers(string type, string code) => _env.Edit(() => _env.Edits.AddMembersCSharp(_env.One(type, SymbolKind.Type), code, false, default));

    private string AddTypes(string code) => _env.Edit(() => _env.Edits.AddTypesCSharp(_env.Fixture, code, false, default));

    [Fact]
    public void LambdasLinqAndCapturedThis()
    {
        Patch("Account::SumPositive", "return values.Where(v => v % 2 == 0).Select(v => v * _balance).Sum();");
        using var run = new Runner(_env);
        var account = run.New("Fixture.Model.Account", "p");
        Assert.Equal(600, run.Call(account, "SumPositive", new List<int> { 1, 2, 3, 4 }));
    }

    [Fact]
    public void ClosureOverLocalsAndParameters()
    {
        Patch("Shop::PriceOf(string, int)", "int bonus = quantity + 1; Func<int, int> f = x => x * bonus; return f(PriceOf(item));");
        using var run = new Runner(_env);
        Assert.Equal(90, run.Call(run.New("Fixture.Model.Shop"), "PriceOf", "pen", 2));
    }

    [Fact]
    public async Task AsyncStateMachine()
    {
        Patch("Account::LoadAsync", "await Task.Delay(1); await Task.Yield(); return Balance + 1;");
        Assert.Contains("await", _env.Decompile("Account::LoadAsync"));
        using var run = new Runner(_env);
        var task = (Task<int>)run.Call(run.New("Fixture.Model.Account", "p"), "LoadAsync")!;
        Assert.Equal(101, await task);
    }

    [Fact]
    public void IteratorStateMachine()
    {
        Patch("Account::Range", "for (int i = 0; i < 3; i++) yield return i * 10;");
        using var run = new Runner(_env);
        var items = ((IEnumerable<int>)run.Call(run.New("Fixture.Model.Account", "p"), "Range")!).ToList();
        Assert.Equal([0, 10, 20], items);
    }

    [Fact]
    public void LocalFunctionsStringSwitchAndArrayInitializers()
    {
        Patch("Shop::Describe", "string Up(string s) => s.ToUpperInvariant() + \"!\"; return Up(\"ok\");");
        // Large enough to compile to a hash switch using <PrivateImplementationDetails>.ComputeStringHash.
        Patch("Shop::PriceOf(string)", """
            switch (item)
            {
                case "a": return 1; case "b": return 2; case "c": return 3; case "d": return 4;
                case "e": return 5; case "f": return 6; case "g": return 7; case "h": return 8;
                default:
                    int[] table = { 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22 };
                    return table[item.Length];
            }
            """);
        using var run = new Runner(_env);
        var shop = run.New("Fixture.Model.Shop");
        Assert.Equal("OK!", run.Call(shop, "Describe"));
        Assert.Equal(5, run.Call(shop, "PriceOf", "e"));
        Assert.Equal(14, run.Call(shop, "PriceOf", "pen"));
    }

    [Fact]
    public void RepeatedPatchesGetFreshHelperNames()
    {
        Patch("Account::SumPositive", "return values.Where(v => v > 1).Sum();");
        Patch("Account::SumPositive", "return values.Where(v => v > 2).Sum();");
        Patch("Shop::PriceOf(string, int)", "return new[] { 1, 2, 3 }.Select(x => x * quantity).Sum();");
        using var run = new Runner(_env);
        Assert.Equal(7, run.Call(run.New("Fixture.Model.Account", "p"), "SumPositive", new List<int> { 1, 2, 3, 4 }));
        Assert.Equal(12, run.Call(run.New("Fixture.Model.Shop"), "PriceOf", "x", 2));
    }

    [Fact]
    public void AddMembersAndUseThemFromAPatch()
    {
        var result = AddMembers("Shop", """
            public int Twice(int x) { return x * 2; }
            private static int _counter;
            public int Counter { get { return _counter; } set { _counter = value; } }
            public int AutoValue { get; set; }
            public int PriceOf(string item, int quantity, int discount) { return PriceOf(item, quantity) - discount; }
            public int SumAll(params int[] values) => values.Where(v => v > 0).Sum();
            public class Receipt { public int Total; public override string ToString() => "R:" + Total; }
            """);
        Assert.Contains("Twice", result);
        Patch("Shop::Describe", "var r = new Receipt { Total = Twice(PriceOf(\"pen\", 2, 5)) }; Counter = 3; AutoValue = SumAll(1, -1, 2); return r + \"/\" + Counter + \"/\" + AutoValue;");

        using var run = new Runner(_env);
        Assert.Equal("R:110/3/3", run.Call(run.New("Fixture.Model.Shop"), "Describe"));
    }

    [Fact]
    public void AddMembersRejectsDuplicatesAndInitializers()
    {
        Assert.Contains("CS0111", Assert.Throws<ToolError>(() => AddMembers("Shop", "public bool Buy(string item) { return true; }")).Message);
        Assert.Contains("Initializers", Assert.Throws<ToolError>(() => AddMembers("Shop", "private int _x = 5;")).Message);
        Assert.Contains("do not parse", Assert.Throws<ToolError>(() => AddMembers("Shop", "this is not C#")).Message);
        Assert.False(_env.Fixture.IsDirty);
    }

    [Fact]
    public void AddTypesThatUseTheAssembly()
    {
        AddTypes("""
            namespace Extensions
            {
                public static class Helpers
                {
                    public static int Credit(Fixture.Model.Shop shop) => shop.Credit * 10;
                    public static IEnumerable<int> Evens(int n) { for (int i = 0; i < n; i += 2) yield return i; }
                }
                public enum Mode { Off, On }
            }
            """);
        Patch("Shop::Describe", "return Extensions.Helpers.Credit(this) + \":\" + string.Join(\",\", Extensions.Helpers.Evens(5)) + \":\" + Extensions.Mode.On;");
        using var run = new Runner(_env);
        Assert.Equal("500:0,2,4:On", run.Call(run.New("Fixture.Model.Shop"), "Describe"));
        Assert.Contains("already exists", Assert.Throws<ToolError>(() => AddTypes("namespace Extensions { public static class Helpers { } }")).Message);
    }

    [Fact]
    public void PrivateMembersOfOtherTypesWorkAtRuntime()
    {
        // Compiled with access checks off; the runtime must still accept the private accesses.
        Patch("Shop::PriceOf(string)", "var p = new Account(item); Account.Log(\"x\"); return p._balance + Secret.Validate(\"LICENSE-12345\").GetHashCode();");
        using var run = new Runner(_env);
        Assert.Equal(100 + true.GetHashCode(), run.Call(run.New("Fixture.Model.Shop"), "PriceOf", "a"));
    }

    [Fact]
    public void DryRunsLeaveTheAssemblyUntouched()
    {
        var preview = _env.Edit(() => _env.Edits.PatchMethodCSharp(_env.One("Account::SumPositive"), "return values.Select(v => v * 2).Sum();", true, default));
        Assert.StartsWith("Dry run", preview);
        Assert.Contains("IL_0001:", preview); // real offsets, not IL_0000 everywhere
        _env.Edits.AddMembersCSharp(_env.One("Shop", SymbolKind.Type), "public int Twice(int x) { return x * 2; }", true, default);
        _env.Edits.AddTypesCSharp(_env.Fixture, "namespace Extensions { public class X { } }", true, default);
        Assert.False(_env.Fixture.IsDirty);
        Assert.Null(((dnlib.DotNet.TypeDef)_env.One("Shop", SymbolKind.Type).Member).FindMethod("Twice"));
    }
}
