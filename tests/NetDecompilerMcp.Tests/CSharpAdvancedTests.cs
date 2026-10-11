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

    /// <summary>
    /// The target's reference copy carries only metadata (writing every body and resource made the first patch of a large
    /// assembly take seconds), grants the patch assembly its internals, drops stand-in tokens, and is written once.
    /// </summary>
    [Fact]
    public void TheTargetsReferenceCopyIsMetadataOnlyAndCached()
    {
        var image = _env.Fixture.GetImageBytes();
        var friend = Services.CSharpPatcher.FriendImage(image, "Fixture.__patch", ["System.Runtime"]);
        Assert.Same(friend, Services.CSharpPatcher.FriendImage(image, "Fixture.__patch", ["System.Runtime"]));
        using var module = dnlib.DotNet.ModuleDefMD.Load(friend);
        Assert.Contains(module.Assembly.CustomAttributes, ca => ca.TypeFullName == "System.Runtime.CompilerServices.InternalsVisibleToAttribute"
                                                                && ca.ConstructorArguments[0].Value?.ToString() == "Fixture.__patch");
        Assert.All(module.GetTypes().SelectMany(t => t.Methods), m => Assert.Equal(0u, (uint)m.RVA));
        Assert.Empty(module.Resources);
        Assert.Empty(module.GetAssemblyRefs().Single(r => r.Name == "System.Runtime").PublicKeyOrToken?.Data ?? []);
        Assert.True(friend.Length < image.Length);
    }

    /// <summary>A generic method is labeled Echo&lt;T&gt;(T); it is still listed as added, while closures stay hidden.</summary>
    [Fact]
    public void AddedGenericMembersAreListed()
    {
        var result = AddMembers("Shop", "public T Echo<T>(T x) { System.Func<T> f = () => x; return f(); }");
        Assert.Contains("Echo<T>(T)", result);
        Assert.DoesNotContain("<>", result);
    }

    /// <summary>Added members all have the token (new): decompile_member and get_il cached one's text under it and showed it for the others.</summary>
    [Fact]
    public async Task EachAddedMemberDecompilesToItself()
    {
        AddMembers("Shop", "public static int Aaa(int x) => x + 1; public static int Bbb(int x) => x + 2;");
        var tools = new NetDecompilerMcp.Tools.DecompileTools(_env.Workspace, _env.Decompiler, _env.Pager);
        Assert.Contains("x + 2", await tools.DecompileMember("Fixture.Model.Shop::Bbb"));
        Assert.Contains("x + 1", await tools.DecompileMember("Fixture.Model.Shop::Aaa"));
        Assert.Contains("ldc.i4.2", await tools.GetIL("Fixture.Model.Shop::Bbb"));
        Assert.Contains("ldc.i4.1", await tools.GetIL("Fixture.Model.Shop::Aaa"));
    }

    /// <summary>
    /// Added members of a type with a nullable context are marked oblivious (an added T Same&lt;T&gt;(T) read as where T : notnull),
    /// and attributes of added type parameters are kept.
    /// </summary>
    [Fact]
    public void AddedMembersAreNullableObliviousAndKeepTypeParameterAttributes()
    {
        AddMembers("Shop", "public static T Same<T>(T x) => x; public static U Choose<[System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicMethods)] U>(U a) => a; public static string Note;");
        var shop = (dnlib.DotNet.TypeDef)_env.One("Fixture.Model.Shop", SymbolKind.Type).Member;
        Assert.Contains(shop.Methods.Single(m => m.Name == "Same").CustomAttributes, ca => ca.TypeFullName == "System.Runtime.CompilerServices.NullableContextAttribute"
                                                                                       && ca.ConstructorArguments[0].Value is (byte)0);
        Assert.Contains(shop.Fields.Single(f => f.Name == "Note").CustomAttributes, ca => ca.TypeFullName == "System.Runtime.CompilerServices.NullableAttribute");
        Assert.DoesNotContain("notnull", _env.Decompile("Fixture.Model.Shop::Same<T>(T)"));
        var pick = shop.Methods.Single(m => m.Name == "Choose").GenericParameters[0];
        Assert.Contains(pick.CustomAttributes, ca => ca.TypeFullName == "System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembersAttribute");
    }

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

    [Trait("Speed", "Slow")]
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

    [Trait("Speed", "Slow")]
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

    [Trait("Speed", "Slow")]
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

    /// <summary>The stubbed async methods of the shadow type compiled to state machines, merged as unused copies (&lt;LoadAsync&gt;d__5$ndm1).</summary>
    [Fact]
    public void AddMembersToATypeWithAsyncMethodsAddsNoStateMachines()
    {
        var account = (dnlib.DotNet.TypeDef)_env.One("Fixture.Model.Account", SymbolKind.Type).Member;
        var nested = account.NestedTypes.Select(t => t.Name.String).ToList();
        AddMembers("Fixture.Model.Account", "public int Twice(int x) { return x * 2; }");
        Assert.Equal(nested, account.NestedTypes.Select(t => t.Name.String).ToList());
    }

    [Fact]
    public void AddMembersRejectsDuplicatesAndInitializers()
    {
        Assert.Contains("CS0111", Assert.Throws<ToolError>(() => AddMembers("Shop", "public bool Buy(string item) { return true; }")).Message);
        Assert.Contains("Initializers", Assert.Throws<ToolError>(() => AddMembers("Shop", "private int _x = 5;")).Message);
        Assert.Contains("do not parse", Assert.Throws<ToolError>(() => AddMembers("Shop", "this is not C#")).Message);
        Assert.False(_env.Fixture.IsDirty);
    }

    [Trait("Speed", "Slow")]
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
