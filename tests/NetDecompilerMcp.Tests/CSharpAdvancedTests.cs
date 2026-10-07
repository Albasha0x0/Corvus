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
        Patch("Player::SumPositive", "return values.Where(v => v % 2 == 0).Select(v => v * _health).Sum();");
        using var run = new Runner(_env);
        var player = run.New("Fixture.Game.Player", "p");
        Assert.Equal(600, run.Call(player, "SumPositive", new List<int> { 1, 2, 3, 4 }));
    }

    [Fact]
    public void ClosureOverLocalsAndParameters()
    {
        Patch("Shop::PriceOf(string, int)", "int bonus = quantity + 1; Func<int, int> f = x => x * bonus; return f(PriceOf(item));");
        using var run = new Runner(_env);
        Assert.Equal(90, run.Call(run.New("Fixture.Game.Shop"), "PriceOf", "sword", 2));
    }

    [Fact]
    public async Task AsyncStateMachine()
    {
        Patch("Player::LoadAsync", "await Task.Delay(1); await Task.Yield(); return Health + 1;");
        Assert.Contains("await", _env.Decompile("Player::LoadAsync"));
        using var run = new Runner(_env);
        var task = (Task<int>)run.Call(run.New("Fixture.Game.Player", "p"), "LoadAsync")!;
        Assert.Equal(101, await task);
    }

    [Fact]
    public void IteratorStateMachine()
    {
        Patch("Player::Range", "for (int i = 0; i < 3; i++) yield return i * 10;");
        using var run = new Runner(_env);
        var items = ((IEnumerable<int>)run.Call(run.New("Fixture.Game.Player", "p"), "Range")!).ToList();
        Assert.Equal([0, 10, 20], items);
    }

    [Fact]
    public void LocalFunctionsStringSwitchAndArrayInitializers()
    {
        Patch("Shop::Describe", "string Up(string s) => s.ToUpperInvariant() + \"!\"; return Up(\"ok\");");
        // A large string switch compiles to a hash switch using <PrivateImplementationDetails>.ComputeStringHash.
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
        var shop = run.New("Fixture.Game.Shop");
        Assert.Equal("OK!", run.Call(shop, "Describe"));
        Assert.Equal(5, run.Call(shop, "PriceOf", "e"));
        Assert.Equal(16, run.Call(shop, "PriceOf", "sword"));
    }

    [Fact]
    public void RepeatedPatchesGetFreshHelperNames()
    {
        Patch("Player::SumPositive", "return values.Where(v => v > 1).Sum();");
        Patch("Player::SumPositive", "return values.Where(v => v > 2).Sum();");
        Patch("Shop::PriceOf(string, int)", "return new[] { 1, 2, 3 }.Select(x => x * quantity).Sum();");
        using var run = new Runner(_env);
        Assert.Equal(7, run.Call(run.New("Fixture.Game.Player", "p"), "SumPositive", new List<int> { 1, 2, 3, 4 }));
        Assert.Equal(12, run.Call(run.New("Fixture.Game.Shop"), "PriceOf", "x", 2));
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
        Patch("Shop::Describe", "var r = new Receipt { Total = Twice(PriceOf(\"sword\", 2, 5)) }; Counter = 3; AutoValue = SumAll(1, -1, 2); return r + \"/\" + Counter + \"/\" + AutoValue;");

        using var run = new Runner(_env);
        Assert.Equal("R:110/3/3", run.Call(run.New("Fixture.Game.Shop"), "Describe"));
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
            namespace Mods
            {
                public static class Cheats
                {
                    public static int Gold(Fixture.Game.Shop shop) => shop.Gold * 10;
                    public static IEnumerable<int> Evens(int n) { for (int i = 0; i < n; i += 2) yield return i; }
                }
                public enum Mode { Off, On }
            }
            """);
        Patch("Shop::Describe", "return Mods.Cheats.Gold(this) + \":\" + string.Join(\",\", Mods.Cheats.Evens(5)) + \":\" + Mods.Mode.On;");
        using var run = new Runner(_env);
        Assert.Equal("500:0,2,4:On", run.Call(run.New("Fixture.Game.Shop"), "Describe"));
        Assert.Contains("already exists", Assert.Throws<ToolError>(() => AddTypes("namespace Mods { public static class Cheats { } }")).Message);
    }

    [Fact]
    public void PrivateMembersOfOtherTypesWorkAtRuntime()
    {
        // Shop reads Player's private field and calls its private static method: compiles with access checks off,
        // and must also pass the runtime's access checks.
        Patch("Shop::PriceOf(string)", "var p = new Player(item); Player.Log(\"x\"); return p._health + Secret.Validate(\"LICENSE-12345\").GetHashCode();");
        using var run = new Runner(_env);
        Assert.Equal(100 + true.GetHashCode(), run.Call(run.New("Fixture.Game.Shop"), "PriceOf", "a"));
    }

    [Fact]
    public void DryRunsLeaveTheAssemblyUntouched()
    {
        var preview = _env.Edit(() => _env.Edits.PatchMethodCSharp(_env.One("Player::SumPositive"), "return values.Select(v => v * 2).Sum();", true, default));
        Assert.StartsWith("Dry run", preview);
        Assert.Contains("IL_0001:", preview); // real offsets, not IL_0000 everywhere
        _env.Edits.AddMembersCSharp(_env.One("Shop", SymbolKind.Type), "public int Twice(int x) { return x * 2; }", true, default);
        _env.Edits.AddTypesCSharp(_env.Fixture, "namespace Mods { public class X { } }", true, default);
        Assert.False(_env.Fixture.IsDirty);
        Assert.Null(((dnlib.DotNet.TypeDef)_env.One("Shop", SymbolKind.Type).Member).FindMethod("Twice"));
    }
}

public class EditHistoryTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    private void Stub(string method, string value) => _env.Edit(() => _env.Edits.StubMethod(_env.One(method), value));

    [Fact]
    public void UndoLastAndMiddleEdits()
    {
        Stub("Secret::Validate", "true");
        _env.Edit(() => _env.Edits.PatchMethodCSharp(_env.One("Player::Score"), "return 7;", false, default));
        _env.Edit(() => _env.Edits.Rename(_env.One("Shop::Describe"), "Describe2"));
        Assert.Equal(3, _env.Fixture.Edits.Count);

        _env.Edit(() => _env.Edits.Undo(_env.Fixture, 2, default)); // the C# patch, in the middle
        Assert.Equal(2, _env.Fixture.Edits.Count);
        Assert.Contains("_health * 2", _env.Decompile("Player::Score"));
        Assert.Contains("return true;", _env.Decompile("Secret::Validate"));
        Assert.NotNull(_env.One("Shop::Describe2"));

        _env.Edit(() => _env.Edits.Undo(_env.Fixture, null, default)); // last: the rename
        Assert.NotNull(_env.One("Shop::Describe"));
        Assert.Single(_env.Fixture.Edits);
    }

    [Fact]
    public void UndoThatBreaksALaterEditChangesNothing()
    {
        _env.Edit(() => _env.Edits.Rename(_env.One("Secret", SymbolKind.Type), "S2"));
        _env.Edit(() => _env.Edits.PatchMethodCSharp(_env.One("Player::CheckLicense"), "return S2.Validate(\"LICENSE-OK-000\");", false, default));
        var ex = Assert.Throws<ToolError>(() => _env.Edit(() => _env.Edits.Undo(_env.Fixture, 1, default)));
        Assert.Contains("could not be re-applied", ex.Message);
        Assert.Equal(2, _env.Fixture.Edits.Count);
        Assert.Contains("S2.Validate", _env.Decompile("Player::CheckLicense"));
    }

    [Fact]
    public void RevertAllAndUndoErrors()
    {
        Assert.Throws<ToolError>(() => _env.Edit(() => _env.Edits.Undo(_env.Fixture, null, default)));
        Stub("Secret::Validate", "true");
        Assert.Throws<ToolError>(() => _env.Edit(() => _env.Edits.Undo(_env.Fixture, 5, default)));
        _env.Edit(() => _env.Edits.RevertAll(_env.Fixture, default));
        Assert.False(_env.Fixture.IsDirty);
        Assert.Contains("StartsWith", _env.Decompile("Secret::Validate"));
    }

    [Fact]
    public void DiffShowsBeforeAndAfter()
    {
        _env.Edit(() => _env.Edits.PatchMethodCSharp(_env.One("Player::Score"), "return _health * 3;", false, default));
        _env.Edit(() => _env.Edits.AddMembersCSharp(_env.One("Shop", SymbolKind.Type), "public int Twice(int x) { return x * 2; }", false, default));
        var diff = _env.History.Diff(_env.Fixture, null, default);
        Assert.Contains("-\treturn _health * 2;", diff);
        Assert.Contains("+\treturn _health * 3;", diff);
        Assert.Contains("(did not exist)", diff);
        Assert.Contains("+public int Twice(int x)", diff);
        Assert.Contains("#2 add_members_csharp", _env.History.Diff(_env.Fixture, 2, default));
        Assert.Contains("#1", _env.History.List(_env.Fixture));
    }

    [Fact]
    public void ScriptsReplayOnAFreshLoadByTokenAndByName()
    {
        Stub("Secret::Validate", "true");
        _env.Edit(() => _env.Edits.Rename(_env.One("Shop::Describe"), "Summary"));
        _env.Edit(() => _env.Edits.PatchMethodCSharp(_env.One("Player::SumPositive"), "return values.Count(v => v > 0) * 1000;", false, default));
        _env.Edit(() => _env.Edits.AddTypesCSharp(_env.Fixture, "namespace Mods { public static class M { public static int One() => 1; } }", false, default));
        using var dir = new TempDir();
        var script = dir.File("edits.json");
        _env.History.Export(_env.Fixture, script);

        foreach (var byName in new[] { false, true })
        {
            if (byName) File.WriteAllText(script, File.ReadAllText(script).Replace("\"mvid\"", "\"mvidIgnored\"")); // force name resolution
            using var fresh = new Env();
            var report = fresh.Edit(() => fresh.History.Apply(script, null, dryRun: false, stopOnError: true, default));
            Assert.Contains("4 applied", report);
            Assert.Contains(byName ? "resolving symbols by name" : "using recorded tokens", report);
            using var run = new Runner(fresh);
            Assert.Equal(3000, run.Call(run.New("Fixture.Game.Player", "p"), "SumPositive", new List<int> { 1, 2, -3, 4 }));
            Assert.Equal(1, run.CallStatic("Mods.M", "One"));
        }
    }

    [Fact]
    public void ScriptFailuresRollBackAndDryRunChecksTargets()
    {
        Stub("Secret::Validate", "true");
        Stub("Player::Score", "5");
        using var dir = new TempDir();
        var script = dir.File("edits.json");
        _env.History.Export(_env.Fixture, script);
        File.WriteAllText(script, File.ReadAllText(script).Replace("Player::Score", "Player::NoSuchMethod").Replace("\"mvid\"", "\"x\""));

        using var fresh = new Env();
        var dry = fresh.History.Apply(script, null, dryRun: true, stopOnError: true, default);
        Assert.Contains("#1 ok", dry);
        Assert.Contains("#2 FAILED", dry);
        var report = fresh.Edit(() => fresh.History.Apply(script, null, dryRun: false, stopOnError: true, default));
        Assert.Contains("rolled back", report);
        Assert.False(fresh.Fixture.IsDirty);
        var lenient = fresh.Edit(() => fresh.History.Apply(script, null, dryRun: false, stopOnError: false, default));
        Assert.Contains("1 applied", lenient);
        Assert.Single(fresh.Fixture.Edits);
    }
}
