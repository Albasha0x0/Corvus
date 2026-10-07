using dnlib.DotNet;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

/// <summary>A fresh workspace with the fixture assembly loaded.</summary>
public sealed class Env : IDisposable
{
    public static readonly string FixturePath = typeof(Fixture.Game.Player).Assembly.Location;

    public ServerOptions Options { get; } = new() { TimeoutSeconds = 60 };
    public AssemblyWorkspace Workspace { get; }
    public DecompilerService Decompiler { get; }
    public AnalysisService Analysis { get; }
    public Il2CppService Il2Cpp { get; }
    public ResourceService Resources { get; } = new();
    public EditService Edits { get; }
    public LoadedAssembly Fixture { get; }

    public Env(string? path = null)
    {
        Workspace = new AssemblyWorkspace(Options);
        Decompiler = new DecompilerService(Workspace, Options);
        Analysis = new AnalysisService(Workspace);
        Il2Cpp = new Il2CppService(Workspace);
        Edits = new EditService(new IlAssembler(Workspace));
        Fixture = Workspace.Load(path ?? FixturePath);
    }

    public ResolvedSymbol One(string symbol, SymbolKind kind = SymbolKind.Any) => SymbolResolver.ResolveOne(Workspace, null, symbol, kind);

    public void Dispose() => Workspace.Dispose();
}

public class SymbolResolutionTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    [Theory]
    [InlineData("Fixture.Game.Player", "Fixture.Game.Player")]
    [InlineData("Player", "Fixture.Game.Player")]
    [InlineData("player", "Fixture.Game.Player")]
    [InlineData("Fixture.Game.Player+Inventory", "Fixture.Game.Player/Inventory")]
    [InlineData("Fixture.Game.Player/Inventory", "Fixture.Game.Player/Inventory")]
    [InlineData("Fixture.Game.Player.Inventory", "Fixture.Game.Player/Inventory")]
    [InlineData("Player.Inventory", "Fixture.Game.Player/Inventory")]
    [InlineData("Container<T>", "Fixture.Game.Container`1")]
    [InlineData("Fixture.Game.Container`1", "Fixture.Game.Container`1")]
    [InlineData("Container", "Fixture.Game.Container`1")]
    public void ResolvesTypeForms(string query, string expected)
    {
        var r = _env.One(query, SymbolKind.Type);
        Assert.Equal(expected, ((TypeDef)r.Member).FullName);
    }

    [Theory]
    [InlineData("Fixture.Game.Player::CheckLicense")]
    [InlineData("Fixture.Game.Player.CheckLicense")]
    [InlineData("Player::CheckLicense")]
    [InlineData("Player.CheckLicense()")]
    public void ResolvesMethodForms(string query)
    {
        var r = _env.One(query);
        Assert.Equal("CheckLicense", r.Member.Name);
    }

    [Fact]
    public void OverloadsAreAllReturnedAndSignatureNarrows()
    {
        var all = SymbolResolver.Resolve(_env.Workspace, null, "Player::TakeDamage");
        Assert.Equal(2, all.Count);
        var one = _env.One("Player::TakeDamage(int, string)");
        Assert.Equal(2, ((MethodDef)one.Member).MethodSig.Params.Count);
        var full = _env.One("Player::TakeDamage(System.Int32)");
        Assert.Single(((MethodDef)full.Member).MethodSig.Params);
        Assert.Throws<ToolError>(() => _env.One("Player::TakeDamage"));
    }

    [Theory]
    [InlineData("Player::.ctor")]
    [InlineData("Player::ctor")]
    [InlineData("Fixture.Game.Player..ctor")]
    public void ResolvesConstructors(string query) => Assert.True(((MethodDef)_env.One(query).Member).IsConstructor);

    [Fact]
    public void ResolvesTokens()
    {
        var player = (TypeDef)_env.One("Player").Member;
        var byToken = _env.One($"0x{player.MDToken.Raw:X8}");
        Assert.Same(player, byToken.Member);
        var method = player.FindMethod("CheckLicense");
        Assert.Same(method, _env.One($"{method.MDToken.Raw:X8}").Member);
    }

    [Fact]
    public void PropertiesFieldsAndEvents()
    {
        Assert.IsAssignableFrom<PropertyDef>(_env.One("Player::Health").Member);
        Assert.IsAssignableFrom<FieldDef>(_env.One("Player::_health").Member);
        Assert.IsAssignableFrom<EventDef>(_env.One("Player::Died").Member);
    }

    [Fact]
    public void NotFoundGivesSuggestions()
    {
        var ex = Assert.Throws<ToolError>(() => _env.One("Player::TakeDmg"));
        Assert.Contains("TakeDamage", ex.Message);
        var ex2 = Assert.Throws<ToolError>(() => _env.One("Fixture.Game.Playr"));
        Assert.Contains("not found", ex2.Message);
    }

    [Fact]
    public void UnknownAssemblyListsLoaded()
    {
        var ex = Assert.Throws<ToolError>(() => SymbolResolver.Resolve(_env.Workspace, "Nope", "Player"));
        Assert.Contains("TestFixture", ex.Message);
    }
}

public class DecompilerTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    [Fact]
    public void DecompilesType()
    {
        var sym = _env.One("Player", SymbolKind.Type);
        var code = _env.Decompiler.DecompileType(sym.Assembly, (TypeDef)sym.Member, default);
        Assert.Contains("public class Player : Entity, IDamageable", code);
        Assert.Contains("TakeDamage(int amount, string source)", code);
        Assert.Contains("class Inventory", code);
    }

    [Fact]
    public void DecompilesAsyncAndIteratorBackToSource()
    {
        var asyncCode = _env.Decompiler.DecompileMembers(_env.Fixture, [_env.One("Player::LoadAsync").Member], default);
        Assert.Contains("await Task.Delay(1)", asyncCode);
        var iterator = _env.Decompiler.DecompileMembers(_env.Fixture, [_env.One("Player::Range").Member], default);
        Assert.Contains("yield return 1", iterator);
        var lambda = _env.Decompiler.DecompileMembers(_env.Fixture, [_env.One("Player::SumPositive").Member], default);
        Assert.Contains("v > 0", lambda);
    }

    [Fact]
    public void DisassemblesIL()
    {
        var il = _env.Decompiler.Disassemble(_env.Fixture, _env.One("Player::CheckLicense").Member, default);
        Assert.Contains("ldstr \"LICENSE-KEY-123\"", il);
        Assert.Contains("IL_0000", il);
    }

    [Fact]
    public void ExportsProject()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ndm-export-" + Guid.NewGuid().ToString("N"));
        try
        {
            var result = _env.Decompiler.ExportProject(_env.Fixture, dir, default);
            Assert.NotNull(result.ProjectFile);
            Assert.True(result.FileCount > 3);
            Assert.Throws<ToolError>(() => _env.Decompiler.ExportProject(_env.Fixture, dir, default)); // not empty any more
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void AssemblyAttributes()
    {
        var text = _env.Decompiler.DecompileAssemblyAttributes(_env.Fixture, default);
        Assert.Contains("TargetFramework", text);
    }
}

public class AnalysisTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    private static string Labels(IEnumerable<AnalysisService.Reference> refs) =>
        string.Join("\n", refs.Select(r => $"{Format.MemberLabel(r.Where)} {r.Kind} {r.Detail}"));

    [Fact]
    public void SearchSymbolsSubstringWildcardRegex()
    {
        var scope = _env.Workspace.Assemblies;
        var r = _env.Analysis.SearchSymbols("damage", false, SymbolKind.Any, scope, null, 100, default);
        Assert.Contains(r.Items, s => s.Member.Name == "TakeDamage");
        Assert.Contains(r.Items, s => s.Member.Name == "IDamageable");
        var w = _env.Analysis.SearchSymbols("Take*", false, SymbolKind.Method, scope, null, 100, default);
        Assert.All(w.Items, s => Assert.StartsWith("Take", s.Member.Name));
        var re = _env.Analysis.SearchSymbols("^Check.*e$", true, SymbolKind.Method, scope, null, 100, default);
        Assert.Single(re.Items);
        Assert.Throws<ToolError>(() => _env.Analysis.SearchSymbols("(", true, SymbolKind.Any, scope, null, 10, default));
    }

    [Fact]
    public void SearchStringsFindsLiteralAndUser()
    {
        var r = _env.Analysis.SearchStrings("license-", false, _env.Workspace.Assemblies, 50, default);
        Assert.Contains(r.Items, h => h.Owner.Name == "CheckLicense" && h.ILOffset != null);
        Assert.Contains(r.Items, h => h.Owner.Name == "Validate");
    }

    [Fact]
    public void ReferencesToMethod()
    {
        var r = _env.Analysis.FindReferences(_env.One("Secret::Validate"), 100, default);
        Assert.Single(r.Items);
        Assert.Equal("CheckLicense", r.Items[0].Where.Name);
        Assert.Equal("call", r.Items[0].Kind);
    }

    [Fact]
    public void ReferencesToFieldDistinguishReadsAndWrites()
    {
        var r = _env.Analysis.FindReferences(_env.One("Player::_health"), 100, default);
        var text = Labels(r.Items);
        Assert.Contains(r.Items, i => i.Kind == "write" && i.Where.Name == "set_Health");
        Assert.Contains(r.Items, i => i.Kind == "read" && i.Where.Name == "get_IsAlive");
        Assert.Contains(r.Items, i => i.Kind == "write" && i.Where.Name == ".ctor");
        Assert.True(r.Total >= 6, text);
    }

    [Fact]
    public void ReferencesToPropertyAndEvent()
    {
        var p = _env.Analysis.FindReferences(_env.One("Player::Health"), 100, default);
        Assert.Contains(p.Items, i => i.Kind == "get" && i.Where.Name == "MoveNext"); // inside LoadAsync's state machine
        var e = _env.Analysis.FindReferences(_env.One("Fixture.Game.Player::Died", SymbolKind.Event), 100, default);
        Assert.Empty(e.Items); // raised via the backing field, not via add/remove
    }

    [Fact]
    public void ReferencesToType()
    {
        var r = _env.Analysis.FindReferences(_env.One("IDamageable", SymbolKind.Type), 100, default);
        Assert.Contains(r.Items, i => i.Kind == "implements" && i.Where.Name == "Player");
        var player = _env.Analysis.FindReferences(_env.One("Player", SymbolKind.Type), 100, default);
        Assert.Contains(player.Items, i => i.Kind == "base type" && i.Where.Name == "Boss");
    }

    [Fact]
    public void Callees()
    {
        var list = _env.Analysis.FindCallees((MethodDef)_env.One("Player::TakeDamage(int, string)").Member);
        Assert.Contains(list, c => c.Target.Contains("::Log("));
        Assert.Contains(list, c => c.Target.Contains("::TakeDamage(int)"));
        Assert.Contains(list, c => c.Kind == "string" && c.Target.Contains("hit by"));
    }

    [Fact]
    public void OverridesAndImplementations()
    {
        var score = _env.Analysis.FindOverrides((MethodDef)_env.One("Entity::Score").Member, default);
        Assert.Equal(["Boss", "Player"], score.Select(s => ((MethodDef)s.Member).DeclaringType.Name.String).Order());
        var iface = _env.Analysis.FindOverrides((MethodDef)_env.One("IDamageable::TakeDamage").Member, default);
        Assert.Contains(iface, s => ((MethodDef)s.Member).DeclaringType.Name == "Player");
        Assert.Throws<ToolError>(() => _env.Analysis.FindOverrides((MethodDef)_env.One("Player::CheckLicense").Member, default));
    }

    [Fact]
    public void Hierarchy()
    {
        var h = _env.Analysis.GetHierarchy((TypeDef)_env.One("Player", SymbolKind.Type).Member, 100, default);
        Assert.StartsWith("Fixture.Game.Entity", h.BaseChain[0]);
        Assert.Contains("Fixture.Game.IDamageable", h.Interfaces);
        Assert.Single(h.Derived);
    }
}

public class Il2CppAndResourceTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    [Fact]
    public void ReadsAddressAttributes()
    {
        var attrs = Il2CppService.GetAttributes(_env.One("NativeThing::Second").Member);
        var addr = Assert.Single(attrs);
        Assert.Equal("0x1100", addr.Values["RVA"]);
        Assert.Equal("4", addr.Values["Slot"]);
        Assert.Equal("0x10", Il2CppService.GetAttributes(_env.One("NativeThing::Counter").Member).Single().Values["Offset"]);
    }

    [Theory]
    [InlineData(0x1000UL, "rva", "First", "exact start")]
    [InlineData(0x1050UL, "rva", "First", "probably inside")]
    [InlineData(0x180001100UL, "va", "Second", "exact start")]
    [InlineData(0x500UL, "offset", "Second", "exact start")]
    public void FindsMethodByAddress(ulong address, string kind, string method, string relation)
    {
        var m = Assert.Single(_env.Il2Cpp.FindByAddress(address, kind, _env.Workspace.Assemblies));
        Assert.Equal(method, m.Entry.Method.Name);
        Assert.StartsWith(relation, m.Relation);
    }

    [Theory]
    [InlineData("0x1A2B", 0x1A2BUL)]
    [InlineData("1A2B", 0x1A2BUL)]
    [InlineData("1A2Bh", 0x1A2BUL)]
    [InlineData("00000001`80001000", 0x180001000UL)]
    [InlineData("d:100", 100UL)]
    public void ParsesAddresses(string text, ulong expected) => Assert.Equal(expected, Il2CppService.ParseAddress(text));

    [Fact]
    public void ListsAndReadsResources()
    {
        var list = _env.Resources.List(_env.Fixture);
        Assert.Contains(list, r => r.Name.EndsWith("hello.txt"));
        var resx = Assert.Single(list, r => r.Name.EndsWith(".resources"));
        Assert.Equal(2, resx.EntryCount);

        var text = _env.Resources.Get(_env.Fixture, list.First(r => r.Name.EndsWith("hello.txt")).Name, null, null);
        Assert.Contains("Hello from an embedded resource.", text);
        var entries = _env.Resources.Get(_env.Fixture, resx.Name, null, null);
        Assert.Contains("Greeting", entries);
        Assert.Equal("Welcome, adventurer!", _env.Resources.Get(_env.Fixture, resx.Name, "Greeting", null));
    }
}

public class EditTests : IDisposable
{
    private readonly Env _env = new();
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ndm-edit-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        _env.Dispose();
        if (Directory.Exists(_dir)) Directory.Delete(_dir, true);
    }

    [Fact]
    public void RenameIsVisibleInDecompilationImmediately()
    {
        _env.Workspace.Write(() => _env.Edits.Rename(_env.One("Secret", SymbolKind.Type), "LicenseChecker"));
        var code = _env.Decompiler.DecompileMembers(_env.Fixture, [_env.One("Player::CheckLicense").Member], default);
        Assert.Contains("LicenseChecker.Validate", code);
        Assert.True(_env.Fixture.IsDirty);
    }

    [Fact]
    public void StubSaveAndReload()
    {
        _env.Workspace.Write(() => _env.Edits.StubMethod(_env.One("Secret::Validate"), "true"));
        _env.Workspace.Write(() => _env.Edits.StubMethod(_env.One("Player::Score"), "0x2A"));
        _env.Workspace.Write(() => _env.Edits.StubMethod(_env.One("Vec2::Length"), null));
        _env.Workspace.Write(() => _env.Edits.StubMethod(_env.One("Container::Get"), null));
        _env.Workspace.Write(() => _env.Edits.StubMethod(_env.One("Player::Tick"), null));
        Assert.Throws<ToolError>(() => _env.Workspace.Write(() => _env.Edits.StubMethod(_env.One("Player::Tick"), "1")));

        var output = Path.Combine(_dir, "Patched.dll");
        _env.Edits.Save(_env.Fixture, output, overwrite: false);
        Assert.Throws<ToolError>(() => _env.Edits.Save(_env.Fixture, output, overwrite: false));

        using var reloaded = new Env(output);
        var code = reloaded.Decompiler.DecompileMembers(reloaded.Fixture,
            [reloaded.One("Secret::Validate").Member, reloaded.One("Player::Score").Member, reloaded.One("Container::Get").Member], default);
        Assert.Contains("return true;", code);
        Assert.Contains("return 42;", code);
        Assert.Contains("return null;", code);
    }

    [Fact]
    public void SavingOverOriginalKeepsBackup()
    {
        Directory.CreateDirectory(_dir);
        var copy = Path.Combine(_dir, "Copy.dll");
        File.Copy(Env.FixturePath, copy);
        using var env = new Env(copy);
        env.Workspace.Write(() => env.Edits.Rename(env.One("Player::CheckLicense"), "IsLicensed"));
        Assert.Throws<ToolError>(() => env.Edits.Save(env.Fixture, copy, overwrite: false));
        env.Edits.Save(env.Fixture, copy, overwrite: true);
        Assert.True(File.Exists(copy + ".bak"));
        var fresh = env.Workspace.Reload(env.Fixture);
        Assert.NotNull(((TypeDef)SymbolResolver.ResolveOne(env.Workspace, null, "Player", SymbolKind.Type).Member).FindMethod("IsLicensed"));
        Assert.False(fresh.IsDirty);
    }

    [Fact]
    public void RenameNamespace()
    {
        _env.Workspace.Write(() => _env.Edits.RenameNamespace(_env.Fixture, "Fixture", "Renamed", includeSubNamespaces: true));
        Assert.Equal("Renamed.Game.Player", ((TypeDef)_env.One("Player", SymbolKind.Type).Member).FullName);
    }
}

public class WorkspaceTests
{
    [Fact]
    public void LoadIsIdempotentAndDoesNotLockFile()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ndm-ws-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var copy = Path.Combine(dir, "TestFixture.dll");
        File.Copy(Env.FixturePath, copy);
        File.WriteAllText(Path.Combine(dir, "native.dll"), "not a PE file");
        try
        {
            using var ws = new AssemblyWorkspace();
            var report = ws.LoadDirectory(dir, recursive: false);
            Assert.Single(report.Loaded);
            Assert.Single(report.Skipped);
            Assert.Same(report.Loaded[0], ws.Load(copy));
            // File is not locked: can be replaced while loaded.
            File.Copy(Env.FixturePath, copy, overwrite: true);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void DuplicateNamesGetDistinctIds()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ndm-dup-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var copy = Path.Combine(dir, "TestFixture.dll");
        File.Copy(Env.FixturePath, copy);
        try
        {
            using var ws = new AssemblyWorkspace();
            var a = ws.Load(Env.FixturePath);
            var b = ws.Load(copy);
            Assert.Equal("TestFixture", a.Id);
            Assert.Equal("TestFixture#2", b.Id);
            Assert.Throws<ToolError>(() => ws.Read(() => SymbolResolver.ResolveOne(ws, null, "Player", SymbolKind.Type)));
            Assert.Same(b, ws.Read(() => SymbolResolver.ResolveOne(ws, "TestFixture#2", "Player", SymbolKind.Type)).Assembly);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void PagerSplitsOnLinesAndReportsOffsets()
    {
        var pager = new OutputPager(new ServerOptions { MaxOutputChars = 2_000 });
        var text = string.Join("\n", Enumerable.Range(0, 500).Select(i => $"line {i:D4}"));
        var first = pager.Page(text);
        Assert.Contains("Call again with offset=", first);
        int next = int.Parse(System.Text.RegularExpressions.Regex.Match(first, @"offset=(\d+)").Groups[1].Value);
        Assert.Equal('\n', text[next - 1]);
        var second = pager.Page(text, next);
        Assert.StartsWith($"[Continuing from offset {next}]", second);
        Assert.Throws<ToolError>(() => pager.Page(text, text.Length + 5));
    }
}
