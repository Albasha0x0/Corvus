using dnlib.DotNet;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Tests;

public class EditTests : IDisposable
{
    private readonly Env _env = new(withConsumer: true);
    private readonly TempDir _dir = new();

    public void Dispose()
    {
        _env.Dispose();
        _dir.Dispose();
    }

    [Fact]
    public void RenamesAreVisibleImmediately()
    {
        _env.Edit(() => _env.Edits.Rename(_env.One("Secret", SymbolKind.Type), "LicenseChecker"));
        Assert.Contains("LicenseChecker.Validate", _env.Decompile("Player::CheckLicense"));
        Assert.True(_env.Fixture.IsDirty);
        Assert.Single(_env.Fixture.Edits);
    }

    [Fact]
    public void RenamePropertyAndEventKeepsAccessorsConsistent()
    {
        _env.Edit(() => _env.Edits.Rename(_env.One("Player::Health"), "Hp"));
        _env.Edit(() => _env.Edits.Rename(_env.One("Player::Died", SymbolKind.Event), "Killed"));
        var player = _env.Def<TypeDef>("Player", SymbolKind.Type);
        Assert.NotNull(player.FindMethod("get_Hp"));
        Assert.NotNull(player.FindMethod("add_Killed"));
        Assert.Contains("public int Hp", _env.Decompiler.DecompileType(_env.Fixture, player, default));
        Assert.Throws<ToolError>(() => _env.Edit(() => _env.Edits.Rename(_env.One("Player::.ctor"), "Make")));
        Assert.Throws<ToolError>(() => _env.Edit(() => _env.Edits.Rename(_env.One("Player::Tick"), " ")));
    }

    [Fact]
    public void StubsEveryReturnKind()
    {
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Secret::Validate"), "true"));
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Player::Score"), "0x2A"));
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Vec2::Length"), "1.5"));
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Container::Get"), null));
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Shop::Describe"), "\"patched\""));
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Player::Tick"), null));
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Shop::Pick"), null));
        Assert.Contains("return true;", _env.Decompile("Secret::Validate"));
        Assert.Contains("return 42;", _env.Decompile("Player::Score"));
        Assert.Contains("return 1.5f;", _env.Decompile("Vec2::Length"));
        Assert.Contains("return null;", _env.Decompile("Container::Get"));
        Assert.Contains("return \"patched\";", _env.Decompile("Shop::Describe"));
        Assert.Contains("return default", _env.Decompile("Shop::Pick"));
    }

    [Theory]
    [InlineData("Player::Tick", "1", "void")]
    [InlineData("Secret::Validate", "maybe", "not a bool")]
    [InlineData("Player::Score", "abc", "not an integer")]
    [InlineData("Shop::Create", "5", "Only null/default")]
    [InlineData("Shop::Pick", "5", "Only 'default'")]
    [InlineData("Entity::Tick", null, "no IL body")]
    [InlineData("Player::Health", "1", "not a method")]
    public void StubErrors(string symbol, string? value, string expected)
    {
        var ex = Assert.Throws<ToolError>(() => _env.Edit(() => _env.Edits.StubMethod(_env.One(symbol), value)));
        Assert.Contains(expected, ex.Message);
        Assert.False(_env.Fixture.IsDirty);
    }

    [Fact]
    public void RenameNamespaceWithAndWithoutSubNamespaces()
    {
        Assert.Throws<ToolError>(() => _env.Edit(() => _env.Edits.RenameNamespace(_env.Fixture, "Nope", "X", false)));
        _env.Edit(() => _env.Edits.RenameNamespace(_env.Fixture, "Fixture", "Renamed", includeSubNamespaces: true));
        Assert.Equal("Renamed.Game.Player", _env.Def<TypeDef>("Player", SymbolKind.Type).FullName);
        Assert.Equal("Renamed.Native.NativeThing", _env.Def<TypeDef>("NativeThing", SymbolKind.Type).FullName);
    }

    [Fact]
    public void DryRunsChangeNothing()
    {
        Assert.StartsWith("Dry run", _env.Edits.Rename(_env.One("Player", SymbolKind.Type), "Hero", dryRun: true));
        Assert.StartsWith("Dry run", _env.Edits.StubMethod(_env.One("Secret::Validate"), "true", dryRun: true));
        Assert.StartsWith("Dry run", _env.Edits.RenameNamespace(_env.Fixture, "Fixture.Game", "X", false, dryRun: true));
        Assert.False(_env.Fixture.IsDirty);
        Assert.Equal("Fixture.Game.Player", _env.Def<TypeDef>("Player", SymbolKind.Type).FullName);
        Assert.Contains("Validate(\"LICENSE-KEY-123\")", _env.Decompile("Player::CheckLicense"));
    }

    [Fact]
    public void SaveWritesNewFileThatReloadsWithEdits()
    {
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Secret::Validate"), "true"));
        var output = _dir.File("Patched.dll");
        Assert.Contains("1 edit", _env.Edits.Save(_env.Fixture, output, overwrite: false));
        Assert.Throws<ToolError>(() => _env.Edits.Save(_env.Fixture, output, overwrite: false));
        _env.Edits.Save(_env.Fixture, output, overwrite: true);

        using var reloaded = new Env(output);
        Assert.Contains("return true;", reloaded.Decompile("Secret::Validate"));
        Assert.False(File.Exists(output + ".bak")); // .bak only when overwriting the original
    }

    [Fact]
    public void DefaultSavePathIsPatchedSibling()
    {
        var copy = _dir.File("Game.dll");
        File.Copy(Env.FixturePath, copy);
        using var env = new Env(copy);
        var message = env.Edits.Save(env.Fixture, null, overwrite: false);
        Assert.Contains("Game.patched.dll", message);
        Assert.True(File.Exists(_dir.File("Game.patched.dll")));
    }

    [Fact]
    public void OverwritingOriginalKeepsBackupAndReloadDiscardsEdits()
    {
        var copy = _dir.File("Copy.dll");
        File.Copy(Env.FixturePath, copy);
        using var env = new Env(copy);
        env.Edit(() => env.Edits.Rename(env.One("Player::CheckLicense"), "IsLicensed"));
        Assert.Throws<ToolError>(() => env.Edits.Save(env.Fixture, copy, overwrite: false));
        env.Edits.Save(env.Fixture, copy, overwrite: true);
        Assert.True(File.Exists(copy + ".bak"));
        Assert.Equal(new FileInfo(Env.FixturePath).Length, new FileInfo(copy + ".bak").Length);

        var fresh = env.Workspace.Reload(env.Fixture);
        Assert.False(fresh.IsDirty);
        Assert.NotNull(env.Def<TypeDef>("Player", SymbolKind.Type).FindMethod("IsLicensed"));
    }

    [Fact]
    public void TokensStayStableAcrossEditsAndSave()
    {
        var token = _env.One("Player::TakeDamage(int)").Member.MDToken.Raw;
        _env.Edit(() => _env.Edits.Rename(_env.One("Secret", SymbolKind.Type), "S2"));
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Player::Score"), "1"));
        var output = _dir.File("Stable.dll");
        _env.Edits.Save(_env.Fixture, output, false);
        using var reloaded = new Env(output);
        Assert.Equal("TakeDamage", reloaded.One($"0x{token:X8}").Member.Name);
    }
}
