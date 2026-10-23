using dnlib.DotNet;
using Corvus.Core;

namespace Corvus.Tests;

public class EditTests : IDisposable
{
    private readonly Env _env = new(withConsumer: true);
    private readonly TempDir _dir = new();

    public void Dispose()
    {
        _env.Dispose();
        _dir.Dispose();
    }

    [Trait("Smoke", "push")]
    [Fact]
    public void RenamesAreVisibleImmediately()
    {
        _env.Edit(() => _env.Edits.Rename(_env.One("Secret", SymbolKind.Type), "TokenValidator"));
        Assert.Contains("TokenValidator.Validate", _env.Decompile("Account::CheckPreview"));
        Assert.True(_env.Fixture.IsDirty);
        Assert.Single(_env.Fixture.Edits);
    }

    [Fact]
    public void RenamePropertyAndEventKeepsAccessorsConsistent()
    {
        _env.Edit(() => _env.Edits.Rename(_env.One("Account::Balance"), "Amount"));
        _env.Edit(() => _env.Edits.Rename(_env.One("Account::Closed", SymbolKind.Event), "Ended"));
        var account = _env.Def<TypeDef>("Account", SymbolKind.Type);
        Assert.NotNull(account.FindMethod("get_Amount"));
        Assert.NotNull(account.FindMethod("add_Ended"));
        Assert.Contains("public int Amount", _env.Decompiler.DecompileType(_env.Fixture, account, default));
        Assert.Throws<ToolError>(() => _env.Edit(() => _env.Edits.Rename(_env.One("Account::.ctor"), "Make")));
        Assert.Throws<ToolError>(() => _env.Edit(() => _env.Edits.Rename(_env.One("Account::Tick"), " ")));
    }

    [Fact]
    public void RenameKeepsTheGenericAritySuffix()
    {
        Assert.Contains("-> Box`1", _env.Edit(() => _env.Edits.Rename(_env.One("Container", SymbolKind.Type), "Box")));
        Assert.Equal("Box`1", _env.Def<TypeDef>("Box", SymbolKind.Type).Name);
        Assert.Throws<ToolError>(() => _env.Edit(() => _env.Edits.Rename(_env.One("Box", SymbolKind.Type), "Box`2")));
        _env.Edit(() => _env.Edits.AddMembersCSharp(_env.One("Box", SymbolKind.Type), "public int Twice(int x) { return x * 2; }", false, default));
        Assert.Contains("Twice", _env.Decompile("Fixture.Model.Box`1"));
    }

    [Fact]
    public void StubWithoutBodyNamesWhereTheCodeIs()
    {
        var abstractError = Assert.Throws<ToolError>(() => _env.Edits.StubMethod(_env.One("Entity::Tick"), null));
        Assert.Equal(ErrorCode.Unsupported, abstractError.Code);
        Assert.Contains("kind=overrides", abstractError.Remediation);

        var module = _env.Fixture.Module;
        var native = new MethodDefUser("Beep", MethodSig.CreateStatic(module.CorLibTypes.Boolean, module.CorLibTypes.UInt32, module.CorLibTypes.UInt32),
            MethodImplAttributes.PreserveSig, MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl | MethodAttributes.HideBySig)
        {
            ImplMap = new ImplMapUser(new ModuleRefUser(module, "kernel32.dll"), "Beep", PInvokeAttributes.CallConvWinapi),
        };
        _env.Def<TypeDef>("Account", SymbolKind.Type).Methods.Add(native);
        var nativeError = Assert.Throws<ToolError>(() => _env.Edits.StubMethod(new ResolvedSymbol(_env.Fixture, native), "true"));
        Assert.StartsWith("the body is native: 'Beep' in kernel32.dll", nativeError.Remediation);
        Assert.Contains("patch_bytes", nativeError.Remediation);
    }

    [Fact]
    public void StubsEveryReturnKind()
    {
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Secret::Validate"), "true"));
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Account::Score"), "0x2A"));
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Vec2::Length"), "1.5"));
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Container::Get"), null));
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Shop::Describe"), "\"patched\""));
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Account::Tick"), null));
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Shop::Pick"), null));
        Assert.Contains("return true;", _env.Decompile("Secret::Validate"));
        Assert.Contains("return 42;", _env.Decompile("Account::Score"));
        Assert.Contains("return 1.5f;", _env.Decompile("Vec2::Length"));
        Assert.Contains("return null;", _env.Decompile("Container::Get"));
        Assert.Contains("return \"patched\";", _env.Decompile("Shop::Describe"));
        Assert.Contains("return default", _env.Decompile("Shop::Pick"));
    }

    [Theory]
    [InlineData("Account::Tick", "1", "void")]
    [InlineData("Secret::Validate", "maybe", "not a bool")]
    [InlineData("Account::Score", "abc", "not an integer")]
    [InlineData("Shop::Create", "5", "Only null/default")]
    [InlineData("Shop::Pick", "5", "Only 'default'")]
    [InlineData("Entity::Tick", null, "no IL body")]
    [InlineData("Account::Balance", "1", "not a method")]
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
        Assert.Equal("Renamed.Model.Account", _env.Def<TypeDef>("Account", SymbolKind.Type).FullName);
        Assert.Equal("Renamed.Native.NativeThing", _env.Def<TypeDef>("NativeThing", SymbolKind.Type).FullName);
    }

    [Fact]
    public void DryRunsChangeNothing()
    {
        Assert.StartsWith("Dry run", _env.Edits.Rename(_env.One("Account", SymbolKind.Type), "Customer", dryRun: true));
        Assert.StartsWith("Dry run", _env.Edits.StubMethod(_env.One("Secret::Validate"), "true", dryRun: true));
        Assert.StartsWith("Dry run", _env.Edits.RenameNamespace(_env.Fixture, "Fixture.Model", "X", false, dryRun: true));
        Assert.False(_env.Fixture.IsDirty);
        Assert.Equal("Fixture.Model.Account", _env.Def<TypeDef>("Account", SymbolKind.Type).FullName);
        Assert.Contains("Validate(\"PREVIEW-CODE-42\")", _env.Decompile("Account::CheckPreview"));
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
    public void WriterFaultIsInternalNotIoError()
    {
        // An operand the writer cannot encode: a fault of this server, not of the disk.
        var body = _env.Def<MethodDef>("Secret::Validate").Body;
        body.Instructions.Insert(0, new dnlib.DotNet.Emit.Instruction());
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Account::Score"), "1"));
        var ex = Record.Exception(() => _env.Edits.Save(_env.Fixture, _dir.File("Broken.dll"), overwrite: false));
        Assert.NotNull(ex);
        Assert.False(ex is ToolError { Code: ErrorCode.IoError }, ex.Message);
        Assert.False(File.Exists(_dir.File("Broken.dll")));
        var result = Mcp.ErrorResult.Internal(ex, "save_assembly");
        var text = ((ModelContextProtocol.Protocol.TextContentBlock)result.Content[0]).Text;
        Assert.StartsWith("Error (internal) in save_assembly", text);
        Assert.Contains("Next: " + ToolError.InternalNext, text);
    }

    [Fact]
    public void DefaultSavePathIsPatchedSibling()
    {
        var copy = _dir.File("App.dll");
        File.Copy(Env.FixturePath, copy);
        using var env = new Env(copy);
        var message = env.Edits.Save(env.Fixture, null, overwrite: false);
        Assert.Contains("App.patched.dll", message);
        Assert.True(File.Exists(_dir.File("App.patched.dll")));
    }

    [Fact]
    public void OverwritingOriginalKeepsBackupAndReloadDiscardsEdits()
    {
        var copy = _dir.File("Copy.dll");
        File.Copy(Env.FixturePath, copy);
        using var env = new Env(copy);
        env.Edit(() => env.Edits.Rename(env.One("Account::CheckPreview"), "HasPreview"));
        Assert.Throws<ToolError>(() => env.Edits.Save(env.Fixture, copy, overwrite: true));
        env.Edits.Save(env.Fixture, copy, overwrite: false, replaceOriginal: true);
        Assert.True(File.Exists(copy + ".bak"));
        Assert.Equal(new FileInfo(Env.FixturePath).Length, new FileInfo(copy + ".bak").Length);

        var fresh = env.Workspace.Reload(env.Fixture);
        Assert.False(fresh.IsDirty);
        Assert.NotNull(env.Def<TypeDef>("Account", SymbolKind.Type).FindMethod("HasPreview"));
    }

    [Fact]
    public void TokensStayStableAcrossEditsAndSave()
    {
        var token = _env.One("Account::Charge(int)").Member.MDToken.Raw;
        _env.Edit(() => _env.Edits.Rename(_env.One("Secret", SymbolKind.Type), "S2"));
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Account::Score"), "1"));
        var output = _dir.File("Stable.dll");
        _env.Edits.Save(_env.Fixture, output, false);
        using var reloaded = new Env(output);
        Assert.Equal("Charge", reloaded.One($"0x{token:X8}").Member.Name);
    }
}
