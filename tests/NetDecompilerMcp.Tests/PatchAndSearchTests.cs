using dnlib.DotNet;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Tests;

public class IlPatchTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    private string Patch(string symbol, string il, string mode = "replace", bool dryRun = false) =>
        _env.Workspace.Write(() => _env.Edits.PatchMethodIL(_env.One(symbol), il, mode, dryRun));

    private string Decompile(string symbol) =>
        _env.Decompiler.DecompileMembers(_env.Fixture, [_env.One(symbol).Member], default);

    [Fact]
    public void ReplaceWithHandWrittenIL()
    {
        Patch("Secret::Validate", """
            ldarg.0                       // key
            call System.String::IsNullOrEmpty(string)
            brtrue.s fail
            ldc.i4.1
            ret
            fail:
            ldc.i4.0
            ret
            """);
        var code = Decompile("Secret::Validate");
        Assert.Contains("IsNullOrEmpty(key)", code);
        Assert.True(_env.Fixture.IsDirty);
    }

    [Fact]
    public void RoundTripsEditedGetIlOutput()
    {
        // Take get_il output verbatim, change the string literal, feed it back.
        var il = _env.Decompiler.Disassemble(_env.Fixture, _env.One("Player::TakeDamage(int, string)").Member, default);
        Patch("Player::TakeDamage(int, string)", il.Replace("\"hit by \"", "\"struck by \""));
        Assert.Contains("\"struck by \" + source", Decompile("Player::TakeDamage(int, string)"));
    }

    [Fact]
    public void ResolvesMembersFromSymbolsAndOtherTypes()
    {
        Patch("Player::CheckLicense", """
            ldstr "anything"
            call Fixture.Game.Secret::Validate(string)
            pop
            ldarg.0
            call Fixture.Game.Player::get_IsAlive()
            ret
            """);
        var code = Decompile("Player::CheckLicense");
        Assert.Contains("Secret.Validate(\"anything\")", code);
        Assert.Contains("IsAlive", code);
    }

    [Fact]
    public void PrependKeepsOriginalAndCanBranchIntoIt()
    {
        Patch("Player::TakeDamage(int)", """
            ldarg.1
            ldc.i4.0
            bge IL_0000
            ret
            """, mode: "prepend");
        var code = Decompile("Player::TakeDamage(int)");
        Assert.Contains("_health -= amount", code);
        Assert.Contains("if (amount >= 0)", code);
    }

    [Fact]
    public void NewLocalsAndDryRun()
    {
        var preview = Patch("Player::Score", """
            .local int
            ldc.i4 0x10
            stloc 0
            ldloc 0
            ret
            """, dryRun: true);
        Assert.StartsWith("Dry run", preview);
        Assert.False(_env.Fixture.IsDirty);
        Assert.Contains("_health * 2", Decompile("Player::Score")); // unchanged
    }

    [Theory]
    [InlineData("ldc.i4.1\nadd\nret", "Stack imbalance")]
    [InlineData("frobnicate\nret", "unknown opcode")]
    [InlineData("ldc.i4.1", "must end with ret")]
    [InlineData("br nowhere\nret", "undefined label")]
    [InlineData("call Nope.Missing::Thing()\nret", "cannot resolve")]
    [InlineData("ldarg 9\nret", "out of range")]
    public void RejectsBadIL(string il, string expected)
    {
        var ex = Assert.Throws<ToolError>(() => Patch("Player::Score", il));
        Assert.Contains(expected, ex.Message);
        Assert.False(_env.Fixture.IsDirty);
    }

    [Fact]
    public void PatchedAssemblySavesAndReloads()
    {
        Patch("Secret::Validate", "ldc.i4.1\nret");
        var dir = Path.Combine(Path.GetTempPath(), "ndm-patch-" + Guid.NewGuid().ToString("N"));
        try
        {
            var path = Path.Combine(dir, "p.dll");
            _env.Edits.Save(_env.Fixture, path, false);
            using var reloaded = new Env(path);
            Assert.Contains("return true;", reloaded.Decompiler.DecompileMembers(reloaded.Fixture, [reloaded.One("Secret::Validate").Member], default));
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void DryRunRenameAndStubDoNotChangeAnything()
    {
        _env.Workspace.Write(() => _env.Edits.Rename(_env.One("Player", SymbolKind.Type), "Hero", dryRun: true));
        _env.Workspace.Write(() => _env.Edits.StubMethod(_env.One("Secret::Validate"), "true", dryRun: true));
        _env.Workspace.Write(() => _env.Edits.RenameNamespace(_env.Fixture, "Fixture.Game", "X", false, dryRun: true));
        Assert.False(_env.Fixture.IsDirty);
        Assert.Equal("Fixture.Game.Player", ((TypeDef)_env.One("Player", SymbolKind.Type).Member).FullName);
    }
}

public class ConstantSearchTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    [Theory]
    [InlineData("100", "MaxHealth")]   // const field
    [InlineData("0x3E8", "Score")]     // ldc.i4 1000 in Boss.Score
    [InlineData("2", "Blue")]          // enum member
    public void FindsConstants(string value, string owner)
    {
        var r = _env.Analysis.SearchConstants(value, _env.Workspace.Assemblies, 100, default);
        Assert.Contains(r.Items, h => h.Owner.Name == owner);
    }

    [Fact]
    public void RejectsNonNumbers() =>
        Assert.Throws<ToolError>(() => _env.Analysis.SearchConstants("hello", _env.Workspace.Assemblies, 10, default));
}
