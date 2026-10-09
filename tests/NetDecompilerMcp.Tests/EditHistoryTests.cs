using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Tests;

public class EditHistoryTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    private void Stub(string method, string value) => _env.Edit(() => _env.Edits.StubMethod(_env.One(method), value));

    [Trait("Speed", "Slow")]
    [Fact]
    public void UndoLastAndMiddleEdits()
    {
        Stub("Secret::Validate", "true");
        _env.Edit(() => _env.Edits.PatchMethodCSharp(_env.One("Account::Score"), "return 7;", false, default));
        _env.Edit(() => _env.Edits.Rename(_env.One("Shop::Describe"), "Describe2"));
        Assert.Equal(3, _env.Fixture.Edits.Count);

        _env.Edit(() => _env.Edits.Undo(_env.Fixture, 2, default)); // the C# patch, in the middle
        Assert.Equal(2, _env.Fixture.Edits.Count);
        Assert.Contains("_balance * 2", _env.Decompile("Account::Score"));
        Assert.Contains("return true;", _env.Decompile("Secret::Validate"));
        Assert.NotNull(_env.One("Shop::Describe2"));

        _env.Edit(() => _env.Edits.Undo(_env.Fixture, null, default)); // last: the rename
        Assert.NotNull(_env.One("Shop::Describe"));
        Assert.Single(_env.Fixture.Edits);
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public void UndoThatBreaksALaterEditChangesNothing()
    {
        _env.Edit(() => _env.Edits.Rename(_env.One("Secret", SymbolKind.Type), "S2"));
        _env.Edit(() => _env.Edits.PatchMethodCSharp(_env.One("Account::CheckLicense"), "return S2.Validate(\"LICENSE-OK-000\");", false, default));
        var ex = Assert.Throws<ToolError>(() => _env.Edit(() => _env.Edits.Undo(_env.Fixture, 1, default)));
        Assert.Contains("could not be re-applied", ex.Message);
        Assert.Equal(2, _env.Fixture.Edits.Count);
        Assert.Contains("S2.Validate", _env.Decompile("Account::CheckLicense"));
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

    [Trait("Speed", "Slow")]
    [Fact]
    public void DiffShowsBeforeAndAfter()
    {
        _env.Edit(() => _env.Edits.PatchMethodCSharp(_env.One("Account::Score"), "return _balance * 3;", false, default));
        _env.Edit(() => _env.Edits.AddMembersCSharp(_env.One("Shop", SymbolKind.Type), "public int Twice(int x) { return x * 2; }", false, default));
        var diff = _env.History.Diff(_env.Fixture, null, default);
        Assert.Contains("-\treturn _balance * 2;", diff);
        Assert.Contains("+\treturn _balance * 3;", diff);
        Assert.Contains("(did not exist)", diff);
        Assert.Contains("+public int Twice(int x)", diff);
        Assert.Contains("#2 add_members_csharp", _env.History.Diff(_env.Fixture, 2, default));
        Assert.Contains("#1", _env.History.List(_env.Fixture));
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public void ScriptsReplayOnAFreshLoadByTokenAndByName()
    {
        Stub("Secret::Validate", "true");
        _env.Edit(() => _env.Edits.Rename(_env.One("Shop::Describe"), "Summary"));
        _env.Edit(() => _env.Edits.PatchMethodCSharp(_env.One("Account::SumPositive"), "return values.Count(v => v > 0) * 1000;", false, default));
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
            Assert.Equal(3000, run.Call(run.New("Fixture.Model.Account", "p"), "SumPositive", new List<int> { 1, 2, -3, 4 }));
            Assert.Equal(1, run.CallStatic("Mods.M", "One"));
        }
    }

    [Fact]
    public void ScriptFailuresRollBackAndDryRunChecksTargets()
    {
        Stub("Secret::Validate", "true");
        Stub("Account::Score", "5");
        using var dir = new TempDir();
        var script = dir.File("edits.json");
        _env.History.Export(_env.Fixture, script);
        File.WriteAllText(script, File.ReadAllText(script).Replace("Account::Score", "Account::NoSuchMethod").Replace("\"mvid\"", "\"x\""));

        using var fresh = new Env();
        var dry = fresh.Edit(() => fresh.History.Apply(script, null, dryRun: true, stopOnError: true, default));
        Assert.False(fresh.Fixture.IsDirty); // #1 was applied for the check, then rolled back
        Assert.Contains("#1 ok", dry);
        Assert.Contains("#2 FAILED", dry);
        var report = fresh.Edit(() => fresh.History.Apply(script, null, dryRun: false, stopOnError: true, default));
        Assert.Contains("rolled back", report);
        Assert.False(fresh.Fixture.IsDirty);
        var lenient = fresh.Edit(() => fresh.History.Apply(script, null, dryRun: false, stopOnError: false, default));
        Assert.Contains("1 applied", lenient);
        Assert.Single(fresh.Fixture.Edits);
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public void DryRunCompilesCSharpEdits_AndShowsTheFullError()
    {
        // #2 depends on #1; #3 will not compile on the target.
        _env.Edit(() => _env.Edits.AddMembersCSharp(_env.One("Fixture.Model.Account", Core.SymbolKind.Type), "public int Bonus() => 7;", false, default));
        _env.Edit(() => _env.Edits.PatchMethodCSharp(_env.One("Account::SumPositive"), "return values.Count(v => v > 0) + Bonus();", false, default));
        _env.Edit(() => _env.Edits.PatchMethodCSharp(_env.One("Account::Score"), "return 11;", false, default));
        using var dir = new TempDir();
        var script = dir.File("edits.json");
        _env.History.Export(_env.Fixture, script);
        File.WriteAllText(script, File.ReadAllText(script).Replace("return 11;", "return NoSuchHelper(11);"));

        using var fresh = new Env();
        var dry = fresh.Edit(() => fresh.History.Apply(script, null, dryRun: true, stopOnError: true, default));
        Assert.Contains("#1 ok", dry);
        Assert.Contains("#2 ok", dry);
        Assert.Contains("#3 FAILED", dry);
        Assert.Contains("C# compilation failed", dry);
        Assert.Contains("CS0103", dry);                 // the compiler error itself, past the first line
        Assert.Contains("NoSuchHelper", dry);
        Assert.Contains("2 would apply, 1 would fail", dry);
        Assert.False(fresh.Fixture.IsDirty);
        Assert.DoesNotContain("Bonus", fresh.Decompile("Fixture.Model.Account"));

        // A dry run rolls back to the existing edits, not to the loaded file.
        fresh.Edit(() => fresh.Edits.StubMethod(fresh.One("Secret::Validate"), "true"));
        fresh.Edit(() => fresh.History.Apply(script, null, dryRun: true, stopOnError: false, default));
        Assert.Equal("stub_method", Assert.Single(fresh.Fixture.Edits).Kind);
    }
}
