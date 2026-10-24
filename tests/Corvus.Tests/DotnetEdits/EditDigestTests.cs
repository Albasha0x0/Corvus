using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Edit content digests: the same in a dry run, the applied edit, list_edits and the save's edit list.</summary>
public sealed class EditDigestTests : IDisposable
{
    private readonly Env _env = new();
    private readonly TempDir _dir = new();
    private readonly EditTools _tools;

    public EditDigestTests() => _tools = new EditTools(_env.Workspace, _env.Edits, _env.History, _env.Decompiler, _env.Pager);

    public void Dispose()
    {
        _env.Dispose();
        _dir.Dispose();
    }

    private static async Task<(string Text, T Record)> Run<T>(Func<Task<string>> call)
    {
        var collector = ToolOutput.Collect();
        var text = await call();
        return (text, Assert.IsType<T>(collector.Value));
    }

    /// <summary>Previews then applies one edit; returns the applied outcome after checking both report one digest.</summary>
    private async Task<EditOutcome> PreviewThenApply(Func<bool, Task<string>> edit)
    {
        var (previewText, preview) = await Run<EditOutcome>(() => edit(true));
        var (_, applied) = await Run<EditOutcome>(() => edit(false));
        Assert.Matches("^[0-9a-f]{16}$", preview.Digest);
        Assert.Contains($"Digest {preview.Digest}", previewText);
        Assert.Equal(preview.Digest, applied.Digest);
        Assert.Single(applied.EditIds);
        return applied;
    }

    [Fact]
    public async Task EveryEditToolReportsOneDigestFromDryRunToSave()
    {
        var id = _env.Fixture.Id;
        var applied = new List<EditOutcome>
        {
            await PreviewThenApply(d => _tools.StubMethod("Secret::Validate", "true", dryRun: d)),
            await PreviewThenApply(d => _tools.PatchMethodIL("Account::CheckPreview", "ldc.i4.1\nret", dryRun: d)),
            await PreviewThenApply(d => _tools.PatchMethodCSharp("Account::Score", "return 9;", dryRun: d)),
            await PreviewThenApply(d => _tools.AddMembersCSharp("Fixture.Model.Account", "public int Bonus() => 7;", dryRun: d)),
            await PreviewThenApply(d => _tools.AddTypesCSharp(id, "namespace Extras { public static class M { public static int One() => 1; } }", dryRun: d)),
            await PreviewThenApply(d => _tools.RenameSymbol("Account::Tick", "Step", dryRun: d)),
            await PreviewThenApply(d => _tools.RenameNamespace(id, "Extras", "Plugins", dryRun: d)),
        };
        Assert.Equal(applied.Count, applied.Select(a => a.Digest).Distinct().Count());

        var (_, list) = await Run<EditList>(() => _tools.ListEdits(id));
        Assert.Equal(applied.Select(a => a.Digest), list.Items.Select(i => i.Digest));

        var (text, saved) = await Run<EditService.SavedFile>(() => _tools.SaveAssembly(id, _dir.File("out.dll")));
        Assert.Equal(applied.Select(a => new SavedEdit(a.EditIds[0], a.Digest!)), saved.EditList);
        Assert.Contains($"Edits written: {applied[0].EditIds[0]} ({applied[0].Digest})", text);
    }

    [Fact]
    public async Task OtherInputsGiveAnotherDigestAndAnUndoneEditLeavesTheSave()
    {
        var id = _env.Fixture.Id;
        var (_, asTrue) = await Run<EditOutcome>(() => _tools.StubMethod("Secret::Validate", "true"));
        var (_, asFalse) = await Run<EditOutcome>(() => _tools.StubMethod("Secret::Validate", "false"));
        Assert.NotEqual(asTrue.Digest, asFalse.Digest);

        var first = await PreviewThenApply(d => _tools.StubMethod("Secret::Validate", "true", dryRun: d));
        var second = await PreviewThenApply(d => _tools.StubMethod("Account::Score", "7", dryRun: d));
        await _tools.UndoEdit(id, first.EditIds[0].Number);
        var (_, saved) = await Run<EditService.SavedFile>(() => _tools.SaveAssembly(id, _dir.File("out.dll")));
        Assert.Equal([new SavedEdit(second.EditIds[0], second.Digest!)], saved.EditList);
    }

    [Fact]
    public async Task SimplifyReportsOneDigestAndNoneWhenNothingChanges()
    {
        await _tools.PatchMethodIL("Account::CheckPreview", "ldc.i4.1\nbrtrue yes\nldc.i4.0\nret\nyes: ldc.i4.1\nret", dryRun: false);
        var applied = await PreviewThenApply(d => _tools.SimplifyMethods("Account::CheckPreview", passes: ["cfg"], dryRun: d));
        var (_, again) = await Run<EditOutcome>(() => _tools.SimplifyMethods("Account::CheckPreview", passes: ["cfg"]));
        Assert.Null(again.Digest); // the constant branch is gone: nothing would change
        var (_, saved) = await Run<EditService.SavedFile>(() => _tools.SaveAssembly(_env.Fixture.Id, _dir.File("out.dll")));
        Assert.Equal(applied.Digest, saved.EditList[^1].Digest);
    }

    [Fact]
    public async Task AnExportedScriptReplaysWithTheSameDigests()
    {
        var id = _env.Fixture.Id;
        await _tools.StubMethod("Secret::Validate", "true", dryRun: false);
        await _tools.PatchMethodCSharp("Account::Score", "var x = 4;\r\nreturn x * 2;", dryRun: false);
        await _tools.RenameSymbol("Account::Tick", "Step", dryRun: false);
        var (_, before) = await Run<EditList>(() => _tools.ListEdits(id));
        var script = _dir.File("edits.json");
        await _tools.ExportEdits(id, script);
        Assert.DoesNotContain("digest", File.ReadAllText(script), StringComparison.OrdinalIgnoreCase); // the script format is unchanged

        await _tools.RevertEdits(id);
        await _tools.ApplyEdits(script, dryRun: false);
        var (_, after) = await Run<EditList>(() => _tools.ListEdits(id));
        Assert.Equal(before.Items.Select(i => i.Digest), after.Items.Select(i => i.Digest));
    }

    [Fact]
    public async Task ASaveWithoutEditsListsNone()
    {
        var (text, saved) = await Run<EditService.SavedFile>(() => _tools.SaveAssembly(_env.Fixture.Id, _dir.File("out.dll")));
        Assert.Empty(saved.EditList);
        Assert.DoesNotContain("Edits written", text);
    }
}
