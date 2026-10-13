using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>The .NET edit tools' outcome records (SX-1): edit ids kept across undo, batch semantics of apply_edits, previews by default.</summary>
public sealed class EditOutcomeTests : IDisposable
{
    private readonly Env _env = new();
    private readonly TempDir _dir = new();
    private readonly ResultStore _results = new(ResultCacheOptions.MemoryOnly);
    private readonly EditTools _tools;

    public EditOutcomeTests() => _tools = new EditTools(_env.Workspace, _env.Edits, _env.History, _env.Decompiler, _env.Pager, results: _results);

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

    [Fact]
    public async Task ACallWithoutDryRunPreviewsAndChangesNothing()
    {
        var (text, outcome) = await Run<EditOutcome>(() => _tools.StubMethod("Secret::Validate", "true"));
        Assert.Contains("pass dryRun=false to apply", text);
        Assert.Equal((false, true), (outcome.Applied, outcome.DryRun));
        Assert.Empty(outcome.EditIds);
        Assert.Empty(_env.Fixture.Edits);
    }

    [Fact]
    public async Task EditIdsSurviveAnUndoOfAnEarlierEdit()
    {
        var (_, first) = await Run<EditOutcome>(() => _tools.StubMethod("Secret::Validate", "true", dryRun: false));
        var (_, second) = await Run<EditOutcome>(() => _tools.StubMethod("Account::Score", "7", dryRun: false));
        var (text, third) = await Run<EditOutcome>(() => _tools.RenameSymbol("Account::Tick", "Step", dryRun: false));
        Assert.Equal([new EditId(_env.Fixture.Id, 3)], third.EditIds);
        Assert.Contains($"Edit {_env.Fixture.Id}#3.", text);
        Assert.Equal(("rename", "Tick", "Step"), (third.Changes[0].Kind, third.Changes[0].Before, third.Changes[0].After));

        var (_, undone) = await Run<EditOutcome>(() => _tools.UndoEdit(_env.Fixture.Id, first.EditIds[0].Number));
        Assert.Equal(first.EditIds, undone.EditIds);
        var (_, list) = await Run<EditList>(() => _tools.ListEdits(_env.Fixture.Id));
        Assert.Equal([second.EditIds[0].ToString(), third.EditIds[0].ToString()], list.Items.Select(i => i.EditId));
        // The ids stay addressable: undo #3 still means the rename.
        await _tools.UndoEdit(_env.Fixture.Id, 3);
        Assert.Equal("stub_method", Assert.Single(_env.Fixture.Edits).Kind);
        var gone = await Assert.ThrowsAsync<ToolError>(() => _tools.UndoEdit(_env.Fixture.Id, 1));
        Assert.Equal(ErrorCode.NotFound, gone.Code);
    }

    private string ScriptWithOneBadEdit()
    {
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Secret::Validate"), "true"));
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Account::Score"), "7"));
        var script = _env.Workspace.Read(() => _env.History.BuildScript(_env.Fixture));
        var bad = script.Edits[1] with { Args = new Dictionary<string, string?>(script.Edits[1].Args) { ["value"] = "not a number" } };
        var path = _dir.File("edits.json");
        File.WriteAllText(path, EditHistoryService.Serialize(script with { Edits = [script.Edits[0], bad] }));
        _env.Edit(() => _env.Edits.RevertAll(_env.Fixture, default));
        return path;
    }

    [Fact]
    public async Task ApplyEditsStoppedOnAFailureIsAnErrorWithEachEditsOutcome()
    {
        var path = ScriptWithOneBadEdit();
        var error = await Assert.ThrowsAsync<ToolError>(() => _tools.ApplyEdits(path, dryRun: false));
        Assert.Equal(ErrorCode.Failed, error.Code);
        Assert.Contains("rolled back", error.Message);
        Assert.Contains("stopOnError=false", error.Remediation);
        var partial = System.Text.Json.JsonSerializer.SerializeToNode(error.Partial)!;
        Assert.Equal((0, 1, true), ((int)partial["applied"]!, (int)partial["failed"]!, (bool)partial["rolledBack"]!));
        Assert.Equal("invalid_argument", (string?)partial["items"]![1]!["Error"]!["Code"]);
        Assert.Empty(_env.Fixture.Edits);
    }

    [Fact]
    public async Task ApplyEditsWithoutStopOnErrorSucceedsWithTheFailureCounted()
    {
        var path = ScriptWithOneBadEdit();
        var (text, outcome) = await Run<EditOutcome>(() => _tools.ApplyEdits(path, dryRun: false, stopOnError: false));
        Assert.Equal((true, 1), (outcome.Applied, outcome.Failed));
        Assert.Single(outcome.EditIds);
        Assert.Contains("1 applied, 1 failed", text);
        var items = outcome.Items!.Cast<EditHistoryService.ApplyItem>().ToList();
        Assert.Equal(("observed", null), (items[0].Basis, items[0].Error));
        Assert.Equal("invalid_argument", items[1].Error!.Code);
        Assert.Single(_env.Fixture.Edits);
    }

    [Fact]
    public async Task RevertKeepsTheDiscardedEditsAsAScriptThatRestoresThem()
    {
        await _tools.StubMethod("Secret::Validate", "true", dryRun: false);
        await _tools.RenameSymbol("Account::Tick", "Step", dryRun: false);
        var (_, reverted) = await Run<EditOutcome>(() => _tools.RevertEdits(_env.Fixture.Id));
        Assert.Equal(2, reverted.EditIds.Count);
        Assert.Empty(_env.Fixture.Edits);
        var script = _dir.File("restore.json");
        File.WriteAllText(script, _results.Read(reverted.ResultId!).Text);
        await _tools.ApplyEdits(script, dryRun: false);
        Assert.Equal(["stub_method", "rename_symbol"], _env.Fixture.Edits.Select(e => e.Kind));
    }
}
