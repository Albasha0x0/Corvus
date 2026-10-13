using Corvus.Core;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>What a C# edit costs: compiles per edit, replays without the scratch pass, cancellable waits.</summary>
public sealed class EditCostTests : IDisposable
{
    private readonly Env _env = new();
    private readonly CSharpPatcher _patcher;
    private readonly EditService _edits;

    public EditCostTests()
    {
        _patcher = new CSharpPatcher(_env.Workspace, _env.Decompiler);
        _edits = new EditService(_env.Workspace, new IlAssembler(_env.Workspace), _patcher);
    }

    public void Dispose() => _env.Dispose();

    private string Patch(string method, string code, bool dryRun = false) =>
        _env.Edit(() => _edits.PatchMethodCSharp(_env.One(method), code, dryRun, default));

    [Fact]
    public void AnEditCompilesOnceForTheScratchCopyAndTheModule()
    {
        Patch("Secret::Validate", "return key.Length > 3;");
        Assert.Equal(1, _patcher.Compiles);
        _env.Edit(() => _edits.AddMembersCSharp(_env.One("Account", SymbolKind.Type), "public int Twice(int x) { return x * 2; }", false, default));
        Assert.Equal(3, _patcher.Compiles); // declarations, then bodies as helpers
        Assert.Contains("return key.Length > 3;", _env.Decompile("Secret::Validate"));
        Assert.Contains("x * 2", _env.Decompile("Account::Twice"));
    }

    [Fact]
    public void UndoReplaysCSharpEditsWithoutAScratchPass()
    {
        Patch("Secret::Validate", "return key.Length > 3;");
        Patch("Account::Score", "return 7;");
        int before = _patcher.Compiles;
        _env.Edit(() => _edits.Undo(_env.Fixture, 2, default));
        Assert.Equal(before + 1, _patcher.Compiles);
        Assert.Contains("return key.Length > 3;", _env.Decompile("Secret::Validate"));
    }

    [Fact]
    public void ACancelledUndoChangesNothing()
    {
        Patch("Secret::Validate", "return key.Length > 3;");
        Patch("Account::Score", "return 7;");
        var module = _env.Fixture.Module;
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => _env.Edit(() => _edits.Undo(_env.Fixture, 1, cancelled.Token)));
        Assert.Same(module, _env.Fixture.Module);
        Assert.Equal(2, _env.Fixture.Edits.Count);
        Assert.Contains("return 7;", _env.Decompile("Account::Score"));
    }

    [Fact]
    public async Task AWaitForAnotherThreadsImageStopsWhenCancelled()
    {
        var images = new CSharpPatcher.DerivedImages();
        var image = new byte[] { 1 };
        using var started = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var maker = Task.Run(() => images.Get(image, "k", () => { started.Set(); release.Wait(); return [2]; }, default));
        started.Wait();
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        Assert.ThrowsAny<OperationCanceledException>(() => images.Get(image, "k", () => [3], cancel.Token));
        release.Set();
        var made = await maker;
        Assert.Equal([2], made!);
        Assert.Same(made, images.Get(image, "k", () => [4], default));
    }
}
