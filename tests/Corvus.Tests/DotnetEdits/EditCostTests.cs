using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;

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
    public void An_edit_compiles_once_for_the_scratch_copy_and_the_module()
    {
        Patch("Secret::Validate", "return code.Length > 3;");
        Assert.Equal(1, _patcher.Compiles);
        _env.Edit(() => _edits.AddMembersCSharp(_env.One("Account", SymbolKind.Type), "public int Twice(int x) { return x * 2; }", false, default));
        Assert.Equal(3, _patcher.Compiles); // declarations, then bodies as helpers
        Assert.Contains("return code.Length > 3;", _env.Decompile("Secret::Validate"));
        Assert.Contains("x * 2", _env.Decompile("Account::Twice"));
    }

    [Fact]
    public async Task An_applied_csharp_edit_compiles_while_another_call_holds_the_shared_lock()
    {
        var ws = _env.Workspace;
        using var holding = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        // Another call keeps the shared lock until released (up to 2 minutes).
        var reader = Task.Run(() => ws.Read(() => { holding.Set(); release.Wait(TimeSpan.FromMinutes(2)); return 0; }));
        holding.Wait();
        var edit = ToolSupport.CompiledEdit(ws, _edits, dryRun: false,
            () => _edits.AddMembersCSharp(_env.One("Account", SymbolKind.Type), "public int Twice(int x) { return x * 2; }", false, default), default);
        // Declarations, then bodies as helpers: two compiles.
        await Task.Run(async () => { while (_patcher.Compiles < 2) await Task.Delay(5); }).WaitAsync(TimeSpan.FromMinutes(1));
        Assert.False(edit.IsCompleted);
        release.Set();
        await reader.WaitAsync(TimeSpan.FromMinutes(1));
        await edit.WaitAsync(TimeSpan.FromMinutes(1));
        // The merge under the exclusive lock reuses the prepared compiles.
        Assert.Equal(2, _patcher.Compiles);
        Assert.Single(_env.Fixture.Edits);
        Assert.Contains("x * 2", _env.Decompile("Account::Twice"));
    }

    [Fact]
    public async Task A_csharp_edit_that_does_not_compile_answers_without_the_exclusive_lock()
    {
        var ws = _env.Workspace;
        using var holding = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var reader = Task.Run(() => ws.Read(() => { holding.Set(); release.Wait(TimeSpan.FromMinutes(2)); return 0; }));
        holding.Wait();
        var edit = ToolSupport.CompiledEdit(ws, _edits, dryRun: false,
            () => _edits.PatchMethodCSharp(_env.One("Secret::Validate"), "return undefinedName;", false, default), default);
        var error = await Assert.ThrowsAsync<ToolError>(() => edit.WaitAsync(TimeSpan.FromMinutes(1)));
        Assert.Contains("undefinedName", error.Message);
        Assert.False(reader.IsCompleted);
        Assert.Empty(_env.Fixture.Edits);
        release.Set();
        await reader.WaitAsync(TimeSpan.FromMinutes(1));
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public void Undo_replays_CSharp_edits_without_a_scratch_pass()
    {
        Patch("Secret::Validate", "return code.Length > 3;");
        Patch("Account::Score", "return 7;");
        int before = _patcher.Compiles;
        _env.Edit(() => _edits.Undo(_env.Fixture, 2, default));
        Assert.Equal(before + 1, _patcher.Compiles);
        Assert.Contains("return code.Length > 3;", _env.Decompile("Secret::Validate"));
    }

    [Fact]
    public void A_cancelled_undo_changes_nothing()
    {
        Patch("Secret::Validate", "return code.Length > 3;");
        Patch("Account::Score", "return 7;");
        var module = _env.Fixture.Module;
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => _env.Edit(() => _edits.Undo(_env.Fixture, 1, cancelled.Token)));
        Assert.Same(module, _env.Fixture.Module);
        Assert.Equal(2, _env.Fixture.Edits.Count);
        Assert.Contains("return 7;", _env.Decompile("Account::Score"));
    }

    /// <summary>A compile error in a generic span method names the method, not its helper, and its Next says how to return from a void method.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void Compile_errors_in_a_generic_span_method_name_the_patched_method()
    {
        using var core = new Env(typeof(object).Assembly.Location);
        var target = core.One("System.DateTimeFormat::FormatCustomized");
        var error = Assert.Throws<ToolError>(() => core.Workspace.Read(() => core.Edits.PatchMethodCSharp(target, "return null;", dryRun: true, default)));
        Assert.Contains("CS0127", error.Message);
        Assert.Contains("DateTimeFormat.FormatCustomized<TChar>(", error.Message);
        Assert.DoesNotContain("__Patch", error.Message);
        Assert.DoesNotContain("__patch", error.Message);
        Assert.Contains("returns void: use 'return;'", error.Remediation);
        Assert.Contains("compiled OK", core.Workspace.Read(() => core.Edits.PatchMethodCSharp(target, "return;", dryRun: true, default)));
    }

    [Fact]
    public async Task A_wait_for_another_threads_image_stops_when_cancelled()
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
