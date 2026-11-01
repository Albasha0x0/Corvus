using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native.Annotations;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>A native image's index reports its state and announces its end.</summary>
public sealed class NativeIndexStateTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly Env _env = new();
    private readonly ManualResetEventSlim _gate = new();
    private int _starts;

    public void Dispose()
    {
        _gate.Set();
        _env.Dispose();
        _dir.Dispose();
    }

    private sealed class FaultingStarts(Exception? fault = null) : IReadOnlyCollection<uint>
    {
        public int Count => 1;
        public IEnumerator<uint> GetEnumerator() => throw fault ?? new InvalidOperationException("the symbol starts cannot be read");
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private (NativeCodeService Code, LoadedNative Native) Load(Func<IReadOnlyCollection<uint>?> starts, bool background = true)
    {
        // No disk index cache: another test's index of the same bytes would skip the build.
        _env.Options.CodeIndexCache = null;
        _env.Options.BackgroundIndexing = background;
        var code = new NativeCodeService(_env.Workspace, _env.Options, null, new AnnotationStore(_dir.File("ann")))
        {
            SymbolStarts = (_, _) =>
            {
                Interlocked.Increment(ref _starts);
                return starts();
            },
        };
        var path = _dir.File("image.dll");
        File.WriteAllBytes(path, NativePatchMigrationTests.X64Image(0x1000, 0x2000, 0x1040, 1));
        return (code, _env.Workspace.LoadAny(path).Native!);
    }

    private IReadOnlyCollection<uint>? Gated()
    {
        _gate.Wait(TimeSpan.FromMinutes(1));
        return [0x1000u, 0x1040u];
    }

    private WorkspaceTools Tools(NativeCodeService code) =>
        new(_env.Workspace, new AotMetadataService(_env.Workspace), new IndexingService(_env.Workspace, new CallGraphService(_env.Workspace), new ServerOptions()),
            new UnpackService(_env.Workspace), code: code);

    private static async Task Waiters(NativeCodeService code, LoadedNative native, int count)
    {
        var limit = DateTime.UtcNow.AddSeconds(30);
        while (code.Waiting(native) < count && DateTime.UtcNow < limit) await Task.Delay(10);
        Assert.True(code.Waiting(native) >= count);
    }

    [Fact]
    public void A_build_in_progress_shows_its_phase_in_the_status_line()
    {
        var (code, native) = Load(Gated);
        var state = code.StateOf(native);
        Assert.Equal("building", state.State);
        Assert.Equal("building: starting", state.Text);
        Assert.Equal($"{native.Id} building: starting", CachesStatus.IndexStates(code, _env.Workspace));
    }

    [Fact]
    public async Task A_warm_up_names_the_image_still_indexing_and_the_call_that_waits()
    {
        var (code, native) = Load(Gated);
        var link = new NativeLinkService(_env.Workspace, code) { WarmUpWait = TimeSpan.FromMilliseconds(50) };
        var pending = await link.WarmUp(null, default);
        Assert.Equal([native], pending);
        var note = NativeLinkService.PartialNote(pending);
        Assert.Contains($"edges into {native.Id} are not yet known", note);
        Assert.Contains($"list_assemblies filter={native.Id} waitSeconds=60", note);
        _gate.Set();
        // The opened index finishes on its own thread; the second wait is the
        // default one, long enough for a loaded machine.
        Assert.Empty(await new NativeLinkService(_env.Workspace, code).WarmUp(null, default));
        Assert.Equal("", NativeLinkService.PartialNote([]));
    }

    [Fact]
    public async Task A_cancelled_warm_up_throws_while_an_index_is_building()
    {
        var (code, _) = Load(Gated);
        var link = new NativeLinkService(_env.Workspace, code);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => link.WarmUp(null, cancelled.Token));
    }

    [Fact]
    public void The_note_for_several_images_waits_the_first_and_says_to_wait_the_others()
    {
        var (_, native) = Load(Gated);
        var note = NativeLinkService.PartialNote([native, native]);
        Assert.Contains($"filter={native.Id} waitSeconds=60 waits for it, then wait the others the same way", note);
    }

    // The first image indexes at once; the second holds its symbol starts until the gate opens.
    private (NativeCodeService Code, LoadedNative Ready, LoadedNative Held) LoadPair()
    {
        _env.Options.CodeIndexCache = null;
        _env.Options.BackgroundIndexing = true;
        string? heldPath = null;
        var code = new NativeCodeService(_env.Workspace, _env.Options, null, new AnnotationStore(_dir.File("ann")))
        {
            SymbolStarts = (n, token) =>
            {
                if (n.FilePath != heldPath) return [0x1000u, 0x1040u];
                _gate.Wait(TimeSpan.FromMinutes(1), token);
                return [0x1000u, 0x1040u];
            },
        };
        var first = _dir.File("first.dll");
        var second = _dir.File("second.dll");
        File.WriteAllBytes(first, NativePatchMigrationTests.X64Image(0x1000, 0x2000, 0x1040, 1));
        File.WriteAllBytes(second, NativePatchMigrationTests.X64Image(0x1000, 0x2000, 0x1040, 2));
        heldPath = second;
        return (code, _env.Workspace.LoadAny(first).Native!, _env.Workspace.LoadAny(second).Native!);
    }

    [Fact]
    public async Task A_two_image_call_tree_is_partial_while_one_index_is_gated()
    {
        var (code, ready, held) = LoadPair();
        var tools = new NativeCodeTools(_env.Workspace, code, _env.Pager,
            new NativeLinkService(_env.Workspace, code) { WarmUpWait = TimeSpan.FromMilliseconds(50) });
        var collector = ToolOutput.Collect();
        var text = await tools.NativeCallTree(ready.Id, "rva:0x1000");
        var partial = Assert.IsType<NativeCallTreeResult>(collector.Value).Partial;
        Assert.StartsWith($"partial: edges into {held.Id} are not yet known", partial);
        Assert.Contains(partial!, text);

        // Once the gate opens the repeated call builds a fresh tree without the note.
        _gate.Set();
        var later = new NativeCodeTools(_env.Workspace, code, _env.Pager, new NativeLinkService(_env.Workspace, code));
        var again = ToolOutput.Collect();
        Assert.DoesNotContain("partial:", await later.NativeCallTree(ready.Id, "rva:0x1000"));
        Assert.Null(Assert.IsType<NativeCallTreeResult>(again.Value).Partial);
    }

    [Fact]
    public async Task A_stalled_name_wait_in_resolve_address_names_the_call_that_waits()
    {
        var (code, _, held) = LoadPair();
        var tools = new NativeTools(_env.Workspace, _env.Pager, code) { StallWindow = TimeSpan.FromMilliseconds(100) };
        var error = await Assert.ThrowsAsync<ToolError>(() => tools.ResolveAddress(held.Id, "main"));
        Assert.Equal(ErrorCode.Timeout, error.Code);
        Assert.Contains($"list_assemblies filter={held.Id} waitSeconds=60", error.Remediation);
    }

    [Fact]
    public async Task Reading_bytes_by_name_does_not_wait_for_the_code_index()
    {
        var (code, _, held) = LoadPair();
        var tools = new NativeTools(_env.Workspace, _env.Pager, code) { StallWindow = TimeSpan.FromMilliseconds(100) };
        var error = await Assert.ThrowsAsync<ToolError>(() => tools.ReadBytes(held.Id, "no_such_name"));
        Assert.NotEqual(ErrorCode.Timeout, error.Code);
        Assert.Equal(0, code.Waiting(held));
        Assert.Equal("building", code.StateOf(held).State);
    }

    [Fact]
    public void Resolving_an_address_by_name_is_a_long_running_call()
    {
        Assert.True(Corvus.Mcp.ToolEffects.Of("resolve_address").LongRunning);
    }

    [Fact]
    public async Task A_wait_of_one_second_returns_the_state_and_the_next_call()
    {
        var (code, native) = Load(Gated);
        var error = await Assert.ThrowsAsync<ToolError>(() => code.Open(native.Id, null, default, waitSeconds: 1));
        Assert.Equal(ErrorCode.Timeout, error.Code);
        Assert.Contains("still indexing", error.Message);
        Assert.Contains($"list_assemblies filter={native.Id} waitSeconds=60", error.Remediation);
        Assert.True(error.Retryable);
    }

    [Fact]
    public async Task A_ready_notice_follows_a_build_that_ended_after_the_wait()
    {
        var (code, native) = Load(Gated);
        await Assert.ThrowsAsync<ToolError>(() => code.Open(native.Id, null, default, waitSeconds: 1));
        Assert.DoesNotContain(_env.Workspace.DrainNotices(), n => n.Contains("indexed"));

        _gate.Set();
        await code.WaitBuilding([native], TimeSpan.FromMinutes(1), default);

        Assert.Equal("ready", code.StateOf(native).State);
        Assert.Contains(_env.Workspace.DrainNotices(), n => n == $"{native.Id} is indexed. Next: list_functions image={native.Id}");
    }

    [Fact]
    public async Task A_build_that_ended_while_a_caller_waited_sends_no_notice()
    {
        var (code, native) = Load(Gated);
        var open = code.Open(native.Id, null, default, waitSeconds: 60);
        await Waiters(code, native, 1);
        _gate.Set();
        await open;
        Assert.DoesNotContain(_env.Workspace.DrainNotices(), n => n.Contains("indexed"));
    }

    [Fact]
    public async Task A_faulted_build_is_not_rebuilt()
    {
        var (code, native) = Load(() => new FaultingStarts());
        var first = await Assert.ThrowsAsync<ToolError>(() => code.Open(native.Id, null, default));
        Assert.Contains("the symbol starts cannot be read", first.Message);
        Assert.Contains($"reload_assembly assembly={native.Id}", first.Remediation);
        Assert.False(first.Retryable);
        int builds = Volatile.Read(ref _starts);

        await Assert.ThrowsAsync<ToolError>(() => code.Open(native.Id, null, default));

        Assert.Equal(builds, Volatile.Read(ref _starts));
        Assert.Equal("failed", code.StateOf(native).State);
    }

    [Fact]
    public async Task A_cancelled_wait_is_a_cancellation_and_sends_no_notice()
    {
        var (code, native) = Load(Gated);
        using var cts = new CancellationTokenSource();
        var open = code.Open(native.Id, null, cts.Token, waitSeconds: 60);
        await Waiters(code, native, 1);
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => open);

        _gate.Set();
        await code.WaitBuilding([native], TimeSpan.FromMinutes(1), default);
        Assert.DoesNotContain(_env.Workspace.DrainNotices(), n => n.Contains("indexed"));
    }

    [Fact]
    public async Task A_failure_after_the_caller_left_sends_a_failure_notice()
    {
        var (code, native) = Load(() =>
        {
            _gate.Wait(TimeSpan.FromMinutes(1));
            return new FaultingStarts();
        });
        await Assert.ThrowsAsync<ToolError>(() => code.Open(native.Id, null, default, waitSeconds: 1));
        _gate.Set();
        await code.WaitBuilding([native], TimeSpan.FromMinutes(1), default);

        Assert.Equal("failed", code.StateOf(native).State);
        Assert.Contains(_env.Workspace.DrainNotices(), n => n.StartsWith($"Indexing {native.Id} failed:") && n.Contains($"reload_assembly assembly={native.Id}"));
    }

    [Fact]
    public async Task A_build_is_retried_after_an_io_fault()
    {
        // The test's first call makes the faulting build, not a build started on load.
        int calls = 0;
        var (code, native) = Load(() => Interlocked.Increment(ref calls) == 1 ? new FaultingStarts(new IOException("read failed")) : [0x1000u, 0x1040u], background: false);
        await Assert.ThrowsAsync<ToolError>(() => code.Open(native.Id, null, default));

        var (_, index) = await code.Open(native.Id, null, default);

        Assert.NotNull(index);
        Assert.Equal("ready", code.StateOf(native).State);
    }

    [Fact]
    public async Task A_patch_clears_a_kept_failure()
    {
        int calls = 0;
        var (code, native) = Load(() => Interlocked.Increment(ref calls) == 1 ? new FaultingStarts() : [0x1000u, 0x1040u]);
        await Assert.ThrowsAsync<ToolError>(() => code.Open(native.Id, null, default));
        await Assert.ThrowsAsync<ToolError>(() => code.Open(native.Id, null, default));

        code.Patched(native, null);
        var (_, index) = await code.Open(native.Id, null, default);

        Assert.NotNull(index);
    }

    [Fact]
    public async Task A_retryable_tool_error_in_a_build_reaches_the_caller_and_is_retried()
    {
        // The test's first call makes the faulting build, not a build started on load.
        int calls = 0;
        var (code, native) = Load(() => Interlocked.Increment(ref calls) == 1
            ? new FaultingStarts(new ToolError(ErrorCode.Timeout, "a helper timed out")) : [0x1000u, 0x1040u], background: false);
        var first = await Assert.ThrowsAsync<ToolError>(() => code.Open(native.Id, null, default));
        Assert.Contains("a helper timed out", first.Message);
        Assert.True(first.Retryable);

        var (_, index) = await code.Open(native.Id, null, default);
        Assert.NotNull(index);
    }

    [Fact]
    public async Task A_listing_names_the_state_of_a_building_image_and_the_next_call()
    {
        var (code, native) = Load(Gated);
        var text = await Tools(code).ListAssemblies(filter: native.Id);
        Assert.Contains("index building: starting", text);
        Assert.Contains($"Next: list_assemblies filter={native.Id} waitSeconds=60", text);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(601)]
    public async Task A_wait_outside_zero_to_600_seconds_is_rejected(int seconds)
    {
        var (code, _) = Load(Gated);
        var error = await Assert.ThrowsAsync<ToolError>(() => Tools(code).ListAssemblies(waitSeconds: seconds));
        Assert.Equal(ErrorCode.InvalidArgument, error.Code);
    }

    [Fact]
    public async Task A_listing_without_a_wait_still_announces_the_end_of_a_running_build()
    {
        var (code, native) = Load(Gated);
        await Tools(code).ListAssemblies(filter: native.Id);
        _gate.Set();
        await code.WaitBuilding([native], TimeSpan.FromMinutes(1), default);
        await Task.Run(() => SpinWait.SpinUntil(() => code.StateOf(native).State == "ready", TimeSpan.FromSeconds(30)));
        Assert.Contains(_env.Workspace.DrainNotices(), n => n.Contains("is indexed"));
    }

    [Fact]
    public async Task A_listing_that_saw_the_build_end_sends_no_notice()
    {
        var (code, native) = Load(Gated);
        var list = Tools(code).ListAssemblies(filter: native.Id, waitSeconds: 60);
        _gate.Set();
        await list;
        await Task.Run(() => SpinWait.SpinUntil(() => code.StateOf(native).State == "ready", TimeSpan.FromSeconds(30)));
        Assert.DoesNotContain(_env.Workspace.DrainNotices(), n => n.Contains("is indexed"));
    }

    [Fact]
    public async Task A_build_with_one_waiter_left_and_one_staying_sends_no_notice()
    {
        var (code, native) = Load(Gated);
        var staying = code.Open(native.Id, null, default, waitSeconds: 60);
        await Waiters(code, native, 1);
        await Assert.ThrowsAsync<ToolError>(() => code.Open(native.Id, null, default, waitSeconds: 1));

        _gate.Set();
        await staying;

        Assert.DoesNotContain(_env.Workspace.DrainNotices(), n => n.Contains("is indexed"));
    }
}
