using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Worker;

namespace Corvus.Tests;

/// <summary>The files worker on Windows: low integrity, mitigation policies, no writes to the profile or HKCU, a bounded process count.</summary>
public sealed class WorkerSandboxTests
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(60);

    private static WorkerPool Pool(bool sandbox) => new(new WorkerPoolOptions
    {
        Enabled = true,
        Sandbox = sandbox,
        Start = WorkerPool.OwnCommand() with { Environment = new Dictionary<string, string?> { [WorkerHost.FixtureOpsVariable] = "1" } },
    });

    private static Task<JsonElement> Run(WorkerPool pool, string op, JsonObject? args = null) =>
        pool.RunAsync(WorkerPool.SandboxedKind, op, args, Limit, CancellationToken.None);

    [Fact]
    public async Task A_sandboxed_worker_cannot_write_the_profile_folder_or_hkcu()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var pool = Pool(sandbox: true);
        var probe = await Run(pool, "fixture_sandbox");
        Assert.Equal(4096, probe.GetProperty("integrity").GetInt32());
        Assert.False(probe.GetProperty("profileWritable").GetBoolean());
        Assert.False(probe.GetProperty("registryWritable").GetBoolean());
    }

    [Fact]
    public async Task A_sandboxed_worker_writes_its_low_labelled_temporary_folder()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var pool = Pool(sandbox: true);
        Assert.True((await Run(pool, "fixture_sandbox")).GetProperty("temporaryWritable").GetBoolean());
    }

    [Fact]
    public async Task A_sandboxed_worker_reads_back_the_mitigation_policies()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var pool = Pool(sandbox: true);
        var probe = await Run(pool, "fixture_sandbox");
        Assert.True(probe.GetProperty("strictHandleChecks").GetBoolean());
        Assert.True(probe.GetProperty("extensionPointsDisabled").GetBoolean());
        Assert.True(probe.GetProperty("noRemoteImages").GetBoolean());
        Assert.True(probe.GetProperty("noLowLabelImages").GetBoolean());
    }

    [Fact]
    public async Task A_worker_without_the_switch_keeps_medium_integrity_and_writes_the_profile_folder()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var pool = Pool(sandbox: false);
        var probe = await Run(pool, "fixture_sandbox");
        Assert.Equal(WindowsSandbox.IntegrityRid(), probe.GetProperty("integrity").GetInt32());
        Assert.True(probe.GetProperty("profileWritable").GetBoolean());
    }

    [Fact]
    public async Task A_sandboxed_worker_cannot_start_more_processes_than_the_job_allows()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var pool = Pool(sandbox: true);
        var started = (await Run(pool, "fixture_spawn", new JsonObject { ["count"] = (int)WindowsSandbox.ActiveProcessLimit + 8 })).GetProperty("started").GetInt32();
        Assert.InRange(started, 1, (int)WindowsSandbox.ActiveProcessLimit - 1);
    }
}
