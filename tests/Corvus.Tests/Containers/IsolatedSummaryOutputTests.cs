using Corvus.Native.Providers.Worker;

namespace Corvus.Tests;

/// <summary>summarize_file output files through a sandboxed files worker: the server places them where the call names.</summary>
public sealed class IsolatedSummaryOutputTests : FileIsolationTestBase
{
    private static WorkerPool SandboxedPool() => new(new WorkerPoolOptions
    {
        Enabled = true,
        Sandbox = true,
        Start = WorkerPool.OwnCommand(),
    });

    // Regression (d5189c2bf): the low-integrity worker wrote sbomPath and
    // stixPath itself, and every write was denied.
    [Fact]
    public async Task A_sandboxed_worker_writes_the_output_files_the_call_names()
    {
        if (!OperatingSystem.IsWindows()) return;
        var sbom = Path.Combine(_dir.Path, "out", "deps.cdx.json");
        var stix = Path.Combine(_dir.Path, "out", "findings.stix.json");
        using var pool = SandboxedPool();
        using var shared = WorkerPool.UseShared(pool);
        await using var session = await Session(false);

        var result = await Call(session, "summarize_file", new() { ["path"] = Env.FixturePath, ["sbomPath"] = sbom, ["stixPath"] = stix });

        Assert.True(result.IsError != true, Whole(result));
        // The fixture has no components: the SBOM is skipped with a note, the STIX bundle is written.
        Assert.Contains("no SBOM written", Whole(result));
        Assert.True(File.Exists(stix) && new FileInfo(stix).Length > 0, Whole(result));
        Assert.Contains(stix, Whole(result));
        Assert.DoesNotContain("outputs-", Whole(result));
    }

    [Fact]
    public async Task A_sandboxed_worker_writes_the_hunts_and_component_files_the_call_names()
    {
        if (!OperatingSystem.IsWindows()) return;
        var hunts = Path.Combine(_dir.Path, "out", "hunts.json");
        var components = Path.Combine(_dir.Path, "out", "components.jsonl");
        using var pool = SandboxedPool();
        using var shared = WorkerPool.UseShared(pool);
        await using var session = await Session(false);

        var result = await Call(session, "summarize_file", new() { ["path"] = Env.FixturePath, ["view"] = "hunts", ["huntsPath"] = hunts, ["componentsPath"] = components });

        Assert.True(result.IsError != true, Whole(result));
        Assert.True(File.Exists(hunts) && new FileInfo(hunts).Length > 0, Whole(result));
        Assert.Contains(hunts, Whole(result));
        Assert.DoesNotContain("outputs-", Whole(result));
    }

    [Fact]
    public async Task An_existing_output_file_is_refused_before_the_worker_runs()
    {
        if (!OperatingSystem.IsWindows()) return;
        var sbom = _dir.File("taken.cdx.json");
        File.WriteAllText(sbom, "old");
        using var pool = SandboxedPool();
        using var shared = WorkerPool.UseShared(pool);
        await using var session = await Session(false);

        var result = await Call(session, "summarize_file", new() { ["path"] = Env.FixturePath, ["sbomPath"] = sbom });

        Assert.True(result.IsError == true);
        Assert.Contains("overwrite=true", Whole(result));
        Assert.Equal("old", File.ReadAllText(sbom));
    }

    [Fact]
    public async Task Overwrite_replaces_an_existing_output_file()
    {
        if (!OperatingSystem.IsWindows()) return;
        var stix = _dir.File("again.stix.json");
        File.WriteAllText(stix, "old");
        using var pool = SandboxedPool();
        using var shared = WorkerPool.UseShared(pool);
        await using var session = await Session(false);

        var result = await Call(session, "summarize_file", new() { ["path"] = Env.FixturePath, ["stixPath"] = stix, ["overwrite"] = true });

        Assert.True(result.IsError != true, Whole(result));
        Assert.NotEqual("old", File.ReadAllText(stix));
    }
}
