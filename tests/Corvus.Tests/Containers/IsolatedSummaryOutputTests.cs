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
        Assert.Contains("No SBOM written", Whole(result));
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
    public async Task A_sandboxed_worker_writes_the_indicator_and_policy_files_the_call_names()
    {
        if (!OperatingSystem.IsWindows()) return;
        var clean = Directory.CreateDirectory(Path.Combine(_dir.Path, "clean")).FullName;
        File.WriteAllBytes(Path.Combine(clean, "Other.dll"), InspectionTests.Compile("Other", "public static class Other { }"));
        var indicators = Path.Combine(_dir.Path, "out", "indicators.json");
        var policy = Path.Combine(_dir.Path, "out", "audit.xml");
        using var pool = SandboxedPool();
        using var shared = WorkerPool.UseShared(pool);
        await using var session = await Session(false);

        var result = await Call(session, "summarize_file", new() { ["path"] = Env.FixturePath, ["cleanFolder"] = clean, ["minFiles"] = 1, ["indicatorsPath"] = indicators, ["policyPath"] = policy });

        Assert.True(result.IsError != true, Whole(result));
        Assert.True(File.Exists(indicators) && File.Exists(policy), Whole(result));
        Assert.Contains("\"action\": \"Audit\"", File.ReadAllText(indicators), StringComparison.Ordinal);
        Assert.Contains("Enabled:Audit Mode", File.ReadAllText(policy), StringComparison.Ordinal);
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
    public async Task Two_outputs_naming_one_file_are_refused_before_the_worker_runs()
    {
        if (!OperatingSystem.IsWindows()) return;
        var same = Path.Combine(_dir.Path, "same.json");
        using var pool = SandboxedPool();
        using var shared = WorkerPool.UseShared(pool);
        await using var session = await Session(false);

        var result = await Call(session, "summarize_file", new() { ["path"] = Env.FixturePath, ["huntsPath"] = same, ["stixPath"] = same });

        Assert.True(result.IsError == true);
        Assert.Contains("name the same file", Whole(result));
        Assert.False(File.Exists(same));
    }

    [Fact]
    public async Task An_output_path_naming_a_folder_is_refused()
    {
        if (!OperatingSystem.IsWindows()) return;
        var folder = Path.Combine(_dir.Path, "folder.json");
        Directory.CreateDirectory(folder);
        using var pool = SandboxedPool();
        using var shared = WorkerPool.UseShared(pool);
        await using var session = await Session(false);

        var result = await Call(session, "summarize_file", new() { ["path"] = Env.FixturePath, ["stixPath"] = folder, ["overwrite"] = true });

        Assert.True(result.IsError == true);
        Assert.Contains("invalid_argument", Whole(result));
        Assert.Contains("is a folder", Whole(result));
    }

    [Fact]
    public async Task A_denied_output_names_its_path_and_is_not_retryable()
    {
        if (!OperatingSystem.IsWindows()) return;
        var stix = _dir.File("locked.stix.json");
        File.WriteAllText(stix, "old");
        File.SetAttributes(stix, FileAttributes.ReadOnly);
        try
        {
            using var pool = SandboxedPool();
            using var shared = WorkerPool.UseShared(pool);
            await using var session = await Session(false);

            var result = await Call(session, "summarize_file", new() { ["path"] = Env.FixturePath, ["stixPath"] = stix, ["overwrite"] = true });

            Assert.True(result.IsError == true);
            Assert.Contains("access_denied", Whole(result));
            Assert.Contains("\"retryable\":false", Whole(result));
            Assert.Contains(stix, Whole(result));
        }
        finally { File.SetAttributes(stix, FileAttributes.Normal); }
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
