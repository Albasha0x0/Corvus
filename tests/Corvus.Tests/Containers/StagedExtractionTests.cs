using Corvus.Native.Providers.Worker;

namespace Corvus.Tests;

/// <summary>unpack_container through a sandboxed files worker: the server fills the folder the call names.</summary>
public sealed class StagedExtractionTests : FileIsolationTestBase
{
    private WorkerPool SandboxedPool() => new(new WorkerPoolOptions
    {
        Enabled = true,
        Sandbox = true,
        Start = WorkerPool.OwnCommand() with { Environment = new Dictionary<string, string?> { [WorkerHost.FixtureOpsVariable] = "1" } },
    });

    [Fact]
    public async Task A_sandboxed_worker_extracts_into_the_folder_the_call_names()
    {
        if (!OperatingSystem.IsWindows()) return;
        var (zip, _, _, _) = Inputs();
        var target = Path.Combine(_dir.Path, "named");
        using var pool = SandboxedPool();
        using var shared = WorkerPool.UseShared(pool);
        await using var session = await Session(false);
        var result = await Call(session, "unpack_container", new() { ["path"] = zip, ["outputDirectory"] = target, ["extractOnly"] = true });
        Assert.True(result.IsError != true, Whole(result));
        Assert.Equal("text 1", File.ReadAllText(Path.Combine(target, "docs", "f1.txt")));
        Assert.DoesNotContain("extract-", Whole(result));
    }

    [Fact]
    public async Task A_second_extract_of_the_same_file_reuses_the_named_folder_and_another_file_is_refused()
    {
        if (!OperatingSystem.IsWindows()) return;
        var (zip, package, _, _) = Inputs();
        var target = Path.Combine(_dir.Path, "reused");
        using var pool = SandboxedPool();
        using var shared = WorkerPool.UseShared(pool);
        await using var session = await Session(false);
        var args = new Dictionary<string, object?> { ["path"] = zip, ["outputDirectory"] = target, ["extractOnly"] = true };
        Assert.True((await Call(session, "unpack_container", args)).IsError != true);
        Assert.True((await Call(session, "unpack_container", args)).IsError != true);
        var other = await Call(session, "unpack_container", new() { ["path"] = package, ["outputDirectory"] = target, ["extractOnly"] = true });
        Assert.True(other.IsError == true);
        Assert.Contains("not empty", Whole(other));
    }

    // A junction in staging points outside it, as a low-integrity worker could plant one.
    [Fact]
    public void A_link_in_staging_is_not_followed_when_the_server_moves_files()
    {
        if (!OperatingSystem.IsWindows()) return;
        var staging = Path.Combine(_dir.Path, "staging");
        var outside = Path.Combine(_dir.Path, "outside");
        Directory.CreateDirectory(staging);
        Directory.CreateDirectory(outside);
        File.WriteAllText(Path.Combine(staging, "kept.txt"), "kept");
        File.WriteAllText(Path.Combine(outside, "secret.txt"), "secret");
        using (var mklink = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe", ["/c", "mklink", "/J", Path.Combine(staging, "link"), outside])
            { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true })!)
        {
            mklink.WaitForExit();
            Assert.Equal(0, mklink.ExitCode);
        }
        var target = Path.Combine(_dir.Path, "named");
        var placed = Corvus.Tools.StagedExtraction.Place(new Corvus.Services.Analysis.UnpackService.Extraction("a.zip", "a.zip", "zip", staging, [], []), staging, target);
        Assert.Equal(target, placed.OutputDirectory);
        Assert.True(File.Exists(Path.Combine(target, "kept.txt")));
        Assert.False(File.Exists(Path.Combine(target, "link", "secret.txt")));
        Assert.Equal("secret", File.ReadAllText(Path.Combine(outside, "secret.txt")));
    }
}
