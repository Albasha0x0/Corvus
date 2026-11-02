using Corvus.Native.Providers.Worker;

namespace Corvus.Tests;

/// <summary>open_minidump view=modules outputPath through a sandboxed files worker: the server fills the folder.</summary>
public sealed class IsolatedSaveTests : FileIsolationTestBase
{
    private static PeBuilt Image() => RebuildFixtures.Build(new PeSpec(true,
        [new SectionSpec(".text", 0x60000020, [0x90, 0xC3])]));

    private static WorkerPool SandboxedPool() => new(new WorkerPoolOptions
    {
        Enabled = true,
        Sandbox = true,
        Start = WorkerPool.OwnCommand() with { Environment = new Dictionary<string, string?> { [WorkerHost.FixtureOpsVariable] = "1" } },
    });

    private string Dump(PeBuilt image)
    {
        using var dump = RebuildFixtures.Dump(_dir,
            new Placed("a.dll", image, 0x180000000UL), new Placed("b.dll", image, 0x190000000UL));
        return dump.Path;
    }

    [Fact]
    public async Task A_sandboxed_worker_saves_the_module_and_layout_the_call_names()
    {
        if (!OperatingSystem.IsWindows()) return;
        var image = Image();
        var dump = Dump(image);
        var target = Path.Combine(_dir.Path, "rebuilt");
        using var pool = SandboxedPool();
        using var shared = WorkerPool.UseShared(pool);
        await using var session = await Session(false);

        var result = await Call(session, "open_minidump", new() { ["path"] = dump, ["view"] = "modules", ["outputPath"] = target, ["modules"] = "b.dll", ["layout"] = "mapped" });

        Assert.True(result.IsError != true, Whole(result));
        var saved = Assert.Single(Directory.GetFiles(target));
        Assert.Equal("b.dll", Path.GetFileName(saved));
        Assert.Equal(RebuildFixtures.Mapped(image.Bytes).Length, new FileInfo(saved).Length);
        Assert.Contains(target, Whole(result));
        Assert.DoesNotContain("modules-", Whole(result));
    }

    [Fact]
    public async Task A_target_folder_that_is_not_empty_is_refused_before_the_worker_runs()
    {
        if (!OperatingSystem.IsWindows()) return;
        var dump = Dump(Image());
        var target = Path.Combine(_dir.Path, "taken");
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "old.txt"), "x");
        using var pool = SandboxedPool();
        using var shared = WorkerPool.UseShared(pool);
        await using var session = await Session(false);

        var result = await Call(session, "open_minidump", new() { ["path"] = dump, ["view"] = "modules", ["outputPath"] = target });

        Assert.True(result.IsError == true);
        Assert.Contains("new or empty folder", Whole(result));
        Assert.Equal(["old.txt"], Directory.GetFiles(target).Select(Path.GetFileName));
    }
}
