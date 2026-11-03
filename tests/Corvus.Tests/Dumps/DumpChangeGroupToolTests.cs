using Corvus.Core;
using Corvus.Native.Providers.Worker;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>open_minidump view=changes group=shape lists one row per group of changed ranges.</summary>
public sealed class DumpChangeGroupToolTests : FileIsolationTestBase
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Group_shape_lists_repeated_stubs_as_one_row(bool is64)
    {
        var dump = StubFixtures.Repeated(_dir, is64, 6);
        using var service = new MinidumpService();
        var tools = new MinidumpTools(service);

        var flat = await tools.OpenMinidump(dump.DumpPath, "changes", imageDirectories: dump.ImageFolder);
        var grouped = await tools.OpenMinidump(dump.DumpPath, "changes", imageDirectories: dump.ImageFolder, group: "shape");

        Assert.Contains("6 changed range", flat);
        Assert.Contains("1 change group", grouped);
        Assert.Contains("code x6", grouped);
    }

    [Fact]
    public async Task Group_outside_the_changes_view_is_refused()
    {
        var dump = StubFixtures.Repeated(_dir, true, 2);
        using var service = new MinidumpService();

        var e = await Assert.ThrowsAsync<ToolError>(() =>
            new MinidumpTools(service).OpenMinidump(dump.DumpPath, "modules", imageDirectories: dump.ImageFolder, group: "shape"));

        Assert.Contains("group", e.Message);
        Assert.Contains("view=changes", e.NextFor(null));
    }

    [Fact]
    public async Task Group_shape_runs_in_the_isolated_worker()
    {
        if (!OperatingSystem.IsWindows()) return;
        var dump = StubFixtures.Repeated(_dir, true, 4);
        var args = new Dictionary<string, object?>
        {
            ["path"] = dump.DumpPath, ["view"] = "changes", ["group"] = "shape", ["imageDirectories"] = dump.ImageFolder,
        };
        string inProcess;
        await using (var session = await Session(true))
            inProcess = Whole(await Call(session, "open_minidump", args));
        using var pool = Pool();
        using var shared = WorkerPool.UseShared(pool);
        await using var isolated = await Session(false);

        var inWorker = Whole(await Call(isolated, "open_minidump", args));

        Assert.Contains("code x4", inProcess);
        Assert.Equal(Rows(inProcess), Rows(inWorker));
    }

    // The group rows, without the dump id that differs between the two servers.
    private static string[] Rows(string text) =>
        text.Split('\n').Where(l => l.Contains(" code x", StringComparison.Ordinal)).ToArray();
}
