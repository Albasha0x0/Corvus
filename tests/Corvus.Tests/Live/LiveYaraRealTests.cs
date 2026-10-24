using System.Text.RegularExpressions;
using Corvus.Native.Providers.Worker;
using Corvus.Native.Providers.Worker.Yara;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Runs where programs for the target can be started and observed and the YARA-X library is found, checked when a test runs.</summary>
[Xunit.Sdk.XunitTestCaseDiscoverer(RunTimeSkips.FactDiscoverer, RunTimeSkips.Assembly)]
public sealed class LiveYaraFactAttribute(string target) : FactAttribute, IRunTimeSkip
{
    public string? RunTimeSkip() => LiveTarget.Of(target).Missing ?? (LiveTarget.Musl ? LiveTarget.MuslStart : null) ?? YaraTestTools.Missing("library");
}

/// <summary>live_read rules= on each target: a rule matches the text a program writes to its data section, at that text's address.</summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
[Permit("live")]
public sealed class LiveYaraRealTests(ITestOutputHelper output) : LiveToolCalls(output), IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [LiveYaraFact("win-x64")] public Task Finds_on_win_x64() => Finds(LiveTarget.WinX64);
    [LiveYaraFact("linux-x64")] public Task Finds_on_linux_x64() => Finds(LiveTarget.LinuxX64);

    private async Task Finds(LiveTarget target)
    {
        using var pool = new WorkerPool(new WorkerPoolOptions
        {
            Enabled = true,
            MemoryLimitBytes = 0,
            Start = WorkerPool.OwnCommand() with { Environment = new Dictionary<string, string?> { [YaraX.LibraryVariable] = YaraTestTools.Library } },
        });
        // The server started below runs in this flow, so its scans use this pool, whose workers end with it.
        using var shared = WorkerPool.UseShared(pool);
        // values fills g_text with a..z repeated, then passes it to Show.
        var exe = target.Build(_dir, "values", LivePrograms.Values);
        await using var server = await Server();
        await Spawn(server, exe, "live-1", "3", "500");
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "Show" });
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 });
        var register = target.FirstArgument!;
        var regs = await Ok(server, "live_read", new() { ["session"] = "live-1", ["registers"] = register });
        var text = Convert.ToUInt64(Regex.Match(regs, $@"{register} +0x([0-9a-fA-F]+)").Groups[1].Value, 16);

        var scan = await Ok(server, "live_read", new()
        {
            ["session"] = "live-1",
            ["rules"] = "rule alphabet { strings: $a = \"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz\" condition: $a }",
        });
        Assert.Matches($@"  alphabet at 0x{text:X}\b", scan);
        Assert.Contains($"$a at 0x{text:X}+52", scan);
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
    }
}
