using System.Text;
using Corvus.Core;
using Corvus.Native.Providers.Worker;
using Corvus.Native.Providers.Worker.Yara;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>live_read rules=: a session's writable memory saved by a scripted backend and scanned with YARA rules.</summary>
public sealed class LiveYaraTests : LiveSessionTestBase
{
    private const string Rule = "rule written { strings: $a = \"written-by-the-program\" condition: $a }";

    [YaraFact]
    public async Task A_rule_matches_a_string_in_program_memory_at_its_address()
    {
        using var pool = new WorkerPool(new WorkerPoolOptions
        {
            Enabled = true,
            MemoryLimitBytes = 0,
            Start = WorkerPool.OwnCommand() with { Environment = new Dictionary<string, string?> { [YaraX.LibraryVariable] = YaraTestTools.Library } },
        });
        using var shared = WorkerPool.UseShared(pool);
        await _tools.LiveSession("spawn", program: Sqlite);
        _backend.Memory[0x5000_0010] = Encoding.ASCII.GetBytes("--written-by-the-program--");
        var (report, text) = await BuildToolCalls.Collected<LiveSessionTools.LiveReadReport>(() => _tools.LiveRead("live-1", rules: Rule));
        var row = Assert.Single(report.Memory);
        Assert.Equal(("written", "yara", "0x50000012"), (row.Name, row.Type, row.Address));
        Assert.Equal("$a at 0x50000012+22", row.Value);
        Assert.Contains("Note: Writable memory of the running program: 1 ranges, 26 bytes saved", text);
    }

    [Fact]
    public async Task A_program_on_macOS_reports_the_scan_not_supported()
    {
        using var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options()))
        {
            Backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { Platform = "darwin" },
        };
        var tools = new LiveSessionTools(new ServerOptions { AllowLiveSpawn = true }, service);
        await tools.LiveSession("spawn", program: Sqlite);
        var refused = await Assert.ThrowsAsync<ToolError>(() => tools.LiveRead("live-1", rules: Rule));
        Assert.Equal((ErrorCode.Unsupported, "a live YARA scan is not supported on macOS."), (refused.Code, refused.Message));
    }

    [Fact]
    public async Task A_backend_that_cannot_save_memory_reports_the_scan_not_checked()
    {
        using var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options()))
        {
            Backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { Captures = false },
        };
        var tools = new LiveSessionTools(new ServerOptions { AllowLiveSpawn = true }, service);
        await tools.LiveSession("spawn", program: Sqlite);
        var refused = await Assert.ThrowsAsync<ToolError>(() => tools.LiveRead("live-1", rules: Rule));
        Assert.Equal(ErrorCode.Unsupported, refused.Code);
        Assert.Equal("the scripted session worker cannot save program memory, so the scan is not checked.", refused.Message);
    }
}
