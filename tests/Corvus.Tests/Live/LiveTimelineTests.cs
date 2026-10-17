using System.Text;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native.Diagnostics;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>An activity source that records what the test sends it.</summary>
internal sealed class ScriptedActivitySource : IActivityTraceSource
{
    public Action<ActivityEntry>? Record { get; private set; }
    public int? ProcessId { get; private set; }
    public int Stops { get; private set; }
    public string? Missing { get; init; }

    public string Name => "scripted trace";

    public ActivityTraceUnavailable? Unavailable() => Missing == null ? null : new(Missing, "use Windows");

    public IActivityTrace Start(int processId, Action<ActivityEntry> record)
    {
        (ProcessId, Record) = (processId, record);
        return new Trace(this);
    }

    public void Send(string category, string name) => Record!(new ActivityEntry(DateTime.UtcNow, category, name));

    private sealed class Trace(ScriptedActivitySource source) : IActivityTrace
    {
        public Task StopAsync()
        {
            source.Stops++;
            return Task.CompletedTask;
        }
    }
}

/// <summary>Activity traces from a scripted source: entries paged with a cursor, names counted, and the kernel providers' fields decoded.</summary>
public sealed class LiveTimelineTests : IDisposable
{
    private static readonly string Sqlite = RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "runtimes", "win-x64", "native", "e_sqlite3.dll");
    private readonly AssemblyWorkspace _workspace = new();
    private readonly LiveSessionService _service;
    private readonly ScriptedLiveBackend _backend;
    private readonly ScriptedActivitySource _source = new();
    private readonly LiveSessionTools _tools;

    public LiveTimelineTests()
    {
        _backend = new ScriptedLiveBackend(Sqlite, 0x7ff6_1000_0000, 0x200000);
        _service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, new ServerOptions())) { Backend = _backend, ActivitySource = _source };
        _tools = new LiveSessionTools(new ServerOptions { AllowLive = true }, _service);
    }

    public void Dispose()
    {
        _service.Dispose();
        _workspace.Dispose();
    }

    [Fact]
    public async Task Entries_page_with_a_cursor_and_the_report_counts_each_name()
    {
        await _tools.LiveSession("attach", program: "4242");
        Assert.Contains("tl-1 tracing live-1", await _tools.LiveTimeline("live-1", "start"));
        Assert.Equal(ScriptedLiveBackend.Pid, _source.ProcessId);
        Assert.Equal(ErrorCode.Conflict, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveTimeline("live-1", "start"))).Code);
        _source.Send("file", @"C:\data\orders.txt");
        _source.Send("registry", @"HKLM\SOFTWARE\Orders\Path");
        _source.Send("file", @"C:\data\orders.txt");
        _source.Send("network", "tcp 127.0.0.1:8080");

        var first = await _tools.LiveTimeline(action: "list", run: "tl-1", limit: 2);
        Assert.Matches(@"#1 \+\d+\.\d{3}s file C:\\data\\orders\.txt\r?\n#2 \+\d+\.\d{3}s registry HKLM\\SOFTWARE\\Orders\\Path\r?\nmore: cursor=3\r?\n", first);
        var rest = await _tools.LiveTimeline(action: "list", run: "tl-1", cursor: "3");
        Assert.Contains("#4 ", rest);
        Assert.Contains("end of the timeline so far; poll again with cursor=5", rest);
        var files = await _tools.LiveTimeline(action: "list", run: "tl-1", category: "file");
        Assert.DoesNotContain("registry", files);

        var report = await _tools.LiveTimeline(action: "report", run: "tl-1");
        Assert.Contains("tl-1 live-1 e_sqlite3.dll: 4 entries (file 2, registry 1, network 1), 3 names, recording", report);
        Assert.Matches(@"\s2  file\s+C:\\data\\orders\.txt\r?\n\s+1  registry\s+HKLM\\SOFTWARE\\Orders\\Path\r?\n\s+1  network\s+tcp 127\.0\.0\.1:8080\r?\n", report);

        Assert.Contains("tl-1 complete: 4 entries", await _tools.LiveTimeline(action: "stop", run: "tl-1"));
        Assert.Equal(1, _source.Stops);
        Assert.Contains("end of the timeline (complete)", await _tools.LiveTimeline(action: "list", run: "tl-1", cursor: "5"));
        Assert.Contains("tl-1 live-1 e_sqlite3.dll: 4 entries, complete", await _tools.LiveTimeline(action: "list"));
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveTimeline(action: "list", run: "tl-1", category: "thread"))).Code);
    }

    [Fact]
    public async Task The_timeline_completes_when_the_program_exits()
    {
        await _tools.LiveSession("attach", program: "4242");
        await _tools.LiveTimeline("live-1", "start");
        _backend.Worker!.Emit(new JsonObject { ["event"] = "exit", ["reason"] = "exit code 0" });
        for (int i = 0; i < 100 && _service.GetTimeline("tl-1").State != "complete"; i++) await Task.Delay(20);
        Assert.Equal("complete", _service.GetTimeline("tl-1").State);
        Assert.Equal(1, _source.Stops);
    }

    [Fact]
    public async Task A_platform_without_a_reader_answers_provider_unavailable()
    {
        using var workspace = new AssemblyWorkspace();
        using var service = new LiveSessionService(workspace, new NativeCodeService(workspace, new ServerOptions()))
        {
            Backend = new ScriptedLiveBackend(Sqlite, 0x7ff6_1000_0000, 0x200000), ActivitySource = new ScriptedActivitySource { Missing = "no reader here" },
        };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true }, service);
        await tools.LiveSession("attach", program: "4242");
        Assert.Equal(ErrorCode.ProviderUnavailable, (await Assert.ThrowsAsync<ToolError>(() => tools.LiveTimeline("live-1", "start"))).Code);
    }

    [Fact]
    public void Registry_names_are_joined_through_key_objects_and_shown_as_hives()
    {
        var d = new ActivityDecoder(7, new DeviceMap([]), "S-1-5-21-1");
        var at = DateTime.UtcNow;
        Assert.Equal("HKLM", d.Key(at, 0, 0xA, 0xB, null, @"\REGISTRY\MACHINE")!.Name);
        Assert.Equal(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", d.Key(at, 0, 0xB, 0xC, null, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion")!.Name);
        Assert.Equal(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName", d.Value(at, 0, 0xC, null, "ProductName")!.Name);
        // a failed open, and the first of a value read's two calls (buffer too small), are left out
        Assert.Null(d.Key(at, unchecked((int)0xC0000034), 0xB, 0, null, "Missing"));
        Assert.Null(d.Value(at, unchecked((int)0x80000005), 0xC, null, "ProductName"));
        Assert.Equal(@"HKCU\Software\Orders", ActivityDecoder.RegistryName(@"\REGISTRY\USER\S-1-5-21-1\Software\Orders", "S-1-5-21-1"));
        Assert.Equal(@"HKCU\Software\Classes\.txt", ActivityDecoder.RegistryName(@"\REGISTRY\USER\S-1-5-21-1_Classes\.txt", "S-1-5-21-1"));
        Assert.Equal(@"HKU\S-1-5-18\Software", ActivityDecoder.RegistryName(@"\Registry\User\S-1-5-18\Software", "S-1-5-21-1"));
    }

    [Fact]
    public void Endpoints_files_and_started_programs_are_decoded_from_the_provider_fields()
    {
        var d = new ActivityDecoder(7, new DeviceMap([(@"\Device\HarddiskVolume2", "C:")]), null);
        var at = DateTime.UtcNow;
        // 127.0.0.1 and port 8080 as the kernel network provider gives them, in network byte order
        Assert.Equal("tcp 127.0.0.1:8080", d.Network(at, 12, BitConverter.ToInt32([127, 0, 0, 1]), 0x901F)!.Name);
        Assert.Equal("tcp [::1]:443", d.Network(at, 28, System.Net.IPAddress.IPv6Loopback.GetAddressBytes(), 0xBB01)!.Name);
        Assert.NotNull(d.Network(at, 42, BitConverter.ToInt32([10, 0, 0, 1]), 0x3500));
        Assert.Null(d.Network(at, 42, BitConverter.ToInt32([10, 0, 0, 1]), 0x3500));
        Assert.Null(d.Network(at, 10, BitConverter.ToInt32([10, 0, 0, 1]), 0x3500));

        Assert.Equal(@"C:\data\orders.txt", d.File(at, @"\Device\HarddiskVolume2\data\orders.txt", 0x60)!.Name);
        Assert.Null(d.File(at, @"\Device\HarddiskVolume2\data", 0x1000021)); // FILE_DIRECTORY_FILE
        Assert.Equal(@"\Device\HarddiskVolume22\x", d.File(at, @"\Device\HarddiskVolume22\x", 0)!.Name);

        // ProcessStart: 48 bytes of fixed fields, the mandatory label SID S-1-16-12288, then ImageName
        var data = new byte[48].Concat(new byte[] { 1, 1, 0, 0, 0, 0, 0, 16, 0, 0x30, 0, 0 })
            .Concat(Encoding.Unicode.GetBytes(@"\Device\HarddiskVolume2\tools\child.exe" + "\0")).Concat(new byte[8]).ToArray();
        Assert.Equal(@"C:\tools\child.exe", d.ProcessStart(at, 99, data).Name);
        Assert.Equal("process 99", d.ProcessStart(at, 99, new byte[20]).Name);
    }
}
