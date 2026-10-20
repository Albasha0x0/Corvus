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
        _tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, _service);
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
        Assert.Equal(files, await _tools.LiveTimeline(action: "list", category: "file")); // a filter without run pages the only timeline

        var report = await _tools.LiveTimeline(action: "report", run: "tl-1");
        Assert.Contains("tl-1 live-1 e_sqlite3.dll: 4 entries (file 2, registry 1, network 1), 3 names, recording", report);
        Assert.Matches(@"\s2  file\s+C:\\data\\orders\.txt\r?\n\s+1  registry\s+HKLM\\SOFTWARE\\Orders\\Path\r?\n\s+1  network\s+tcp 127\.0\.0\.1:8080\r?\n", report);

        Assert.Contains("tl-1 complete: 4 entries", await _tools.LiveTimeline(action: "stop", run: "tl-1"));
        Assert.Equal(1, _source.Stops);
        Assert.Contains("end of the timeline (complete)", await _tools.LiveTimeline(action: "list", run: "tl-1", cursor: "5"));
        Assert.Contains("tl-1 live-1 e_sqlite3.dll: 4 entries, complete", await _tools.LiveTimeline(action: "list"));
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveTimeline(action: "list", run: "tl-1", category: "thread"))).Code);
    }

    /// <summary>tl-1 and tl-2 on one session, one after the other: orders.txt and the registry value in both, the rest in one.</summary>
    private async Task TwoTimelines()
    {
        await _tools.LiveSession("attach", program: "4242");
        await _tools.LiveTimeline("live-1", "start");
        _source.Send("file", @"C:\data\orders.txt");
        _source.Send("file", @"C:\data\old.cfg");
        _source.Send("registry", @"HKLM\SOFTWARE\Orders\Path");
        _source.Send("network", "tcp 127.0.0.1:8080");
        await _tools.LiveTimeline(action: "stop", run: "tl-1");
        await _tools.LiveTimeline("live-1", "start");
        _source.Send("file", @"C:\data\orders.txt");
        _source.Send("file", @"C:\data\orders.txt");
        _source.Send("file", @"C:\data\new.cfg");
        _source.Send("registry", @"HKLM\SOFTWARE\Orders\Path");
        _source.Send("process", @"C:\tools\child.exe");
        await _tools.LiveTimeline(action: "stop", run: "tl-2");
    }

    [Fact]
    public async Task A_filtered_page_with_every_match_ends_the_timeline_and_its_poll_starts_past_the_rest()
    {
        await _tools.LiveSession("attach", program: "4242");
        await _tools.LiveTimeline("live-1", "start");
        _source.Send("file", @"C:\data\orders.txt");
        _source.Send("file", @"C:\data\old.cfg");
        _source.Send("registry", @"HKLM\SOFTWARE\Orders\Path");
        _source.Send("network", "tcp 127.0.0.1:8080");

        var files = await _tools.LiveTimeline(action: "list", run: "tl-1", category: "file", limit: 2);
        Assert.Contains("#2 ", files);
        Assert.DoesNotContain("more:", files);
        Assert.Contains("end of the timeline so far; poll again with cursor=5", files);
        Assert.Contains("more: cursor=2", await _tools.LiveTimeline(action: "list", run: "tl-1", category: "file", limit: 1));
    }

    [Fact]
    public async Task Entry_pages_cut_to_the_output_budget_skip_no_entry()
    {
        await _tools.LiveSession("attach", program: "4242");
        await _tools.LiveTimeline("live-1", "start");
        for (int i = 1; i <= 2000; i++) _source.Send("file", $@"C:\data\file{i}-{new string('x', 50)}.txt");
        using var pipeline = new OutputPipeline();
        var seen = await pipeline.PageAll("live_timeline", 600, (cursor, ct) => _tools.LiveTimeline(action: "list", run: "tl-1", cursor: cursor, limit: 1000, cancellationToken: ct),
            @"file(\d+)-", field: "name");
        Assert.Equal(Enumerable.Range(1, 2000), seen);
    }

    [Fact]
    public async Task Diff_lists_the_pairs_unique_to_each_timeline()
    {
        await TwoTimelines();
        var text = await _tools.LiveTimeline(action: "diff", a: "tl-1", b: "tl-2");
        Assert.Contains("tl-1 e_sqlite3.dll and tl-2 e_sqlite3.dll: 2 names only in tl-1, 2 only in tl-2, 2 in both", text);
        Assert.Matches(@"only in tl-1:\r?\n\s+file\s+C:\\data\\old\.cfg\r?\n\s+network\s+tcp 127\.0\.0\.1:8080\r?\n\s+only in tl-2:\r?\n\s+file\s+C:\\data\\new\.cfg\r?\n\s+process\s+C:\\tools\\child\.exe\r?\n", text);
        Assert.DoesNotContain("orders.txt", text);
        Assert.DoesNotContain(@"Orders\Path", text);

        var files = await _tools.LiveTimeline(action: "diff", a: "tl-1", b: "tl-2", category: "file");
        Assert.Contains("1 name only in tl-1, 1 only in tl-2, 1 in both", files);
        Assert.DoesNotContain("network", files);
        Assert.DoesNotContain("child.exe", files);
    }

    [Fact]
    public async Task Diff_pages_through_offset_and_limit()
    {
        await TwoTimelines();
        var first = await _tools.LiveTimeline(action: "diff", a: "tl-1", b: "tl-2", limit: 3);
        Assert.Contains("4 names (showing 1-3)", first);
        Assert.Contains("new.cfg", first);
        Assert.DoesNotContain("child.exe", first);
        var rest = await _tools.LiveTimeline(action: "diff", a: "tl-1", b: "tl-2", offset: 3, limit: 3);
        Assert.Contains("4 names (showing 4-4)", rest);
        // a page that starts inside a side repeats that side's heading
        Assert.Matches(@"only in tl-2:\r?\n\s+process\s+C:\\tools\\child\.exe", rest);
        Assert.DoesNotContain("old.cfg", rest);
    }

    [Fact]
    public async Task Diff_of_a_timeline_with_itself_is_refused()
    {
        await TwoTimelines();
        var e = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveTimeline(action: "diff", a: "tl-1", b: "TL-1"));
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
        Assert.Contains("pass two different timelines", e.Remediation);
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveTimeline(action: "diff", a: "tl-1", b: "tl-9"))).Code);
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
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, service);
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

    /// <summary>A started program keeps its process id beside the name, so a program that relaunches itself can be attached.</summary>
    [Fact]
    public void A_started_program_carries_its_process_id()
    {
        var started = new ActivityDecoder(7, new DeviceMap([]), null).ProcessStart(DateTime.UtcNow, 4321, []);
        Assert.Equal(("process", 4321), (started.Category, started.ProcessId));
    }

    [Fact]
    public void Keys_held_open_before_the_trace_name_the_root_of_later_relative_opens()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var held = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft")!;
        var keys = OpenKeys.Read(Environment.ProcessId);
        var key = keys.First(k => k.Path.Equals(@"\REGISTRY\MACHINE\SOFTWARE\Microsoft", StringComparison.OrdinalIgnoreCase));
        // the handle table shows object addresses to elevated processes only, as event tracing needs anyway
        ulong keyObject = key.Object != 0 ? key.Object : 0xA;
        var d = new ActivityDecoder(Environment.ProcessId, new DeviceMap([]), null);
        d.Known(keyObject, key.Path);
        Assert.Equal(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            d.Key(DateTime.UtcNow, 0, keyObject, 0xB, null, @"Windows NT\CurrentVersion")!.Name, StringComparer.OrdinalIgnoreCase);
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
