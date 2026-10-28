using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using Corvus.Core;
using Corvus.Core.Logs;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Process Monitor logs: backing files and CSV exports read into one timeline.</summary>
public sealed class ProcmonTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static List<ProcmonLog.Event> Events(string path, out ProcmonLog log)
    {
        var events = new List<ProcmonLog.Event>();
        using var s = File.OpenRead(path);
        log = ProcmonLog.Read(s, events.Add, default);
        return events;
    }

    /// <summary>The time of day as Process Monitor's CSV export writes it, in this machine's time zone.</summary>
    private static string TimeOfDay(DateTime utc)
    {
        var local = utc.ToLocalTime();
        return local.ToString("h:mm:ss", CultureInfo.InvariantCulture) + "." + (local.Ticks % TimeSpan.TicksPerSecond).ToString("D7", CultureInfo.InvariantCulture) +
            local.ToString(" tt", CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// The detail as the export shows it: the export writes each line break as a semicolon and cuts a detail at 4,095
    /// characters and a network detail after its first values, so a longer detail here that begins with the export's is
    /// cut to it.
    /// </summary>
    private static string? Cut(string? mine, string? export)
    {
        mine = mine?.Replace("\r\n", ";").Replace('\n', ';');
        return mine != null && export != null && mine.Length > export.Length && mine.StartsWith(export, StringComparison.Ordinal)
            && (export.Length == 4095 || mine.AsSpan(export.Length).StartsWith(", ")) ? export : mine;
    }

    private static readonly HashSet<string> DetailOperations = ["Process Create", "Load Image", "Thread Create"];

    private static readonly byte[] V4Source = [192, 168, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    private static readonly byte[] V6Source = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    private static readonly byte[] V6Target = [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];

    /// <summary>A capture of worker.exe started by builder.exe: one event of each kind the reader names.</summary>
    private static List<ProcmonSamples.Ev> SampleEvents() =>
    [
        new(0, 11, 1, 1, 0, ProcmonSamples.ProcessCreate(4200, @"C:\work\worker.exe", "worker.exe /job 7")),
        new(1, 77, 1, 3, 0, ProcmonSamples.ThreadCreate(78)),
        new(1, 77, 1, 5, 0, ProcmonSamples.LoadImage(0x7FF600000000, 0x20000, @"C:\work\worker.exe")),
        new(1, 77, 2, 0, 0, ProcmonSamples.RegOpenKey(@"HKLM\Software\Sample", ascii: true)),
        new(1, 77, 2, 5, 0xC0000034, ProcmonSamples.RegQueryValue(@"HKLM\Software\Sample\Mode")),
        new(1, 77, 3, 23, 0, ProcmonSamples.File(@"C:\work\input.dat")),
        new(1, 77, 3, 32, 0, ProcmonSamples.QueryDirectory(@"C:\work\", "*.dat")),
        new(1, 77, 3, 25, 0, ProcmonSamples.File(@"C:\work\input.dat", sub: 0x05)),
        new(1, 77, 5, 5, 0, ProcmonSamples.Network(true, V4Source, 50000, ProcmonSamples.NamedHost, 443, true, 0, "mss", "1460", "sackopt", "1")),
        new(1, 77, 5, 2, 0xC0001234, ProcmonSamples.Network(false, V6Source, 5353, V6Target, 53, false, 48, "seqnum", "0")),
        new(1, 77, 3, 38, 0, ProcmonSamples.File(@"C:\work\input.dat")),
        new(1, 77, 1, 2, 0, new byte[52]),
    ];

    private string Write(byte[] bytes, string name = "capture.pml")
    {
        var path = _dir.File(name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    [Fact]
    public void A_backing_file_names_operations_paths_results_and_details_as_process_monitor_does()
    {
        var events = Events(Write(ProcmonSamples.Log(SampleEvents())), out var log);
        Assert.Empty(log.Notes);
        Assert.Equal(12, events.Count);
        Assert.Equal(
        [
            ("Process Create", @"C:\work\worker.exe", "SUCCESS", "PID: 4200, Command line: worker.exe /job 7"),
            ("Thread Create", "", "SUCCESS", "Thread ID: 78"),
            ("Load Image", @"C:\work\worker.exe", "SUCCESS", "Image Base: 0x7ff600000000, Image Size: 0x20000"),
            ("RegOpenKey", @"HKLM\Software\Sample", "SUCCESS", null),
            ("RegQueryValue", @"HKLM\Software\Sample\Mode", "NAME NOT FOUND", null),
            ("ReadFile", @"C:\work\input.dat", "SUCCESS", null),
            ("QueryDirectory", @"C:\work\*.dat", "SUCCESS", null),
            ("QueryStandardInformationFile", @"C:\work\input.dat", "SUCCESS", null),
            ("TCP Connect", "192.168.1.20:50000 -> files.build.example:https", "SUCCESS", "Length: 0, mss: 1460, sackopt: 1"),
            ("UDP Send", "fe80:0:0:0:0:0:0:1:5353 -> 2001:db8:0:0:0:0:0:5:53", "0xC0001234", "Length: 48, seqnum: 0"),
            ("CloseFile", @"C:\work\input.dat", "SUCCESS", null),
            ("Process Exit", "", "SUCCESS", null),
        ], events.Select(e => (e.Operation, e.Path, e.Result, e.Detail)));
        Assert.Equal(("builder.exe", 4100, 11, "Process"), (events[0].ProcessName, events[0].Pid, events[0].ThreadId, events[0].Class));
        Assert.Equal(("worker.exe", 4200, "File System"), (events[5].ProcessName, events[5].Pid, events[5].Class));
        Assert.Equal(ProcmonSamples.Start.AddMilliseconds(20), events[2].Time);
        Assert.Equal(TimeSpan.FromTicks(1234), events[2].Duration);
    }

    [Fact]
    public void Capture_facts_and_processes_come_from_the_backing_files_tables()
    {
        Events(Write(ProcmonSamples.Log(SampleEvents())), out var log);
        Assert.Equal((9, true, "BUILD-HOST", @"C:\Windows", 12L, "10.0.26100", 8), (log.Header!.Version, log.Header.Is64Bit, log.Header.Computer,
            log.Header.SystemRoot, log.Header.Events, log.Header.Windows, log.Header.Processors));
        var worker = log.Processes[1];
        Assert.Equal((4200, 4100, "worker.exe", @"C:\work\worker.exe", "worker.exe /job 7", @"BUILD\builder", "High", "Sample Company", 1),
            (worker.Pid, worker.ParentPid, worker.Name, worker.ImagePath, worker.CommandLine, worker.User, worker.Integrity, worker.Company, worker.Modules));
        Assert.Equal(ProcmonSamples.Start.AddSeconds(-29), worker.Started);
        Assert.Null(worker.Ended);
    }

    [Fact]
    public void A_csv_export_reads_its_columns_with_quotes_commas_and_line_breaks()
    {
        var path = _dir.File("capture.csv");
        File.WriteAllText(path, "\uFEFF\"Time of Day\",\"Process Name\",\"PID\",\"Operation\",\"Path\",\"Result\",\"Detail\"\r\n" +
            "\"5:06:07.0000000 AM\",\"builder.exe\",\"4100\",\"Process Create\",\"C:\\work\\worker.exe\",\"SUCCESS\",\"PID: 4200, Command line: worker.exe \"\"a, b\"\"\"\r\n" +
            "\"5:06:07.0100000 AM\",\"worker.exe\",\"4200\",\"WriteFile\",\"C:\\work\\out.txt\",\"SUCCESS\",\"line one\r\nline two\"\r\n");
        var events = Events(path, out var log);
        Assert.Equal("Process Monitor CSV export", log.Format);
        Assert.Null(log.Header);
        Assert.Equal(2, events.Count);
        Assert.Equal(("5:06:07.0000000 AM", "builder.exe", 4100, "Process Create", @"C:\work\worker.exe", "PID: 4200, Command line: worker.exe \"a, b\""),
            (events[0].TimeText, events[0].ProcessName, events[0].Pid, events[0].Operation, events[0].Path, events[0].Detail));
        Assert.Equal("line one\nline two", events[1].Detail);
        Assert.Null(events[1].Time);
    }

    [Fact]
    public void The_view_counts_operations_and_pages_one_process_pid_operation_or_result()
    {
        var path = Write(ProcmonSamples.Log(SampleEvents()));
        ProcmonFileView.Facts View(string? table = null, long offset = 0, int? limit = null)
        {
            var f = FileInput.Open(path);
            f.Options = new FileViewOptions("procmon", table, Offset: offset, Limit: limit);
            return (ProcmonFileView.Facts)new ProcmonFileView().Inspect(f, default)!.Detail;
        }
        var all = View(limit: 5);
        Assert.Equal((12L, 12L, 5, 5L), (all.Events, all.Matched, all.Page.Count, all.Next!.Value));
        Assert.Equal(11, all.Processes["worker.exe (4200)"]);
        Assert.Equal(1, all.Results["NAME NOT FOUND"]);
        Assert.Equal(2, all.ProcessTable.Count);
        Assert.Equal((ProcmonSamples.Start, ProcmonSamples.Start.AddMilliseconds(110)), (all.First!.Value, all.Last!.Value));

        Assert.Equal([0L], View("4100").Page.Select(e => e.Number));
        Assert.Equal([5L, 10L], View("readfile").Page.Select(e => e.Number).Concat(View("CloseFile").Page.Select(e => e.Number)));
        Assert.Equal([4L], View("NAME NOT FOUND").Page.Select(e => e.Number));
        var worker = View("worker.exe", offset: 9);
        Assert.Equal((11L, 2), (worker.Matched, worker.Page.Count));
        Assert.Contains("no event of process, PID, operation or result 'none.exe'", View("none.exe").Notes);
    }

    [Fact]
    public void A_capture_that_was_not_closed_is_rejected_and_a_damaged_event_is_a_note()
    {
        var open = ProcmonSamples.Log(SampleEvents());
        BinaryPrimitives.WriteUInt64LittleEndian(open.AsSpan(0x250), 0);
        using (var s = new MemoryStream(open))
            Assert.Contains("not closed", Assert.Throws<InvalidDataException>(() => ProcmonLog.Read(s, _ => { }, default)).Message);
        var f = FileInput.Open(Write(open, "open.pml"));
        f.Options = new FileViewOptions("procmon");
        Assert.Equal(ErrorCode.MalformedInput, Assert.Throws<ToolError>(() => new ProcmonFileView().Inspect(f, default)).Code);

        var damaged = ProcmonSamples.Log(SampleEvents());
        long offsets = (long)BinaryPrimitives.ReadUInt64LittleEndian(damaged.AsSpan(0x248));
        long third = BinaryPrimitives.ReadUInt32LittleEndian(damaged.AsSpan((int)offsets + 2 * 5));
        // The detail size of the third event now runs past the end of the file.
        BinaryPrimitives.WriteUInt32LittleEndian(damaged.AsSpan((int)third + 0x2C), 0xFFFFF);
        var events = Events(Write(damaged, "damaged.pml"), out var log);
        Assert.Equal(11, events.Count);
        Assert.StartsWith("event 2 at 0x", Assert.Single(log.Notes));
    }

    // Regression: a table offset past 2 GiB made MemoryStream throw
    // ArgumentOutOfRangeException from its Position setter.
    [Fact]
    public void A_table_offset_past_the_end_of_a_memory_stream_is_an_end_of_stream()
    {
        var data = ProcmonSamples.Log(SampleEvents());
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(0x258), 0x1_0000_0000);
        using var s = new MemoryStream(data);
        Assert.Throws<EndOfStreamException>(() => ProcmonLog.Read(s, _ => { }, default));
    }

    [Fact]
    [FuzzEntry(typeof(ProcmonLog), typeof(ProcmonFileView))]
    public void Fuzzed_process_monitor_logs_never_throw()
    {
        var csv = Encoding.UTF8.GetBytes("\"Time of Day\",\"Process Name\",\"PID\",\"Operation\",\"Path\",\"Result\",\"Detail\"\r\n" +
            "\"5:06:07.0000000 AM\",\"builder.exe\",\"4100\",\"ReadFile\",\"C:\\work\\a\",\"SUCCESS\",\"Offset: 0\"\r\n");
        var path = _dir.File("fuzz.pml");
        foreach (var sample in new[] { ProcmonSamples.Log(SampleEvents()), csv })
        {
            var failures = FormatFuzz.Run(sample, b =>
            {
                using (var s = new MemoryStream(b))
                    try { ProcmonLog.Read(s, _ => { }, default); }
                    catch (Exception e) when (e is InvalidDataException or EndOfStreamException) { }
                File.WriteAllBytes(path, b);
                try { new ProcmonFileView().Inspect(FileInput.Open(path), default); }
                catch (ToolError e) when (e.Code == ErrorCode.MalformedInput) { }
            }, 100);
            Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
        }
    }

    // Process Monitor (CORVUS_PROCMON) opens the built backing file and saves it as CSV: the fixture is a file it
    // accepts, read the same here.
    [RequiresRealDataFact("CORVUS_PROCMON")]
    [Trait("Speed", "Slow")]
    public void Built_backing_files_read_as_process_monitor_exports_them()
    {
        var pml = Write(ProcmonSamples.Log(SampleEvents()));
        var csv = _dir.File("capture.csv");
        var psi = new ProcessStartInfo(Environment.GetEnvironmentVariable("CORVUS_PROCMON")!) { UseShellExecute = false };
        foreach (var a in new[] { "/AcceptEula", "/Quiet", "/Minimized", "/OpenLog", pml, "/SaveAs", csv }) psi.ArgumentList.Add(a);
        using (var p = Process.Start(psi)!)
            if (!p.WaitForExit(120_000))
            {
                // A file it rejects leaves a message box open.
                p.Kill();
                Assert.Fail("Process Monitor did not exit");
            }
        Assert.True(File.Exists(csv), "Process Monitor wrote no CSV export");
        var mismatches = new List<string>();
        Assert.Equal(12, Compare(pml, csv, mismatches));
        Assert.True(mismatches.Count == 0, string.Join("\n", mismatches));
    }

    /// <summary>Compares a backing file read here with Process Monitor's CSV export of it, event by event; returns the events compared.</summary>
    private long Compare(string pml, string csvPath, List<string> mismatches)
    {
        var ours = Events(pml, out var log);
        var theirs = Events(csvPath, out var csv);
        foreach (var n in log.Notes.Concat(csv.Notes).Take(5)) output.WriteLine($"{Path.GetFileName(pml)}: {n}");
        if (ours.Count != theirs.Count) mismatches.Add($"{Path.GetFileName(pml)}: {ours.Count} events here, {theirs.Count} in the export");
        long compared = 0;
        for (int i = 0; i < Math.Min(ours.Count, theirs.Count); i++)
        {
            var (a, b) = (ours[i], theirs[i]);
            bool detail = DetailOperations.Contains(a.Operation) || a.Class == "Network";
            var mine = (TimeOfDay(a.Time!.Value), a.ProcessName, a.Pid, a.Operation, a.Path, a.Result, detail ? Cut(a.Detail, b.Detail) : null);
            var export = (b.TimeText, b.ProcessName, b.Pid, b.Operation, b.Path, b.Result, detail ? b.Detail : null);
            compared++;
            if (mine != export && mismatches.Count < 400) mismatches.Add($"{Path.GetFileName(pml)} #{i}: {mine}\n    vs {export}");
        }
        return compared;
    }

    // Each backing file under CORVUS_PROCMON_FILES sits beside the CSV export Process Monitor wrote of it (same name,
    // .csv; /OpenLog with /SaveAs, default columns); compared per event: time of day, process name, PID, operation,
    // path and result, and the detail of the operations whose detail is read. The CSV export read here must give the same.
    [RequiresRealDataFact("CORVUS_PROCMON_FILES")]
    [Trait("Speed", "Slow")]
    public void Real_captures_read_as_process_monitor_exports_them()
    {
        var files = Directory.EnumerateFiles(Environment.GetEnvironmentVariable("CORVUS_PROCMON_FILES")!, "*.pml", SearchOption.AllDirectories)
            .Where(p => File.Exists(Path.ChangeExtension(p, ".csv"))).Order(StringComparer.Ordinal).ToList();
        long compared = 0;
        var mismatches = new List<string>();
        var clock = Stopwatch.StartNew();
        foreach (var path in files) compared += Compare(path, Path.ChangeExtension(path, ".csv"), mismatches);
        output.WriteLine($"{files.Count} captures, {compared:N0} events, {clock.Elapsed.TotalSeconds:0.0} s");
        foreach (var m in mismatches.Take(40)) output.WriteLine(m);
        Assert.True(compared > 0, "no event compared");
        Assert.True(mismatches.Count == 0, $"{mismatches.Count} mismatches:\n" + string.Join("\n", mismatches.Take(40)));
    }
}
