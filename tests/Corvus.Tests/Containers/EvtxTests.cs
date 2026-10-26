using System.Diagnostics;
using System.Text;
using System.Xml.Linq;
using Corvus.Core;
using Corvus.Core.Logs;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Windows event log files: records rendered from binary XML, recovered records, the timeline view.</summary>
public sealed class EvtxTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static List<EvtxFile.Event> Events(string path, out EvtxFile file)
    {
        var events = new List<EvtxFile.Event>();
        using var s = File.OpenRead(path);
        file = EvtxFile.Read(s, events.Add, default);
        return events;
    }

    /// <summary>An element as one string: name, attributes in name order, text and children.</summary>
    private static string Canonical(XElement e)
    {
        var sb = new StringBuilder();
        void Walk(XElement x)
        {
            sb.Append('<').Append(x.Name.LocalName);
            foreach (var a in x.Attributes().Where(a => !a.IsNamespaceDeclaration).OrderBy(a => a.Name.LocalName, StringComparer.Ordinal))
                sb.Append(' ').Append(a.Name.LocalName).Append("='").Append(a.Value).Append('\'');
            sb.Append('>');
            foreach (var n in x.Nodes())
                if (n is XElement child) Walk(child);
                else if (n is XText t) sb.Append(t.Value);
            sb.Append("</>");
        }
        Walk(e);
        return sb.ToString();
    }

    private static readonly Guid ProviderGuid = Guid.Parse("0f3c9a52-7d4e-4b61-a2f8-5c1e9d73b046");

    private static EvtxSamples.Sample Sample(ulong id, ushort eventId = 4104, string provider = "Sample-Provider", Guid? activity = null) =>
        new(id, provider, ProviderGuid, eventId, 3, new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc).AddTicks(1234567 + (long)id * 10_000_000), 1200, 34,
            "Sample/Operational", "build-host", @"C:\work\report.txt", ["one", "", "three"], activity, EvtxSamples.LocalSystem);

    private string Write(byte[] bytes, string name = "sample.evtx")
    {
        var path = _dir.File(name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static EvtxFileView.Facts View(string path, string? table = null, long offset = 0, int? limit = null)
    {
        var f = FileInput.Open(path);
        f.Options = new FileViewOptions("evtx", table, Offset: offset, Limit: limit);
        return (EvtxFileView.Facts)new EvtxFileView().Inspect(f, default)!.Detail;
    }

    [Fact]
    public void A_templated_event_renders_with_its_substitutions_as_the_event_log_writes_it()
    {
        var events = Events(Write(EvtxSamples.Log([Sample(41)])), out var file);
        var e = Assert.Single(events);
        Assert.Equal("<Event xmlns='" + EvtxSamples.Namespace + "'><System><Provider Name='Sample-Provider' Guid='{0f3c9a52-7d4e-4b61-a2f8-5c1e9d73b046}'/>" +
            "<EventID>4104</EventID><Level>3</Level><TimeCreated SystemTime='2026-01-02T03:04:46.1234567Z'/><EventRecordID>41</EventRecordID><Correlation/>" +
            "<Execution ProcessID='1200' ThreadID='34'/><Channel>Sample/Operational</Channel><Computer>build-host</Computer><Security UserID='S-1-5-18'/></System>" +
            @"<EventData><Data Name='Path'>C:\work\report.txt</Data><Data Name='Items'>one</Data><Data Name='Items'></Data><Data Name='Items'>three</Data>" +
            "</EventData></Event>", e.Xml);
        Assert.Equal(("Sample-Provider", 4104, 3, "Sample/Operational", "build-host", 1200, 34, "S-1-5-18", 41UL),
            (e.Provider, e.EventId, e.Level, e.Channel, e.Computer, e.ProcessId, e.ThreadId, e.UserId, e.EventRecordId));
        Assert.Equal(new DateTime(2026, 1, 2, 3, 4, 46, DateTimeKind.Utc).AddTicks(1234567), e.Created);
        Assert.Equal(["Path", "Items", "Items", "Items"], e.Data.Select(d => d.Key));
        Assert.Equal((1, 1, 0L, false), (file.Chunks, file.Records, file.Recovered, e.Recovered));
        Assert.Empty(file.Notes);
    }

    [Fact]
    public void Later_events_reuse_templates_and_names_by_chunk_offset_and_nested_values_are_escaped()
    {
        var activity = Guid.Parse("a1b2c3d4-0000-4000-8000-00000000abcd");
        var events = Events(Write(EvtxSamples.Log([Sample(1), Sample(2, 7, activity: activity), new EvtxSamples.NestedData(Sample(3, 9, "Plain-Provider"), "a & b < c")])), out var file);
        Assert.Equal(3, events.Count);
        Assert.Contains("<Correlation ActivityID='{a1b2c3d4-0000-4000-8000-00000000abcd}'/>", events[1].Xml);
        Assert.Equal((7, 2UL), (events[1].EventId, events[1].EventRecordId));
        Assert.StartsWith("<Event xmlns='" + EvtxSamples.Namespace + "'><System><Provider Name='Plain-Provider' Guid=", events[2].Xml);
        Assert.EndsWith("</System><EventData><Data>a &amp; b &lt; c</Data></EventData></Event>", events[2].Xml);
        Assert.Equal(("Plain-Provider", 9), (events[2].Provider, events[2].EventId));
        Assert.Equal(new KeyValuePair<string, string>("#0", "a & b < c"), Assert.Single(events[2].Data));
        Assert.Empty(file.Notes);
    }

    [Fact]
    public void Events_in_a_chunks_free_space_are_recovered_and_marked()
    {
        var events = Events(Write(EvtxSamples.Log([Sample(1), Sample(2)], free: [Sample(90, 1102)])), out var file);
        Assert.Equal((2L, 1L), (file.Records, file.Recovered));
        var recovered = Assert.Single(events, e => e.Recovered);
        Assert.Equal((1102, 90UL), (recovered.EventId, recovered.EventRecordId));
    }

    [Fact]
    public void A_changed_record_byte_is_named_by_the_chunk_checksum_and_still_read()
    {
        var bytes = EvtxSamples.Log([Sample(1)]);
        int at = bytes.AsSpan().IndexOf(Encoding.Unicode.GetBytes("build-host"));
        bytes[at] = (byte)'B';
        var events = Events(Write(bytes), out var file);
        Assert.Equal("Build-host", Assert.Single(events).Computer);
        Assert.Contains("chunk 0: record checksum does not match", file.Notes);
    }

    [Fact]
    public void A_file_without_the_header_signature_is_rejected()
    {
        var bytes = EvtxSamples.Log([Sample(1)]);
        bytes[0] = (byte)'X';
        using var s = new MemoryStream(bytes);
        Assert.Throws<InvalidDataException>(() => EvtxFile.Read(s, _ => { }, default));
        var f = FileInput.Open(Write(bytes));
        f.Options = new FileViewOptions("evtx");
        Assert.Null(new EvtxFileView().Inspect(f, default));
    }

    [Fact]
    public void The_view_counts_by_provider_and_event_id_and_pages_one_providers_events()
    {
        var path = Write(EvtxSamples.Log([Sample(1, 10), Sample(2, 20), Sample(3, 10, "Other-Provider"), Sample(4, 10), Sample(5, 30)], dirty: true));
        var all = View(path, limit: 2);
        Assert.Equal((5L, 5L, 2, 2L), (all.Records, all.Matched, all.Page.Count, all.Next!.Value));
        Assert.Equal(4, all.Providers["Sample-Provider"]);
        Assert.Equal(2, all.EventIds["Sample-Provider/10"]);
        Assert.Equal(5, all.Levels["warning"]);
        Assert.True(all.Header.Dirty);
        Assert.Equal(all.Page[0].Created, all.First);

        var byId = View(path, "10");
        Assert.Equal([1UL, 3UL, 4UL], byId.Page.Select(r => r.EventRecordId!.Value));
        var pair = View(path, "sample-provider/10", offset: 1);
        Assert.Equal((2L, 4UL), (pair.Matched, Assert.Single(pair.Page).EventRecordId!.Value));
        Assert.Null(pair.Next);
        Assert.Contains("no event of provider or event id 'None'", View(path, "None").Notes);
    }

    // wevtutil (CORVUS_WEVTUTIL) reads the built log: the fixture is a file Windows accepts, rendered the same here.
    [RequiresRealDataFact("CORVUS_WEVTUTIL")]
    [Trait("Speed", "Slow")]
    public void Built_logs_render_as_wevtutil_renders_them()
    {
        var path = Write(EvtxSamples.Log([Sample(1), Sample(2, 7, activity: Guid.NewGuid()), new EvtxSamples.NestedData(Sample(3, 9, "Plain-Provider"), "a & b < c")]));
        var reference = Wevtutil(path);
        var ours = Events(path, out _);
        Assert.Equal(reference.Select(Canonical), ours.Select(e => Canonical(XElement.Parse(e.Xml))));
    }

    [Fact]
    [FuzzEntry(typeof(EvtxFile), typeof(EvtxFileView))]
    public void Fuzzed_event_logs_never_throw()
    {
        var sample = EvtxSamples.Log([Sample(1), Sample(2, 7, activity: Guid.NewGuid()), new EvtxSamples.NestedData(Sample(3, 9, "Plain"), "x")], free: [Sample(4)]);
        var path = _dir.File("fuzz.evtx");
        var failures = FormatFuzz.Run(sample, b =>
        {
            using (var s = new MemoryStream(b))
                try { EvtxFile.Read(s, _ => { }, default); }
                catch (InvalidDataException) { }
            File.WriteAllBytes(path, b);
            try { new EvtxFileView().Inspect(FileInput.Open(path), default); }
            catch (ToolError e) when (e.Code == ErrorCode.MalformedInput) { }
        }, 100);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    private static ulong XmlRecordId(XElement e) => ulong.Parse(e.Descendants().First(x => x.Name.LocalName == "EventRecordID").Value);

    // wevtutil (CORVUS_WEVTUTIL) renders every record of each event log under CORVUS_EVTX_FILES; compared: each record's
    // XML (element and attribute names and values, text) by record id.
    [RequiresRealDataFact("CORVUS_WEVTUTIL", "CORVUS_EVTX_FILES")]
    [Trait("Speed", "Slow")]
    public void Real_event_logs_render_as_wevtutil_renders_them()
    {
        var files = Directory.EnumerateFiles(Environment.GetEnvironmentVariable("CORVUS_EVTX_FILES")!, "*.evtx", SearchOption.AllDirectories).Order(StringComparer.Ordinal).ToList();
        long records = 0, recovered = 0;
        var mismatches = new List<string>();
        var clock = Stopwatch.StartNew();
        foreach (var path in files)
        {
            var ours = Events(path, out var file);
            recovered += file.Recovered;
            var live = ours.Where(e => !e.Recovered).ToList();
            var reference = Wevtutil(path);
            records += live.Count;
            if (reference.Count != live.Count) mismatches.Add($"{Path.GetFileName(path)}: wevtutil {reference.Count} records, here {live.Count}");
            // An exported log numbers its record headers from 1; the XML keeps each event's own EventRecordID.
            var byId = live.GroupBy(e => XmlRecordId(XElement.Parse(e.Xml))).ToDictionary(g => g.Key, g => g.First());
            foreach (var r in reference)
            {
                var id = XmlRecordId(r);
                if (!byId.TryGetValue(id, out var e)) { mismatches.Add($"{Path.GetFileName(path)} {id}: not read here"); continue; }
                var mine = Canonical(XElement.Parse(e.Xml));
                var theirs = Canonical(r);
                if (mine != theirs && mismatches.Count < 400)
                {
                    int at = Enumerable.Range(0, Math.Min(mine.Length, theirs.Length)).FirstOrDefault(i => mine[i] != theirs[i], Math.Min(mine.Length, theirs.Length));
                    mismatches.Add($"{Path.GetFileName(path)} {id}: ...{mine[Math.Max(0, at - 60)..Math.Min(mine.Length, at + 80)]}\n    vs ...{theirs[Math.Max(0, at - 60)..Math.Min(theirs.Length, at + 80)]}");
                }
            }
            foreach (var n in file.Notes.Take(5)) output.WriteLine($"{Path.GetFileName(path)}: {n}");
        }
        output.WriteLine($"{files.Count} files, {records:N0} records, {recovered:N0} recovered, {clock.Elapsed.TotalSeconds:0.0} s with wevtutil");
        foreach (var m in mismatches.Take(40)) output.WriteLine(m);
        Assert.True(records > 0, "no record read");
        Assert.True(mismatches.Count == 0, $"{mismatches.Count} mismatches:\n" + string.Join("\n", mismatches.Take(40)));
    }

    private static List<XElement> Wevtutil(string path)
    {
        var psi = new ProcessStartInfo(Environment.GetEnvironmentVariable("CORVUS_WEVTUTIL")!) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, StandardOutputEncoding = Encoding.Unicode };
        foreach (var a in new[] { "qe", path, "/lf:true", "/f:xml", "/uni:true" }) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var text = p.StandardOutput.ReadToEnd();
        var error = p.StandardError.ReadToEnd();
        p.WaitForExit();
        Assert.True(p.ExitCode == 0, $"wevtutil exit {p.ExitCode}: {error}");
        return [.. XElement.Parse("<all>" + text + "</all>").Elements()];
    }
}
