using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Corvus.Core;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>summarize_file on a file above the stream threshold: the same facts as from the bytes, in bounded memory.</summary>
public sealed class StreamedSummaryTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    public void Dispose() { _ws.Dispose(); _dir.Dispose(); }

    private InspectionService.FileSummary Summary(string path, bool streamed) =>
        new InspectionService(_ws) { StreamAbove = streamed ? 64 : FileInput.StreamAbove }.Summarize(null, path, default);

    /// <summary>A raw-IP pcap of <paramref name="count"/> UDP datagrams of <paramref name="payload"/> bytes over 50 flows.</summary>
    internal static void WritePcap(Stream o, long count, int payload = 64)
    {
        Span<byte> header = stackalloc byte[24];
        BinaryPrimitives.WriteUInt32LittleEndian(header, 0xA1B2C3D4);
        BinaryPrimitives.WriteUInt16LittleEndian(header[4..], 2);
        BinaryPrimitives.WriteUInt16LittleEndian(header[6..], 4);
        BinaryPrimitives.WriteUInt32LittleEndian(header[16..], 65535);
        BinaryPrimitives.WriteUInt32LittleEndian(header[20..], 101);
        o.Write(header);
        const int Batch = 1000;
        int frame = 16 + 28 + payload;
        var block = new byte[Batch * frame];
        for (int i = 0; i < Batch; i++)
        {
            var f = block.AsSpan(i * frame, frame);
            BinaryPrimitives.WriteUInt32LittleEndian(f, (uint)(1_700_000_000 + i));
            BinaryPrimitives.WriteUInt32LittleEndian(f[8..], (uint)(28 + payload));
            BinaryPrimitives.WriteUInt32LittleEndian(f[12..], (uint)(28 + payload));
            var ip = f[16..];
            ip[0] = 0x45;
            BinaryPrimitives.WriteUInt16BigEndian(ip[2..], (ushort)(28 + payload));
            ip[8] = 64;
            ip[9] = 17;
            ((ReadOnlySpan<byte>)[10, 0, 0, 2]).CopyTo(ip[12..]);
            ((ReadOnlySpan<byte>)[10, 0, 1, (byte)(i % 50)]).CopyTo(ip[16..]);
            BinaryPrimitives.WriteUInt16BigEndian(ip[20..], 40000);
            BinaryPrimitives.WriteUInt16BigEndian(ip[22..], 9000);
            BinaryPrimitives.WriteUInt16BigEndian(ip[24..], (ushort)(8 + payload));
        }
        for (long written = 0; written < count; written += Batch)
            o.Write(block, 0, (int)Math.Min(Batch, count - written) * frame);
    }

    [Fact]
    public void Capture_streamed_gives_the_facts_of_the_bytes()
    {
        var path = _dir.File("c.pcap");
        using (var f = File.Create(path)) WritePcap(f, 3000);
        var whole = Summary(path, streamed: false);
        var streamed = Summary(path, streamed: true);
        Assert.Equal(whole.File, streamed.File);
        Assert.Equal(3000, ((PcapFileView.Facts)streamed.Views["pcap"].Detail).Packets);
        Assert.Equal(((PcapFileView.Facts)whole.Views["pcap"].Detail).FlowCount, ((PcapFileView.Facts)streamed.Views["pcap"].Detail).FlowCount);
        Assert.Contains(streamed.Notes, n => n.StartsWith("Read as a stream (", StringComparison.Ordinal));
        Assert.Contains(streamed.Notes, n => n.Contains("packet capture, read as a stream: not a container", StringComparison.Ordinal));
        Assert.DoesNotContain("firmware", streamed.Views.Keys);
    }

    [Fact]
    public void Zip_streamed_finds_the_assemblies_of_the_bytes()
    {
        var path = _dir.File("app.nupkg");
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Create))
        {
            zip.CreateEntryFromFile(Env.FixturePath, "lib/net10.0/" + Path.GetFileName(Env.FixturePath));
            zip.CreateEntry("app.nuspec").Open().Dispose();
        }
        var whole = Summary(path, streamed: false);
        var streamed = Summary(path, streamed: true);
        Assert.Equal("NuGet package", streamed.Container);
        Assert.Equal(whole.Container, streamed.Container);
        Assert.NotEmpty(streamed.Assemblies);
        Assert.Equal(whole.Assemblies.Select(a => (a.Path, a.Sha256)), streamed.Assemblies.Select(a => (a.Path, a.Sha256)));
    }

    [Fact]
    public void Har_streamed_lists_the_entries_of_the_bytes()
    {
        var body = Convert.ToBase64String(File.ReadAllBytes(Env.FixturePath));
        var har = JsonSerializer.SerializeToUtf8Bytes(new
        {
            log = new
            {
                pages = new[] { new { id = "p", title = new string('t', 200_000) } },
                entries = new object[]
                {
                    new { request = new { method = "GET", url = "https://app.example/" }, response = new { status = 200, content = new { mimeType = "text/html", text = "<p>" } } },
                    new { request = new { method = "GET", url = "https://app.example/lib.dll" }, response = new { status = 200, content = new { mimeType = "application/octet-stream", text = body, encoding = "base64" } } },
                },
            },
        });
        var path = _dir.File("s.har");
        File.WriteAllBytes(path, [0xEF, 0xBB, 0xBF, .. har]);
        var streamed = Summary(path, streamed: true);
        Assert.Equal(Captures.HarKind, streamed.Container);
        Assert.Equal(Summary(path, streamed: false).Assemblies.Select(a => a.Sha256), streamed.Assemblies.Select(a => a.Sha256));
        Assert.Equal("app.example/lib.dll", Assert.Single(streamed.Assemblies).Path);
    }

    [Fact]
    public void Flows_streamed_list_the_responses_of_the_bytes()
    {
        var path = _dir.File("capture.flows");
        File.WriteAllBytes(path, CaptureTests.Flows());
        var whole = Summary(path, streamed: false);
        var streamed = Summary(path, streamed: true);
        Assert.Equal(Captures.FlowKind, streamed.Container);
        Assert.Equal(whole.Notes.Where(n => !n.StartsWith("Read as a stream", StringComparison.Ordinal)), streamed.Notes.Where(n => !n.StartsWith("Read as a stream", StringComparison.Ordinal)));

        var notes = new List<string>();
        var read = new List<CapturedResponse>();
        Captures.ReadFlows(new TrickleStream(CaptureTests.Flows()[..^10], 7), read.Add, notes, 1 << 20, default);
        Assert.Equal(["https://api.example/v1/config?x=1", "http://api.example:8080/script"], read.Select(r => r.Url));
        Assert.StartsWith("Flow file damaged at byte", notes[0]);
        notes.Clear();
        Captures.ReadFlows(new MemoryStream(CaptureTests.Flows()), _ => { }, notes, 64, default);
        Assert.StartsWith("A flow at byte 0 is larger than 64 bytes; 0 flow(s) read before it.", Assert.Single(notes));
    }

    [Fact]
    public void Endpoint_rows_of_a_capture_are_read_as_a_stream()
    {
        var flows = _dir.File("capture.flows");
        File.WriteAllBytes(flows, CaptureTests.Flows());
        var har = _dir.File("capture.har");
        File.WriteAllText(har, """{"log":{"entries":[{"request":{"method":"GET","url":"https://a.example/items/12?q=1"},"response":{"status":200,"content":{"text":"AAAA","encoding":"base64"}}},{"request":{"method":"GET","url":"https://a.example/items/13?q=2"},"response":{"status":404}}]}}""");
        var unpack = new UnpackService(_ws);
        var fromHar = unpack.Search(har, "*", "endpoint", 100, AnalysisLimits.Default, default);
        Assert.Equal((Captures.HarKind, 2), (fromHar.Container, fromHar.Searched));
        Assert.Equal("GET https://a.example/items/{n}?q=… | 2 request(s), status 200, 404 | capture", $"{Assert.Single(fromHar.Items).Name} | {fromHar.Items[0].Detail} | {fromHar.Items[0].Seen}");
        var fromFlows = unpack.Search(flows, "*", "endpoint", 100, AnalysisLimits.Default, default);
        Assert.Equal((Captures.FlowKind, 3), (fromFlows.Container, fromFlows.Searched));
        Assert.Equal(["GET http://api.example:8080/script", "GET https://api.example/broken", "GET https://api.example/v1/config?x=…"], fromFlows.Items.Select(i => i.Name).Order(StringComparer.Ordinal));
        Assert.Contains(fromFlows.Notes, n => n.StartsWith("1 flow(s) that are not HTTP", StringComparison.Ordinal));
    }

    [Fact]
    public void Native_images_are_held_without_their_overlay()
    {
        var overlay = new byte[300_000];
        new Random(2).NextBytes(overlay);
        var pe = new PeBuilder { Overlay = overlay };
        pe.Sections.Add(new PeBuilder.Section { Name = ".text", Data = new byte[0x400], Characteristics = 0x60000020 });
        var elf = new NativeFormats.ElfWriter().Build();
        var macho = new NativeFormats.MachOWriter().Build();
        foreach (var (name, image, appended) in new[] { ("a.dll", pe.Build(), Array.Empty<byte>()), ("a.so", elf, overlay), ("a.dylib", macho, overlay) })
        {
            var path = _dir.File(name);
            File.WriteAllBytes(path, [.. image, .. appended]);
            var input = FileInput.Open(path, streamAbove: 64);
            Assert.Equal(new FileInfo(path).Length - overlay.Length, input.Image.Length);
            var whole = Summary(path, streamed: false);
            var streamed = Summary(path, streamed: true);
            Assert.Equal(whole.File.Type, streamed.File.Type);
            Assert.Equal(whole.Views.Keys.Order(), streamed.Views.Keys.Order());
            Assert.Contains(streamed.Notes, n => n.Contains($"the {overlay.Length:N0} bytes after it (an overlay) are not held", StringComparison.Ordinal));
        }
    }

    [Fact]
    [FuzzEntry(typeof(ImageExtent))]
    public void Fuzzed_image_extents_never_throw()
    {
        var failures = new List<string>();
        foreach (var seed in new[] { new NativeFormats.ElfWriter().Build(), new NativeFormats.ElfWriter { Is64 = false }.Build(), new NativeFormats.MachOWriter().Build(),
                     NativeFormats.MachOWriter.Fat([(NativeFormats.MachOWriter.CpuArm64, 0, new NativeFormats.MachOWriter().Build())]) })
            failures.AddRange(FormatFuzz.Run(seed, b =>
            {
                if (ImageExtent.Of(b, b.Length, (at, n) => b.AsSpan((int)at, n).ToArray()) is { } end) Assert.InRange(end, 1, b.Length);
                Containers.OpenLarge(() => new MemoryStream(b, writable: false), b, b, b.Length, "x", AnalysisLimits.Default, default);
            }, 300));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(5)));
    }

    [Fact]
    public void A_streamed_pe_signature_is_verified_in_ranges()
    {
        var folder = Path.GetDirectoryName(ContainerFixtures.NuGetPackage("Microsoft.CodeAnalysis.Common"))!;
        var signed = Directory.EnumerateFiles(Path.Combine(folder, "lib"), "Microsoft.CodeAnalysis.dll", SearchOption.AllDirectories).Order(StringComparer.Ordinal).First();
        var path = _dir.File("signed.dll");
        File.Copy(signed, path);
        var whole = Summary(path, streamed: false).File.Certificate;
        Assert.True(whole.Present && whole.DigestMatches == true, whole.ToString());
        Assert.Equal(whole, Summary(path, streamed: true).File.Certificate);
        // A signature over other bytes.
        var grafted = _dir.File("grafted.dll");
        File.WriteAllBytes(grafted, ContainerFuzzTests.SignedFixture());
        Assert.Equal((true, false), (Summary(grafted, streamed: true).File.Certificate.Present, Summary(grafted, streamed: true).File.Certificate.DigestMatches));
    }

    [Fact]
    public void Embedded_assemblies_are_carved_from_a_stream_in_windows()
    {
        var path = _dir.File("blob.bin");
        var padding = new byte[100_000];
        new Random(3).NextBytes(padding);
        File.WriteAllBytes(path, [.. padding, .. File.ReadAllBytes(Env.FixturePath), .. padding]);
        var whole = Summary(path, streamed: false);
        var streamed = Summary(path, streamed: true);
        Assert.Equal(whole.Container, streamed.Container);
        Assert.Equal(whole.Assemblies.Select(a => (a.Path, a.Sha256)), streamed.Assemblies.Select(a => (a.Path, a.Sha256)));
        Assert.Single(streamed.Assemblies);
    }

    [Fact]
    public void Hermes_view_reads_a_package_whole_only_when_it_names_a_bundle()
    {
        var path = _dir.File("app.apk");
        File.WriteAllBytes(path, AndroidSamples.Apk());
        var input = FileInput.Open(path, streamAbove: 64);
        Assert.True(input.Streamed);
        Assert.Null(new HermesFileView().Inspect(input, default));
        Assert.Null(typeof(FileInput).GetField("_bytes", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.GetValue(input));
    }

    [Fact]
    public void Har_reader_refills_across_small_reads()
    {
        var har = Encoding.UTF8.GetBytes("""{"other":{"log":1},"log":{"creator":{"name":"x"},"entries":[{"request":{"method":"GET","url":"https://a/1"},"response":{"status":200,"content":{"text":"one"}}},7,{"request":{"method":"POST","url":"https://a/2"},"response":{"status":201}}]}}""");
        var got = new List<CapturedResponse>();
        Assert.True(Captures.ReadHar(new TrickleStream(har, 5), got.Add, 1 << 20, default));
        Assert.Equal(["GET https://a/1 200 one", "POST https://a/2 201 "], got.Select(r => $"{r.Method} {r.Url} {r.Status} {(r.Body is { } b ? Encoding.UTF8.GetString(b) : "")}"));
        Assert.False(Captures.ReadHar(new MemoryStream("""{"log":{"version":"1.2"}}"""u8.ToArray()), got.Add, 1 << 20, default));
        Assert.False(Captures.ReadHar(new MemoryStream("[1,2]"u8.ToArray()), got.Add, 1 << 20, default));
    }

    [Fact]
    public void Fuzzed_streamed_har_never_throws_past_a_tool_error()
    {
        var seed = Encoding.UTF8.GetBytes("""{"log":{"entries":[{"request":{"method":"GET","url":"https://a/1"},"response":{"status":200,"headers":[{"name":"content-encoding","value":"gzip"}],"content":{"text":"AAEC","encoding":"base64"}}},{"request":{"method":"PUT","url":"https://a/2"}}]}}""");
        var failures = FormatFuzz.Run(seed, b =>
        {
            try { Captures.ReadHar(new TrickleStream(b, 13), _ => { }, 256, default); }
            catch (ToolError) { }
        }, 1500);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(5)));
    }

    /// <summary>A stream that returns at most a few bytes per read.</summary>
    private sealed class TrickleStream(byte[] data, int most) : MemoryStream(data, writable: false)
    {
        public override int Read(byte[] buffer, int offset, int count) => base.Read(buffer, offset, Math.Min(count, most));
        public override int Read(Span<byte> buffer) => base.Read(buffer[..Math.Min(buffer.Length, most)]);
    }
}

/// <summary>The memory ceiling of a streamed summary, each test in a process of its own (the working set is the process's).</summary>
public sealed class StreamedSummaryMemoryTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    public void Dispose() { _ws.Dispose(); _dir.Dispose(); }

    [Fact]
    [Trait("Speed", "Slow")]
    public void Two_gigabyte_capture_summary_stays_within_the_memory_ceiling()
    {
        if (ChildTest.Rerun(this, output)) return;
        var path = _dir.File("large.pcap");
        using (var f = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20)) StreamedSummaryTests.WritePcap(f, 2L * 1024 * 1024 * 1024 / (16 + 28 + 1400), 1400);
        long length = new FileInfo(path).Length;
        GC.Collect();
        GC.WaitForPendingFinalizers();
        long baseline = Environment.WorkingSet, peak = baseline;
        using var done = new ManualResetEventSlim();
        var sampler = new Thread(() => { while (!done.Wait(20)) peak = Math.Max(peak, Environment.WorkingSet); }) { IsBackground = true };
        sampler.Start();
        var clock = Stopwatch.StartNew();
        var summary = new InspectionService(_ws).Summarize(null, path, default);
        clock.Stop();
        done.Set();
        sampler.Join();
        peak = Math.Max(peak, Environment.WorkingSet);
        output.WriteLine($"{length:N0} bytes in {clock.Elapsed.TotalSeconds:F1} s; working set {baseline >> 20} MB before, peak {peak >> 20} MB (+{(peak - baseline) >> 20} MB)");
        Assert.Equal(length, summary.File.Size);
        Assert.True(((PcapFileView.Facts)summary.Views["pcap"].Detail).Packets > 1_000_000);
        Assert.True(peak - baseline < 200L << 20, $"working set grew by {(peak - baseline) >> 20} MB");
    }

    private static void Pattern(Stream o, long count)
    {
        var block = new byte[1 << 20];
        new Random(7).NextBytes(block);
        for (long w = 0; w < count; w += block.Length) o.Write(block, 0, (int)Math.Min(block.Length, count - w));
    }

    /// <summary>A 1 GiB input of each streamed kind: a native image with an overlay, an APK, a flow file, a module, a binary plist, a HAR.</summary>
    private string Gigabyte(string kind, long size = 1L << 30)
    {
        var path = _dir.File($"large-{size}." + kind);
        using var f = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
        switch (kind)
        {
            case "so":
                f.Write(new NativeFormats.ElfWriter().Build());
                Pattern(f, size);
                break;
            case "apk":
                using (var zip = new ZipArchive(f, ZipArchiveMode.Create, leaveOpen: true))
                {
                    foreach (var (name, data) in new[] { ("AndroidManifest.xml", AndroidSamples.Manifest()), ("resources.arsc", AndroidSamples.Resources()), ("classes.dex", AndroidSamples.Dex()) })
                        using (var e = zip.CreateEntry(name).Open()) e.Write(data);
                    using var big = zip.CreateEntry("assets/big.bin", CompressionLevel.NoCompression).Open();
                    Pattern(big, size);
                }
                break;
            case "flows":
                static byte[] B(byte[] b) => [.. Encoding.ASCII.GetBytes($"{b.Length}:"), .. b, (byte)','];
                static byte[] S(string s) => B(Encoding.UTF8.GetBytes(s));
                static byte[] D(params byte[][] items) { byte[] inner = [.. items.SelectMany(x => x)]; return [.. Encoding.ASCII.GetBytes($"{inner.Length}:"), .. inner, (byte)'}']; }
                var flow = D(S("type"), S("http"), S("request"), D(S("method"), S("GET"), S("scheme"), S("https"), S("host"), S("a.example"), S("path"), S("/items/1")),
                    S("response"), D(S("status_code"), "3:200#"u8.ToArray(), S("content"), B(new byte[64 << 10])));
                for (long w = 0; w < size; w += flow.Length) f.Write(flow);
                break;
            case "wasm":
                f.Write([0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x00, .. WasmAsm.Leb(1 + 3 + (ulong)size), 3, .. "big"u8]);
                Pattern(f, size);
                break;
            case "plist":
                f.Write([.. "bplist00"u8, 0x4F, 0x13]);
                Span<byte> be = stackalloc byte[8];
                BinaryPrimitives.WriteInt64BigEndian(be, size);
                f.Write(be);
                Pattern(f, size);
                long table = f.Position;
                BinaryPrimitives.WriteInt64BigEndian(be, 8);
                f.Write(be);
                var trailer = new byte[32];
                (trailer[6], trailer[7]) = (8, 1);
                BinaryPrimitives.WriteInt64BigEndian(trailer.AsSpan(8), 1);
                BinaryPrimitives.WriteInt64BigEndian(trailer.AsSpan(24), table);
                f.Write(trailer);
                break;
            case "har":
                var entry = Encoding.UTF8.GetBytes("""{"request":{"method":"GET","url":"https://a.example/items/1"},"response":{"status":200,"content":{"text":" """.TrimEnd() + new string('x', 60_000) + "\"}}}");
                f.Write("""{"log":{"entries":["""u8);
                for (long w = 0; w < size; w += entry.Length + 1) { f.Write(entry); f.WriteByte((byte)','); }
                f.Write(entry);
                f.Write("]}}"u8);
                break;
        }
        return path;
    }

    [Theory]
    [Trait("Speed", "Slow")]
    [InlineData("so")]
    [InlineData("apk")]
    [InlineData("flows")]
    [InlineData("wasm")]
    [InlineData("plist")]
    [InlineData("har")]
    public void Gigabyte_inputs_stay_within_the_memory_ceiling(string kind)
    {
        if (ChildTest.Rerun(this, output, [kind])) return;
        void Read(string path)
        {
            if (kind == "har") Assert.Single(new UnpackService(_ws).Search(path, "*", "endpoint", 100, AnalysisLimits.Default, default).Items);
            else new InspectionService(_ws).Summarize(null, path, default, new FileViewOptions("all"));
        }
        // The same work on 16 MB first, so the code it loads and the heap it sizes are not counted.
        Read(Gigabyte(kind, 16 << 20));
        var path = Gigabyte(kind);
        GC.Collect();
        GC.WaitForPendingFinalizers();
        long baseline = Environment.WorkingSet, peak = baseline;
        using var done = new ManualResetEventSlim();
        var sampler = new Thread(() => { while (!done.Wait(20)) peak = Math.Max(peak, Environment.WorkingSet); }) { IsBackground = true };
        sampler.Start();
        var clock = Stopwatch.StartNew();
        Read(path);
        clock.Stop();
        done.Set();
        sampler.Join();
        peak = Math.Max(peak, Environment.WorkingSet);
        output.WriteLine($"{kind}: {new FileInfo(path).Length:N0} bytes in {clock.Elapsed.TotalSeconds:F1} s; working set +{(peak - baseline) >> 20} MB");
        Assert.True(peak - baseline < 200L << 20, $"working set grew by {(peak - baseline) >> 20} MB");
    }
}
