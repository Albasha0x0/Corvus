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
            zip.CreateEntryFromFile(typeof(StreamedSummaryTests).Assembly.Location, "lib/net10.0/Corvus.Tests.dll");
            zip.CreateEntry("app.nuspec").Open().Dispose();
        }
        var whole = Summary(path, streamed: false);
        var streamed = Summary(path, streamed: true);
        Assert.Equal("NuGet package", streamed.Container);
        Assert.Equal(whole.Container, streamed.Container);
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

/// <summary>The memory ceiling of a streamed summary, measured without other tests running (the working set is the process's).</summary>
[Collection(nameof(SerialTimingTests))]
public sealed class StreamedSummaryMemoryTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    public void Dispose() { _ws.Dispose(); _dir.Dispose(); }

    [Fact]
    [Trait("Speed", "Slow")]
    public void Two_gigabyte_capture_summary_stays_within_the_memory_ceiling()
    {
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
}
