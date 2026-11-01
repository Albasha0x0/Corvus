using System.IO.Compression;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

public sealed class NativeEmbeddedContentTests
{
    [Fact]
    public void The_overview_of_a_native_image_names_its_script_container_and_gzip_stream()
    {
        var script = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Containers", "AutoItFixtures", "ledger-3.3.18.0.a3x"));
        var gzip = new MemoryStream();
        using (var z = new GZipStream(gzip, CompressionLevel.Optimal, leaveOpen: true)) z.Write(new byte[2000]);
        var data = new byte[0x1000 + script.Length + 0x100 + gzip.Length];
        script.CopyTo(data, 0x1000);
        gzip.ToArray().CopyTo(data, 0x1000 + script.Length + 0x100);
        var pe = new PeBuilder();
        pe.Add(".rdata", data);
        using var dir = new TempDir();
        var path = dir.File("host.exe");
        File.WriteAllBytes(path, pe.Build());

        using var workspace = new AssemblyWorkspace(new ServerOptions());
        var summary = new InspectionService(workspace).Summarize(null, path, default);

        Assert.Contains(summary.Highlights, h => h.StartsWith("Script container: AutoIt compiled script at 0x", StringComparison.Ordinal));
        Assert.Contains(summary.Highlights, h => h.StartsWith("Compression stream: 1 gzip stream(s) at 0x", StringComparison.Ordinal) && h.Contains("(2,000 bytes expanded)", StringComparison.Ordinal));
    }

    private static byte[] Gzip(int size)
    {
        var gzip = new MemoryStream();
        using (var z = new GZipStream(gzip, CompressionLevel.Optimal, leaveOpen: true)) z.Write(new byte[size]);
        return gzip.ToArray();
    }

    private static string Summarize(byte[] data, CancellationToken ct = default)
    {
        var pe = new PeBuilder();
        pe.Add(".rdata", data);
        using var dir = new TempDir();
        var path = dir.File("host.exe");
        File.WriteAllBytes(path, pe.Build());
        using var workspace = new AssemblyWorkspace(new ServerOptions());
        return string.Join(" ", new InspectionService(workspace).Summarize(null, path, ct).Highlights);
    }

    // Regression: macOS CI missed every stream; zlib there writes OS byte 19.
    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(19)]
    [InlineData(255)]
    public void A_gzip_stream_is_named_whichever_operating_system_wrote_it(byte os)
    {
        var data = new byte[0x200 + 0x100];
        var gzip = Gzip(500);
        gzip[9] = os;
        gzip.CopyTo(data, 0x100);
        Assert.Contains("Compression stream: 1 gzip stream(s) at 0x", Summarize(data), StringComparison.Ordinal);
    }

    [Fact]
    public void The_gzip_stream_line_names_the_call_that_extracts_it()
    {
        // The stream sits at 0x100 in a section of a host with a spaced path.
        var data = new byte[0x200 + 0x100];
        Gzip(500).CopyTo(data, 0x100);
        var pe = new PeBuilder();
        pe.Add(".rdata", data);
        using var dir = new TempDir();
        var path = Path.Combine(dir.File("host dir"), "host.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, pe.Build());
        using var workspace = new AssemblyWorkspace(new ServerOptions());
        var line = Assert.Single(new InspectionService(workspace).Summarize(null, path, default).Highlights, h => h.StartsWith("Compression stream", StringComparison.Ordinal));
        Assert.EndsWith($"unpack_container path=\"{path}\" extracts them.", line, StringComparison.Ordinal);
    }

    [Fact]
    public void A_gzip_stream_alone_is_named_in_the_overview()
    {
        var data = new byte[0x200 + 0x100];
        Gzip(500).CopyTo(data, 0x100);
        Assert.Contains("Compression stream: 1 gzip stream(s) at 0x", Summarize(data), StringComparison.Ordinal);
    }

    [Fact]
    public void Images_without_a_script_or_gzip_stream_get_no_embedded_content_line()
    {
        var text = Summarize(new byte[0x400]);
        Assert.DoesNotContain("Compression stream", text, StringComparison.Ordinal);
        Assert.DoesNotContain("Script container", text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_gzip_magic_with_a_truncated_body_is_not_listed()
    {
        var stream = Gzip(2000);
        var data = new byte[0x400];
        Array.Copy(stream, 0, data, 0x100, 14);
        Assert.DoesNotContain("1 gzip", Summarize(data), StringComparison.Ordinal);
    }

    [Fact]
    public void More_than_three_streams_end_with_an_ellipsis()
    {
        var stream = Gzip(300);
        var data = new byte[0x100 + 5 * (stream.Length + 0x20)];
        for (int i = 0; i < 5; i++) stream.CopyTo(data, 0x100 + i * (stream.Length + 0x20));
        var text = Summarize(data);
        Assert.Contains("5 gzip stream(s)", text, StringComparison.Ordinal);
        Assert.Contains("expanded), ....", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Magic_hits_past_the_candidate_limit_are_reported_as_unread()
    {
        var data = new byte[0x100 + 5000 * 16];
        for (int i = 0; i < 5000; i++) { int o = 0x100 + i * 16; data[o] = 0x1F; data[o + 1] = 0x8B; data[o + 2] = 0x08; data[o + 9] = 3; }
        var text = Summarize(data);
        Assert.Contains("some candidates not read", text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_cancelled_token_stops_the_scan()
    {
        var data = new byte[0x300];
        Gzip(100).CopyTo(data, 0x100);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => Summarize(data, cts.Token));
    }
}
