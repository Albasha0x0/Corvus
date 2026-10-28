using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>The per-call output count: the expansion limit against containers whose entries share one stored copy.</summary>
public sealed class ExpansionLimitTests
{
    private const int Entry = 64 * 1024;
    private const int Copies = 400;

    // A low floor and ratio, so a fixture of a few hundred KB reaches the limit.
    private static IDisposable Call() => Spent.Enter(new Spent(ratio: 10, floor: 1 << 20));

    private static void AssertNamesTheLimit(Func<ContainerContents> open)
    {
        using var call = Call();
        var error = Assert.Throws<ToolError>(() => open());
        Assert.Equal(ErrorCode.LimitExceeded, error.Code);
        Assert.Contains("expansion limit", error.Message);
        Assert.Contains(Spent.ExpansionVariable, error.Remediation);
    }

    [Fact]
    public void Output_under_the_floor_is_not_refused()
    {
        var spent = new Spent(ratio: 10, floor: 1 << 20);
        spent.Input(10);
        spent.Produced(1 << 20, "a");
        Assert.Equal(1 << 20, spent.Bytes);
    }

    [Fact]
    public void Output_past_the_floor_and_the_ratio_is_refused()
    {
        var spent = new Spent(ratio: 10, floor: 1 << 20);
        spent.Input(1000);
        spent.Produced(1 << 20, "a");
        var error = Assert.Throws<ToolError>(() => spent.Produced(1, "b"));
        Assert.StartsWith("b lifts the output", error.Message);
    }

    [Fact]
    public void Output_within_the_ratio_is_not_refused_past_the_floor()
    {
        var spent = new Spent(ratio: 10, floor: 1 << 20);
        spent.Input(1 << 20);
        for (int i = 0; i < 10; i++) spent.Produced(1 << 20, "a");
        Assert.Equal(10, spent.Items);
    }

    [Fact]
    public void A_ratio_of_zero_turns_the_limit_off()
    {
        var spent = new Spent(ratio: 0, floor: 0);
        spent.Input(1);
        spent.Produced(1 << 30, "a");
        Assert.Equal(0, Spent.RatioSetting("0"));
        Assert.Equal(Spent.DefaultRatio, Spent.RatioSetting(null));
        Assert.Equal(Spent.DefaultRatio, Spent.RatioSetting("many"));
    }

    [Fact]
    public void Copies_of_the_limits_share_the_call_counter()
    {
        using var call = Call();
        var copy = AnalysisLimits.Default with { MaxDepth = 2 };
        Assert.NotNull(copy.Spent);
        Assert.Same(AnalysisLimits.Default.Spent, copy.Spent);
    }

    [Fact]
    public void A_cancelled_call_stops_at_its_next_count()
    {
        using var cts = new CancellationTokenSource();
        var spent = new Spent(cts.Token);
        cts.Cancel();
        Assert.Throws<OperationCanceledException>(() => spent.Produced(1, "a"));
    }

    [Fact]
    public void A_gzip_of_zeros_past_the_floor_unpacks_at_the_default_ratio()
    {
        var gzip = new MemoryStream();
        using (var z = new GZipStream(gzip, CompressionLevel.Optimal, leaveOpen: true))
        using (var tar = new System.Formats.Tar.TarWriter(z))
            tar.WriteEntry(new System.Formats.Tar.UstarTarEntry(System.Formats.Tar.TarEntryType.RegularFile, "zeros.img")
                { DataStream = new MemoryStream(new byte[4 << 20]) });
        // The default ratio with a 1 MiB floor: deflate expands zeros about
        // 1,030 times.
        using var call = Spent.Enter(new Spent(ratio: Spent.DefaultRatio, floor: 1 << 20));
        var contents = Containers.Open(gzip.ToArray(), "zeros.tar.gz", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(4 << 20, Assert.Single(contents.Items).Bytes.Length);
        Assert.True(Spent.Current!.Bytes > 1 << 20);
    }

    [Fact]
    public void A_zip_whose_entries_share_one_local_header_is_stopped()
    {
        var zip = SharedZip();
        AssertNamesTheLimit(() => Containers.Open(zip, "shared.zip", AnalysisLimits.Default, default, allFiles: true));
    }

    [Fact]
    public void An_asar_whose_entries_share_one_offset_is_stopped()
    {
        var (asar, _) = AsarWriter.Build([new AsarWriter.File("e0.bin", new byte[Entry], Integrity: false)], editHeader: json =>
        {
            var root = JsonNode.Parse(json)!;
            var files = root["files"]!.AsObject();
            for (int i = 1; i < Copies; i++) files[$"e{i}.bin"] = files["e0.bin"]!.DeepClone();
            return root.ToJsonString();
        });
        AssertNamesTheLimit(() => Containers.Open(asar, "shared.asar", AnalysisLimits.Default, default, allFiles: true));
    }

    [Fact]
    public void A_xar_whose_files_share_one_heap_range_is_stopped()
    {
        var xar = SharedXar();
        AssertNamesTheLimit(() => Containers.Open(xar, "shared.pkg", AnalysisLimits.Default, default, allFiles: true));
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_one_gib_tar_of_zero_filled_files_unpacks_past_the_floor()
    {
        using var dir = new TempDir();
        var tar = dir.File("zeros.tar");
        const long size = 256L << 20;
        WriteZeroTar(tar, 4, size);
        using var workspace = new AssemblyWorkspace(new ServerOptions());
        using var call = Spent.Enter(new Spent());
        var extraction = new UnpackService(workspace).Extract(tar, dir.File("out"), AnalysisLimits.Default, default);
        Assert.Equal(4, extraction.Files.Count);
        Assert.All(extraction.Files, f => Assert.Equal(size, f.Size));
        Assert.True(Spent.Current!.Bytes > Spent.Floor);
    }

    /// <summary>A ustar archive of <paramref name="count"/> zero-filled files, written in 1 MiB pieces.</summary>
    private static void WriteZeroTar(string path, int count, long size)
    {
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 20);
        var zeros = new byte[1 << 20];
        for (int i = 0; i < count; i++)
        {
            var header = new byte[512];
            Encoding.ASCII.GetBytes($"zero{i}.img").CopyTo(header, 0);
            Encoding.ASCII.GetBytes("0000644\0").CopyTo(header, 100);
            Encoding.ASCII.GetBytes(Convert.ToString(size, 8).PadLeft(11, '0') + "\0").CopyTo(header, 124);
            Encoding.ASCII.GetBytes("00000000000\0").CopyTo(header, 136);
            header[156] = (byte)'0';
            Encoding.ASCII.GetBytes("ustar\000").CopyTo(header, 257);
            "        "u8.CopyTo(header.AsSpan(148));
            int sum = 0;
            foreach (var b in header) sum += b;
            Encoding.ASCII.GetBytes(Convert.ToString(sum, 8).PadLeft(6, '0') + "\0 ").CopyTo(header, 148);
            file.Write(header);
            for (long left = size; left > 0; left -= zeros.Length) file.Write(zeros, 0, (int)Math.Min(left, zeros.Length));
        }
        file.Write(new byte[1024]);
    }

    /// <summary>One deflated entry and <see cref="Copies"/> central directory records that all point at it.</summary>
    private static byte[] SharedZip()
    {
        var one = new MemoryStream();
        using (var archive = new ZipArchive(one, ZipArchiveMode.Create, leaveOpen: true))
        using (var s = archive.CreateEntry("e0000.bin", CompressionLevel.Optimal).Open())
            s.Write(new byte[Entry]);
        var bytes = one.ToArray();
        var end = bytes.AsSpan(bytes.Length - 22);
        int size = (int)BinaryPrimitives.ReadUInt32LittleEndian(end[12..]), at = (int)BinaryPrimitives.ReadUInt32LittleEndian(end[16..]);
        var record = bytes.AsSpan(at, size).ToArray();
        var output = new MemoryStream();
        output.Write(bytes, 0, at);
        for (int i = 0; i < Copies; i++)
        {
            Encoding.ASCII.GetBytes($"e{i:0000}.bin").CopyTo(record, 46);
            output.Write(record);
        }
        var tail = end.ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(tail.AsSpan(8), Copies);
        BinaryPrimitives.WriteUInt16LittleEndian(tail.AsSpan(10), Copies);
        BinaryPrimitives.WriteUInt32LittleEndian(tail.AsSpan(12), (uint)(size * Copies));
        output.Write(tail);
        return output.ToArray();
    }

    /// <summary>A xar whose table of contents names <see cref="Copies"/> stored files at heap offset 0.</summary>
    private static byte[] SharedXar()
    {
        var toc = new StringBuilder("<?xml version=\"1.0\"?><xar><toc>");
        for (int i = 0; i < Copies; i++)
            toc.Append($"<file id=\"{i + 1}\"><name>e{i}.bin</name><type>file</type><data><offset>0</offset><length>{Entry}</length>")
               .Append($"<size>{Entry}</size><encoding style=\"application/octet-stream\"/></data></file>");
        var text = Encoding.UTF8.GetBytes(toc.Append("</toc></xar>").ToString());
        var compressed = new MemoryStream();
        using (var z = new ZLibStream(compressed, CompressionLevel.Optimal, leaveOpen: true)) z.Write(text);
        var header = new byte[28];
        "xar!"u8.CopyTo(header);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), 28);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6), 1);
        BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(8), (ulong)compressed.Length);
        BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(16), (ulong)text.Length);
        return [.. header, .. compressed.ToArray(), .. new byte[Entry]];
    }
}
