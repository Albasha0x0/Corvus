using System.Buffers.Binary;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>NXPK archives built at test time: header, entry data, then the index.</summary>
public sealed class NxpkArchiveTests
{
    private static readonly byte[] Zstd = [0x28, 0xB5, 0x2F, 0xFD, 1, 2, 3, 4, 5, 6];
    private static readonly byte[] Lz4 = [0x04, 0x22, 0x4D, 0x18, 1, 2, 3, 4, 5, 6];
    private static readonly byte[] Zlib = [0x78, 0x9C, 1, 2, 3, 4, 5, 6];
    private static readonly byte[] Plain = "plain bytes"u8.ToArray();

    private static byte[] Build(params (uint Sign, byte[] Bytes, uint Original)[] entries)
    {
        using var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        w.Write(new byte[20]);
        var offsets = new List<uint>();
        foreach (var e in entries) { offsets.Add((uint)ms.Length); w.Write(e.Bytes); }
        uint index = (uint)ms.Length;
        for (int i = 0; i < entries.Length; i++)
        {
            w.Write(entries[i].Sign);
            w.Write(offsets[i]);
            w.Write((uint)entries[i].Bytes.Length);
            w.Write(entries[i].Original);
            w.Write(new byte[8]);
            w.Write(new byte[4]);
        }
        var data = ms.ToArray();
        "NXPK"u8.CopyTo(data);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), (uint)entries.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(16), index);
        return data;
    }

    [Fact]
    public void An_archive_is_identified_with_its_count_index_and_compression_kinds()
    {
        var data = Build((0xA1, Zstd, 100), (0xA2, Lz4, 100), (0xA3, Zlib, 100), (0xA4, Plain, (uint)Plain.Length));
        Assert.Equal("nxpk archive", Blob.Identify(data));
        var contents = Containers.Open(data, "data.npk", AnalysisLimits.Default, default);
        Assert.Equal(NxpkArchive.Kind, contents.Kind);
        var note = contents.Notes[0];
        Assert.Contains("4 entr", note);
        Assert.Contains("index at 0x", note);
        foreach (var kind in new[] { "1 zstd", "1 lz4 frame", "1 zlib", "1 stored" }) Assert.Contains(kind, note);
        Assert.Equal(4, contents.Entries!.Count);
    }

    [Fact]
    public void A_truncated_index_is_named_and_the_present_entries_are_kept()
    {
        var data = Build((1, Zstd, 100), (2, Zstd, 100));
        var cut = data[..^20];
        var contents = Containers.Open(cut, "data.npk", AnalysisLimits.Default, default);
        Assert.Single(contents.Entries!);
        Assert.Contains(contents.Notes, n => n.Contains("index ends after 1 of 2"));
    }
    private static byte[] Payload() => System.Text.Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("MZ payload line\n", 64)));

    private static byte[] ZlibOf(byte[] raw)
    {
        using var ms = new MemoryStream();
        using (var z = new System.IO.Compression.ZLibStream(ms, System.IO.Compression.CompressionLevel.Optimal, true)) z.Write(raw);
        return ms.ToArray();
    }

    private static byte[] Lz4FrameOf(byte[] raw)
    {
        var block = new byte[K4os.Compression.LZ4.LZ4Codec.MaximumOutputSize(raw.Length)];
        int n = K4os.Compression.LZ4.LZ4Codec.Encode(raw, block);
        using var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        w.Write(new byte[] { 0x04, 0x22, 0x4D, 0x18, 0x60, 0x40, 0x82 });
        w.Write((uint)n);
        w.Write(block, 0, n);
        w.Write(0u);
        return ms.ToArray();
    }

    [Fact]
    public void Each_compression_kind_is_listed_with_its_sizes_and_extracted()
    {
        var raw = Payload();
        var zstd = new ZstdSharp.Compressor().Wrap(raw).ToArray();
        var data = Build((0xB1, zstd, (uint)raw.Length), (0xB2, Lz4FrameOf(raw), (uint)raw.Length),
                         (0xB3, ZlibOf(raw), (uint)raw.Length), (0xB4, raw, (uint)raw.Length));
        var contents = Containers.Open(data, "data.npk", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(4, contents.Items.Count);
        Assert.All(contents.Items, i => Assert.Equal(raw, i.Bytes));
        Assert.Contains(contents.Entries!, e => e.Path == "000000b2" && e.Detail!.Contains("lz4 frame, offset 0x") && e.Detail.Contains("original"));
    }

    [Fact]
    public void The_total_extraction_limit_stops_the_entries_and_is_named()
    {
        var raw = Payload();
        var data = Build((1, ZlibOf(raw), (uint)raw.Length), (2, ZlibOf(raw), (uint)raw.Length));
        var limits = AnalysisLimits.Default with { MaxTotalBytes = raw.Length + 1 };
        var contents = Containers.Open(data, "data.npk", limits, default, allFiles: true);
        Assert.Single(contents.Items);
        Assert.Equal(2, contents.Entries!.Count);
        Assert.Contains(contents.Notes, n => n.Contains("extraction limit"));
    }

    [Fact]
    public void A_corrupt_entry_is_named_and_the_next_one_is_extracted()
    {
        var raw = Payload();
        var bad = ZlibOf(raw); bad[^6] ^= 0xFF; Array.Resize(ref bad, bad.Length - 8);
        var data = Build((1, bad, (uint)raw.Length), (2, ZlibOf(raw), (uint)raw.Length));
        var contents = Containers.Open(data, "data.npk", AnalysisLimits.Default, default, allFiles: true);
        Assert.Single(contents.Items);
        Assert.Contains(contents.Notes, n => n.StartsWith("00000001: damaged"));
    }
}
