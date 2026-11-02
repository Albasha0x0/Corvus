using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>NXPK archives built at test time: header, entry data, then the index.</summary>
public sealed class NxpkArchiveTests
{
    private static readonly byte[] Zstd = [0x28, 0xB5, 0x2F, 0xFD, 1, 2, 3, 4, 5, 6];
    private static readonly byte[] Lz4 = [0x04, 0x22, 0x4D, 0x18, 1, 2, 3, 4, 5, 6];
    private static readonly byte[] Zlib = ZlibOf(Payload());
    private static readonly byte[] Plain = "plain bytes"u8.ToArray();

    private static byte[] Build(params (uint Sign, byte[] Bytes, uint Original)[] entries)
    {
        using var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        w.Write(new byte[24]);
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
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20), index);
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

    [Fact]
    public void A_streamed_archive_extracts_its_identified_entries()
    {
        var raw = Payload();
        var data = Build((1, ZlibOf(raw), (uint)raw.Length), (2, ZlibOf([1, 2, 0, 255, 3, 0]), 6));
        var contents = Containers.OpenStream(() => new MemoryStream(data, writable: false), data.AsSpan(0, 24), "data.npk", AnalysisLimits.Default, default);
        Assert.NotNull(contents);
        Assert.Equal(NxpkArchive.Kind, contents!.Kind);
        Assert.Equal(2, contents.Entries!.Count);
        Assert.Equal(raw, Assert.Single(contents.Items).Bytes);
    }

    [Fact]
    public void A_dictionary_compressed_zstd_entry_is_counted_and_not_called_damaged()
    {
        var raw = Payload();
        var withDictionary = new ZstdSharp.Compressor().Wrap(raw).ToArray();
        // Single-segment frame with a 1-byte dictionary id of 7.
        withDictionary[4] = (byte)((withDictionary[4] & ~3) | 1);
        var framed = withDictionary[..5].Concat(new byte[] { 7 }).Concat(withDictionary[5..]).ToArray();
        var data = Build((1, framed, (uint)raw.Length));
        var contents = Containers.Open(data, "data.npk", AnalysisLimits.Default, default, allFiles: true);
        Assert.Empty(contents.Items);
        Assert.Contains(contents.Notes, n => n.Contains("need a trained dictionary") && n.Contains("7 x1"));
        Assert.DoesNotContain(contents.Notes, n => n.Contains("damaged"));
    }

    [Fact]
    public void A_stream_shorter_than_the_header_gives_a_partial_result_with_a_note()
    {
        var contents = NxpkArchive.Open(new MemoryStream("NXPK"u8.ToArray()), "data.npk", true, AnalysisLimits.Default, default);
        Assert.Empty(contents.Items);
        Assert.Empty(contents.Entries!);
        Assert.Contains(contents.Notes, n => n.Contains("cut short"));
    }

    [Fact]
    public void An_unknown_compression_is_listed_and_counted_not_extracted()
    {
        var data = Build((1, [1, 2, 3, 4, 5], 99));
        var contents = Containers.Open(data, "data.npk", AnalysisLimits.Default, default, allFiles: true);
        Assert.Empty(contents.Items);
        Assert.Contains("unknown compression", contents.Entries!.Single().Detail);
        Assert.Contains(contents.Notes, n => n.Contains("1 entr(ies) use an unknown compression"));
    }

    [Fact]
    public void An_entry_outside_the_file_is_listed_and_named()
    {
        var data = Build((1, Plain, (uint)Plain.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(data.Length - 28 + 8), 0x7FFFFFFF);
        var contents = Containers.Open(data, "data.npk", AnalysisLimits.Default, default, allFiles: true);
        Assert.Empty(contents.Items);
        Assert.Contains("outside the file", contents.Entries!.Single().Detail);
        Assert.Contains(contents.Notes, n => n.Contains("1 entr(ies) lie outside the file"));
    }

    [Fact]
    public void An_entry_over_the_per_item_limit_by_stored_or_original_size_is_skipped_and_named()
    {
        var raw = Payload();
        var data = Build((1, raw, (uint)raw.Length), (2, ZlibOf(raw), 10));
        var limits = AnalysisLimits.Default with { MaxItemBytes = 10 };
        var contents = Containers.Open(data, "data.npk", limits, default, allFiles: true);
        Assert.Empty(contents.Items);
        Assert.Equal(2, contents.Entries!.Count);
        Assert.Contains(contents.Notes, n => n.Contains("2 entr(ies) are over the per-item limit"));
    }

    [Fact]
    public void The_item_count_limit_stops_the_entries_and_is_named()
    {
        var data = Build((1, Plain, (uint)Plain.Length), (2, Plain, (uint)Plain.Length));
        var contents = Containers.Open(data, "data.npk", AnalysisLimits.Default with { MaxItems = 1 }, default, allFiles: true);
        Assert.Single(contents.Items);
        Assert.Equal(2, contents.Entries!.Count);
        Assert.Contains(contents.Notes, n => n.Contains("extraction limit"));
    }

    [Fact]
    public void Unpack_and_search_read_the_archive_entries()
    {
        var raw = Payload();
        var data = Build((0xC1, ZlibOf(raw), (uint)raw.Length), (0xC2, Lz4FrameOf(raw), (uint)raw.Length));
        using var dir = new TempDir();
        using var workspace = new AssemblyWorkspace(new ServerOptions());
        var path = dir.File("data.npk");
        System.IO.File.WriteAllBytes(path, data);
        var service = new UnpackService(workspace);
        var report = service.Unpack(path, dir.File("out"), load: false, AnalysisLimits.Default, default);
        Assert.Equal(NxpkArchive.Kind, report.Container);
        Assert.Equal(2, report.Files.Count);
        Assert.All(report.Files, f => Assert.Equal(raw, System.IO.File.ReadAllBytes(f.Path)));
        var found = service.Search(path, "000000c2", "file", 10, AnalysisLimits.Default, default);
        Assert.Contains(found.Items, m => m.Path == "000000c2" && m.Detail!.Contains("lz4 frame"));
        Assert.Contains(found.Items, m => m.Path == "000000c2.bin");
    }

    [Fact]
    [FuzzEntry(typeof(NxpkArchive))]
    public void Fuzzed_archives_never_throw_past_a_tool_error()
    {
        var seed = Build((0xC1, Zstd, 100), (0xC2, Lz4, 100), (0xC3, Plain, (uint)Plain.Length));
        var failures = FormatFuzz.Run(seed, b => { try { NxpkArchive.Open(b, "data.npk", true, AnalysisLimits.Default, default); } catch (ToolError) { } }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }
}
