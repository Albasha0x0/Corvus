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
}
