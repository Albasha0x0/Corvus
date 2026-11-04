using System.Buffers.Binary;
using System.Text;
using Corvus.Core;
using Corvus.Core.Archives;

namespace Corvus.Tests;

/// <summary>BSA archives built at test time: header, folder records, file records, name block, data.</summary>
public sealed class BsaArchiveTests
{
    private static byte[] Zlib(byte[] raw)
    {
        using var ms = new MemoryStream();
        using (var z = new System.IO.Compression.ZLibStream(ms, System.IO.Compression.CompressionLevel.Optimal, true)) z.Write(raw);
        return ms.ToArray();
    }

    private static byte[] Lz4Frame(byte[] raw)
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

    private static byte[] Payload() => Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("MZ payload line\n", 64)));

    // One folder; each file is its name and the bytes stored after the optional embedded name and size prefix.
    private static byte[] Build(uint version, uint flags, string folder, params (string Name, byte[] Stored, uint Original)[] files)
    {
        bool embed = (flags & 0x100) != 0, packed = (flags & 4) != 0;
        int record = version == 105 ? 24 : 16;
        string names = string.Concat(files.Select(f => f.Name + "\0"));
        int folderBlock = 1 + folder.Length + 1 + 16 * files.Length;
        long dataStart = 36 + record + folderBlock + names.Length;
        var bodies = files.Select(f =>
        {
            var m = new MemoryStream();
            if (embed) { m.WriteByte((byte)(folder.Length + 1 + f.Name.Length)); m.Write(Encoding.ASCII.GetBytes(folder + "\\" + f.Name)); }
            if (packed) m.Write(BitConverter.GetBytes(f.Original));
            m.Write(f.Stored);
            return m.ToArray();
        }).ToArray();
        var all = new MemoryStream();
        var w = new BinaryWriter(all);
        w.Write(Encoding.ASCII.GetBytes("BSA\0")); w.Write(version); w.Write(36u); w.Write(flags | 3);
        w.Write(1u); w.Write((uint)files.Length); w.Write((uint)(folder.Length + 1)); w.Write((uint)names.Length); w.Write(0u);
        w.Write(0UL); w.Write((uint)files.Length);
        long folderAt = 36 + record + names.Length;
        if (version == 105) { w.Write(0u); w.Write((ulong)folderAt); } else w.Write((uint)folderAt);
        w.Write((byte)(folder.Length + 1)); w.Write(Encoding.ASCII.GetBytes(folder)); w.Write((byte)0);
        long at = dataStart;
        foreach (var b in bodies) { w.Write(0UL); w.Write((uint)b.Length); w.Write((uint)at); at += b.Length; }
        w.Write(Encoding.ASCII.GetBytes(names));
        foreach (var b in bodies) w.Write(b);
        return all.ToArray();
    }

    [Fact]
    public void A_v104_archive_lists_folders_and_extracts_a_zlib_file()
    {
        var raw = Payload();
        var data = Build(104, 4, "scripts", ("run.bin", Zlib(raw), (uint)raw.Length));
        Assert.Equal("bsa archive", Blob.Identify(data));
        var contents = Containers.Open(data, "a.bsa", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(BsaArchive.Kind, contents.Kind);
        Assert.Equal("scripts/run.bin", contents.Entries!.Single().Path);
        Assert.Equal(raw.Length, contents.Entries!.Single().Size);
        Assert.Equal(raw, contents.Items.Single().Bytes);
    }

    [Fact]
    public void An_archive_with_embedded_names_strips_the_prefix()
    {
        var data = Build(104, 0x100, "docs", ("a.txt", Encoding.ASCII.GetBytes("plain body"), 0));
        var contents = Containers.Open(data, "a.bsa", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("plain body", Encoding.ASCII.GetString(contents.Items.Single().Bytes));
    }

    [Fact]
    public void A_v105_archive_extracts_an_lz4_file()
    {
        var raw = Payload();
        var data = Build(105, 4, "bin", ("x.bin", Lz4Frame(raw), (uint)raw.Length));
        var contents = Containers.OpenStream(() => new MemoryStream(data, writable: false), data.AsSpan(0, 40), "a.bsa", AnalysisLimits.Default, default);
        Assert.Equal(BsaArchive.Kind, contents!.Kind);
        Assert.Equal("bin/x.bin", contents.Entries!.Single().Path);
        Assert.Equal(raw, contents.Items.Single().Bytes);
    }

    [Fact]
    public void A_file_count_past_the_file_is_malformed()
    {
        var data = Build(104, 0, "d", ("a.txt", Encoding.ASCII.GetBytes("MZ body"), 0));
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20), 0x7FFFFFFF);
        var contents = Containers.Open(data, "a.bsa", AnalysisLimits.Default, default, allFiles: true);
        Assert.Empty(contents.Entries!);
        Assert.Contains(contents.Notes, n => n.Contains("BSA index malformed"));
    }
}
