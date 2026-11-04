using System.Buffers.Binary;
using System.Text;
using Corvus.Core;
using Corvus.Core.Archives;

namespace Corvus.Tests;

/// <summary>BA2 archives built at test time: header, records, data, name table.</summary>
public sealed class BtdxArchiveTests
{
    private static byte[] Zlib(byte[] raw)
    {
        using var ms = new MemoryStream();
        using (var z = new System.IO.Compression.ZLibStream(ms, System.IO.Compression.CompressionLevel.Optimal, true)) z.Write(raw);
        return ms.ToArray();
    }

    private static byte[] Names(params string[] names)
    {
        var m = new MemoryStream();
        var w = new BinaryWriter(m);
        foreach (var n in names) { w.Write((ushort)n.Length); w.Write(Encoding.ASCII.GetBytes(n)); }
        return m.ToArray();
    }

    private static byte[] General(params (string Name, byte[] Stored, uint Packed, uint Original)[] files)
    {
        long dataAt = 24 + 36L * files.Length;
        var m = new MemoryStream();
        var w = new BinaryWriter(m);
        w.Write(Encoding.ASCII.GetBytes("BTDX")); w.Write(1u); w.Write(Encoding.ASCII.GetBytes("GNRL")); w.Write((uint)files.Length);
        w.Write((ulong)(dataAt + files.Sum(f => f.Stored.Length)));
        long at = dataAt;
        foreach (var f in files)
        {
            w.Write(0u); w.Write(Encoding.ASCII.GetBytes("bin\0")); w.Write(0u); w.Write(0x100100u);
            w.Write((ulong)at); w.Write(f.Packed); w.Write(f.Original); w.Write(0xBAADF00Du);
            at += f.Stored.Length;
        }
        foreach (var f in files) w.Write(f.Stored);
        w.Write(Names(files.Select(f => f.Name).ToArray()));
        return m.ToArray();
    }

    [Fact]
    public void A_general_archive_extracts_stored_and_packed_files()
    {
        var raw = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("MZ payload line\n", 64)));
        var packed = Zlib(raw);
        var data = General(("misc\\plain.bin", Encoding.ASCII.GetBytes("MZ stored"), 0, 9), ("misc\\zip.bin", packed, (uint)packed.Length, (uint)raw.Length));
        Assert.Equal("ba2 archive", Blob.Identify(data));
        var contents = Containers.OpenStream(() => new MemoryStream(data, writable: false), data.AsSpan(0, 40), "a.ba2", AnalysisLimits.Default, default);
        Assert.Equal(BtdxArchive.Kind, contents!.Kind);
        Assert.Equal(["misc/plain.bin", "misc/zip.bin"], contents.Entries!.Select(e => e.Path));
        Assert.Equal("MZ stored", Encoding.ASCII.GetString(contents.Items[0].Bytes));
        Assert.Equal(raw, contents.Items[1].Bytes);
    }

    [Fact]
    public void A_texture_archive_is_listed_not_extracted()
    {
        var m = new MemoryStream();
        var w = new BinaryWriter(m);
        w.Write(Encoding.ASCII.GetBytes("BTDX")); w.Write(1u); w.Write(Encoding.ASCII.GetBytes("DX10")); w.Write(1u);
        w.Write((ulong)(24 + 24 + 2 * 24 + 100));
        w.Write(0u); w.Write(Encoding.ASCII.GetBytes("dds\0")); w.Write(0u);
        w.Write((byte)0); w.Write((byte)2); w.Write((ushort)24); w.Write((ushort)16); w.Write((ushort)16); w.Write((byte)1); w.Write((byte)71); w.Write((ushort)0);
        for (int i = 0; i < 2; i++) { w.Write(0UL); w.Write(0u); w.Write(64u); w.Write((ushort)0); w.Write((ushort)0); w.Write(0xBAADF00Du); }
        w.Write(new byte[100]);
        w.Write(Names("t\\a.dds"));
        var contents = Containers.Open(m.ToArray(), "a.ba2", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("t/a.dds", contents.Entries!.Single().Path);
        Assert.Equal(128, contents.Entries!.Single().Size);
        Assert.Contains("not extracted: texture chunks", contents.Entries!.Single().Detail);
        Assert.Empty(contents.Items);
    }

    [Fact]
    public void A_name_table_past_the_file_is_malformed()
    {
        var data = General(("a.bin", Encoding.ASCII.GetBytes("MZ body"), 0, 7));
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(16), (ulong)data.Length + 100);
        var contents = Containers.Open(data, "a.ba2", AnalysisLimits.Default, default, allFiles: true);
        Assert.Contains(contents.Notes, n => n.Contains("BA2 index malformed"));
    }

    [Fact]
    [FuzzEntry(typeof(BtdxArchive))]
    public void Fuzzed_archives_never_throw_past_a_tool_error()
    {
        var failures = FormatFuzz.Run(General(("a.bin", Encoding.ASCII.GetBytes("MZ body"), 0, 7)), b => { try { BtdxArchive.Open(b, "a.ba2", true, AnalysisLimits.Default, default); } catch (ToolError) { } }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }
}
