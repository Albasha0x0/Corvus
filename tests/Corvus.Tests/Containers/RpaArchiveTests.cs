using System.Text;
using Corvus.Core;
using Corvus.Core.Archives;

namespace Corvus.Tests;

/// <summary>RPA archives built at test time: header line, file data, then a zlib pickle index.</summary>
public sealed class RpaArchiveTests
{
    private static byte[] Zlib(byte[] raw)
    {
        using var ms = new MemoryStream();
        using (var z = new System.IO.Compression.ZLibStream(ms, System.IO.Compression.CompressionLevel.Optimal, true)) z.Write(raw);
        return ms.ToArray();
    }

    private static void Str(List<byte> p, string s)
    {
        p.Add((byte)'U');
        p.Add((byte)s.Length);
        p.AddRange(Encoding.Latin1.GetBytes(s));
    }

    private static void Int(List<byte> p, long v)
    {
        p.Add((byte)'J');
        p.AddRange(BitConverter.GetBytes((int)v));
    }

    // Version 3 keys offsets and lengths with key; version 2 stores them plain.
    private static byte[] Build(int version, uint key, byte[] extraOp, params (string Name, string Data, string Prefix)[] files)
    {
        var body = new List<byte>();
        var pickle = new List<byte> { 0x80, 2, (byte)'}', (byte)'(' };
        pickle.AddRange(extraOp);
        var header = version == 3 ? $"RPA-3.0 {{0:x16}} {key:x8}\n" : "RPA-2.0 {0:x16}\n";
        int headerLength = string.Format(header, 0L).Length;
        uint mask = version == 3 ? key : 0;
        foreach (var f in files)
        {
            var bytes = Encoding.ASCII.GetBytes(f.Data);
            long at = headerLength + body.Count;
            body.AddRange(bytes);
            Str(pickle, f.Name);
            pickle.Add((byte)']');
            pickle.Add((byte)'(');
            Int(pickle, at ^ mask);
            Int(pickle, bytes.Length ^ mask);
            Str(pickle, f.Prefix);
            pickle.Add((byte)'t');
            pickle.Add((byte)'a');
        }
        pickle.Add((byte)'u');
        pickle.Add((byte)'.');
        long indexAt = headerLength + body.Count;
        var all = new List<byte>(Encoding.ASCII.GetBytes(string.Format(header, indexAt)));
        all.AddRange(body);
        all.AddRange(Zlib([.. pickle]));
        return [.. all];
    }

    [Fact]
    public void A_v3_archive_lists_names_with_keyed_offsets()
    {
        var data = Build(3, 0x5A5A5A5A, [], ("scripts/a.txt", "alpha text", ""), ("images/b.txt", "bravo text", ""));
        Assert.Equal("rpa archive", Blob.Identify(data));
        var contents = Containers.Open(data, "a.rpa", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(RpaArchive.Kind, contents.Kind);
        Assert.Equal(["scripts/a.txt", "images/b.txt"], contents.Entries!.Select(e => e.Path));
        Assert.Contains("key 0x5A5A5A5A", contents.Notes[0]);
        Assert.Equal("bravo text", Encoding.ASCII.GetString(contents.Items.Single(i => i.Name.EndsWith("b.txt")).Bytes));
    }

    [Fact]
    public void A_v2_archive_without_a_key_extracts_its_files()
    {
        var data = Build(2, 0, [], ("a.txt", "alpha text", ""));
        var contents = Containers.Open(data, "a.rpa", AnalysisLimits.Default, default, allFiles: true);
        Assert.Contains("RPA archive 2.0", contents.Notes[0]);
        Assert.Equal("alpha text", Encoding.ASCII.GetString(contents.Items.Single().Bytes));
    }

    [Fact]
    public void A_streamed_archive_lists_and_extracts_its_files()
    {
        var data = Build(3, 0x5A5A5A5A, [], ("scripts/a.txt", "alpha text", ""), ("b.txt", "tail", "head-"));
        var contents = Containers.OpenStream(() => new MemoryStream(data, writable: false), data.AsSpan(0, 16), "a.rpa", AnalysisLimits.Default, default);
        Assert.Equal(RpaArchive.Kind, contents!.Kind);
        Assert.Equal(["scripts/a.txt", "b.txt"], contents.Entries!.Select(e => e.Path));
        Assert.Equal("head-tail", Encoding.ASCII.GetString(contents.Items.Single(i => i.Name == "b.txt").Bytes));
    }

    [Fact]
    public void A_prefix_is_joined_to_the_data()
    {
        var data = Build(3, 0x1234, [], ("a.txt", "tail", "head-"));
        var contents = Containers.Open(data, "a.rpa", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("head-tail", Encoding.ASCII.GetString(contents.Items.Single().Bytes));
        Assert.Equal(9, contents.Entries!.Single().Size);
    }

    [Fact]
    public void An_index_with_an_unexpected_pickle_opcode_is_refused()
    {
        // A GLOBAL opcode names a callable; the reader refuses it and runs nothing.
        var data = Build(3, 1, "cos\nsystem\n"u8.ToArray(), ("a.txt", "alpha text", ""));
        var contents = Containers.Open(data, "a.rpa", AnalysisLimits.Default, default, allFiles: true);
        Assert.Empty(contents.Items);
        Assert.Empty(contents.Entries!);
        Assert.Contains(contents.Notes, n => n.Contains("malformed") && n.Contains("opcode 0x63"));
    }

    [Fact]
    [FuzzEntry(typeof(RpaArchive))]
    public void Fuzzed_archives_never_throw_past_a_tool_error()
    {
        var failures = FormatFuzz.Run(Build(3, 0x5A5A5A5A, [], ("a.txt", "alpha text", ""), ("b.txt", "tail", "head-")), b => { try { RpaArchive.Open(b, "a.rpa", true, AnalysisLimits.Default, default); } catch (ToolError) { } }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }
}
