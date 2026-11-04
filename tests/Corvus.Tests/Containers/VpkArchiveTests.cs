using System.Buffers.Binary;
using System.Text;
using Corvus.Core;
using Corvus.Core.Archives;

namespace Corvus.Tests;

/// <summary>VPK packages built at test time: header, directory tree, then file data.</summary>
public sealed class VpkArchiveTests
{
    private static byte[] Build(uint version, params (string Ext, string Dir, string File, string Preload, string Data, ushort Archive)[] files)
    {
        var tree = new MemoryStream();
        var data = new MemoryStream();
        var w = new BinaryWriter(tree);
        void Z(string s) { w.Write(Encoding.UTF8.GetBytes(s)); w.Write((byte)0); }
        foreach (var ext in files.Select(f => f.Ext).Distinct())
        {
            Z(ext);
            foreach (var dir in files.Where(f => f.Ext == ext).Select(f => f.Dir).Distinct())
            {
                Z(dir);
                foreach (var f in files.Where(f => f.Ext == ext && f.Dir == dir))
                {
                    Z(f.File);
                    w.Write(0u);
                    w.Write((ushort)f.Preload.Length);
                    w.Write(f.Archive);
                    w.Write((uint)(f.Archive == 0x7FFF ? data.Length : 0));
                    w.Write((uint)f.Data.Length);
                    w.Write((ushort)0xFFFF);
                    w.Write(Encoding.ASCII.GetBytes(f.Preload));
                    if (f.Archive == 0x7FFF) data.Write(Encoding.ASCII.GetBytes(f.Data));
                }
                Z("");
            }
            Z("");
        }
        Z("");
        int header = version == 2 ? 28 : 12;
        var all = new byte[header + tree.Length + data.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(all, 0x55AA1234);
        BinaryPrimitives.WriteUInt32LittleEndian(all.AsSpan(4), version);
        BinaryPrimitives.WriteUInt32LittleEndian(all.AsSpan(8), (uint)tree.Length);
        if (version == 2) BinaryPrimitives.WriteUInt32LittleEndian(all.AsSpan(12), (uint)data.Length);
        tree.ToArray().CopyTo(all, header);
        data.ToArray().CopyTo(all, header + (int)tree.Length);
        return all;
    }

    [Fact]
    public void A_v2_archive_lists_paths_with_preload_and_data()
    {
        var data = Build(2, ("txt", "docs/en", "readme", "PRE-", "body text", 0x7FFF), ("txt", "docs/en", "notes", "", "more text", 0x7FFF));
        Assert.Equal("vpk archive", Blob.Identify(data));
        var contents = Containers.Open(data, "pak01_dir.vpk", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(VpkArchive.Kind, contents.Kind);
        Assert.Equal(["docs/en/readme.txt", "docs/en/notes.txt"], contents.Entries!.Select(e => e.Path));
        Assert.Contains("preload", contents.Entries![0].Detail);
        Assert.Equal("PRE-body text", Encoding.ASCII.GetString(contents.Items.Single(i => i.Name.EndsWith("readme.txt")).Bytes));
        Assert.Contains(contents.Notes, n => n.Contains("sizes only"));
    }

    [Fact]
    public void A_streamed_archive_lists_and_extracts_its_files()
    {
        var data = Build(2, ("txt", "docs/en", "readme", "PRE-", "body text", 0x7FFF), ("txt", "d", "a", "", "in sibling", 3));
        var contents = Containers.OpenStream(() => new MemoryStream(data, writable: false), data.AsSpan(0, 28), "pak01_dir.vpk", AnalysisLimits.Default, default);
        Assert.Equal(VpkArchive.Kind, contents!.Kind);
        Assert.Equal(["docs/en/readme.txt", "d/a.txt"], contents.Entries!.Select(e => e.Path));
        Assert.Equal("PRE-body text", Encoding.ASCII.GetString(contents.Items.Single().Bytes));
    }

    [Fact]
    public void A_directory_over_the_per_item_limit_is_read_from_its_start_and_named()
    {
        var data = Build(1, ("txt", " ", "top", "", "first file", 0x7FFF), ("txt", " ", "next", "", "second file", 0x7FFF));
        var limits = AnalysisLimits.Default with { MaxItemBytes = 24 };
        var contents = Containers.Open(data, "pak01_dir.vpk", limits, default, allFiles: true);
        Assert.Contains(contents.Notes, n => n.Contains("over the per-item limit of 24 bytes"));
    }

    [Fact]
    public void A_v1_archive_extracts_data_after_the_tree()
    {
        var data = Build(1, ("txt", " ", "top", "", "first file", 0x7FFF), ("txt", " ", "next", "", "second file", 0x7FFF));
        var contents = Containers.Open(data, "pak01_dir.vpk", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(["top.txt", "next.txt"], contents.Entries!.Select(e => e.Path));
        Assert.Equal("second file", Encoding.ASCII.GetString(contents.Items.Single(i => i.Name == "next.txt").Bytes));
    }

    [Fact]
    public void A_sibling_archive_that_is_absent_is_named_not_opened()
    {
        var data = Build(2, ("txt", "d", "a", "", "in sibling", 3), ("txt", "d", "b", "", "in file", 0x7FFF));
        var contents = Containers.Open(data, "pak01_dir.vpk", AnalysisLimits.Default, default, allFiles: true);
        Assert.Contains(contents.Notes, n => n.Contains("pak01_003.vpk") && n.Contains("not opened"));
        Assert.Contains("not opened", contents.Entries![0].Detail);
        Assert.Equal("in file", Encoding.ASCII.GetString(contents.Items.Single().Bytes));
    }

    [Fact]
    public void A_truncated_directory_is_malformed()
    {
        var data = Build(2, ("txt", "d", "a", "", "alpha", 0x7FFF), ("txt", "d", "b", "", "bravo", 0x7FFF));
        var cut = data[..(28 + 24)];
        var contents = Containers.Open(cut, "pak01_dir.vpk", AnalysisLimits.Default, default, allFiles: true);
        Assert.Contains(contents.Notes, n => n.Contains("malformed"));
    }

    [Fact]
    [FuzzEntry(typeof(VpkArchive))]
    public void Fuzzed_archives_never_throw_past_a_tool_error()
    {
        var failures = FormatFuzz.Run(Build(2, ("txt", "docs/en", "readme", "PRE-", "body text", 0x7FFF)), b => { try { VpkArchive.Open(b, "a.vpk", true, AnalysisLimits.Default, default); } catch (ToolError) { } }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }
}
