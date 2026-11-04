using System.Buffers.Binary;
using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>NXPK archives with an "NXFN" name table appended after the index.</summary>
public sealed class NxpkNameTableTests
{
    private static readonly byte[] Plain = "plain bytes"u8.ToArray();

    private static byte[] Build(string[] names, int declaredExtra = 0, int cut = 0, int entries = -1)
    {
        int n = entries < 0 ? names.Length : entries;
        using var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        w.Write(new byte[24]);
        uint dataAt = (uint)ms.Length;
        for (int i = 0; i < n; i++) w.Write(Plain);
        uint index = (uint)ms.Length;
        for (int i = 0; i < n; i++)
        {
            w.Write((uint)(0xA0 + i));
            w.Write((uint)(dataAt + i * Plain.Length));
            w.Write((uint)Plain.Length);
            w.Write((uint)Plain.Length);
            w.Write(new byte[12]);
        }
        var paths = Encoding.UTF8.GetBytes(string.Concat(names.Select(x => x + "\0")));
        w.Write("NXFN"u8.ToArray());
        w.Write(0u);
        w.Write((uint)(paths.Length + declaredExtra));
        w.Write((uint)(paths.Length + declaredExtra));
        w.Write(paths);
        var data = ms.ToArray();
        "NXPK"u8.CopyTo(data);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), (uint)n);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20), index);
        return cut > 0 ? data[..^cut] : data;
    }

    [Fact]
    public void Names_from_the_table_are_listed_and_extracted()
    {
        var data = Build(["lib/a.bin", "b.bin"]);
        var contents = Containers.Open(data, "data.npk", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(["lib/a.bin", "b.bin"], contents.Entries!.Select(e => e.Path));
        Assert.Equal(["lib" + Path.DirectorySeparatorChar + "a.bin", "b.bin"], contents.Items.Select(i => i.Name));
        Assert.DoesNotContain(contents.Notes, n => n.Contains("stores no file names"));
    }

    [Fact]
    public void An_archive_without_the_marker_keeps_signature_names_and_the_note()
    {
        var data = Build(["x"]);
        var at = data.AsSpan().IndexOf("NXFN"u8);
        data[at] = (byte)'Z';
        var contents = Containers.Open(data, "data.npk", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("000000a0", contents.Entries![0].Path);
        Assert.Contains(contents.Notes, n => n.Contains("stores no file names"));
    }

    [Fact]
    public void Search_by_file_finds_a_named_entry()
    {
        var data = Build(["scripts/main.lua", "other.txt"]);
        using var dir = new TempDir();
        using var workspace = new AssemblyWorkspace(new ServerOptions());
        var path = dir.File("data.npk");
        System.IO.File.WriteAllBytes(path, data);
        var found = new UnpackService(workspace).Search(path, "main.lua", "file", 10, AnalysisLimits.Default, default);
        Assert.Contains(found.Items, m => m.Path == "scripts/main.lua");
    }

    [Fact]
    public void A_parent_segment_name_is_refused_and_the_entry_keeps_its_signature()
    {
        var data = Build(["../escape.bin", "ok.bin"]);
        var contents = Containers.Open(data, "data.npk", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("000000a0.bin", contents.Items[0].Name);
        Assert.Equal("ok.bin", contents.Items[1].Name);
        Assert.Contains(contents.Notes, n => n.StartsWith("000000a0: name '../escape.bin' refused"));
        Assert.Contains(contents.Names!, i => i.Name == "../escape.bin");
    }

    [Fact]
    public void A_rooted_and_a_drive_name_are_refused()
    {
        var data = Build(["/etc/x", "C:/x"]);
        var contents = Containers.Open(data, "data.npk", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(["000000a0.bin", "000000a1.bin"], contents.Items.Select(i => i.Name));
        Assert.Equal(2, contents.Names!.Count);
    }

    [Fact]
    public void A_truncated_table_keeps_the_names_read_and_is_partial()
    {
        var data = Build(["one.bin", "two.bin", "three.bin"], cut: 6);
        var contents = Containers.Open(data, "data.npk", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("one.bin", contents.Entries![0].Path);
        Assert.Equal("two.bin", contents.Entries[1].Path);
        Assert.Equal("000000a2", contents.Entries[2].Path);
        Assert.Contains(contents.Notes, n => n.Contains("partial"));
    }

    [Fact]
    public void A_table_with_fewer_names_than_entries_is_partial()
    {
        var data = Build(["only.bin"], entries: 2);
        var contents = Containers.Open(data, "data.npk", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(["only.bin", "000000a1"], contents.Entries!.Select(e => e.Path));
        Assert.Contains(contents.Notes, n => n.Contains("1 of 2 names"));
    }
}
