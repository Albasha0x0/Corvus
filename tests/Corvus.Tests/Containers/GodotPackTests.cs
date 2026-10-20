using System.Text;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>Godot resource packs of each directory layout built at test time, standalone and after an executable.</summary>
public sealed class GodotPackTests
{
    /// <summary>A pack: header, file data, then the directory (format 3+ at its offset, earlier formats after the header).</summary>
    public static byte[] Build(uint format, params (string Path, byte[] Bytes, uint Flags)[] files)
    {
        int header = format >= 3 ? 40 + 64 : format == 2 ? 32 + 64 : 20 + 64;
        using var data = new MemoryStream();
        var offsets = new List<long>();
        foreach (var f in files)
        {
            offsets.Add(data.Length);
            data.Write(f.Bytes);
        }
        using var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        w.Write("GDPC"u8);
        w.Write(format);
        w.Write(format == 1 ? 3u : 4u);
        w.Write(format switch { 1 => 5u, 2 => 2u, _ => 7u });
        w.Write(1u);
        long dirAt = header + data.Length;
        if (format >= 2)
        {
            w.Write(2u); // file base relative to the pack
            w.Write((ulong)header);
            if (format >= 3) w.Write((ulong)dirAt);
        }
        w.Write(new byte[64]);
        void Directory()
        {
            w.Write((uint)files.Length);
            for (int i = 0; i < files.Length; i++)
            {
                var path = Encoding.UTF8.GetBytes(format == 1 ? "res://" + files[i].Path : files[i].Path);
                int padded = (path.Length + 3) & ~3;
                w.Write((uint)padded);
                w.Write(path);
                w.Write(new byte[padded - path.Length]);
                w.Write((ulong)(format == 1 ? header + offsets[i] : offsets[i]));
                w.Write((ulong)files[i].Bytes.Length);
                w.Write(new byte[16]);
                if (format >= 2) w.Write(files[i].Flags);
            }
        }
        if (format < 3)
        {
            // earlier formats keep the directory after the header, so the data follows it
            var head = ms.ToArray();
            using var dir = new MemoryStream();
            w = new BinaryWriter(dir);
            Directory();
            int shift = (int)dir.Length;
            using var all = new MemoryStream();
            all.Write(head);
            all.Write(dir.ToArray());
            all.Write(data.ToArray());
            var bytes = all.ToArray();
            // the data moved past the directory: point the file base (format 2) or each offset (format 1) there
            if (format == 2) BitConverter.GetBytes((ulong)(header + shift)).CopyTo(bytes, 24);
            else
            {
                int at = header + 4;
                foreach (var (i, path) in files.Select((f, i) => (i, f.Path)))
                {
                    int padded = (Encoding.UTF8.GetByteCount("res://" + path) + 3) & ~3;
                    at += 4 + padded;
                    BitConverter.GetBytes((ulong)(header + shift + offsets[i])).CopyTo(bytes, at);
                    at += 32;
                }
            }
            return bytes;
        }
        w.Write(data.ToArray());
        Directory();
        return ms.ToArray();
    }

    private static (string, byte[], uint)[] Sample() =>
    [
        (".godot/exported/main.scn", "RSCC\0\0\0\0"u8.ToArray(), 0),
        ("icon.ctex", "GST2rest"u8.ToArray(), 0),
        ("player.gd", "extends Node\n"u8.ToArray(), 0),
        ("../evil.txt", "x"u8.ToArray(), 0),
    ];

    [Theory]
    [InlineData(1u, "Godot 3.5.1")]
    [InlineData(2u, "Godot 4.2.1")]
    [InlineData(3u, "Godot 4.7.1")]
    [InlineData(4u, "Godot 4.7.1")]
    public void ListsEveryFileWithItsRole(uint format, string engine)
    {
        var contents = Containers.Open(Build(format, Sample()), "game.pck", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(GodotPack.Kind, contents.Kind);
        Assert.Equal([".godot/exported/main.scn: compressed resource", "icon.ctex: texture", "player.gd: GDScript", "../evil.txt: text, unsafe name"],
            contents.Entries!.Select(e => $"{e.Path}: {e.Detail}"));
        Assert.StartsWith($"Godot pack format {format}, {engine}: 4 file(s)", contents.Notes[0]);
        Assert.Equal("extends Node\n", Encoding.UTF8.GetString(contents.Items.Single(i => i.Name == "player.gd").Bytes));
        Assert.DoesNotContain(contents.Items, i => i.Name.Contains(".."));
    }

    [Fact]
    public void APackEmbeddedInAnExecutableIsFound()
    {
        var pe = new PeBuilder();
        pe.Add(".text", [0xC3], 0x60000020);
        var exe = pe.Build();
        var pack = Build(4, Sample());
        var bytes = exe.Concat(pack).Concat(BitConverter.GetBytes((ulong)pack.Length)).Concat("GDPC"u8.ToArray()).ToArray();
        var contents = Containers.Open(bytes, "game.exe", AnalysisLimits.Default, default, allFiles: true);
        Assert.True(contents.Kind == GodotPack.Kind, $"{Blob.Identify(bytes)}: {string.Join("; ", contents.Notes)}");
        Assert.Contains($"embedded at 0x{exe.Length:X}", contents.Notes[0]);
        Assert.Equal("GST2rest", Encoding.ASCII.GetString(contents.Items.Single(i => i.Name == "icon.ctex").Bytes));
    }

    [Fact]
    public void EncryptedAndRemovedEntriesAreNoted()
    {
        var contents = Containers.Open(Build(4, ("a.scn", "RSRC"u8.ToArray(), 1), ("b.scn", [], 2)), "patch.pck", AnalysisLimits.Default, default);
        Assert.Equal(["a.scn: encrypted", "b.scn: removal (a patch pack deletes it)"], contents.Entries!.Select(e => $"{e.Path}: {e.Detail}"));
        Assert.Contains(contents.Notes, n => n.StartsWith("1 file(s) are encrypted", StringComparison.Ordinal));
    }

    [Fact]
    [FuzzEntry(typeof(GodotPack))]
    public void Fuzzed_packs_never_throw_past_a_tool_error()
    {
        var failures = new List<string>();
        foreach (var format in new uint[] { 1, 2, 4 })
            failures.AddRange(FormatFuzz.Run(Build(format, Sample()), b =>
            {
                try { GodotPack.Open(b, 0, "game.pck", allFiles: true, AnalysisLimits.Default, default); }
                catch (ToolError) { }
            }, 500));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }
}
