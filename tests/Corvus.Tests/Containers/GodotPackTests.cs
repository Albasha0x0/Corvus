using System.Security.Cryptography;
using System.Text;
using Corvus.Core;
using Corvus.Native.Providers;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Godot resource packs of each directory layout built at test time, standalone and after an executable.</summary>
public sealed class GodotPackTests(ITestOutputHelper output)
{
    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Containers", "GodotFixtures", name);

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
            // File base relative to the pack.
            w.Write(2u);
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
            // Earlier formats keep the directory after the header, so the data follows it.
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
            // The data moved past the directory: point the file base (format 2) or each offset (format 1) there.
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
    public void Lists_every_file_with_its_role(uint format, string engine)
    {
        var contents = Containers.Open(Build(format, Sample()), "app.pck", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(GodotPack.Kind, contents.Kind);
        Assert.Equal([".godot/exported/main.scn: compressed resource", "icon.ctex: texture", "player.gd: GDScript", "../evil.txt: text, unsafe name"],
            contents.Entries!.Select(e => $"{e.Path}: {e.Detail}"));
        Assert.StartsWith($"Godot pack format {format}, {engine}: 4 file(s)", contents.Notes[0]);
        Assert.Equal("extends Node\n", Encoding.UTF8.GetString(contents.Items.Single(i => i.Name == "player.gd").Bytes));
        Assert.DoesNotContain(contents.Items, i => i.Name.Contains(".."));
    }

    [Fact]
    public void A_pack_embedded_in_an_executable_is_found()
    {
        var pe = new PeBuilder();
        pe.Add(".text", [0xC3], 0x60000020);
        var exe = pe.Build();
        var pack = Build(4, Sample());
        var bytes = exe.Concat(pack).Concat(BitConverter.GetBytes((ulong)pack.Length)).Concat("GDPC"u8.ToArray()).ToArray();
        var contents = Containers.Open(bytes, "app.exe", AnalysisLimits.Default, default, allFiles: true);
        Assert.True(contents.Kind == GodotPack.Kind, $"{Blob.Identify(bytes)}: {string.Join("; ", contents.Notes)}");
        Assert.Contains($"embedded at 0x{exe.Length:X}", contents.Notes[0]);
        Assert.Equal("GST2rest", Encoding.ASCII.GetString(contents.Items.Single(i => i.Name == "icon.ctex").Bytes));
    }

    [Fact]
    public void Encrypted_and_removed_entries_are_noted()
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
                try { GodotPack.Open(b, 0, "app.pck", allFiles: true, AnalysisLimits.Default, default); }
                catch (ToolError) { }
            }, 500));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }

    // The engine's PCKPacker wrote these (build.ps1): two text files under config/.
    [Theory]
    [InlineData("format-1.pck", 1, "Godot 3.6.3")]
    [InlineData("format-2.pck", 2, "Godot 4.3.0")]
    [InlineData("format-3.pck", 3, "Godot 4.5.1")]
    [InlineData("format-4.pck", 4, "Godot 4.7.2")]
    public void Packs_PCKPacker_wrote_in_each_format_list_and_extract_their_files(string fixture, int format, string engine)
    {
        var contents = Containers.Open(File.ReadAllBytes(Fixture(fixture)), fixture, AnalysisLimits.Default, default, allFiles: true);
        Assert.StartsWith($"Godot pack format {format}, {engine}: 2 file(s)", contents.Notes[0]);
        Assert.Equal(string.Concat(Enumerable.Repeat("[section]\nname=Ledger\ncount=3\n", 40)),
            Encoding.UTF8.GetString(contents.Items.Single(i => i.Name == "config/settings.ini").Bytes));
        Assert.Equal("nested entry\n", Encoding.UTF8.GetString(contents.Items.Single(i => i.Name == "config/nested/notes.txt").Bytes));
    }

    // A Godot 3 export embeds the pack with file offsets, not pack offsets; adding the pack start put every file past the end.
    [Fact]
    public void A_format_1_pack_embedded_after_an_executable_reads_its_files_at_file_offsets()
    {
        var pe = new PeBuilder();
        pe.Add(".text", [0xC3], 0x60000020);
        var exe = pe.Build();
        var pack = File.ReadAllBytes(Fixture("format-1.pck"));
        // Shift each directory entry's offset (after its path) by the executable's length, as the exporter does.
        int at = 20 + 64, count = BitConverter.ToInt32(pack, at);
        for (at += 4; count-- > 0; at += 32)
        {
            at += 4 + BitConverter.ToInt32(pack, at);
            BitConverter.GetBytes(BitConverter.ToInt64(pack, at) + exe.Length).CopyTo(pack, at);
        }
        var bytes = exe.Concat(pack).Concat(BitConverter.GetBytes((ulong)pack.Length)).Concat("GDPC"u8.ToArray()).ToArray();
        var contents = Containers.Open(bytes, "app.exe", AnalysisLimits.Default, default, allFiles: true);
        Assert.Contains($"embedded at 0x{exe.Length:X}: 2 file(s)", contents.Notes[0]);
        Assert.Equal("nested entry\n", Encoding.UTF8.GetString(contents.Items.Single(i => i.Name == "config/nested/notes.txt").Bytes));
    }

    [Fact]
    public void A_PCKPacker_pack_with_an_encrypted_directory_lists_nothing_and_says_so()
    {
        var contents = Containers.Open(File.ReadAllBytes(Fixture("format-4-encrypted.pck")), "format-4-encrypted.pck", AnalysisLimits.Default, default);
        Assert.Equal("Godot pack format 4, Godot 4.7.2: the directory is encrypted (the export's encryption key opens it); no files listed.", contents.Notes[0]);
        Assert.Empty(contents.Entries!);
    }

    // The fixtures and each pack or executable under CORVUS_GODOT_PACKS are mounted by the engine (the newest 3.x release
    // for format 1, the newest 4.x for later formats) and walked from res://; the paths and each file's MD5 are compared.
    // The engine refuses an encrypted pack without the key compiled into it; Corvus must then name the encryption.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_GODOT_RELEASES")]
    public void Paths_and_contents_equal_what_the_runtime_mounts()
    {
        var releases = Directory.GetDirectories(RealData.Path("CORVUS_GODOT_RELEASES"), "godot-*")
            .Select(d => (Version: Version.Parse(Path.GetFileName(d)[6..]), Exe: Engine(d))).Where(r => r.Exe != null).ToList();
        string Newest(int major) => releases.Where(r => r.Version.Major == major).MaxBy(r => r.Version).Exe!;
        var files = new[] { "format-1.pck", "format-2.pck", "format-3.pck", "format-4.pck", "format-4-encrypted.pck" }.Select(Fixture).ToList();
        if (Environment.GetEnvironmentVariable("CORVUS_GODOT_PACKS") is { Length: > 0 } dir)
            files.AddRange(Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal));
        var problems = new List<string>();
        int packs = 0, compared = 0, refused = 0;
        using var project = new TempDir();
        File.WriteAllBytes(Path.Combine(project.Path, "project.godot"), []);
        foreach (var file in files)
        {
            var data = File.ReadAllBytes(file);
            long? start = GodotPack.Looks(data) ? 0 : GodotPack.Embedded(data);
            if (start == null) continue;
            packs++;
            string name = Path.GetFileName(file);
            var c = GodotPack.Open(data, start.Value, name, allFiles: true, AnalysisLimits.Default, default);
            int format = BitConverter.ToInt32(data, (int)start.Value + 4);
            string[] args = format == 1
                ? ["--no-window", "--path", project.Path, "--script", Fixture("list3.gd"), file]
                : ["--headless", "--path", project.Path, "--script", Fixture("list4.gd"), "--", file];
            var run = ExternalTools.Run(Newest(format == 1 ? 3 : 4), args, TimeSpan.FromMinutes(3), 1 << 26, default);
            var lines = run.Text.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
            if (lines.Contains("REFUSED"))
            {
                refused++;
                if (!c.Notes[0].Contains("encrypted", StringComparison.Ordinal)) problems.Add($"{name}: the engine refuses it; Corvus reads it: {c.Notes[0]}");
                continue;
            }
            var theirs = lines.Where(l => l.StartsWith("FILE\t", StringComparison.Ordinal)).Select(l => l.Split('\t')).ToDictionary(p => p[1], p => p[2]);
            var ours = c.Items.ToDictionary(i => i.Name, i => Convert.ToHexStringLower(MD5.HashData(i.Bytes)));
            // The host project's own empty project.godot is not in the pack.
            if (!ours.ContainsKey("project.godot") && theirs.GetValueOrDefault("project.godot") == "d41d8cd98f00b204e9800998ecf8427e") theirs.Remove("project.godot");
            var missing = theirs.Keys.Except(ours.Keys).Order(StringComparer.Ordinal).ToList();
            var extra = ours.Keys.Except(theirs.Keys).Order(StringComparer.Ordinal).ToList();
            var differ = theirs.Keys.Intersect(ours.Keys).Where(k => theirs[k] != ours[k]).Order(StringComparer.Ordinal).ToList();
            if (missing.Count + extra.Count + differ.Count > 0)
                problems.Add($"{name}: {missing.Count} only the engine lists ({string.Join(", ", missing.Take(3))}), {extra.Count} only Corvus ({string.Join(", ", extra.Take(3))}), {differ.Count} differ ({string.Join(", ", differ.Take(3))})");
            else compared += theirs.Count;
        }
        output.WriteLine($"{packs} packs: {compared} files equal by path and MD5 to the engine's, {refused} refused by the engine");
        foreach (var p in problems.Take(40)) output.WriteLine(p);
        Assert.Empty(problems);
        Assert.True(compared > 0);
    }

    // The console build where a release ships one (it writes to the console), else the editor executable.
    private static string? Engine(string folder) =>
        Directory.GetFiles(folder, "Godot_v*").Where(f => Path.GetExtension(f) is ".exe" or ".x86_64")
            .OrderBy(f => !f.Contains("_console", StringComparison.Ordinal)).FirstOrDefault();
}
