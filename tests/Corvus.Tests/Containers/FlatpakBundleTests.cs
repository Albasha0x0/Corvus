using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Corvus.Core;
using Corvus.Core.Archives;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Flatpak single-file bundles: an OSTree static delta built here, its metadata listed and its tree rebuilt.</summary>
public sealed class FlatpakBundleTests
{
    /// <summary>GVariant serialization of the few shapes a bundle needs, with framing offsets sized to each container.</summary>
    private static class Gv
    {
        public static byte[] U32(uint v) => BitConverter.GetBytes(v);
        public static byte[] U64(ulong v) => BitConverter.GetBytes(v);
        public static byte[] Str(string s) => [.. Encoding.UTF8.GetBytes(s), 0];
        public static byte[] Variant(string type, byte[] value) => [.. value, 0, .. Encoding.ASCII.GetBytes(type)];

        private static int OffsetSize(int body, int count)
        {
            foreach (int s in new[] { 1, 2, 4 })
                if (body + count * s <= (s == 1 ? 0xFF : s == 2 ? 0xFFFF : int.MaxValue)) return body + count == 0 ? 0 : s;
            throw new InvalidOperationException();
        }

        private static void Pad(MemoryStream o, int to) { while (o.Length % to != 0) o.WriteByte(0); }

        private static void Offsets(MemoryStream o, List<int> offsets)
        {
            int size = OffsetSize((int)o.Length, offsets.Count);
            foreach (var v in offsets) o.Write(BitConverter.GetBytes(v), 0, size);
        }

        public static byte[] Tuple(string type, params byte[][] values)
        {
            var members = GVariant.Members(type);
            var o = new MemoryStream();
            var framing = new List<int>();
            for (int i = 0; i < members.Count; i++)
            {
                Pad(o, GVariant.Alignment(members[i]));
                o.Write(values[i]);
                if (GVariant.FixedSize(members[i]) == null && i < members.Count - 1) framing.Add((int)o.Length);
            }
            if (GVariant.FixedSize(type) is { } fixedSize) { Pad(o, GVariant.Alignment(type)); return o.ToArray()[..fixedSize]; }
            framing.Reverse();
            Offsets(o, framing);
            return o.ToArray();
        }

        public static byte[] Array(string element, IEnumerable<byte[]> items)
        {
            var o = new MemoryStream();
            var ends = new List<int>();
            foreach (var item in items)
            {
                Pad(o, GVariant.Alignment(element));
                o.Write(item);
                ends.Add((int)o.Length);
            }
            if (GVariant.FixedSize(element) == null) Offsets(o, ends);
            return o.ToArray();
        }

        public static byte[] Dict(params (string Key, string Type, byte[] Value)[] entries) =>
            Array("{sv}", entries.Select(e => Tuple("{sv}", Str(e.Key), Variant(e.Type, e.Value))));
    }

    private static readonly byte[] App = Encoding.ASCII.GetBytes(new string('a', 3000));
    private const string Keyfile = "[Application]\nname=org.example.Viewer\nruntime=org.example.Platform/x86_64/1\ncommand=viewer\n\n[Context]\nshared=ipc;\n";

    /// <summary>A bundle of one inline, uncompressed part: metadata, files/bin/viewer (written in two pieces) and a link to it.</summary>
    internal static byte[] Bundle()
    {
        var objects = new List<(byte Type, byte[] Id, byte[] Data, int Mode)>();
        byte[] Meta(byte type, byte[] data)
        {
            var id = SHA256.HashData(data);
            objects.Add((type, id, data, -1));
            return id;
        }
        byte[] File(byte[] content, int mode, bool link)
        {
            var stat = new byte[12];
            BinaryPrimitives.WriteUInt32BigEndian(stat.AsSpan(8), (uint)(link ? 0xA1FF : 0x81ED));
            var header = Gv.Tuple("(uuuusa(ayay))", stat[..4], stat[4..8], stat[8..], Gv.U32(0), Gv.Str(link ? Encoding.UTF8.GetString(content) : ""), []);
            var prefix = new byte[8];
            BinaryPrimitives.WriteUInt32BigEndian(prefix, (uint)header.Length);
            var id = SHA256.HashData([.. prefix, .. header, .. link ? [] : content]);
            objects.Add((1, id, content, mode));
            return id;
        }
        var keyfile = File(Encoding.ASCII.GetBytes(Keyfile), 0, link: false);
        var viewer = File(App, 0, link: false);
        var link = File("viewer"u8.ToArray(), 1, link: true);
        var dirMeta = Meta(3, Gv.Tuple("(uuua(ayay))", Gv.U32(0), Gv.U32(0), Gv.U32(0x41ED), []));
        byte[] Tree((string, byte[])[] files, (string, byte[])[] dirs) => Gv.Tuple("(a(say)a(sayay))",
            Gv.Array("(say)", files.Select(f => Gv.Tuple("(say)", Gv.Str(f.Item1), f.Item2))),
            Gv.Array("(sayay)", dirs.Select(d => Gv.Tuple("(sayay)", Gv.Str(d.Item1), d.Item2, dirMeta))));
        var bin = Meta(2, Tree([("link", link), ("viewer", viewer)], []));
        var files = Meta(2, Tree([], [("bin", bin)]));
        var root = Meta(2, Tree([("metadata", keyfile)], [("files", files)]));
        var timestamp = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(timestamp, 1_700_000_000);
        var commitBody = Gv.Tuple("(a{sv}aya(say)sstayay)", [], [], [], Gv.Str("test build"), Gv.Str(""), timestamp, root, dirMeta);
        var commit = Meta(4, commitBody);

        // The part: modes, one empty xattr set, the raw data and the operations.
        var raw = new MemoryStream();
        var ops = new MemoryStream();
        void Var(long v) { do { byte b = (byte)(v & 0x7F); v >>= 7; ops.WriteByte((byte)(b | (v > 0 ? 0x80 : 0))); } while (v > 0); }
        long Put(byte[] data) { long at = raw.Length; raw.Write(data); return at; }
        foreach (var (type, id, data, mode) in objects)
        {
            if (type != 1) { ops.WriteByte((byte)'S'); Var(data.Length); Var(Put(data)); }
            else if (ReferenceEquals(data, App))
            {
                // An object opened, written in two pieces and closed.
                ops.WriteByte((byte)'o'); Var(mode); Var(0); Var(data.Length);
                ops.WriteByte((byte)'w'); Var(1000); Var(Put(data[..1000]));
                ops.WriteByte((byte)'w'); Var(data.Length - 1000); Var(Put(data[1000..]));
                ops.WriteByte((byte)'c');
            }
            else { ops.WriteByte((byte)'S'); Var(mode); Var(0); Var(data.Length); Var(Put(data)); }
        }
        var modes = new[] { 0x81ED, 0xA1FF }.Select(m => { var b = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, (uint)m); return Gv.Tuple("(uuu)", Gv.U32(0), Gv.U32(0), b); });
        var payload = Gv.Tuple("(a(uuu)aa(ayay)ayay)", Gv.Array("(uuu)", modes), Gv.Array("a(ayay)", [[]]), raw.ToArray(), ops.ToArray());
        var list = objects.SelectMany(o => (byte[])[o.Type, .. o.Id]).ToArray();
        var header = Gv.Tuple("(uayttay)", Gv.U32(0), new byte[32], Gv.U64((ulong)payload.Length), Gv.U64((ulong)payload.Length), list);
        var metadata = Gv.Dict(("flatpak", "u", Gv.U32(0xE5890001)), ("ref", "s", Gv.Str("app/org.example.Viewer/x86_64/stable")), ("metadata", "s", Gv.Str(Keyfile)),
            ("deltas/ab/cd/0", "(yay)", Gv.Tuple("(yay)", [0], payload)));
        return Gv.Tuple("(a{sv}tayay(a{sv}aya(say)sstayay)aya(uayttay)a(yaytt))", metadata, timestamp, [], commit, commitBody, [],
            Gv.Array("(uayttay)", [header]), []);
    }

    [Fact]
    public void Bundle_lists_its_ref_and_metadata_and_rebuilds_the_tree()
    {
        var c = Containers.Open(Bundle(), "viewer.flatpak", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("flatpak bundle", c.Kind);
        Assert.StartsWith("flatpak bundle app/org.example.Viewer/x86_64/stable: commit ", c.Notes[0]);
        Assert.Contains("('test build')", c.Notes[0]);
        Assert.Contains("metadata: [Application] name=org.example.Viewer, runtime=org.example.Platform/x86_64/1, command=viewer; [Context] shared=ipc;", c.Notes);
        Assert.Contains("8 objects, each matching its SHA-256 checksum", c.Notes);
        Assert.Equal(["files/bin/link", "files/bin/viewer", "metadata"], c.Entries!.Select(e => e.Path).Order(StringComparer.Ordinal));
        Assert.Equal("symbolic link to viewer", c.Entries!.Single(e => e.Path == "files/bin/link").Detail);
        Assert.Equal(App, c.Items.Single(i => i.Name == "files/bin/viewer").Bytes);
        // Read from a stream, the same listing.
        var streamed = new FlatpakBundleReader().Open(new MemoryStream(Bundle()), "viewer.flatpak", true, AnalysisLimits.Default, default)!;
        Assert.Equal(c.Entries!.Select(e => e.Path), streamed.Entries!.Select(e => e.Path));
    }

    [Fact]
    public void Unpack_and_search_reach_the_bundle_files()
    {
        using var dir = new TempDir();
        using var workspace = new AssemblyWorkspace(new ServerOptions());
        var path = dir.File("viewer.flatpak");
        File.WriteAllBytes(path, Bundle());
        var report = new UnpackService(workspace).Unpack(path, dir.File("out"), load: false, AnalysisLimits.Default, default);
        Assert.Equal("flatpak bundle", report.Container);
        Assert.Equal(App, File.ReadAllBytes(report.Files.Single(f => f.Path.Replace('\\', '/').EndsWith("files/bin/viewer", StringComparison.Ordinal)).Path));
        var found = new UnpackService(workspace).Search(path, "viewer", "file", 10, AnalysisLimits.Default, default);
        Assert.Contains(found.Items, m => m.Path == "files/bin/viewer");
        var summary = new InspectionService(workspace).Summarize(null, path, default);
        Assert.Equal("flatpak bundle", summary.Container);
        Assert.Contains(summary.Notes, n => n.StartsWith("flatpak bundle app/org.example.Viewer/x86_64/stable", StringComparison.Ordinal));
    }

    [Fact]
    [FuzzEntry(typeof(FlatpakBundleReader), typeof(GVariant))]
    public void Fuzzed_bundles_never_throw_unexpectedly()
    {
        var failures = FormatFuzz.Run(Bundle(), b => { try { Containers.Open(b, "x.flatpak", AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { } }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
