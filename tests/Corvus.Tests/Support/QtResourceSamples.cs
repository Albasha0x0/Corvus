using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using Corvus.Core.Archives;

namespace Corvus.Tests;

/// <summary>Builds Qt resource collections as rcc lays them out, as a .rcc file or the three arrays a program holds.</summary>
internal static class QtResourceSamples
{
    /// <summary>One file: path from the root, content, storage (null, "zlib" or "zstd"), Qt locale numbers and modification time in ms.</summary>
    public sealed record File(string Path, byte[] Content, string? Compression = null, int Language = 1, int Territory = 0, long Modified = 1_760_000_000_000);

    public static readonly IReadOnlyList<File> Sample =
    [
        new("app/readme.txt", Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("hello resource\n", 200))), "zlib"),
        new("app/readme.txt", Encoding.UTF8.GetBytes("bonjour"), Language: 85, Territory: 84),
        new("app/icons/a.bin", [.. Enumerable.Range(0, 256).Select(i => (byte)i)]),
        new("app/icons/small/b.txt", Encoding.UTF8.GetBytes("small")),
        new("app/empty.txt", []),
        new("app/data/table.json", Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("{\"k\":1}", 100))), "zstd"),
    ];

    private sealed class Dir
    {
        public readonly SortedDictionary<string, Dir> Dirs = new(StringComparer.Ordinal);
        public readonly List<(string Name, File File)> Files = [];
    }

    /// <summary>The data, names and tree arrays of <paramref name="files"/>; version 1 trees have no modification times.</summary>
    public static (byte[] Data, byte[] Names, byte[] Tree, uint Flags) Arrays(IReadOnlyList<File> files, int version)
    {
        var root = new Dir();
        foreach (var f in files)
        {
            var parts = f.Path.Split('/');
            var d = root;
            foreach (var p in parts[..^1])
            {
                if (!d.Dirs.TryGetValue(p, out var next)) d.Dirs[p] = next = new Dir();
                d = next;
            }
            d.Files.Add((parts[^1], f));
        }
        var data = new MemoryStream();
        var names = new MemoryStream();
        var nameAt = new Dictionary<string, uint>(StringComparer.Ordinal);
        uint flags = 0;
        uint Name(string n)
        {
            if (nameAt.TryGetValue(n, out var at)) return at;
            nameAt[n] = at = (uint)names.Length;
            Write(names, (ushort)n.Length); Write(names, QtResources.Hash(n)); names.Write(Encoding.BigEndianUnicode.GetBytes(n));
            return at;
        }
        uint Data(File f)
        {
            var at = (uint)data.Length;
            byte[] stored = f.Content;
            if (f.Compression == "zlib")
            {
                var z = new MemoryStream();
                Write(z, (uint)f.Content.Length);
                using (var zs = new ZLibStream(z, CompressionLevel.Optimal, leaveOpen: true)) zs.Write(f.Content);
                stored = z.ToArray();
                flags |= 1;
            }
            else if (f.Compression == "zstd")
            {
                using var c = new ZstdSharp.Compressor(3);
                stored = c.Wrap(f.Content).ToArray();
                flags |= 4;
            }
            Write(data, (uint)stored.Length); data.Write(stored);
            return at;
        }
        // Breadth first: each directory's children take consecutive indexes, sorted by name hash.
        var nodes = new List<(uint Name, ushort Flags, uint A, uint B, uint C, long Modified)> { default };
        var queue = new Queue<(Dir Dir, int Index)>();
        queue.Enqueue((root, 0));
        while (queue.Count > 0)
        {
            var (dir, index) = queue.Dequeue();
            var children = dir.Dirs.Select(p => (p.Key, (object)p.Value)).Concat(dir.Files.Select(p => (p.Name, (object)p.File)))
                .OrderBy(c => QtResources.Hash(c.Item1)).ToList();
            uint first = (uint)nodes.Count;
            nodes[index] = (nodes[index].Name, 2, (uint)children.Count, first, 0, 0);
            foreach (var (name, child) in children)
            {
                if (child is Dir sub)
                {
                    nodes.Add((Name(name), 2, 0, 0, 0, 0));
                    queue.Enqueue((sub, nodes.Count - 1));
                }
                else
                {
                    var f = (File)child;
                    ushort fl = f.Compression switch { "zlib" => 1, "zstd" => 4, _ => 0 };
                    nodes.Add((Name(name), fl, (uint)f.Territory, (uint)f.Language, Data(f), f.Modified));
                }
            }
        }
        var tree = new MemoryStream();
        foreach (var n in nodes)
        {
            Write(tree, n.Name); Write(tree, n.Flags);
            if ((n.Flags & 2) != 0) { Write(tree, n.A); Write(tree, n.B); }
            else { Write(tree, (ushort)n.A); Write(tree, (ushort)n.B); Write(tree, n.C); }
            if (version >= 2) { Write(tree, (uint)(n.Modified >> 32)); Write(tree, (uint)n.Modified); }
        }
        return (data.ToArray(), names.ToArray(), tree.ToArray(), flags);
    }

    /// <summary>A binary .rcc file: the header, then data, names and tree as rcc --binary writes them.</summary>
    public static byte[] Rcc(IReadOnlyList<File> files, int version = 3)
    {
        var (data, names, tree, flags) = Arrays(files, version);
        int header = version >= 3 ? 24 : 20;
        var s = new MemoryStream();
        s.Write("qres"u8);
        Write(s, (uint)version);
        Write(s, (uint)(header + data.Length + names.Length));
        Write(s, (uint)header);
        Write(s, (uint)(header + data.Length));
        if (version >= 3) Write(s, flags);
        s.Write(data); s.Write(names); s.Write(tree);
        return s.ToArray();
    }

    /// <summary>The three arrays between other bytes, as a program image holds them: data, names, tree, each 8-aligned; with where each starts.</summary>
    public static (byte[] Bytes, List<(int Data, int Names, int Tree)> At) Embed(params (IReadOnlyList<File> Files, int Version)[] collections)
    {
        var at = new List<(int, int, int)>();
        var s = new MemoryStream();
        var filler = new Random(7);
        void Fill(int n) { var b = new byte[n]; filler.NextBytes(b); s.Write(b); }
        void Align() { while (s.Length % 8 != 0) s.WriteByte(0); }
        Fill(4096);
        foreach (var (files, version) in collections)
        {
            var (data, names, tree, _) = Arrays(files, version);
            Align(); int d = (int)s.Length; s.Write(data);
            Align(); int n = (int)s.Length; s.Write(names);
            Align(); int t = (int)s.Length; s.Write(tree);
            at.Add((d, n, t));
            Fill(1000);
        }
        return (s.ToArray(), at);
    }

    private static void Write(Stream s, ushort v) { Span<byte> b = stackalloc byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, v); s.Write(b); }
    private static void Write(Stream s, uint v) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, v); s.Write(b); }
}
