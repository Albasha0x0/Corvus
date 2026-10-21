using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;
using static Corvus.Tests.FirmwareFilesystemTests;

namespace Corvus.Tests;

/// <summary>apk v3 (ADB) packages and indexes built here: metadata, files, links and scripts listed; binaries extracted; mutated files never throw.</summary>
public sealed class ApkV3Tests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    /// <summary>An ADB tree: blobs, integers and objects written into one block, with the adb header first.</summary>
    private sealed class Tree
    {
        private readonly MemoryStream _b = new();

        public Tree() => _b.Write(new byte[8]);

        private void Align() { while (_b.Position % 4 != 0) _b.WriteByte(0); }

        public uint Blob(byte[] value)
        {
            Align();
            uint at = (uint)_b.Position;
            var length = new byte[2];
            BinaryPrimitives.WriteUInt16LittleEndian(length, (ushort)value.Length);
            _b.Write(length);
            _b.Write(value);
            return 0x90000000 | at;
        }

        public uint Text(string value) => Blob(Encoding.UTF8.GetBytes(value));

        public static uint Int(uint value) => 0x10000000 | value;

        public uint Object(params uint[] slots) => Write(0xE0000000, slots);

        public uint Array(params uint[] items) => Write(0xD0000000, items);

        private uint Write(uint type, uint[] slots)
        {
            Align();
            uint at = (uint)_b.Position;
            var word = new byte[4];
            foreach (var v in (uint[])[(uint)slots.Length + 1, .. slots])
            {
                BinaryPrimitives.WriteUInt32LittleEndian(word, v);
                _b.Write(word);
            }
            return type | at;
        }

        public byte[] Done(uint root)
        {
            var b = _b.ToArray();
            BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4), root);
            return b;
        }
    }

    private static void Block(MemoryStream o, uint type, byte[] payload)
    {
        var head = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(head, (type << 30) | (uint)(payload.Length + 4));
        o.Write(head);
        o.Write(payload);
        while (o.Length % 8 != 0) o.WriteByte(0);
    }

    /// <summary>"ADB." + schema, the tree block and data blocks, deflate-compressed behind "ADBd".</summary>
    private static byte[] File(string schema, byte[] tree, params (uint Path, uint File, byte[] Bytes)[] data)
    {
        var o = new MemoryStream();
        o.Write("ADB."u8);
        o.Write(Encoding.ASCII.GetBytes(schema));
        Block(o, 0, tree);
        foreach (var (path, file, bytes) in data)
        {
            var payload = new byte[8 + bytes.Length];
            BinaryPrimitives.WriteUInt32LittleEndian(payload, path);
            BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(4), file);
            bytes.CopyTo(payload, 8);
            Block(o, 2, payload);
        }
        var packed = new MemoryStream();
        packed.Write("ADBd"u8);
        using (var z = new DeflateStream(packed, CompressionLevel.Fastest, leaveOpen: true)) z.Write(o.ToArray());
        return packed.ToArray();
    }

    private static uint Info(Tree t, string name, string version, uint depends) =>
        t.Object(t.Text(name), t.Text(version), 0, t.Text("test package"), t.Text("x86_64"), t.Text("MIT"), 0, 0, 0, 0, 0, Tree.Int(4096), Tree.Int(1234), 0, depends);

    private static uint Depends(Tree t) => t.Array(t.Object(t.Text("libc")), t.Object(t.Text("libfoo"), t.Text("2.0"), Tree.Int(5)));

    /// <summary>A package: bin/tool (a program), bin/sh linked to it, etc/tool.conf, and a post-install script.</summary>
    private static byte[] Package()
    {
        var t = new Tree();
        var acl = t.Object(Tree.Int(493), t.Text("root"), t.Text("root"));
        var bin = t.Object(t.Text("bin"), acl, t.Array(
            t.Object(t.Text("tool"), acl, Tree.Int((uint)Isa("mips32be.elf").Length)),
            t.Object(t.Text("sh"), acl, Tree.Int(4), 0, 0, t.Blob([0x00, 0xA0, .. "tool"u8]))));
        var etc = t.Object(t.Text("etc"), acl, t.Array(t.Object(t.Text("tool.conf"), acl, Tree.Int(6))));
        var scripts = t.Object(0, 0, t.Text("#!/bin/sh\nexit 0\n"));
        var root = t.Object(Info(t, "tool", "1.0-r1", Depends(t)), t.Array(t.Object(0, acl), bin, etc), scripts);
        return File("pckg", t.Done(root), (2, 1, Isa("mips32be.elf")), (3, 1, "a = 1\n"u8.ToArray()));
    }

    private static byte[] Index()
    {
        var t = new Tree();
        var root = t.Object(t.Text("test repository"), t.Array(Info(t, "tool", "1.0-r1", Depends(t)), Info(t, "libfoo", "2.0-r3", 0)));
        return File("indx", t.Done(root));
    }

    [Fact]
    public void Package_lists_metadata_files_and_links_and_extracts_its_program()
    {
        var c = Containers.Open(Package(), "tool.apk", AnalysisLimits.Default, default);
        Assert.Equal("apk v3 package", c.Kind);
        Assert.StartsWith("package tool 1.0-r1 (x86_64): test package; license MIT; depends libc, libfoo>=2.0; installed size 4,096 bytes; 4 files", c.Notes[0]);
        Assert.Equal(["bin/tool", "bin/sh", "etc/tool.conf", ".post-install"], c.Entries!.Select(e => e.Path));
        Assert.Equal("symbolic link to tool", c.Entries![1].Detail);
        Assert.Equal(Isa("mips32be.elf"), Assert.Single(c.Items).Bytes);
        var all = Containers.Open(Package(), "tool.apk", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(["bin/tool", "etc/tool.conf", ".post-install"], all.Items.Select(i => i.Name));
    }

    [Fact]
    public void Index_lists_its_packages_and_search_finds_them()
    {
        var c = Containers.Open(Index(), "packages.adb", AnalysisLimits.Default, default);
        Assert.Equal("apk v3 index", c.Kind);
        Assert.Empty(c.Items);
        Assert.Equal(["tool-1.0-r1.apk 1234 x86_64; depends libc, libfoo>=2.0", "libfoo-2.0-r3.apk 1234 x86_64"], c.Entries!.Select(e => $"{e.Path} {e.Size} {e.Detail}"));
        var path = _dir.File("packages.adb");
        System.IO.File.WriteAllBytes(path, Index());
        var found = new UnpackService(_workspace).Search(path, "libfoo", "file", 10, AnalysisLimits.Default, default);
        Assert.Equal("libfoo-2.0-r3.apk", Assert.Single(found.Items).Path);
    }

    [Fact]
    public void Summarize_and_unpack_read_the_package()
    {
        var path = _dir.File("tool.apk");
        System.IO.File.WriteAllBytes(path, Package());
        var summary = new InspectionService(_workspace).Summarize(null, path, default);
        Assert.Equal("apk v3 package", summary.Container);
        Assert.Contains(summary.Notes, n => n.StartsWith("package tool 1.0-r1 (x86_64)", StringComparison.Ordinal));
        var report = new UnpackService(_workspace).Unpack(path, _dir.File("out"), load: false, AnalysisLimits.Default, default);
        Assert.Equal(Isa("mips32be.elf"), System.IO.File.ReadAllBytes(report.Files.Single(f => f.Path.Replace('\\', '/').EndsWith("bin/tool", StringComparison.Ordinal)).Path));
    }

    [Fact]
    [FuzzEntry(typeof(Core.Archives.ApkV3Reader))]
    public void Fuzzed_apk_v3_files_never_throw_unexpectedly()
    {
        static byte[] Stored(byte[] packed)
        {
            using var z = new DeflateStream(new MemoryStream(packed, 4, packed.Length - 4), CompressionMode.Decompress);
            var o = new MemoryStream();
            z.CopyTo(o);
            return o.ToArray();
        }
        foreach (var (name, seed) in new[] { ("x.apk", Package()), ("x.adb", Index()), ("s.apk", Stored(Package())), ("s.adb", Stored(Index())) })
        {
            var failures = FormatFuzz.Run(seed, b => { try { Containers.Open(b, name, AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { } }, 800);
            Assert.True(failures.Count == 0, name + ": " + string.Join("\n", failures.Take(20)));
        }
    }
}
