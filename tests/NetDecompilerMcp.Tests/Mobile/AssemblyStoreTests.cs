using System.Buffers.Binary;
using System.IO.Hashing;
using System.Text;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Core.Mobile;
using NetDecompilerMcp.Services.Analysis;
using NetDecompilerMcp.Tests.NativeFormats;

namespace NetDecompilerMcp.Tests;

/// <summary>Writes .NET for Android assembly stores in the layouts of xamarin-app.hh (v1, v2, v3) and their ELF wrappers.</summary>
internal static class AssemblyStoreWriter
{
    public sealed record Item(string Name, byte[] Data, byte[]? Debug = null, byte[]? Config = null, bool Ignore = false);

    /// <summary>"XAZS": the XALZ header with a Zstandard frame.</summary>
    public static byte[] Xazs(byte[] data, uint index = 0)
    {
        using var zstd = new ZstdSharp.Compressor(3);
        var frame = zstd.Wrap(data).ToArray();
        var result = new byte[12 + frame.Length];
        "XAZS"u8.CopyTo(result);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4), index);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(8), (uint)data.Length);
        frame.CopyTo(result.AsSpan(12));
        return result;
    }

    /// <summary>Version 2 or 3: header, index (hash, descriptor, [ignore]), 28-byte descriptors, names, data.</summary>
    public static byte[] V2(IReadOnlyList<Item> items, uint version = 3, uint abi = 0x00010000, bool is64 = true, bool ignoreByte = true)
    {
        int hashSize = is64 ? 8 : 4, stride = hashSize + 4 + (ignoreByte ? 1 : 0);
        var names = items.Select(i => Encoding.UTF8.GetBytes(i.Name)).ToList();
        int indexCount = items.Count * 2;
        int headerAndIndex = 20 + indexCount * stride;
        int namesAt = headerAndIndex + items.Count * 28;
        int dataAt = namesAt + names.Sum(n => 4 + n.Length);
        var blobs = new List<byte[]>();
        var descriptors = new List<uint[]>();
        int at = dataAt;
        uint Place(byte[]? b) { if (b == null) return 0; blobs.Add(b); var o = (uint)at; at += b.Length; return o; }
        foreach (var i in items)
            descriptors.Add([0, Place(i.Data), (uint)i.Data.Length, Place(i.Debug), (uint)(i.Debug?.Length ?? 0), Place(i.Config), (uint)(i.Config?.Length ?? 0)]);
        var w = new MemoryStream();
        void U32(uint v) => w.Write(BitConverter.GetBytes(v));
        U32(AssemblyStore.Magic); U32(version | abi | (is64 ? 0x80000000 : 0)); U32((uint)items.Count); U32((uint)indexCount); U32((uint)(indexCount * stride));
        var index = items.SelectMany((item, d) => new[] { item.Name, Path.GetFileNameWithoutExtension(item.Name) }.Select(n => (Hash: (ulong)Crc32.HashToUInt32(Encoding.UTF8.GetBytes(n)), D: d)))
            .OrderBy(e => e.Hash);
        foreach (var (hash, d) in index)
        {
            if (is64) w.Write(BitConverter.GetBytes(hash)); else U32((uint)hash);
            U32((uint)d);
            if (ignoreByte) w.WriteByte(items[d].Ignore ? (byte)1 : (byte)0);
        }
        foreach (var d in descriptors) foreach (var v in d) U32(v);
        foreach (var n in names) { U32((uint)n.Length); w.Write(n); }
        foreach (var b in blobs) w.Write(b);
        return w.ToArray();
    }

    /// <summary>Version 1: header (local count, global count, store id), 24-byte descriptors, and in store 0 two global hash tables.</summary>
    public static byte[] V1(IReadOnlyList<byte[]> images, uint storeId, int globalCount = 0)
    {
        int tables = storeId == 0 ? globalCount * 20 * 2 : 0;
        int at = 20 + images.Count * 24 + tables;
        var w = new MemoryStream();
        void U32(uint v) => w.Write(BitConverter.GetBytes(v));
        U32(AssemblyStore.Magic); U32(1); U32((uint)images.Count); U32((uint)globalCount); U32(storeId);
        foreach (var image in images) { U32((uint)at); U32((uint)image.Length); U32(0); U32(0); U32(0); U32(0); at += image.Length; }
        w.Write(new byte[tables]);
        foreach (var image in images) w.Write(image);
        return w.ToArray();
    }

    /// <summary>A shared library holding <paramref name="store"/>: at the "_assembly_store" symbol (libassembly-store.so) or as the "payload" section.</summary>
    public static byte[] Elf(byte[] store, bool symbol, bool is64 = true)
    {
        var elf = new ElfWriter { Is64 = is64, Machine = is64 ? ElfWriter.EmAarch64 : ElfWriter.EmArm, Data = store };
        if (symbol) elf.Symbols.Add(new ElfWriter.Symbol("_assembly_store", ElfWriter.DataRva, (uint)store.Length, Type: 1));
        else elf.DataSectionName = "payload";
        return elf.Build();
    }
}

public class AssemblyStoreTests
{
    private static readonly byte[] Fixture = File.ReadAllBytes(Env.FixturePath);
    private static readonly byte[] Consumer = File.ReadAllBytes(Env.ConsumerPath);

    [Fact]
    public void V3_InTheStoreLibrary_NamesEntries_DecompressesZstdAndLz4_KeepsDebugAndConfig()
    {
        var store = AssemblyStoreWriter.V2([
            new("TestFixture.dll", AssemblyStoreWriter.Xazs(Fixture), Debug: [1, 2, 3], Config: "<configuration/>\0"u8.ToArray()),
            new("TestFixture.Consumer", ContainerFixtures.Xalz(Consumer, 1)),
            new("fr/TestFixture.resources.dll", ContainerFixtures.Module("Satellite"), Ignore: true)]);
        var s = AssemblyStore.TryRead(AssemblyStoreWriter.Elf(store, symbol: true), "lib/arm64-v8a/libassembly-store.so", AnalysisLimits.Default)!;
        Assert.Empty(s.Issues);
        Assert.Equal((3, "arm64-v8a", true, "_assembly_store symbol"), (s.Version, s.Abi, s.Is64Bit, s.Location));
        Assert.Equal(["TestFixture.dll", "TestFixture.Consumer.dll", "fr/TestFixture.resources.dll"], s.Entries.Select(e => e.Name));
        Assert.Equal(Fixture, s.Entries[0].Image);
        Assert.Equal("zstd", s.Entries[0].Compression);
        Assert.Equal([1, 2, 3], s.Entries[0].Debug);
        Assert.StartsWith("<configuration/>", Encoding.UTF8.GetString(s.Entries[0].Config!));
        Assert.Equal(Consumer, s.Entries[1].Image);
        Assert.Equal("lz4", s.Entries[1].Compression);
        Assert.Equal([false, false, true], s.Entries.Select(e => e.Ignored));
    }

    [Fact]
    public void V2_InThePayloadSection_32Bit_WithoutIgnoreFlags()
    {
        var store = AssemblyStoreWriter.V2([new("TestFixture.dll", Fixture)], version: 2, abi: 0x00040000, is64: false, ignoreByte: false);
        var s = AssemblyStore.TryRead(AssemblyStoreWriter.Elf(store, symbol: false, is64: false), "lib/x86/libassemblies.x86.blob.so", AnalysisLimits.Default)!;
        Assert.Empty(s.Issues);
        Assert.Equal((2, "x86", false, "payload section"), (s.Version, s.Abi, s.Is64Bit, s.Location));
        Assert.Equal(("TestFixture.dll", "none"), (s.Entries.Single().Name, s.Entries.Single().Compression));
        Assert.Null(AssemblyStore.TryRead(AssemblyStoreWriter.Elf([1, 2, 3], symbol: false), "lib/x86/libfoo.so", AnalysisLimits.Default));
    }

    [Fact]
    public void V1_NamesComeFromTheManifest_OrFromTheMetadata()
    {
        var shared = AssemblyStoreWriter.V1([ContainerFixtures.Xalz(Fixture)], storeId: 0, globalCount: 2);
        var arch = AssemblyStoreWriter.V1([Consumer], storeId: 1);
        var manifest = AssemblyStore.ReadV1Manifest("Hash 32     Hash 64             Blob ID  Blob idx  Name\n" +
                                                    "0xa2e0939b  0x4288cfb749e4c631  000      0000      TestFixture\n" +
                                                    "0x1d2b8f1a  0x91aa1b2c3d4e5f60  001      0000      Renamed.Consumer\n");
        var s0 = AssemblyStore.TryRead(shared, "assemblies/assemblies.blob", AnalysisLimits.Default, manifest)!;
        Assert.Equal((1, null, "TestFixture.dll", "lz4"), (s0.Version, s0.Abi, s0.Entries.Single().Name, s0.Entries.Single().Compression));
        var s1 = AssemblyStore.TryRead(arch, "assemblies/assemblies.arm64_v8a.blob", AnalysisLimits.Default, manifest)!;
        Assert.Equal(("arm64-v8a", 1u, "Renamed.Consumer.dll"), (s1.Abi, s1.StoreId, s1.Entries.Single().Name));
        Assert.Equal("TestFixture.Consumer.dll", AssemblyStore.TryRead(arch, "assemblies/assemblies.arm64_v8a.blob", AnalysisLimits.Default)!.Entries.Single().Name);
    }

    [Fact]
    public void DamagedStores_ReportIssues_AndKeepWhatReads()
    {
        var store = AssemblyStoreWriter.V2([new("A.dll", Fixture), new("B.dll", Consumer)]);
        var cut = store[..^(Consumer.Length / 2)]; // B's data runs past the end
        var s = AssemblyStore.TryRead(cut, "x", AnalysisLimits.Default)!;
        Assert.Equal("A.dll", s.Entries.Single().Name);
        Assert.Contains(s.Issues, i => i.Message.Contains("B.dll", StringComparison.Ordinal));

        var huge = (byte[])store.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(huge.AsSpan(8), 0x7FFFFFFF);
        Assert.Empty(AssemblyStore.TryRead(huge, "x", AnalysisLimits.Default)!.Entries);
        var corrupt = AssemblyStoreWriter.V2([new("C.dll", [.. "XAZS"u8, 0, 0, 0, 0, 100, 0, 0, 0, 1, 2, 3])]);
        Assert.Contains("corrupt zstd", AssemblyStore.TryRead(corrupt, "x", AnalysisLimits.Default)!.Issues.Single().Message);
        var future = (byte[])store.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(future.AsSpan(4), 0x80010009);
        Assert.Contains("unsupported store version", AssemblyStore.TryRead(future, "x", AnalysisLimits.Default)!.Issues.Single().Message);

        var random = new Random(7);
        for (int n = 0; n < 300; n++)
        {
            var bytes = (byte[])store.Clone();
            for (int k = 0; k < 4; k++) bytes[random.Next(bytes.Length)] = (byte)random.Next(256);
            AssemblyStore.TryRead(bytes[..random.Next(20, bytes.Length)], "x", AnalysisLimits.Default); // never throws
        }
    }

    [Fact]
    public void Apk_UnpacksStoreEntriesUnderTheirNames_WithAbi()
    {
        var v3 = AssemblyStoreWriter.Elf(AssemblyStoreWriter.V2([new("TestFixture.dll", AssemblyStoreWriter.Xazs(Fixture))]), symbol: true);
        var v3x86 = AssemblyStoreWriter.Elf(AssemblyStoreWriter.V2([new("TestFixture.dll", AssemblyStoreWriter.Xazs(Fixture))], abi: 0x00030000), symbol: true);
        var apk = ContainerFixtures.Zip(
            ("AndroidManifest.xml", [0x03, 0x00, 0x08, 0x00]),
            ("lib/arm64-v8a/libassembly-store.so", v3),
            ("lib/x86_64/libassembly-store.so", v3x86),
            ("lib/arm64-v8a/libmonosgen-2.0.so", [0x7F, (byte)'E', (byte)'L', (byte)'F']));
        var contents = Containers.Open(apk, "app.apk", AnalysisLimits.Default, default);
        Assert.Equal("Android package (Xamarin / MAUI)", contents.Kind);
        var item = Assert.Single(contents.Items, i => i.Name == "assemblies/arm64-v8a/TestFixture.dll");
        Assert.Equal(Fixture, item.Bytes);
        Assert.Contains("assembly store v3 (_assembly_store symbol) entry 0 (XAZS Zstandard)", item.Origin);
        Assert.Contains(contents.Items, i => i.Name == "assemblies/x86_64/TestFixture.dll");

        using var dir = new TempDir();
        File.WriteAllBytes(dir.File("app.apk"), apk);
        using var workspace = new AssemblyWorkspace(new ServerOptions());
        var report = new UnpackService(workspace).Unpack(dir.File("app.apk"), dir.File("out"), true, AnalysisLimits.Default, default);
        var file = Assert.Single(report.Files, f => f.LoadedAs != null);
        Assert.EndsWith("TestFixture.dll", file.Path);
        Assert.Equal("TestFixture", file.LoadedAs);
    }

    [Fact]
    public void StandaloneXazs_IsDecompressed()
    {
        var contents = Containers.Open(AssemblyStoreWriter.Xazs(Fixture), "TestFixture.dll", AnalysisLimits.Default, default);
        Assert.Equal(Fixture, Assert.Single(contents.Items).Bytes);
    }
}
