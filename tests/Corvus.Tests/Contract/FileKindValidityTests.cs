using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Services.Analysis;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

/// <summary>Every file kind Blob.Identify reports checks more than its magic, and a minimal instance is reported.</summary>
public sealed class FileKindValidityTests
{
    private static readonly int[] Sizes = [4099, 70_001];
    private static readonly int[] Seeds = [1, 2, 3];

    /// <summary>The bytes each kind starts with, as far as Blob.Identify reads them; an empty row is a kind decided by structure alone.</summary>
    internal static readonly (string Kind, byte[] Magic)[] Magics =
    [
        ("zip", "PK\x03\x04"u8.ToArray()), ("zip", "PK\x05\x06"u8.ToArray()), ("jmod", "JM\x01\x00PK"u8.ToArray()),
        ("gzip", [0x1F, 0x8B]), ("zlib", [0x78, 0x9C]), ("zlib", [0x78, 0x01]), ("zlib", [0x78, 0xDA]), ("zlib", [0x78, 0x5E]),
        ("7z", [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]), ("rar", "Rar!"u8.ToArray()), ("cab", "MSCF"u8.ToArray()),
        ("pdf", "%PDF-"u8.ToArray()), ("png", [0x89, (byte)'P', (byte)'N', (byte)'G']), ("jpeg", [0xFF, 0xD8, 0xFF]),
        ("gif", "GIF8"u8.ToArray()), ("ico", [0, 0, 1, 0]), ("elf", [0x7F, (byte)'E', (byte)'L', (byte)'F']),
        ("ole (msi/doc/xls)", [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]), ("lnk shortcut", [0x4C, 0, 0, 0, 1, 0x14, 2, 0]),
        ("xalz (Xamarin LZ4)", "XALZ"u8.ToArray()), ("xazs (.NET for Android Zstandard)", "XAZS"u8.ToArray()),
        ("xaba (Xamarin assembly store)", "XABA"u8.ToArray()), (".resources", [0xCE, 0xCA, 0xEF, 0xBE]),
        ("portable pdb", "BSJB"u8.ToArray()), ("wasm", "\0asm"u8.ToArray()), ("webcil", "WbIL"u8.ToArray()),
        ("pdb", "Microsoft C/C++ MSF 7.00"u8.ToArray()), ("hermes bytecode", [0xC6, 0x1F, 0xBC, 0x03, 0xC1, 0x03, 0x19, 0x1F]),
        ("ines rom", "NES\x1A"u8.ToArray()), ("qt resources", "qres"u8.ToArray()), ("flash swf", "FWS"u8.ToArray()),
        ("flash swf", "CWS"u8.ToArray()), ("registry hive", "regf"u8.ToArray()), ("package resource index", "mrm_pri2"u8.ToArray()),
        ("gamemaker data", "FORM"u8.ToArray()), ("lua bytecode", "\x1bLua\x53"u8.ToArray()), ("luajit bytecode", "\x1bLJ\x02"u8.ToArray()),
        ("gguf", "GGUF"u8.ToArray()), ("pickle", [0x80, 4]), ("pyinstaller pyz", "PYZ\0"u8.ToArray()),
        ("mach-o", [0xCF, 0xFA, 0xED, 0xFE]), ("mach-o", [0xCA, 0xFE, 0xBA, 0xBE]), ("godotpck", "GDPC"u8.ToArray()), ("nxpk archive", "NXPK"u8.ToArray()),
        ("rpa archive", "RPA-"u8.ToArray()), ("bsa archive", "BSA\0"u8.ToArray()), ("ba2 archive", "BTDX"u8.ToArray()),
        ("vpk archive", [0x34, 0x12, 0xAA, 0x55]),
        ("webdata", "UnityWebData1.0\0"u8.ToArray()), ("asar", [4, 0, 0, 0]), ("esp32 flash", [0xAA, 0x50]),
        ("autoit script", [0xA3, 0x48, 0x4B, 0xBE, 0x98, 0x6C, 0x4A, 0xA9, 0x99, 0x4C, 0x53, 0x0A, 0x86, 0xD6, 0x48, 0x7D]),
        ("jimage", [0xDA, 0xDA, 0xFE, 0xCA]), ("python bytecode", [0xA7, 0x0D, 0x0D, 0x0A]), ("esp32 partition table", [0xAA, 0x50]),
        ("esp32 nvs", []), ("safetensors", []), ("onnx", []), ("unreal pak", []), ("unreal utoc", []),
        // Formats a view sniffs that Blob.Identify does not report.
        ("sqlite", "SQLite format 3\0"u8.ToArray()), ("plist", "bplist00"u8.ToArray()), ("evtx", "ElfFile\0"u8.ToArray()), ("procmon", "PML_"u8.ToArray()),
        ("pcap", [0xD4, 0xC3, 0xB2, 0xA1]), ("pcap", [0xA1, 0xB2, 0xC3, 0xD4]), ("pcapng", [0x0A, 0x0D, 0x0D, 0x0A]), ("esp32 image", [0xE9]),
        ("realm", "T-DB"u8.ToArray()), ("xml", "<?xml"u8.ToArray()), ("rpm", [0xED, 0xAB, 0xEE, 0xDB]), ("cpio", "070701"u8.ToArray()),
    ];

    // Marks a kind records after its first bytes, planted beside them: kind, offset from the start of the magic, bytes.
    private static readonly Dictionary<string, (int At, byte[] Bytes)> Extras = new() { ["gamemaker data"] = (8, "GEN8"u8.ToArray()) };

    /// <summary>Copies a row's magic, and the marks it records further on, into <paramref name="d"/> at <paramref name="offset"/>.</summary>
    internal static void Plant(byte[] d, string kind, byte[] magic, int offset)
    {
        magic.CopyTo(d, offset);
        if (Extras.TryGetValue(kind, out var extra)) extra.Bytes.CopyTo(d, offset + extra.At);
    }

    private static byte[] Bytes(params object[] parts)
    {
        var o = new MemoryStream();
        foreach (var p in parts)
            switch (p)
            {
                case string s: o.Write(Encoding.Latin1.GetBytes(s)); break;
                case byte[] b: o.Write(b); break;
                case int n: o.WriteByte((byte)n); break;
                case uint u: o.Write(BitConverter.GetBytes(u)); break;
                case ushort w: o.Write(BitConverter.GetBytes(w)); break;
            }
        return o.ToArray();
    }

    private static byte[] Padded(int length, params object[] parts)
    {
        var head = Bytes(parts);
        var d = new byte[Math.Max(length, head.Length)];
        head.CopyTo(d, 0);
        return d;
    }

    private static byte[] Compressed(Func<Stream, Stream> wrap)
    {
        var o = new MemoryStream();
        using (var z = wrap(o)) z.Write("a minimal instance of the kind"u8);
        return o.ToArray();
    }

    private static uint Crc32(ReadOnlySpan<byte> b) => ~Core.Firmware.Crc.Raw(0xFFFFFFFF, b);

    private static byte[] SevenZip()
    {
        var d = new byte[32];
        new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }.CopyTo(d, 0);
        d[7] = 4;
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(8), Crc32(d.AsSpan(12, 20)));
        return d;
    }

    private static byte[] Png() => Bytes(new byte[] { 0x89, (byte)'P', (byte)'N', (byte)'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13 }, "IHDR", new byte[21]);

    private static byte[] Icon()
    {
        var d = new byte[40];
        d[2] = 1; d[4] = 1; d[6] = 1; d[7] = 1; d[10] = 1; d[12] = 32;
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(14), 18);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(18), 22);
        return d;
    }

    private static byte[] Compound()
    {
        var d = new byte[512];
        new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }.CopyTo(d, 0);
        d[26] = 3; d[28] = 0xFE; d[29] = 0xFF; d[30] = 9; d[32] = 6;
        return d;
    }

    private static byte[] ShellLink()
    {
        var d = new byte[76];
        d[0] = 0x4C;
        new byte[] { 1, 0x14, 2, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46 }.CopyTo(d, 4);
        return d;
    }

    private static byte[] MetadataRoot() => Bytes("BSJB", (ushort)1, (ushort)1, 0u, 12u, "v4.0.30319\0\0");

    private static byte[] Pdb()
    {
        var d = new byte[64];
        "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\0\0\0"u8.CopyTo(d);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(32), 4096);
        return d;
    }

    private static byte[] Hermes()
    {
        var d = new byte[128];
        BinaryPrimitives.WriteUInt64LittleEndian(d, 0x1F1903C103BC1FC6);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(8), 96);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(32), 128);
        return d;
    }

    private static byte[] Swf()
    {
        var d = new byte[32];
        "FWS"u8.CopyTo(d);
        d[3] = 10; d[4] = 32; d[8] = 15 << 3;
        d[8 + 9 + 4] = 0x43; d[8 + 9 + 5] = 0x02;
        return d;
    }

    private static byte[] Lua() => Padded(32, "\x1bLua\x54\0\x19\x93\r\n\x1a\n", 4, 8, 8);

    private static byte[] UnrealPakFooter()
    {
        var d = new byte[44];
        BinaryPrimitives.WriteUInt32LittleEndian(d, 0x5A6F12E1);
        d[4] = 1;
        return d;
    }

    private static byte[] UnrealTocHeader()
    {
        var d = new byte[0x90];
        "-==--==--==--==-"u8.CopyTo(d);
        d[16] = 3; d[20] = 0x90;
        return d;
    }

    private static byte[] AutoItData() => [.. Magics.First(m => m.Kind == "autoit script").Magic, .. "AU3!EA06"u8.ToArray()];

    private static byte[] PythonBytecode() => Core.Python.PyVersion.WithHeader(Core.Python.PyVersion.MagicOf((3, 12))!, (3, 12), [0xE3, 0, 0, 0, 0]);

    private static byte[] LuaJit() => Padded(32, "\x1bLJ\x02\0", 6, "@a.lua", 20, 0, 0, 2, 0);

    /// <summary>A minimal instance of each kind, by the name Blob.Identify reports.</summary>
    internal static Dictionary<string, Func<byte[]>> Instances() => new()
    {
        ["zip"] = () => ContainerFixtures.Zip(("a.txt", "x"u8.ToArray())),
        ["jmod"] = () => Bytes("JM\x01\x00", ContainerFixtures.Zip(("a.txt", "x"u8.ToArray()))),
        ["gzip"] = () => Compressed(s => new GZipStream(s, CompressionLevel.Optimal, true)),
        ["zlib"] = () => Compressed(s => new ZLibStream(s, CompressionLevel.Optimal, true)),
        ["7z"] = SevenZip,
        ["rar"] = () => Padded(16, "Rar!\x1A\x07\x01\0"),
        ["cab"] = () => Padded(36, "MSCF", new byte[20], 3, 1),
        ["pdf"] = () => Encoding.ASCII.GetBytes("%PDF-1.4\n"),
        ["png"] = Png,
        ["jpeg"] = () => Padded(32, new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0, 28 }, "JFIF\0"),
        ["gif"] = () => Padded(16, "GIF89a", (ushort)1, (ushort)1),
        ["ico"] = Icon,
        ["elf"] = () => FormatWriterTests.SampleElf().Build(),
        ["mach-o"] = () => FormatWriterTests.SampleMachO().Build(),
        ["ole (msi/doc/xls)"] = Compound,
        ["lnk shortcut"] = ShellLink,
        ["xalz (Xamarin LZ4)"] = () => Padded(24, "XALZ", 0u, 16u),
        ["xazs (.NET for Android Zstandard)"] = () => Padded(24, "XAZS", 0u, 16u, new byte[] { 0x28, 0xB5, 0x2F, 0xFD }),
        ["xaba (Xamarin assembly store)"] = () => Padded(24, "XABA", 3u, 0u),
        [".resources"] = () => Padded(24, new byte[] { 0xCE, 0xCA, 0xEF, 0xBE }, 1u, 16u),
        ["portable pdb"] = MetadataRoot,
        ["wasm"] = () => Bytes(new byte[] { 0, 0x61, 0x73, 0x6D }, 1u),
        ["webcil"] = () => Padded(32, "WbIL", 0u, (ushort)1),
        ["pdb"] = Pdb,
        ["asar"] = () => AsarWriter.Build([AsarWriter.Text("package.json", "{}")]).Item1,
        ["hermes bytecode"] = Hermes,
        ["webdata"] = () => Padded(32, "UnityWebData1.0\0", 24u),
        ["godotpck"] = () => Padded(32, "GDPC", 2u, 4u, 2u, 0u),
        ["nxpk archive"] = () => Padded(32, "NXPK", 1u, 0u, 0u, 0u, 24u),
        ["rpa archive"] = () => Padded(16, "RPA-3.0 "),
        ["bsa archive"] = () => Padded(36, "BSA\0", 103u),
        ["ba2 archive"] = () => Padded(24, "BTDX", 1u, "GNRL"),
        ["vpk archive"] = () => Padded(12, 0x55AA1234u, 2u),
        ["jimage"] = () => Padded(32, new byte[] { 0xDA, 0xDA, 0xFE, 0xCA }, 0x10000u),
        ["ines rom"] = () => Padded(16, "NES\x1A", 1, 1),
        ["qt resources"] = () => Padded(80, "qres", new byte[] { 0, 0, 0, 1, 0, 0, 0, 20, 0, 0, 0, 40, 0, 0, 0, 60 }),
        ["flash swf"] = Swf,
        ["registry hive"] = () => Padded(4096, "regf", new byte[16], 1u, 3u, 0u, 1u),
        ["package resource index"] = () => Padded(64, "mrm_pri2", (ushort)0, (ushort)1, 64u, 32u, 64u, (ushort)1, (ushort)0xFFFF, 0u),
        ["gamemaker data"] = () => Padded(96, "FORM", 96u, "GEN8", 64u),
        ["lua bytecode"] = Lua,
        ["luajit bytecode"] = LuaJit,
        ["gguf"] = () => Bytes("GGUF", 3u, new byte[16]),
        ["pickle"] = () => new byte[] { 0x80, 2, (byte)'}', (byte)'q', 0, (byte)'.' },
        ["esp32 flash"] = () => Esp32Samples.Flash(NvsWriter.Sample().Writer.Build()),
        ["esp32 partition table"] = () => Esp32Samples.Table(Esp32Samples.Layout),
        ["esp32 nvs"] = () => NvsWriter.Sample().Writer.Build(),
        ["unreal pak"] = UnrealPakFooter,
        ["unreal utoc"] = UnrealTocHeader,
        ["autoit script"] = AutoItData,
        ["safetensors"] = () => ModelSamples.Safetensors("""{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}""", 4),
        ["onnx"] = () => ModelSamples.Onnx(),
        ["pyinstaller pyz"] = () => FrozenPythonTests.Pyz(null),
        ["python bytecode"] = PythonBytecode,
    };

    /// <summary>Kinds that report a magic planted in random data, with the first case that did.</summary>
    internal static SortedDictionary<string, string> PlantedHits()
    {
        var hits = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var (kind, magic) in Magics)
            foreach (int size in Sizes)
                foreach (int seed in Seeds)
                {
                    var d = new byte[size];
                    new Random(seed * 7919 + (magic.Length > 0 ? magic[0] : 0)).NextBytes(d);
                    Plant(d, kind, magic, 0);
                    if (Blob.Identify(d) == kind) hits.TryAdd(kind, $"size {size}, seed {seed}, magic {Convert.ToHexString(magic)}");
                }
        return hits;
    }

    [Fact]
    public void A_magic_planted_in_random_data_is_not_identified_as_its_kind()
    {
        var hits = PlantedHits();
        Assert.True(hits.Count == 0, string.Join("\n", hits.Select(h => $"{h.Key}: {h.Value}")));
    }

    private static HashSet<string> IdentifyKinds()
    {
        var src = File.ReadAllText(Path.Combine(DocsTests.RepoRoot(), "src", "Corvus", "Core", "Blob.cs"));
        var body = src[src.IndexOf("public static string Identify", StringComparison.Ordinal)..];
        body = body[..body.IndexOf("public static bool StartsWith", StringComparison.Ordinal)];
        return Regex.Matches(body, "return \"([^\"]+)\"", RegexOptions.NonBacktracking).Select(m => m.Groups[1].Value).Where(k => k is not ("text" or "data")).ToHashSet();
    }

    [Fact]
    public void Every_kind_identify_can_return_has_a_planted_row()
    {
        var missing = IdentifyKinds().Where(k => !Magics.Any(m => m.Kind == k)).Order(StringComparer.Ordinal).ToList();
        Assert.True(missing.Count == 0, "no planted row for: " + string.Join(", ", missing));
    }

    [Fact]
    public void A_minimal_instance_of_each_listed_kind_is_identified_as_it()
    {
        var kinds = IdentifyKinds();
        foreach (var (kind, build) in Instances())
        {
            Assert.Contains(kind, kinds);
            Assert.True(Blob.Identify(build()) == kind, $"{kind}: identified as '{Blob.Identify(build())}'");
        }
    }

    [Fact]
    public void Every_kind_identify_can_return_has_a_minimal_instance()
    {
        var instances = Instances();
        var missing = IdentifyKinds().Where(k => !instances.ContainsKey(k)).Order(StringComparer.Ordinal).ToList();
        Assert.True(missing.Count == 0, "no minimal instance for: " + string.Join(", ", missing));
    }

    /// <summary>Single-field changes, as (offset, value), each of which must stop the kind being identified.</summary>
    private static Dictionary<string, (int At, byte Value)[]> Mutations() => new()
    {
        ["zip"] = [(4, 0xFF), (8, 0x7F), (26, 0)],
        ["gzip"] = [(2, 7), (3, 0xE0), (9, 99)],
        ["7z"] = [(8, 0x55), (7, 9)],
        ["rar"] = [(5, 0)],
        ["cab"] = [(4, 1), (24, 4)],
        ["pdf"] = [(6, (byte)'x')],
        ["png"] = [(8, 1), (12, (byte)'X')],
        ["jpeg"] = [(3, 0), (5, 1)],
        ["gif"] = [(6, 0), (8, 0)],
        ["ico"] = [(4, 0), (12, 3)],
        ["elf"] = [(6, 2), (4, 3)],
        ["mach-o"] = [(12, 0), (4, 0xFF)],
        ["ole (msi/doc/xls)"] = [(26, 9), (30, 10), (32, 7)],
        ["wasm"] = [(4, 2)],
        ["pdb"] = [(32, 1)],
        ["portable pdb"] = [(4, 2), (12, 7)],
        ["webcil"] = [(4, 1), (8, 0)],
        [".resources"] = [(4, 2)],
        ["gguf"] = [(4, 9)],
        ["registry hive"] = [(24, 9)],
        ["flash swf"] = [(3, 0), (4, 1)],
        ["lua bytecode"] = [(5, 1), (7, 0)],
        ["unreal pak"] = [(0, 0), (4, 12), (15, 0x7F), (23, 0x7F)],
        ["unreal utoc"] = [(0, 0), (15, 0), (20, 0x91)],
        ["autoit script"] = [(0, 0), (23, (byte)'7')],
        ["safetensors"] = [(7, 0xFF), (8, (byte)'x')],
        ["onnx"] = [(1, 0), (2, 0x77)],
        ["python bytecode"] = [(4, 9), (3, 0)],
        ["pyinstaller pyz"] = [(0, 0), (6, 0)],
        ["esp32 partition table"] = [(1, 0x51)],
        ["esp32 flash"] = [(0, 0)],
        ["esp32 nvs"] = [(4, 0x55)],
    };

    [Fact]
    public void A_changed_header_field_stops_the_kind_being_identified()
    {
        var instances = Instances();
        foreach (var (kind, changes) in Mutations())
        {
            Assert.Equal(kind, Blob.Identify(instances[kind]()));
            foreach (var (at, value) in changes)
            {
                var d = instances[kind]();
                d[at] = value;
                Assert.True(Blob.Identify(d) != kind, $"{kind}: still identified with byte {at} set to 0x{value:X2}");
            }
        }
    }

    [Fact]
    [FuzzEntry(typeof(FileHeaders))]
    public void Fuzzed_files_never_throw_from_the_kind_checks()
    {
        foreach (var seed in Instances().Values.Select(b => b()))
        {
            var failures = FormatFuzz.Run(seed, b => Blob.Identify(b), 100);
            Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
        }
    }

    [Fact]
    public void A_zlib_stream_cut_by_the_end_of_the_data_is_identified()
    {
        var d = Instances()["zlib"]();
        Assert.Equal("zlib", Blob.Identify(d.AsSpan(0, d.Length - 4)));
    }

    [Fact]
    public void A_zip_with_no_entries_is_identified()
    {
        Assert.Equal("zip", Blob.Identify("PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"u8));
    }

    [Fact]
    public void A_zip_with_a_comment_longer_than_the_bytes_read_is_identified()
    {
        var d = new byte[32];
        "PK\x05\x06"u8.CopyTo(d);
        d[20] = 200;
        Assert.Equal("zip", Blob.Identify(d));
    }

    [Fact]
    public void A_jpeg_with_any_first_segment_marker_is_identified()
    {
        foreach (byte marker in new byte[] { 0xED, 0xE8, 0xFE, 0xC4, 0xC0 })
            {
            var d = Padded(32, new byte[] { 0xFF, 0xD8, 0xFF, marker, 0, 16 });
            d[20] = 0xFF;
            Assert.Equal("jpeg", Blob.Identify(d));
        }
        Assert.NotEqual("jpeg", Blob.Identify(Padded(32, new byte[] { 0xFF, 0xD8, 0xFF, 0xD9, 0, 28 })));
    }

    [Fact]
    public void A_zlib_magic_planted_in_many_seeds_of_random_data_is_not_identified()
    {
        foreach (var second in new byte[] { 0x01, 0x5E, 0x9C, 0xDA })
            for (int seed = 0; seed < 200; seed++)
            {
                var d = new byte[seed % 2 == 0 ? 24 : 4099];
                new Random(seed).NextBytes(d);
                d[0] = 0x78;
                d[1] = second;
                Assert.NotEqual("zlib", Blob.Identify(d));
            }
    }

    [Fact]
    public void A_thin_32_bit_arm_mach_o_header_is_read_as_arm32()
    {
        var d = new byte[32];
        BinaryPrimitives.WriteUInt32LittleEndian(d, 0xFEEDFACE);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(4), 12);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(12), 2);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(16), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(20), 8);
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, d);
            Assert.True(Corvus.Services.AotBinaryLayout.IsArm32(path));
        }
        finally { File.Delete(path); }
    }
}

/// <summary>Every summarize_file view applies to its own format only: a magic planted in random data is not viewed.</summary>
public sealed class FileViewValidityTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>Views that apply to a magic planted in random data, with the first case that did.</summary>
    private SortedDictionary<string, string> PlantedHits()
    {
        var hits = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var view in Providers.Of<IFileSummaryView>())
        {
            var folder = Directory.CreateDirectory(_dir.File(view.Name)).FullName;
            foreach (var (kind, magic) in FileKindValidityTests.Magics)
                foreach (int size in new[] { 4099, 70_001 })
                {
                    var d = new byte[size];
                    new Random(size + (magic.Length > 0 ? magic[0] : 0)).NextBytes(d);
                    FileKindValidityTests.Plant(d, kind, magic, 0);
                    var path = Path.Combine(folder, "sample.bin");
                    File.WriteAllBytes(path, d);
                    try
                    {
                        var shown = view.Inspect(new FileInput(path, d, Blob.Identify(d)) { Options = new FileViewOptions(view.Name) }, default);
                        if (shown != null) hits.TryAdd(view.Name, $"{kind}, size {size}");
                    }
                    catch (ToolError) { }
                }
        }
        return hits;
    }

    [Fact]
    public void A_minimal_instance_of_each_listed_view_is_viewed()
    {
        var views = Providers.Of<IFileSummaryView>().ToDictionary(v => v.Name);
        foreach (var (name, instance) in FileViewInstances.All())
        {
            var path = instance.Place(Directory.CreateDirectory(_dir.File("instance-" + name)).FullName);
            var d = File.ReadAllBytes(path);
            Assert.True(views[name].Inspect(new FileInput(path, d, Blob.Identify(d)) { Options = new FileViewOptions(name) }, default) != null, $"{name}: nothing viewed for its instance");
        }
    }

    [Fact]
    public void Every_view_has_a_minimal_instance()
    {
        var instances = FileViewInstances.All();
        var missing = Providers.Of<IFileSummaryView>().Where(v => !instances.ContainsKey(v.Name)).Select(v => v.Name).Order(StringComparer.Ordinal).ToList();
        Assert.True(missing.Count == 0, "no minimal instance for: " + string.Join(", ", missing));
    }

    [Fact]
    public void A_changed_header_field_stops_the_view()
    {
        var views = Providers.Of<IFileSummaryView>().ToDictionary(v => v.Name);
        var failures = new List<string>();
        foreach (var (name, changes) in FileViewInstances.Mutations())
            foreach (var (at, value) in changes)
            {
                var path = FileViewInstances.All()[name].Place(Directory.CreateDirectory(_dir.File($"mutated-{name}-{at}")).FullName);
                var d = File.ReadAllBytes(path);
                Assert.True(views[name].Inspect(new FileInput(path, d, Blob.Identify(d)) { Options = new FileViewOptions(name) }, default) != null, $"{name}: not viewed before the change");
                d[at] = value;
                File.WriteAllBytes(path, d);
                FileView? shown = null;
                try { shown = views[name].Inspect(new FileInput(path, d, Blob.Identify(d)) { Options = new FileViewOptions(name) }, default); }
                catch (ToolError) { }
                if (shown != null) failures.Add($"{name}: still viewed with byte {at} set to 0x{value:X2}");
            }
        Assert.True(failures.Count == 0, string.Join(", ", failures));
    }

    [Fact]
    public void Every_mutation_names_a_listed_view()
    {
        var unknown = FileViewInstances.Mutations().Keys.Where(k => !FileViewInstances.All().ContainsKey(k)).ToList();
        Assert.True(unknown.Count == 0, "mutation for a view with no instance: " + string.Join(", ", unknown));
    }

    [Fact]
    public void Every_view_with_an_instance_has_a_mutation_or_a_reason()
    {
        var mutations = FileViewInstances.Mutations();
        var missing = FileViewInstances.All().Keys.Where(k => !mutations.ContainsKey(k) && !FileViewInstances.NotMagicGated.ContainsKey(k)).Order(StringComparer.Ordinal).ToList();
        Assert.True(missing.Count == 0, "no mutation and no reason for: " + string.Join(", ", missing));
        var both = FileViewInstances.NotMagicGated.Keys.Where(mutations.ContainsKey).ToList();
        Assert.True(both.Count == 0, "listed with a reason and a mutation: " + string.Join(", ", both));
    }

    [Fact]
    public void A_magic_planted_in_random_data_is_not_viewed_by_any_view()
    {
        var hits = PlantedHits();
        Assert.True(hits.Count == 0, string.Join("\n", hits.Select(h => $"{h.Key}: {h.Value}")));
    }
}

/// <summary>Code built by a compiler for each instruction set the raw view reports, from the ISA fixtures.</summary>
internal static class RawCodeFixtures
{
    /// <summary>Size built code is repeated to, 4 KiB.</summary>
    public const int FileSize = 4096;

    /// <summary>Fixtures without an instruction set in the raw view, with the reason.</summary>
    public static readonly IReadOnlyDictionary<string, string> NotReported = new Dictionary<string, string>
    {
        ["armbe.elf"] = "big-endian ARM is not an instruction set the raw view loads",
        ["m6502.bin"] = "6502 has no signature in RawCandidates.NotChecked",
        ["nrom.nes"] = "6502 has no signature in RawCandidates.NotChecked",
    };

    /// <summary>Instruction sets of the raw view without a fixture, with the reason.</summary>
    public static readonly IReadOnlyDictionary<string, string> NoFixture = new Dictionary<string, string>
    {
        ["arm"] = "no 32-bit ARM fixture; the signatures are checked on thumb and arm64 builds",
        ["mips64"] = "no 64-bit MIPS big-endian fixture",
        ["mips64el"] = "no 64-bit MIPS little-endian fixture",
        ["ppc64le"] = "no little-endian PowerPC fixture",
    };

    private static readonly (string File, string Arch)[] Files =
    [
        ("mips32be.elf", "mips"), ("mips32be-got.elf", "mips"), ("mips32be-plt.elf", "mips"), ("mips32le.elf", "mipsel"), ("ppc32.elf", "ppc"),
        ("ppc64.elf", "ppc64"), ("ppc64v1.elf", "ppc64"), ("riscv32.elf", "riscv32"), ("riscv64.elf", "riscv64"), ("emu-x86.elf", "x86"),
        ("emu-x64.elf", "x64"), ("emu-arm64.elf", "arm64"), ("cortexm.bin", "thumb"), ("m68k.bin", "m68k"),
    ];

    /// <summary>The code of each fixture with its instruction set.</summary>
    public static IEnumerable<(string File, string Arch, byte[] Code)> Built()
    {
        foreach (var (file, arch) in Files)
        {
            var path = Path.Combine(AppContext.BaseDirectory, "Engines", "IsaFixtures", file);
            if (file == "cortexm.bin") { yield return (file, arch, File.ReadAllBytes(path)[256..]); continue; }
            if (file == "m68k.bin") { yield return (file, arch, File.ReadAllBytes(path)); continue; }
            var image = Corvus.Native.NativeImageLoader.Open(path);
            var code = new List<byte>();
            foreach (var section in image.Sections.Where(x => x.IsExecutable))
            {
                var bytes = new byte[section.RawSize];
                image.Read(section.Rva, bytes);
                code.AddRange(bytes);
            }
            yield return (file, arch, [.. code]);
        }
    }

    /// <summary>The code repeated to <see cref="FileSize"/> bytes at least.</summary>
    public static byte[] Repeated(byte[] code)
    {
        var d = new List<byte>();
        while (d.Count < FileSize) d.AddRange(code);
        return [.. d];
    }
}

/// <summary>The raw view reads built code for every instruction set it reports and never reads random data as code.</summary>
public sealed class RawCodeValidityTests(Xunit.Abstractions.ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static readonly int[] Sizes = [4096, 16_384, 65_536, 262_144, 1 << 20];

    private static byte[] Random(int size, int seed)
    {
        var d = new byte[size];
        new System.Random(seed).NextBytes(d);
        return d;
    }

    private string? Viewed(byte[] d)
    {
        var path = _dir.File("sample.bin");
        File.WriteAllBytes(path, d);
        var view = new RawCodeFileView().Inspect(new FileInput(path, d, Blob.Identify(d)), default);
        return view == null ? null
            : string.Join(" ", ((RawCodeFileView.Facts)view.Detail).Regions.SelectMany(r => r.Isas).Select(i => i.Arch));
    }

    [Fact]
    public void Random_data_of_every_size_and_seed_is_not_read_as_code()
    {
        double worst = 0;
        var read = new List<string>();
        foreach (int size in Sizes)
            for (int seed = 1; seed <= 24; seed++)
            {
                var d = Random(size, seed);
                worst = Math.Max(worst, Corvus.Native.RawCandidates.Score(d)[0].Score);
                if (Viewed(d) != null) read.Add($"size {size}, seed {seed}");
            }
        output.WriteLine($"highest random score {worst} (reported from {Corvus.Native.RawCandidates.MinScore})");
        Assert.True(worst < Corvus.Native.RawCandidates.MinScore / 2, $"highest random score {worst}");
        Assert.True(read.Count == 0, string.Join(", ", read));
    }

    [Fact]
    public void Built_code_of_every_reported_instruction_set_is_read_as_code()
    {
        double lowest = double.MaxValue;
        var missed = new List<string>();
        foreach (var (file, arch, code) in RawCodeFixtures.Built())
        {
            var d = RawCodeFixtures.Repeated(code);
            var isas = Corvus.Native.RawCandidates.Isas(d);
            double score = isas.FirstOrDefault(i => i.Arch == arch)?.Score ?? 0;
            lowest = Math.Min(lowest, score);
            output.WriteLine($"{file}: {arch} {score}");
            if (score < Corvus.Native.RawCandidates.MinScore || Viewed(d)?.Contains(arch, StringComparison.Ordinal) != true) missed.Add($"{file}: {arch}");
        }
        output.WriteLine($"lowest built score {lowest}");
        Assert.True(lowest >= Corvus.Native.RawCandidates.MinScore, $"lowest built score {lowest}");
        Assert.True(missed.Count == 0, string.Join(", ", missed));
    }

    [Fact]
    public void Unrepeated_built_code_of_1_KiB_is_read_as_its_instruction_set()
    {
        var missed = new List<string>();
        // Mostly padding or, for emu-x86.elf, no frame prologue in the first KiB.
        foreach (var (file, arch, code) in RawCodeFixtures.Built().Where(b => b.Code.Length >= 1024 && b.Code[..1024].Count(x => x == 0) < 256 && b.File != "emu-x86.elf"))
        {
            var d = code[..1024];
            double score = Corvus.Native.RawCandidates.Isas(d).FirstOrDefault(i => i.Arch == arch)?.Score ?? 0;
            output.WriteLine($"{file}: {arch} {score}");
            if (score == 0) missed.Add($"{file}: {arch}");
        }
        Assert.True(missed.Count == 0, string.Join(", ", missed));
    }

    [Fact]
    public void Every_instruction_set_without_a_built_row_names_its_reason()
    {
        var built = RawCodeFixtures.Built().Select(b => b.Arch).ToHashSet();
        var unlisted = Corvus.Native.RawCandidates.Score(new byte[4096]).Select(c => c.Arch)
            .Where(a => !built.Contains(a) && !RawCodeFixtures.NoFixture.ContainsKey(a)).ToList();
        Assert.True(unlisted.Count == 0, string.Join(", ", unlisted));
    }

    [Fact]
    public void Every_fixture_without_a_built_row_names_its_reason()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "Engines", "IsaFixtures");
        var rows = RawCodeFixtures.Built().Select(b => b.File).ToHashSet();
        var unlisted = Directory.EnumerateFiles(dir).Select(Path.GetFileName).Where(f => f!.EndsWith(".elf") || f.EndsWith(".bin") || f.EndsWith(".nes"))
            .Where(f => !rows.Contains(f!) && !RawCodeFixtures.NotReported.ContainsKey(f!)).ToList();
        Assert.True(unlisted.Count == 0, string.Join(", ", unlisted));
    }
}

/// <summary>Every scan that reports a format at an arbitrary offset checks more than its magic.</summary>
public sealed class EmbeddedScanValidityTests
{
    private static readonly int[] Offsets = [1, 7, 100, 2000];

    private static int Carved(byte[] d) => Containers.Carve(d, "sample.bin", "data", AnalysisLimits.Default, default).Items.Count;

    private static int Streams(byte[] d) => NativeEmbeddedContent.Highlights("sample.bin", d, default).Count(l => l.StartsWith("Compression stream", StringComparison.Ordinal));

    /// <summary>The scans, each as the count of formats it reports in the bytes, with a minimal instance to embed.</summary>
    private static Dictionary<string, (Func<byte[], int> Count, Func<byte[]> Instance)> Scans() => new()
    {
        ["Containers.Carve"] = (Carved, FileKindValidityTests.Instances()["gzip"]),
        ["NativeEmbeddedContent.Highlights"] = (Streams, FileKindValidityTests.Instances()["gzip"]),
        ["Blob.CarvePe"] = (d => Blob.CarvePe(d).Count, () => NativePeTests.KitchenSink(true)),
        ["AppendedArchive.CountEndRecords"] = (d => Core.Archives.AppendedArchive.CountEndRecords(() => new MemoryStream(d), default).Count, FileKindValidityTests.Instances()["zip"]),
        ["AutoItScript.Find"] = (d => Core.AutoIt.AutoItScript.Find(d) >= 0 ? 1 : 0,
            () => [.. FileKindValidityTests.Magics.First(m => m.Kind == "autoit script").Magic, .. "AU3!EA06"u8.ToArray()]),
    };

    private static byte[] Embedded(byte[] inner, int offset, int seed, string? kind = null)
    {
        var d = new byte[70_001];
        new Random(seed * 31 + offset).NextBytes(d);
        if (kind == null) inner.CopyTo(d, offset);
        else FileKindValidityTests.Plant(d, kind, inner, offset);
        return d;
    }

    [Fact]
    public void A_magic_planted_in_random_data_is_not_reported_by_any_scan()
    {
        var reported = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var (name, scan) in Scans())
            foreach (var (kind, magic) in FileKindValidityTests.Magics.Where(m => m.Magic.Length > 0))
                foreach (int offset in Offsets)
                    foreach (int seed in new[] { 1, 2, 3 })
                        if (scan.Count(Embedded(magic, offset, seed, kind)) > 0) reported.TryAdd(name, $"{kind} at {offset}, seed {seed}");
        Assert.True(reported.Count == 0, string.Join("\n", reported.Select(r => $"{r.Key}: {r.Value}")));
    }

    [Fact]
    public void A_minimal_instance_inside_random_data_is_reported_by_each_scan()
    {
        foreach (var (name, scan) in Scans())
            foreach (int offset in Offsets)
                Assert.True(scan.Count(Embedded(scan.Instance(), offset, 1)) > 0, $"{name}: nothing reported for its instance at {offset}");
    }

    [Fact]
    public void Every_source_file_that_scans_for_a_magic_has_a_scan_row()
    {
        var src = Path.Combine(DocsTests.RepoRoot(), "src", "Corvus");
        var known = new[] { "Services/Analysis/InspectionService.cs", "Core/Archives/AppendedArchive.cs", "Core/Containers.cs", "Core/Blob.cs", "Services/Analysis/NativeEmbeddedContent.cs", "Core/AutoIt/AutoItScript.cs" };
        var call = new Regex(@"Blob\.FindAll\(|Blob\.CarvePe\(", RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);
        var unknown = Directory.EnumerateFiles(src, "*.cs", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(src, f).Replace(Path.DirectorySeparatorChar, '/'))
            .Where(f => !f.StartsWith("obj/", StringComparison.Ordinal) && !known.Contains(f) && call.IsMatch(File.ReadAllText(Path.Combine(src, f))))
            .ToList();
        Assert.True(unknown.Count == 0, "a scan with no row in EmbeddedScanValidityTests.Scans: " + string.Join(", ", unknown));
    }
}
