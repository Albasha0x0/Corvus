using System.Text;
using Corvus.Core;
using Corvus.Core.Archives;
using Corvus.Core.Disks;
using Corvus.Core.Documents;
using Corvus.Core.Firmware;
using Corvus.Core.Firmware.Esp32;
using Corvus.Core.Flash;
using Corvus.Core.Installers;
using Corvus.Core.Mobile;
using Corvus.Core.Node;
using Corvus.Core.Python;
using Corvus.Services.Web;

namespace Corvus.Tests;

/// <summary>Every container reader checks its header fields, not only its magic.</summary>
public sealed class ContainerReaderHeaderTests
{
    private static readonly int[] Extra = [1, 7, 100, 4099, 70_001, 1_100_000];

    /// <summary>Readers the planted cases cannot apply to, with the reason.</summary>
    private static readonly Dictionary<Type, string> Exempt = new()
    {
        [typeof(TransformedBlockContainerReader)] = "a marker and a block-aligned length; a cut payload is listed as partial",
    };
    private static readonly int[] Seeds = [1, 2, 3];
    private const int KeptBytes = 512;

    /// <summary>Where a magic sits in an instance: an offset, the first match or the last (a trailer).</summary>
    internal sealed record Mark(byte[]? Magic, int At = -1, int Length = 0, bool Last = false)
    {
        public (int At, int Length) Resolve(byte[] instance)
        {
            if (Magic == null) return (At, Length);
            int at = At >= 0 ? At : Last ? instance.AsSpan().LastIndexOf(Magic) : instance.AsSpan().IndexOf(Magic);
            Assert.True(at >= 0 && instance.AsSpan(at).StartsWith(Magic), "the magic is not in the instance");
            return (at, Magic.Length);
        }
    }

    internal sealed record Instance(string Name, Func<byte[]> Build, Mark Mark);

    private static Mark Text(string magic, int at = -1, bool last = false) => new(Encoding.Latin1.GetBytes(magic), at, 0, last);

    private static Mark Bytes(params byte[] magic) => new(magic);

    private static Mark Head(int length) => new(null, 0, length);

    private static Instance I(string name, Func<byte[]> build, Mark mark) => new(name, build, mark);

    private static byte[] NtfsVolume()
    {
        var volume = new byte[8 << 20];
        using var disk = DiskStream.Open(FsSource.Of(DiskImageTests.Fixture("disk-gpt.vhdx"), "d"))!;
        disk.Position = 1 << 20;
        disk.ReadExactly(volume);
        return volume;
    }

    private static byte[] Tar() => Decompress(TarGz());

    private static byte[] TarGz() => ArchiveReaderTests.TarGz(("lib/app.dll", ContainerFixtures.Module("App")), ("README.md", "# hello"u8.ToArray()));

    private static byte[] Decompress(byte[] gz)
    {
        using var plain = new MemoryStream();
        using (var z = new System.IO.Compression.GZipStream(new MemoryStream(gz), System.IO.Compression.CompressionMode.Decompress)) z.CopyTo(plain);
        return plain.ToArray();
    }

    private static byte[] Xz() => [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00, 0x04, 0xE6, 0xD6, 0xB4, 0x46, .. new byte[64]];

    private static byte[] Bzip2() => [.. "BZh9"u8, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, .. new byte[64]];

    private static byte[] SevenZip()
    {
        var d = new byte[32];
        byte[] sig = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 4];
        sig.CopyTo(d, 0);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(8), ~Crc.Raw(0xFFFFFFFF, d.AsSpan(12, 20)));
        return d;
    }

    private static byte[] Rar4() => [.. "Rar!\u001A\u0007\0"u8, 0xCF, 0x90, 0x73, 0, 0, 0x0D, 0, 0, 0, 0, 0, 0, 0];

    private static byte[] Eml() => MailMessageTests.Eml();

    /// <summary>The minimal instances of each reader: file name, bytes and magic.</summary>
    internal static Dictionary<Type, Instance[]> Instances() => new()
    {
        [typeof(AceReader)] = [I("x.ace", () => [.. AceArchiveTests.Main(), .. AceArchiveTests.File("docs\\a.txt", 100, [1, 2, 3])], Text("**ACE**"))],
        [typeof(ApkV3Reader)] = [I("x.apk", ApkV3Tests.Package, Text("ADB")), I("x.adb", ApkV3Tests.Index, Text("ADB"))],
        [typeof(ArReader)] = [I("x.deb", ArArchiveTests.Deb, Text("!<arch>\n"))],
        [typeof(ArchiveReader)] =
        [
            I("x.tgz", TarGz, Bytes(0x1F, 0x8B)), I("x.tar", Tar, Text("ustar", 257)), I("x.xz", Xz, Bytes(0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00)),
            I("x.bz2", Bzip2, Text("BZh")), I("x.7z", SevenZip, Bytes(0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C)), I("x.rar", Rar4, Text("Rar!\u001A\u0007")),
        ],
        [typeof(FlatpakBundleReader)] = [I("x.flatpak", FlatpakBundleTests.Bundle, Text("flatpak\0"))],
        [typeof(IndexedBlobStoreReader)] = [I("package.bin", () => IndexedBlobStoreTests.Store(0, IndexedBlobStoreTests.Text(40), IndexedBlobStoreTests.Noise(64), IndexedBlobStoreTests.Text(24)), Head(4))],
        [typeof(QtResourceReader)] = [I("x.rcc", () => QtResourceSamples.Rcc(QtResourceSamples.Sample, 1), Text("qres"))],
        [typeof(RpmReader)] = [I("x.rpm", () => File.ReadAllBytes(RpmReaderTests.Fixture("ledger-tools-gzip.rpm")), Bytes(0xED, 0xAB, 0xEE, 0xDB))],
        [typeof(TransformedBlockContainerReader)] = [I("x.luae", () => TransformedBlockContainerTests.Container(256), Head(4))],
        [typeof(XarReader)] = [I("x.pkg", () => XarCpioTests.Xar("Payload", XarCpioTests.Cpio("a.bin", new byte[64]), "d"), Text("xar!"))],
        [typeof(CpioReader)] = [I("x.cpio", () => XarCpioTests.Cpio("a.bin", new byte[64]), Text("070701"))],
        [typeof(VirtualDiskReader)] = [I("d.vhdx", () => DiskImageTests.Fixture("disk-gpt.vhdx"), Text("vhdxfile")), I("v.vhd", () => DiskImageTests.Fixture("disk-mbr-dynamic.vhd"), Text("conectix"))],
        [typeof(Iso9660Reader)] = [I("a.iso", () => DiskImageTests.Fixture("joliet.iso"), Text("CD001", 16 * 2048 + 1))],
        [typeof(NtfsReader)] = [I("n.img", NtfsVolume, Text("NTFS    ", 3))],
        [typeof(ChmReader)] = [I("x.chm", () => ChmTests.Chm([("/index.htm", "<p>"u8.ToArray())], [("/big.htm", ChmTests.Page(1000, 5))]), Text("ITSF"))],
        [typeof(CompoundFileReader)] = [I("doc.doc", OfficeDocumentTests.WordDocument, Bytes(0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1))],
        [typeof(MailReader)] = [I("a.eml", Eml, Text("Return-Path:")), I("a.mht", MailMessageTests.Mht, Text("From:")), I("a.ics", () => MailMessageTests.Ics(), Text("BEGIN:VCALENDAR"))],
        [typeof(OneNoteReader)] = [I("a.one", () => OfficeDocumentTests.OneNoteSection([1, 2, 3]), Head(16))],
        [typeof(PdfReader)] = [I("a.pdf", () => PdfDocumentTests.Base().Build(), Text("%PDF-"))],
        [typeof(ShellLinkReader)] = [I("a.lnk", () => ShellLinkTests.Shortcut("/c calc", [1, 2, 3]), Head(20))],
        [typeof(ApfsReader)] = [I("x.apfs", () => new ApfsWriter().File("a/b.txt", [1, 2, 3]).Build(), Text("NXSB", 32))],
        [typeof(UImageReader)] = [I("k.uimage", () => FirmwareImageTests.UImage(new byte[16]), Head(4))],
        [typeof(FitReader)] = [I("i.itb", () => FirmwareImageTests.Fit(FirmwareFilesystemTests.Isa("armbe.elf"), new byte[64]), Head(4))],
        [typeof(AndroidBootReader)] = [I("boot.img", () => FirmwareImageTests.AndroidBoot(FirmwareFilesystemTests.Isa("armbe.elf"), new byte[16]), Text("ANDROID!"))],
        [typeof(TrxReader)] = [I("fw.trx", () => FirmwareImageTests.Trx(new byte[100], FirmwareFilesystemTests.FsFixture("squashfs-lzo.img")), Text("HDR0"))],
        [typeof(CramfsReader)] = [I("c.img", () => FirmwareFilesystemTests.FsFixture("cramfs-le.img"), Head(4)), I("c.img", () => FirmwareFilesystemTests.FsFixture("cramfs-be.img"), Head(4))],
        [typeof(Esp32FlashReader)] = [I("flash.bin", () => Esp32Samples.Flash(NvsWriter.Sample().Writer.Build(empty: 0))[..0x12000], Bytes(0xE9))],
        [typeof(ExtReader)] = [I("ext2.img", () => FirmwareFilesystemTests.FsFixture("ext2.img"), Bytes(0x53, 0xEF)), I("ext4.img", () => FirmwareFilesystemTests.FsFixture("ext4.img"), Bytes(0x53, 0xEF))],
        [typeof(FatReader)] = [I("fat12.img", () => FirmwareFilesystemTests.FsFixture("fat12.img"), Bytes(0x55, 0xAA)), I("fat32.img", () => FirmwareFilesystemTests.FsFixture("fat32.img"), Bytes(0x55, 0xAA))],
        [typeof(HfsPlusReader)] = [I("x.hfs", () => new HfsPlusWriter().File("a/b.txt", [1, 2, 3]).Build(), Text("H+", 1024))],
        [typeof(InesRomReader)] = [I("x.nes", () => InesRomTests.Rom(4, 1, mapper: 4), Text("NES\x1A"))],
        [typeof(Jffs2Reader)] = [I("x.jffs2", () => FirmwareFlashTests.Jffs2(false), Head(2)), I("x.jffs2", () => FirmwareFlashTests.Jffs2(true), Head(2))],
        [typeof(SquashfsReader)] = [I("x.squashfs", () => FirmwareFilesystemTests.FsFixture("squashfs-gzip.img"), Text("hsqs"))],
        [typeof(UbiReader)] = [I("x.ubi", () => FirmwareFlashTests.Ubi(FirmwareFlashTests.Ubifs(), FirmwareFilesystemTests.Isa("armbe.elf")), Text("UBI#"))],
        [typeof(UbifsReader)] = [I("x.ubifs", () => FirmwareFlashTests.Ubifs(), Head(4))],
        [typeof(UdifReader)] = [I("x.dmg", () => UdifWriter.Build([("disk image (Apple_HFS : 0)", new HfsPlusWriter().File("a/b.txt", [1, 2, 3]).Build())], 0x80000005, 1), Text("koly", last: true))],
        [typeof(SwfReader)] = [I("a.swf", () => SwfTests.Sample('F'), Head(3)), I("a.swf", () => SwfTests.Sample('C'), Head(3))],
        [typeof(BurnBundleReader)] = [I("Setup.exe", InstallerStubTests.BurnFixture, Text(".wixburn"))],
        [typeof(CabinetReader)] = [I("a.cab", () => InstallerTests.Fixture("mszip.cab"), Text("MSCF"))],
        [typeof(ClickOnceManifestReader)] = [I("App.application", () => ClickOnceTests.DeploymentManifest(ClickOnceTests.AppManifest([1, 2, 3])), Text("urn:schemas-microsoft-com:asm.v1"))],
        [typeof(InnoSetupReader)] = [I("Setup.exe", () => InstallerStubTests.InnoFixture(), Text("PE\0\0"))],
        [typeof(MsiReader)] = [I("c.msi", () => InstallerTests.Fixture("sample.msi"), Bytes(0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1))],
        [typeof(NsisInstallerReader)] = [I("Setup.exe", () => InstallerStubTests.NsisFixture(), Text("NullsoftInst"))],
        [typeof(SquirrelSetupReader)] = [I("Setup.exe", () => InstallerStubTests.Stub("DATA", 131, InstallerStubTests.Zip(("RELEASES", Encoding.ASCII.GetBytes($"{new string('A', 40)} A-1-full.nupkg 3\n")), ("A-1-full.nupkg", [1, 2, 3]))), Text("PE\0\0"))],
        [typeof(AssetCatalogReader)] = [I("Assets.car", () => AssetCatalogTests.Catalog().Build(), Text("BOMStore"))],
        [typeof(NodeBundleReader)] = [I("app", NodeBundleTests.Seed, Text("NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2"))],
        [typeof(FrozenPythonReader)] = [I("fuzz.exe", () => FrozenPythonTests.PyInstallerSample(), Text("_MEIPASS"))],
        [typeof(BlobPayloadReader)] = [I("logo.svg", () => Encoding.UTF8.GetBytes(BlobPayloadTests.Svg(BlobPayloadTests.Script($"'{Convert.ToBase64String(BlobPayloadTests.ArchiveBytes(6000))}'"))), Text("<![CDATA["))],
    };

    internal static Type[] ReaderTypes() => typeof(IContainerReader).Assembly.GetTypes()
        .Where(t => t is { IsClass: true, IsAbstract: false } && typeof(IContainerReader).IsAssignableFrom(t)).OrderBy(t => t.FullName, StringComparer.Ordinal).ToArray();

    private static IContainerReader Reader(Type t) => (IContainerReader)Activator.CreateInstance(t, nonPublic: true)!;

    [Fact]
    public void Every_container_reader_has_a_minimal_instance()
    {
        var instances = Instances();
        var missing = ReaderTypes().Where(t => !instances.ContainsKey(t)).Select(t => t.Name).ToList();
        Assert.True(missing.Count == 0, "container readers without a minimal instance: " + string.Join(", ", missing));
        var unknown = instances.Keys.Where(t => !ReaderTypes().Contains(t)).Select(t => t.Name).ToList();
        Assert.True(unknown.Count == 0, "instances for types that are no container reader: " + string.Join(", ", unknown));
    }

    [Fact]
    public void A_minimal_instance_is_accepted_by_its_reader()
    {
        var refused = new List<string>();
        foreach (var (type, list) in Instances())
            foreach (var i in list)
            {
                var bytes = i.Build();
                i.Mark.Resolve(bytes);
                if (!Reader(type).Accepts(bytes, i.Name)) refused.Add($"{type.Name}: {i.Name}");
            }
        Assert.True(refused.Count == 0, "not accepted: " + string.Join("; ", refused));
    }

    /// <summary>How a reader takes the data, or null if it refuses it or opens it empty with a note.</summary>
    internal static string? Outcome(IContainerReader reader, byte[] data, string name)
    {
        if (!reader.Accepts(data, name)) return null;
        ContainerContents c;
        try { c = reader.Open(data, name, true, AnalysisLimits.Default, default); }
        catch (Exception ex) { return $"accepted, then Open threw {ex.GetType().Name}: {ex.Message.ReplaceLineEndings(" ")[..Math.Min(80, ex.Message.Length)]}"; }
        if (c.Items.Count > 0 || c.Entries is { Count: > 0 }) return $"accepted, then Open returned {c.Items.Count} items and {c.Entries?.Count ?? 0} entries";
        return c.Notes.Count == 0 ? "accepted, then Open returned nothing and no note" : null;
    }

    /// <summary>Readers that take a magic planted in random data, with the first case.</summary>
    internal static SortedDictionary<string, string> PlantedHits()
    {
        var hits = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var (type, list) in Instances().Where(e => !Exempt.ContainsKey(e.Key)))
            foreach (var i in list)
            {
                var instance = i.Build();
                var (at, length) = i.Mark.Resolve(instance);
                foreach (int extra in Extra)
                    foreach (int seed in Seeds)
                    {
                        int tail = instance.Length - at;
                        var d = new byte[i.Mark.Last ? Math.Max(tail, length + extra) : at + length + extra];
                        new Random(seed * 7919 + extra).NextBytes(d);
                        if (i.Mark.Last) instance.AsSpan(at, length).CopyTo(d.AsSpan(d.Length - tail));
                        else instance.AsSpan(0, at + length).CopyTo(d);
                        if (Outcome(Reader(type), d, i.Name) is { } why) hits.TryAdd($"{type.Name} ({i.Name})", $"{why} [{d.Length} bytes, seed {seed}]");
                    }
            }
        return hits;
    }

    /// <summary>Readers whose Open fails other than with a tool error on an instance with a random payload.</summary>
    internal static SortedDictionary<string, string> RandomPayloadFailures()
    {
        var hits = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var (type, list) in Instances().Where(e => !Exempt.ContainsKey(e.Key)))
            foreach (var i in list)
            {
                var instance = i.Build();
                if (instance.Length < 2 * KeptBytes) continue;
                foreach (int seed in Seeds)
                {
                    var d = (byte[])instance.Clone();
                    new Random(seed).NextBytes(d.AsSpan(KeptBytes));
                    var reader = Reader(type);
                    if (!reader.Accepts(d, i.Name)) continue;
                    try { reader.Open(d, i.Name, true, AnalysisLimits.Default, default); }
                    catch (ToolError) { }
                    catch (Exception ex) { hits.TryAdd($"{type.Name} ({i.Name})", $"Open threw {ex.GetType().Name} [{d.Length} bytes, seed {seed}]"); }
                }
            }
        return hits;
    }

    [Fact]
    public void A_magic_followed_by_random_bytes_is_refused_or_opens_empty_with_a_note()
    {
        var hits = PlantedHits();
        Assert.True(hits.Count == 0, string.Join("\n", hits.Select(h => $"{h.Key}: {h.Value}")));
    }

    [Fact]
    public void A_random_payload_behind_a_valid_header_fails_only_with_a_tool_error()
    {
        var hits = RandomPayloadFailures();
        Assert.True(hits.Count == 0, string.Join("\n", hits.Select(h => $"{h.Key}: {h.Value}")));
    }

    private static Type? TakenBy(byte[] data, string name) => Containers.ReaderFor(data, name)?.GetType();

    [Fact]
    public void A_truncated_ines_image_is_not_taken_as_ines()
    {
        var rom = InesRomTests.Rom(4, 1, mapper: 4);
        Assert.Equal(typeof(InesRomReader), TakenBy(rom, "x.nes"));
        Assert.NotEqual(typeof(InesRomReader), TakenBy(rom[..(16 + 0x4000)], "x.nes"));
    }

    [Fact]
    public void A_cut_ace_main_header_is_not_taken_as_ace()
    {
        var cut = AceArchiveTests.Main().Take(20).ToArray();
        Assert.NotEqual(typeof(AceReader), TakenBy(cut, "x.ace"));
    }

    [Fact]
    public void A_fat_image_without_its_tables_is_not_taken_as_fat()
    {
        var image = FirmwareFilesystemTests.FsFixture("fat12.img");
        Assert.Equal(typeof(FatReader), TakenBy(image, "x.img"));
        Assert.NotEqual(typeof(FatReader), TakenBy(image[..512], "x.img"));
    }

    [Fact]
    public void A_header_with_text_in_bytes_7_to_15_is_taken_as_ines()
    {
        var rom = InesRomTests.Rom(2, 1, mapper: 0);
        "DiskDude!"u8.CopyTo(rom.AsSpan(7));
        Assert.Equal(typeof(InesRomReader), TakenBy(rom, "x.nes"));
    }

    [Fact]
    public void A_declared_size_past_the_end_of_a_whole_file_over_1_mib_is_refused()
    {
        var rom = new byte[3 << 19];
        "NES\x1A"u8.CopyTo(rom);
        rom[4] = 200;
        Assert.False(InesRom.Holds(rom));
        // A head of a larger file is exactly HeadBytes long: its sizes are unknown.
        Assert.True(InesRom.Holds(rom.AsSpan(0, Containers.HeadBytes)));
    }

    [Fact]
    public void A_fixed_vhd_over_1_mib_is_found_by_its_footer_at_the_end()
    {
        var disk = new byte[(3 << 19) + 512];
        FirmwareSignatureValidityTests.VhdFooter().CopyTo(disk, disk.Length - 512);
        Assert.True(DiskStream.Looks(disk));
        Assert.False(DiskStream.Looks(disk.AsSpan(0, Containers.HeadBytes)));
        disk[^512] ^= 1;
        Assert.False(DiskStream.Looks(disk));
    }

    [Fact]
    public void A_version_2_supplementary_volume_descriptor_is_taken_as_iso_9660()
    {
        var image = DiskImageTests.Fixture("joliet.iso");
        int at = 16 * 2048;
        image[at] = 2;
        image[at + 6] = 2;
        Assert.True(Iso9660Reader.Looks(image));
        image[at] = 1;
        Assert.False(Iso9660Reader.Looks(image));
    }
}
