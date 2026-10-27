using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Firmware;
using Corvus.Services.Analysis;
using static Corvus.Tests.FirmwareFilesystemTests;

namespace Corvus.Tests;

/// <summary>Boot and whole firmware images: parts carved at their offsets and opened by their readers, streamed or in memory.</summary>
public sealed class FirmwareImageTests
{
    private static uint Crc32(ReadOnlySpan<byte> b) => ~Crc.Raw(0xFFFFFFFF, b);

    private static byte[] Gzip(byte[] data)
    {
        var o = new MemoryStream();
        using (var z = new GZipStream(o, CompressionLevel.Optimal, leaveOpen: true)) z.Write(data);
        return o.ToArray();
    }

    /// <summary>A legacy uImage: header with both CRCs, then the payload (type 2 kernel; 4 multi-file with a size list).</summary>
    internal static byte[] UImage(byte[] payload, byte type = 2, byte arch = 5, byte comp = 1, string title = "MIPS OpenWrt Linux-6.6")
    {
        var h = new byte[64];
        BinaryPrimitives.WriteUInt32BigEndian(h, 0x27051956);
        BinaryPrimitives.WriteUInt32BigEndian(h.AsSpan(8), 1_700_000_000);
        BinaryPrimitives.WriteUInt32BigEndian(h.AsSpan(12), (uint)payload.Length);
        BinaryPrimitives.WriteUInt32BigEndian(h.AsSpan(16), 0x80060000);
        BinaryPrimitives.WriteUInt32BigEndian(h.AsSpan(20), 0x80060000);
        BinaryPrimitives.WriteUInt32BigEndian(h.AsSpan(24), Crc32(payload));
        h[28] = 5; h[29] = arch; h[30] = type; h[31] = comp;
        Encoding.ASCII.GetBytes(title).CopyTo(h, 32);
        BinaryPrimitives.WriteUInt32BigEndian(h.AsSpan(4), Crc32(h));
        return [.. h, .. payload];
    }

    [Fact]
    public void UImage_kernel_is_decoded_and_named_with_its_architecture()
    {
        var kernel = Isa("mips32be.elf");
        var c = Containers.Open(UImage(Gzip(kernel)), "kernel.uimage", AnalysisLimits.Default, default);
        Assert.Equal("uImage", c.Kind);
        var item = Assert.Single(c.Items);
        Assert.Equal("kernel", item.Name);
        Assert.Equal(kernel, item.Bytes);
        Assert.Contains("arch mips", item.Origin);
        // Headerless code gets the call that maps it.
        var raw = Containers.Open(UImage(Gzip(new byte[4096]), arch: 22), "raw.uimage", AnalysisLimits.Default, default);
        Assert.Contains(raw.Notes, n => n.Contains("load_assembly format=raw arch=arm64 base=0x80060000 entry=0x80060000", StringComparison.Ordinal));
    }

    [Fact]
    public void UImage_multi_file_lists_each_part()
    {
        var a = Isa("mips32be.elf");
        var b = Isa("armbe.elf");
        var payload = new MemoryStream();
        foreach (var n in new[] { a.Length, b.Length, 0 }) payload.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(n)));
        payload.Write(a);
        while (payload.Length % 4 != 0) payload.WriteByte(0);
        payload.Write(b);
        var c = Containers.Open(UImage(payload.ToArray(), type: 4, comp: 0), "multi.uimage", AnalysisLimits.Default, default);
        Assert.Equal([a, b], c.Items.Select(i => i.Bytes));
    }

    /// <summary>A FIT: /images with a gzip kernel inline and a device tree as external data after the tree.</summary>
    internal static byte[] Fit(byte[] kernel, byte[] external)
    {
        var strings = new MemoryStream();
        var offsets = new Dictionary<string, int>();
        int Str(string s)
        {
            if (offsets.TryGetValue(s, out int o)) return o;
            offsets[s] = (int)strings.Length;
            strings.Write(Encoding.ASCII.GetBytes(s + "\0"));
            return offsets[s];
        }
        var st = new MemoryStream();
        void U32(uint v) { var b = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, v); st.Write(b); }
        void Pad() { while (st.Length % 4 != 0) st.WriteByte(0); }
        void Begin(string name) { U32(1); st.Write(Encoding.ASCII.GetBytes(name + "\0")); Pad(); }
        void Prop(string name, byte[] value) { U32(3); U32((uint)value.Length); U32((uint)Str(name)); st.Write(value); Pad(); }
        void Text(string name, string value) => Prop(name, Encoding.ASCII.GetBytes(value + "\0"));
        void Num(string name, uint value) { var b = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, value); Prop(name, b); }
        Begin("");
        Text("description", "test FIT");
        Begin("images");
        Begin("kernel-1");
        Text("type", "kernel"); Text("arch", "mips"); Text("compression", "gzip");
        Num("load", 0x80060000); Num("entry", 0x80060000);
        Prop("data", Gzip(kernel));
        U32(2);
        Begin("fdt-1");
        Text("type", "flat_dt"); Text("compression", "none");
        Num("data-offset", 0); Num("data-size", (uint)external.Length);
        U32(2);
        U32(2);
        U32(2);
        U32(9);
        int structAt = 40, stringsAt = structAt + (int)st.Length;
        int total = stringsAt + (int)strings.Length;
        var h = new byte[40];
        BinaryPrimitives.WriteUInt32BigEndian(h, 0xD00DFEED);
        BinaryPrimitives.WriteUInt32BigEndian(h.AsSpan(4), (uint)total);
        BinaryPrimitives.WriteUInt32BigEndian(h.AsSpan(8), (uint)structAt);
        BinaryPrimitives.WriteUInt32BigEndian(h.AsSpan(12), (uint)stringsAt);
        BinaryPrimitives.WriteUInt32BigEndian(h.AsSpan(16), 40);
        BinaryPrimitives.WriteUInt32BigEndian(h.AsSpan(20), 17);
        BinaryPrimitives.WriteUInt32BigEndian(h.AsSpan(24), 16);
        BinaryPrimitives.WriteUInt32BigEndian(h.AsSpan(32), (uint)strings.Length);
        BinaryPrimitives.WriteUInt32BigEndian(h.AsSpan(36), (uint)st.Length);
        var fit = new MemoryStream();
        fit.Write(h);
        fit.Write(st.ToArray());
        fit.Write(strings.ToArray());
        while (fit.Length % 4 != 0) fit.WriteByte(0);
        fit.Write(external);
        return fit.ToArray();
    }

    [Fact]
    public void Fit_images_inline_and_external_are_extracted()
    {
        var kernel = Isa("mips32be.elf");
        var dtb = Enumerable.Range(0, 300).Select(i => (byte)i).ToArray();
        var c = Containers.Open(Fit(kernel, dtb), "image.itb", AnalysisLimits.Default, default);
        Assert.Equal("FIT", c.Kind);
        Assert.Equal(kernel, c.Items.Single(i => i.Name == "kernel-1").Bytes);
        Assert.Contains("arch mips, load 0x80060000", c.Items.Single(i => i.Name == "kernel-1").Origin);
        Assert.Equal(dtb, c.Items.Single(i => i.Name == "fdt-1").Bytes);
    }

    /// <summary>An Android boot image (header v0, 2 KiB pages): a kernel and a gzip-compressed cpio ramdisk.</summary>
    internal static byte[] AndroidBoot(byte[] kernel, byte[] ramdisk)
    {
        const int Page = 2048;
        var h = new byte[Page];
        "ANDROID!"u8.CopyTo(h);
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(8), (uint)kernel.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(12), 0x10008000);
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(16), (uint)ramdisk.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(36), Page);
        Encoding.ASCII.GetBytes("test-board").CopyTo(h, 48);
        byte[] Padded(byte[] b) => [.. b, .. new byte[(Page - b.Length % Page) % Page]];
        return [.. h, .. Padded(kernel), .. Padded(ramdisk)];
    }

    [Fact]
    public void Android_boot_ramdisk_opens_down_to_its_files()
    {
        var kernel = Isa("armbe.elf");
        var image = AndroidBoot(kernel, Gzip(FsFixture("cpio-newc.cpio")));
        var c = Containers.Open(image, "boot.img", AnalysisLimits.Default, default);
        Assert.Equal("Android boot image", c.Kind);
        Assert.Equal(kernel, c.Items.Single(i => i.Name == "kernel").Bytes);
        var ramdisk = Containers.Open(c.Items.Single(i => i.Name == "ramdisk").Bytes, "ramdisk", AnalysisLimits.Default, default, allFiles: true);
        AssertTree(ramdisk);
    }

    /// <summary>A TRX v1 image: header with its CRC, then a kernel and a filesystem partition.</summary>
    internal static byte[] Trx(byte[] kernel, byte[] rootfs)
    {
        int kernelAt = 28, rootAt = (28 + kernel.Length + 3) & ~3;
        var body = new byte[rootAt + rootfs.Length];
        kernel.CopyTo(body, kernelAt);
        rootfs.CopyTo(body, rootAt);
        "HDR0"u8.CopyTo(body);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(4), (uint)body.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(12), 1 << 16);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(16), (uint)kernelAt);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(20), (uint)rootAt);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(8), Crc32(body.AsSpan(12)));
        return body;
    }

    [Fact]
    public void Trx_partitions_open_as_their_formats()
    {
        var rootfs = FsFixture("squashfs-xz.img");
        var c = Containers.Open(Trx(UImage(Gzip(Isa("mips32be.elf"))), rootfs), "fw.trx", AnalysisLimits.Default, default);
        Assert.Equal("TRX", c.Kind);
        Assert.Equal(rootfs, c.Items[1].Bytes);
        Assert.Equal("uImage", Containers.Open(c.Items[0].Bytes, "partition_0", AnalysisLimits.Default, default).Kind);
    }

    /// <summary>
    /// A NOR flash dump as an OpenWrt router ships it: boot loader bytes, a uImage kernel at 64 KiB, the squashfs root at
    /// 192 KiB, then a JFFS2 overlay after erased flash.
    /// </summary>
    internal static byte[] FlashDump()
    {
        var image = new byte[2 << 20];
        image.AsSpan().Fill(0xFF);
        new Random(5).NextBytes(image.AsSpan(0, 0x8000));
        UImage(Gzip(Isa("mips32be.elf"))).CopyTo(image, 0x10000);
        FsFixture("squashfs-gzip.img").CopyTo(image, 0x30000);
        FirmwareFlashTests.Jffs2(big: true).CopyTo(image, 0x100000);
        return image;
    }

    /// <summary>The squashfs fixture's own size (bytes used), short of the 4 KiB padding after it.</summary>
    private static long SquashfsUsed() => BinaryPrimitives.ReadInt64LittleEndian(FsFixture("squashfs-gzip.img").AsSpan(40));

    [Fact]
    public void Flash_dump_is_carved_and_each_part_opened()
    {
        var dump = FlashDump();
        var c = Containers.Open(dump, "flash.bin", AnalysisLimits.Default, default);
        Assert.Equal("firmware image", c.Kind);
        Assert.Contains(c.Items, i => i.Name == "0x10000.uimage");
        var squash = c.Items.Single(i => i.Name == "0x30000.squashfs");
        Assert.Equal(SquashfsUsed(), squash.Bytes.Length);
        AssertTree(Containers.Open(squash.Bytes, squash.Name, AnalysisLimits.Default, default, allFiles: true));
        var overlay = c.Items.Single(i => i.Name == "0x100000.jffs2");
        AssertTree(Containers.Open(overlay.Bytes, overlay.Name, AnalysisLimits.Default, default, allFiles: true), "version.txt 3");
        // Read as a stream, the same parts.
        var streamed = Containers.OpenStream(() => new MemoryStream(dump), dump.AsSpan(0, 4096), "flash.bin", AnalysisLimits.Default, default)!;
        Assert.Equal(c.Items.Select(i => (i.Name, Blob.Sha256(i.Bytes))), streamed.Items.Select(i => (i.Name, Blob.Sha256(i.Bytes))));
    }

    [Fact]
    public void Unpack_writes_the_programs_inside_the_firmware()
    {
        using var dir = new TempDir();
        using var workspace = new AssemblyWorkspace(new ServerOptions());
        var path = dir.File("flash.bin");
        File.WriteAllBytes(path, FlashDump());
        var report = new UnpackService(workspace).Unpack(path, dir.File("out"), load: false, AnalysisLimits.Default, default);
        Assert.Equal("firmware image", report.Container);
        // The root filesystem's programs, ELF files a native load reads at their own architecture.
        var busybox = report.Files.Where(f => f.Path.Replace('\\', '/').EndsWith("_unpacked/bin/busybox", StringComparison.Ordinal)).ToList();
        Assert.NotEmpty(busybox);
        Assert.All(busybox, f => Assert.Equal("elf", f.Kind));
        Assert.Equal(Isa("mips32be.elf"), File.ReadAllBytes(busybox[0].Path));
        var native = workspace.LoadAny(busybox[0].Path).Native!;
        Assert.Equal(Corvus.Native.NativeArch.Mips, native.Image.Arch);
    }

    [Fact]
    public void A_vendor_header_is_scanned_past_to_the_parts_after_it()
    {
        var header = new byte[0x200];
        new Random(7).NextBytes(header);
        // A header, then a uImage kernel and a squashfs root.
        var kernel = UImage(Gzip(Isa("mips32be.elf")));
        var bare = Containers.Open([.. header, .. kernel, .. FsFixture("squashfs-gzip.img")], "vendor.img", AnalysisLimits.Default, default);
        Assert.Equal("firmware image", bare.Kind);
        Assert.Contains(bare.Items, i => i.Name == "0x200.uimage");
        Assert.Contains(bare.Items, i => i.Name == $"0x{0x200 + kernel.Length:X}.squashfs");
        // A header, then a zip holding the flash image: unpacked down to the root filesystem's programs.
        using var dir = new TempDir();
        using var workspace = new AssemblyWorkspace(new ServerOptions());
        var path = dir.File("factory.img");
        File.WriteAllBytes(path, [.. header, .. ContainerFixtures.Zip(("flash.bin", FlashDump()))]);
        var report = new UnpackService(workspace).Unpack(path, dir.File("out"), load: false, AnalysisLimits.Default, default);
        Assert.Equal("firmware image", report.Container);
        // The zip is read at the top level, keeping nesting levels for the filesystems inside.
        Assert.Contains(report.Files, f => Path.GetRelativePath(report.OutputDirectory, f.Path).Replace('\\', '/') == "flash.bin_unpacked/0x30000.squashfs_unpacked/bin/busybox");
    }

    [Fact]
    public void A_sercomm_header_is_sized_and_named_before_the_zip_it_wraps()
    {
        var header = new byte[0x200];
        "sErCoMm\0"u8.CopyTo(header);
        "sErCoMm"u8.CopyTo(header.AsSpan(63));
        byte[] image = [.. header, .. ContainerFixtures.Zip(("flash.bin", FlashDump()))];
        var c = Containers.Open(image, "factory.img", AnalysisLimits.Default, default);
        Assert.StartsWith("firmware image: a 512-byte Sercomm firmware header, then a ", c.Notes[0]);
        var facts = (FirmwareFileView.Facts)new FirmwareFileView().Inspect(new FileInput("factory.img", image, Blob.Identify(image)), default)!.Detail!;
        Assert.Contains(facts.Signatures, h => h.Offset == "0x0" && h.Format == "Sercomm firmware header" && h.Size == 512);
    }

    [Fact]
    public void Firmware_view_lists_each_part_with_its_size()
    {
        var dump = FlashDump();
        var facts = (FirmwareFileView.Facts)new FirmwareFileView().Inspect(new FileInput("flash.bin", dump, Blob.Identify(dump)), default)!.Detail!;
        var hits = facts.Signatures.Select(h => $"{h.Offset} {h.Format} {h.Size}").ToList();
        Assert.Contains($"0x10000 U-Boot uImage {UImage(Gzip(Isa("mips32be.elf"))).Length}", hits);
        Assert.Contains($"0x30000 squashfs (little endian) {SquashfsUsed()}", hits);
        Assert.Contains(hits, h => h.StartsWith("0x100000 JFFS2 filesystem (big endian) ", StringComparison.Ordinal));
        // Nothing is reported inside the squashfs it sized.
        Assert.DoesNotContain(facts.Signatures, h => Convert.ToInt64(h.Offset, 16) is > 0x30000 and < 0x30000 + 4096);
    }

    [Fact]
    public void A_filesystem_no_reader_opens_is_carved_with_a_note()
    {
        var dump = new byte[0x20000];
        dump.AsSpan().Fill(0xFF);
        // A squashfs 3.0 superblock: its 64-bit size at offset 63.
        var sb = dump.AsSpan(0x1000);
        "hsqs"u8.CopyTo(sb);
        BinaryPrimitives.WriteUInt32LittleEndian(sb[28..], 3);
        BinaryPrimitives.WriteInt64LittleEndian(sb[63..], 0x2000);
        var c = Containers.Open(dump, "old.bin", AnalysisLimits.Default, default);
        Assert.Equal(0x2000, c.Items.Single(i => i.Name == "0x1000.squashfs").Bytes.Length);
        Assert.True(c.Notes.Any(n => n.StartsWith("0x1000.squashfs: squashfs (little endian) (version 3.0) is carved out, but no in-process reader opens it", StringComparison.Ordinal)), string.Join(" | ", c.Notes));
    }

    [Fact]
    public void At_least_100_formats_are_checked()
    {
        Assert.True(FirmwareSignatures.Count >= 100, $"{FirmwareSignatures.Count} signatures");
        Assert.Equal(FirmwareSignatures.All.Count, FirmwareSignatures.All.Select(s => s.Format).Distinct().Count());
    }

    [Fact]
    public void An_archive_with_no_files_never_reads_as_complete()
    {
        var empty = Encoding.ASCII.GetBytes($"070701{0:X8}{0:X8}{0:X8}{0:X8}{1:X8}{0:X8}{0:X8}{0:X8}{0:X8}{0:X8}{0:X8}{11:X8}{0:X8}TRAILER!!!\0");
        var c = Containers.Open(empty, "empty.cpio", AnalysisLimits.Default, default);
        Assert.Empty(c.Entries!);
        Assert.Contains(c.Notes, n => n.Contains("no files were recovered", StringComparison.Ordinal) && n.Contains("nothing extracted", StringComparison.Ordinal));
    }

    [Fact]
    [FuzzEntry(typeof(UImageReader), typeof(FitReader), typeof(AndroidBootReader), typeof(TrxReader), typeof(FirmwareCarve), typeof(FirmwareSignatures), typeof(BootParts))]
    public void Fuzzed_boot_and_firmware_images_never_throw_unexpectedly()
    {
        var seeds = new[]
        {
            ("k.uimage", UImage(Gzip(Isa("mips32be.elf")))), ("i.itb", Fit(Isa("armbe.elf"), new byte[64])), ("boot.img", AndroidBoot(Isa("armbe.elf"), Gzip(FsFixture("cpio-newc.cpio")))),
            ("fw.trx", Trx(new byte[100], FsFixture("squashfs-lzo.img"))), ("flash.bin", FlashDump()[..0x50000]),
        };
        foreach (var (name, seed) in seeds)
        {
            var failures = FormatFuzz.Run(seed, b =>
            {
                try { Containers.Open(b, name, AnalysisLimits.Default, default); } catch (ToolError) { }
                FirmwareSignatures.Scan(b, 500, default);
            }, 300);
            Assert.True(failures.Count == 0, name + ": " + string.Join("\n", failures.Take(20)));
        }
    }
}
