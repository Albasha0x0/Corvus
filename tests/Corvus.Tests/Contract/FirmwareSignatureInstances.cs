using System.Buffers.Binary;
using System.IO.Hashing;
using System.Text;
using Corvus.Core.Firmware;

namespace Corvus.Tests;

/// <summary>Minimal valid firmware instances and the single-byte changes that must stop each.</summary>
internal static class FirmwareSignatureInstances
{
    private sealed class Image(int length)
    {
        public readonly byte[] D = new byte[length];

        public Image Text(int at, string s) { Encoding.Latin1.GetBytes(s).CopyTo(D, at); return this; }
        public Image Bytes(int at, params byte[] b) { b.CopyTo(D, at); return this; }
        public Image U8(int at, int v) { D[at] = (byte)v; return this; }
        public Image Le16(int at, uint v) { BinaryPrimitives.WriteUInt16LittleEndian(D.AsSpan(at), (ushort)v); return this; }
        public Image Be16(int at, uint v) { BinaryPrimitives.WriteUInt16BigEndian(D.AsSpan(at), (ushort)v); return this; }
        public Image Le32(int at, uint v) { BinaryPrimitives.WriteUInt32LittleEndian(D.AsSpan(at), v); return this; }
        public Image Be32(int at, uint v) { BinaryPrimitives.WriteUInt32BigEndian(D.AsSpan(at), v); return this; }
        public Image Le64(int at, ulong v) { BinaryPrimitives.WriteUInt64LittleEndian(D.AsSpan(at), v); return this; }
        public Image Be64(int at, ulong v) { BinaryPrimitives.WriteUInt64BigEndian(D.AsSpan(at), v); return this; }

        public static implicit operator byte[](Image i) => i.D;
    }

    private static uint Crc32(ReadOnlySpan<byte> b) => ~Crc.Raw(0xFFFFFFFF, b);

    private static readonly (string Magic, bool Big)[] SquashfsMagics = [("shsq", false), ("qshs", true), ("tqsh", false), ("hsqt", true)];

    private static byte[] Squashfs(string magic, bool big)
    {
        var i = new Image(96).Text(0, magic);
        return big ? i.Be32(12, 131072).Be16(20, 1).Be16(28, 4).Be64(40, 96) : i.Le32(12, 131072).Le16(20, 1).Le16(28, 4).Le64(40, 96);
    }

    private static (int At, int Value)[] SquashfsChanges(bool big) => big ? [(13, 3), (21, 0), (29, 5), (47, 0)] : [(14, 3), (20, 0), (28, 5), (40, 0)];

    private static byte[] Jffs2(bool big)
    {
        var i = new Image(12);
        if (big) i.Be16(0, 0x1985).Be16(2, 0xE001).Be32(4, 12).Be32(8, Crc.Jffs2(i.D.AsSpan(0, 8)));
        else i.Le16(0, 0x1985).Le16(2, 0xE001).Le32(4, 12).Le32(8, Crc.Jffs2(i.D.AsSpan(0, 8)));
        return i;
    }

    private static byte[] Ubi()
    {
        var i = new Image(64).Text(0, "UBI#").U8(4, 1);
        return i.Be32(60, Crc.Ubi(i.D.AsSpan(0, 60)));
    }

    private static byte[] Ubifs()
    {
        var i = new Image(4096).Bytes(0, 0x31, 0x18, 0x10, 0x06).Le32(16, 4096).U8(20, 6).Le32(36, 4096).Le32(40, 1);
        return i.Le32(4, Crc.Ubi(i.D.AsSpan(8)));
    }

    private static byte[] Newc(string magic)
    {
        var s = new StringBuilder(magic);
        for (int field = 0; field < 13; field++) s.Append(field == 11 ? "0000000B" : "00000000");
        s.Append("TRAILER!!!\0\0\0\0");
        return Encoding.ASCII.GetBytes(s.ToString());
    }

    private static byte[] Odc() => Encoding.ASCII.GetBytes("070707" + new string('0', 53) + "000013" + new string('0', 11) + "TRAILER!!!\0");

    private static byte[] Tar()
    {
        var i = new Image(1536).Text(0, "a").Text(100, "0000644\0").Text(124, "00000000000\0").Text(136, "00000000000\0").U8(156, '0').Text(257, "ustar\0").Text(263, "00");
        long sum = 0;
        for (int at = 0; at < 512; at++) sum += at is >= 148 and < 156 ? 32 : i.D[at];
        return i.Text(148, Convert.ToString(sum, 8).PadLeft(6, '0') + "\0 ");
    }

    private static byte[] Zip() => new Image(53).Bytes(0, (byte)'P', (byte)'K', 3, 4).Le16(4, 20).Le16(26, 1).Text(30, "a").Bytes(31, (byte)'P', (byte)'K', 5, 6);

    private static byte[] Rar4()
    {
        var i = new Image(20).Text(0, "Rar!\u001A\u0007\0").U8(9, 0x73).Le16(12, 13);
        return i.Le16(7, (ushort)Crc32(i.D.AsSpan(9)));
    }

    private static byte[] Ar() => new Image(68).Text(0, "!<arch>\n").Text(8, "a/").Text(56, "0").Text(66, "`\n");

    private static byte[] Sparse() =>
        new Image(40).Bytes(0, 0x3A, 0xFF, 0x26, 0xED).Le16(4, 1).Le16(8, 28).Le16(10, 12).Le32(12, 4096).Le32(16, 1).Le32(20, 1).Le16(28, 0xCAC1).Le32(36, 12);

    private static byte[] Lz4()
    {
        byte[] descriptor = [0x40, 0x40];
        return new Image(11).Bytes(0, 0x04, 0x22, 0x4D, 0x18).Bytes(4, descriptor).U8(6, (byte)(XxHash32.HashToUInt32(descriptor) >> 8));
    }

    private static byte[] Trx()
    {
        var i = new Image(28).Text(0, "HDR0").Le32(4, 28).Le16(14, 1);
        return i.Le32(8, Crc32(i.D.AsSpan(12)));
    }

    /// <summary>A minimal instance by registered signature name.</summary>
    internal static Dictionary<string, Func<byte[]>> All()
    {
        var all = new Dictionary<string, Func<byte[]>>
        {
            ["squashfs (little endian)"] = () => Squashfs("hsqs", false),
            ["squashfs (big endian)"] = () => Squashfs("sqsh", true),
            ["cramfs (little endian)"] = () => new Image(96).Bytes(0, 0x45, 0x3D, 0xCD, 0x28).Le32(4, 96).Text(16, "Compressed ROMFS"),
            ["cramfs (big endian)"] = () => new Image(96).Bytes(0, 0x28, 0xCD, 0x3D, 0x45).Be32(4, 96).Text(16, "Compressed ROMFS"),
            ["ext2/3/4 filesystem"] = () => new Image(2048).Le32(1024, 16).Le32(1028, 2).Le32(1048, 0).Le32(1056, 8192).Le32(1064, 16).Bytes(1080, 0x53, 0xEF).Le16(1082, 1),
            ["FAT12/FAT16 boot sector"] = () => new Image(512).U8(0, 0xEB).Le16(11, 512).U8(13, 1).Le16(14, 1).U8(16, 2).Le16(19, 1).Text(54, "FAT12   ").Bytes(510, 0x55, 0xAA),
            ["FAT32 boot sector"] = () => new Image(512).U8(0, 0xEB).Le16(11, 512).U8(13, 1).Le16(14, 1).U8(16, 2).Le32(32, 1).Text(82, "FAT32   ").Bytes(510, 0x55, 0xAA),
            ["exFAT boot sector"] = () => new Image(512).Text(3, "EXFAT   ").Le64(72, 1).U8(108, 9).Bytes(510, 0x55, 0xAA),
            ["NTFS boot sector"] = () => new Image(512).Text(3, "NTFS    ").Le16(11, 512).Le64(40, 1).Bytes(510, 0x55, 0xAA),
            ["JFFS2 filesystem (little endian)"] = () => Jffs2(false),
            ["JFFS2 filesystem (big endian)"] = () => Jffs2(true),
            ["UBI image"] = Ubi,
            ["UBIFS superblock"] = Ubifs,
            ["romfs filesystem"] = () => new Image(48).Text(0, "-rom1fs-").Be32(8, 48).Text(16, "vol"),
            ["ISO 9660 filesystem"] = () => new Image(0x8100).U8(0x8000, 1).Text(0x8001, "CD001").U8(0x8006, 1).Le32(0x8050, 1).Le16(0x8080, 2048),
            ["Btrfs filesystem"] = () => new Image(0x10100).Le64(0x10030, 0x10000).Text(0x10040, "_BHRfS_M").Le64(0x10070, 0x10100).Le32(0x10090, 4096).Le32(0x10094, 16384),
            ["XFS filesystem"] = () => new Image(512).Text(0, "XFSB").Be32(4, 512).Be64(8, 1),
            ["F2FS filesystem"] = () => new Image(0x500).Bytes(0x400, 0x10, 0x20, 0xF5, 0xF2).Le16(0x404, 1).Le32(0x40C, 9).Le64(0x448, 1),
            ["EROFS filesystem"] = () => new Image(0x500).Bytes(0x400, 0xE2, 0xE1, 0xF5, 0xE0).U8(0x40C, 9).Le32(0x424, 1),
            ["HFS+ volume"] = () => new Image(0x500).Bytes(0x400, (byte)'H', (byte)'+', 0, 4).Be32(0x428, 512).Be32(0x42C, 1),
            ["HFSX volume"] = () => new Image(0x500).Bytes(0x400, (byte)'H', (byte)'X', 0, 5).Be32(0x428, 512).Be32(0x42C, 1),
            ["APFS container"] = () => new Image(4096).Text(32, "NXSB").Le32(36, 4096).Le64(40, 1),
            ["LUKS encrypted volume"] = () => new Image(8).Bytes(0, (byte)'L', (byte)'U', (byte)'K', (byte)'S', 0xBA, 0xBE).Be16(6, 1),
            ["LVM2 physical volume"] = () => new Image(32).Text(0, "LABELONE").Text(24, "LVM2 001"),
            ["GPT partition table"] = () => new Image(92).Text(0, "EFI PART").Le32(8, 0x10000).Le32(12, 92),
            ["cpio archive (newc)"] = () => Newc("070701"),
            ["cpio archive (newc with CRC)"] = () => Newc("070702"),
            ["cpio archive (odc)"] = Odc,
            ["POSIX tar archive"] = Tar,
            ["zip archive"] = Zip,
            ["RAR archive (v4)"] = Rar4,
            ["7-Zip archive"] = () => new Image(32).Bytes(0, 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C).U8(7, 4),
            ["Microsoft cabinet"] = () => new Image(36).Text(0, "MSCF").Le32(8, 36).U8(24, 3).U8(25, 1),
            ["ar archive"] = Ar,
            ["WebPlayerData table"] = () => new Image(20).Text(0, "UnityWebData1.0\0").Le32(16, 20),
            ["RPM package"] = () => new Image(96).Bytes(0, 0xED, 0xAB, 0xEE, 0xDB).U8(4, 3).Text(10, "pkg-1.0"),
            ["xar archive"] = () => new Image(28).Text(0, "xar!").Be16(4, 28).Be16(6, 1),
            ["ARJ archive"] = () => new Image(32).Bytes(0, 0x60, 0xEA).Le16(2, 30).U8(4, 30).U8(10, 2),
            ["Windows imaging (WIM)"] = () => new Image(12).Text(0, "MSWIM\0\0\0").Le32(8, 208),
            ["Compound file (OLE)"] = () => new Image(32).Bytes(0, 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1).Le16(28, 0xFFFE).Le16(30, 9),
            ["Compiled HTML help (CHM)"] = () => new Image(12).Text(0, "ITSF").Le32(4, 3).Le32(8, 0x60),
            ["Android sparse image"] = Sparse,
            ["Android backup"] = () => Encoding.ASCII.GetBytes("ANDROID BACKUP\n5\n"),
            ["LZ4 compressed data"] = Lz4,
            ["LZ4 legacy compressed data"] = () => new Image(12).Bytes(0, 0x02, 0x21, 0x4C, 0x18).Le32(4, 16),
            ["lzop compressed data"] = () => new Image(32).Bytes(0, 0x89, 0x4C, 0x5A, 0x4F, 0x00, 0x0D, 0x0A, 0x1A, 0x0A).Be16(9, 0x1030).U8(15, 1),
            ["lzip compressed data"] = () => new Image(8).Text(0, "LZIP").U8(4, 1).U8(5, 16),
            ["flattened device tree"] = () => new Image(40).Bytes(0, 0xD0, 0x0D, 0xFE, 0xED).Be32(4, 40).Be32(8, 36).Be32(20, 17),
            ["TRX firmware header"] = Trx,
            ["Android boot image"] = () => new Image(2048).Text(0, "ANDROID!").Le32(36, 2048),
            ["Android vendor boot image"] = () => new Image(16).Text(0, "VNDRBOOT").Le32(8, 3).Le32(12, 4096),
            ["Android DTB/DTBO table"] = () => new Image(32).Bytes(0, 0xD7, 0xB7, 0xAB, 0x1E).Be32(4, 32).Be32(8, 32).Be32(12, 32),
            ["Android verified boot (vbmeta)"] = () => new Image(256).Text(0, "AVB0").Be32(4, 1),
            ["Seama firmware header"] = () => new Image(28).Bytes(0, 0x5E, 0xA3, 0xA4, 0x17),
            ["Sercomm firmware header"] = () => new Image(512).Text(0, "sErCoMm\0").Text(63, "sErCoMm"),
            ["Netgear CHK header"] = () => new Image(40).Text(0, "*#$^").Be32(4, 40),
            ["TP-Link firmware header"] = () => new Image(28).Be32(0, 2).Text(4, "TP-LINK Technologies"),
            ["Linux kernel (x86 bzImage)"] = () => new Image(1024).U8(0x1F1, 1).Bytes(0x1FE, 0x55, 0xAA).Text(0x202, "HdrS").Le16(0x206, 0x20F),
            ["Linux kernel (ARM zImage)"] = () => new Image(48).Bytes(0x24, 0x18, 0x28, 0x6F, 0x01).Le32(0x2C, 48),
        };
        foreach (var (magic, big) in SquashfsMagics) all[$"squashfs (non-standard magic {magic})"] = () => Squashfs(magic, big);
        return all;
    }

    /// <summary>Single-byte changes as (offset, value); a negative value inverts the byte.</summary>
    internal static Dictionary<string, (int At, int Value)[]> Changes()
    {
        var all = new Dictionary<string, (int At, int Value)[]>
        {
            ["squashfs (little endian)"] = SquashfsChanges(false),
            ["squashfs (big endian)"] = SquashfsChanges(true),
            ["cramfs (little endian)"] = [(16, 'X'), (4, 0)],
            ["cramfs (big endian)"] = [(16, 'X'), (7, 0)],
            ["ext2/3/4 filesystem"] = [(1048, 7), (1082, 0), (1064, 0), (1057, 0), (1100, 2), (1028, 0), (1024, 0)],
            ["FAT12/FAT16 boot sector"] = [(0, 0x90), (16, 3), (13, 3), (510, 0), (12, 3), (19, 0), (58, 'X')],
            ["FAT32 boot sector"] = [(0, 0x90), (16, 3), (13, 3), (510, 0), (12, 3), (32, 0)],
            ["exFAT boot sector"] = [(510, 0), (511, 0), (108, 8), (72, 0)],
            ["NTFS boot sector"] = [(510, 0), (12, 3), (40, 0)],
            ["JFFS2 filesystem (little endian)"] = [(2, 0), (4, 11), (8, -1)],
            ["JFFS2 filesystem (big endian)"] = [(3, 0), (7, 11), (8, -1)],
            ["UBI image"] = [(4, 0), (5, 1), (60, -1)],
            ["UBIFS superblock"] = [(20, 5), (17, 0), (4, -1)],
            ["romfs filesystem"] = [(11, 0), (16, 0)],
            ["ISO 9660 filesystem"] = [(0x8000, 2), (0x8006, 2), (0x8081, 7), (0x8050, 0)],
            ["Btrfs filesystem"] = [(0x10072, 0xFF), (0x10032, 2), (0x10091, 0x11), (0x10095, 0x41)],
            ["XFS filesystem"] = [(6, 3), (15, 0)],
            ["F2FS filesystem"] = [(0x404, 2), (0x40C, 8), (0x448, 0)],
            ["EROFS filesystem"] = [(0x40C, 8), (0x424, 0)],
            ["HFS+ volume"] = [(0x42A, 0), (0x42F, 0)],
            ["HFSX volume"] = [(0x42A, 0), (0x42F, 0)],
            ["APFS container"] = [(37, 0), (40, 0)],
            ["LUKS encrypted volume"] = [(7, 3)],
            ["LVM2 physical volume"] = [(24, 'X')],
            ["GPT partition table"] = [(10, 2), (12, 91)],
            // The entry name is not a header field: a header whose next entry is past the bytes in hand is reported.
            ["cpio archive (newc)"] = [(6, 'G'), (94, 'G')],
            ["cpio archive (newc with CRC)"] = [(6, 'G'), (94, 'G')],
            ["cpio archive (odc)"] = [(6, '8'), (59, '8')],
            ["POSIX tar archive"] = [(148, -1), (0, 1), (1, 'b')],
            ["zip archive"] = [(4, 64), (8, 5), (26, 0)],
            ["RAR archive (v4)"] = [(9, 0x74), (7, -1), (12, 12)],
            ["7-Zip archive"] = [(6, 1), (7, 5)],
            ["Microsoft cabinet"] = [(4, 1), (24, 2), (25, 2), (8, 0)],
            ["ar archive"] = [(66, 'x'), (56, 'x')],
            ["WebPlayerData table"] = [(16, 19)],
            ["RPM package"] = [(4, 5), (6, 2), (10, 0)],
            ["xar archive"] = [(5, 27), (7, 2)],
            ["ARJ archive"] = [(2, 0), (4, 29), (10, 3)],
            ["Windows imaging (WIM)"] = [(8, 207)],
            ["Compound file (OLE)"] = [(28, 0), (30, 10)],
            ["Compiled HTML help (CHM)"] = [(4, 2), (8, 0x5F)],
            ["Android sparse image"] = [(4, 2), (8, 29), (10, 13), (13, 0)],
            ["Android backup"] = [(15, '0')],
            ["LZ4 compressed data"] = [(4, 0), (5, 0), (6, -1)],
            ["LZ4 legacy compressed data"] = [(4, 0), (7, 0xFF)],
            ["lzop compressed data"] = [(9, 0x08), (15, 0)],
            ["lzip compressed data"] = [(4, 2), (5, 5)],
            ["flattened device tree"] = [(7, 39), (23, 0), (11, 0xFF)],
            ["TRX firmware header"] = [(14, 3), (4, 27), (8, -1)],
            ["Android boot image"] = [(40, 9), (37, 3)],
            ["Android vendor boot image"] = [(8, 5), (13, 0x11)],
            ["Android DTB/DTBO table"] = [(11, 31), (15, 31), (7, 0)],
            ["Android verified boot (vbmeta)"] = [(7, 2), (19, 0xFF)],
            ["Seama firmware header"] = [(4, 1), (6, 4)],
            ["Sercomm firmware header"] = [(63, 'x')],
            ["Netgear CHK header"] = [(7, 39), (6, 5)],
            ["TP-Link firmware header"] = [(3, 0), (3, 4)],
            ["Linux kernel (x86 bzImage)"] = [(0x1FE, 0), (0x1FF, 0), (0x207, 1), (0x1F1, 9)],
            ["Linux kernel (ARM zImage)"] = [(0x2C, 0), (0x28, 3)],
        };
        foreach (var (magic, big) in SquashfsMagics) all[$"squashfs (non-standard magic {magic})"] = SquashfsChanges(big);
        return all;
    }
}
