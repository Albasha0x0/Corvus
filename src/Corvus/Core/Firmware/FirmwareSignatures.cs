using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Firmware;

/// <summary>What a signature found: filesystems, boot images and archives are regions an unpack carves out.</summary>
internal enum SignatureKind { Filesystem, Boot, Archive, Compressed, Executable, Key, Media, Document, Other }

/// <summary>One format at an offset: its size when the header declares or implies one.</summary>
internal sealed record SignatureHit(long Offset, string Format, SignatureKind Kind, long? Size, string? Detail);

/// <summary>
/// Header-validated signatures of the formats firmware images hold: each format's magic, checked against its own header
/// fields (versions, sizes, CRCs, counts) before it counts, and sized from them where the header allows.
/// </summary>
internal static class FirmwareSignatures
{
    /// <summary>The bytes a check reads: a window of the file from <see cref="Origin"/>, and further ranges on request.</summary>
    internal sealed class Window(byte[] d, int n, long origin, long length, Func<long, int, byte[]>? readAt)
    {
        public readonly byte[] D = d;
        public readonly int N = n;
        public readonly long Origin = origin, Length = length;

        public bool Has(int at, int count) => at >= 0 && count >= 0 && at <= N - count;
        public int U8(int at) => Has(at, 1) ? D[at] : -1;
        public uint Be16(int at) => Has(at, 2) ? BinaryPrimitives.ReadUInt16BigEndian(D.AsSpan(at)) : 0u;
        public uint Le16(int at) => Has(at, 2) ? BinaryPrimitives.ReadUInt16LittleEndian(D.AsSpan(at)) : 0u;
        public uint Be32(int at) => Has(at, 4) ? BinaryPrimitives.ReadUInt32BigEndian(D.AsSpan(at)) : 0u;
        public uint Le32(int at) => Has(at, 4) ? BinaryPrimitives.ReadUInt32LittleEndian(D.AsSpan(at)) : 0u;
        public ulong Be64(int at) => Has(at, 8) ? BinaryPrimitives.ReadUInt64BigEndian(D.AsSpan(at)) : 0ul;
        public ulong Le64(int at) => Has(at, 8) ? BinaryPrimitives.ReadUInt64LittleEndian(D.AsSpan(at)) : 0ul;
        public bool Is(int at, ReadOnlySpan<byte> s) => Has(at, s.Length) && D.AsSpan(at, s.Length).SequenceEqual(s);
        public string Ascii(int at, int count) => Has(at, count) ? Encoding.ASCII.GetString(D, at, count).TrimEnd('\0', ' ') : "";

        /// <summary>Bytes from the file left after <paramref name="at"/> (in this window's coordinates).</summary>
        public long Left(int at) => Length - (Origin + at);

        /// <summary>A size that fits the file from <paramref name="at"/>.</summary>
        public bool Fits(int at, long size) => size > 0 && size <= Left(at);

        /// <summary><paramref name="count"/> bytes at window offset <paramref name="at"/>, read past the window when needed; null past the file.</summary>
        public byte[]? Read(long at, int count)
        {
            if (at < 0 || count < 0 || Origin + at + count > Length) return null;
            if (at + count <= N) return D.AsSpan((int)at, count).ToArray();
            return readAt?.Invoke(Origin + at, count);
        }

        public bool Printable(int at, int count)
        {
            if (!Has(at, count)) return false;
            foreach (byte b in D.AsSpan(at, count)) if (b is < 0x20 or > 0x7E) return false;
            return true;
        }
    }

    /// <summary>A format: its magic, found <see cref="MagicAt"/> bytes into its header, and the header check.</summary>
    internal sealed record Signature(string Format, SignatureKind Kind, byte[] Magic, int MagicAt, Func<Window, int, (long? Size, string? Detail)?> Check);

    private static Signature S(string format, SignatureKind kind, ReadOnlySpan<byte> magic, Func<Window, int, (long? Size, string? Detail)?> check, int magicAt = 0) =>
        new(format, kind, magic.ToArray(), magicAt, check);

    private static Signature S(string format, SignatureKind kind, string magic, Func<Window, int, (long? Size, string? Detail)?> check, int magicAt = 0) =>
        new(format, kind, Encoding.Latin1.GetBytes(magic), magicAt, check);

    private static (long? Size, string? Detail)? Sized(Window w, int at, long size, string? detail = null) => w.Fits(at, size) ? (size, detail) : null;
    private static (long? Size, string? Detail)? Found(string? detail = null) => (null, detail);

    public static readonly IReadOnlyList<Signature> All = Build();

    /// <summary>Formats a scan of firmware reports.</summary>
    public static int Count => All.Count;

    private static List<Signature> Build()
    {
        var list = new List<Signature>();
        const SignatureKind Fs = SignatureKind.Filesystem, Boot = SignatureKind.Boot, Arc = SignatureKind.Archive, Comp = SignatureKind.Compressed,
            Exe = SignatureKind.Executable, Key = SignatureKind.Key, Media = SignatureKind.Media, Doc = SignatureKind.Document, Other = SignatureKind.Other;

        // filesystems
        list.Add(S("squashfs (little endian)", Fs, "hsqs", Squashfs(false)));
        list.Add(S("squashfs (big endian)", Fs, "sqsh", Squashfs(true)));
        foreach (var (magic, big) in new[] { ("shsq", false), ("qshs", true), ("tqsh", false), ("hsqt", true) })
            list.Add(S($"squashfs (non-standard magic {magic})", Fs, magic, Squashfs(big)));
        list.Add(S("cramfs (little endian)", Fs, [0x45, 0x3D, 0xCD, 0x28], (w, at) => w.Is(at + 16, "Compressed ROMFS"u8) ? Sized(w, at, w.Le32(at + 4), $"{w.Le32(at + 40):N0} files") : null));
        list.Add(S("cramfs (big endian)", Fs, [0x28, 0xCD, 0x3D, 0x45], (w, at) => w.Is(at + 16, "Compressed ROMFS"u8) ? Sized(w, at, w.Be32(at + 4), $"{w.Be32(at + 40):N0} files") : null));
        list.Add(S("ext2/3/4 filesystem", Fs, [0x53, 0xEF], (w, at) =>
        {
            int sb = at + 1024;
            uint log = w.Le32(sb + 24), blocks = w.Le32(sb + 4), inodes = w.Le32(sb + 0), rev = w.Le32(sb + 76);
            if (log > 6 || blocks == 0 || inodes == 0 || rev > 1 || w.Le32(sb + 32) == 0 || w.Le32(sb + 40) == 0 || w.Le16(sb + 58) is 0 or > 4) return null;
            uint incompat = w.Le32(sb + 96);
            return Sized(w, at, (long)blocks << (10 + (int)log), $"{((incompat & 0x2C0) != 0 ? "ext4" : (w.Le32(sb + 92) & 4) != 0 ? "ext3" : "ext2")}, volume '{w.Ascii(sb + 120, 16)}'");
        }, 1024 + 56));
        list.Add(S("FAT12/FAT16 boot sector", Fs, "FAT1", (w, at) => w.Is(at + 54, "FAT12   "u8) || w.Is(at + 54, "FAT16   "u8) ? Fat(w, at, $"{w.Ascii(at + 54, 8)}, volume '{w.Ascii(at + 43, 11)}'") : null, 54));
        list.Add(S("FAT32 boot sector", Fs, "FAT32   ", (w, at) => Fat(w, at, $"volume '{w.Ascii(at + 71, 11)}'"), 82));
        list.Add(S("exFAT boot sector", Fs, "EXFAT   ", (w, at) => w.U8(at + 510) == 0x55 && w.U8(at + 511) == 0xAA && w.U8(at + 108) is >= 9 and <= 12
            ? Sized(w, at, (long)w.Le64(at + 72) << w.U8(at + 108)) : null, 3));
        list.Add(S("NTFS boot sector", Fs, "NTFS    ", (w, at) => w.U8(at + 510) == 0x55 && w.U8(at + 511) == 0xAA && w.Le16(at + 11) is 512 or 1024 or 2048 or 4096
            ? Sized(w, at, (long)w.Le64(at + 40) * w.Le16(at + 11)) : null, 3));
        list.Add(S("JFFS2 filesystem (little endian)", Fs, [0x85, 0x19], (w, at) => Jffs2(w, at, false)));
        list.Add(S("JFFS2 filesystem (big endian)", Fs, [0x19, 0x85], (w, at) => Jffs2(w, at, true)));
        list.Add(S("UBI image", Fs, "UBI#", Ubi));
        list.Add(S("UBIFS superblock", Fs, [0x31, 0x18, 0x10, 0x06], (w, at) =>
            w.U8(at + 20) == 6 && w.Le32(at + 16) == 4096 && w.Read(at + 8, 4088) is { } body && Crc.Ubi(body) == w.Le32(at + 4)
                ? Sized(w, at, (long)w.Le32(at + 36) * w.Le32(at + 40), $"{w.Le32(at + 36):N0}-byte logical blocks") : null));
        list.Add(S("romfs filesystem", Fs, "-rom1fs-", (w, at) => w.Be32(at + 8) > 32 && w.Printable(at + 16, 1) ? Sized(w, at, w.Be32(at + 8), $"'{w.Ascii(at + 16, 16)}'") : null));
        list.Add(S("ISO 9660 filesystem", Fs, "CD001", (w, at) => w.U8(at + 0x8000) == 1 && w.U8(at + 0x8006) == 1 && w.Le16(at + 0x8080) is 512 or 1024 or 2048 or 4096
            ? Sized(w, at, (long)w.Le32(at + 0x8050) * w.Le16(at + 0x8080), $"volume '{w.Ascii(at + 0x8028, 32)}'") : null, 0x8001));
        list.Add(S("Btrfs filesystem", Fs, "_BHRfS_M", (w, at) => Sized(w, at, (long)w.Le64(at + 0x10070)), 0x10040));
        list.Add(S("XFS filesystem", Fs, "XFSB", (w, at) => w.Be32(at + 4) is >= 512 and <= 65536 && (w.Be32(at + 4) & (w.Be32(at + 4) - 1)) == 0
            ? Sized(w, at, (long)w.Be64(at + 8) * w.Be32(at + 4)) : null));
        list.Add(S("F2FS filesystem", Fs, [0x10, 0x20, 0xF5, 0xF2], (w, at) => w.Le16(at + 0x404) == 1 && w.Le32(at + 0x40C) is >= 9 and <= 16
            ? Sized(w, at, (long)w.Le64(at + 0x448) << (int)w.Le32(at + 0x40C)) : null, 0x400));
        list.Add(S("EROFS filesystem", Fs, [0xE2, 0xE1, 0xF5, 0xE0], (w, at) => w.U8(at + 0x40C) is >= 9 and <= 16
            ? Sized(w, at, (long)w.Le32(at + 0x424) << w.U8(at + 0x40C)) : null, 0x400));
        list.Add(S("HFS+ volume", Fs, "H+\0\u0004", (w, at) => w.Be32(at + 0x428) is >= 512 and <= 65536 ? Sized(w, at, (long)w.Be32(at + 0x42C) * w.Be32(at + 0x428)) : null, 0x400));
        list.Add(S("HFSX volume", Fs, "HX\0\u0005", (w, at) => w.Be32(at + 0x428) is >= 512 and <= 65536 ? Sized(w, at, (long)w.Be32(at + 0x42C) * w.Be32(at + 0x428)) : null, 0x400));
        list.Add(S("APFS container", Fs, "NXSB", (w, at) => w.Le32(at + 36) is >= 4096 and <= 65536 ? Sized(w, at, (long)w.Le64(at + 40) * w.Le32(at + 36)) : null, 32));
        list.Add(S("LUKS encrypted volume", Fs, "LUKSº¾", (w, at) => w.Be16(at + 6) is 1 or 2 ? Found($"LUKS{w.Be16(at + 6)}") : null));
        list.Add(S("LVM2 physical volume", Fs, "LABELONE", (w, at) => w.Is(at + 24, "LVM2 001"u8) ? Found() : null));
        list.Add(S("GPT partition table", Fs, "EFI PART", (w, at) => w.Le32(at + 8) == 0x10000 && w.Le32(at + 12) is >= 92 and <= 512 ? Found($"{w.Le32(at + 80)} partition entries") : null));

        // archives
        list.Add(S("cpio archive (newc)", Arc, "070701", Cpio));
        list.Add(S("cpio archive (newc with CRC)", Arc, "070702", Cpio));
        list.Add(S("cpio archive (odc)", Arc, "070707", Cpio));
        list.Add(S("POSIX tar archive", Arc, "ustar", Tar, 257));
        list.Add(S("zip archive", Arc, "PK\u0003\u0004", Zip));
        list.Add(S("RAR archive (v4)", Arc, "Rar!\u001A\u0007\0", (w, at) => w.U8(at + 9) == 0x73 ? Found() : null));
        list.Add(S("RAR archive (v5)", Arc, "Rar!\u001A\u0007\u0001\0", (w, at) => Found()));
        list.Add(S("7-Zip archive", Arc, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], (w, at) => w.U8(at + 6) == 0 && w.U8(at + 7) <= 4
            ? Sized(w, at, 32 + (long)w.Le64(at + 12) + (long)w.Le64(at + 20), $"version 0.{w.U8(at + 7)}") : null));
        list.Add(S("Microsoft cabinet", Arc, "MSCF", (w, at) => w.Le32(at + 4) == 0 && w.U8(at + 25) == 1 && w.U8(at + 24) == 3 ? Sized(w, at, w.Le32(at + 8), $"{w.Le16(at + 28)} files") : null));
        list.Add(S("ar archive", Arc, "!<arch>\n", Ar));
        list.Add(S("RPM package", Arc, [0xED, 0xAB, 0xEE, 0xDB], (w, at) => w.U8(at + 4) is 3 or 4 && w.Be16(at + 6) <= 1 && w.Printable(at + 10, 1) ? Found($"'{w.Ascii(at + 10, 66)}'") : null));
        list.Add(S("xar archive", Arc, "xar!", (w, at) => w.Be16(at + 4) >= 28 && w.Be16(at + 6) == 1 ? Found() : null));
        list.Add(S("ARJ archive", Arc, [0x60, 0xEA], (w, at) => w.Le16(at + 2) is > 0 and <= 2600 && w.U8(at + 4) is >= 30 and < 64 && w.U8(at + 10) == 2 ? Found() : null));
        list.Add(S("Windows imaging (WIM)", Arc, "MSWIM\0\0\0", (w, at) => w.Le32(at + 8) == 208 ? Found() : null));
        list.Add(S("Compound file (OLE)", Doc, [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], (w, at) => w.Le16(at + 28) == 0xFFFE && w.Le16(at + 30) is 9 or 12 ? Found() : null));
        list.Add(S("Compiled HTML help (CHM)", Doc, "ITSF", (w, at) => w.Le32(at + 4) == 3 ? Found() : null));
        list.Add(S("Android sparse image", Boot, [0x3A, 0xFF, 0x26, 0xED], SparseImage));
        list.Add(S("Android backup", Arc, "ANDROID BACKUP\n", (w, at) => w.U8(at + 15) is >= (byte)'1' and <= (byte)'9' ? Found() : null));

        // compressed streams
        list.Add(S("gzip compressed data", Comp, [0x1F, 0x8B, 0x08], (w, at) => (w.U8(at + 3) & 0xE0) == 0 && w.U8(at + 9) is <= 13 or 255
            ? Found((w.U8(at + 3) & 8) != 0 ? $"original name '{CString(w, at + 10, 64)}'" : null) : null));
        list.Add(S("bzip2 compressed data", Comp, "BZh", (w, at) => w.U8(at + 3) is >= (byte)'1' and <= (byte)'9' && w.Is(at + 4, [0x31, 0x41, 0x59, 0x26, 0x53, 0x59])
            ? Found($"{(w.U8(at + 3) - '0') * 100} KiB blocks") : null));
        list.Add(S("xz compressed data", Comp, [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], (w, at) => w.U8(at + 6) == 0 && w.U8(at + 7) is 0 or 1 or 4 or 10
            && ~Crc.Raw(0xFFFFFFFF, w.D.AsSpan(at + 6, 2)) == w.Le32(at + 8) ? Found() : null));
        list.Add(S("LZMA compressed data", Comp, [0x5D, 0x00, 0x00], (w, at) => w.Le32(at + 1) is var dict && dict >= 1 << 16 && dict <= 1 << 26 && (dict & (dict - 1)) == 0
            && (long)w.Le64(at + 5) is var unpacked && (unpacked == -1 || unpacked is > 0 and < 1L << 32) ? Found($"dictionary {dict >> 10} KiB" + (unpacked > 0 ? $", {unpacked:N0} bytes unpacked" : "")) : null));
        list.Add(S("Zstandard compressed data", Comp, [0x28, 0xB5, 0x2F, 0xFD], (w, at) => (w.U8(at + 4) & 0x08) == 0 && w.Has(at, 6) ? Found() : null));
        list.Add(S("LZ4 compressed data", Comp, [0x04, 0x22, 0x4D, 0x18], Lz4Frame));
        list.Add(S("LZ4 legacy compressed data", Comp, [0x02, 0x21, 0x4C, 0x18], (w, at) => w.Le32(at + 4) is > 0 and <= 8 << 20 ? Found() : null));
        list.Add(S("lzop compressed data", Comp, [0x89, 0x4C, 0x5A, 0x4F, 0x00, 0x0D, 0x0A, 0x1A, 0x0A], (w, at) => w.Be16(at + 9) >= 0x0900 && w.U8(at + 15) is 1 or 2 or 3 ? Found() : null));
        list.Add(S("lzip compressed data", Comp, "LZIP", (w, at) => w.U8(at + 4) == 1 && (w.U8(at + 5) & 0x1F) is >= 12 and <= 29 ? Found() : null));
        list.Add(S("LZFSE compressed data", Comp, "bvx2", (w, at) => w.Le32(at + 4) is > 0 and < 1 << 28 ? Found() : null));
        list.Add(S("OpenSSL encrypted data", Key, "Salted__", (w, at) => w.Has(at, 16) ? Found() : null));

        // boot images and firmware headers
        list.Add(S("U-Boot uImage", Boot, [0x27, 0x05, 0x19, 0x56], (w, at) => w.Has(at, 64) && UImageReader.Looks(w.D.AsSpan(at, 64))
            ? Sized(w, at, 64 + (long)w.Be32(at + 12), $"'{w.Ascii(at + 32, 32)}', arch {UImageReader.ArchName((byte)w.U8(at + 29)) ?? w.U8(at + 29).ToString()}, load 0x{w.Be32(at + 16):X}") : null));
        list.Add(S("flattened device tree", Boot, [0xD0, 0x0D, 0xFE, 0xED], (w, at) => w.Be32(at + 4) >= 40 && w.Be32(at + 20) is >= 1 and <= 17 && w.Be32(at + 8) < w.Be32(at + 4)
            ? Sized(w, at, w.Be32(at + 4), w.Has(at, 40) && FitReader.Looks(w.D.AsSpan(at, Math.Min(w.N - at, 1 << 17))) ? "FIT image" : null) : null));
        list.Add(S("TRX firmware header", Boot, "HDR0", (w, at) => (w.Le32(at + 12) >> 16) is 1 or 2 && w.Le32(at + 4) >= 28 && w.Read(at + 12, (int)Math.Min(w.Le32(at + 4) - 12, 64 << 20)) is { } body
            && ~Crc.Raw(0xFFFFFFFF, body) == w.Le32(at + 8) ? Sized(w, at, w.Le32(at + 4), $"version {w.Le32(at + 12) >> 16}") : null));
        list.Add(S("Android boot image", Boot, "ANDROID!", AndroidBoot));
        list.Add(S("Android vendor boot image", Boot, "VNDRBOOT", (w, at) => w.Le32(at + 8) is 3 or 4 && w.Le32(at + 12) is 2048 or 4096 or 16384 ? Found($"v{w.Le32(at + 8)}") : null));
        list.Add(S("Android DTB/DTBO table", Boot, [0xD7, 0xB7, 0xAB, 0x1E], (w, at) => w.Be32(at + 8) == 32 && w.Be32(at + 12) == 32 ? Sized(w, at, w.Be32(at + 4), $"{w.Be32(at + 16)} entries") : null));
        list.Add(S("Android verified boot (vbmeta)", Boot, "AVB0", (w, at) => w.Be32(at + 4) == 1 ? Sized(w, at, 256 + (long)w.Be64(at + 12) + (long)w.Be64(at + 20)) : null));
        list.Add(S("Seama firmware header", Boot, [0x5E, 0xA3, 0xA4, 0x17], (w, at) => w.Be16(at + 4) == 0 && w.Be16(at + 6) < 1024 ? Sized(w, at, 12 + w.Be16(at + 6) + 16 + (long)w.Be32(at + 8)) : null));
        list.Add(S("Netgear CHK header", Boot, "*#$^", (w, at) => w.Be32(at + 4) is >= 40 and <= 1024 ? Sized(w, at, w.Be32(at + 4) + (long)w.Be32(at + 24) + w.Be32(at + 28), $"board '{w.Ascii(at + 40, 16)}'") : null));
        list.Add(S("TP-Link firmware header", Boot, "TP-LINK Technologies", (w, at) => w.Be32(at) is 1 or 2 or 3 ? Found($"version {w.Be32(at)}") : null, 4));
        list.Add(S("Linux kernel (x86 bzImage)", Boot, "HdrS", (w, at) => w.U8(at + 0x1FE) == 0x55 && w.U8(at + 0x1FF) == 0xAA && w.Le16(at + 0x206) >= 0x200
            ? Sized(w, at, (w.U8(at + 0x1F1) is var s && s == 0 ? 5 : s + 1) * 512L + w.Le32(at + 0x1F4) * 16L, $"boot protocol {w.U8(at + 0x207)}.{w.U8(at + 0x206):D2}") : null, 0x202));
        list.Add(S("Linux kernel (ARM zImage)", Boot, [0x18, 0x28, 0x6F, 0x01], (w, at) => w.Le32(at + 0x2C) > w.Le32(at + 0x28) && w.Le32(at + 0x2C) - w.Le32(at + 0x28) < 64 << 20 && w.Le32(at + 0x28) % 4 == 0 ? Sized(w, at, w.Le32(at + 0x2C) - w.Le32(at + 0x28)) : null, 0x24));
        list.Add(S("Linux kernel (ARM64 Image)", Boot, "ARMd", (w, at) => w.Le64(at + 16) > 0 ? Sized(w, at, (long)w.Le64(at + 16), $"text offset 0x{w.Le64(at + 8):X}") : null, 0x38));
        list.Add(S("Linux kernel (RISC-V Image)", Boot, "RSC\u0005", (w, at) => w.Le64(at + 16) > 0 ? Sized(w, at, (long)w.Le64(at + 16)) : null, 0x34));
        list.Add(S("Linux kernel version string", Other, "Linux version ", (w, at) => w.U8(at + 14) is >= (byte)'1' and <= (byte)'9' ? Found(CString(w, at, 120)) : null));
        list.Add(S("U-Boot version string", Other, "U-Boot ", (w, at) => (w.Is(at + 7, "20"u8) || w.Is(at + 7, "SPL"u8) || w.Is(at + 7, "1."u8)) ? Found(CString(w, at, 80)) : null));
        list.Add(S("UEFI firmware volume", Boot, "_FVH", (w, at) => w.Le16(at + 48) is >= 56 and < 4096 && w.U8(at + 55) is 1 or 2 ? Sized(w, at, (long)w.Le64(at + 32)) : null, 40));
        list.Add(S("Intel flash descriptor", Boot, [0x5A, 0xA5, 0xF0, 0x0F], (w, at) => w.U8(at + 0x13) <= 7 ? Found() : null, 16));
        list.Add(S("coreboot CBFS file", Boot, "LARCHIVE", (w, at) => w.Be32(at + 12) is >= 24 and < 4096 ? Sized(w, at, w.Be32(at + 12) + (long)w.Be32(at + 8), $"'{CString(w, at + 24, 64)}'") : null));
        list.Add(S("ESP32 application image", Boot, [0xE9], (w, at) => w.U8(at + 1) is > 0 and <= 16 && w.U8(at + 2) <= 5 && w.Le32(at + 4) is >= 0x40000000 and < 0x50000000
            && w.Le16(at + 12) <= 0x20 && w.Le32(at + 19) == 0 && w.U8(at + 23) <= 1 && w.Le32(at + 24) is >= 0x3F000000 and < 0x60000000 && w.Le32(at + 28) is > 0 and < 16 << 20
            ? Found($"{w.U8(at + 1)} segments, chip {w.Le16(at + 12)}, entry 0x{w.Le32(at + 4):X}") : null));
        list.Add(S("uClinux flat binary (bFLT)", Exe, "bFLT", (w, at) => w.Be32(at + 4) is 2 or 4 && w.Be32(at + 8) == 64 && w.Be32(at + 12) >= 64 && w.Be32(at + 16) >= w.Be32(at + 12)
            ? Sized(w, at, w.Be32(at + 32) + 4L * w.Be32(at + 36), $"version {w.Be32(at + 4)}") : null));

        // executables and code
        list.Add(S("PE image", Exe, "MZ", (w, at) => PeImage.TryParse(w.D.AsSpan(0, w.N), at) is { } pe && pe.EndOfImage > 0
            ? Sized(w, at, pe.EndOfImage, pe.IsDotNet(w.D.AsSpan(0, w.N)) ? ".NET assembly" : null) : null));
        list.Add(S("ELF", Exe, [0x7F, (byte)'E', (byte)'L', (byte)'F'], Elf));
        list.Add(S("Mach-O (32-bit)", Exe, [0xCE, 0xFA, 0xED, 0xFE], (w, at) => MachO(w, at, 28)));
        list.Add(S("Mach-O (64-bit)", Exe, [0xCF, 0xFA, 0xED, 0xFE], (w, at) => MachO(w, at, 32)));
        list.Add(S("Mach-O (big endian)", Exe, [0xFE, 0xED, 0xFA], (w, at) => w.U8(at + 3) is 0xCE or 0xCF && w.Be32(at + 12) is >= 1 and <= 12 && w.Be32(at + 16) is > 0 and < 10_000 ? Found() : null));
        list.Add(S("Mach-O universal binary", Exe, [0xCA, 0xFE, 0xBA, 0xBE], (w, at) => w.Be32(at + 4) is >= 1 and <= 20 && w.Be32(at + 8) is 7 or 12 or 18 or 0x01000007 or 0x0100000C or 0x01000012
            ? Found($"{w.Be32(at + 4)} architectures") : null));
        list.Add(S("Java class file", Exe, [0xCA, 0xFE, 0xBA, 0xBE], (w, at) => w.Be16(at + 6) is >= 45 and <= 80 && w.Be16(at + 8) > 0 ? Found($"class version {w.Be16(at + 6)}") : null));
        list.Add(S("Dalvik executable (DEX)", Exe, "dex\n0", (w, at) => w.U8(at + 5) == '3' && w.U8(at + 6) is >= (byte)'5' and <= (byte)'9' && w.U8(at + 7) == 0 && w.Le32(at + 36) == 0x70
            ? Sized(w, at, w.Le32(at + 32), $"version {w.Ascii(at + 4, 3)}") : null));
        list.Add(S("optimized DEX (ODEX)", Exe, "dey\n03", (w, at) => w.U8(at + 7) == 0 && w.Le32(at + 8) >= 40 ? Found() : null));
        list.Add(S("Android OAT file", Exe, "oat\n", (w, at) => w.U8(at + 4) is >= (byte)'0' and <= (byte)'2' && w.U8(at + 7) == 0 ? Found($"version {w.Ascii(at + 4, 3)}") : null));
        list.Add(S("Android VDEX file", Exe, "vdex", (w, at) => w.U8(at + 4) == '0' && w.U8(at + 7) == 0 ? Found($"version {w.Ascii(at + 4, 3)}") : null));
        list.Add(S("Android ART image", Exe, "art\n", (w, at) => w.U8(at + 4) == '0' && w.U8(at + 7) == 0 ? Found($"version {w.Ascii(at + 4, 3)}") : null));
        list.Add(S("WebAssembly module", Exe, "\0asm", (w, at) => w.Le32(at + 4) == 1 && w.U8(at + 8) <= 12 ? Found() : null));
        list.Add(S("Lua bytecode", Exe, "\u001BLua", (w, at) => w.U8(at + 4) is 0x51 or 0x52 or 0x53 or 0x54 ? Found($"Lua {w.U8(at + 4) >> 4}.{w.U8(at + 4) & 15}") : null));
        list.Add(S("LLVM bitcode", Exe, "BCÀÞ", (w, at) => w.U8(at + 4) == 0x35 ? Found() : null));
        list.Add(S("LLVM bitcode wrapper", Exe, [0xDE, 0xC0, 0x17, 0x0B], (w, at) => w.Le32(at + 4) == 0 && w.Le32(at + 8) >= 20 ? Sized(w, at, (long)w.Le32(at + 8) + w.Le32(at + 12)) : null));
        list.Add(S("Python bytecode (.pyc)", Exe, [0x0D, 0x0A], (w, at) => w.Le16(at - 2) is >= 3000 and < 4000 && w.Le32(at + 2) <= 3 ? Found($"magic {w.Le16(at - 2)}") : null, 2));
        list.Add(S("executable script", Exe, "#!/", (w, at) => (w.Is(at + 3, "bin/"u8) || w.Is(at + 3, "usr/"u8)) && w.Printable(at, 12) ? Found(CString(w, at, 60, '\n')) : null));
        list.Add(S("Android binary XML", Doc, [0x03, 0x00, 0x08, 0x00], (w, at) => w.Le32(at + 4) > 8 && w.Le16(at + 8) == 1 && w.Le16(at + 10) == 0x1C ? Sized(w, at, w.Le32(at + 4)) : null));

        // keys and certificates
        foreach (var label in new[] { "CERTIFICATE", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY",
                     "PUBLIC KEY", "RSA PUBLIC KEY", "CERTIFICATE REQUEST", "X509 CRL", "DH PARAMETERS", "PGP PUBLIC KEY BLOCK", "PGP PRIVATE KEY BLOCK", "PGP SIGNATURE", "PGP MESSAGE" })
            list.Add(S($"PEM {label.ToLowerInvariant()}", Key, $"-----BEGIN {label}-----", Pem(label)));
        list.Add(S("DER certificate", Key, [0x30, 0x82], (w, at) => w.Be16(at + 2) is var len && len >= 256 && w.U8(at + 4) == 0x30 && w.U8(at + 5) == 0x82 && w.Be16(at + 6) < len && w.U8(at + 8) == 0xA0
            ? Sized(w, at, 4 + len) : null));
        foreach (var kind in new[] { "ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256" })
            list.Add(S($"OpenSSH public key ({kind})", Key, kind + " AAAA", (w, at) => Found()));

        // media and documents
        list.Add(S("PNG image", Media, [0x89, (byte)'P', (byte)'N', (byte)'G', 0x0D, 0x0A, 0x1A, 0x0A], Png));
        list.Add(S("JPEG image", Media, [0xFF, 0xD8, 0xFF], (w, at) => w.U8(at + 3) is 0xE0 or 0xE1 or 0xDB or 0xEE or 0xE2 && w.Be16(at + 4) >= 2
            && (w.U8(at + 3) != 0xE0 || w.Is(at + 6, "JFIF\0"u8)) && (w.U8(at + 3) != 0xE1 || w.Is(at + 6, "Exif\0"u8) || w.Is(at + 6, "http"u8)) ? Found() : null));
        list.Add(S("GIF image", Media, "GIF8", (w, at) => (w.Is(at + 4, "7a"u8) || w.Is(at + 4, "9a"u8)) && w.Le16(at + 6) > 0 && w.Le16(at + 8) > 0 ? Found($"{w.Le16(at + 6)}x{w.Le16(at + 8)}") : null));
        list.Add(S("BMP image", Media, "BM", (w, at) => w.Le32(at + 6) == 0 && w.Le32(at + 14) is 12 or 40 or 52 or 56 or 108 or 124 && w.Le16(at + 26) == 1 && w.Le32(at + 10) < w.Le32(at + 2)
            ? Sized(w, at, w.Le32(at + 2), $"{w.Le32(at + 18)}x{w.Le32(at + 22)}") : null));
        list.Add(S("TIFF image (little endian)", Media, "II*\0", (w, at) => w.Le32(at + 4) is >= 8 and < 1 << 28 ? Found() : null));
        list.Add(S("TIFF image (big endian)", Media, "MM\0*", (w, at) => w.Be32(at + 4) is >= 8 and < 1 << 28 ? Found() : null));
        list.Add(S("WebP image", Media, "WEBP", (w, at) => Riff(w, at, "VP8"), 8));
        list.Add(S("WAVE audio", Media, "WAVE", (w, at) => Riff(w, at, "fmt "), 8));
        list.Add(S("AVI video", Media, "AVI ", (w, at) => Riff(w, at, "LIST"), 8));
        list.Add(S("MP3 audio with ID3 tag", Media, "ID3", (w, at) => w.U8(at + 3) is 2 or 3 or 4 && w.U8(at + 4) == 0 && ((w.U8(at + 6) | w.U8(at + 7) | w.U8(at + 8) | w.U8(at + 9)) & 0x80) == 0 ? Found() : null));
        list.Add(S("Ogg stream", Media, "OggS", (w, at) => w.U8(at + 4) == 0 && w.U8(at + 5) <= 7 ? Found() : null));
        list.Add(S("FLAC audio", Media, "fLaC", (w, at) => (w.U8(at + 4) & 0x7F) == 0 && w.Be32(at + 4) << 8 >> 8 == 34 ? Found() : null));
        list.Add(S("TrueType font", Media, [0x00, 0x01, 0x00, 0x00], (w, at) => w.Be16(at + 4) is >= 4 and <= 64 && w.Be16(at + 6) is 16 or 32 or 64 or 128 or 256 or 512 && w.Printable(at + 12, 4) ? Found($"{w.Be16(at + 4)} tables") : null));
        list.Add(S("OpenType font", Media, "OTTO", (w, at) => w.Be16(at + 4) is >= 4 and <= 64 && w.Printable(at + 12, 4) ? Found() : null));
        list.Add(S("WOFF font", Media, "wOFF", (w, at) => w.Be16(at + 12) is > 0 and <= 64 ? Sized(w, at, w.Be32(at + 8)) : null));
        list.Add(S("WOFF2 font", Media, "wOF2", (w, at) => w.Be16(at + 12) is > 0 and <= 64 ? Sized(w, at, w.Be32(at + 8)) : null));
        list.Add(S("PDF document", Doc, "%PDF-", (w, at) => w.U8(at + 5) is (byte)'1' or (byte)'2' && w.U8(at + 6) == '.' ? Found($"version {w.Ascii(at + 5, 3)}") : null));
        list.Add(S("RTF document", Doc, "{\\rtf1", (w, at) => Found()));
        list.Add(S("SQLite database", Doc, "SQLite format 3\0", (w, at) => w.Be16(at + 16) is var page && (page == 1 || page >= 512 && (page & (page - 1)) == 0) && w.U8(at + 21) == 64
            ? Sized(w, at, (page == 1 ? 65536L : page) * w.Be32(at + 28)) : null));
        list.Add(S("XML document", Doc, "<?xml version=", (w, at) => w.U8(at + 14) is (byte)'"' or (byte)'\'' ? Found() : null));
        list.Add(S("HTML document", Doc, "<!DOCTYPE html", (w, at) => Found()));
        list.Add(S("VHD disk image", Fs, "conectix", (w, at) => w.Be32(at + 12) == 0x00010000 ? Found($"{(long)w.Be64(at + 48):N0}-byte disk") : null));
        list.Add(S("VMDK sparse extent", Fs, "KDMV", (w, at) => w.Le32(at + 4) is 1 or 2 or 3 ? Found() : null));
        list.Add(S("QEMU QCOW image", Fs, "QFIû", (w, at) => w.Be32(at + 4) is 1 or 2 or 3 ? Found($"version {w.Be32(at + 4)}, {(long)w.Be64(at + 24):N0}-byte disk") : null));
        list.Add(S("Apple disk image (koly)", Fs, "koly", (w, at) => w.Be32(at + 4) == 4 && w.Be32(at + 8) == 512 ? Found() : null));
        return list;
    }

    private static string CString(Window w, int at, int max, char stop = '\0')
    {
        var sb = new StringBuilder();
        for (int i = 0; i < max && w.U8(at + i) is var b && b > 0 && b != stop; i++) sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
        return sb.ToString();
    }

    private static Func<Window, int, (long? Size, string? Detail)?> Squashfs(bool big) => (w, at) =>
    {
        uint U32(int o) => big ? w.Be32(at + o) : w.Le32(at + o);
        uint U16(int o) => big ? w.Be16(at + o) : w.Le16(at + o);
        uint major = U16(28), minor = U16(30);
        if (!w.Has(at, 96) || major is < 1 or > 4 || minor > 1) return null;
        string detail = $"version {major}.{minor}" + (major == 4 ? $", compression {U16(20) switch { 1 => "gzip", 2 => "lzma", 3 => "lzo", 4 => "xz", 5 => "lz4", 6 => "zstd", var c => c.ToString() }}" : "");
        if (major == 4)
        {
            uint bs = U32(12);
            if (bs < 4096 || bs > 1 << 20 || (bs & (bs - 1)) != 0 || U16(20) is 0 or > 6) return null;
            return Sized(w, at, (long)(big ? w.Be64(at + 40) : w.Le64(at + 40)), $"{detail}, {U32(4):N0} inodes, {bs >> 10} KiB blocks");
        }
        // versions 1-3: a 32-bit size at 8; version 3 also keeps a 64-bit one at 63
        long size = major == 3 ? (long)(big ? w.Be64(at + 63) : w.Le64(at + 63)) : U32(8);
        return Sized(w, at, size, detail);
    };

    private static (long? Size, string? Detail)? Fat(Window w, int at, string detail)
    {
        if (w.U8(at + 510) != 0x55 || w.U8(at + 511) != 0xAA || w.U8(at) is not (0xEB or 0xE9)) return null;
        uint bps = w.Le16(at + 11);
        int spc = w.U8(at + 13);
        if (bps is not (512 or 1024 or 2048 or 4096) || spc <= 0 || (spc & (spc - 1)) != 0 || w.Le16(at + 14) == 0 || w.U8(at + 16) is not (1 or 2)) return null;
        long sectors = w.Le16(at + 19) is var s16 and not 0 ? s16 : w.Le32(at + 32);
        return Sized(w, at, sectors * bps, detail);
    }

    private static (long? Size, string? Detail)? Jffs2(Window w, int at, bool big)
    {
        if (!Jffs2Node(w.Read(at, 12), big, out _)) return null;
        // the filesystem runs while nodes follow, across erased (0xFF) gaps of up to an erase block
        long p = at, end = at;
        int nodes = 0;
        while (nodes < 1 << 20)
        {
            var h = w.Read(p, 12);
            if (Jffs2Node(h, big, out long length)) { p += (length + 3) & ~3L; end = p; nodes++; continue; }
            if (h == null || h[0] != 0xFF) break;
            var gap = w.Read(p, (int)Math.Clamp(w.Length - (w.Origin + p), 0, 256 << 10));
            int next = gap == null ? -1 : gap.AsSpan().IndexOfAnyExcept((byte)0xFF);
            if (next < 0) break;
            p += next & ~3;
        }
        return Sized(w, at, end - at, $"{(big ? "big" : "little")} endian, {nodes:N0} nodes");
    }

    private static bool Jffs2Node(byte[]? h, bool big, out long length)
    {
        length = 0;
        if (h == null || h.Length < 12) return false;
        uint magic = big ? BinaryPrimitives.ReadUInt16BigEndian(h) : BinaryPrimitives.ReadUInt16LittleEndian(h);
        uint type = big ? BinaryPrimitives.ReadUInt16BigEndian(h.AsSpan(2)) : BinaryPrimitives.ReadUInt16LittleEndian(h.AsSpan(2));
        length = big ? BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(4)) : BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(4));
        uint crc = big ? BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(8)) : BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(8));
        return magic == 0x1985 && type is 0xE001 or 0xE002 or 0x2003 or 0x2004 or 0x2006 or 0xE008 or 0xE009 && length >= 12 && Crc.Jffs2(h.AsSpan(0, 8)) == crc;
    }

    private static (long? Size, string? Detail)? Ubi(Window w, int at)
    {
        if (!w.Has(at, 64) || !UbiReader.Looks(w.D.AsSpan(at, 64))) return null;
        // the image runs while erase-counter headers follow at the erase-block size
        long peb = 0;
        for (long size = 16 << 10; size <= 4 << 20 && peb == 0; size <<= 1)
            if (w.Read(at + size, 64) is { } next && UbiReader.Looks(next)) peb = size;
        if (peb == 0) return Found("one erase block");
        long blocks = 1;
        while (blocks < 1 << 20 && w.Read(at + blocks * peb, 64) is { } h && UbiReader.Looks(h)) blocks++;
        return Sized(w, at, blocks * peb, $"{peb >> 10} KiB erase blocks, {blocks:N0} blocks");
    }

    private static (long? Size, string? Detail)? Cpio(Window w, int at)
    {
        // the header fields are 8 hex digits (newc) or 6 octal (odc): every one must parse
        bool newc = w.U8(at + 5) is (byte)'1' or (byte)'2';
        int fields = newc ? 13 : 0;
        for (int i = 0; i < fields; i++)
            for (int j = 0; j < 8; j++)
                if (!Uri.IsHexDigit((char)w.U8(at + 6 + i * 8 + j))) return null;
        if (!newc)
            for (int i = 6; i < 76; i++)
                if (w.U8(at + i) is < (byte)'0' or > (byte)'7') return null;
        // walk the entries to the trailer for the size
        long p = at;
        for (int entries = 0; entries < 200_000; entries++)
        {
            var h = w.Read(p, newc ? 110 : 76);
            if (h == null) return Found();
            long Field(int o, int n, int radix)
            {
                try { return Convert.ToInt64(Encoding.ASCII.GetString(h, o, n), radix); }
                catch (FormatException) { return -1; }
                catch (ArgumentException) { return -1; }
            }
            long nameSize = newc ? Field(94, 8, 16) : Field(59, 6, 8), fileSize = newc ? Field(54, 8, 16) : Field(65, 11, 8);
            if (nameSize <= 0 || nameSize > 4096 || fileSize < 0) return entries > 0 ? Found() : null;
            long nameAt = p + (newc ? 110 : 76);
            long data = newc ? (nameAt + nameSize + 3) & ~3L : nameAt + nameSize;
            long next = newc ? (data + fileSize + 3) & ~3L : data + fileSize;
            if (w.Read(nameAt, (int)nameSize - 1) is { } name && name.AsSpan().SequenceEqual("TRAILER!!!"u8)) return Sized(w, at, next - at, $"{entries:N0} entries");
            p = next;
            if (w.Read(p, 6) is not { } magic || !magic.AsSpan(0, 5).SequenceEqual("07070"u8)) return entries > 0 ? Found($"{entries + 1:N0} entries, no trailer") : null;
        }
        return Found();
    }

    private static (long? Size, string? Detail)? Tar(Window w, int at)
    {
        if (!w.Has(at, 512) || !w.Printable(at, 1)) return null;
        // the header checksum: the sum of its bytes with the checksum field read as spaces
        long sum = 0;
        for (int i = 0; i < 512; i++) sum += i is >= 148 and < 156 ? 32 : w.D[at + i];
        long stored = 0;
        for (int i = 148; i < 156 && w.D[at + i] is >= (byte)'0' and <= (byte)'7'; i++) stored = stored * 8 + (w.D[at + i] - '0');
        if (stored != sum) return null;
        // the archive ends with two zero blocks; entries are walked to them
        long p = at;
        for (int entries = 0; entries < 200_000; entries++)
        {
            var h = w.Read(p, 512);
            if (h == null) return Found();
            if (h.All(b => b == 0)) return Sized(w, at, p + 1024 - at, $"{entries:N0} entries");
            long size = 0;
            for (int i = 124; i < 136 && h[i] is >= (byte)'0' and <= (byte)'7'; i++) size = size * 8 + (h[i] - '0');
            p += 512 + (size + 511) / 512 * 512;
        }
        return Found();
    }

    private static (long? Size, string? Detail)? Zip(Window w, int at)
    {
        uint version = w.Le16(at + 4), nameLength = w.Le16(at + 26);
        if (version > 63 || w.Le16(at + 8) is not (0 or 8 or 9 or 12 or 14 or 93 or 95 or 98 or 99) || nameLength is 0 or > 1024 || !w.Has(at + 30, (int)nameLength)) return null;
        var name = Encoding.UTF8.GetString(w.D, at + 30, (int)nameLength);
        // the end of central directory record gives the archive's size
        int end = w.D.AsSpan(at, w.N - at).IndexOf("PK\u0005\u0006"u8);
        if (end >= 0 && w.Has(at + end, 22)) return Sized(w, at, end + 22 + w.Le16(at + end + 20), $"first entry '{name}'");
        return Found($"first entry '{name}'");
    }

    private static (long? Size, string? Detail)? Ar(Window w, int at)
    {
        long p = at + 8;
        int members = 0;
        string? first = null;
        while (members < 100_000 && w.Read(p, 60) is { } h && h[58] == '`' && h[59] == '\n')
        {
            first ??= Encoding.ASCII.GetString(h, 0, 16).Trim();
            if (!long.TryParse(Encoding.ASCII.GetString(h, 48, 10).Trim(), out long size) || size < 0) break;
            p += 60 + size + (size & 1);
            members++;
        }
        return members == 0 ? null : Sized(w, at, p - at, $"{members:N0} members" + (first == "debian-binary" ? ", Debian package" : ""));
    }

    private static (long? Size, string? Detail)? SparseImage(Window w, int at)
    {
        if (w.Le16(at + 4) != 1 || w.Le16(at + 8) != 28 || w.Le16(at + 10) != 12 || w.Le32(at + 12) is < 1024 or > 1 << 20) return null;
        uint chunks = w.Le32(at + 20);
        long p = at + 28;
        for (uint i = 0; i < chunks && i < 1 << 20; i++)
        {
            var c = w.Read(p, 12);
            if (c == null) return Found();
            p += BinaryPrimitives.ReadUInt32LittleEndian(c.AsSpan(8));
        }
        return Sized(w, at, p - at, $"{w.Le32(at + 16):N0} blocks of {w.Le32(at + 12):N0} bytes, {chunks:N0} chunks");
    }

    private static (long? Size, string? Detail)? AndroidBoot(Window w, int at)
    {
        uint version = w.Le32(at + 40);
        if (version > 8) return null;
        if (version >= 3)
            return Sized(w, at, 4096 + Pages(w.Le32(at + 8), 4096) + Pages(w.Le32(at + 12), 4096), $"header v{version}");
        uint page = w.Le32(at + 36);
        if (page is not (2048 or 4096 or 8192 or 16384)) return null;
        return Sized(w, at, page + Pages(w.Le32(at + 8), page) + Pages(w.Le32(at + 16), page) + Pages(w.Le32(at + 24), page), $"header v{version}, '{w.Ascii(at + 48, 16)}'");
    }

    private static long Pages(uint size, uint page) => (size + page - 1L) / page * page;

    private static (long? Size, string? Detail)? Elf(Window w, int at)
    {
        int cls = w.U8(at + 4), data = w.U8(at + 5);
        if (cls is not (1 or 2) || data is not (1 or 2) || w.U8(at + 6) != 1) return null;
        bool big = data == 2, is64 = cls == 2;
        uint U16(int o) => big ? w.Be16(at + o) : w.Le16(at + o);
        ulong Addr(int o) => is64 ? (big ? w.Be64(at + o) : w.Le64(at + o)) : big ? w.Be32(at + o) : w.Le32(at + o);
        uint type = U16(16), machine = U16(18);
        if (type is 0 or > 4 || U16(is64 ? 52 : 40) != (is64 ? 64 : 52)) return null;
        // the file ends at the section header table (or its last program segment when there is none)
        ulong shoff = Addr(is64 ? 40 : 32);
        uint shentsize = U16(is64 ? 58 : 46), shnum = U16(is64 ? 60 : 48);
        long size = shoff > 0 && shnum > 0 && shentsize is 40 or 64 ? (long)shoff + shnum * shentsize : 0;
        var name = machine switch
        {
            2 => "SPARC", 3 => "x86", 8 => big ? "MIPS (big endian)" : "MIPS (little endian)", 20 => "PowerPC", 21 => "PowerPC64", 40 => big ? "ARM (big endian)" : "ARM",
            42 => "SuperH", 50 => "IA-64", 62 => "x86-64", 83 => "AVR", 94 => "Xtensa", 183 => "ARM64", 243 => "RISC-V", 258 => "LoongArch", var m => $"machine {m}",
        };
        var detail = $"{(is64 ? 64 : 32)}-bit {name} {type switch { 1 => "relocatable", 2 => "executable", 3 => "shared object", _ => "core" }}";
        return size > 0 && size < 1L << 32 ? Sized(w, at, size, detail) ?? Found(detail) : Found(detail);
    }

    private static (long? Size, string? Detail)? MachO(Window w, int at, int headerSize)
    {
        uint cpu = w.Le32(at + 4), type = w.Le32(at + 12), commands = w.Le32(at + 16), size = w.Le32(at + 20);
        if ((cpu & 0xFFFFFF) is not (7 or 12 or 18) || type is 0 or > 12 || commands is 0 or > 10_000 || size > 1 << 24) return null;
        return Found($"{commands} load commands");
    }

    private static Func<Window, int, (long? Size, string? Detail)?> Pem(string label)
    {
        var end = Encoding.ASCII.GetBytes($"-----END {label}-----");
        return (w, at) =>
        {
            int from = at + 11 + label.Length + 5;
            if (!w.Has(from, 1)) return null;
            int found = w.D.AsSpan(from, Math.Min(w.N - from, 64 << 10)).IndexOf(end);
            return found < 0 ? null : Sized(w, at, from - at + found + end.Length);
        };
    }

    private static (long? Size, string? Detail)? Png(Window w, int at)
    {
        if (w.Be32(at + 8) != 13 || !w.Is(at + 12, "IHDR"u8) || !w.Has(at + 12, 21) || ~Crc.Raw(0xFFFFFFFF, w.D.AsSpan(at + 12, 17)) != w.Be32(at + 29)) return null;
        var detail = $"{w.Be32(at + 16)}x{w.Be32(at + 20)}";
        long p = at + 8;
        for (int chunks = 0; chunks < 100_000; chunks++)
        {
            var c = w.Read(p, 8);
            if (c == null) return Found(detail);
            long length = BinaryPrimitives.ReadUInt32BigEndian(c);
            p += 12 + length;
            if (c.AsSpan(4).SequenceEqual("IEND"u8)) return Sized(w, at, p - at, detail);
        }
        return Found(detail);
    }

    /// <summary>An LZ4 frame descriptor: version 01, no reserved bits, and its header checksum (second byte of XXH32).</summary>
    private static (long? Size, string? Detail)? Lz4Frame(Window w, int at)
    {
        int flags = w.U8(at + 4);
        if ((flags & 0xC2) != 0x40 || (w.U8(at + 5) & 0x8F) != 0 || (w.U8(at + 5) >> 4) < 4) return null;
        int length = 2 + ((flags & 8) != 0 ? 8 : 0) + ((flags & 1) != 0 ? 4 : 0);
        if (!w.Has(at + 4, length + 1)) return null;
        return (byte)(System.IO.Hashing.XxHash32.HashToUInt32(w.D.AsSpan(at + 4, length)) >> 8) == w.U8(at + 4 + length) ? Found() : null;
    }

    private static (long? Size, string? Detail)? Riff(Window w, int at, string firstChunk) =>
        w.Is(at, "RIFF"u8) && w.Is(at + 12, Encoding.ASCII.GetBytes(firstChunk)) ? Sized(w, at, 8 + (long)w.Le32(at + 4)) : null;

    /// <summary>The signatures keyed by their first two magic bytes (a one-byte magic under every second byte).</summary>
    private static readonly List<Signature>?[] ByPrefix = Index();

    private static List<Signature>?[] Index()
    {
        var table = new List<Signature>?[65536];
        foreach (var s in All)
        {
            if (s.Magic.Length == 1)
                for (int b = 0; b < 256; b++) (table[s.Magic[0] << 8 | b] ??= []).Add(s);
            else (table[s.Magic[0] << 8 | s.Magic[1]] ??= []).Add(s);
        }
        return table;
    }

    /// <summary>
    /// Signatures whose header starts below <paramref name="limit"/> in the window; a region a sized filesystem, boot image or
    /// archive covers is not searched again inside (its parts are its own reader's business). Returns the first offset
    /// after the last region, for the next window.
    /// </summary>
    public static long Scan(Window w, int limit, long skipUntil, List<SignatureHit> hits, int maxHits, Func<Signature, bool>? only, CancellationToken ct)
    {
        int last = w.N - 1;
        for (int i = (int)Math.Clamp(skipUntil - w.Origin, 0, w.N); i < last && hits.Count < maxHits; i++)
        {
            var bucket = ByPrefix[w.D[i] << 8 | w.D[i + 1]];
            if (bucket == null) continue;
            if ((i & 0xFFFFF) == 0) ct.ThrowIfCancellationRequested();
            foreach (var s in bucket)
            {
                int header = i - s.MagicAt;
                if (header < 0 || header >= limit || header + w.Origin < skipUntil || !w.Is(i, s.Magic) || (only != null && !only(s))) continue;
                (long? Size, string? Detail)? r;
                try { r = s.Check(w, header); }
                // a check reads arbitrary bytes: a range it did not guard is a miss, not a failure
                catch (Exception ex) when (ex is IOException or InvalidDataException or ArgumentException or IndexOutOfRangeException or OverflowException or ToolError) { r = null; }
                if (r is not { } found) continue;
                hits.Add(new SignatureHit(w.Origin + header, s.Format, s.Kind, found.Size, found.Detail));
                if (found.Size is { } size && s.Kind is SignatureKind.Filesystem or SignatureKind.Boot or SignatureKind.Archive && size > 64)
                {
                    skipUntil = w.Origin + header + size;
                    i = (int)Math.Min(int.MaxValue - 1, skipUntil - w.Origin) - 1;
                    break;
                }
            }
        }
        return skipUntil;
    }

    /// <summary>Every signature of a file in memory.</summary>
    public static List<SignatureHit> Scan(byte[] data, int maxHits, CancellationToken ct)
    {
        var hits = new List<SignatureHit>();
        Scan(new Window(data, data.Length, 0, data.Length, null), data.Length, 0, hits, maxHits, null, ct);
        return hits;
    }

    /// <summary>Every signature of a file read from a stream in windows of <paramref name="window"/> bytes, each overlapping the next by <paramref name="overlap"/>.</summary>
    public static List<SignatureHit> Scan(Stream s, long length, int maxHits, CancellationToken ct, int window = 64 << 20, int overlap = 1 << 20)
    {
        var hits = new List<SignatureHit>();
        byte[] ReadAt(long at, int n)
        {
            var b = new byte[n];
            long keep = s.Position;
            s.Position = at;
            s.ReadExactly(b);
            s.Position = keep;
            return b;
        }
        var buffer = new byte[(int)Math.Min(window, Math.Max(length, 1))];
        long origin = 0, skip = 0;
        int filled = 0;
        s.Position = 0;
        while (hits.Count < maxHits)
        {
            filled += s.ReadAtLeast(buffer.AsSpan(filled), buffer.Length - filled, throwOnEndOfStream: false);
            bool last = origin + filled >= length || filled < buffer.Length;
            // a signature starting in the overlap is left to the next window, which holds its header whole
            skip = Scan(new Window(buffer, filled, origin, length, ReadAt), last ? filled : filled - overlap, skip, hits, maxHits, null, ct);
            if (last) break;
            buffer.AsSpan(filled - overlap, overlap).CopyTo(buffer);
            origin += filled - overlap;
            filled = overlap;
        }
        return hits;
    }
}
