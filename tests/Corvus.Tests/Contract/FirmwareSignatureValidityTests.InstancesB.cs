using System.Buffers.Binary;
using System.Text;
using Corvus.Core.Firmware;

namespace Corvus.Tests;

public sealed partial class FirmwareSignatureValidityTests
{
    private static byte[] Zeros(int length, params (int At, byte[] Bytes)[] fields)
    {
        var d = new byte[length];
        foreach (var (at, bytes) in fields) bytes.CopyTo(d, at);
        return d;
    }

    private static byte[] B(params int[] bytes) => bytes.Select(b => (byte)b).ToArray();

    private static byte[] Text(string s) => Encoding.Latin1.GetBytes(s);

    private static byte[] Le32(uint v) => BitConverter.GetBytes(v);

    private static byte[] Be32(uint v) => B((int)(v >> 24), (int)(v >> 16 & 0xFF), (int)(v >> 8 & 0xFF), (int)(v & 0xFF));

    private static byte[] Pe32()
    {
        var d = new byte[0x170];
        "MZ"u8.CopyTo(d);
        BinaryPrimitives.WriteInt32LittleEndian(d.AsSpan(0x3C), 0x40);
        "PE\0\0"u8.CopyTo(d.AsSpan(0x40));
        BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(0x44), 0x14C);
        BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(0x46), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(0x54), 0xE0);
        BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(0x58), 0x10B);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(0x58 + 92), 16);
        ".text"u8.CopyTo(d.AsSpan(0x138));
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(0x138 + 16), 0x10);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(0x138 + 20), 0x160);
        return d;
    }

    private static byte[] Elf64()
    {
        var d = new byte[64];
        B(0x7F, 'E', 'L', 'F', 2, 1, 1).CopyTo(d, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(16), 2);
        BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(18), 62);
        BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(52), 64);
        return d;
    }

    private static byte[] MachOLittle(int magic) =>
        Zeros(32, (0, B(magic, 0xFA, 0xED, 0xFE)), (4, Le32(7)), (12, Le32(2)), (16, Le32(1)), (20, Le32(16)));

    private static byte[] MachOBig() => Zeros(32, (0, B(0xFE, 0xED, 0xFA, 0xCE)), (12, Be32(2)), (16, Be32(1)));

    private static byte[] Png()
    {
        var ihdr = Bytes("IHDR", Be32(1), Be32(1), B(8, 2, 0, 0, 0));
        return Bytes(B(0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A), Be32(13), ihdr, Be32(Crc32(ihdr)), Be32(0), "IEND", B(0xAE, 0x42, 0x60, 0x82));
    }

    private static byte[] Riff(string form, string chunk) => Bytes("RIFF", Le32(16), form, chunk, Le32(4), new byte[4]);

    private static byte[] Pem(string label) => Text($"-----BEGIN {label}-----\nAAAA\n-----END {label}-----\n");

    private static readonly string[] PemLabels =
    [
        "CERTIFICATE", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY",
        "PUBLIC KEY", "RSA PUBLIC KEY", "CERTIFICATE REQUEST", "X509 CRL", "DH PARAMETERS", "PGP PUBLIC KEY BLOCK", "PGP PRIVATE KEY BLOCK", "PGP SIGNATURE", "PGP MESSAGE",
    ];

    private static byte[] Font(string magic) => Zeros(32, (0, Text(magic)), (5, B(4)), (7, B(64)), (12, Text("cmap")));

    private static byte[] Woff(string magic) => Zeros(44, (0, Text(magic)), (8, Be32(44)), (12, B(0, 1)));

    /// <summary>Minimal instances of the second half of the signatures that had none.</summary>
    private static Dictionary<string, Func<byte[]>> InstancesB()
    {
        var instances = new Dictionary<string, Func<byte[]>>
        {
            ["Linux kernel (ARM64 Image)"] = () => Zeros(64, (0x38, Text("ARMd")), (16, Le32(64))),
            ["Linux kernel (RISC-V Image)"] = () => Zeros(64, (0x34, B('R', 'S', 'C', 5)), (16, Le32(64))),
            ["Linux kernel version string"] = () => Text("Linux version 5.10.0 (builder)\0"),
            ["U-Boot version string"] = () => Text("U-Boot 2020.01\0"),
            ["UEFI firmware volume"] = () => Zeros(64, (40, Text("_FVH")), (32, Le32(64)), (48, B(56)), (55, B(2))),
            ["Intel flash descriptor"] = () => Zeros(32, (16, B(0x5A, 0xA5, 0xF0, 0x0F)), (20, B(3, 0, 4, 2))),
            ["coreboot CBFS file"] = () => Zeros(40, (0, Text("LARCHIVE")), (8, Be32(8)), (12, Be32(32)), (24, Text("a"))),
            ["ESP32 application image"] = () => Zeros(32, (0, B(0xE9, 1)), (4, Le32(0x40080000)), (24, Le32(0x3F400000)), (28, Le32(16))),
            ["uClinux flat binary (bFLT)"] = () => Zeros(64, (0, Text("bFLT")), (4, Be32(4)), (8, Be32(64)), (12, Be32(64)), (16, Be32(64)), (32, Be32(64))),
            ["PE image"] = Pe32,
            ["ELF"] = Elf64,
            ["Mach-O (32-bit)"] = () => MachOLittle(0xCE),
            ["Mach-O (64-bit)"] = () => MachOLittle(0xCF),
            ["Mach-O (big endian)"] = MachOBig,
            ["Mach-O universal binary"] = () => Zeros(32, (0, B(0xCA, 0xFE, 0xBA, 0xBE)), (4, Be32(1)), (8, Be32(7))),
            ["Java class file"] = () => Zeros(32, (0, B(0xCA, 0xFE, 0xBA, 0xBE)), (6, B(0, 52, 0, 1))),
            ["Dalvik executable (DEX)"] = () => Zeros(112, (0, Text("dex\n039\0")), (32, Le32(112)), (36, Le32(0x70))),
            ["optimized DEX (ODEX)"] = () => Zeros(64, (0, Text("dey\n036\0")), (8, Le32(40))),
            ["Android OAT file"] = () => Zeros(32, (0, Text("oat\n064\0"))),
            ["Android VDEX file"] = () => Zeros(32, (0, Text("vdex021\0"))),
            ["Android ART image"] = () => Zeros(32, (0, Text("art\n057\0"))),
            ["Lua bytecode"] = () => Zeros(32, (0, B(0x1B, 'L', 'u', 'a', 0x54, 0, 0x19, 0x93, 0x0D, 0x0A, 0x1A, 0x0A))),
            ["LLVM bitcode"] = () => Zeros(16, (0, B('B', 'C', 0xC0, 0xDE, 0x35, 0x14))),
            ["LLVM bitcode wrapper"] = () => Zeros(32, (0, B(0xDE, 0xC0, 0x17, 0x0B)), (8, Le32(20)), (12, Le32(4))),
            ["Python bytecode (.pyc)"] = () => Zeros(16, (0, B(0xA7, 0x0D, 0x0D, 0x0A))),
            ["executable script"] = () => Text("#!/bin/sh -e\nexit 0\n"),
            ["Android binary XML"] = () => Zeros(32, (0, B(3, 0, 8, 0)), (4, Le32(32)), (8, B(1, 0, 0x1C, 0))),
            ["DER certificate"] = () => Zeros(260, (0, B(0x30, 0x82, 0x01, 0x00, 0x30, 0x82, 0x00, 0xF0, 0xA0))),
            ["PNG image"] = Png,
            ["GIF image"] = () => Zeros(13, (0, Text("GIF89a")), (6, B(1, 0, 1, 0))),
            ["BMP image"] = () => Zeros(58, (0, Text("BM")), (2, Le32(58)), (10, Le32(54)), (14, Le32(40)), (18, Le32(1)), (22, Le32(1)), (26, B(1, 0, 24, 0))),
            ["WebP image"] = () => Riff("WEBP", "VP8 "),
            ["WAVE audio"] = () => Riff("WAVE", "fmt "),
            ["AVI video"] = () => Riff("AVI ", "LIST"),
            ["MP3 audio with ID3 tag"] = () => Zeros(16, (0, B('I', 'D', '3', 3, 0, 0, 0, 0, 0, 10))),
            ["Ogg stream"] = () => Zeros(27, (0, B('O', 'g', 'g', 'S', 0, 2))),
            ["FLAC audio"] = () => Zeros(42, (0, B('f', 'L', 'a', 'C', 0, 0, 0, 34))),
            ["TrueType font"] = () => Font("\0\u0001\0\0"),
            ["OpenType font"] = () => Font("OTTO"),
            ["WOFF font"] = () => Woff("wOFF"),
            ["WOFF2 font"] = () => Woff("wOF2"),
            ["SQLite database"] = () => Zeros(512, (0, Text("SQLite format 3\0")), (16, B(2, 0)), (21, B(64)), (28, Be32(1))),
            ["VHD disk image"] = () => Zeros(64, (0, Text("conectix")), (12, Be32(0x10000))),
            ["VMDK sparse extent"] = () => Zeros(32, (0, Text("KDMV")), (4, Le32(1))),
            ["QEMU QCOW image"] = () => Zeros(32, (0, B('Q', 'F', 'I', 0xFB)), (4, Be32(3))),
            ["Apple disk image (koly)"] = () => Zeros(32, (0, Text("koly")), (4, Be32(4)), (8, Be32(512))),
        };
        foreach (var label in PemLabels) instances[$"PEM {label.ToLowerInvariant()}"] = () => Pem(label);
        return instances;
    }

    /// <summary>Single-field changes to the instances above, as (offset, value).</summary>
    private static Dictionary<string, (int At, byte Value)[]> MutationsB()
    {
        var mutations = new Dictionary<string, (int At, byte Value)[]>
        {
            ["Linux kernel (ARM64 Image)"] = [(16, 0)],
            ["Linux kernel (RISC-V Image)"] = [(16, 0)],
            ["Linux kernel version string"] = [(14, (byte)'x')],
            ["U-Boot version string"] = [(7, (byte)'x')],
            ["UEFI firmware volume"] = [(55, 0), (48, 0), (32, 0)],
            ["Intel flash descriptor"] = [(20, 0), (22, 3), (21, 2)],
            ["coreboot CBFS file"] = [(15, 0), (8, 0xFF)],
            ["ESP32 application image"] = [(1, 0), (7, 0x60), (28, 0), (19, 1), (13, 1)],
            ["uClinux flat binary (bFLT)"] = [(7, 3), (11, 0), (36, 0xFF)],
            ["PE image"] = [(0x40, (byte)'X'), (0x3C, 0), (0x46, 0), (0x58, 0), (0x14F, 0x7F)],
            ["ELF"] = [(4, 3), (5, 0), (6, 2), (16, 0), (52, 0)],
            ["Mach-O (32-bit)"] = [(4, 0x20), (12, 0), (16, 0), (23, 0x7F)],
            ["Mach-O (64-bit)"] = [(4, 0x20), (12, 0), (16, 0), (23, 0x7F)],
            ["Mach-O (big endian)"] = [(3, 0), (15, 0), (19, 0)],
            ["Mach-O universal binary"] = [(7, 0), (11, 0)],
            ["Java class file"] = [(7, 0), (9, 0)],
            ["Dalvik executable (DEX)"] = [(5, (byte)'2'), (6, (byte)'4'), (7, 1), (36, 0), (32, 0)],
            ["optimized DEX (ODEX)"] = [(7, 1), (8, 0)],
            ["Android OAT file"] = [(4, (byte)'9'), (7, 1)],
            ["Android VDEX file"] = [(4, (byte)'1'), (7, 1)],
            ["Android ART image"] = [(4, (byte)'1'), (7, 1)],
            ["Lua bytecode"] = [(4, 0x50), (5, 1), (6, 0), (11, 0)],
            ["LLVM bitcode"] = [(4, 0)],
            ["LLVM bitcode wrapper"] = [(4, 1), (8, 0), (15, 0x7F)],
            ["Python bytecode (.pyc)"] = [(1, 0), (4, 9)],
            ["executable script"] = [(3, (byte)'x'), (9, 1)],
            ["Android binary XML"] = [(8, 2), (10, 0), (4, 0)],
            ["DER certificate"] = [(8, 0xA1), (4, 0x31), (5, 0x81), (2, 0), (6, 1)],
            ["PNG image"] = [(11, 12), (13, (byte)'X'), (17, 9), (30, 0xAA)],
            ["GIF image"] = [(4, (byte)'8'), (6, 0), (8, 0)],
            ["BMP image"] = [(6, 1), (14, 41), (26, 2), (10, 100), (2, 0)],
            ["WebP image"] = [(0, (byte)'X'), (12, (byte)'X'), (7, 0x7F)],
            ["WAVE audio"] = [(0, (byte)'X'), (12, (byte)'X'), (7, 0x7F)],
            ["AVI video"] = [(0, (byte)'X'), (12, (byte)'X'), (7, 0x7F)],
            ["MP3 audio with ID3 tag"] = [(3, 5), (4, 1), (6, 0x80)],
            ["Ogg stream"] = [(4, 1), (5, 8)],
            ["FLAC audio"] = [(4, 1), (7, 35)],
            ["TrueType font"] = [(5, 2), (7, 17), (12, 0)],
            ["OpenType font"] = [(5, 2), (12, 0)],
            ["WOFF font"] = [(13, 0), (11, 0), (8, 0x7F)],
            ["WOFF2 font"] = [(13, 0), (11, 0), (8, 0x7F)],
            ["SQLite database"] = [(21, 63), (17, 1), (31, 2)],
            ["VHD disk image"] = [(13, 0), (12, 1)],
            ["VMDK sparse extent"] = [(4, 9)],
            ["QEMU QCOW image"] = [(7, 9)],
            ["Apple disk image (koly)"] = [(7, 3), (10, 0)],
        };
        foreach (var label in PemLabels)
        {
            int end = 11 + label.Length + 5;
            mutations[$"PEM {label.ToLowerInvariant()}"] = [(end, (byte)'x'), (end + 2, 1)];
        }
        return mutations;
    }

    [Fact]
    public void Every_instance_of_the_second_half_has_a_header_field_change_that_stops_it()
    {
        var mutations = MutationsB();
        Assert.True(InstancesB().Keys.All(mutations.ContainsKey), "an instance without a mutation");
        Assert.True(mutations.Keys.All(InstancesB().ContainsKey), "a mutation without an instance");
    }

    // RT-326: the Lua check read the version byte alone.
    [Fact]
    public void A_lua_5_1_header_with_its_size_fields_is_reported()
    {
        var d = Zeros(32, (0, B(0x1B, 'L', 'u', 'a', 0x51, 0, 1, 4, 8, 4, 8, 0)));
        Assert.Contains(FirmwareSignatures.Scan(d, 16, default), h => h.Format == "Lua bytecode" && h.Offset == 0);
    }

    // RT-326: the PEM check rejected CRLF line ends and armor headers.
    [Fact]
    public void A_pem_block_with_crlf_line_ends_and_armor_headers_is_reported()
    {
        var d = Text("-----BEGIN PGP MESSAGE-----\r\nVersion: test\r\n\r\nAAAA\r\n-----END PGP MESSAGE-----\r\n");
        Assert.Contains(FirmwareSignatures.Scan(d, 16, default), h => h.Format == "PEM pgp message" && h.Offset == 0);
    }

    // RT-326: the descriptor check read the last byte of its own magic.
    [Fact]
    public void An_intel_flash_descriptor_after_16_erased_bytes_is_reported()
    {
        var d = Zeros(32, (0, Enumerable.Repeat((byte)0xFF, 16).ToArray()), (16, B(0x5A, 0xA5, 0xF0, 0x0F)), (20, B(3, 0, 4, 2)));
        Assert.Contains(FirmwareSignatures.Scan(d, 16, default), h => h.Format == "Intel flash descriptor" && h.Offset == 0);
    }

    // RT-326: the check read the version number two bytes before the file start.
    [Fact]
    public void A_python_bytecode_header_is_reported_at_offset_0_with_its_magic_number()
    {
        var d = Zeros(16, (0, B(0xA7, 0x0D, 0x0D, 0x0A)));
        Assert.Contains(FirmwareSignatures.Scan(d, 16, default),
            h => h.Format == "Python bytecode (.pyc)" && h.Offset == 0 && h.Detail!.Contains("magic 3495"));
    }
}
