using System.Buffers.Binary;

namespace Corvus.Core;

/// <summary>
/// Header checks beyond the magic for the file kinds Blob.Identify reports;
/// each takes the start of the file and is false when a field is out of range.
/// </summary>
internal static class FileHeaders
{
    private static uint U16(ReadOnlySpan<byte> b, int at) => BinaryPrimitives.ReadUInt16LittleEndian(b[at..]);
    private static uint U32(ReadOnlySpan<byte> b, int at) => BinaryPrimitives.ReadUInt32LittleEndian(b[at..]);
    private static uint B32(ReadOnlySpan<byte> b, int at) => BinaryPrimitives.ReadUInt32BigEndian(b[at..]);

    /// <summary>
    /// A zip local file header or end-of-central-directory record; a header cut
    /// short is checked as far as it goes.
    /// </summary>
    public static bool Zip(ReadOnlySpan<byte> b)
    {
        if (b.Length >= 22 && b[2] == 5 && b[3] == 6)
            return U16(b, 4) == U16(b, 6) && U16(b, 8) <= U16(b, 10);
        if (b.Length < 10) return false;
        if (U16(b, 4) > 63 || (U16(b, 6) & 0xF010) != 0 || U16(b, 8) is not (0 or 8 or 9 or 12 or 14 or 93 or 95 or 98 or 99)) return false;
        return b.Length < 28 || U16(b, 26) is > 0 and <= 1024;
    }

    /// <summary>A JDK module: four header bytes, then a zip.</summary>
    public static bool Jmod(ReadOnlySpan<byte> b) => b.Length > 4 && Zip(b[4..]);

    /// <summary>
    /// A gzip member header: deflate method, no reserved flags, a defined
    /// extra-flags and operating system byte.
    /// </summary>
    public static bool Gzip(ReadOnlySpan<byte> b) =>
        b.Length >= 18 && b[2] == 8 && (b[3] & 0xE0) == 0 && b[8] is 0 or 2 or 4 && b[9] is <= 13 or 19 or 255;

    /// <summary>
    /// A zlib header without a preset dictionary whose first 4 KB inflate
    /// without an error; a stream cut by the end of the data is valid.
    /// </summary>
    public static bool Zlib(ReadOnlySpan<byte> b)
    {
        if (b.Length < 7 || (b[1] & 0x20) != 0 || ((b[0] << 8) | b[1]) % 31 != 0) return false;
        try
        {
            using var inflate = new System.IO.Compression.DeflateStream(new MemoryStream(b[2..Math.Min(b.Length, 4098)].ToArray()), System.IO.Compression.CompressionMode.Decompress);
            var buffer = new byte[1 << 14];
            int total = 0, n;
            while ((n = inflate.Read(buffer)) > 0) total += n;
            // Short random data must produce output; a stream cut by the end is valid.
            return total > 0 || b.Length >= 64;
        }
        catch (InvalidDataException) { return false; }
    }

    /// <summary>
    /// A 7z signature header: version 0.2 to 0.4 and the start header CRC-32.
    /// </summary>
    public static bool SevenZip(ReadOnlySpan<byte> b) =>
        b.Length >= 32 && b[6] == 0 && b[7] is >= 2 and <= 4 && ~Firmware.Crc.Raw(0xFFFFFFFF, b.Slice(12, 20)) == U32(b, 8);

    /// <summary>
    /// The seven-byte version 4 or eight-byte version 5 RAR signature.
    /// </summary>
    public static bool Rar(ReadOnlySpan<byte> b) =>
        b.Length >= 8 && b[4] == 0x1A && b[5] == 7 && (b[6] == 0 || b[6] == 1 && b[7] == 0);

    /// <summary>
    /// A cabinet header: version 1.3 and its reserved fields clear.
    /// </summary>
    public static bool Cabinet(ReadOnlySpan<byte> b) =>
        b.Length >= 36 && U32(b, 4) == 0 && U32(b, 12) == 0 && U32(b, 20) == 0 && b[24] == 3 && b[25] == 1;

    /// <summary>"%PDF-" and a version number such as "1.7".</summary>
    public static bool Pdf(ReadOnlySpan<byte> b) =>
        b.Length >= 8 && b[..5].SequenceEqual("%PDF-"u8) && b[5] is (byte)'1' or (byte)'2' && b[6] == (byte)'.' && b[7] is >= (byte)'0' and <= (byte)'9';

    /// <summary>
    /// The eight-byte PNG signature and an IHDR chunk of 13 bytes.
    /// </summary>
    public static bool Png(ReadOnlySpan<byte> b) =>
        b.Length >= 16 && b[..8].SequenceEqual((byte[])[0x89, (byte)'P', (byte)'N', (byte)'G', 0x0D, 0x0A, 0x1A, 0x0A])
        && B32(b, 8) == 13 && b.Slice(12, 4).SequenceEqual("IHDR"u8);

    /// <summary>
    /// A JPEG start of image and a defined first segment marker with a length
    /// of at least two.
    /// </summary>
    public static bool Jpeg(ReadOnlySpan<byte> b) =>
        b.Length >= 6 && b[3] is >= 0xE0 and <= 0xEF or 0xFE or 0xDB or 0xC4 or 0xC0 or 0xC1 or 0xC2 && JpegSegmentEnds(b);

    // The first segment is at least 2 bytes and, when read, is followed by a marker.
    private static bool JpegSegmentEnds(ReadOnlySpan<byte> b)
    {
        int length = BinaryPrimitives.ReadUInt16BigEndian(b[4..]);
        if (length < 2) return false;
        if (4 + length < b.Length) return b[4 + length] == 0xFF;
        // A segment running past the data is an application or comment segment that starts with a printable name.
        return b[3] is >= 0xE0 and <= 0xEF or 0xFE && (b.Length < 9 || b[6..9].IndexOfAnyExceptInRange((byte)0x20, (byte)0x7E) < 0);
    }

    /// <summary>A GIF87a or GIF89a header with a nonzero logical screen.</summary>
    public static bool Gif(ReadOnlySpan<byte> b) =>
        b.Length >= 13 && b[..3].SequenceEqual("GIF"u8) && (b[3..6].SequenceEqual("87a"u8) || b[3..6].SequenceEqual("89a"u8)) && U16(b, 6) > 0 && U16(b, 8) > 0;

    /// <summary>
    /// An icon directory with a first entry whose planes, depth and image range
    /// are defined.
    /// </summary>
    public static bool Icon(ReadOnlySpan<byte> b)
    {
        if (b.Length < 22) return false;
        uint count = U16(b, 4), offset = U32(b, 18), size = U32(b, 14);
        return count is >= 1 and <= 256 && b[9] == 0 && U16(b, 10) <= 1 && U16(b, 12) is 0 or 1 or 4 or 8 or 16 or 24 or 32
            && offset >= 6 + 16 * count && size > 0 && (long)offset + size <= int.MaxValue;
    }

    private static uint Half(ReadOnlySpan<byte> b, int at, bool big) => big ? BinaryPrimitives.ReadUInt16BigEndian(b[at..]) : U16(b, at);
    private static uint Word(ReadOnlySpan<byte> b, int at, bool big) => big ? B32(b, at) : U32(b, at);

    /// <summary>
    /// An ELF identification with a defined class, byte order and version, and
    /// a header size that matches the class.
    /// </summary>
    public static bool Elf(ReadOnlySpan<byte> b)
    {
        if (b.Length < 20 || b[4] is not (1 or 2) || b[5] is not (1 or 2) || b[6] != 1) return false;
        bool big = b[5] == 2;
        uint type = Half(b, 16, big);
        if (type is 0 || type > 4 && type < 0xFE00) return false;
        int sizeAt = b[4] == 2 ? 52 : 40;
        return b.Length < sizeAt + 2 || Half(b, sizeAt, big) == (b[4] == 2 ? 64u : 52u);
    }

    /// <summary>
    /// A Mach-O header: a known CPU family, a defined file type and a command
    /// table that fits.
    /// </summary>
    public static bool MachO(ReadOnlySpan<byte> b)
    {
        if (b.Length < 24) return false;
        uint magic = B32(b, 0);
        bool swap = magic is 0xCEFAEDFE or 0xCFFAEDFE;
        if (!swap && magic is not (0xFEEDFACE or 0xFEEDFACF)) return false;
        uint cpu = Word(b, 4, !swap), type = Word(b, 12, !swap), commands = Word(b, 16, !swap), commandBytes = Word(b, 20, !swap);
        return CpuFamily(cpu) && type is >= 1 and <= 12 && commands is >= 1 and <= 4096 && commandBytes >= 8 * commands && commandBytes <= 1 << 24;
    }

    private static bool CpuFamily(uint cpu) => (cpu & 0xFCFFFFFF) is 7 or 12 or 18 && (cpu & 0x03000000) is 0 or 0x01000000 or 0x02000000;

    /// <summary>
    /// A fat Mach-O header: fewer than 64 slices, the first of a Mach-O CPU
    /// family with a plausible alignment, so a Java class is not taken for one.
    /// </summary>
    public static bool MachOFat(ReadOnlySpan<byte> b) =>
        b.Length >= 28 && B32(b, 4) is > 0 and < 64 && CpuFamily(B32(b, 8)) && (B32(b, 0) == 0xCAFEBABE
            ? B32(b, 16) >= 8 + 20 * B32(b, 4) && B32(b, 20) > 0 && B32(b, 24) <= 24
            : B32(b, 0) == 0xCAFEBABF && b.Length >= 36 && B32(b, 16) == 0 && B32(b, 20) >= 8 + 32 * B32(b, 4) && B32(b, 24) == 0 && B32(b, 28) > 0 && B32(b, 32) <= 24);

    /// <summary>
    /// A compound file header: major version 3 or 4, the matching sector size
    /// and the fixed mini sector size.
    /// </summary>
    public static bool Compound(ReadOnlySpan<byte> b) =>
        b.Length >= 512 && U16(b, 28) == 0xFFFE && U16(b, 26) is 3 or 4 && U16(b, 30) == (U16(b, 26) == 3 ? 9u : 12u) && U16(b, 32) == 6
        && U16(b, 34) == 0 && U32(b, 36) == 0;

    /// <summary>
    /// An XALZ header: an assembly index and a decompressed size of 1 byte to 1
    /// GiB.
    /// </summary>
    public static bool Xalz(ReadOnlySpan<byte> b) => b.Length >= 13 && U32(b, 4) < 1 << 16 && U32(b, 8) is > 0 and <= 1 << 30;

    /// <summary>An XAZS header: the XALZ fields and a Zstandard frame.</summary>
    public static bool Xazs(ReadOnlySpan<byte> b) =>
        b.Length >= 16 && U32(b, 4) < 1 << 16 && U32(b, 8) is > 0 and <= 1 << 30 && U32(b, 12) == 0xFD2FB528;

    /// <summary>
    /// An assembly store header: version 1 to 3, no undefined flag bits and a
    /// bounded entry count.
    /// </summary>
    public static bool AssemblyStore(ReadOnlySpan<byte> b) =>
        b.Length >= 20 && (U32(b, 4) & 0xFFFF) is >= 1 and <= 3 && (U32(b, 4) & 0x7F000000) == 0 && U32(b, 8) <= 1 << 20;

    /// <summary>
    /// A resources file header: header version 1 and a header size that fits.
    /// </summary>
    public static bool Resources(ReadOnlySpan<byte> b) => b.Length >= 12 && U32(b, 4) == 1 && U32(b, 8) is >= 1 and < 4096;

    /// <summary>
    /// A metadata root: version 1.1, a clear reserved field and a version
    /// string length in 4-byte units.
    /// </summary>
    public static bool MetadataRoot(ReadOnlySpan<byte> b) =>
        b.Length >= 16 && U16(b, 4) == 1 && U16(b, 6) == 1 && U32(b, 8) == 0 && U32(b, 12) is > 0 and <= 255 && U32(b, 12) % 4 == 0;

    /// <summary>
    /// A WebAssembly binary header: version 1, or the component layer.
    /// </summary>
    public static bool Wasm(ReadOnlySpan<byte> b) =>
        b.Length >= 8 && b[..4].SequenceEqual("\0asm"u8) && (U32(b, 4) == 1 || b[6] == 1 && b[7] == 0 && U16(b, 4) is 0x0A or 0x0D);

    /// <summary>
    /// A webcil header: version 0.0, a section count that fits and a clear
    /// reserved field.
    /// </summary>
    public static bool Webcil(ReadOnlySpan<byte> b) =>
        b.Length >= 28 && U32(b, 4) == 0 && U16(b, 8) is >= 1 and <= 96 && U16(b, 10) == 0;

    private static ReadOnlySpan<byte> MsfSignature => "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\0\0\0"u8;

    /// <summary>
    /// The 32-byte MSF 7.00 signature and a block size of 512 to 4096.
    /// </summary>
    public static bool Pdb(ReadOnlySpan<byte> b) =>
        b.Length >= 36 && b[..32].SequenceEqual(MsfSignature) && U32(b, 32) is 512 or 1024 or 2048 or 4096;
}
