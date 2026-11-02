using System.Buffers.Binary;
using Corvus.Core.Firmware;
using SharpCompress.Compressors.LZMA;

namespace Corvus.Core.Archives;

/// <summary>A file that is one compressed stream (zlib, gzip, xz, bzip2, LZMA, Zstandard, LZ4, LZFSE, lzop, lzip), inflated to one item.</summary>
internal static class CompressedStream
{
    private const string Zlib = "zlib";

    /// <summary>Formats the signature catalog reports as compressed streams, plus zlib, which the type check reports.</summary>
    internal static readonly string[] Formats =
    [
        "gzip compressed data", "bzip2 compressed data", "xz compressed data", "LZMA compressed data", "Zstandard compressed data", "LZ4 compressed data",
        "LZ4 legacy compressed data", "lzop compressed data", "lzip compressed data", "LZFSE compressed data",
    ];

    /// <summary>The format of a file that starts with a compressed stream, or null.</summary>
    internal static string? Format(ReadOnlySpan<byte> data)
    {
        if (Blob.Identify(data) == Zlib) return Zlib;
        foreach (var format in Formats)
            if (FirmwareSignatures.Holds(data, Containers.KnownLength(data), format)) return format;
        return null;
    }

    /// <summary>The stream inflated within <see cref="AnalysisLimits.MaxItemBytes"/> as one item; null when the data starts with no compressed stream.</summary>
    public static ContainerContents? Open(byte[] data, string name, AnalysisLimits limits, CancellationToken ct)
    {
        if (Format(data) is not { } format) return null;
        // A tar wrapped in one of these is the archive reader's.
        if (format is "gzip compressed data" or "xz compressed data" or "bzip2 compressed data" && WrapsTar(format, data)) return null;
        var label = format == Zlib ? Zlib : format.Replace(" compressed data", "");
        byte[] decoded;
        try { decoded = Decode(format, data, limits.MaxItemBytes); }
        // The decoders of the formats without a shared codec throw their own types on damaged bodies.
        catch (Exception ex) when (ex is not (InvalidDataException or OperationCanceledException or OutOfMemoryException or ToolError))
        {
            return null;
        }
        catch (InvalidDataException ex) when (ex.Message.StartsWith("decodes past", StringComparison.Ordinal))
        {
            throw new ToolError(ErrorCode.LimitExceeded, $"{name}: the {label} stream {ex.Message}.", AnalysisLimits.Reached("item", $"{limits.MaxItemBytes:N0}-byte", 1, name));
        }
        catch (InvalidDataException)
        {
            // A weak magic at offset 0 is not proof of a stream; the reader and carve paths run instead.
            return null;
        }
        // Neither inflater reports a stream cut at a block boundary; the trailer does.
        List<string> notes = TrailerHolds(format, data, decoded) ? [] : [$"{name}: the {label} checksum does not match the {decoded.Length:N0} decoded bytes; the stream is cut or damaged."];
        return new ContainerContents($"{label} stream", [new ExtractedItem(OutputName(name), decoded, $"{label} stream, decompressed")], notes);
    }

    /// <summary>Whether the zlib Adler-32 or the gzip CRC-32 and size trailer matches the decoded bytes; true for the formats whose decoder checks its own.</summary>
    private static bool TrailerHolds(string format, byte[] data, byte[] decoded)
    {
        if (format == Zlib && data.Length >= 4)
        {
            uint a = 1, b = 0;
            foreach (var x in decoded)
            {
                a = (a + x) % 65521;
                b = (b + a) % 65521;
            }
            return BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(data.Length - 4)) == (b << 16 | a);
        }
        if (format == "gzip compressed data")
        {
            // Zero padding after the last member is not part of its trailer; the size field itself may end in zeros.
            var end = data.Length;
            if (GzipTrailerHolds(data.AsSpan(0, end), decoded)) return true;
            while (end > 0 && data[end - 1] == 0) end--;
            return end != data.Length && GzipTrailerHolds(data.AsSpan(0, end), decoded);
        }
        return true;
    }

    /// <summary>Whether the last 8 bytes are the CRC-32 and size of the decoded bytes' tail; a multi-member file's trailer covers its last member.</summary>
    private static bool GzipTrailerHolds(ReadOnlySpan<byte> data, byte[] decoded)
    {
        if (data.Length < 8) return false;
        var size = BinaryPrimitives.ReadUInt32LittleEndian(data[^4..]);
        return size <= decoded.Length
            && BinaryPrimitives.ReadUInt32LittleEndian(data[^8..]) == System.IO.Hashing.Crc32.HashToUInt32(decoded.AsSpan(decoded.Length - (int)size));
    }

    private static bool WrapsTar(string format, byte[] data)
    {
        try
        {
            var head = FsCodec.DecodeHead(format.Split(' ')[0], data, 512);
            return FirmwareSignatures.Holds(head, long.MaxValue, "POSIX tar archive");
        }
        catch (InvalidDataException) { return false; }
    }

    private static readonly string[] StreamExtensions = [".z", ".zlib", ".gz", ".bz2", ".xz", ".lzma", ".zst", ".lz4", ".lzo", ".lz", ".lzfse"];

    /// <summary>The input's file name without its compression suffix, else with ".out".</summary>
    private static string OutputName(string name)
    {
        var file = Path.GetFileName(name);
        foreach (var extension in StreamExtensions)
            if (file.Length > extension.Length && file.EndsWith(extension, StringComparison.OrdinalIgnoreCase)) return file[..^extension.Length];
        return (file.Length == 0 ? "stream" : file) + ".out";
    }

    private static byte[] Decode(string format, byte[] data, long max) => format switch
    {
        Zlib => FsCodec.DecodeStream("zlib", data, max),
        "gzip compressed data" => FsCodec.DecodeStream("gzip", data, max),
        "bzip2 compressed data" => FsCodec.DecodeStream("bzip2", data, max),
        "xz compressed data" => FsCodec.DecodeStream("xz", data, max),
        "LZMA compressed data" => FsCodec.DecodeStream("lzma", data, max),
        "Zstandard compressed data" => FsCodec.DecodeStream("zstd", data, max),
        "LZ4 compressed data" => FsCodec.DecodeStream("lz4", data, max),
        "LZ4 legacy compressed data" => Lz4Legacy(data, max),
        "LZFSE compressed data" => LzfseStream(data, max),
        "lzip compressed data" => Lzip(data, max),
        _ => Lzop(data, max),
    };

    /// <summary>Legacy frames: magic 0x184C2102, then blocks of a 4-byte size and data, each decoding to at most 8 MiB; the magic may repeat.</summary>
    private static byte[] Lz4Legacy(byte[] src, long max)
    {
        const int BlockMax = 8 << 20;
        var output = new MemoryStream();
        var block = new byte[BlockMax];
        int p = 0;
        while (p + 4 <= src.Length)
        {
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(src.AsSpan(p));
            p += 4;
            if (size == 0x184C2102) continue;
            if (size == 0 || size > src.Length - p) throw new InvalidDataException("bad LZ4 block length");
            int n = K4os.Compression.LZ4.LZ4Codec.Decode(src.AsSpan(p, (int)size), block);
            if (n < 0) throw new InvalidDataException("damaged LZ4 block");
            if (output.Length + n > max) throw new InvalidDataException($"decodes past {max:N0} bytes");
            output.Write(block, 0, n);
            p += (int)size;
        }
        if (p != src.Length) throw new InvalidDataException("truncated LZ4 frame");
        return output.ToArray();
    }

    private static byte[] LzfseStream(byte[] src, long max)
    {
        long size = Lzfse.DecodedSize(src) ?? throw new InvalidDataException("damaged LZFSE block headers");
        if (size > max) throw new InvalidDataException($"decodes past {max:N0} bytes");
        var output = new byte[size];
        if (Lzfse.Decode(src, output) != size) throw new InvalidDataException("decodes short of its declared size");
        return output;
    }

    /// <summary>One lzip member: 6-byte header, an LZMA stream with lc=3, lp=0, pb=2, and a 20-byte trailer of CRC-32, data size and member size.</summary>
    private static byte[] Lzip(byte[] src, long max)
    {
        if (src.Length < 6 + 20) throw new InvalidDataException("truncated lzip member");
        ulong dataSize = BinaryPrimitives.ReadUInt64LittleEndian(src.AsSpan(src.Length - 16)), memberSize = BinaryPrimitives.ReadUInt64LittleEndian(src.AsSpan(src.Length - 8));
        if (memberSize != (ulong)src.Length) throw new InvalidDataException("more than one member; only a single member is read");
        if (dataSize > (ulong)max) throw new InvalidDataException($"decodes past {max:N0} bytes");
        int dictBits = src[5] & 31;
        uint dictionary = (1u << dictBits) - (1u << dictBits) / 16 * (uint)(src[5] >> 5);
        var props = new byte[5];
        props[0] = 0x5D;
        BinaryPrimitives.WriteUInt32LittleEndian(props.AsSpan(1), dictionary);
        using var input = new MemoryStream(src, 6, src.Length - 6 - 20, writable: false);
        using var lzma = LzmaStream.Create(props, input, input.Length, (long)dataSize, false);
        var output = Blob.ReadBounded(lzma, max) ?? throw new InvalidDataException($"decodes past {max:N0} bytes");
        if ((ulong)output.Length != dataSize) throw new InvalidDataException("decodes short of its declared size");
        return output;
    }

    // Header field order follows lzop 1.04 (version 0x1040 and later).
    private const uint Adler32Data = 0x1, Adler32Packed = 0x2, ExtraField = 0x40, Crc32Data = 0x100, Crc32Packed = 0x200, Filter = 0x800;

    /// <summary>An lzop file: header, then blocks of an unpacked size, a packed size, optional checksums and data; a block with equal sizes is stored.</summary>
    private static byte[] Lzop(byte[] src, long max)
    {
        var s = new Cursor(src, 9);
        int version = s.U16();
        s.Skip(2);
        if (version >= 0x0940) s.Skip(2);
        int method = s.U8();
        if (version >= 0x0940) s.Skip(1);
        uint flags = s.U32();
        if ((flags & Filter) != 0) s.Skip(4);
        s.Skip(4);
        s.Skip(version >= 0x0940 ? 8 : 4);
        s.Skip(s.U8());
        s.Skip(4);
        if ((flags & ExtraField) != 0)
        {
            s.Skip((int)Math.Min(s.U32(), int.MaxValue));
            s.Skip(4);
        }
        if (method is < 1 or > 3) throw new InvalidDataException($"unsupported lzop method {method}");
        var output = new MemoryStream();
        while (true)
        {
            uint unpacked = s.U32();
            if (unpacked == 0) break;
            uint packed = s.U32();
            if (unpacked > 64 << 20 || packed > unpacked) throw new InvalidDataException("bad lzop block size");
            if (output.Length + unpacked > max) throw new InvalidDataException($"decodes past {max:N0} bytes");
            if ((flags & Adler32Data) != 0) s.Skip(4);
            if ((flags & Crc32Data) != 0) s.Skip(4);
            if (packed < unpacked)
            {
                if ((flags & Adler32Packed) != 0) s.Skip(4);
                if ((flags & Crc32Packed) != 0) s.Skip(4);
            }
            var body = s.Take((int)packed);
            if (packed == unpacked) output.Write(body);
            else
            {
                var block = new byte[unpacked];
                if (FsCodec.Lzo1x(body, block) != unpacked) throw new InvalidDataException("lzop block decodes short of its size");
                output.Write(block);
            }
        }
        return output.ToArray();
    }

    private ref struct Cursor
    {
        private readonly ReadOnlySpan<byte> _d;
        private int _p;

        public Cursor(byte[] d, int p)
        {
            _d = d;
            _p = p;
        }

        public void Skip(int n)
        {
            if (n < 0 || n > _d.Length - _p) throw new InvalidDataException("truncated lzop data");
            _p += n;
        }

        public ReadOnlySpan<byte> Take(int n)
        {
            var span = _d.Slice(_p, Math.Min(n, Math.Max(0, _d.Length - _p)));
            if (span.Length < n) throw new InvalidDataException("truncated lzop data");
            _p += n;
            return span;
        }

        public int U8() => Take(1)[0];
        public int U16() => BinaryPrimitives.ReadUInt16BigEndian(Take(2));
        public uint U32() => BinaryPrimitives.ReadUInt32BigEndian(Take(4));
    }
}
