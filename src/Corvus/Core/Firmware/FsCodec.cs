using System.IO.Compression;
using SharpCompress.Compressors.LZMA;
using SharpCompress.Compressors.Xz;

namespace Corvus.Core.Firmware;

/// <summary>
/// The block and stream codecs of firmware filesystems and boot images: zlib, raw deflate, gzip, LZMA (the "alone" header),
/// xz, LZO1X, LZ4 (block and frame), Zstandard and bzip2. Damaged input is an <see cref="InvalidDataException"/>.
/// </summary>
internal static class FsCodec
{
    /// <summary>Decodes one block into <paramref name="dst"/>; returns the bytes written.</summary>
    public static int Decode(string codec, ReadOnlySpan<byte> src, Span<byte> dst)
    {
        try
        {
            switch (codec)
            {
                case "none":
                    if (src.Length > dst.Length) throw new InvalidDataException("stored block larger than its slot");
                    src.CopyTo(dst);
                    return src.Length;
                case "lzo": return Lzo1x(src, dst);
                case "lz4":
                    int n = K4os.Compression.LZ4.LZ4Codec.Decode(src, dst);
                    return n >= 0 ? n : throw new InvalidDataException("damaged LZ4 block");
                case "zstd":
                    using (var z = new ZstdSharp.Decompressor()) return z.Unwrap(src, dst);
                default:
                    using (var s = Open(codec, new MemoryStream(src.ToArray(), writable: false), dst.Length))
                    {
                        int total = 0;
                        for (int got; total < dst.Length && (got = s.Read(dst[total..])) > 0;) total += got;
                        return total;
                    }
            }
        }
        catch (Exception ex) when (ex is not (InvalidDataException or OperationCanceledException or OutOfMemoryException))
        {
            throw new InvalidDataException($"damaged {codec} data: {ex.Message}", ex);
        }
    }

    /// <summary>A whole stream decoded (its size not known up front), at most <paramref name="max"/> bytes.</summary>
    public static byte[] DecodeStream(string codec, ReadOnlySpan<byte> src, long max)
    {
        try
        {
            if (codec == "lz4") return Lz4Frame(src, max);
            if (codec == "zstd")
            {
                using var zs = new ZstdSharp.DecompressionStream(new MemoryStream(src.ToArray(), writable: false));
                return Blob.ReadBounded(zs, max) ?? throw new InvalidDataException($"decodes past {max:N0} bytes");
            }
            using var s = Open(codec, new MemoryStream(src.ToArray(), writable: false), -1);
            return Blob.ReadBounded(s, max) ?? throw new InvalidDataException($"decodes past {max:N0} bytes");
        }
        catch (Exception ex) when (ex is not (InvalidDataException or OperationCanceledException or OutOfMemoryException))
        {
            throw new InvalidDataException($"damaged {codec} data: {ex.Message}", ex);
        }
    }

    private static Stream Open(string codec, MemoryStream input, long outputSize) => codec switch
    {
        "zlib" => new ZLibStream(input, CompressionMode.Decompress),
        "deflate" => new DeflateStream(input, CompressionMode.Decompress),
        "gzip" => new GZipStream(input, CompressionMode.Decompress),
        "xz" => new XZStream(input),
        "bzip2" => SharpCompress.Compressors.BZip2.BZip2Stream.Create(input, SharpCompress.Compressors.CompressionMode.Decompress, false, false, false),
        "lzma" => Lzma(input, outputSize),
        _ => throw new InvalidDataException($"no {codec} decoder"),
    };

    /// <summary>LZMA with the 13-byte "alone" header: 5 property bytes and the unpacked size (all ones when unknown).</summary>
    private static Stream Lzma(MemoryStream input, long outputSize)
    {
        var header = new byte[13];
        input.ReadExactly(header);
        long declared = BitConverter.ToInt64(header, 5);
        long size = declared >= 0 ? declared : outputSize;
        return LzmaStream.Create(header[..5], input, input.Length - 13, size, false);
    }

    /// <summary>An LZ4 frame (magic 0x184D2204): its blocks, each decoded with the 64 KiB before it as the dictionary.</summary>
    private static byte[] Lz4Frame(ReadOnlySpan<byte> src, long max)
    {
        if (src.Length < 7 || System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(src) != 0x184D2204) throw new InvalidDataException("no LZ4 frame header");
        byte flags = src[4];
        int blockMax = 1 << (8 + 2 * ((src[5] >> 4) & 7));
        if (blockMax < 1 << 16) throw new InvalidDataException("bad LZ4 block size");
        int p = 6 + ((flags & 8) != 0 ? 8 : 0) + ((flags & 1) != 0 ? 4 : 0) + 1;
        bool blockSums = (flags & 0x10) != 0;
        var output = new MemoryStream();
        var window = new byte[blockMax + (64 << 10)];
        int kept = 0; // dictionary bytes at the start of window
        while (true)
        {
            if (p + 4 > src.Length) throw new InvalidDataException("truncated LZ4 frame");
            uint size = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(src[p..]);
            p += 4;
            if (size == 0) break;
            int length = (int)(size & 0x7FFFFFFF);
            if (length > blockMax || p + length > src.Length) throw new InvalidDataException("bad LZ4 block length");
            int n;
            if ((size & 0x80000000) != 0) { src.Slice(p, length).CopyTo(window.AsSpan(kept)); n = length; }
            else if ((n = K4os.Compression.LZ4.LZ4Codec.Decode(src.Slice(p, length), window.AsSpan(kept, blockMax), window.AsSpan(0, kept))) < 0)
                throw new InvalidDataException("damaged LZ4 block");
            if (output.Length + n > max) throw new InvalidDataException($"decodes past {max:N0} bytes");
            output.Write(window, kept, n);
            int next = Math.Min(64 << 10, kept + n);
            Buffer.BlockCopy(window, kept + n - next, window, 0, next);
            kept = next;
            p += length + (blockSums ? 4 : 0);
        }
        return output.ToArray();
    }

    /// <summary>LZO1X decompression (the format of lzo1x_1 and lzo1x_999 output), bounds-checked.</summary>
    public static int Lzo1x(ReadOnlySpan<byte> src, Span<byte> dst)
    {
        int ip = 0, op = 0, t, m;
        try
        {
            if (src[0] > 17)
            {
                t = src[ip++] - 17;
                if (t < 4) goto MatchNext;
                Copy(src, ref ip, dst, ref op, t);
                goto FirstLiteralRun;
            }
        Loop:
            t = src[ip++];
            if (t >= 16) goto Match;
            if (t == 0)
            {
                while (src[ip] == 0) { t += 255; ip++; }
                t += 15 + src[ip++];
            }
            Copy(src, ref ip, dst, ref op, t + 3);
        FirstLiteralRun:
            t = src[ip++];
            if (t >= 16) goto Match;
            m = op - (1 + 0x0800) - (t >> 2) - (src[ip++] << 2);
            Back(dst, ref op, m, 3);
            goto MatchDone;
        Match:
            if (t >= 64)
            {
                m = op - 1 - ((t >> 2) & 7) - (src[ip++] << 3);
                t = (t >> 5) - 1;
            }
            else if (t >= 32)
            {
                t &= 31;
                if (t == 0)
                {
                    while (src[ip] == 0) { t += 255; ip++; }
                    t += 31 + src[ip++];
                }
                m = op - 1 - ((src[ip] >> 2) + (src[ip + 1] << 6));
                ip += 2;
            }
            else if (t >= 16)
            {
                m = op - ((t & 8) << 11);
                t &= 7;
                if (t == 0)
                {
                    while (src[ip] == 0) { t += 255; ip++; }
                    t += 7 + src[ip++];
                }
                m -= (src[ip] >> 2) + (src[ip + 1] << 6);
                ip += 2;
                if (m == op) return op; // end of stream
                m -= 0x4000;
            }
            else
            {
                m = op - 1 - (t >> 2) - (src[ip++] << 2);
                Back(dst, ref op, m, 2);
                goto MatchDone;
            }
            Back(dst, ref op, m, t + 2);
        MatchDone:
            t = src[ip - 2] & 3;
            if (t == 0) goto Loop;
        MatchNext:
            Copy(src, ref ip, dst, ref op, t);
            t = src[ip++];
            goto Match;
        }
        catch (IndexOutOfRangeException) { throw new InvalidDataException("damaged LZO data"); }
        catch (ArgumentOutOfRangeException) { throw new InvalidDataException("damaged LZO data"); }
    }

    private static void Copy(ReadOnlySpan<byte> src, ref int ip, Span<byte> dst, ref int op, int n)
    {
        src.Slice(ip, n).CopyTo(dst.Slice(op, n));
        ip += n;
        op += n;
    }

    /// <summary>A match: <paramref name="n"/> bytes from <paramref name="from"/>, byte by byte since the ranges may overlap.</summary>
    private static void Back(Span<byte> dst, ref int op, int from, int n)
    {
        if (from < 0 || n > dst.Length - op) throw new InvalidDataException("LZO match outside the output");
        for (int i = 0; i < n; i++) dst[op + i] = dst[from + i];
        op += n;
    }
}
