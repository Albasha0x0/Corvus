using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Archives;
using Corvus.Core.Firmware;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Files that are one compressed stream, built here per format: unpack_container writes the inflated bytes as one file.</summary>
public sealed class CompressedStreamTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    private static readonly byte[] Payload = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Range(0, 300).Select(i => $"record {i}: value {i * 7 % 101}\n")));

    private static readonly byte[] Short = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("corvus xz fixture ", 8)));

    // Written by the Python lzma module: an xz file with a CRC-32 check, an LZMA file with a 64 KiB dictionary, and a lzip member of Short.
    private const string XzHex = "fd377a585a0000016922de360200210116000000742fe5a3e0008f00195d00319bcaac4a7690c99b6e4bb3bbb715a1f00ca7a9c58bf5000000000000444b2d7b0001319001000000a040c9653e300d8b020000000001595a";
    private const string LzipHex = "4c5a4950011000319bcaac4a7690c99b6e4bb3bbb715a1f00ca7a9c58f3e16e7fffe749000444b2d7b90000000000000003900000000000000";

    private const string LzmaHex = "5d00000100ffffffffffffffff00319bcaac4a7690c99b6e4bb3bbb715a1f00ca7a9c58f3e16e7fffe749000";

    private static byte[] Compress(Func<Stream, Stream> wrap, byte[] data)
    {
        var o = new MemoryStream();
        using (var z = wrap(o)) z.Write(data);
        return o.ToArray();
    }

    private static byte[] Lz4Frame(byte[] data)
    {
        byte[] descriptor = [0x60, 0x40];
        byte check = (byte)(System.IO.Hashing.XxHash32.HashToUInt32(descriptor) >> 8);
        var size = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(size, (uint)data.Length | 0x80000000);
        return [0x04, 0x22, 0x4D, 0x18, .. descriptor, check, .. size, .. data, 0, 0, 0, 0];
    }

    private static byte[] Lz4Legacy(byte[] data)
    {
        var block = new byte[K4os.Compression.LZ4.LZ4Codec.MaximumOutputSize(data.Length)];
        int n = K4os.Compression.LZ4.LZ4Codec.Encode(data, block);
        var size = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(size, (uint)n);
        return [0x02, 0x21, 0x4C, 0x18, .. size, .. block.AsSpan(0, n).ToArray()];
    }

    /// <summary>An lzop file whose one block is a four-byte literal run, then an eight-byte match at distance 4.</summary>
    private static byte[] Lzop(out byte[] expected)
    {
        expected = "abcdabcdabcd"u8.ToArray();
        byte[] block = [21, (byte)'a', (byte)'b', (byte)'c', (byte)'d', 0xEC, 0x00, 0x11, 0x00, 0x00];
        byte[] magic = [0x89, 0x4C, 0x5A, 0x4F, 0x00, 0x0D, 0x0A, 0x1A, 0x0A];
        // Version 0x1040, library 0x2080, needed 0x0940, method 1, level 1, no flags; then mode, mtime, name length and checksum, all zero.
        byte[] header = [.. magic, 0x10, 0x40, 0x20, 0x80, 0x09, 0x40, 1, 1, 0, 0, 0, 0, .. new byte[17]];
        return [.. header, 0, 0, 0, 12, 0, 0, 0, (byte)block.Length, .. block, 0, 0, 0, 0];
    }

    private static IEnumerable<(string Format, byte[] Stream, byte[] Expected)> Fixtures()
    {
        yield return ("zlib", Compress(o => new ZLibStream(o, CompressionLevel.SmallestSize), Payload), Payload);
        yield return ("gzip compressed data", Compress(o => new GZipStream(o, CompressionLevel.SmallestSize), Payload), Payload);
        yield return ("bzip2 compressed data", Compress(o => SharpCompress.Compressors.BZip2.BZip2Stream.Create(o, SharpCompress.Compressors.CompressionMode.Compress, false, false, true), Payload), Payload);
        yield return ("xz compressed data", Convert.FromHexString(XzHex), Short);
        yield return ("LZMA compressed data", Convert.FromHexString(LzmaHex), Short);
        yield return ("Zstandard compressed data", new ZstdSharp.Compressor().Wrap(Payload).ToArray(), Payload);
        yield return ("LZ4 compressed data", Lz4Frame(Payload.AsSpan(0, 4000).ToArray()), Payload.AsSpan(0, 4000).ToArray());
        yield return ("LZ4 legacy compressed data", Lz4Legacy(Payload), Payload);
        yield return ("lzop compressed data", Lzop(out var lzop), lzop);
        yield return ("lzip compressed data", Convert.FromHexString(LzipHex), Short);
        yield return ("LZFSE compressed data", LzfseTests.Fixture("text.lzfse"), LzfseTests.LedgerText(300014));
    }

    public static TheoryData<string> Names() => [.. Fixtures().Select(f => f.Format)];

    // The catalog is the signature table plus zlib; a new compressed signature fails here until it has a fixture.
    [Fact]
    public void Every_compressed_stream_signature_has_a_fixture()
    {
        var reported = FirmwareSignatures.All.Where(s => s.Kind == SignatureKind.Compressed).Select(s => s.Format).Append("zlib").Order();
        Assert.Equal(reported, Fixtures().Select(f => f.Format).Order());
        Assert.Equal(reported, CompressedStream.Formats.Append("zlib").Order());
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void A_compressed_stream_file_unpacks_to_its_bytes(string format)
    {
        var (_, stream, expected) = Fixtures().Single(f => f.Format == format);
        Assert.Equal(format, CompressedStream.Format(stream));
        var path = _dir.File("sample.bin");
        File.WriteAllBytes(path, stream);
        var report = new UnpackService(_workspace).Unpack(path, _dir.File("out-" + Math.Abs(format.GetHashCode())), load: false, AnalysisLimits.Default, default);
        var file = Assert.Single(report.Files);
        Assert.Equal(expected, File.ReadAllBytes(file.Path));
        Assert.Equal("sample.bin.out", Path.GetFileName(file.Path));
    }

    [Fact]
    public void The_compression_suffix_is_dropped_from_the_output_name()
    {
        var path = _dir.File("records.txt.zst");
        File.WriteAllBytes(path, new ZstdSharp.Compressor().Wrap(Payload).ToArray());
        var report = new UnpackService(_workspace).Unpack(path, _dir.File("out"), load: false, AnalysisLimits.Default, default);
        Assert.Equal("records.txt", Path.GetFileName(Assert.Single(report.Files).Path));
    }

    [Fact]
    public void A_stream_past_the_item_limit_is_refused_and_names_the_limit()
    {
        var path = _dir.File("big.z");
        File.WriteAllBytes(path, Compress(o => new ZLibStream(o, CompressionLevel.Fastest), new byte[1 << 20]));
        var error = Assert.Throws<ToolError>(() => new UnpackService(_workspace).Unpack(path, _dir.File("out"), load: false,
            new AnalysisLimits { MaxItemBytes = 1 << 16 }, default));
        Assert.Equal(ErrorCode.LimitExceeded, error.Code);
        Assert.Contains("item limit", error.Remediation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_cut_stream_keeps_its_decoded_bytes_and_notes_the_checksum()
    {
        var noise = new byte[60_000];
        new Random(7).NextBytes(noise);
        var stream = Compress(o => new ZLibStream(o, CompressionLevel.Fastest), noise);
        var c = Containers.Open(stream[..(stream.Length / 2)], "cut.z", AnalysisLimits.Default, default);
        Assert.NotEmpty(Assert.Single(c.Items).Bytes);
        Assert.Contains("checksum does not match", Assert.Single(c.Notes));
        Assert.Empty(Containers.Open(stream, "whole.z", AnalysisLimits.Default, default).Notes);
    }

    [Fact]
    public void A_compressed_tar_stays_an_archive()
    {
        var tar = new MemoryStream();
        using (var w = new System.Formats.Tar.TarWriter(tar, System.Formats.Tar.TarEntryFormat.Gnu, leaveOpen: true))
            w.WriteEntry(new System.Formats.Tar.GnuTarEntry(System.Formats.Tar.TarEntryType.RegularFile, "a.txt") { DataStream = new MemoryStream(Payload) });
        var c = Containers.Open(Compress(o => new GZipStream(o, CompressionLevel.Fastest), tar.ToArray()), "a.tar.gz", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("tar.gz", c.Kind);
        Assert.Equal("a.txt", Assert.Single(c.Items).Name);
    }

    [Theory]
    [InlineData(0x78, 0xDA)]
    [InlineData(0x1F, 0x8B)]
    [InlineData(0x5D, 0x00)]
    [InlineData(0x28, 0xB5)]
    public void A_magic_with_a_garbage_body_is_not_a_stream_and_does_not_throw(int first, int second)
    {
        var junk = new byte[4096];
        new Random(3).NextBytes(junk);
        junk[0] = (byte)first;
        junk[1] = (byte)second;
        var c = Containers.Open(junk, "blob.bin", AnalysisLimits.Default, default);
        Assert.DoesNotContain("stream", c.Kind);
    }

    [Fact]
    public void A_multi_member_gzip_decodes_whole_without_a_checksum_note()
    {
        var joined = Compress(o => new GZipStream(o, CompressionLevel.Fastest), Payload)
            .Concat(Compress(o => new GZipStream(o, CompressionLevel.Fastest), Short)).ToArray();
        var c = Containers.Open(joined, "two.gz", AnalysisLimits.Default, default);
        Assert.Equal([.. Payload, .. Short], Assert.Single(c.Items).Bytes);
        Assert.Empty(c.Notes);
    }

    [Fact]
    public void A_gzip_with_trailing_zero_padding_has_no_checksum_note()
    {
        var padded = Compress(o => new GZipStream(o, CompressionLevel.Fastest), Payload).Concat(new byte[16]).ToArray();
        Assert.Empty(Containers.Open(padded, "padded.gz", AnalysisLimits.Default, default).Notes);
    }

    [Fact]
    [FuzzEntry(typeof(CompressedStream))]
    public void Fuzzed_streams_never_throw_past_a_tool_error()
    {
        foreach (var (_, stream, _) in Fixtures())
        {
            var failures = FormatFuzz.Run(stream, b => { try { CompressedStream.Open(b, "x.bin", AnalysisLimits.Default, default); } catch (ToolError) { } }, 100);
            Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
        }
    }
}
