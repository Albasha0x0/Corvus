using System.Security.Cryptography;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>
/// A file as summarize_file reads it. A file up to <see cref="StreamAbove"/> bytes is read whole; a larger one keeps only its
/// <see cref="Head"/> in memory and is read through <see cref="OpenRead"/> by the views that stream (pcap, SQLite, zip, HAR,
/// archives); <see cref="Bytes"/> reads it whole on first use, for the formats that need the whole image.
/// <see cref="Kind"/> is Blob.Identify of the head (of the whole file for an MZ image, whose PE checks need it).
/// </summary>
public sealed class FileInput
{
    /// <summary>Files above this size are streamed rather than read whole up front.</summary>
    public const long StreamAbove = 64L << 20;
    /// <summary>Bytes kept from the start of a streamed file.</summary>
    public const int HeadBytes = 1 << 20;

    private byte[]? _bytes;

    /// <summary>A file already in memory.</summary>
    public FileInput(string path, byte[] bytes, string kind)
    {
        Path = path;
        _bytes = bytes;
        Head = bytes;
        Kind = kind;
        Length = bytes.Length;
    }

    private FileInput(string path, long length, byte[] head)
    {
        Path = path;
        Length = length;
        Head = head;
        Kind = Blob.Identify(head);
        Streamed = true;
    }

    public string Path { get; }
    public string Kind { get; }
    public long Length { get; }

    /// <summary>The start of the file (all of it when it is in memory).</summary>
    public byte[] Head { get; }

    /// <summary>True when the file was opened as a stream (over <see cref="StreamAbove"/>); <see cref="Bytes"/> may still read it whole.</summary>
    public bool Streamed { get; }

    /// <summary>The whole file, read on first use when streamed.</summary>
    public byte[] Bytes => _bytes ??= ReadWhole();

    /// <summary>A seekable read-only stream over the file; the caller disposes it.</summary>
    public Stream OpenRead() => _bytes != null
        ? new MemoryStream(_bytes, writable: false)
        : new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16);

    private List<string>? _zipNames;

    /// <summary>Whether a zip's central directory names an entry that matches; read from the stream, nothing extracted.</summary>
    public bool HasZipEntry(Func<string, bool> match)
    {
        if (_zipNames == null)
        {
            try
            {
                using var zip = new System.IO.Compression.ZipArchive(OpenRead(), System.IO.Compression.ZipArchiveMode.Read);
                _zipNames = [.. zip.Entries.Select(e => e.FullName)];
            }
            catch (InvalidDataException) { _zipNames = []; }
        }
        return _zipNames.Any(match);
    }

    /// <summary>The file at <paramref name="full"/>: read whole up to <see cref="StreamAbove"/> bytes, else its head only.</summary>
    public static FileInput Open(string full, long streamAbove = StreamAbove)
    {
        long length = new FileInfo(full).Length;
        if (length <= streamAbove)
        {
            var bytes = File.ReadAllBytes(full);
            return new FileInput(full, bytes, Blob.Identify(bytes));
        }
        var head = new byte[Math.Min(HeadBytes, length)];
        using (var f = File.OpenRead(full)) f.ReadExactly(head);
        var input = new FileInput(full, length, head);
        if (head[0] == 'M' && head[1] == 'Z')
        {
            var bytes = input.Bytes; // the PE checks behind Identify need the whole image
            return new FileInput(full, bytes, Blob.Identify(bytes));
        }
        return input;
    }

    private byte[] ReadWhole()
    {
        if (Length > Math.Min(AnalysisLimits.Default.MaxTotalBytes, Array.MaxLength))
            throw new ToolError(ErrorCode.LimitExceeded, $"{Path} is too large to read whole ({Length:N0} bytes); only the views that stream it apply.");
        return File.ReadAllBytes(Path);
    }

    /// <summary>MD5, SHA-1, SHA-256 and the byte entropy in one pass (streamed in 1 MiB blocks when the file is not in memory).</summary>
    public (string Md5, string Sha1, string Sha256, double Entropy) Hashes(CancellationToken ct)
    {
        if (_bytes != null) return (Blob.Md5(_bytes), Blob.Sha1(_bytes), Blob.Sha256(_bytes), Blob.Entropy(_bytes));
        using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        using var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var counts = new long[256];
        var buffer = new byte[1 << 20];
        long total = 0;
        using var s = OpenRead();
        int n;
        while ((n = s.Read(buffer)) > 0)
        {
            ct.ThrowIfCancellationRequested();
            var block = buffer.AsSpan(0, n);
            md5.AppendData(block);
            sha1.AppendData(block);
            sha256.AppendData(block);
            foreach (var b in block) counts[b]++;
            total += n;
        }
        double e = 0;
        foreach (var c in counts)
        {
            if (c == 0) continue;
            double p = (double)c / total;
            e -= p * Math.Log2(p);
        }
        return (Convert.ToHexStringLower(md5.GetHashAndReset()), Convert.ToHexStringLower(sha1.GetHashAndReset()),
            Convert.ToHexStringLower(sha256.GetHashAndReset()), e);
    }
}
