using System.Security.Cryptography;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>A file as summarize_file reads it: whole up to <see cref="StreamAbove"/> bytes, else its <see cref="Head"/> plus streamed reads.</summary>
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
    public string Kind { get; private set; }
    public long Length { get; }

    /// <summary>The start of the file (all of it when it is in memory).</summary>
    public byte[] Head { get; }

    /// <summary>True when the file was opened as a stream (over <see cref="StreamAbove"/>); <see cref="Bytes"/> may still read it whole.</summary>
    public bool Streamed { get; }

    /// <summary>The view asked for and its paging (summarize_file view=, table=, columns=, offset=, limit=).</summary>
    public FileViewOptions Options { get; set; } = FileViewOptions.None;

    /// <summary>The whole file, read on first use when streamed.</summary>
    public byte[] Bytes => _bytes ??= ReadWhole();

    private byte[]? _image;
    private long? _imageLength;

    /// <summary>A streamed native image up to the end of its last section, without the overlay; the whole file otherwise.</summary>
    public byte[] Image
    {
        get
        {
            if (_image != null) return _image;
            if (Streamed && _bytes == null && Wasm is { } wasm) return _image = wasm.Bytes;
            if (!Streamed || _bytes != null || ImageLength >= Length) return _image = Bytes;
            if (ImageLength > Array.MaxLength)
                throw new ToolError(ErrorCode.LimitExceeded, $"{Path}'s image is too large to read whole ({ImageLength:N0} bytes); only the views that stream it apply.");
            var image = new byte[ImageLength];
            using (var s = OpenRead()) s.ReadExactly(image);
            return _image = image;
        }
    }

    private WasmCompact? _wasm;

    /// <summary>A streamed WebAssembly module without its bulk (data segment contents, large custom sections); null otherwise.</summary>
    public WasmCompact? Wasm
    {
        get
        {
            if (_wasm != null || !Streamed || !WasmModule.IsWasm(Head)) return _wasm;
            using var s = OpenRead();
            return _wasm = WasmCompact.Read(s, default);
        }
    }

    /// <summary>The end of a streamed native image in its file (<see cref="ImageExtent"/>), else the file's length.</summary>
    public long ImageLength => _imageLength ??= Streamed ? ImageExtent.Of(Head, Length, ReadAt) ?? Length : Length;

    /// <summary><paramref name="count"/> bytes at <paramref name="offset"/>.</summary>
    public byte[] ReadAt(long offset, int count)
    {
        if (_bytes != null) return _bytes.AsSpan((int)offset, count).ToArray();
        var b = new byte[count];
        using var s = OpenRead();
        s.Position = offset;
        s.ReadExactly(b);
        return b;
    }

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
        // The PE checks behind Identify read the sections.
        if (head[0] == 'M' && head[1] == 'Z') input.Kind = Blob.Identify(input.Image);
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

/// <summary>summarize_file's view and paging; a view does costly work only when it is the one asked for, or view=all.</summary>
public sealed record FileViewOptions(string View = "overview", string? Table = null, IReadOnlyList<string>? Columns = null, long Offset = 0, int? Limit = null)
{
    public static readonly FileViewOptions None = new();

    /// <summary>An SBOM is to be written, which needs view=dependencies whatever view is shown.</summary>
    public bool Sbom { get; init; }

    /// <summary>A STIX bundle is to be written, which needs every network value, not the summary's first ten.</summary>
    public bool Stix { get; init; }

    /// <summary>view=assets: only the assets bound to this class (short or namespace-qualified name).</summary>
    public string? Script { get; init; }

    /// <summary>Whether <paramref name="view"/> is the one asked for (view=all asks for every view).</summary>
    public bool Wants(string view) => View == view || View == "all" || view == "dependencies" && Sbom;
}
