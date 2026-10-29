using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Corvus.Core;


namespace Corvus.Services.Web.Packages;

/// <summary>A package's files from a zip, tar.gz, .gem, .crx, folder, manifest or agent file; files over the limits are listed, not read.</summary>
internal sealed class PackageFiles
{
    public const int MaxEntries = 50_000;
    public const long MaxFile = 32L << 20, MaxTotal = 512L << 20;

    /// <summary>Bytes kept from the end of an image over <see cref="MaxFile"/>, where a compile trailer sits.</summary>
    public const int MaxTail = 8 << 20;

    // Past MaxScan an oversize file is classified by its header alone.
    private const long MaxScan = 256L << 20;
    private const int MaxEmbedded = 4;

    private readonly Dictionary<string, byte[]?> _files = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> _sizes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, byte[]> _heads = new(StringComparer.Ordinal);

    /// <summary>Script text before a Bun or Deno compile trailer in the last <see cref="MaxTail"/> bytes of an image, by path.</summary>
    public Dictionary<string, string> Embedded { get; } = new(StringComparer.Ordinal);

    public string Container { get; private set; } = "folder";
    public List<string> Notes { get; } = [];

    /// <summary>Listed files whose bytes were not read, each with the limit that stopped it.</summary>
    public List<string> NotRead { get; } = [];

    /// <summary>Files past <see cref="MaxEntries"/>: neither listed nor read.</summary>
    public int Unlisted { get; private set; }

    /// <summary>The CRX header when the package is a Chrome extension file.</summary>
    public CrxHeader? Crx { get; private set; }

    public IEnumerable<string> Paths => _sizes.Keys;
    public int Count => _sizes.Count;
    public long Size(string path) => _sizes.GetValueOrDefault(path);
    public bool Has(string path) => _sizes.ContainsKey(path);
    public byte[]? Bytes(string path) => _files.GetValueOrDefault(path);

    /// <summary>Up to the first 8 bytes of a file, read or over the limits; null when not opened.</summary>
    public byte[]? Head(string path) => Bytes(path) is { } b ? b[..Math.Min(8, b.Length)] : _heads.GetValueOrDefault(path);

    /// <summary>ELF, Mach-O or PE from a file's first bytes; null for any other header.</summary>
    internal static string? ImageKind(ReadOnlySpan<byte> head) => head switch
    {
        [0x7F, (byte)'E', (byte)'L', (byte)'F', ..] => "ELF",
        [(byte)'M', (byte)'Z', ..] => "PE",
        [0xCE or 0xCF, 0xFA, 0xED, 0xFE, ..] or [0xFE, 0xED, 0xFA, 0xCE or 0xCF, ..] => "Mach-O",
        // A Java class shares 0xCAFEBABE; its major version in bytes 6 and 7 is 45 or more.
        [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, < 20] => "Mach-O",
        _ => null,
    };

    public string? Text(string path) => Bytes(path) is { } b ? Scripts.ScriptText.Decode(b, out _) : null;

    /// <summary>The package's files, or null when <paramref name="path"/> is not a package container this reads.</summary>
    public static PackageFiles? Open(string path, CancellationToken ct)
    {
        var files = new PackageFiles();
        if (Directory.Exists(path))
        {
            files.Container = "folder";
            files.ReadFolder(path, ct);
            return files;
        }
        if (!File.Exists(path)) return null;
        using var stream = File.OpenRead(path);
        // A tar names its format at offset 257, inside the first 512-byte header.
        Span<byte> head = stackalloc byte[512];
        int n = stream.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
        stream.Position = 0;
        head = head[..n];
        try
        {
            if (head.StartsWith("Cr24"u8))
            {
                files.Container = "crx";
                var header = CrxHeader.Read(stream, out long zipAt);
                files.Crx = header;
                using var rest = new SubStream(stream, zipAt, stream.Length - zipAt);
                files.ReadZip(rest, ct);
                return files;
            }
            if (head.StartsWith("PK\x03\x04"u8))
            {
                files.Container = "zip";
                files.ReadZip(stream, ct);
                return files;
            }
            if (head.Length >= 2 && head[0] == 0x1F && head[1] == 0x8B)
            {
                files.Container = "tar.gz";
                using var gz = new GZipStream(stream, CompressionMode.Decompress);
                files.ReadTar(gz, ct);
                return files.Count > 0 ? files : null;
            }
            if (head.Length >= 262 && head[257..262].SequenceEqual("ustar"u8))
            {
                files.Container = "tar";
                files.ReadTar(stream, ct, gem: true);
                return files.Count > 0 ? files : null;
            }
        }
        catch (Exception ex) when (ex is InvalidDataException or EndOfStreamException or FormatException or IOException)
        {
            if (files.Count == 0) return null;
            files.Notes.Add($"{files.Container}: stopped reading at entry {files.Count + 1}: {ex.Message}");
            return files;
        }
        var name = Path.GetFileName(path);
        if (name is "package.json" or "composer.json" or "manifest.json" or "setup.py" or "setup.cfg" or "pyproject.toml" or "extension.vsixmanifest" or "PKG-INFO" or "METADATA")
        {
            files.Container = "file";
            files.ReadFolder(Path.GetDirectoryName(Path.GetFullPath(path))!, ct, only: name);
            return files;
        }
        if (AgentRoot(path) is { } root)
        {
            files.Container = "folder";
            files.ReadAgentFolder(root, ct);
            return files;
        }
        return null;
    }

    /// <summary>The repository folder of an agent configuration file, or null when <paramref name="path"/> is none.</summary>
    internal static string? AgentRoot(string path)
    {
        var parts = Path.GetFullPath(path).Replace('\\', '/').Split('/');
        if (AgentFiles.Kind(string.Join('/', parts[Math.Max(0, parts.Length - 3)..])) == null) return null;
        int folder = Array.FindLastIndex(parts, parts.Length - 1, Math.Min(3, parts.Length), p => AgentFiles.Folders.Contains(p, StringComparer.Ordinal));
        return string.Join(Path.DirectorySeparatorChar, parts[..(folder > 0 ? folder : parts.Length - 1)]);
    }

    /// <summary>A repository's agent configuration: its root files, and the agent files in its configuration folders.</summary>
    private void ReadAgentFolder(string root, CancellationToken ct)
    {
        var top = new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        var deep = new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint, RecurseSubdirectories = true };
        var found = Directory.EnumerateFiles(root, "*", top).Select(f => (File: f, Rel: Path.GetFileName(f)))
            .Where(f => f.Rel.EndsWith(".md", StringComparison.OrdinalIgnoreCase) || AgentFiles.Kind(f.Rel) != null);
        foreach (var dir in AgentFiles.Folders.Select(d => Path.Combine(root, d)).Where(Directory.Exists))
            found = found.Concat(Directory.EnumerateFiles(dir, "*", deep).Select(f => (File: f, Rel: Path.GetRelativePath(root, f).Replace('\\', '/')))
                .Where(f => AgentFiles.Kind(f.Rel) != null));
        foreach (var (file, rel) in found)
        {
            ct.ThrowIfCancellationRequested();
            Add(rel, new FileInfo(file).Length, () => ReadFile(file), () => File.OpenRead(file));
        }
        Notes.Add($"agent configuration read from {Path.GetFileName(root)} root files and {string.Join(", ", AgentFiles.Folders)}; other subfolders not read");
    }

    private void Add(string path, long size, Func<byte[]?> read, Func<Stream?>? open = null)
    {
        path = path.Replace('\\', '/').TrimStart('/');
        if (path.Length == 0 || path.EndsWith('/')) return;
        if (_sizes.Count >= MaxEntries)
        {
            if (Unlisted++ == 0) Notes.Add($"over {MaxEntries:N0} files: the rest are not listed");
            return;
        }
        _sizes[path] = size;
        if (size > MaxFile || _total + size > MaxTotal)
        {
            _files[path] = null;
            if (size > MaxFile && open != null) ReadEnds(path, size, open);
            var kind = _heads.TryGetValue(path, out var head) && ImageKind(head) is { } k ? $", {k} image" : "";
            NotRead.Add(size > MaxFile ? $"{path} (over {MaxFile >> 20} MiB{kind})" : $"{path} (past {MaxTotal >> 20} MiB read)");
            return;
        }
        var bytes = read();
        _total += bytes?.Length ?? 0;
        _files[path] = bytes;
        if (bytes != null && ImageKind(bytes) != null) EmbeddedScript(path, bytes.AsSpan(Math.Max(0, bytes.Length - MaxTail)));
    }

    private long _total;

    private static readonly byte[][] CompileTrailers = ["\n---- Bun! ----\n"u8.ToArray(), "d3n0l4nd"u8.ToArray()];

    // Streams the file once, keeping its header and a ring of its last MaxTail bytes.
    private void ReadEnds(string path, long size, Func<Stream?> open)
    {
        try
        {
            using var s = open();
            if (s == null) return;
            var head = new byte[8];
            if (s.ReadAtLeast(head, head.Length, throwOnEndOfStream: false) < head.Length) return;
            _heads[path] = head;
            if (ImageKind(head) == null || size > MaxScan || Embedded.Count >= MaxEmbedded) return;
            if (s.CanSeek) s.Position = size - MaxTail;
            var ring = new byte[MaxTail];
            long total = 0;
            int n;
            while ((n = s.Read(ring, (int)(total % MaxTail), (int)Math.Min(MaxTail - total % MaxTail, 81920))) > 0) total += n;
            int start = (int)(total % MaxTail);
            EmbeddedScript(path, total < MaxTail ? ring[..start] : [.. ring[start..], .. ring[..start]]);
            if (Embedded.ContainsKey(path)) Notes.Add($"{path}: script before its compile trailer read from the last {MaxTail >> 20} MiB");
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException) { }
    }

    private void EmbeddedScript(string path, ReadOnlySpan<byte> tail)
    {
        int at = -1;
        foreach (var t in CompileTrailers) at = Math.Max(at, tail.LastIndexOf(t));
        if (at > 0 && Embedded.Count < MaxEmbedded) Embedded[path] = Encoding.UTF8.GetString(tail[..at]);
    }

    private void ReadZip(Stream stream, CancellationToken ct)
    {
        using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        foreach (var e in zip.Entries)
        {
            ct.ThrowIfCancellationRequested();
            if (e.FullName.EndsWith('/')) continue;
            Add(e.FullName, e.Length, () => ReadBounded(e.Open(), MaxFile), e.Open);
        }
    }

    /// <summary>The gem's data.tar.gz members are listed under this folder.</summary>
    public const string GemData = "data.tar.gz/";

    /// <summary>The gem's gemspec, unpacked from metadata.gz.</summary>
    public const string GemSpec = "metadata.gz";

    // With gem, metadata.gz is unpacked in place and data.tar.gz's members are read under GemData.
    private void ReadTar(Stream stream, CancellationToken ct, bool gem = false, string prefix = "")
    {
        using var tar = new TarReader(stream, leaveOpen: true);
        while (tar.GetNextEntry(copyData: false) is { } e)
        {
            ct.ThrowIfCancellationRequested();
            if (e.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile or TarEntryType.ContiguousFile)) continue;
            if (gem && e.Name == GemSpec && e.DataStream is { } spec)
            {
                Container = "gem";
                var bytes = ReadBounded(new GZipStream(spec, CompressionMode.Decompress), MaxFile);
                Add(GemSpec, bytes?.Length ?? 0, () => bytes);
                if (bytes == null) NotRead.Add($"{GemSpec} (gemspec over {MaxFile >> 20} MiB unpacked)");
                continue;
            }
            if (gem && e.Name == "data.tar.gz" && e.DataStream is { } data)
            {
                Container = "gem";
                using var gz = new GZipStream(data, CompressionMode.Decompress, leaveOpen: true);
                ReadTar(gz, ct, prefix: GemData);
                continue;
            }
            Add(prefix + e.Name, e.Length, () => e.DataStream is { } s ? ReadBounded(s, MaxFile) : [], () => e.DataStream);
        }
    }

    private void ReadFolder(string root, CancellationToken ct, string? only = null)
    {
        var options = new EnumerationOptions { RecurseSubdirectories = only == null, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        foreach (var file in Directory.EnumerateFiles(root, only ?? "*", options))
        {
            ct.ThrowIfCancellationRequested();
            var rel = Path.GetRelativePath(root, file).Replace('\\', '/');
            if (rel.StartsWith("node_modules/", StringComparison.Ordinal)) continue;
            // Of .git, only the config and hooks run anything.
            if (rel.StartsWith(".git/", StringComparison.Ordinal) && rel != ".git/config"
                && !(rel.StartsWith(".git/hooks/", StringComparison.Ordinal) && rel.IndexOf('/', 11) < 0 && !rel.EndsWith(".sample", StringComparison.Ordinal))) continue;
            long size = new FileInfo(file).Length;
            Add(rel, size, () => ReadFile(file), () => File.OpenRead(file));
        }
    }

    private static byte[]? ReadFile(string path)
    {
        try { return File.ReadAllBytes(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    private static byte[]? ReadBounded(Stream s, long max)
    {
        using (s)
        {
            using var copy = new MemoryStream();
            var buffer = new byte[81920];
            int n;
            while ((n = s.Read(buffer, 0, buffer.Length)) > 0)
            {
                if (copy.Length + n > max) return null;
                copy.Write(buffer, 0, n);
            }
            return copy.ToArray();
        }
    }

    /// <summary>A read-only window of another stream (the zip after a CRX header).</summary>
    private sealed class SubStream(Stream inner, long start, long length) : Stream
    {
        private long _position;
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position { get => _position; set => _position = Math.Clamp(value, 0, length); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_position >= length) return 0;
            inner.Position = start + _position;
            int n = inner.Read(buffer, offset, (int)Math.Min(count, length - _position));
            _position += n;
            return n;
        }
        public override long Seek(long offset, SeekOrigin origin) => Position = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            _ => length + offset,
        };
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
