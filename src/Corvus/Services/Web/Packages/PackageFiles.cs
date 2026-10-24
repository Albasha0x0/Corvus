using System.Formats.Tar;
using System.IO.Compression;


namespace Corvus.Services.Web.Packages;

/// <summary>
/// The files of a package: a zip (.whl, .vsix, .xpi, .zip), a tar.gz (npm tarball, Python sdist), a .crx (its header
/// read, the zip after it), a folder, one manifest file, or an agent configuration file (its repository's agent files). Entries are read within limits: entry count, size per file
/// and in total; a file over the per-file limit is listed with its size and not read.
/// </summary>
internal sealed class PackageFiles
{
    public const int MaxEntries = 50_000;
    public const long MaxFile = 32L << 20, MaxTotal = 512L << 20;

    private readonly Dictionary<string, byte[]?> _files = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> _sizes = new(StringComparer.Ordinal);

    public string Container { get; private set; } = "folder";
    public List<string> Notes { get; } = [];

    /// <summary>The CRX header when the package is a Chrome extension file.</summary>
    public CrxHeader? Crx { get; private set; }

    public IEnumerable<string> Paths => _sizes.Keys;
    public int Count => _sizes.Count;
    public long Size(string path) => _sizes.GetValueOrDefault(path);
    public bool Has(string path) => _sizes.ContainsKey(path);
    public byte[]? Bytes(string path) => _files.GetValueOrDefault(path);

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
        Span<byte> head = stackalloc byte[16];
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
        }
        catch (Exception ex) when (ex is InvalidDataException or EndOfStreamException or FormatException or IOException)
        {
            if (files.Count == 0) return null;
            files.Notes.Add($"{files.Container}: stopped reading at entry {files.Count + 1}: {ex.Message}");
            return files;
        }
        // one manifest file: package.json, manifest.json, setup.py, pyproject.toml, extension.vsixmanifest, PKG-INFO / METADATA
        var name = Path.GetFileName(path);
        if (name is "package.json" or "manifest.json" or "setup.py" or "setup.cfg" or "pyproject.toml" or "extension.vsixmanifest" or "PKG-INFO" or "METADATA")
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

    /// <summary>
    /// The folder an agent configuration file belongs to (the parent of .claude, .cursor, .vscode or .github when it sits
    /// in one), or null when <paramref name="path"/> is no agent configuration file.
    /// </summary>
    internal static string? AgentRoot(string path)
    {
        var parts = Path.GetFullPath(path).Replace('\\', '/').Split('/');
        if (PackageReview.AgentFileKind(string.Join('/', parts[Math.Max(0, parts.Length - 3)..])) == null) return null;
        int folder = Array.FindLastIndex(parts, parts.Length - 1, Math.Min(3, parts.Length), p => PackageReview.AgentFolders.Contains(p, StringComparer.Ordinal));
        return string.Join(Path.DirectorySeparatorChar, parts[..(folder > 0 ? folder : parts.Length - 1)]);
    }

    /// <summary>A repository's agent configuration: its root files, and the agent files in its configuration folders.</summary>
    private void ReadAgentFolder(string root, CancellationToken ct)
    {
        var top = new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        var deep = new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint, RecurseSubdirectories = true };
        var found = Directory.EnumerateFiles(root, "*", top).Select(f => (File: f, Rel: Path.GetFileName(f)))
            .Where(f => f.Rel.EndsWith(".md", StringComparison.OrdinalIgnoreCase) || PackageReview.AgentFileKind(f.Rel) != null);
        foreach (var dir in PackageReview.AgentFolders.Select(d => Path.Combine(root, d)).Where(Directory.Exists))
            found = found.Concat(Directory.EnumerateFiles(dir, "*", deep).Select(f => (File: f, Rel: Path.GetRelativePath(root, f).Replace('\\', '/')))
                .Where(f => PackageReview.AgentFileKind(f.Rel) != null));
        foreach (var (file, rel) in found)
        {
            ct.ThrowIfCancellationRequested();
            Add(rel, new FileInfo(file).Length, () => ReadFile(file));
        }
        Notes.Add($"agent configuration read from {Path.GetFileName(root)}'s root files and its {string.Join(", ", PackageReview.AgentFolders)} folders; instruction files in other subfolders are not read");
    }

    private void Add(string path, long size, Func<byte[]?> read)
    {
        path = path.Replace('\\', '/').TrimStart('/');
        if (path.Length == 0 || path.EndsWith('/')) return;
        if (_sizes.Count >= MaxEntries)
        {
            if (_sizes.Count == MaxEntries) Notes.Add($"over {MaxEntries:N0} files: the rest are not listed");
            return;
        }
        _sizes[path] = size;
        if (size > MaxFile || _total + size > MaxTotal) { _files[path] = null; return; }
        var bytes = read();
        _total += bytes?.Length ?? 0;
        _files[path] = bytes;
    }

    private long _total;

    private void ReadZip(Stream stream, CancellationToken ct)
    {
        using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        foreach (var e in zip.Entries)
        {
            ct.ThrowIfCancellationRequested();
            if (e.FullName.EndsWith('/')) continue;
            Add(e.FullName, e.Length, () => ReadBounded(e.Open(), MaxFile));
        }
    }

    private void ReadTar(Stream stream, CancellationToken ct)
    {
        using var tar = new TarReader(stream, leaveOpen: true);
        while (tar.GetNextEntry(copyData: false) is { } e)
        {
            ct.ThrowIfCancellationRequested();
            if (e.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile or TarEntryType.ContiguousFile)) continue;
            Add(e.Name, e.Length, () => e.DataStream is { } s ? ReadBounded(s, MaxFile) : []);
        }
    }

    private void ReadFolder(string root, CancellationToken ct, string? only = null)
    {
        var options = new EnumerationOptions { RecurseSubdirectories = only == null, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        foreach (var file in Directory.EnumerateFiles(root, only ?? "*", options))
        {
            ct.ThrowIfCancellationRequested();
            var rel = Path.GetRelativePath(root, file).Replace('\\', '/');
            if (rel.StartsWith("node_modules/", StringComparison.Ordinal) || rel.StartsWith(".git/", StringComparison.Ordinal)) continue;
            long size = new FileInfo(file).Length;
            Add(rel, size, () => ReadFile(file));
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
