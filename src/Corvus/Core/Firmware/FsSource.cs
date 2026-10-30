using Corvus.Core.Archives;

namespace Corvus.Core.Firmware;

/// <summary>Random-access reads of one filesystem image: a region of a seekable stream, or bytes in memory.</summary>
internal sealed class FsSource
{
    private readonly Stream _stream;
    private readonly long _base;

    public FsSource(Stream stream, long @base, long length, string name)
    {
        _stream = stream;
        _base = @base;
        Length = Math.Max(0, Math.Min(length, stream.Length - @base));
        Name = name;
    }

    public static FsSource Of(byte[] data, string name) => new(new MemoryStream(data, writable: false), 0, data.Length, name);

    public long Length { get; }
    public string Name { get; }

    /// <summary><paramref name="n"/> bytes at <paramref name="at"/>; a read past the end is malformed input.</summary>
    public byte[] Read(long at, int n)
    {
        if (at < 0 || n < 0 || at > Length - n) throw Malformed($"a structure at 0x{at:X} ({n:N0} bytes) runs past the end of the image");
        var b = new byte[n];
        _stream.Position = _base + at;
        _stream.ReadExactly(b);
        return b;
    }

    /// <summary>Fills <paramref name="into"/> from <paramref name="at"/>; a read past the end is malformed input.</summary>
    public void Read(long at, Span<byte> into)
    {
        if (at < 0 || at > Length - into.Length) throw Malformed($"a structure at 0x{at:X} ({into.Length:N0} bytes) runs past the end of the image");
        _stream.Position = _base + at;
        _stream.ReadExactly(into);
    }

    /// <summary>The bytes from <paramref name="at"/> to at most <paramref name="n"/>, shorter at the end of the image.</summary>
    public byte[] ReadUpTo(long at, int n) => at < 0 || at >= Length ? [] : Read(at, (int)Math.Min(n, Length - at));

    public ToolError Malformed(string what) => new(ErrorCode.MalformedInput, $"{Name}: {what}.");
}

/// <summary>One filesystem image as a container level; binaries and packages are extracted, an unreadable file becomes a note.</summary>
internal sealed class FsTree(string kind, bool allFiles, AnalysisLimits limits, CancellationToken ct)
{
    private readonly List<ExtractedItem> _items = [];
    private readonly List<ContainerEntry> _entries = [];
    private long _total;
    private int _unread;
    private readonly List<string> _hidden = [];

    public List<string> Notes { get; } = [];
    public string Kind => kind;
    public CancellationToken Token => ct;
    public AnalysisLimits Limits => limits;

    /// <summary>Directory nesting kept; deeper trees are cut with a note (a loop in corrupt metadata ends here too).</summary>
    public const int MaxDepth = 64;

    public int Count => _entries.Count;

    /// <summary>Paths extracted even without allFiles: small metadata a reader describes the image from.</summary>
    public Func<string, bool>? Keep { get; init; }

    /// <summary>A name read from the image that is usable as one path component.</summary>
    public static bool UsableName(string name) => name.Length > 0 && name is not ("." or "..") && name.IndexOfAny(['/', '\0']) < 0;

    /// <summary>Bytes read to classify a file before reading all of it (as much as a streamed file's head).</summary>
    private const int Head = 1 << 20;

    /// <summary>A regular file; <paramref name="read"/> gives its first n bytes (n at most <paramref name="size"/>).</summary>
    public void File(string path, long size, Func<long, byte[]> read, string? detail = null, long? mode = null, bool hidden = false)
    {
        ct.ThrowIfCancellationRequested();
        if (hidden) _hidden.Add(path);
        _entries.Add(new ContainerEntry(path, size, detail) { Mode = Octal(mode) });
        if (_items.Count >= limits.MaxItems) return;
        if (size < 0 || size > limits.MaxItemBytes) { Notes.Add($"{path}: {size:N0} bytes, over the item limit; listed, not extracted"); return; }
        bool all = allFiles || Keep?.Invoke(path) == true;
        byte[] bytes;
        try
        {
            // A large file is read whole only when its start shows a binary or a package.
            if (!all && size > Head && !ArchiveItems.Wanted(read(Head))) return;
            bytes = read(size);
        }
        catch (Exception ex) when (Damaged(ex))
        {
            Unreadable(path, ex);
            return;
        }
        _total += bytes.Length;
        if (_total > limits.MaxTotalBytes)
            throw new ToolError(ErrorCode.LimitExceeded, $"extracting {path} passes the {limits.MaxTotalBytes:N0}-byte total limit.", "unpack fewer files or raise the limits");
        if (all || ArchiveItems.Wanted(bytes)) _items.Add(new ExtractedItem(path, bytes, $"{kind} file"));
    }

    /// <summary>Damaged structure or data: the exceptions a reader turns into a note or a malformed-input error.</summary>
    public static bool Damaged(Exception ex) => ex is InvalidDataException or ToolError { Code: ErrorCode.MalformedInput } or EndOfStreamException;

    public void Unreadable(string path, Exception ex)
    {
        if (++_unread <= 20) Notes.Add($"{path}: unreadable ({(ex is ToolError t ? t.Message : ex.Message)})");
    }

    /// <summary>Runs a reader; damaged structure outside any one file is malformed input.</summary>
    public static ContainerContents Guard(FsSource src, Func<ContainerContents> read)
    {
        try { return read(); }
        catch (Exception ex) when (ex is InvalidDataException or EndOfStreamException) { throw src.Malformed(ex.Message); }
    }

    /// <summary>A FIFO, device or socket (by the file type bits of <paramref name="mode"/>): listed with no data.</summary>
    public void Special(string path, long mode) =>
        _entries.Add(new ContainerEntry(path, 0, (mode & 0xF000) switch { 0x1000 => SpecialKinds[0], 0x2000 => SpecialKinds[1], 0x6000 => SpecialKinds[2], _ => SpecialKinds[3] }) { Mode = Octal(mode) });

    private static readonly string[] SpecialKinds = ["FIFO (named pipe)", "character device", "block device", "socket"];

    public void Link(string path, string target, long? mode = null) => _entries.Add(new ContainerEntry(path, target.Length, $"symbolic link to {target}") { Mode = Octal(mode) });

    private static string? Octal(long? mode) => mode is { } m ? Convert.ToString(m & 0xFFF, 8) : null;

    public ContainerContents Done()
    {
        if (_unread > 20) Notes.Add($"{_unread - 20} more files unreadable");
        foreach (var h in _hidden.Take(20)) Notes.Add($"Hidden entry: '{MemberNames.Show(h)}' carries the hidden attribute.");
        if (_hidden.Count > 20) Notes.Add($"{_hidden.Count - 20} more hidden entries.");
        // NTFS names a stream as file:stream.
        Notes.AddRange(MemberNames.Notes(_entries.Select(e => e.Path).ToList(), streams: kind != "NTFS"));
        if (_entries.Count == 0) Notes.Add($"no files were recovered from this {kind} image: nothing extracted");
        int files = _entries.Count(e => e.Detail == null || !(e.Detail.StartsWith("symbolic link", StringComparison.Ordinal) || SpecialKinds.Contains(e.Detail)));
        if (!allFiles && files > _items.Count)
            Notes.Add($"{files - _items.Count} of {files} files not extracted (not binaries or packages; allFiles extracts every file).");
        return new ContainerContents(kind, _items, Notes) { Entries = _entries };
    }
}
