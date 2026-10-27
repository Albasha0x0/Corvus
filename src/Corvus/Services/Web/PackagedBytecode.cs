using System.IO.Compression;
using Corvus.Core;

namespace Corvus.Services.Web;

/// <summary>Bytecode from a file or one ZIP entry, parsed once; the four most recent are cached by path, size and write time.</summary>
internal sealed class PackagedBytecode<T> where T : class
{
    private readonly List<((string Path, long Size, DateTime Written) Key, T Value)> _recent = [];

    /// <summary>The parsed file at <paramref name="path"/>; a ZIP is read through <paramref name="entry"/>, and a null entry throws <paramref name="none"/>.</summary>
    /// <remarks><paramref name="parse"/> gets the full path, the entry name (null for a plain file) and the bytes.</remarks>
    public T Open(string path, string what, Func<ZipArchive, ZipArchiveEntry?> entry, Func<ToolError> none, Func<string, string?, byte[], T> parse, CancellationToken ct)
    {
        var info = new FileInfo(InputFiles.RequireRegularFile(path, what));
        if (!info.Exists) throw Targets.FileNotFound(path);
        var key = (info.FullName, info.Length, info.LastWriteTimeUtc);
        lock (_recent)
            if (_recent.FirstOrDefault(r => r.Key == key) is { Value: not null } hit) return hit.Value;
        ct.ThrowIfCancellationRequested();
        string? inner = null;
        byte[] bytes;
        using (var s = info.OpenRead())
        {
            Span<byte> head = stackalloc byte[4];
            int n = s.ReadAtLeast(head, 4, throwOnEndOfStream: false);
            s.Position = 0;
            if (n == 4 && Blob.StartsWith(head, "PK\x03\x04"u8))
            {
                using var zip = new ZipArchive(s, ZipArchiveMode.Read);
                var e = entry(zip) ?? throw none();
                if (e.Length > JsAnalysis.MaxFileBytes) throw new ToolError(ErrorCode.LimitExceeded, $"{e.FullName} is {e.Length:N0} bytes; entries up to {JsAnalysis.MaxFileBytes:N0} bytes are read.");
                inner = e.FullName;
                using var es = e.Open();
                bytes = Blob.ReadBounded(es, JsAnalysis.MaxFileBytes) ?? throw new ToolError(ErrorCode.LimitExceeded, $"{e.FullName} is over {JsAnalysis.MaxFileBytes:N0} bytes.");
            }
            else bytes = JsAnalysis.Read(path);
        }
        var value = parse(info.FullName, inner, bytes);
        lock (_recent)
        {
            _recent.RemoveAll(r => r.Key == key);
            _recent.Insert(0, (key, value));
            if (_recent.Count > 4) _recent.RemoveAt(_recent.Count - 1);
        }
        return value;
    }
}
