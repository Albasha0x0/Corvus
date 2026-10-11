using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Patching;

namespace NetDecompilerMcp.Services;

/// <summary>
/// A session file (net-decompiler-session/1): the loaded files by path and SHA-256, each assembly's edit script (the
/// export_edits format), each native image's patch set (the export_native_patches json) and user names and comments,
/// and notes. Everything is re-derived from the files themselves on load; nothing in it is executed.
/// </summary>
public sealed class SessionService(AssemblyWorkspace workspace, EditHistoryService history, NativeCodeService code, NotesService? notes = null)
{
    public const string Format = "net-decompiler-session/1";
    public const long MaxBytes = 64L << 20;
    public const int MaxFiles = 10_000;
    /// <summary>Files hashed per search root when looking for a moved file.</summary>
    public const int MaxSearchedFiles = 200_000;

    public static readonly string[] Parts = ["edits", "patches", "annotations", "notes"];

    public sealed record SessionFile(string Id, string Kind, string Path, string? RelativePath, string Sha256, long Size, string? Mvid);

    public sealed record SessionEdits(string Id, string Sha256, EditHistoryService.Script Script);

    public sealed record SessionAnnotations(Dictionary<string, string> Names, Dictionary<string, string> Comments);

    public sealed record SessionNative(string Id, string Sha256, JsonElement? Patches, SessionAnnotations? Annotations);

    public sealed record Document(string Format, DateTime Created, string ServerVersion, List<string> SearchDirectories, List<SessionFile> Files,
        List<SessionEdits> DotNet, List<SessionNative> Native, List<Note>? Notes);

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static HashSet<string> ParseInclude(string? include)
    {
        if (string.IsNullOrWhiteSpace(include) || include.Trim().Equals("all", StringComparison.OrdinalIgnoreCase)) return [.. Parts];
        var set = new HashSet<string>(StringComparer.Ordinal);
        foreach (var part in include.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var p = part.ToLowerInvariant();
            if (!Parts.Contains(p)) throw new ToolError(ErrorCode.InvalidArgument, $"Unknown part '{part}'.", "use all or a comma-separated list of " + string.Join(", ", Parts));
            set.Add(p);
        }
        return set;
    }

    private static string Hex(uint rva) => rva.ToString("x", CultureInfo.InvariantCulture);

    /// <summary>The session of what is loaded now; <paramref name="sessionPath"/> anchors the relative paths.</summary>
    public Document Build(string sessionPath, IReadOnlySet<string> include)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(sessionPath))!;
        var files = new List<SessionFile>();
        var dotnet = new List<SessionEdits>();
        var native = new List<SessionNative>();
        workspace.Read(() =>
        {
            foreach (var asm in workspace.Assemblies)
            {
                files.Add(new SessionFile(asm.Id, "dotnet", asm.FilePath, Path.GetRelativePath(dir, asm.FilePath), asm.OriginalSha256, asm.OriginalBytes.LongLength,
                    asm.Module.Mvid?.ToString()));
                if (include.Contains("edits") && asm.IsDirty) dotnet.Add(new SessionEdits(asm.Id, asm.OriginalSha256, history.BuildScript(asm)));
            }
            foreach (var n in workspace.Natives)
            {
                // A mixed-mode assembly's native view loads with the assembly.
                if (n.ManagedView == null)
                    files.Add(new SessionFile(n.Id, "native", n.FilePath, Path.GetRelativePath(dir, n.FilePath), n.OriginalSha256, Length(n.FilePath), null));
                JsonElement? patches = null;
                if (include.Contains("patches") && n.HasPatches)
                {
                    using var doc = JsonDocument.Parse(NativeEditService.RenderPatches(n, PatchExport.Format.Json).Content);
                    patches = doc.RootElement.Clone();
                }
                SessionAnnotations? annotations = null;
                if (include.Contains("annotations") && code.Annotations(n) is { } ann && (ann.NameCount > 0 || ann.CommentCount > 0))
                    annotations = new SessionAnnotations(ann.Names().ToDictionary(x => Hex(x.Rva), x => x.Name), ann.Comments().ToDictionary(x => Hex(x.Rva), x => x.Comment));
                if (patches != null || annotations != null) native.Add(new SessionNative(n.Id, n.OriginalSha256, patches, annotations));
            }
            return 0;
        });
        List<Note>? noteList = null;
        if (include.Contains("notes") && notes != null)
        {
            var keys = files.Select(f => f.Sha256.ToLowerInvariant()).Concat(files.Where(f => f.Mvid != null).Select(f => new NoteAnchor(NoteAnchor.DotNet, Mvid: f.Mvid).StoreKey))
                .Append("global");
            noteList = notes.All(keys);
        }
        return new Document(Format, DateTime.UtcNow, typeof(SessionService).Assembly.GetName().Version?.ToString(3) ?? "?", [.. workspace.SearchDirectories],
            files, dotnet, native, noteList);
    }

    private static long Length(string path)
    {
        try { return new FileInfo(path).Length; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return -1; }
    }

    public static string Serialize(Document document) => JsonSerializer.Serialize(document, Json);

    public static Document Read(string path)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full)) throw new ToolError(ErrorCode.NotFound, $"File not found: {full}");
        if (new FileInfo(full).Length > MaxBytes) throw new ToolError(ErrorCode.LimitExceeded, $"{full} is over {MaxBytes >> 20} MiB, the session file limit.");
        Document? doc;
        try { doc = JsonSerializer.Deserialize<Document>(File.ReadAllBytes(full), Json); }
        catch (JsonException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{full} is not a valid session file: {ex.Message}"); }
        if (doc == null || doc.Format != Format || doc.Files == null)
            throw new ToolError(ErrorCode.MalformedInput, $"{full} is not a net-decompiler session file (expected format '{Format}').");
        if (doc.Files.Count > MaxFiles) throw new ToolError(ErrorCode.LimitExceeded, $"{full} lists {doc.Files.Count:N0} files; the limit is {MaxFiles:N0}.");
        return doc with { DotNet = doc.DotNet ?? [], Native = doc.Native ?? [], SearchDirectories = doc.SearchDirectories ?? [] };
    }

    /// <summary>
    /// Where a recorded file is now: <paramref name="Path"/> holds the same bytes (the recorded path, the path relative to
    /// the session file, or a file of the same size under a search root); <paramref name="Other"/> is a file at the
    /// recorded or relative path with other bytes (another build).
    /// </summary>
    public sealed record Located(string? Path, string How, string? Other);

    public static Located Locate(SessionFile file, string sessionDir, IReadOnlyList<string> roots, CancellationToken ct)
    {
        string? other = null;
        foreach (var (candidate, how) in new[] { (file.Path, "recorded_path"), (file.RelativePath is { } r ? System.IO.Path.GetFullPath(System.IO.Path.Combine(sessionDir, r)) : null, "relative_path") })
        {
            if (candidate == null || !File.Exists(candidate)) continue;
            if (Sha256(candidate) == file.Sha256) return new(candidate, how, null);
            other ??= candidate;
        }
        foreach (var root in roots.Where(Directory.Exists))
        {
            int seen = 0;
            foreach (var candidate in Directory.EnumerateFiles(root, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint }))
            {
                ct.ThrowIfCancellationRequested();
                if (++seen > MaxSearchedFiles) break;
                long length;
                try { length = new FileInfo(candidate).Length; }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }
                if (length == file.Size && Sha256(candidate) == file.Sha256) return new(candidate, "search_root", other);
                if (other == null && System.IO.Path.GetFileName(candidate).Equals(System.IO.Path.GetFileName(file.Path), StringComparison.OrdinalIgnoreCase)) other = candidate;
            }
        }
        return new(null, "not_found", other);
    }

    private static string? Sha256(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16);
            return Convert.ToHexStringLower(SHA256.HashData(stream));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>A recorded RVA key (lowercase hex).</summary>
    public static uint? Rva(string key) => uint.TryParse(key, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v) ? v : null;
}
