using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Corvus.Core;
using Corvus.Native.Patching;

namespace Corvus.Services;

/// <summary>
/// A session file (corvus-session/1): the loaded files by path and SHA-256, each assembly's edit script (the
/// export_edits format), each native image's patch set (the export_native_patches json) and user names and comments,
/// notes, the Il2Cpp games read by the built-in reader (their input, binary and metadata, not the generated dummy assemblies)
/// and the open minidumps. Everything is re-derived from the files themselves on load; nothing in it is executed.
/// </summary>
public sealed class SessionService(AssemblyWorkspace workspace, EditHistoryService history, NativeCodeService code, NotesService? notes = null,
    MinidumpService? dumps = null)
{
    public const string Format = "corvus-session/1";

    // Migration only: the format of session files written before the rename, still read.
    private const string LegacyFormat = "net-decompiler-session/1";
    public const long MaxBytes = 64L << 20;
    public const int MaxFiles = 10_000;
    /// <summary>Files hashed per search root when looking for a moved file.</summary>
    public const int MaxSearchedFiles = 200_000;

    public static readonly string[] Parts = ["edits", "patches", "annotations", "notes"];

    public sealed record SessionFile(string Id, string Kind, string Path, string? RelativePath, string Sha256, long Size, string? Mvid);

    public sealed record SessionEdits(string Id, string Sha256, EditHistoryService.Script Script);

    public sealed record SessionAnnotations(Dictionary<string, string> Names, Dictionary<string, string> Comments)
    {
        /// <summary>Decompiler (pseudocode) comments by RVA.</summary>
        public Dictionary<string, string>? Pseudo { get; init; }
        /// <summary>Engine comment kinds (eol, pre, plate) of comments that are not repeatable, by RVA.</summary>
        public Dictionary<string, string>? CommentKinds { get; init; }
    }

    public sealed record SessionNative(string Id, string Sha256, JsonElement? Patches, SessionAnnotations? Annotations)
    {
        /// <summary>The native edit journal's name, comment and engine edits (<see cref="NativeEditJournal.Export"/>), so they stay undoable after load_session.</summary>
        public JsonElement? Journal { get; init; }
    }

    /// <summary>
    /// An Il2Cpp game read by the built-in reader: <see cref="Input"/> is what load_assembly reads again (the package, else
    /// the metadata, which finds the binary beside it); the binary is checked by SHA-256 after the read.
    /// </summary>
    public sealed record SessionIl2Cpp(SessionFile Input, string Binary, string BinarySha256, string? Slice);

    /// <summary>An open minidump, reopened under the same file name id.</summary>
    public sealed record SessionDump(SessionFile File);

    public sealed record Document(string Format, DateTime Created, string ServerVersion, List<string> SearchDirectories, List<SessionFile> Files,
        List<SessionEdits> DotNet, List<SessionNative> Native, List<Note>? Notes)
    {
        public List<SessionIl2Cpp>? Il2Cpp { get; init; }
        public List<SessionDump>? Dumps { get; init; }
    }

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

    internal static string Hex(uint rva) => rva.ToString("x", CultureInfo.InvariantCulture);

    /// <summary>The session of what is loaded now; <paramref name="sessionPath"/> anchors the relative paths.</summary>
    public Document Build(string sessionPath, IReadOnlySet<string> include)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(sessionPath))!;
        var files = new List<SessionFile>();
        var dotnet = new List<SessionEdits>();
        var native = new List<SessionNative>();
        var games = new Dictionary<string, Il2CppRawLoader.Marker>(StringComparer.OrdinalIgnoreCase); // cache entry -> what it was read from
        workspace.Read(() =>
        {
            foreach (var asm in workspace.Assemblies)
            {
                // Dummy assemblies of the built-in Il2Cpp reader are regenerated from the game, which the session records instead.
                if (Path.GetDirectoryName(asm.FilePath) is { } folder && Path.GetFileName(folder) == Il2CppRawLoader.DummyFolder
                    && Path.GetDirectoryName(folder) is { } entry && (games.ContainsKey(entry) || Il2CppRawLoader.ReadMarker(entry) is { } marker && games.TryAdd(entry, marker)))
                {
                    if (include.Contains("edits") && asm.IsDirty) dotnet.Add(new SessionEdits(asm.Id, asm.OriginalSha256, history.BuildScript(asm)));
                    continue;
                }
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
                if (include.Contains("annotations") && code.Annotations(n) is { } ann && (ann.NameCount > 0 || ann.CommentCount > 0 || ann.PseudoCommentCount > 0))
                {
                    var kinds = ann.Comments().Where(x => ann.CommentKindAt(x.Rva) != null).ToDictionary(x => Hex(x.Rva), x => ann.CommentKindAt(x.Rva)!);
                    annotations = new SessionAnnotations(ann.Names().ToDictionary(x => Hex(x.Rva), x => x.Name), ann.Comments().ToDictionary(x => Hex(x.Rva), x => x.Comment))
                    {
                        Pseudo = ann.PseudoCommentCount > 0 ? ann.PseudoComments().ToDictionary(x => Hex(x.Rva), x => x.Comment) : null,
                        CommentKinds = kinds.Count > 0 ? kinds : null,
                    };
                }
                JsonElement? edits = null;
                if (include.Contains("annotations") && new NativeEditJournal(workspace, code).Export(n) is { Count: > 0 } entries)
                    edits = JsonSerializer.SerializeToElement(entries);
                if (patches != null || annotations != null || edits != null) native.Add(new SessionNative(n.Id, n.OriginalSha256, patches, annotations) { Journal = edits });
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
        var il2cpp = new List<SessionIl2Cpp>();
        foreach (var (entry, marker) in games)
        {
            string input = marker.Package ?? marker.Metadata;
            if (marker.Binary.Length > 0 && SessionFileOf("il2cpp", input, dir) is { } file && Sha256(marker.Binary) is { } binarySha)
            {
                il2cpp.Add(new SessionIl2Cpp(file, marker.Binary, binarySha, marker.Slice));
                continue;
            }
            // The game's files are gone: the dummy assemblies are listed like other files.
            var dummy = Path.Combine(entry, Il2CppRawLoader.DummyFolder) + Path.DirectorySeparatorChar;
            files.AddRange(workspace.Read(() => workspace.Assemblies.Where(a => a.FilePath.StartsWith(dummy, StringComparison.OrdinalIgnoreCase))
                .Select(a => new SessionFile(a.Id, "dotnet", a.FilePath, Path.GetRelativePath(dir, a.FilePath), a.OriginalSha256, a.OriginalBytes.LongLength, a.Module.Mvid?.ToString()))
                .ToList()));
        }
        var dumpList = new List<SessionDump>();
        foreach (string id in dumps?.OpenIds.Order(StringComparer.OrdinalIgnoreCase) ?? Enumerable.Empty<string>())
            if (dumps!.PathOf(id) is { } dumpPath && SessionFileOf(id, dumpPath, dir) is { } file)
                dumpList.Add(new SessionDump(file));
        return new Document(Format, DateTime.UtcNow, typeof(SessionService).Assembly.GetName().Version?.ToString(3) ?? "?", [.. workspace.SearchDirectories],
            files, dotnet, native, noteList) { Il2Cpp = il2cpp.Count > 0 ? il2cpp : null, Dumps = dumpList.Count > 0 ? dumpList : null };
    }

    /// <summary>A file recorded by path, relative path and SHA-256; null when it cannot be read now.</summary>
    private static SessionFile? SessionFileOf(string id, string path, string sessionDir) =>
        File.Exists(path) && Sha256(path) is { } sha ? new SessionFile(id, "file", path, Path.GetRelativePath(sessionDir, path), sha, Length(path), null) : null;

    private static long Length(string path)
    {
        try { return new FileInfo(path).Length; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return -1; }
    }

    public static string Serialize(Document document) => JsonSerializer.Serialize(document, Json);

    public static Document Read(string path)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full)) throw Targets.FileNotFound(full);
        if (new FileInfo(full).Length > MaxBytes) throw new ToolError(ErrorCode.LimitExceeded, $"{full} is over {MaxBytes >> 20} MiB, the session file limit.");
        Document? doc;
        try { doc = JsonSerializer.Deserialize<Document>(File.ReadAllBytes(full), Json); }
        catch (JsonException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{full} is not a valid session file: {ex.Message}"); }
        if (doc == null || doc.Format is not (Format or LegacyFormat) || doc.Files == null)
            throw new ToolError(ErrorCode.MalformedInput, $"{full} is not a session file (expected format '{Format}').");
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
