using System.Text.Json;
using System.Text.Json.Serialization;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Native.Annotations;

/// <summary>The persisted names and comments of one image, keyed by RVA (lowercase hex, no 0x).</summary>
public sealed class AnnotationDocument
{
    /// <summary>0 in files written before the field existed.</summary>
    [JsonPropertyName("formatVersion")] public int FormatVersion { get; set; }
    [JsonPropertyName("path")] public string Path { get; set; } = "";
    [JsonPropertyName("sha256")] public string Sha256 { get; set; } = "";
    [JsonPropertyName("imageBase")] public ulong ImageBase { get; set; }
    [JsonPropertyName("names")] public Dictionary<string, string> Names { get; set; } = new();
    [JsonPropertyName("comments")] public Dictionary<string, string> Comments { get; set; } = new();

    public bool IsEmpty => Names.Count == 0 && Comments.Count == 0;
}

/// <summary>
/// Per-user sidecar storage for native annotations: one JSON file per image SHA-256 under
/// <c>&lt;LocalAppData&gt;/NetDecompilerMcp/annotations/&lt;sha256&gt;.json</c> (the same per-user root the analysis
/// cache uses, a sibling folder), written atomically. A different file hash is a different sidecar, so a changed file
/// starts clean; <see cref="FindOtherHashesForPath"/> reports when a sidecar already exists for the same path.
/// Imported name layers (load_pdb, apply_il2cpp_names) live beside it, one compressed file per source
/// (&lt;sha256&gt;.&lt;source&gt;.names, <see cref="SavedNameLayer"/>).
/// </summary>
public sealed class AnnotationStore
{
    public const string RootVariable = "NDM_ANNOTATIONS_DIR";

    /// <summary>The sidecar format this build writes; a newer one is left untouched.</summary>
    public const int FormatVersion = 1;

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public string Root { get; }

    public AnnotationStore(string? root = null)
    {
        var chosen = root
            ?? (Environment.GetEnvironmentVariable(RootVariable) is { Length: > 0 } custom ? custom
                : System.IO.Path.Combine(System.IO.Path.GetDirectoryName(AnalysisCache.DefaultRoot)!, "annotations"));
        Root = System.IO.Path.GetFullPath(chosen);
    }

    private string FileFor(string sha256) => System.IO.Path.Combine(Root, sha256.ToLowerInvariant() + ".json");

    /// <summary>
    /// A loaded sidecar. <paramref name="Warning"/> reports a sidecar that could not be used; <paramref name="WriteBlocked"/>
    /// means it is still in place (locked, or a newer format) and must not be overwritten.
    /// </summary>
    public sealed record LoadResult(AnnotationDocument? Document, string? Warning, bool WriteBlocked);

    /// <summary>The saved document for <paramref name="sha256"/>, or null when none exists or it could not be used.</summary>
    public AnnotationDocument? Load(string sha256) => Open(sha256).Document;

    /// <summary>
    /// Reads the sidecar of <paramref name="sha256"/>. One that is malformed, unreadable or locked is moved aside to
    /// &lt;sha256&gt;.json.corrupt-&lt;utc&gt;-&lt;guid&gt; so a later save cannot destroy it; if it cannot be moved it is left in place and writes are blocked.
    /// </summary>
    public LoadResult Open(string sha256)
    {
        var file = FileFor(sha256);
        string problem;
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                // Shared for delete so a concurrent writer's rename over the file is not blocked by this read.
                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                var doc = JsonSerializer.Deserialize<AnnotationDocument>(fs, Json);
                if (doc == null) { problem = "the document is null"; break; }
                if (doc.FormatVersion > FormatVersion)
                    return new(null, $"The annotation sidecar {file} has format version {doc.FormatVersion} (this build writes {FormatVersion}); " +
                                     "it is left untouched and names and comments of this image are not saved this session.", true);
                return new(doc, null, false);
            }
            catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException) { return new(null, null, false); }
            catch (JsonException ex) { problem = "malformed: " + ex.Message; break; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                problem = ex.Message;
                if (attempt >= 4) break;
                Thread.Sleep(20 << attempt); // a transient lock (antivirus, a backup) usually clears quickly
            }
        }
        var aside = $"{file}.corrupt-{DateTime.UtcNow:yyyyMMddTHHmmssZ}-{Guid.NewGuid():N}";
        try
        {
            File.Move(file, aside);
            return new(null, $"The annotation sidecar {file} could not be read ({problem}); it was moved to {aside} and this image starts with no saved names or comments.", false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new(null, $"The annotation sidecar {file} could not be read ({problem}) or moved aside ({ex.Message}); it is left untouched " +
                             "and names and comments of this image are not saved this session.", true);
        }
    }

    /// <summary>
    /// Writes <paramref name="document"/> through a temp file and an atomic rename; deletes the sidecar when it has become
    /// empty. Returns null on success, else the problem (persistence is best-effort; in-memory annotations still work).
    /// </summary>
    public string? Save(AnnotationDocument document)
    {
        var file = FileFor(document.Sha256);
        document.FormatVersion = FormatVersion;
        var bytes = JsonSerializer.SerializeToUtf8Bytes(document, Json);
        lock (WriteGates.GetOrAdd(file, _ => new object()))
            for (int attempt = 0; ; attempt++)
            {
                try
                {
                    Directory.CreateDirectory(Root);
                    if (document.IsEmpty) File.Delete(file);
                    else SafeFile.WriteAllBytes(file, bytes, overwrite: true);
                    return null;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ToolError)
                {
                    // Another process renaming over the file, or a reader, can hold the target briefly.
                    if (attempt >= 7 || ex is ToolError) return ex.Message;
                    Thread.Sleep(10 * (attempt + 1) + Random.Shared.Next(10));
                }
            }
    }

    /// <summary>Serializes writers of one sidecar within the process, across store instances.</summary>
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, object> WriteGates =
        new(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);

    // ---- imported name layers (load_pdb, apply_il2cpp_names) ----

    private readonly object _layerGate = new();

    /// <summary>The file of one saved imported layer: &lt;sha256&gt;.&lt;source&gt;.names beside the sidecar.</summary>
    public string LayerFileFor(string sha256, NativeNameSource source) => System.IO.Path.Combine(Root, $"{sha256.ToLowerInvariant()}.{source.Id()}.names");

    /// <summary>Writes an imported layer atomically; returns null on success, else the problem (persistence is best-effort).</summary>
    public string? SaveLayer(string sha256, string imagePath, NativeNameLayers.Layer layer)
    {
        var file = LayerFileFor(sha256, layer.Source);
        var temp = file + ".tmp-" + Environment.ProcessId + "-" + Environment.CurrentManagedThreadId;
        try
        {
            lock (_layerGate)
            {
                Directory.CreateDirectory(Root);
                using (var fs = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16))
                    SavedNameLayer.Write(fs, sha256.ToLowerInvariant(), imagePath, layer);
                File.Move(temp, file, overwrite: true);
            }
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            try { File.Delete(temp); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            return ex.Message;
        }
    }

    /// <summary>The saved layer of <paramref name="source"/> for <paramref name="sha256"/>, or null when none (or unreadable).</summary>
    public NativeNameLayers.Layer? LoadLayer(string sha256, NativeNameSource source, CancellationToken ct = default)
    {
        var file = LayerFileFor(sha256, source);
        try
        {
            if (!File.Exists(file)) return null;
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16);
            return SavedNameLayer.Read(fs, sha256, ct) is { } layer && layer.Source == source ? layer : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Deletes a saved layer; true when there was one.</summary>
    public bool DeleteLayer(string sha256, NativeNameSource source)
    {
        var file = LayerFileFor(sha256, source);
        try
        {
            lock (_layerGate)
            {
                if (!File.Exists(file)) return false;
                File.Delete(file);
                return true;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// SHA-256 hashes of sidecars that record the same file path as <paramref name="path"/> but a different hash:
    /// annotations made against an earlier version of a file now changed on disk.
    /// </summary>
    public IReadOnlyList<string> FindOtherHashesForPath(string path, string currentSha256)
    {
        var result = new List<string>();
        try
        {
            if (!Directory.Exists(Root)) return result;
            var full = System.IO.Path.GetFullPath(path);
            foreach (var file in Directory.EnumerateFiles(Root, "*.json"))
            {
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    var doc = JsonSerializer.Deserialize<AnnotationDocument>(fs, Json);
                    if (doc != null && !doc.IsEmpty
                        && string.Equals(System.IO.Path.GetFullPath(doc.Path), full, StringComparison.OrdinalIgnoreCase)
                        && !string.Equals(doc.Sha256, currentSha256, StringComparison.OrdinalIgnoreCase))
                        result.Add(doc.Sha256);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or ArgumentException) { }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return result;
    }
}
