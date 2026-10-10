using System.Text.Json;
using System.Text.Json.Serialization;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Native.Annotations;

/// <summary>The persisted names and comments of one image, keyed by RVA (lowercase hex, no 0x).</summary>
public sealed class AnnotationDocument
{
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

    /// <summary>The saved document for <paramref name="sha256"/>, or null when none exists (or it cannot be read).</summary>
    public AnnotationDocument? Load(string sha256)
    {
        var file = FileFor(sha256);
        try
        {
            if (!File.Exists(file)) return null;
            return JsonSerializer.Deserialize<AnnotationDocument>(File.ReadAllText(file), Json);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    /// <summary>Writes <paramref name="document"/> atomically; deletes the sidecar when it has become empty.</summary>
    public void Save(AnnotationDocument document)
    {
        var file = FileFor(document.Sha256);
        try
        {
            Directory.CreateDirectory(Root);
            if (document.IsEmpty)
            {
                if (File.Exists(file)) File.Delete(file);
                return;
            }
            var temp = file + ".tmp-" + Environment.ProcessId;
            File.WriteAllText(temp, JsonSerializer.Serialize(document, Json));
            File.Move(temp, file, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Persistence is best-effort; in-memory annotations still work for this session.
        }
    }

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
                    var doc = JsonSerializer.Deserialize<AnnotationDocument>(File.ReadAllText(file), Json);
                    if (doc != null && !doc.IsEmpty
                        && string.Equals(System.IO.Path.GetFullPath(doc.Path), full, StringComparison.OrdinalIgnoreCase)
                        && !string.Equals(doc.Sha256, currentSha256, StringComparison.OrdinalIgnoreCase))
                        result.Add(doc.Sha256);
                }
                catch (Exception ex) when (ex is IOException or JsonException or ArgumentException) { }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return result;
    }
}
