using System.Text.Json;
using System.Text.Json.Serialization;
using Corvus.Core;
using Corvus.Native.Code;
using Corvus.Native.Providers;

namespace Corvus.Native.Annotations;

/// <summary>The persisted names and comments of one image, keyed by RVA (lowercase hex, no 0x).</summary>
public sealed class AnnotationDocument
{
    /// <summary>0 in files written before the field existed.</summary>
    [JsonPropertyName("formatVersion")] public int FormatVersion { get; set; }
    /// <summary>Incremented by every write; 0 in files written before the field existed, which readers treat as changed.</summary>
    [JsonPropertyName("revision")] public ulong Revision { get; set; }
    [JsonPropertyName("path")] public string Path { get; set; } = "";
    [JsonPropertyName("sha256")] public string Sha256 { get; set; } = "";
    [JsonPropertyName("imageBase")] public ulong ImageBase { get; set; }
    [JsonPropertyName("names")] public Dictionary<string, string> Names { get; set; } = new();
    [JsonPropertyName("comments")] public Dictionary<string, string> Comments { get; set; } = new();
    /// <summary>Format 4: the user's decompiler (pseudocode) comments by RVA; absent when there are none.</summary>
    [JsonPropertyName("pseudoComments"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public Dictionary<string, string>? PseudoComments { get; set; }
    /// <summary>Format 4: the engine comment kind of a comment (eol, pre, plate) by RVA; absent: repeatable (earlier formats).</summary>
    [JsonPropertyName("commentKinds"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public Dictionary<string, string>? CommentKinds { get; set; }

    // The user's engine types (UserTypeLayer); absent when there are none.
    [JsonPropertyName("declarations"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public List<string>? Declarations { get; set; }
    [JsonPropertyName("types"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public Dictionary<string, string>? Types { get; set; }
    [JsonPropertyName("locals"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public Dictionary<string, List<LocalEntry>>? Locals { get; set; }
    [JsonPropertyName("stackVars"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public Dictionary<string, List<StackVarEntry>>? StackVars { get; set; }

    public sealed class LocalEntry
    {
        [JsonPropertyName("local")] public string Local { get; set; } = "";
        [JsonPropertyName("stack")] public int? Stack { get; set; }
        [JsonPropertyName("name")] public string? Name { get; set; }
        [JsonPropertyName("type")] public string? Type { get; set; }
    }

    public sealed class StackVarEntry
    {
        [JsonPropertyName("offset")] public int Offset { get; set; }
        [JsonPropertyName("name")] public string? Name { get; set; }
        [JsonPropertyName("type")] public string? Type { get; set; }
        /// <summary>Format 3: the member is deleted.</summary>
        [JsonPropertyName("delete"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] public bool Delete { get; set; }
    }

    // Format 3: enum members, analysis edits in the order made, operand display formats.
    [JsonPropertyName("enumMembers"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public List<EnumMemberEntry>? EnumMembers { get; set; }

    public sealed class EnumMemberEntry
    {
        [JsonPropertyName("enum")] public string Enum { get; set; } = "";
        [JsonPropertyName("member")] public string Member { get; set; } = "";
        /// <summary>Null: the member is removed.</summary>
        [JsonPropertyName("value")] public long? Value { get; set; }
    }

    [JsonPropertyName("analysis"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public List<AnalysisEntry>? Analysis { get; set; }
    [JsonPropertyName("operands"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public List<OperandEntry>? Operands { get; set; }

    public sealed class OperandEntry
    {
        [JsonPropertyName("rva")] public string Rva { get; set; } = "";
        [JsonPropertyName("operand")] public int Operand { get; set; }
        [JsonPropertyName("display")] public string Display { get; set; } = "";
        [JsonPropertyName("detail"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Detail { get; set; }
    }

    public sealed class AnalysisEntry
    {
        [JsonPropertyName("rva")] public string Rva { get; set; } = "";
        [JsonPropertyName("kind")] public string Kind { get; set; } = "";
        [JsonPropertyName("end"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? End { get; set; }
        [JsonPropertyName("type"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Type { get; set; }
    }

    /// <summary>Format 4: type renames and deletions in the order made.</summary>
    [JsonPropertyName("typeEdits"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public List<TypeEditEntry>? TypeEdits { get; set; }

    public sealed class TypeEditEntry
    {
        [JsonPropertyName("name")] public string Name { get; set; } = "";
        /// <summary>Null: the type is deleted.</summary>
        [JsonPropertyName("newName"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? NewName { get; set; }
    }

    /// <summary>Format 4: struct and union member edits in the order made.</summary>
    [JsonPropertyName("fields"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public List<FieldEntry>? Fields { get; set; }

    public sealed class FieldEntry
    {
        [JsonPropertyName("type")] public string Type { get; set; } = "";
        [JsonPropertyName("name"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Name { get; set; }
        [JsonPropertyName("offset"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public int? Offset { get; set; }
        /// <summary>Null: the member is removed.</summary>
        [JsonPropertyName("fieldType"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? FieldType { get; set; }
    }

    /// <summary>Holds what format 4 added (pseudocode comments, comment kinds, type and member edits); older builds must leave such a file alone.</summary>
    public bool HasFormat4 => PseudoComments is { Count: > 0 } || CommentKinds is { Count: > 0 } || TypeEdits is { Count: > 0 } || Fields is { Count: > 0 };

    /// <summary>Holds what format 3 added; older builds must leave such a file alone.</summary>
    public bool HasFormat3 => Analysis is { Count: > 0 } || Operands is { Count: > 0 } || EnumMembers is { Count: > 0 }
                              || StackVars?.Values.Any(l => l.Any(s => s.Delete)) == true;

    public bool HasUserTypes => Declarations is { Count: > 0 } || Types is { Count: > 0 } || Locals is { Count: > 0 } || StackVars is { Count: > 0 } || HasFormat3
                                || TypeEdits is { Count: > 0 } || Fields is { Count: > 0 };

    public bool IsEmpty => Names.Count == 0 && Comments.Count == 0 && !HasUserTypes && !HasFormat4;
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

    /// <summary>The newest sidecar format this build reads; a newer one is left untouched.</summary>
    public const int FormatVersion = 4;

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

    /// <summary>How long a save waits for another process's write of the same sidecar.</summary>
    public TimeSpan LockTimeout { get; init; } = LockedJsonFile.DefaultTimeout;

    /// <summary>
    /// Saves under the cross-process lock: re-reads the sidecar fresh (through <see cref="Open"/>, so a corrupt one is
    /// still moved aside), passes it to <paramref name="merge"/> and writes the result with the next revision, or deletes
    /// the sidecar when the result is empty. A sidecar that must not be overwritten is left untouched. Returns the
    /// document written (empty when deleted) or the problem (persistence is best-effort; in-memory annotations still work).
    /// </summary>
    public SaveResult Update(string sha256, Func<LoadResult, AnnotationDocument> merge)
    {
        var file = FileFor(sha256);
        AnnotationDocument? written = null;
        (long, long) stamp = default;
        var problem = LockedJsonFile.Update(file, () =>
        {
            var current = Open(sha256);
            if (current.WriteBlocked) return LockedJsonFile.Change.Keep(current.Warning ?? $"{file} must not be overwritten");
            written = merge(current);
            if (written.IsEmpty) return LockedJsonFile.Change.Remove();
            written.Revision = (current.Document?.Revision ?? 0) + 1;
            // the lowest version that holds the content, so older builds still read and write files they understand
            written.FormatVersion = written.HasFormat4 ? 4 : written.HasFormat3 ? 3 : written.HasUserTypes ? 2 : 1;
            return LockedJsonFile.Change.Write(JsonSerializer.SerializeToUtf8Bytes(written, Json));
        }, LockTimeout, () => stamp = Stamp(sha256));
        return problem == null ? new(written, stamp, null) : new(null, default, problem);
    }

    /// <summary>
    /// The outcome of <see cref="Update"/>: the document written (empty when the sidecar was deleted) and the sidecar's
    /// <see cref="Stamp"/> right after the write, or the problem.
    /// </summary>
    public sealed record SaveResult(AnnotationDocument? Written, (long Length, long Ticks) Stamp, string? Problem);

    /// <summary>Length and last write time of the sidecar (zeros when absent): a cheap check for a write by another process.</summary>
    public (long Length, long Ticks) Stamp(string sha256)
    {
        try
        {
            var info = new FileInfo(FileFor(sha256));
            return info.Exists ? (info.Length, info.LastWriteTimeUtc.Ticks) : (0, 0);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return (-1, 0); }
    }

    // ---- imported name layers (load_pdb, apply_il2cpp_names) ----

    private readonly object _layerGate = new();

    /// <summary>The file of one saved imported layer: &lt;sha256&gt;.&lt;source&gt;.names beside the sidecar.</summary>
    public string LayerFileFor(string sha256, NativeNameSource source) => System.IO.Path.Combine(Root, $"{sha256.ToLowerInvariant()}.{source.Id()}.names");

    /// <summary>
    /// Writes an imported layer atomically; returns null on success, else the problem (persistence is best-effort).
    /// Layers are whole files re-derivable from their source, so the last writer wins.
    /// </summary>
    public string? SaveLayer(string sha256, string imagePath, NativeNameLayers.Layer layer)
    {
        var file = LayerFileFor(sha256, layer.Source);
        try
        {
            using var buffer = new MemoryStream();
            SavedNameLayer.Write(buffer, sha256.ToLowerInvariant(), imagePath, layer);
            lock (_layerGate) SafeFile.WriteAllBytes(file, buffer.GetBuffer().AsSpan(0, (int)buffer.Length), overwrite: true);
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ToolError)
        {
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
