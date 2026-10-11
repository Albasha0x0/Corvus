using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Corvus.Core;
using Corvus.Native.Annotations;

namespace Corvus.Services;

/// <summary>What a note is about: a native address, a .NET member, a whole file or dump, or nothing (session-wide).</summary>
public sealed record NoteAnchor(
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("sha256")] string? Sha256 = null,
    [property: JsonPropertyName("mvid")] string? Mvid = null,
    [property: JsonPropertyName("rva")] uint? Rva = null,
    [property: JsonPropertyName("token")] uint? Token = null,
    [property: JsonPropertyName("label")] string? Label = null)
{
    public const string Native = "native", DotNet = "dotnet", File = "file", Dump = "dump", None = "none";

    public static readonly NoteAnchor Global = new(None);

    /// <summary>The store file the note lives in: the binary's SHA-256, the module's MVID, or global.</summary>
    [JsonIgnore] public string StoreKey => Kind == DotNet ? "mvid-" + Mvid!.ToLowerInvariant() : Sha256?.ToLowerInvariant() ?? "global";
}

public sealed record Note(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("text")] string Text,
    [property: JsonPropertyName("tags")] IReadOnlyList<string> Tags,
    [property: JsonPropertyName("evidence")] IReadOnlyList<string> Evidence,
    [property: JsonPropertyName("anchor")] NoteAnchor Anchor,
    [property: JsonPropertyName("revision")] int Revision,
    [property: JsonPropertyName("created")] DateTime Created,
    [property: JsonPropertyName("updated")] DateTime Updated,
    [property: JsonPropertyName("author")] string? Author);

/// <summary>A partial update: null leaves a field as it is.</summary>
public sealed record NoteChange(string? Status = null, string? Text = null, string? AppendText = null, IReadOnlyList<string>? AddTags = null,
    IReadOnlyList<string>? RemoveTags = null, IReadOnlyList<string>? AddEvidence = null, string? Kind = null);

/// <summary>
/// Analyst notes, persisted per user beside the annotation sidecars (&lt;annotations&gt;/notes/&lt;sha256 | mvid-guid | global&gt;.json)
/// so a binary's notes follow its identity. Writes go through <see cref="LockedJsonFile"/>, so server processes sharing
/// the store never drop each other's notes; a per-note revision decides concurrent updates.
/// </summary>
public sealed class NotesService(AnnotationStore store)
{
    public const string Format = "corvus-notes/1";

    // Migration only: the format of note files written before the rename; read, and rewritten in the current one.
    private const string LegacyFormat = "net-decompiler-notes/1";
    public const int MaxText = 4_000, MaxTags = 10, MaxEvidence = 10, MaxEvidenceChars = 400, MaxTagChars = 64;
    public const int MaxPerFile = 10_000, MaxTotal = 50_000;
    public static readonly string[] Kinds = ["finding", "question", "hypothesis", "todo"];
    public static readonly string[] Statuses = ["open", "confirmed", "refuted", "answered", "dropped"];

    public sealed class NoteFile
    {
        [JsonPropertyName("format")] public string Format { get; set; } = NotesService.Format;
        [JsonPropertyName("notes")] public List<Note> Notes { get; set; } = [];
    }

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    public string Root { get; } = Path.Combine(store.Root, "notes");

    private string FileFor(string key) => Path.Combine(Root, key + ".json");

    public static string NewId()
    {
        const string alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        Span<byte> bytes = stackalloc byte[8];
        RandomNumberGenerator.Fill(bytes);
        var chars = new char[9];
        chars[0] = 'n';
        for (int i = 0; i < 8; i++) chars[i + 1] = alphabet[bytes[i] & 31];
        return new string(chars);
    }

    public static string CheckKind(string? kind) => Pick(kind, Kinds, "kind", "finding");

    public static string CheckStatus(string? status) => Pick(status, Statuses, "status", "open");

    private static string Pick(string? value, string[] set, string name, string fallback)
    {
        var v = string.IsNullOrWhiteSpace(value) ? fallback : value.Trim().ToLowerInvariant();
        return set.Contains(v) ? v : throw new ToolError(ErrorCode.InvalidArgument, $"{name} must be one of {string.Join(", ", set)}, not '{value}'.");
    }

    private static string CheckText(string? text)
    {
        var t = (text ?? "").Trim();
        if (t.Length == 0) throw new ToolError(ErrorCode.InvalidArgument, "The note text is empty.");
        if (t.Length > MaxText) throw new ToolError(ErrorCode.LimitExceeded, $"The note text is {t.Length:N0} characters; the limit is {MaxText:N0}.");
        return t;
    }

    private static List<string> Merge(IEnumerable<string> current, IReadOnlyList<string>? add, IReadOnlyList<string>? remove, int max, int maxChars, string what)
    {
        var list = current.ToList();
        foreach (var r in remove ?? []) list.RemoveAll(x => x.Equals(r.Trim(), StringComparison.OrdinalIgnoreCase));
        foreach (var raw in add ?? [])
        {
            var a = raw.Trim();
            if (a.Length == 0 || list.Contains(a, StringComparer.OrdinalIgnoreCase)) continue;
            if (a.Length > maxChars) throw new ToolError(ErrorCode.LimitExceeded, $"A {what} entry is {a.Length} characters; the limit is {maxChars}.");
            list.Add(a);
        }
        if (list.Count > max) throw new ToolError(ErrorCode.LimitExceeded, $"A note holds at most {max} {what} entries ({list.Count} given).");
        return list;
    }

    /// <summary>Records a new note (revision 1).</summary>
    public Note Record(string text, string? kind, string? status, NoteAnchor anchor, IReadOnlyList<string>? tags, IReadOnlyList<string>? evidence, string? author)
    {
        var now = DateTime.UtcNow;
        var note = new Note(NewId(), CheckKind(kind), CheckStatus(status), CheckText(text), Merge([], tags, null, MaxTags, MaxTagChars, "tag"),
            Merge([], evidence, null, MaxEvidence, MaxEvidenceChars, "evidence"), anchor, 1, now, now, author);
        if (CountAll() >= MaxTotal)
            throw new ToolError(ErrorCode.LimitExceeded, $"The note store holds {MaxTotal:N0} notes, its limit.", "update_note status=dropped, or remove note files under " + Root);
        Write(anchor.StoreKey, file =>
        {
            if (file.Notes.Count >= MaxPerFile)
                throw new ToolError(ErrorCode.LimitExceeded, $"{anchor.Label ?? anchor.StoreKey} has {MaxPerFile:N0} notes, the limit for one binary.");
            file.Notes.Add(note);
        });
        _count = (_count ?? 0) + 1;
        return note;
    }

    /// <summary>
    /// Applies <paramref name="change"/> when the note is at <paramref name="expectedRevision"/>; otherwise a Conflict whose
    /// details carry the current note, so the caller can merge without another call.
    /// </summary>
    public Note Update(string id, int expectedRevision, NoteChange change)
    {
        var key = KeyOf(id) ?? throw new ToolError(ErrorCode.NotFound, $"No note has the id '{id}'.", "list_notes shows the ids");
        Note? updated = null;
        Write(key, file =>
        {
            int i = file.Notes.FindIndex(n => n.Id == id);
            if (i < 0) throw new ToolError(ErrorCode.NotFound, $"No note has the id '{id}'.", "list_notes shows the ids");
            var current = file.Notes[i];
            if (current.Revision != expectedRevision)
                throw new ToolError(ErrorCode.Conflict, $"Note {id} is at revision {current.Revision}, not {expectedRevision}: it changed since it was read.",
                    "merge with the current note in details.current and call update_note with its revision")
                { Details = new { reason = "revision_conflict", current } };
            var text = change.Text != null ? CheckText(change.Text) : current.Text;
            if (!string.IsNullOrWhiteSpace(change.AppendText)) text = CheckText(text + "\n" + change.AppendText.Trim());
            updated = current with
            {
                Kind = change.Kind != null ? CheckKind(change.Kind) : current.Kind,
                Status = change.Status != null ? CheckStatus(change.Status) : current.Status,
                Text = text,
                Tags = Merge(current.Tags, change.AddTags, change.RemoveTags, MaxTags, MaxTagChars, "tag"),
                Evidence = Merge(current.Evidence, change.AddEvidence, null, MaxEvidence, MaxEvidenceChars, "evidence"),
                Revision = current.Revision + 1,
                Updated = DateTime.UtcNow,
            };
            file.Notes[i] = updated;
        });
        return updated!;
    }

    /// <summary>
    /// Adds notes made elsewhere (a session file, another build): a note whose id exists is kept as it is unless the incoming
    /// revision is higher. Returns (added, updated, unchanged).
    /// </summary>
    public (int Added, int Updated, int Unchanged) Import(IEnumerable<Note> notes)
    {
        int added = 0, updated = 0, unchanged = 0;
        foreach (var group in notes.GroupBy(n => n.Anchor.StoreKey))
            Write(group.Key, file =>
            {
                foreach (var note in group)
                {
                    int i = file.Notes.FindIndex(n => n.Id == note.Id);
                    if (i < 0)
                    {
                        if (file.Notes.Count >= MaxPerFile) throw new ToolError(ErrorCode.LimitExceeded, $"{group.Key} has {MaxPerFile:N0} notes, the limit for one binary.");
                        file.Notes.Add(note);
                        added++;
                    }
                    else if (note.Revision > file.Notes[i].Revision) { file.Notes[i] = note; updated++; }
                    else unchanged++;
                }
            });
        _count = null;
        _ids.Clear();
        return (added, updated, unchanged);
    }

    private void Write(string key, Action<NoteFile> change)
    {
        var path = FileFor(key);
        var (written, problem) = LockedJsonFile.Update<NoteFile>(path, current =>
        {
            var file = current ?? new NoteFile();
            if (file.Format is not (Format or LegacyFormat))
                throw new ToolError(ErrorCode.Conflict, $"{path} has format '{file.Format}', not {Format}; it is left untouched.");
            file.Format = Format;
            change(file);
            return file;
        }, Json);
        if (problem != null) throw new ToolError(ErrorCode.IoError, $"The note was not saved: {problem}");
        foreach (var n in written!.Notes) _ids[n.Id] = key;
    }

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _ids = new(StringComparer.Ordinal);
    private int? _count;

    private string? KeyOf(string id)
    {
        if (_ids.TryGetValue(id, out var key) && Read(key).Any(n => n.Id == id)) return key;
        foreach (var (k, notes) in Files())
            foreach (var n in notes) _ids[n.Id] = k;
        return _ids.GetValueOrDefault(id);
    }

    private int CountAll() => _count ??= Files().Sum(f => f.Notes.Count);

    /// <summary>The notes of one store file (empty when it does not exist or cannot be read).</summary>
    public IReadOnlyList<Note> Read(string key) => LockedJsonFile.Read<NoteFile>(FileFor(key), Json).Value?.Notes ?? [];

    /// <summary>Every store file with its notes.</summary>
    public IEnumerable<(string Key, List<Note> Notes)> Files()
    {
        if (!Directory.Exists(Root)) yield break;
        foreach (var path in Directory.EnumerateFiles(Root, "*.json"))
            if (LockedJsonFile.Read<NoteFile>(path, Json).Value is { Format: Format or LegacyFormat } file)
                yield return (Path.GetFileNameWithoutExtension(path), file.Notes);
    }

    /// <summary>The notes anchored to <paramref name="keys"/> (store keys), or every note when null.</summary>
    public List<Note> All(IEnumerable<string>? keys = null) =>
        keys == null ? Files().SelectMany(f => f.Notes).ToList() : keys.Distinct().SelectMany(Read).ToList();

    /// <summary>Open notes of one store file that <paramref name="match"/> accepts (a decompile header; cheap when the file does not exist).</summary>
    public int OpenCount(string key, Func<NoteAnchor, bool> match) => Read(key).Count(n => n.Status == "open" && match(n.Anchor));

    /// <summary>The header line decompile output gets when open notes exist, else empty.</summary>
    public static string Header(int open, string anchor) =>
        open == 0 ? "" : $"// notes: {open} open (list_notes anchor={anchor})\n";

    /// <summary>Open and total counts across the store.</summary>
    public (int Open, int Total) Counts()
    {
        int open = 0, total = 0;
        foreach (var (_, notes) in Files())
        {
            total += notes.Count;
            open += notes.Count(n => n.Status == "open");
        }
        _count = total;
        return (open, total);
    }
}
