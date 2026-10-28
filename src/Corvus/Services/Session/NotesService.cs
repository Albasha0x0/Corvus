using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
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

/// <summary>Where a note's claim was seen: a rerunnable tool call with its result hash, a saved record that supports or
/// refutes it, or text; a plain string reads as text.</summary>
[JsonConverter(typeof(NoteEvidenceConverter))]
public sealed record NoteEvidence(
    [property: JsonPropertyName("tool")] string? Tool = null,
    [property: JsonPropertyName("args")] JsonObject? Args = null,
    [property: JsonPropertyName("resultSha256")] string? ResultSha256 = null,
    [property: JsonPropertyName("text")] string? Text = null,
    [property: JsonPropertyName("result")] string? Result = null,
    [property: JsonPropertyName("expect")] string? Expect = null,
    [property: JsonPropertyName("verdict")] string? Verdict = null)
{
    public const string Supports = "supports", Refutes = "refutes";

    public static implicit operator NoteEvidence(string text) => new(Text: text);

    /// <summary>Equal entries name the same saved record, the same call (tool and canonical args) or the same text.</summary>
    [JsonIgnore] internal string Key => Result != null ? "result " + Result : Tool != null ? Tool + " " + ResultHashes.Canonical(Args ?? new JsonObject()) : "text " + Text;

    public override string ToString() =>
        Result != null ? $"{Expect ?? Supports} {Result}" + (Tool != null ? $" ({Tool})" : "") + (Text != null ? $" {Text}" : "") + (Verdict != null ? $": {Verdict}" : "")
        : Tool == null ? Text ?? "" : $"{Tool} {ResultHashes.Canonical(Args ?? new JsonObject())}" + (ResultSha256 != null ? $" sha256 {ResultSha256[..12]}" : "") + (Text != null ? $" ({Text})" : "");
}

internal sealed class NoteEvidenceConverter : JsonConverter<NoteEvidence>
{
    private sealed record Shape(string? Tool, JsonObject? Args, string? ResultSha256, string? Text, string? Result = null, string? Expect = null, string? Verdict = null);

    private static readonly JsonSerializerOptions Plain = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    public override NoteEvidence Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String) return new NoteEvidence(Text: reader.GetString());
        var s = JsonSerializer.Deserialize<Shape>(ref reader, Plain) ?? throw new JsonException("an evidence entry is an object or a string");
        return new NoteEvidence(s.Tool, s.Args, s.ResultSha256, s.Text, s.Result, s.Expect, s.Verdict);
    }

    public override void Write(Utf8JsonWriter writer, NoteEvidence value, JsonSerializerOptions options) =>
        JsonSerializer.Serialize(writer, new Shape(value.Tool, value.Args, value.ResultSha256, value.Text, value.Result, value.Expect, value.Verdict), Plain);
}

public sealed record Note(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("text")] string Text,
    [property: JsonPropertyName("tags")] IReadOnlyList<string> Tags,
    [property: JsonPropertyName("evidence")] IReadOnlyList<NoteEvidence> Evidence,
    [property: JsonPropertyName("anchor")] NoteAnchor Anchor,
    [property: JsonPropertyName("revision")] int Revision,
    [property: JsonPropertyName("created")] DateTime Created,
    [property: JsonPropertyName("updated")] DateTime Updated,
    [property: JsonPropertyName("author")] string? Author,
    [property: JsonPropertyName("origin")] string? Origin = null);

/// <summary>A partial update: null leaves a field as it is.</summary>
public sealed record NoteChange(string? Status = null, string? Text = null, string? AppendText = null, IReadOnlyList<string>? AddTags = null,
    IReadOnlyList<string>? RemoveTags = null, IReadOnlyList<NoteEvidence>? AddEvidence = null, string? Kind = null);

/// <summary>Analyst notes stored per binary identity beside the annotations; locked writes keep processes from dropping
/// each other's notes, and a per-note revision decides concurrent updates.</summary>
public sealed class NotesService(AnnotationStore store)
{
    // 3: evidence entries may link a saved record (result, expect, verdict); 2 had objects (tool, args, resultSha256, text); 1 strings, read as text.
    public const string Format = "corvus-notes/3";
    private const string Format2 = "corvus-notes/2";
    private const string Format1 = "corvus-notes/1";

    // Migration only: the format of note files written before the rename; read, and rewritten in the current one.
    private const string LegacyFormat = "net-decompiler-notes/1";
    public const int MaxText = 4_000, MaxTags = 10, MaxEvidence = 10, MaxEvidenceChars = 1_000, MaxTagChars = 64;
    public const int MaxPerFile = 10_000, MaxTotal = 50_000;
    public static readonly string[] Kinds = ["finding", "question", "hypothesis", "todo"];
    public static readonly string[] Statuses = ["open", "confirmed", "refuted", "answered", "dropped"];

    /// <summary>
    /// Who wrote a note: an MCP client (agent) or the command line (user);
    /// notes from older versions have none.
    /// </summary>
    public const string AgentOrigin = "agent", UserOrigin = "user";

    /// <summary>
    /// The origin of a note written through the client named
    /// <paramref name="clientName"/>.
    /// </summary>
    public static string OriginOf(string? clientName) => clientName == ClientProfiles.CliClientName ? UserOrigin : AgentOrigin;

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

    /// <summary>Checks evidence entries; a call without resultSha256 takes this process's latest identical call's hash, else
    /// goes in <paramref name="unmatched"/>.</summary>
    public static List<NoteEvidence> CheckEvidence(IReadOnlyList<NoteEvidence>? entries, List<string>? unmatched = null)
    {
        var list = new List<NoteEvidence>();
        foreach (var raw in entries ?? [])
        {
            var e = raw with { Tool = string.IsNullOrWhiteSpace(raw.Tool) ? null : raw.Tool.Trim(), Text = string.IsNullOrWhiteSpace(raw.Text) ? null : raw.Text.Trim(),
                ResultSha256 = string.IsNullOrWhiteSpace(raw.ResultSha256) ? null : raw.ResultSha256.Trim().ToLowerInvariant(),
                Result = string.IsNullOrWhiteSpace(raw.Result) ? null : raw.Result.Trim(), Expect = string.IsNullOrWhiteSpace(raw.Expect) ? null : raw.Expect.Trim().ToLowerInvariant() };
            if (e.Result != null)
            {
                if (!ResultStore.IsId(e.Result))
                    throw new ToolError(ErrorCode.InvalidArgument, $"result '{e.Result}' is not a kept result id (r-<12 hex>).", "pass a kept result id or last:N");
                e = e with { Expect = e.Expect ?? NoteEvidence.Supports };
                if (e.Expect is not (NoteEvidence.Supports or NoteEvidence.Refutes))
                    throw new ToolError(ErrorCode.InvalidArgument, $"expect must be supports or refutes, not '{raw.Expect}'.");
                list.Add(e);
                continue;
            }
            if (e.Expect != null || e.Verdict != null)
                throw new ToolError(ErrorCode.InvalidArgument, "expect and verdict belong to an evidence entry that links a saved record.", "pass {result: \"r-…\" or \"last:N\", expect}");
            if (e.Tool == null && e.Text == null)
                throw new ToolError(ErrorCode.InvalidArgument, "An evidence entry needs a saved record (result), a tool (with its args) or a text.", "pass {result}, {tool, args} of the call that shows it, or {text}");
            if (e.Tool == null && (e.Args != null || e.ResultSha256 != null))
                throw new ToolError(ErrorCode.InvalidArgument, "An evidence entry with args or resultSha256 needs the tool they belong to.");
            if (e.ResultSha256 is { } sha && (sha.Length != 64 || !sha.All(char.IsAsciiHexDigit)))
                throw new ToolError(ErrorCode.InvalidArgument, $"resultSha256 '{sha}' is not a SHA-256 (64 hex digits).", "copy it from _meta corvus/provenance, or leave it out");
            if (e.Tool != null && e.ResultSha256 == null)
            {
                e = e with { ResultSha256 = ResultHashes.Latest(e.Tool, e.Args) };
                if (e.ResultSha256 == null) unmatched?.Add(e.Tool);
            }
            list.Add(e);
        }
        return list;
    }

    private static List<NoteEvidence> MergeEvidence(IEnumerable<NoteEvidence> current, IReadOnlyList<NoteEvidence>? add)
    {
        var list = current.ToList();
        foreach (var e in add ?? [])
        {
            int size = JsonSerializer.Serialize(e).Length;
            if (size > MaxEvidenceChars) throw new ToolError(ErrorCode.LimitExceeded, $"An evidence entry is {size} characters as JSON; the limit is {MaxEvidenceChars}.");
            int i = list.FindIndex(x => x.Key == e.Key);
            if (i < 0) list.Add(e);
            // The same call again keeps its latest result.
            else if (e.ResultSha256 != null) list[i] = e;
        }
        if (list.Count > MaxEvidence) throw new ToolError(ErrorCode.LimitExceeded, $"A note holds at most {MaxEvidence} evidence entries ({list.Count} given).");
        return list;
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
    public Note Record(string text, string? kind, string? status, NoteAnchor anchor, IReadOnlyList<string>? tags, IReadOnlyList<NoteEvidence>? evidence, string? author,
        string? origin = null)
    {
        var now = DateTime.UtcNow;
        var note = new Note(NewId(), CheckKind(kind), CheckStatus(status), CheckText(text), Merge([], tags, null, MaxTags, MaxTagChars, "tag"),
            MergeEvidence([], evidence), anchor, 1, now, now, author, origin);
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

    /// <summary>Applies <paramref name="change"/> at <paramref name="expectedRevision"/>, else a Conflict carrying the current
    /// note.</summary>
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
                Evidence = MergeEvidence(current.Evidence, change.AddEvidence),
                Revision = current.Revision + 1,
                Updated = DateTime.UtcNow,
            };
            file.Notes[i] = updated;
        });
        return updated!;
    }

    /// <summary>Adds notes made elsewhere; an existing id is replaced only by a higher revision. Returns the counts.</summary>
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
            if (file.Format is not (Format or Format2 or Format1 or LegacyFormat))
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
            if (LockedJsonFile.Read<NoteFile>(path, Json).Value is { Format: Format or Format2 or Format1 or LegacyFormat } file)
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
