using System.Text.Json;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Native.Annotations;

/// <summary>
/// The user's names, comments and engine types for one image, keyed by RVA. The authoritative in-memory copy for a
/// session: it is loaded from the sidecar when the image loads (by the image's load-time SHA-256, which stays the
/// annotation key even after in-memory patches) and saved on every change. Saves merge: under the sidecar's lock the
/// file is re-read and only this process's changes since the last read or write are applied on top, so several server
/// processes annotating one image keep each other's entries; their entries flow into this copy
/// (<see cref="MergedFromDisk"/>). The code index mirrors it so names show up in disassembly, list_functions and cross-references.
/// </summary>
public sealed class NativeAnnotations
{
    private readonly AnnotationStore _store;
    private readonly object _gate = new();
    private readonly Dictionary<uint, string> _names = new();
    private readonly Dictionary<uint, string> _comments = new();
    private UserTypeLayer _userTypes = UserTypeLayer.Empty;

    // The sidecar as last read or written: the change set of this process is the difference between it and the live maps.
    private Snapshot _base = Snapshot.Empty();
    private ulong _baseRevision;
    private (long Length, long Ticks) _stamp;

    /// <summary>The SHA-256 the sidecar is keyed by (the file's hash when first loaded).</summary>
    public string Sha256 { get; }
    public string FilePath { get; }
    public ulong ImageBase { get; }

    /// <summary>Hashes of sidecars for the same path but a different file version, if any (set once at load).</summary>
    public IReadOnlyList<string> StaleSiblingHashes { get; }

    /// <summary>Set when the sidecar is left in place and must not be overwritten: changes stay in memory.</summary>
    public string? WriteBlocked { get; private set; }

    /// <summary>Names and comments another process saved, now in this copy (null: removed). Raised outside the lock.</summary>
    public event Action<IReadOnlyList<(uint Rva, string? Name)>, IReadOnlyList<(uint Rva, string? Comment)>>? MergedFromDisk;

    private readonly Action<string>? _notify;
    private string? _lastSaveProblem;

    /// <param name="notify">Receives warnings about the sidecar (moved aside, left in place, a failed save, a conflict).</param>
    public NativeAnnotations(AnnotationStore store, string filePath, string sha256, ulong imageBase, Action<string>? notify = null)
    {
        _store = store;
        _notify = notify;
        FilePath = filePath;
        Sha256 = sha256;
        ImageBase = imageBase;
        StaleSiblingHashes = store.FindOtherHashesForPath(filePath, sha256);
        _stamp = store.Stamp(sha256);
        var loaded = store.Open(sha256);
        if (loaded.Warning != null) notify?.Invoke(loaded.Warning);
        if (loaded.WriteBlocked) WriteBlocked = loaded.Warning;
        if (loaded.Document is { } doc)
        {
            Adopt(doc);
            _base = Live();
            _baseRevision = doc.Revision;
        }
    }

    private static UserTypeLayer UserTypesOf(AnnotationDocument doc)
    {
        if (!doc.HasUserTypes) return UserTypeLayer.Empty;
        var types = new Dictionary<uint, string>();
        foreach (var (k, v) in doc.Types ?? []) if (Rva(k) is { } r && !string.IsNullOrWhiteSpace(v)) types[r] = v;
        var locals = new Dictionary<uint, IReadOnlyList<NativeLocalEdit>>();
        foreach (var (k, list) in doc.Locals ?? [])
            if (Rva(k) is { } f && list is { Count: > 0 })
                locals[f] = list.Where(e => e.Local.Length > 0).Select(e => new NativeLocalEdit(f, e.Local, e.Stack, e.Name, e.Type)).ToList();
        var stack = new Dictionary<uint, IReadOnlyList<NativeStackVarEdit>>();
        foreach (var (k, list) in doc.StackVars ?? [])
            if (Rva(k) is { } f && list is { Count: > 0 }) stack[f] = list.Select(e => new NativeStackVarEdit(f, e.Offset, e.Name, e.Type)).ToList();
        var analysis = new List<NativeAnalysisEdit>();
        foreach (var a in doc.Analysis ?? [])
            if (Rva(a.Rva) is { } r && a.Kind.Length > 0)
                analysis.Add(new NativeAnalysisEdit(r, a.Kind, a.End != null ? Rva(a.End) : null, a.Type));
        return new UserTypeLayer(doc.Declarations?.Where(d => !string.IsNullOrWhiteSpace(d)).ToList() ?? [], types, locals, stack, analysis);
    }

    private static AnnotationDocument.AnalysisEntry Entry(NativeAnalysisEdit a) =>
        new() { Rva = Hex(a.Rva), Kind = a.Kind, End = a.End is { } e ? Hex(e) : null, Type = a.Type };

    /// <summary>The user's engine types (prototypes, global types, locals, stack members, declarations).</summary>
    public UserTypeLayer UserTypes { get { lock (_gate) return _userTypes; } }

    /// <summary>Replaces the user types with <paramref name="change"/>'s result and persists; returns the new layer.</summary>
    public UserTypeLayer ChangeUserTypes(Func<UserTypeLayer, UserTypeLayer> change)
    {
        Merged? merged;
        UserTypeLayer result;
        lock (_gate)
        {
            var next = change(_userTypes);
            if (ReferenceEquals(next, _userTypes)) return next;
            _userTypes = next;
            merged = Persist();
            result = _userTypes;
        }
        Raise(merged);
        return result;
    }

    private static uint? Rva(string hex) => uint.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var v) ? v : null;

    private static string Hex(uint rva) => rva.ToString("x", System.Globalization.CultureInfo.InvariantCulture);

    public int NameCount { get { lock (_gate) return _names.Count; } }
    public int CommentCount { get { lock (_gate) return _comments.Count; } }

    public string? NameAt(uint rva) { lock (_gate) return _names.GetValueOrDefault(rva); }
    public string? CommentAt(uint rva) { lock (_gate) return _comments.GetValueOrDefault(rva); }

    /// <summary>A snapshot of all (rva, name) pairs, sorted by RVA.</summary>
    public IReadOnlyList<(uint Rva, string Name)> Names()
    {
        lock (_gate) return _names.Select(kv => (kv.Key, kv.Value)).OrderBy(p => p.Key).ToList();
    }

    public IReadOnlyList<(uint Rva, string Comment)> Comments()
    {
        lock (_gate) return _comments.Select(kv => (kv.Key, kv.Value)).OrderBy(p => p.Key).ToList();
    }

    /// <summary>
    /// Validates and records a name at <paramref name="rva"/>; a null or empty name removes it. Refuses a name already
    /// used at another address unless <paramref name="allowDuplicate"/>. Persists on success.
    /// </summary>
    public void SetName(uint rva, string? name, bool allowDuplicate = false)
    {
        Merged? merged;
        lock (_gate)
        {
            if (string.IsNullOrWhiteSpace(name)) _names.Remove(rva);
            else
            {
                var valid = NativeName.Validate(name);
                if (!allowDuplicate)
                    foreach (var (other, used) in _names)
                        if (other != rva && string.Equals(used, valid, StringComparison.Ordinal))
                            throw new ToolError(ErrorCode.Conflict, $"The name '{valid}' is already used at rva 0x{other:X}.",
                                "pass allowDuplicate=true to use it anyway, or pick another name");
                _names[rva] = valid;
            }
            merged = Persist();
        }
        Raise(merged);
    }

    /// <summary>Records a comment at <paramref name="rva"/>; a null or empty text removes it. Persists on success.</summary>
    public void SetComment(uint rva, string? text)
    {
        Merged? merged;
        lock (_gate)
        {
            var t = text?.Trim();
            if (string.IsNullOrEmpty(t)) _comments.Remove(rva);
            else _comments[rva] = Cap(t);
            merged = Persist();
        }
        Raise(merged);
    }

    /// <summary>Records validated names and comments in one change, persisted once (migrate_native_names).</summary>
    public void SetMany(IEnumerable<(uint Rva, string Name)> names, IEnumerable<(uint Rva, string Text)> comments)
    {
        Merged? merged;
        lock (_gate)
        {
            foreach (var (rva, name) in names) _names[rva] = NativeName.Validate(name);
            foreach (var (rva, text) in comments)
            {
                var t = text.Trim();
                if (t.Length > 0) _comments[rva] = Cap(t);
            }
            merged = Persist();
        }
        Raise(merged);
    }

    private const int MaxComment = 4000;

    private static string Cap(string text) => text.Length > MaxComment ? text[..MaxComment] : text;

    /// <summary>
    /// Takes in what other processes saved since the last read or write. Cheap when nothing changed (one file stat), so
    /// readers call it before reporting names.
    /// </summary>
    public void Refresh()
    {
        if (WriteBlocked != null) return;
        var stamp = _store.Stamp(Sha256);
        Merged? merged;
        lock (_gate)
        {
            if (stamp == _stamp || WriteBlocked != null) return;
            var loaded = _store.Open(Sha256);
            if (loaded.Warning != null) _notify?.Invoke(loaded.Warning);
            _stamp = stamp;
            if (loaded.WriteBlocked) { WriteBlocked = loaded.Warning; return; }
            if (loaded.Document is { Revision: > 0 } same && same.Revision == _baseRevision) return;
            // A sidecar moved aside as corrupt adds nothing: this copy still holds everything it had.
            var disk = loaded.Document is { } doc ? Normalize(doc) : loaded.Warning != null ? _base : Snapshot.Empty();
            var (result, _) = Merge(_base, Live(), disk);
            _base = disk;
            _baseRevision = loaded.Document?.Revision ?? 0;
            merged = Adopt(ToDocument(result));
        }
        Raise(merged);
    }

    private sealed record Merged(IReadOnlyList<(uint Rva, string? Name)> Names, IReadOnlyList<(uint Rva, string? Comment)> Comments);

    private void Raise(Merged? merged)
    {
        if (merged is { } m && (m.Names.Count > 0 || m.Comments.Count > 0)) MergedFromDisk?.Invoke(m.Names, m.Comments);
    }

    /// <summary>Saves this process's changes merged onto the sidecar; returns what other processes had added. Caller holds the gate.</summary>
    private Merged? Persist()
    {
        if (WriteBlocked != null) return null;
        var mine = Live();
        var warnings = new List<string>();
        var conflicts = new List<string>();
        var saved = _store.Update(Sha256, loaded =>
        {
            if (loaded.Warning != null) warnings.Add(loaded.Warning);
            var disk = loaded.Document is { } doc ? Normalize(doc) : loaded.Warning != null ? _base : Snapshot.Empty();
            var (result, found) = Merge(_base, mine, disk);
            conflicts = found;
            return ToDocument(result);
        });
        foreach (var w in warnings) _notify?.Invoke(w);
        if (saved.Problem != null)
        {
            // The change set stays (the base is unchanged), so the next save retries it. One notice per distinct problem.
            if (saved.Problem != _lastSaveProblem) _notify?.Invoke($"Annotations of {FilePath} could not be saved: {saved.Problem}");
            _lastSaveProblem = saved.Problem;
            return null;
        }
        _lastSaveProblem = null;
        if (conflicts.Count > 0)
            _notify?.Invoke($"Annotations of {FilePath} were also changed by another process: {conflicts.Count} conflict(s), this process's values kept " +
                            $"(a replaced name is kept as a [conflict] comment): {string.Join("; ", conflicts.Take(5))}{(conflicts.Count > 5 ? "; ..." : "")}");
        var written = saved.Written!;
        var merged = Adopt(written);
        _base = Live();
        _baseRevision = written.Revision;
        _stamp = saved.Stamp;
        return merged;
    }

    private AnnotationDocument Current() => Compose(_names, _comments, _userTypes);

    private static AnnotationDocument Compose(Dictionary<uint, string> names, Dictionary<uint, string> comments, UserTypeLayer u)
    {
        var doc = new AnnotationDocument();
        foreach (var (r, n) in names) doc.Names[Hex(r)] = n;
        foreach (var (r, c) in comments) doc.Comments[Hex(r)] = c;
        if (u.Declarations.Count > 0) doc.Declarations = [.. u.Declarations];
        if (u.Types.Count > 0) doc.Types = u.Types.ToDictionary(t => Hex(t.Key), t => t.Value);
        if (u.Locals.Count > 0)
            doc.Locals = u.Locals.ToDictionary(l => Hex(l.Key), l => l.Value.Select(e => new AnnotationDocument.LocalEntry { Local = e.Local, Stack = e.Stack, Name = e.Name, Type = e.Type }).ToList());
        if (u.StackVars.Count > 0)
            doc.StackVars = u.StackVars.ToDictionary(s => Hex(s.Key), s => s.Value.Select(e => new AnnotationDocument.StackVarEntry { Offset = e.Offset, Name = e.Name, Type = e.Type }).ToList());
        if (u.Analysis.Count > 0) doc.Analysis = u.Analysis.Select(Entry).ToList();
        return doc;
    }

    /// <summary>Replaces the live maps with <paramref name="doc"/>; returns the names and comments that changed.</summary>
    private Merged Adopt(AnnotationDocument doc)
    {
        var (names, comments) = Maps(doc);
        var result = new Merged(Replace(_names, names), Replace(_comments, comments));
        var types = UserTypesOf(doc);
        if (types.Stamp != _userTypes.Stamp) _userTypes = types;
        return result;
    }

    private static (Dictionary<uint, string> Names, Dictionary<uint, string> Comments) Maps(AnnotationDocument doc)
    {
        var names = new Dictionary<uint, string>();
        var comments = new Dictionary<uint, string>();
        foreach (var (k, v) in doc.Names) if (Rva(k) is { } r) names[r] = v;
        foreach (var (k, v) in doc.Comments) if (Rva(k) is { } r) comments[r] = v;
        return (names, comments);
    }

    private static List<(uint, string?)> Replace(Dictionary<uint, string> live, Dictionary<uint, string> next)
    {
        var changed = new List<(uint, string?)>();
        foreach (var (rva, value) in live) if (!next.ContainsKey(rva)) changed.Add((rva, null));
        foreach (var (rva, value) in next) if (!live.TryGetValue(rva, out var old) || old != value) changed.Add((rva, value));
        live.Clear();
        foreach (var (rva, value) in next) live[rva] = value;
        return changed;
    }

    // ---- merge ----

    private const int NameSection = 0, CommentSection = 1, TypeSection = 2, LocalSection = 3, StackSection = 4, DeclarationSection = 5, AnalysisSection = 6;
    private static readonly string[] SectionLabels = ["name", "comment", "type", "locals", "stack members", "declaration", "analysis edit"];

    /// <summary>The sidecar as one comparable text value per key in each section (lists as their JSON).</summary>
    private sealed class Snapshot
    {
        public readonly Dictionary<string, string>[] Sections;

        private Snapshot(Dictionary<string, string>[] sections) => Sections = sections;

        public static Snapshot Empty() => new([.. SectionLabels.Select(_ => new Dictionary<string, string>(StringComparer.Ordinal))]);

        public Snapshot Clone() => new([.. Sections.Select(s => new Dictionary<string, string>(s, StringComparer.Ordinal))]);
    }

    private Snapshot Live() => ToSnapshot(Current());

    /// <summary>A document read from disk in the shape this build writes, so unchanged entries compare equal.</summary>
    private static Snapshot Normalize(AnnotationDocument doc)
    {
        var (names, comments) = Maps(doc);
        return ToSnapshot(Compose(names, comments, UserTypesOf(doc)));
    }

    private static Snapshot ToSnapshot(AnnotationDocument doc)
    {
        var s = Snapshot.Empty();
        foreach (var (k, v) in doc.Names) s.Sections[NameSection][k] = v;
        foreach (var (k, v) in doc.Comments) s.Sections[CommentSection][k] = v;
        foreach (var (k, v) in doc.Types ?? []) s.Sections[TypeSection][k] = v;
        foreach (var (k, v) in doc.Locals ?? []) s.Sections[LocalSection][k] = JsonSerializer.Serialize(v);
        foreach (var (k, v) in doc.StackVars ?? []) s.Sections[StackSection][k] = JsonSerializer.Serialize(v);
        foreach (var d in doc.Declarations ?? []) s.Sections[DeclarationSection][d] = d;
        foreach (var a in doc.Analysis ?? []) s.Sections[AnalysisSection][a.Rva] = JsonSerializer.Serialize(a);
        return s;
    }

    private AnnotationDocument ToDocument(Snapshot s)
    {
        var doc = new AnnotationDocument
        {
            Path = FilePath, Sha256 = Sha256, ImageBase = ImageBase,
            Names = new(s.Sections[NameSection]), Comments = new(s.Sections[CommentSection]),
        };
        if (s.Sections[TypeSection].Count > 0) doc.Types = new(s.Sections[TypeSection]);
        if (s.Sections[LocalSection].Count > 0)
            doc.Locals = s.Sections[LocalSection].ToDictionary(kv => kv.Key, kv => JsonSerializer.Deserialize<List<AnnotationDocument.LocalEntry>>(kv.Value)!);
        if (s.Sections[StackSection].Count > 0)
            doc.StackVars = s.Sections[StackSection].ToDictionary(kv => kv.Key, kv => JsonSerializer.Deserialize<List<AnnotationDocument.StackVarEntry>>(kv.Value)!);
        if (s.Sections[DeclarationSection].Count > 0) doc.Declarations = [.. s.Sections[DeclarationSection].Keys];
        if (s.Sections[AnalysisSection].Count > 0)
            doc.Analysis = s.Sections[AnalysisSection].Values.Select(v => JsonSerializer.Deserialize<AnnotationDocument.AnalysisEntry>(v)!).ToList();
        return doc;
    }

    /// <summary>
    /// Applies this process's changes (<paramref name="mine"/> against <paramref name="base"/>) onto <paramref name="disk"/>.
    /// Where another process changed the same key too, this process's value wins, except that a removal loses to a
    /// change; a replaced name is kept as a [conflict] comment and a replaced comment is appended to ours.
    /// </summary>
    private static (Snapshot Merged, List<string> Conflicts) Merge(Snapshot @base, Snapshot mine, Snapshot disk)
    {
        var merged = disk.Clone();
        var conflicts = new List<string>();
        var replacedNames = new List<(string Key, string Theirs)>();
        for (int section = 0; section < SectionLabels.Length; section++)
        {
            var (was, ours, theirs, result) = (@base.Sections[section], mine.Sections[section], disk.Sections[section], merged.Sections[section]);
            foreach (var key in was.Keys.Union(ours.Keys, StringComparer.Ordinal).ToList())
            {
                var before = was.GetValueOrDefault(key);
                var value = ours.GetValueOrDefault(key);
                if (value == before) continue;
                var other = theirs.GetValueOrDefault(key);
                if (other == value) continue;
                if (other != null && other != before)
                {
                    if (value == null) continue;
                    conflicts.Add($"{SectionLabels[section]} at 0x{key}: kept '{Short(value)}', other process had '{Short(other)}'");
                    if (section == NameSection) replacedNames.Add((key, other));
                    else if (section == CommentSection) value = Cap(value + "\n[conflict] another process commented: " + other);
                }
                if (value == null) result.Remove(key);
                else result[key] = value;
            }
        }
        var comments = merged.Sections[CommentSection];
        foreach (var (key, theirs) in replacedNames)
        {
            var line = $"[conflict] another process named this '{theirs}'";
            comments[key] = Cap(comments.TryGetValue(key, out var c) ? c + "\n" + line : line);
        }
        // Declarations apply in order: theirs first, then ours that are new.
        Reorder(merged.Sections[DeclarationSection], disk.Sections[DeclarationSection].Keys.Concat(mine.Sections[DeclarationSection].Keys));
        // Analysis edits: ours in our order (an edit made again moved to the end), then theirs.
        Reorder(merged.Sections[AnalysisSection], mine.Sections[AnalysisSection].Keys.Concat(disk.Sections[AnalysisSection].Keys));
        return (merged, conflicts);
    }

    /// <summary>Rebuilds an order-carrying section in <paramref name="order"/> (keys not in it are dropped from the order).</summary>
    private static void Reorder(Dictionary<string, string> section, IEnumerable<string> order)
    {
        var ordered = order.Where(section.ContainsKey).Distinct(StringComparer.Ordinal).Select(k => (k, section[k])).ToList();
        section.Clear();
        foreach (var (k, v) in ordered) section[k] = v;
    }

    private static string Short(string text) => text.Length > 60 ? text[..57] + "..." : text;
}
