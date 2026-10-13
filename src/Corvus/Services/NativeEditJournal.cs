using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Patching;
using Corvus.Native.Providers;

namespace Corvus.Services;

/// <summary>Names, comments and pseudocode comments at one address.</summary>
public sealed record NativeAnnotationState(string? Name, string? Comment, string? CommentKind, string? Pseudo)
{
    public static readonly NativeAnnotationState None = new(null, null, null, null);
}

/// <summary>One address's annotations before and after an edit.</summary>
public sealed record NativeAnnotationChange(uint Rva, NativeAnnotationState Before, NativeAnnotationState After);

/// <summary>
/// One journaled native edit: an id that is never reused, the tool that made it and what it changed: byte patch
/// (<see cref="Patch"/>), names and comments (<see cref="Annotations"/>) or engine user types (<see cref="UserTypes"/>, made in <see cref="Engine"/>).
/// </summary>
public sealed record NativeJournalEntry(EditId Id, string Tool, string Kind, string Description)
{
    public const string PatchKind = "patch", AnnotationKind = "annotation", EngineKind = "engine";

    public NativePatch? Patch { get; init; }
    public IReadOnlyList<NativeAnnotationChange> Annotations { get; init; } = [];
    public UserTypeDelta? UserTypes { get; init; }
    /// <summary>The engine an engine edit was made in (ida, ghidra); undo opens it when no session is open.</summary>
    public string? Engine { get; init; }
    /// <summary>The engine batch that takes the edit back, when the recording tool knows a better one than the generic inverse.</summary>
    public NativeUserTypeBatch? Inverse { get; init; }
    /// <summary>The engine's own prototypes the edit replaced, set again on undo.</summary>
    public IReadOnlyDictionary<uint, string>? EnginePrototypes { get; init; }
    public DateTime Time { get; init; } = DateTime.UtcNow;
}

/// <summary>An undo: the entry taken back, the changes as made by the undo, the engines that received them, and notes.</summary>
public sealed record NativeUndoResult(NativeJournalEntry Entry, IReadOnlyList<EditChange> Changes, IReadOnlyList<string> PushedTo, IReadOnlyList<string> Notes);

/// <summary>
/// The native edit journal (EL-6): every native edit of a loaded image (byte patch, name, comment, engine type edit,
/// migration) gets an <see cref="EditId"/> "&lt;image&gt;#n" with what it replaced, so undo puts the previous state back
/// and pushes it to the engines. The entries belong to the loaded image (all instances share them); a reload starts a new journal.
/// </summary>
public sealed class NativeEditJournal(AssemblyWorkspace workspace, NativeCodeService code, NativeEngineService? engines = null,
    NativeNamePush? names = null, NativeUserTypePush? userTypes = null)
{
    private sealed class ImageJournal
    {
        public readonly List<NativeJournalEntry> Entries = [];
        public int Next = 1;
    }

    private static readonly ConditionalWeakTable<LoadedNative, ImageJournal> Journals = new();

    private static ImageJournal Of(LoadedNative native) => Journals.GetValue(native, _ => new ImageJournal());

    /// <summary>The image's edits in the order made; patches no longer in the patch set (reloaded, replaced) are dropped.</summary>
    public IReadOnlyList<NativeJournalEntry> Entries(LoadedNative native)
    {
        var j = Of(native);
        lock (j)
        {
            j.Entries.RemoveAll(e => e.Patch != null && !native.Patches.Patches.Contains(e.Patch));
            return [.. j.Entries];
        }
    }

    /// <summary>The entry <paramref name="id"/> of the image, or null.</summary>
    public NativeJournalEntry? Find(LoadedNative native, EditId id) => Entries(native).FirstOrDefault(e => e.Id == id);

    private EditId Add(LoadedNative native, Func<EditId, NativeJournalEntry> make)
    {
        var j = Of(native);
        lock (j)
        {
            var entry = make(new EditId(native.Id, j.Next++));
            j.Entries.Add(entry);
            return entry.Id;
        }
    }

    // ---- record ----

    /// <summary>Records a byte patch already added to the image's patch set.</summary>
    public EditId RecordPatch(LoadedNative native, string tool, NativePatch patch) =>
        Add(native, id => new NativeJournalEntry(id, tool, NativeJournalEntry.PatchKind, patch.Description) { Patch = patch });

    /// <summary>The annotations at <paramref name="rva"/> as kept now.</summary>
    public NativeAnnotationState StateAt(LoadedNative native, uint rva)
    {
        var ann = code.Annotations(native);
        return new(ann.NameAt(rva), ann.CommentAt(rva), ann.CommentKindAt(rva), ann.PseudoCommentAt(rva));
    }

    /// <summary>
    /// Runs <paramref name="apply"/>, which changes names or comments at <paramref name="rvas"/>, and records what changed
    /// there as one edit; null when nothing changed. Migrations pass every address they write.
    /// </summary>
    public EditId? RecordAnnotations(LoadedNative native, string tool, IEnumerable<uint> rvas, Action apply, string? description = null)
    {
        var at = rvas.Distinct().ToList();
        var before = at.Select(r => StateAt(native, r)).ToList();
        apply();
        var changes = at.Select((r, i) => new NativeAnnotationChange(r, before[i], StateAt(native, r))).Where(c => c.Before != c.After).ToList();
        if (changes.Count == 0) return null;
        return Add(native, id => new NativeJournalEntry(id, tool, NativeJournalEntry.AnnotationKind, description ?? Describe(tool, changes)) { Annotations = changes });
    }

    /// <summary>Records an engine user-type change from <paramref name="before"/> to <paramref name="after"/>; null when they hold the same items.</summary>
    public EditId? RecordUserTypes(LoadedNative native, string tool, string? engine, UserTypeLayer before, UserTypeLayer after, string? description = null,
        NativeUserTypeBatch? inverse = null)
    {
        var delta = UserTypeDelta.Between(before, after);
        if (delta.IsEmpty) return null;
        return Add(native, id => new NativeJournalEntry(id, tool, NativeJournalEntry.EngineKind, description ?? Describe(tool, delta))
            { UserTypes = delta, Engine = engine, Inverse = inverse });
    }

    /// <summary>
    /// <see cref="NativeUserTypePush.ApplyAsync"/> with the layer change it records journaled as one edit (null when the
    /// engine took nothing). The before and after layers are the ones swapped under the annotation lock.
    /// </summary>
    public async Task<(UserTypeResult Result, EditId? EditId)> ApplyUserTypesAsync(LoadedNative native, INativeDecompilerSession session, string tool,
        NativeUserTypeBatch edit, Func<UserTypeResult, UserTypeLayer, UserTypeLayer?> record, CancellationToken ct, string? description = null,
        NativeUserTypeBatch? inverse = null)
    {
        var push = userTypes ?? throw new ToolError(ErrorCode.Unsupported, "Engine edits need the user type push.");
        var previous = await EnginePrototypes(native, session, edit, ct).ConfigureAwait(false);
        UserTypeLayer? before = null, after = null;
        var result = await push.ApplyAsync(native, session, edit, (r, layer) =>
        {
            var next = record(r, layer);
            (before, after) = (layer, next);
            return next;
        }, ct).ConfigureAwait(false);
        var id = before != null && after != null ? RecordUserTypes(native, tool, session.ProviderId, before, after, description, inverse) : null;
        if (id is { } recorded && previous.Count > 0)
        {
            var j = Of(native);
            lock (j)
                if (j.Entries.FindIndex(e => e.Id == recorded) is var i and >= 0) j.Entries[i] = j.Entries[i] with { EnginePrototypes = previous };
        }
        return (result, id);
    }

    /// <summary>
    /// The engine's own prototypes of the functions the batch types that have no user type yet: clearing a user type does
    /// not bring them back in every engine (Ghidra keeps the signature), so undo sets them again.
    /// </summary>
    private async Task<IReadOnlyDictionary<uint, string>> EnginePrototypes(LoadedNative native, INativeDecompilerSession session, NativeUserTypeBatch edit, CancellationToken ct)
    {
        var result = new Dictionary<uint, string>();
        var layer = code.Annotations(native).UserTypes;
        foreach (var t in edit.Types.Where(t => !layer.Types.ContainsKey(t.Rva)))
        {
            try
            {
                if (await session.GetFunctionRecordAsync(t.Rva, ct).ConfigureAwait(false) is { Start: var start, Prototype: { Length: > 0 } proto } && start == t.Rva)
                    result[t.Rva] = proto;
            }
            catch (ToolError) { } // no function there, or the engine cannot say: undo clears the type
        }
        return result;
    }

    private static string Describe(string tool, IReadOnlyList<NativeAnnotationChange> changes) =>
        changes.Count == 1 ? $"{tool} rva 0x{changes[0].Rva:X}" : $"{tool} {changes.Count} addresses";

    private static string Describe(string tool, UserTypeDelta delta) =>
        delta.Items.Count == 1 && delta.Describe().First() is var (kind, target, _, _) ? $"{tool} {kind} {target}" : $"{tool} {delta.Items.Count} items";

    // ---- undo ----

    /// <summary>
    /// Takes back edit <paramref name="id"/> (null: the last): restores the previous bytes, names, comments or user types,
    /// refreshes the code index and pushes the change to the engines with this image open (an engine edit's own engine is
    /// opened when it is not). Refused when a later edit changed the same item.
    /// </summary>
    public async Task<NativeUndoResult> UndoAsync(LoadedNative native, EditId? id, CancellationToken ct)
    {
        var entries = Entries(native);
        var entry = id is { } want
            ? entries.FirstOrDefault(e => e.Id == want) ?? throw new ToolError(ErrorCode.NotFound, $"There is no native edit {want}.",
                "list_native_edits shows the recorded edits")
            : entries.LastOrDefault() ?? throw new ToolError(ErrorCode.NotFound, $"{native.Id} has no native edits to undo.",
                "list_native_edits shows what is recorded");
        var result = entry.Kind switch
        {
            NativeJournalEntry.PatchKind => UndoPatch(native, entry),
            NativeJournalEntry.AnnotationKind => await UndoAnnotations(native, entry, entries, ct).ConfigureAwait(false),
            _ => await UndoUserTypes(native, entry, entries, ct).ConfigureAwait(false),
        };
        var j = Of(native);
        lock (j) j.Entries.Remove(entry);
        return result;
    }

    private NativeUndoResult UndoPatch(LoadedNative native, NativeJournalEntry entry) => workspace.Write(() =>
    {
        var patch = entry.Patch!;
        var set = native.Patches;
        int index = set.Patches.ToList().IndexOf(patch);
        if (index < 0) throw new ToolError(ErrorCode.NotFound, $"The patch of {entry.Id} is no longer recorded.", "list_native_edits shows the recorded edits");
        if (set.LaterSlotUser(index + 1) is { } later && Entries(native).FirstOrDefault(e => e.Patch == later.Patch) is var by)
            throw new ToolError(ErrorCode.Conflict,
                $"Native edit {by?.Id.ToString() ?? $"#{later.Number}"} ({later.Patch.Description}) rewrote a relocation entry this edit also rewrote; undoing this one first would leave the table inconsistent.",
                $"undo_native_edit editId={by?.Id.ToString() ?? native.Id + "#?"} first");
        set.Remove(index + 1);
        NativeEditService.Rebuild(code, native);
        var va = NativeAddress.Va(native.Image, patch.Rva);
        return new NativeUndoResult(entry, [new EditChange("bytes", va, Hex(patch.Replacement), Hex(patch.Original))], [], []);
    });

    private async Task<NativeUndoResult> UndoAnnotations(LoadedNative native, NativeJournalEntry entry, IReadOnlyList<NativeJournalEntry> entries, CancellationToken ct)
    {
        // only the parts the edit changed must still hold its values: a later comment does not block undoing a rename there
        var changed = entry.Annotations.Where(c => !Holds(StateAt(native, c.Rva), c)).ToList();
        if (changed.Count > 0)
        {
            var by = entries.SkipWhile(e => e != entry).Skip(1).FirstOrDefault(e => e.Annotations.Any(a => changed.Any(c => c.Rva == a.Rva && Overlaps(a, c))));
            throw new ToolError(ErrorCode.Conflict,
                $"The annotations at {NativeAddress.Va(native.Image, changed[0].Rva)} changed since {entry.Id}{(by != null ? $" (by {by.Id})" : "")}.",
                by != null ? $"undo_native_edit editId={by.Id} first" : "rename_native or comment_native sets the value wanted");
        }
        var ann = code.Annotations(native);
        workspace.Write(() =>
        {
            var restore = entry.Annotations;
            ann.Apply([.. restore.Where(c => c.Before.Name != c.After.Name).Select(c => (c.Rva, c.Before.Name))],
                [.. restore.Where(CommentChanged).Select(c => (c.Rva, c.Before.Comment))],
                [.. restore.Where(c => c.Before.Pseudo != c.After.Pseudo).Select(c => (c.Rva, c.Before.Pseudo))], allowDuplicate: true,
                kinds: [.. restore.Where(CommentChanged).Select(c => (c.Rva, c.Before.CommentKind))]);
            foreach (var index in new[] { code.Ready(native), code.Provisional(native) }.OfType<Native.Code.NativeCodeIndex>().Distinct())
                foreach (var c in restore)
                {
                    if (c.Before.Name != c.After.Name) index.SetUserName(c.Rva, c.Before.Name);
                    if (CommentChanged(c)) index.SetUserComment(c.Rva, c.Before.Comment);
                }
            return 0;
        });
        var changes = new List<EditChange>();
        foreach (var c in entry.Annotations)
        {
            var va = NativeAddress.Va(native.Image, c.Rva);
            if (c.Before.Name != c.After.Name) changes.Add(new("name", va, c.After.Name, c.Before.Name));
            if (c.Before.Comment != c.After.Comment || c.Before.CommentKind != c.After.CommentKind) changes.Add(new("comment", va, c.After.Comment, c.Before.Comment));
            if (c.Before.Pseudo != c.After.Pseudo) changes.Add(new("pseudocode", va, c.After.Pseudo, c.Before.Pseudo));
        }
        var pushed = new List<string>();
        var notes = new List<string>();
        if (engines != null && names != null)
            foreach (var s in engines.ImageSessions(native).Where(s => s.State == "open" && s.Session != null))
            {
                try
                {
                    await names.EnsureAsync(native, s.Session!, ct).ConfigureAwait(false);
                    pushed.Add(s.Engine);
                }
                catch (ToolError e) { notes.Add($"{NativeEngineService.DisplayName(s.Engine)}: {e.Message}"); }
            }
        return new NativeUndoResult(entry, changes, pushed, notes);
    }

    private async Task<NativeUndoResult> UndoUserTypes(LoadedNative native, NativeJournalEntry entry, IReadOnlyList<NativeJournalEntry> entries, CancellationToken ct)
    {
        var delta = entry.UserTypes!;
        var ann = code.Annotations(native);
        delta.Revert(ann.UserTypes, out var conflicts);
        if (conflicts.Count > 0)
        {
            var by = entries.SkipWhile(e => e != entry).Skip(1).FirstOrDefault(e => e.UserTypes?.Items.Any(i => conflicts.Contains(i.Key)) == true);
            throw new ToolError(ErrorCode.Conflict, $"{conflicts.Count} item(s) of {entry.Id} changed since{(by != null ? $" (by {by.Id})" : "")}.",
                by != null ? $"undo_native_edit editId={by.Id} first" : "list_native_edits shows the later edits");
        }
        var notes = new List<string>();
        var pushed = new List<string>();
        var sessions = engines?.ImageSessions(native).Where(s => s.State == "open" && s.Session != null).Select(s => s.Session!).ToList() ?? [];
        if (sessions.Count == 0 && engines != null && entry.Engine != null && engines.UnavailabilityOf(entry.Engine) == null)
            sessions.Add(await engines.Session(native, entry.Engine, null, ct).ConfigureAwait(false));
        foreach (var session in sessions)
        {
            if (userTypes == null) break;
            var inverse = entry.Inverse ?? delta.Inverse(delta.Revert(ann.UserTypes, out _), out _);
            if (entry.Inverse == null && entry.EnginePrototypes is { Count: > 0 } own)
                inverse = inverse with { Types = [.. inverse.Types.Select(t => t.Declaration.Length == 0 && own.TryGetValue(t.Rva, out var p) ? t with { Declaration = p } : t)] };
            var result = await userTypes.ApplyAsync(native, session, inverse, (r, layer) => delta.Revert(layer, out var ignored), ct).ConfigureAwait(false);
            pushed.Add(session.ProviderId);
            foreach (var failed in result.Items.Where(i => !i.Applied).Take(5))
                notes.Add($"{NativeEngineService.DisplayName(session.ProviderId)} did not take back {failed.Kind} {failed.Target}: {failed.Error}");
        }
        if (pushed.Count == 0) ann.ChangeUserTypes(layer => delta.Revert(layer, out _));
        if (entry.Inverse == null)
        {
            delta.Inverse(UserTypeLayer.Empty, out var irreversible);
            notes.AddRange(irreversible.Select(i => $"the engine database keeps the {i}; reanalyze_native or a fresh database drops it"));
        }
        var changes = delta.Describe().Select(d => new EditChange(d.Kind, d.Target, d.After, d.Before)).ToList();
        return new NativeUndoResult(entry, changes, pushed, notes);
    }

    private static bool CommentChanged(NativeAnnotationChange c) => c.Before.Comment != c.After.Comment || c.Before.CommentKind != c.After.CommentKind;

    /// <summary>The parts <paramref name="c"/> changed hold its after values in <paramref name="now"/>.</summary>
    private static bool Holds(NativeAnnotationState now, NativeAnnotationChange c) =>
        (c.Before.Name == c.After.Name || now.Name == c.After.Name)
        && (!CommentChanged(c) || (now.Comment == c.After.Comment && now.CommentKind == c.After.CommentKind))
        && (c.Before.Pseudo == c.After.Pseudo || now.Pseudo == c.After.Pseudo);

    /// <summary>Two changes of one address touch a common part.</summary>
    private static bool Overlaps(NativeAnnotationChange a, NativeAnnotationChange b) =>
        (a.Before.Name != a.After.Name && b.Before.Name != b.After.Name) || (CommentChanged(a) && CommentChanged(b))
        || (a.Before.Pseudo != a.After.Pseudo && b.Before.Pseudo != b.After.Pseudo);

    private static string Hex(byte[] bytes) => bytes.Length <= 16 ? Convert.ToHexString(bytes) : Convert.ToHexString(bytes, 0, 16) + "...";

    // ---- sessions ----

    /// <summary>The image's name, comment and engine edits as JSON for save_session (patches travel in their own part).</summary>
    public JsonArray Export(LoadedNative native)
    {
        var list = new JsonArray();
        foreach (var e in Entries(native).Where(e => e.Kind != NativeJournalEntry.PatchKind))
            list.Add(JsonSerializer.SerializeToNode(new JournalRecord(e.Tool, e.Kind, e.Description, e.Engine,
                e.Annotations.Count == 0 ? null : [.. e.Annotations],
                e.UserTypes is { } d ? [.. d.Items.Select(i => new DeltaRecord(i.Key, Node(i.Before), Node(i.After)))] : null), Options));
        return list;
    }

    /// <summary>
    /// Records <paramref name="records"/> (from <see cref="Export"/>) as edits of this image without applying them: load_session
    /// restores the values themselves, so after it the restored edits are undoable here.
    /// </summary>
    public IReadOnlyList<EditId> Import(LoadedNative native, JsonArray records)
    {
        var ids = new List<EditId>();
        var known = Export(native).Select(n => n?.ToJsonString()).ToHashSet();
        foreach (var node in records)
        {
            var r = node?.Deserialize<JournalRecord>(Options);
            if (r == null || known.Contains(node!.ToJsonString())) continue; // already journaled: a session loaded twice
            if (r.Kind == NativeJournalEntry.AnnotationKind && r.Annotations is { Count: > 0 } a)
                ids.Add(Add(native, id => new NativeJournalEntry(id, r.Tool, r.Kind, r.Description) { Annotations = a }));
            else if (r.Kind == NativeJournalEntry.EngineKind && r.UserTypes is { Count: > 0 } u)
                ids.Add(Add(native, id => new NativeJournalEntry(id, r.Tool, r.Kind, r.Description)
                    { Engine = r.Engine, UserTypes = new UserTypeDelta([.. u.Select(i => new UserTypeDelta.Item(i.Key, Value(i.Key, i.Before), Value(i.Key, i.After)))]) }));
        }
        return ids;
    }

    private sealed record JournalRecord(string Tool, string Kind, string Description, string? Engine, List<NativeAnnotationChange>? Annotations, List<DeltaRecord>? UserTypes);

    private sealed record DeltaRecord(string Key, JsonNode? Before, JsonNode? After);

    private static readonly JsonSerializerOptions Options = new() { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull };

    private static JsonNode? Node(object? value) => value == null ? null : JsonSerializer.SerializeToNode(value, value.GetType(), Options);

    private static object? Value(string key, JsonNode? node) => node == null ? null : key[0] switch
    {
        'D' or 'T' => node.GetValue<string>(),
        'R' => node.Deserialize<NativeTypeEdit>(Options),
        'E' => node.Deserialize<NativeEnumMemberEdit>(Options),
        'F' => node.Deserialize<NativeFieldEdit>(Options),
        'A' => node.Deserialize<NativeAnalysisEdit>(Options),
        'L' => node.Deserialize<NativeLocalEdit>(Options),
        'S' => node.Deserialize<NativeStackVarEdit>(Options),
        'O' => node.Deserialize<NativeOperandEdit>(Options),
        _ => null,
    };
}
