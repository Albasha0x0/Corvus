using L = Corvus.Mcp.LatencyClass;
using O = Corvus.Mcp.OutputClass;

namespace Corvus.Mcp;

// Contract rows of the notes family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs, ParameterDomains.cs and ToolContract.cs.

public static partial class ToolEffects
{
    private static Dictionary<string, Effects> NotesTools() => new(StringComparer.Ordinal)
    {
        // Notes (kept per user beside the annotation sidecars)
        ["record_note"] = Changes(destructive: false, idempotent: false),
        // Replaces text or status; a repeat with the same revision is a conflict.
        ["update_note"] = Changes(destructive: true, idempotent: true),
        ["list_notes"] = Reads(),
    };
}

public static partial class ParameterDomains
{
    private static Dictionary<string, IReadOnlyDictionary<string, Domain>> NotesTools() => new(StringComparer.Ordinal)
    {
        ["record_note"] = new Dictionary<string, Domain> { ["kind"] = NoteKind, ["status"] = NoteStatus },
        ["update_note"] = new Dictionary<string, Domain> { ["kind"] = NoteKind, ["status"] = NoteStatus },
        ["list_notes"] = new Dictionary<string, Domain> { ["kind"] = NoteKind, ["status"] = Of([.. NoteStatus.Values, "all"]) },
    };
}

public sealed partial record ToolContract
{
    private static Dictionary<string, ToolContract> NotesTools() => new(StringComparer.Ordinal)
    {
        ["record_note"] = Row(O.Edit, L.Instant, lean: true, noDryRun: "only adds a note; update_note status=dropped retires it"),
        ["update_note"] = Row(O.Edit, L.Instant, noDryRun: "guarded by the note's revision; the previous text stays in its history"),
        ["list_notes"] = Row(O.List, L.Instant, lean: true, sort: "updated descending, id"),
    };
}
