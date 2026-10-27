namespace Corvus.Core;

/// <summary>An applied edit with the inputs to replay it, for undo, edit scripts and diffs.</summary>
/// <param name="Kind">Name of the edit tool that produced the record.</param>
/// <param name="Args">Tool arguments; symbols stored as stable labels (Ns.Type::Method(int)) plus the metadata token.</param>
/// <param name="Touched">Labels of members changed or added by the edit.</param>
public sealed record EditRecord(string Kind, IReadOnlyDictionary<string, string?> Args, string Description, IReadOnlyList<string> Touched)
{
    public string? Arg(string name) => Args.TryGetValue(name, out var v) ? v : null;

    /// <summary>Read from a script whose labels predate generic arity (Method<T>(...)); see <see cref="SymbolResolver.Resolve"/>.</summary>
    public bool LegacyLabels { get; init; }

    /// <summary>The edit's number in its assembly (its <see cref="EditId"/>): given once, kept when other edits are undone; 0 until recorded.</summary>
    public int Number { get; init; }

    /// <summary>The content digest (<see cref="EditDigest"/>); a dry run reports the same for the record it would make.</summary>
    public string ContentDigest() => EditDigest.Of(Kind, Args);
}

/// <summary>The record a dry run would have made, scoped to the call, since dry runs hold only the read lock and run side by side.</summary>
public static class EditPreview
{
    private sealed class Slot { public EditRecord? Record; }

    private static readonly AsyncLocal<Slot?> Current = new();

    /// <summary>Runs <paramref name="edit"/> and returns its result with the record a dry run in it offered, if any.</summary>
    public static (T Result, EditRecord? Previewed) Capture<T>(Func<T> edit)
    {
        var slot = new Slot();
        var outer = Current.Value;
        Current.Value = slot;
        try { return (edit(), slot.Record); }
        finally { Current.Value = outer; }
    }

    /// <summary>Called by an edit in a dry run with the record it would make.</summary>
    public static void Offer(EditRecord record)
    {
        if (Current.Value is { } slot) slot.Record = record;
    }
}
