namespace NetDecompilerMcp.Core;

/// <summary>
/// An applied edit with the inputs needed to replay it. Used for undo (rebuild from the original image and replay),
/// edit scripts and diffs.
/// </summary>
/// <param name="Kind">Name of the edit tool that produced the record.</param>
/// <param name="Args">Tool arguments; symbols stored as stable labels (Ns.Type::Method(int)) plus the metadata token.</param>
/// <param name="Touched">Labels of members changed or added by the edit.</param>
public sealed record EditRecord(string Kind, IReadOnlyDictionary<string, string?> Args, string Description, IReadOnlyList<string> Touched)
{
    public string? Arg(string name) => Args.TryGetValue(name, out var v) ? v : null;

    /// <summary>Read from a script whose labels predate generic arity (Method<T>(...)); see <see cref="SymbolResolver.Resolve"/>.</summary>
    public bool LegacyLabels { get; init; }
}
