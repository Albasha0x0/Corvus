namespace Corvus.Core;

/// <summary>
/// Why a result may be incomplete or less certain: the closed vocabulary of provenance "limitations" (STANDARDS S5.4),
/// published as docs/limitations.md. Free text goes to the result's text, not here; a new entry needs an id and a meaning.
/// </summary>
public enum Limitation
{
    AnalysisPartial,
    EngineProfileStandard,
    IndexBuilding,
    RegexTimeouts,
    RowCap,
    TimeLimit,
    ObfuscatedNames,
    NoPdb,
    HeuristicBoundaries,
    IndirectCalls,
    UnresolvedReferences,
    ArchitectureUndecoded,
    EncryptedMetadata,
}

public static class Limitations
{
    /// <summary>The id sent in results ("analysis-partial").</summary>
    public static string Id(Limitation limitation) => limitation switch
    {
        Limitation.AnalysisPartial => "analysis-partial",
        Limitation.EngineProfileStandard => "engine-profile-standard",
        Limitation.IndexBuilding => "index-building",
        Limitation.RegexTimeouts => "regex-timeouts",
        Limitation.RowCap => "row-cap",
        Limitation.TimeLimit => "time-limit",
        Limitation.ObfuscatedNames => "obfuscated-names",
        Limitation.NoPdb => "no-pdb",
        Limitation.HeuristicBoundaries => "heuristic-boundaries",
        Limitation.IndirectCalls => "indirect-calls",
        Limitation.UnresolvedReferences => "unresolved-references",
        Limitation.ArchitectureUndecoded => "architecture-undecoded",
        Limitation.EncryptedMetadata => "encrypted-metadata",
        _ => throw new ArgumentOutOfRangeException(nameof(limitation)),
    };

    /// <summary>What the limitation means for the result, for client authors.</summary>
    public static string Meaning(Limitation limitation) => limitation switch
    {
        Limitation.AnalysisPartial => "The engine's analysis had not finished; functions, references or types it finds later are missing.",
        Limitation.EngineProfileStandard => "The engine database was built with the standard analysis profile; the full profile can find more.",
        Limitation.IndexBuilding => "The code index was still being built; references from code not yet indexed are missing.",
        Limitation.RegexTimeouts => "The pattern ran out of time on some inputs; those inputs were skipped.",
        Limitation.RowCap => "A scan or collection cap stopped before the end of the input; counts are lower bounds.",
        Limitation.TimeLimit => "The call's time limit stopped the work; the result holds what finished.",
        Limitation.ObfuscatedNames => "Names are transformed or compiler-generated; matches by name are unreliable.",
        Limitation.NoPdb => "No symbol file was loaded; names, types and boundaries are recovered, not read.",
        Limitation.HeuristicBoundaries => "Function starts and ends come from heuristics, not from symbols or unwind data.",
        Limitation.IndirectCalls => "Calls through pointers, virtual slots or reflection are not resolved to their targets.",
        Limitation.UnresolvedReferences => "Referenced assemblies or modules were not found; types and calls into them are unresolved.",
        Limitation.ArchitectureUndecoded => "The built-in engine does not decode this instruction set; code facts come from metadata and symbols only.",
        Limitation.EncryptedMetadata => "Metadata is encrypted or packed; only the part that could be read is reflected.",
        _ => throw new ArgumentOutOfRangeException(nameof(limitation)),
    };

    /// <summary>The limitation with id <paramref name="id"/>, or null.</summary>
    public static Limitation? Parse(string id) =>
        Enum.GetValues<Limitation>().Where(l => Id(l) == id).Select(l => (Limitation?)l).FirstOrDefault();

    /// <summary>docs/limitations.md: every limitation id and its meaning.</summary>
    public static string Markdown()
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("""
            # Result limitations

            <!-- Generated from Core/Limitations.cs by ErrorContractTests; run the tests with CORVUS_UPDATE_DOCS=1 to update. -->

            A result whose coverage is not complete names why in the `limitations` list of its provenance record
            (`_meta["corvus/provenance"]`). The list uses only these ids; details are in the result's text. A record that says it
            stopped early (`truncated`, `cut`, `incomplete`, or a `partial` reason) has coverage `partial` too.

            Function results also name their facets (`pseudocode`, `callers`, `callees`, `xrefs`, `strings`, `cfg`) as `available`
            or `unavailable: why`, in the provenance and in the record's `coverage.facets`. Comparisons of kept results
            (`oldResult` / `newResult`) report what a side does not show as `unknown`: a page of a longer result, a result that is
            not complete, or a facet either side lacks; never as equal, removed, added or changed.

            | Id | Meaning |
            |---|---|

            """);
        foreach (var limitation in Enum.GetValues<Limitation>())
            sb.Append($"| `{Id(limitation)}` | {Meaning(limitation)} |\n");
        return sb.ToString();
    }
}
