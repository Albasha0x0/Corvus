using System.ComponentModel;

namespace Corvus.Core;

// Kept results and bundle entries read as comparison inputs (evidence as input).

/// <summary>Where a comparison input came from: the reference as given, its kind, and the call that produced it.</summary>
public sealed record EvidenceSource(
    string Ref,
    [property: Description("kept, recent (this session's call) or bundle.")] string Kind,
    string Tool, string? Arguments, IReadOnlyList<KeptInput> Inputs, DateTimeOffset? Created);

public sealed record EvidenceChange(
    [property: Description("changed, removed, added, or unknown (absent from a partial side); engine memory: what wrote the range.")] string Kind,
    string Key, string? Old, string? New,
    [property: Description("changed: the fields that differ; engine memory: the range's detail.")] IReadOnlyList<string>? Fields);

/// <summary>A comparison of two results: where each came from, how they were compared and the counts; the rows are the record's changes.</summary>
public sealed record EvidenceSummary(
    EvidenceSource Old, EvidenceSource New,
    [property: Description("items (by the key field By) or text (by line).")] string Basis,
    string? By,
    [property: Description("complete, or partial: a side holds one page, so absent items are unknown.")] string Completeness,
    int Same, int Changed, int Removed, int Added, int Unknown);
