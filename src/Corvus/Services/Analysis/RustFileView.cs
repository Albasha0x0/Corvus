using Corvus.Core;
using Corvus.Native;

namespace Corvus.Services.Analysis;

/// <summary>view=rust: the crate dependency list cargo-auditable embeds (.dep-v0): root crate, every crate with version, source and kind, and the edges.</summary>
internal sealed class RustFileView : IFileSummaryView
{
    private const int MaxListed = 200;

    /// <summary>A crate and the names of the crates it depends on.</summary>
    public sealed record Crate(string Name, string Version, string Source, string Kind, IReadOnlyList<string> Dependencies);

    public sealed record Facts(string Section, string? Root, int Crates, int BuildCrates, int Edges, IReadOnlyList<Crate> Packages, IReadOnlyList<string> Notes);

    public string Name => "rust";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (NativeImageLoader.Detect(file.Bytes) == NativeFileKind.Unknown || file.Bytes.AsSpan().IndexOf(".dep-v0"u8) < 0) return null;
        RustAudit? audit;
        try { audit = RustAudit.Of(NativeImageLoader.FromBytes(file.Bytes, file.Path), file.Bytes); }
        catch (ToolError) { return null; }
        if (audit == null) return null;
        var p = audit.Packages;
        string Label(int i) => i < p.Count ? $"{p[i].Name} {p[i].Version}" : $"#{i}";
        var crates = p.Take(MaxListed).Select(c => new Crate(c.Name, c.Version, c.Source, c.Kind, [.. c.Dependencies.Select(Label)])).ToList();
        var root = p.FirstOrDefault(c => c.Root);
        var notes = new List<string>(audit.Issues);
        if (p.Count > MaxListed) notes.Add($"crates: the first {MaxListed} of {p.Count:N0}");
        var facts = new Facts(audit.Section, root != null ? $"{root.Name} {root.Version}" : null, p.Count, p.Count(c => c.Kind == "build"),
            p.Sum(c => c.Dependencies.Count), crates, notes);

        var highlights = new List<string>();
        if (p.Count > 0)
            highlights.Add($"Rust (cargo-auditable): {(facts.Root != null ? facts.Root + " with " : "")}{p.Count:N0} crates: " +
                           string.Join(", ", p.Where(c => !c.Root).Take(8).Select(c => $"{c.Name} {c.Version}")) + (p.Count > 9 ? ", …" : "") + ".");
        if (audit.Issues.Count > 0) highlights.Add($"Dependency list ({audit.Section}) issue: {audit.Issues[0]}.");
        return new FileView(facts, highlights);
    }
}
