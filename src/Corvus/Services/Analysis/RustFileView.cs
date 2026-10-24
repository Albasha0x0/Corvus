using Corvus.Core;
using Corvus.Native;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=rust: the crate dependency list cargo-auditable embeds (.dep-v0): root crate, every crate with version, source and
/// kind, and the edges. Without it, the rustc commit and the crates named in the panic locations' source paths.
/// </summary>
internal sealed class RustFileView : IFileSummaryView
{
    private const int MaxListed = 200;
    private const int MaxCrates = 2000;

    /// <summary>A crate and the names of the crates it depends on.</summary>
    public sealed record Crate(string Name, string Version, string Source, string Kind, IReadOnlyList<string> Dependencies);

    /// <param name="Section">.dep-v0, or "source paths" when the crates come from the paths the panic locations name.</param>
    /// <param name="RustcCommit">The rustc commit of the standard library paths (/rustc/&lt;commit&gt;/library/...).</param>
    public sealed record Facts(string Section, string? Root, int Crates, int BuildCrates, int Edges, IReadOnlyList<Crate> Packages, IReadOnlyList<string> Notes,
        string? RustcCommit = null);

    public string Name => "rust";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (NativeImageLoader.Detect(file.Head) == NativeFileKind.Unknown) return null;
        var commit = StringForms.RustcCommit(file.Image);
        if (file.Image.AsSpan().IndexOf(".dep-v0"u8) < 0) return FromSourcePaths(file.Image, commit);
        RustAudit? audit;
        try { audit = RustAudit.Of(NativeImageLoader.FromBytes(file.Image, file.Path), file.Image); }
        catch (ToolError) { return null; }
        if (audit == null) return null;
        var p = audit.Packages;
        string Label(int i) => i < p.Count ? $"{p[i].Name} {p[i].Version}" : $"#{i}";
        var crates = p.Take(MaxListed).Select(c => new Crate(c.Name, c.Version, c.Source, c.Kind, [.. c.Dependencies.Select(Label)])).ToList();
        var root = p.FirstOrDefault(c => c.Root);
        var notes = new List<string>(audit.Issues);
        if (p.Count > MaxListed) notes.Add($"crates: the first {MaxListed} of {p.Count:N0}");
        var facts = new Facts(audit.Section, root != null ? $"{root.Name} {root.Version}" : null, p.Count, p.Count(c => c.Kind == "build"),
            p.Sum(c => c.Dependencies.Count), crates, notes, commit);

        var highlights = new List<string>();
        if (p.Count > 0)
            highlights.Add($"Rust (cargo-auditable): {(facts.Root != null ? facts.Root + " with " : "")}{p.Count:N0} crates: " +
                           string.Join(", ", p.Where(c => !c.Root).Take(8).Select(c => $"{c.Name} {c.Version}")) + (p.Count > 9 ? ", …" : "") + ".");
        if (audit.Issues.Count > 0) highlights.Add($"Dependency list ({audit.Section}) issue: {audit.Issues[0]}.");
        return new FileView(facts, highlights);
    }

    /// <summary>A release build without the list: the crates its panic locations name (registry paths), with the rustc commit.</summary>
    private static FileView? FromSourcePaths(byte[] image, string? commit)
    {
        var crates = RegistryCrates(image);
        if (commit == null && crates.Count == 0) return null;
        var listed = crates.Take(MaxListed).Select(c => new Crate(c.Name, c.Version, "crates.io", "runtime", [])).ToList();
        var notes = new List<string> { "crates from source paths: those with no panic location or assertion in the build are not named" };
        if (crates.Count > MaxListed) notes.Add($"crates: the first {MaxListed} of {crates.Count:N0}");
        var facts = new Facts("source paths", null, crates.Count, 0, 0, listed, notes, commit);
        var text = $"Rust program{(commit != null ? $" built with rustc commit {commit[..12]}" : "")}";
        if (crates.Count > 0)
            text += $", {crates.Count:N0} crates named in its source paths: " +
                    string.Join(", ", crates.Take(8).Select(c => $"{c.Name} {c.Version}")) + (crates.Count > 8 ? ", …" : "");
        return new FileView(facts, [text + "."]);
    }

    /// <summary>name-version folders under a cargo registry index folder (index.crates.io-&lt;hash&gt;, github.com-&lt;hash&gt;), sorted by name.</summary>
    internal static List<(string Name, string Version)> RegistryCrates(byte[] image)
    {
        var found = new SortedSet<(string, string)>();
        var span = image.AsSpan();
        foreach (var marker in new[] { "index.crates.io-"u8.ToArray(), "github.com-"u8.ToArray() })
            for (int at = 0, i; (i = span[at..].IndexOf(marker)) >= 0 && found.Count < MaxCrates; at += i + marker.Length)
            {
                int p = at + i + marker.Length, hex = 0;
                while (p < span.Length && hex < 16 && IsHex(span.Slice(p, 1))) { p++; hex++; }
                if (hex != 16 || p >= span.Length || span[p] is not ((byte)'/' or (byte)'\\')) continue;
                int end = ++p;
                while (end < span.Length && end - p < 128 && span[end] is not ((byte)'/' or (byte)'\\' or 0)) end++;
                if (end >= span.Length || span[end] == 0 || SplitCrate(System.Text.Encoding.ASCII.GetString(span[p..end])) is not { } crate) continue;
                found.Add(crate);
            }
        return [.. found];
    }

    /// <summary>("regex-automata", "0.4.14") for "regex-automata-0.4.14": the version starts at the first "-N.N.N".</summary>
    internal static (string, string)? SplitCrate(string folder)
    {
        for (int i = folder.IndexOf('-'); i > 0; i = folder.IndexOf('-', i + 1))
        {
            var name = folder[..i];
            var version = folder[(i + 1)..];
            var parts = version.Split('.', 3);
            if (parts.Length == 3 && parts[0].Length > 0 && parts[0].All(char.IsAsciiDigit) && parts[1].Length > 0 && parts[1].All(char.IsAsciiDigit)
                && parts[2].Length > 0 && char.IsAsciiDigit(parts[2][0]) && version.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '+')
                && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
                return (name, version);
        }
        return null;
    }

    private static bool IsHex(ReadOnlySpan<byte> b)
    {
        foreach (var c in b)
            if (!char.IsAsciiHexDigitLower((char)c) && !char.IsAsciiDigit((char)c)) return false;
        return true;
    }
}
