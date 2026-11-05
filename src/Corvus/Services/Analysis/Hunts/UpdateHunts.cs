using Corvus.Core;
using Corvus.Native;

namespace Corvus.Services.Analysis.Hunts;

/// <summary>Hunting queries and notes for what a new build adds to an old one.</summary>
public static class UpdateHunts
{
    /// <summary>Added imported functions named in one note; the rest are counted.</summary>
    public const int MaxNamedImports = 20;

    private static readonly HashSet<string> Kinds = new(StringComparer.Ordinal)
        { HuntKind.Domain, HuntKind.Url, HuntKind.Ipv4, HuntKind.Ipv6, HuntKind.NamedPipe, HuntKind.FilePath, HuntKind.DllName };

    /// <summary>
    /// Queries limited to <paramref name="newSha1"/> for the hosts, URLs, addresses, pipes, files and library names
    /// only <paramref name="newFacts"/> holds; no added fact gives no query and a note saying so.
    /// </summary>
    public static HuntSet Added(IEnumerable<HuntFact> oldFacts, IEnumerable<HuntFact> newFacts, string newSha1)
    {
        var before = oldFacts.Where(f => Kinds.Contains(f.Kind)).Select(f => (f.Kind, f.Value.Trim())).ToHashSet(Key);
        var added = newFacts.Where(f => Kinds.Contains(f.Kind) && !before.Contains((f.Kind, f.Value.Trim()))).ToList();
        if (added.Count == 0) return new HuntSet([], ["No host, URL, address, pipe, file or library name was added in the new build, so no query was written."]);
        return KqlHunts.Write(added, newSha1);
    }

    /// <summary>One note naming the functions the new build imports and the old one does not; empty when none.</summary>
    public static IReadOnlyList<string> AddedImports(IEnumerable<NativeImport> oldImports, IEnumerable<NativeImport> newImports)
    {
        static string Name(NativeImport i) => $"{i.Module}!{i.Name ?? "#" + i.Ordinal}".ToLowerInvariant();
        var before = oldImports.Select(Name).ToHashSet(StringComparer.Ordinal);
        var added = newImports.Select(Name).Where(n => !before.Contains(n)).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();
        if (added.Count == 0) return [];
        var named = string.Join(", ", added.Take(MaxNamedImports));
        return [$"{added.Count} imported function(s) were added and have no query, Defender XDR lists no column for them: {named}" +
                (added.Count > MaxNamedImports ? $" (+{added.Count - MaxNamedImports} more)" : "") + "."];
    }

    /// <summary>One note per added capability label with the functions that hold it; the label has no Defender XDR column, so no query.</summary>
    public static IReadOnlyList<string> AddedCapabilities(IEnumerable<EvidenceChange> changes) =>
        [.. changes.Where(c => c.Kind == "added").Select(c => $"Capability {c.Key} was added and has no query, Defender XDR lists no column for it" +
                                                               (string.IsNullOrEmpty(c.New) ? "." : $": {c.New}."))];

    private static readonly IEqualityComparer<(string Kind, string Value)> Key = new KeyComparer();

    private sealed class KeyComparer : IEqualityComparer<(string Kind, string Value)>
    {
        public bool Equals((string Kind, string Value) a, (string Kind, string Value) b) =>
            a.Kind == b.Kind && string.Equals(a.Value, b.Value, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode((string Kind, string Value) k) => HashCode.Combine(k.Kind, StringComparer.OrdinalIgnoreCase.GetHashCode(k.Value));
    }
}
