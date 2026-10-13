namespace Corvus.Tests;

/// <summary>
/// A guard that lands before every tool complies: today's violations are listed in Ratchets/&lt;name&gt;.txt and the list may
/// only shrink. A new violation fails; so does a listed entry that now complies, until it is removed.
/// An entry ending in "# permanent: &lt;reason&gt;" is a reviewed exemption that stays (gate G2: only those remain).
/// CORVUS_UPDATE_RATCHETS=1 drops the entries that comply and writes a missing list from today's state; it never adds to one.
/// </summary>
internal static class Ratchet
{
    public const string UpdateVariable = "CORVUS_UPDATE_RATCHETS";

    private const string PermanentMark = "permanent:";

    private static string Folder => Path.Combine(DocsTests.RepoRoot(), "tests", "Corvus.Tests", "Ratchets");

    /// <summary>The entries of list <paramref name="name"/> with their permanent-exemption reason (null: still to fix); null when there is no list.</summary>
    public static Dictionary<string, string?>? Entries(string name)
    {
        var file = Path.Combine(Folder, name + ".txt");
        if (!File.Exists(file)) return null;
        var entries = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var line in File.ReadAllLines(file))
        {
            var hash = line.IndexOf('#');
            var key = (hash < 0 ? line : line[..hash]).Trim();
            if (key.Length == 0) continue;
            var comment = hash < 0 ? "" : line[(hash + 1)..].Trim();
            string? reason = comment.StartsWith(PermanentMark, StringComparison.Ordinal) ? comment[PermanentMark.Length..].Trim() : null;
            Assert.True(reason is null or { Length: > 0 }, $"Ratchets/{name}.txt: '{key}' is marked permanent without a reason");
            entries[key] = reason;
        }
        return entries;
    }

    /// <summary>Checks <paramref name="violations"/> (key: what breaks the rule, value: how) against the list <paramref name="name"/>.</summary>
    public static void Check(string name, string rule, IReadOnlyDictionary<string, string> violations)
    {
        var entries = Entries(name);
        if (Environment.GetEnvironmentVariable(UpdateVariable) == "1")
        {
            entries = entries == null
                ? violations.Keys.ToDictionary(k => k, string? (_) => null, StringComparer.Ordinal)
                : entries.Where(e => violations.ContainsKey(e.Key)).ToDictionary(StringComparer.Ordinal);
            Directory.CreateDirectory(Folder);
            File.WriteAllText(Path.Combine(Folder, name + ".txt"), $"# Exemptions from: {rule}\n# This list may only shrink (tests/Corvus.Tests/Ratchet.cs).\n"
                + string.Concat(entries.OrderBy(e => e.Key, StringComparer.Ordinal).Select(e => e.Key + (e.Value is { } r ? $" # {PermanentMark} {r}" : "") + "\n")));
        }
        var exempt = entries?.Keys.ToHashSet(StringComparer.Ordinal) ?? [];
        var added = violations.Where(v => !exempt.Contains(v.Key)).OrderBy(v => v.Key, StringComparer.Ordinal).Select(v => $"{v.Key}: {v.Value}").ToList();
        var complies = exempt.Where(e => !violations.ContainsKey(e)).Order(StringComparer.Ordinal).ToList();
        Assert.True(added.Count == 0, $"{rule}; new violations (fix them, never add them to Ratchets/{name}.txt):\n{string.Join("\n", added)}");
        Assert.True(complies.Count == 0, $"{rule}; these comply now: remove them from Ratchets/{name}.txt ({UpdateVariable}=1 does it): {string.Join(", ", complies)}");
    }
}
