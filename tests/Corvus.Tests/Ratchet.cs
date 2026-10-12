namespace Corvus.Tests;

/// <summary>
/// A guard that lands before every tool complies: today's violations are listed in Ratchets/&lt;name&gt;.txt and the list may
/// only shrink. A new violation fails; so does a listed entry that now complies, until it is removed.
/// CORVUS_UPDATE_RATCHETS=1 drops the entries that comply and writes a missing list from today's state; it never adds to one.
/// </summary>
internal static class Ratchet
{
    public const string UpdateVariable = "CORVUS_UPDATE_RATCHETS";

    private static string Folder => Path.Combine(DocsTests.RepoRoot(), "tests", "Corvus.Tests", "Ratchets");

    /// <summary>Checks <paramref name="violations"/> (key: what breaks the rule, value: how) against the list <paramref name="name"/>.</summary>
    public static void Check(string name, string rule, IReadOnlyDictionary<string, string> violations)
    {
        var file = Path.Combine(Folder, name + ".txt");
        HashSet<string>? exempt = File.Exists(file)
            ? File.ReadAllLines(file).Select(l => l.Split('#')[0].Trim()).Where(l => l.Length > 0).ToHashSet(StringComparer.Ordinal)
            : null;
        if (Environment.GetEnvironmentVariable(UpdateVariable) == "1")
        {
            exempt = (exempt == null ? violations.Keys : violations.Keys.Where(exempt.Contains)).ToHashSet(StringComparer.Ordinal);
            Directory.CreateDirectory(Folder);
            File.WriteAllText(file, $"# Exemptions from: {rule}\n# This list may only shrink (tests/Corvus.Tests/Ratchet.cs).\n"
                + string.Concat(exempt.Order(StringComparer.Ordinal).Select(k => k + "\n")));
        }
        exempt ??= [];
        var added = violations.Where(v => !exempt.Contains(v.Key)).OrderBy(v => v.Key, StringComparer.Ordinal).Select(v => $"{v.Key}: {v.Value}").ToList();
        var complies = exempt.Where(e => !violations.ContainsKey(e)).Order(StringComparer.Ordinal).ToList();
        Assert.True(added.Count == 0, $"{rule}; new violations (fix them, never add them to Ratchets/{name}.txt):\n{string.Join("\n", added)}");
        Assert.True(complies.Count == 0, $"{rule}; these comply now: remove them from Ratchets/{name}.txt ({UpdateVariable}=1 does it): {string.Join(", ", complies)}");
    }
}
