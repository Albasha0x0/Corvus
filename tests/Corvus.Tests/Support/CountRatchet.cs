using System.Globalization;

namespace Corvus.Tests;

/// <summary>
/// A measured ratchet: Ratchets/&lt;name&gt;.txt holds one "key = value" line per measured item, and values move one way only.
/// A ceiling (duplicate lines, surviving mutants) fails when a value rises or a new key appears, and when a value fell
/// until the file records it; a floor (coverage) fails when a value drops below it. CORVUS_UPDATE_RATCHETS=1 writes the
/// tighter values (lower ceilings, dropped zero keys, higher or new floors) and never loosens one.
/// </summary>
internal static class CountRatchet
{
    /// <summary>The measured lists; their lines are values, not exemptions (RatchetTests skips them).</summary>
    public static readonly string[] Names = ["coverage", "duplicate-lines", "mutation-survivors"];

    private static string PathOf(string name) => Path.Combine(DocsTests.RepoRoot(), "tests", "Corvus.Tests", "Ratchets", name + ".txt");

    public static Dictionary<string, double> Read(string name)
    {
        var values = new Dictionary<string, double>(StringComparer.Ordinal);
        if (!File.Exists(PathOf(name))) return values;
        foreach (var raw in File.ReadAllLines(PathOf(name)))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#') continue;
            var eq = line.LastIndexOf(" = ", StringComparison.Ordinal);
            Assert.True(eq > 0, $"Ratchets/{name}.txt: '{line}' is not 'key = value'");
            values[line[..eq].Trim()] = double.Parse(line[(eq + 3)..], CultureInfo.InvariantCulture);
        }
        return values;
    }

    /// <summary>
    /// Checks <paramref name="measured"/> against the list; <paramref name="floor"/>: values may only rise, else only fall.
    /// <paramref name="partial"/>: only some keys were measured, so a recorded key without a measurement is left alone.
    /// </summary>
    public static void Check(string name, string rule, IReadOnlyDictionary<string, double> measured, bool floor, bool partial = false)
    {
        Assert.Contains(name, Names);
        var recorded = Read(name);
        if (Environment.GetEnvironmentVariable(Ratchet.UpdateVariable) == "1")
        {
            var next = new SortedDictionary<string, double>(StringComparer.Ordinal);
            foreach (var (key, value) in measured)
            {
                var had = recorded.TryGetValue(key, out var old);
                if (floor) next[key] = had ? Math.Max(old, value) : value;
                else if (had && value < old && value > 0) next[key] = value;
                else if (had && value >= old) next[key] = old;
                else if (!had && (recorded.Count == 0 || partial) && value > 0) next[key] = value; // first recording, or a new target of a partial list
            }
            if (floor || partial) foreach (var (key, value) in recorded) if (!measured.ContainsKey(key)) next.TryAdd(key, value);
            var header = string.Concat(File.Exists(PathOf(name)) ? File.ReadLines(PathOf(name)).TakeWhile(l => l.StartsWith('#')).Select(l => l + "\n")
                : [$"# {rule}\n", $"# Measured ratchet: values may only {(floor ? "rise" : "fall")} (tests/Corvus.Tests/Support/CountRatchet.cs).\n"]);
            File.WriteAllText(PathOf(name), header + string.Concat(next.Select(e => $"{e.Key} = {e.Value.ToString(CultureInfo.InvariantCulture)}\n")));
            recorded = Read(name);
        }
        Assert.True(recorded.Count > 0, $"Ratchets/{name}.txt is missing: record it once with {Ratchet.UpdateVariable}=1");
        var worse = new List<string>();
        var better = new List<string>();
        foreach (var (key, value) in measured.OrderBy(e => e.Key, StringComparer.Ordinal))
        {
            var had = recorded.TryGetValue(key, out var limit);
            if (floor)
            {
                if (had && value < limit) worse.Add($"{key}: {value} < floor {limit}");
                else if (!had || value > limit) better.Add($"{key}: {value}{(had ? $" > floor {limit}" : " (no floor yet)")}");
            }
            else if (!had && value > 0) worse.Add($"{key}: {value} (new)");
            else if (had && value > limit) worse.Add($"{key}: {value} > {limit}");
            else if (had && value < limit) better.Add($"{key}: {value} < {limit}");
        }
        if (!floor && !partial) better.AddRange(recorded.Keys.Where(k => !measured.ContainsKey(k)).Select(k => $"{k}: 0 (gone)"));
        Assert.True(worse.Count == 0, $"{rule}; worse than Ratchets/{name}.txt (fix it, never loosen the file):\n{string.Join("\n", worse)}");
        // A ceiling that fell is recorded at once, so it cannot creep back; a floor that rose may be raised when convenient.
        if (!floor) Assert.True(better.Count == 0, $"{rule}; better than Ratchets/{name}.txt: record it ({Ratchet.UpdateVariable}=1):\n{string.Join("\n", better)}");
    }
}
