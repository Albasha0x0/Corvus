namespace Corvus.Services;

/// <summary>
/// Maps method RVAs from an old build to a new one by metadata identity, cross-checked with the native matcher; a key
/// with several RVAs on either side is ambiguous and not mapped.
/// </summary>
public static class AotBuildMap
{
    /// <summary>A method with code: its identity key and RVA.</summary>
    public readonly record struct Method(string Key, uint Rva);

    /// <summary>The native matcher's answer for an old RVA; NewRva null when unmatched.</summary>
    public readonly record struct NativeAnswer(uint? NewRva, int? Tier, string? Basis, double Confidence, string Reason);

    /// <summary>One old method's outcome; Status is agree, disagree, metadata_only, removed or ambiguous.</summary>
    public sealed record Entry(string Key, uint OldRva, uint? NewRva, uint? MatchedRva, string Status, int? Tier, string? Basis, double Confidence, string Detail);

    public sealed record Result(List<Entry> Entries, int OldMethods, int NewMethods, int Added)
    {
        public int Count(string status) => Entries.Count(e => e.Status == status);
    }

    public static Result Map(IReadOnlyList<Method> oldMethods, IReadOnlyList<Method> newMethods, Func<uint, NativeAnswer> native, CancellationToken ct)
    {
        var olds = Group(oldMethods);
        var news = Group(newMethods);
        var entries = new List<Entry>(olds.Count);
        var answers = new Dictionary<uint, NativeAnswer>();
        int n = 0;
        foreach (var (key, oldRvas) in olds.OrderBy(kv => kv.Value[0]).ThenBy(kv => kv.Key, StringComparer.Ordinal))
        {
            if ((++n & 0x3FF) == 0) ct.ThrowIfCancellationRequested();
            uint oldRva = oldRvas[0];
            if (oldRvas.Count > 1)
            {
                entries.Add(new(key, oldRva, null, null, "ambiguous", null, null, 0, $"{oldRvas.Count} methods of this identity in the old build ({Rvas(oldRvas)})"));
                continue;
            }
            if (!news.TryGetValue(key, out var newRvas))
            {
                entries.Add(new(key, oldRva, null, null, "removed", null, null, 0, "no method of this identity has code in the new build"));
                continue;
            }
            if (newRvas.Count > 1)
            {
                entries.Add(new(key, oldRva, null, null, "ambiguous", null, null, 0, $"{newRvas.Count} methods of this identity in the new build ({Rvas(newRvas)})"));
                continue;
            }
            uint newRva = newRvas[0];
            if (!answers.TryGetValue(oldRva, out var a)) answers[oldRva] = a = native(oldRva);
            if (a.NewRva is not { } matched)
                entries.Add(new(key, oldRva, newRva, null, "metadata_only", null, null, 1, $"the native matcher did not map it ({a.Reason})"));
            else if (matched == newRva)
                entries.Add(new(key, oldRva, newRva, matched, "agree", a.Tier, a.Basis, 1, $"matcher {a.Reason}, tier {a.Tier} {a.Basis}"));
            else
                entries.Add(new(key, oldRva, newRva, matched, "disagree", a.Tier, a.Basis, a.Confidence,
                    $"metadata says rva 0x{newRva:X}, the native matcher (tier {a.Tier} {a.Basis}) says 0x{matched:X}"));
        }
        int added = news.Keys.Count(k => !olds.ContainsKey(k));
        return new Result(entries, olds.Count, news.Count, added);
    }

    private static Dictionary<string, List<uint>> Group(IReadOnlyList<Method> methods)
    {
        var map = new Dictionary<string, List<uint>>(StringComparer.Ordinal);
        foreach (var m in methods)
        {
            if (!map.TryGetValue(m.Key, out var list)) map[m.Key] = list = [];
            if (!list.Contains(m.Rva)) list.Add(m.Rva);
        }
        return map;
    }

    private static string Rvas(List<uint> rvas) => string.Join(", ", rvas.Take(4).Select(r => $"0x{r:X}")) + (rvas.Count > 4 ? ", ..." : "");
}
