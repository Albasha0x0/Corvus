using System.Runtime.CompilerServices;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Native.Diff;

/// <summary>Where an address of the old build is in the new build, how sure that is, and why.</summary>
public sealed record MappedAddress(uint OldRva, uint? NewRva, double Confidence, string Reason, string Detail, FunctionMatch? Pair, IReadOnlyList<uint> Candidates);

/// <summary>
/// Maps addresses of an old build to the new build through a <see cref="MatchResult"/>: function starts to the matched
/// function; addresses inside a function to the corresponding instruction after aligning the two instruction sequences
/// by shape (common prefix and suffix, then LCS, or unique-token anchors for long sequences); data addresses by the
/// same string literal, or by following the old build's references through matched instructions and reading what the
/// new instructions reference. One instance caches decoded functions and alignments; not thread-safe.
/// </summary>
public sealed class AddressMapper(MatchResult match)
{
    private const int MaxReferences = 64;

    private readonly MaskedDecoder _oldDecoder = new(match.Old.Index.Image);
    private readonly MaskedDecoder _newDecoder = new(match.New.Index.Image);
    private readonly Dictionary<int, (List<MaskedInsn> Old, List<MaskedInsn> New, int[] Map)> _alignments = [];
    private Dictionary<string, List<uint>>? _newStrings;

    public MatchResult Match => match;

    public MappedAddress Map(uint oldRva, CancellationToken ct)
    {
        var oldIndex = match.Old.Index;
        var fn = oldIndex.FunctionAt(oldRva);
        if (fn != null && match.Old.ByStart.TryGetValue(fn.Start, out var oi))
        {
            var pair = match.ByOld[oi];
            if (pair == null)
            {
                var amb = match.Ambiguous.GetValueOrDefault((true, oi));
                return new(oldRva, null, 0, amb != null ? "ambiguous" : "function_not_matched",
                    amb != null ? $"{fn.Name} has {amb.Candidates.Count} equally good counterparts ({amb.Reason})" : $"{fn.Name} has no counterpart in the new build",
                    null, amb?.Candidates.Select(c => match.New.Functions[c.Index].Start).ToList() ?? []);
            }
            return InFunction(oldRva, oi, pair, ct);
        }
        return Data(oldRva, ct);
    }

    private MappedAddress InFunction(uint oldRva, int oi, FunctionMatch pair, CancellationToken ct)
    {
        var oldFn = match.Old.Functions[oi].Function;
        var newFn = match.New.Functions[pair.New].Function;
        if (oldRva == oldFn.Start)
            return new(oldRva, newFn.Start, pair.Confidence, "function_start", $"{oldFn.Name} -> {newFn.Name} ({MatchResult.TierNames[pair.Tier]})", pair, []);

        var (olds, news, map) = Alignment(oi, pair, ct);
        int k = FunctionCode.IndexOf(olds, oldRva);
        if (k < 0) return new(oldRva, null, 0, "not_an_instruction", $"{oldFn.Name} has no decoded instruction at this address", pair, []);
        uint into = oldRva - olds[k].Rva;
        if (map[k] >= 0)
        {
            var n = news[map[k]];
            bool same = olds[k].Bytes.AsSpan().SequenceEqual(n.Bytes) || SameMasked(olds[k], n);
            return new(oldRva, n.Rva + Math.Min(into, (uint)n.Length - 1), Math.Round(pair.Confidence * (same ? 1 : 0.9), 3), "aligned_instruction",
                $"instruction {k} of {oldFn.Name} -> instruction {map[k]} of {newFn.Name}{(same ? "" : " (operands differ)")}", pair, []);
        }
        // between the nearest aligned neighbors
        int p = k - 1;
        while (p >= 0 && map[p] < 0) p--;
        int q = k + 1;
        while (q < olds.Count && map[q] < 0) q++;
        int newFrom = p >= 0 ? map[p] + 1 : 0;
        int newTo = q < olds.Count ? map[q] : news.Count;
        int oldGap = q - p - 1, newGap = newTo - newFrom;
        if (oldGap == newGap && newGap > 0)
        {
            var n = news[newFrom + (k - p - 1)];
            return new(oldRva, n.Rva + Math.Min(into, (uint)n.Length - 1), Math.Round(pair.Confidence * 0.6, 3), "replaced_instruction",
                $"instruction {k} of {oldFn.Name} changed; {oldGap} instruction(s) replaced one for one", pair, []);
        }
        var near = new List<uint>();
        if (p >= 0) near.Add(news[map[p]].Rva);
        if (q < olds.Count) near.Add(news[map[q]].Rva);
        return newGap == 0
            ? new(oldRva, null, 0, "instruction_removed", $"instruction {k} of {oldFn.Name} has no counterpart in {newFn.Name}; the nearest aligned instructions are listed", pair, near)
            : new(oldRva, null, 0, "changed_region", $"instruction {k} of {oldFn.Name} is in a changed region ({oldGap} old vs {newGap} new instructions)", pair, near);
    }

    private static bool SameMasked(MaskedInsn a, MaskedInsn b)
    {
        if (a.Length != b.Length || a.Wild != b.Wild) return false;
        for (int i = 0; i < a.Length; i++) if (!a.IsWild(i) && a.Bytes[i] != b.Bytes[i]) return false;
        return true;
    }

    private (List<MaskedInsn> Old, List<MaskedInsn> New, int[] Map) Alignment(int oi, FunctionMatch pair, CancellationToken ct)
    {
        if (_alignments.TryGetValue(oi, out var cached)) return cached;
        var olds = FunctionCode.Instructions(match.Old.Index, _oldDecoder, match.Old.Functions[oi].Function, ct, out _);
        var news = FunctionCode.Instructions(match.New.Index, _newDecoder, match.New.Functions[pair.New].Function, ct, out _);
        var map = InstructionAlignment.Align(olds.Select(i => i.Token).ToArray(), news.Select(i => i.Token).ToArray(), ct);
        if (_alignments.Count > 4096) _alignments.Clear();
        return _alignments[oi] = (olds, news, map);
    }

    // ---- data ----

    private MappedAddress Data(uint oldRva, CancellationToken ct)
    {
        var oldIndex = match.Old.Index;
        var newIndex = match.New.Index;
        if (oldIndex.StringAt(oldRva) is { } s)
        {
            var text = oldIndex.ReadString(s, 4096);
            _newStrings ??= Strings(newIndex);
            if (_newStrings.TryGetValue(Key(s.Encoding, text), out var at))
                return at.Count == 1
                    ? new(oldRva, at[0], 0.95, "same_string", $"the string literal \"{Clip(text)}\"", null, [])
                    : new(oldRva, null, 0, "ambiguous", $"the string literal \"{Clip(text)}\" is at {at.Count} addresses in the new build", null, at.Take(8).ToList());
        }

        var votes = new Dictionary<uint, int>();
        int followed = 0;
        foreach (var x in oldIndex.RefsTo(oldRva, MaxReferences))
        {
            ct.ThrowIfCancellationRequested();
            if (x.Kind is XrefKind.Pointer) continue;
            if (oldIndex.FunctionAt(x.From) is not { } fn || !match.Old.ByStart.TryGetValue(fn.Start, out var oi) || match.ByOld[oi] is not { } pair) continue;
            var (olds, news, map) = Alignment(oi, pair, ct);
            int k = FunctionCode.IndexOf(olds, x.From);
            if (k < 0 || map[k] < 0) continue;
            followed++;
            var o = olds[k];
            var n = news[map[k]];
            if (o.Target is not { } ot || n.Target is not { } nt) continue;
            // the reference may name the address directly, or at an offset into it (folded into the displacement)
            uint target = nt + (oldRva - ot);
            votes[target] = votes.GetValueOrDefault(target) + 1;
        }
        if (votes.Count == 1)
        {
            var (rva, count) = votes.First();
            return new(oldRva, rva, count >= 2 ? 0.9 : 0.75, "followed_references",
                $"{count} reference(s) from matched instructions agree", null, []);
        }
        if (votes.Count > 1)
        {
            var ranked = votes.OrderByDescending(v => v.Value).ToList();
            return new(oldRva, null, 0, "conflicting_references",
                $"{followed} followed reference(s) point at {votes.Count} different addresses", null, ranked.Take(8).Select(v => v.Key).ToList());
        }
        return new(oldRva, null, 0, "no_reference_to_follow",
            "not in a function, not a string literal, and no reference from a matched instruction names it", null, []);
    }

    private static string Key(StringEncoding e, string text) => (e == StringEncoding.Utf16 ? "W:" : "A:") + text;

    private static Dictionary<string, List<uint>> Strings(NativeCodeIndex index)
    {
        var result = new Dictionary<string, List<uint>>(StringComparer.Ordinal);
        foreach (var s in index.Strings)
        {
            var key = Key(s.Encoding, index.ReadString(s, 4096));
            if (!result.TryGetValue(key, out var list)) result[key] = list = [];
            list.Add(s.Rva);
        }
        return result;
    }

    private static string Clip(string s) => s.Length <= 60 ? s : s[..57] + "...";
}

/// <summary>Aligns two token sequences: common prefix and suffix, then LCS, or unique-token anchors when too long.</summary>
public static class InstructionAlignment
{
    private const long MaxDpCells = 2_000_000;

    /// <summary>For each element of <paramref name="a"/>, the aligned index in <paramref name="b"/>, or -1.</summary>
    public static int[] Align(int[] a, int[] b, CancellationToken ct = default)
    {
        var map = new int[a.Length];
        Array.Fill(map, -1);
        Range(a, b, 0, a.Length, 0, b.Length, map, 0, ct);
        return map;
    }

    private static void Range(int[] a, int[] b, int a0, int a1, int b0, int b1, int[] map, int depth, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        while (a0 < a1 && b0 < b1 && a[a0] == b[b0]) map[a0++] = b0++;
        while (a0 < a1 && b0 < b1 && a[a1 - 1] == b[b1 - 1]) map[--a1] = --b1;
        int n = a1 - a0, m = b1 - b0;
        if (n == 0 || m == 0) return;
        if ((long)n * m <= MaxDpCells) { Lcs(a, b, a0, a1, b0, b1, map); return; }
        if (depth > 32) return;

        // anchors: tokens occurring exactly once on each side, kept in increasing order (longest increasing subsequence)
        var countA = new Dictionary<int, int>();
        var posA = new Dictionary<int, int>();
        for (int i = a0; i < a1; i++) { countA[a[i]] = countA.GetValueOrDefault(a[i]) + 1; posA[a[i]] = i; }
        var countB = new Dictionary<int, int>();
        var posB = new Dictionary<int, int>();
        for (int j = b0; j < b1; j++) { countB[b[j]] = countB.GetValueOrDefault(b[j]) + 1; posB[b[j]] = j; }
        var anchors = new List<(int I, int J)>();
        for (int i = a0; i < a1; i++)
            if (countA[a[i]] == 1 && countB.GetValueOrDefault(a[i]) == 1) anchors.Add((i, posB[a[i]]));
        var chain = IncreasingChain(anchors);
        if (chain.Count == 0) return;
        int pa = a0, pb = b0;
        foreach (var (i, j) in chain)
        {
            Range(a, b, pa, i, pb, j, map, depth + 1, ct);
            map[i] = j;
            pa = i + 1; pb = j + 1;
        }
        Range(a, b, pa, a1, pb, b1, map, depth + 1, ct);
    }

    private static void Lcs(int[] a, int[] b, int a0, int a1, int b0, int b1, int[] map)
    {
        int n = a1 - a0, m = b1 - b0;
        var t = new int[(n + 1) * (m + 1)];
        for (int i = n - 1; i >= 0; i--)
            for (int j = m - 1; j >= 0; j--)
                t[i * (m + 1) + j] = a[a0 + i] == b[b0 + j] ? t[(i + 1) * (m + 1) + j + 1] + 1 : Math.Max(t[(i + 1) * (m + 1) + j], t[i * (m + 1) + j + 1]);
        int x = 0, y = 0;
        while (x < n && y < m)
        {
            if (a[a0 + x] == b[b0 + y]) { map[a0 + x] = b0 + y; x++; y++; }
            else if (t[(x + 1) * (m + 1) + y] >= t[x * (m + 1) + y + 1]) x++;
            else y++;
        }
    }

    /// <summary>The longest subsequence of <paramref name="items"/> (ordered by I) whose J also increases.</summary>
    public static List<(int I, int J)> IncreasingChain(List<(int I, int J)> items)
    {
        if (items.Count == 0) return [];
        var tails = new List<int>();
        var prev = new int[items.Count];
        for (int k = 0; k < items.Count; k++)
        {
            int lo = 0, hi = tails.Count;
            while (lo < hi) { int mid = (lo + hi) >>> 1; if (items[tails[mid]].J < items[k].J) lo = mid + 1; else hi = mid; }
            prev[k] = lo > 0 ? tails[lo - 1] : -1;
            if (lo == tails.Count) tails.Add(k); else tails[lo] = k;
        }
        var result = new List<(int, int)>(tails.Count);
        for (int k = tails[^1]; k >= 0; k = prev[k]) result.Add(items[k]);
        result.Reverse();
        return result;
    }
}

/// <summary>Match results per pair of indexes and options, kept while both indexes are alive.</summary>
public static class MatchCache
{
    private static readonly ConditionalWeakTable<NativeCodeIndex, ConditionalWeakTable<NativeCodeIndex, Dictionary<string, MatchResult>>> Table = new();

    public static MatchResult Get(NativeCodeIndex oldIndex, NativeCodeIndex newIndex, MatchOptions options, CancellationToken ct)
    {
        var inner = Table.GetValue(oldIndex, _ => new());
        var byKey = inner.GetValue(newIndex, _ => new());
        // names count for tier 1, so a change of either side's names makes a new result
        string key = $"{options.Key}|{oldIndex.Sourced.Version}|{newIndex.Sourced.Version}";
        lock (byKey)
            if (byKey.TryGetValue(key, out var hit)) return hit;
        var result = BuildMatcher.Match(ImagePrints.Of(oldIndex, ct), ImagePrints.Of(newIndex, ct), options, ct);
        lock (byKey)
        {
            if (byKey.Count > 8) byKey.Clear();
            byKey[key] = result;
        }
        return result;
    }
}
