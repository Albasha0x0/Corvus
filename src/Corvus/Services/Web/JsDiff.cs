using System.IO.Hashing;
using System.Text;
using System.Text.RegularExpressions;
using Acornima.Ast;
using Corvus.Core;

namespace Corvus.Services.Web;

/// <summary>
/// One module of a bundle diff: Change is identical, changed, added or removed; Tier says how the pair was made (path:
/// the bundler key or source-map path, shape: the normalized syntax hash, strings: the string literals).
/// </summary>
public sealed record JsModuleChange(string Change, string? OldId, string? NewId, string? Name, string? Tier, int OldBytes, int NewBytes, string? Detail);

/// <summary>analyze_js view=diff: counts and the module rows (identical ones only when asked for by query).</summary>
public sealed record JsDiffResult(int OldModules, int NewModules, int Identical, int Changed, int Added, int Removed,
    [property: System.ComponentModel.Description("Pairs whose module id differs (webpack renumbering).")] int Renumbered,
    IReadOnlyList<JsModuleChange> Rows, string? TokenDiff);

/// <summary>
/// Two builds of a bundle compared module by module: pairs by original path (bundler key or source map), then by a
/// normalized syntax hash (identifiers by first use, module ids at require calls folded, property names and literals
/// kept), then by the string literals they share; webpack id renumbering pairs as identical.
/// </summary>
internal static partial class JsDiff
{
    private const int MaxTokenDiffBytes = 256 * 1024;

    private sealed class Facts(JsModule module)
    {
        public JsModule Module = module;
        public string? Path;
        public ulong Hash, Skeleton;
        public HashSet<string> Strings = new(StringComparer.Ordinal);
    }

    public static JsDiffResult Compare(string oldPath, string newPath, string? query, CancellationToken ct)
    {
        // the two sides parse and hash at once
        var oldTask = Task.Run(() => Read(oldPath, ct), ct);
        var (newText, newFacts) = Read(newPath, ct);
        var (oldText, oldFacts) = oldTask.GetAwaiter().GetResult();
        var pairs = new List<(Facts Old, Facts New, string Tier)>();
        var oldLeft = oldFacts.ToHashSet();
        var newLeft = newFacts.ToHashSet();

        // a key shared by one module on each side pairs them; k modules on each side (copies of one code) pair in file order
        void Unique(Func<Facts, string?> key, string tier)
        {
            var olds = oldLeft.Where(f => key(f) != null).GroupBy(f => key(f)!).ToDictionary(g => g.Key, g => g.OrderBy(f => f.Module.Start).ToList());
            var news = newLeft.Where(f => key(f) != null).GroupBy(f => key(f)!).ToDictionary(g => g.Key, g => g.OrderBy(f => f.Module.Start).ToList());
            foreach (var (k, os) in olds)
                if (news.TryGetValue(k, out var ns) && os.Count == ns.Count)
                    for (int i = 0; i < os.Count; i++)
                    {
                        pairs.Add((os[i], ns[i], tier));
                        oldLeft.Remove(os[i]);
                        newLeft.Remove(ns[i]);
                    }
        }
        Unique(f => f.Path, "path");
        Unique(f => f.Hash.ToString("x16", System.Globalization.CultureInfo.InvariantCulture), "shape");
        Strings(oldLeft, newLeft, pairs, ct);
        Requires(oldFacts, newFacts, oldLeft, newLeft, pairs);
        Unique(f => f.Skeleton.ToString("x16", System.Globalization.CultureInfo.InvariantCulture), "skeleton");
        Requires(oldFacts, newFacts, oldLeft, newLeft, pairs);

        var rows = new List<JsModuleChange>();
        foreach (var (o, n, tier) in pairs)
        {
            bool same = o.Hash == n.Hash;
            string? detail = same ? null : StringDelta(o, n);
            if (o.Module.Id != n.Module.Id) detail = $"id {o.Module.Id} -> {n.Module.Id}" + (detail != null ? "; " + detail : "");
            rows.Add(new JsModuleChange(same ? "identical" : "changed", o.Module.Id, n.Module.Id, n.Path ?? o.Path, tier,
                o.Module.End - o.Module.Start, n.Module.End - n.Module.Start, detail));
        }
        rows.AddRange(oldLeft.Select(o => new JsModuleChange("removed", o.Module.Id, null, o.Path, null, o.Module.End - o.Module.Start, 0, Sample(o.Strings))));
        rows.AddRange(newLeft.Select(n => new JsModuleChange("added", null, n.Module.Id, n.Path, null, 0, n.Module.End - n.Module.Start, Sample(n.Strings))));
        int identical = rows.Count(r => r.Change == "identical");
        var shown = rows.Where(r => query == null ? r.Change != "identical"
                : r.OldId == query || r.NewId == query || r.Name?.Contains(query, StringComparison.OrdinalIgnoreCase) == true || r.Change == query)
            .OrderBy(r => r.Change switch { "changed" => 0, "added" => 1, "removed" => 2, _ => 3 }).ThenBy(r => r.Name ?? r.NewId ?? r.OldId, StringComparer.Ordinal).ToList();
        string? tokens = null;
        if (query != null && shown.Count == 1 && shown[0] is { Change: "changed", OldId: { } oi, NewId: { } ni })
        {
            var o = oldFacts.First(f => f.Module.Id == oi).Module;
            var n = newFacts.First(f => f.Module.Id == ni).Module;
            tokens = o.End - o.Start <= MaxTokenDiffBytes && n.End - n.Start <= MaxTokenDiffBytes
                ? TextDiff.Unified(Tokens(oldText[o.Start..o.End]), Tokens(newText[n.Start..n.End]), "old/" + oi, "new/" + ni)
                : $"modules over {MaxTokenDiffBytes:N0} bytes: no token diff";
        }
        return new JsDiffResult(oldFacts.Count, newFacts.Count, identical, rows.Count(r => r.Change == "changed"), newLeft.Count, oldLeft.Count,
            pairs.Count(p => p.Old.Module.Id != p.New.Module.Id), shown, tokens);
    }

    private static (string Text, List<Facts> Facts) Read(string path, CancellationToken ct)
    {
        var bytes = JsAnalysis.Read(path);
        var text = Encoding.UTF8.GetString(bytes);
        var notes = new List<string>();
        var tree = JsModules.Parse(text, notes) ?? throw new ToolError(ErrorCode.MalformedInput, $"{System.IO.Path.GetFileName(path)} could not be parsed: {string.Join("; ", notes)}");
        var modules = JsModules.Find(text, tree, ct);
        if (modules.Count == 0) throw new ToolError(ErrorCode.NotFound, $"{System.IO.Path.GetFileName(path)} has no module table.", "analyze_js view=modules shows what was found; compare_folders compares plain files");
        SourceMap? map = null;
        try { map = SourceMap.Locate(path, bytes)?.Map; }
        catch (ToolError) { }
        catch (FormatException) { }
        var facts = modules.Select(m => new Facts(m) { Path = m.Name }).ToList();
        var byStart = facts.GroupBy(f => f.Module.Start).ToDictionary(g => g.Key, g => g.First());
        var lines = LineStarts(text);
        var stack = new Stack<Node>();
        stack.Push(tree);
        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var node = stack.Pop();
            if (byStart.TryGetValue(node.Start, out var f) && f.Module.End == node.End && f.Hash == 0)
            {
                Fingerprint(node, f);
                if (f.Path == null && map != null) f.Path = Original(map, lines, f.Module);
            }
            foreach (var c in node.ChildNodes)
                if (c != null) stack.Push(c);
        }
        return (text, facts);
    }

    /// <summary>The original source most of three probes inside the module map to.</summary>
    private static string? Original(SourceMap map, List<int> lines, JsModule m)
    {
        var votes = new List<string>();
        foreach (var fraction in new[] { 0.25, 0.5, 0.75 })
        {
            int offset = m.Start + (int)((m.End - m.Start) * fraction);
            int line = lines.BinarySearch(offset);
            if (line < 0) line = ~line - 1;
            if (map.Find(line, offset - lines[line]) is { Source: >= 0 } seg && seg.Source < map.Sources.Count) votes.Add(map.Sources[seg.Source]);
        }
        return votes.GroupBy(v => v).OrderByDescending(g => g.Count()).FirstOrDefault()?.Key;
    }

    /// <summary>XxHash64 of the module's tree: node types, property names and literals; other names by first use; required ids as #.</summary>
    private static void Fingerprint(Node factory, Facts f)
    {
        var hash = new XxHash64();
        var skeleton = new XxHash64();
        var names = new Dictionary<string, int>(StringComparer.Ordinal);
        string? require = factory is IFunction fn ? fn.Params.Count >= 3 && fn.Params[2] is Identifier r ? r.Name
            : fn.Params.FirstOrDefault(p => p is Identifier { Name: "require" }) is Identifier named ? named.Name : null : null;
        var folded = new HashSet<Node>();
        var stack = new Stack<(Node Node, bool Name)>();
        stack.Push((factory, false));
        Span<byte> buffer = stackalloc byte[4];
        while (stack.Count > 0)
        {
            var (node, isName) = stack.Pop();
            System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(buffer, (int)node.Type);
            hash.Append(buffer);
            skeleton.Append(buffer);
            switch (node)
            {
                case Identifier id:
                    hash.Append(Encoding.UTF8.GetBytes(isName ? id.Name : "$" + (names.TryGetValue(id.Name, out var n) ? n : names[id.Name] = names.Count)));
                    if (isName && id.Name.Length >= 3) f.Strings.Add("." + id.Name); // property names survive minification
                    continue;
                case StringLiteral s:
                    if (!folded.Contains(s)) { hash.Append(Encoding.UTF8.GetBytes(s.Value)); if (s.Value.Length >= 3) f.Strings.Add(s.Value); }
                    continue;
                case Literal l:
                    hash.Append(Encoding.UTF8.GetBytes(folded.Contains(l) ? "#" : l.Raw));
                    continue;
                case TemplateElement t:
                    hash.Append(Encoding.UTF8.GetBytes(t.Value.Raw ?? ""));
                    if (t.Value.Cooked is { Length: >= 3 } cooked) f.Strings.Add(cooked);
                    continue;
                case CallExpression { Callee: Identifier callee, Arguments: [Literal arg, ..] } when callee.Name == require:
                    folded.Add(arg);
                    break;
            }
            var children = new List<(Node, bool)>();
            foreach (var c in node.ChildNodes)
                if (c != null)
                    children.Add((c, node switch
                    {
                        MemberExpression { Computed: false } m => ReferenceEquals(c, m.Property),
                        Property { Computed: false } p => ReferenceEquals(c, p.Key),
                        MethodDefinition { Computed: false } md => ReferenceEquals(c, md.Key),
                        PropertyDefinition { Computed: false } pd => ReferenceEquals(c, pd.Key),
                        _ => false,
                    }));
            for (int i = children.Count - 1; i >= 0; i--) stack.Push(children[i]);
        }
        f.Hash = hash.GetCurrentHashAsUInt64() | 1; // never 0: 0 marks "not fingerprinted"
        f.Skeleton = skeleton.GetCurrentHashAsUInt64();
    }

    /// <summary>Unpaired modules with at least three strings, paired when each is the other's best match by Jaccard similarity of 0.5 or more.</summary>
    private static void Strings(HashSet<Facts> oldLeft, HashSet<Facts> newLeft, List<(Facts, Facts, string)> pairs, CancellationToken ct)
    {
        var index = new Dictionary<string, List<Facts>>(StringComparer.Ordinal);
        foreach (var n in newLeft.Where(n => n.Strings.Count >= 3))
            foreach (var s in n.Strings)
                (index.TryGetValue(s, out var l) ? l : index[s] = []).Add(n);
        Facts? Best(Facts o, IEnumerable<Facts> candidates, out double score)
        {
            Facts? best = null;
            score = 0;
            foreach (var c in candidates.Distinct())
            {
                int shared = o.Strings.Count(c.Strings.Contains);
                double j = (double)shared / (o.Strings.Count + c.Strings.Count - shared);
                if (j > score) { score = j; best = c; }
            }
            return best;
        }
        var chosen = new List<(Facts, Facts)>();
        foreach (var o in oldLeft.Where(o => o.Strings.Count >= 3))
        {
            ct.ThrowIfCancellationRequested();
            var candidates = o.Strings.Where(index.ContainsKey).SelectMany(s => index[s]).Where(c => c.Strings.Count >= 3).Take(5000).ToList();
            if (Best(o, candidates, out var score) is not { } n || score < 0.5) continue;
            var back = oldLeft.Where(x => x.Strings.Count >= 3 && x.Strings.Overlaps(n.Strings));
            if (Best(n, back, out _) == o) chosen.Add((o, n));
        }
        foreach (var (o, n) in chosen)
            if (oldLeft.Remove(o) && newLeft.Remove(n)) pairs.Add((o, n, "strings"));
    }

    /// <summary>
    /// Pairs spread along the require graph: when two paired modules require the same number of modules, the unpaired ones
    /// at the same position pair (tier requires), if their sizes are within a factor of two; repeated until nothing changes.
    /// </summary>
    private static void Requires(List<Facts> oldFacts, List<Facts> newFacts, HashSet<Facts> oldLeft, HashSet<Facts> newLeft, List<(Facts Old, Facts New, string Tier)> pairs)
    {
        var oldById = oldFacts.GroupBy(f => f.Module.Id).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        var newById = newFacts.GroupBy(f => f.Module.Id).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        for (int done = 0, round = 0; round < 50; round++, done = pairs.Count)
        {
            for (int i = done; i < pairs.Count; i++)
            {
                var (o, n, _) = pairs[i];
                if (o.Module.Requires.Count != n.Module.Requires.Count) continue;
                for (int r = 0; r < o.Module.Requires.Count; r++)
                    if (oldById.TryGetValue(o.Module.Requires[r], out var ro) && newById.TryGetValue(n.Module.Requires[r], out var rn)
                        && oldLeft.Contains(ro) && newLeft.Contains(rn) && Similar(ro, rn))
                    {
                        oldLeft.Remove(ro);
                        newLeft.Remove(rn);
                        pairs.Add((ro, rn, "requires"));
                    }
            }
            if (pairs.Count == done) break;
        }
    }

    private static bool Similar(Facts a, Facts b)
    {
        double x = a.Module.End - a.Module.Start, y = b.Module.End - b.Module.Start;
        return x <= 2 * y && y <= 2 * x;
    }

    private static string? StringDelta(Facts o, Facts n)
    {
        var added = n.Strings.Except(o.Strings).Where(s => !s.StartsWith('.')).ToList();
        var removed = o.Strings.Except(n.Strings).Where(s => !s.StartsWith('.')).ToList();
        if (added.Count == 0 && removed.Count == 0) return "code changed, strings the same";
        return $"strings +{added.Count} -{removed.Count}" + (added.Count > 0 ? ": +" + Sample(added) : "") + (removed.Count > 0 ? "; -" + Sample(removed) : "");
    }

    private static string? Sample(IEnumerable<string> strings)
    {
        var s = strings.Where(x => x.Length <= 60 && !x.StartsWith('.')).Take(3).Select(x => $"\"{x}\"").ToList();
        return s.Count == 0 ? null : string.Join(", ", s);
    }

    /// <summary>The module's tokens one per line, for a line diff that reads as a token diff.</summary>
    private static string Tokens(string code) => string.Join('\n', Token().Matches(code).Select(m => m.Value));

    private static List<int> LineStarts(string text)
    {
        var starts = new List<int> { 0 };
        for (int i = 0; i < text.Length; i++)
            if (text[i] == '\n') starts.Add(i + 1);
        return starts;
    }

    [GeneratedRegex(@"""(?:\\.|[^""\\\n])*""|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`|[A-Za-z_$][\w$]*|\d[\w.]*|\S", RegexOptions.None, 1000)]
    private static partial Regex Token();
}
