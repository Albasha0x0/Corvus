using Acornima.Ast;

namespace Corvus.Services.Web;

/// <summary>A search hit: what matched (string, identifier or property), its module, generated and (with a map) original position.</summary>
public sealed record JsHit(string Kind, string Value, string? Module, int Line, int Column, string? Original);

/// <summary>analyze_js view=search and view=refs over one parsed file.</summary>
public static class JsSearch
{
    public const int MaxHits = 2000;

    /// <summary>String literals, identifiers and property names containing <paramref name="query"/> (case-insensitive), in text order.</summary>
    public static List<JsHit> Find(string text, Acornima.Ast.Program script, IReadOnlyList<JsModule> modules, SourceMap? map, string query, CancellationToken ct)
    {
        var lines = LineStarts(text);
        var hits = new List<JsHit>();
        var stack = new Stack<Node>();
        stack.Push(script);
        while (stack.Count > 0 && hits.Count < MaxHits)
        {
            ct.ThrowIfCancellationRequested();
            var node = stack.Pop();
            (string Kind, string Value)? match = node switch
            {
                StringLiteral s when s.Value.Contains(query, StringComparison.OrdinalIgnoreCase) => ("string", s.Value),
                Identifier i when i.Name.Contains(query, StringComparison.OrdinalIgnoreCase) => ("identifier", i.Name),
                _ => null,
            };
            if (match is { } m)
            {
                var (line, column) = Position(lines, node.Start);
                string? original = null;
                if (map?.Find(line, column) is { Source: >= 0 } seg && seg.Source < map.Sources.Count)
                    original = $"{map.Sources[seg.Source]}:{seg.OriginalLine + 1}:{seg.OriginalColumn + 1}";
                var module = modules.LastOrDefault(x => x.Start <= node.Start && node.End <= x.End)?.Id;
                hits.Add(new JsHit(m.Kind, m.Value.Length > 200 ? m.Value[..197] + "..." : m.Value, module, line + 1, column + 1, original));
            }
            foreach (var child in node.ChildNodes)
                if (child != null) stack.Push(child);
        }
        hits.Sort((a, b) => a.Line != b.Line ? a.Line.CompareTo(b.Line) : a.Column.CompareTo(b.Column));
        return hits;
    }

    /// <summary>The modules <paramref name="id"/> requires, and the modules requiring it (a require of its id, or a dependency map entry to it).</summary>
    public static (IReadOnlyList<string> Requires, IReadOnlyList<string> RequiredBy) Refs(IReadOnlyList<JsModule> modules, JsModule target)
    {
        bool Points(string request) => request == target.Id || request.EndsWith(" -> " + target.Id, StringComparison.Ordinal)
                                       || (target.Name != null && (request == target.Name || request.EndsWith("/" + target.Name.Split('/')[^1].Replace(".js", ""), StringComparison.Ordinal)));
        var by = modules.Where(m => m != target && m.Requires.Any(Points)).Select(m => m.Id).ToList();
        return (target.Requires, by);
    }

    private static List<int> LineStarts(string text)
    {
        var starts = new List<int> { 0 };
        for (int i = 0; i < text.Length; i++)
            if (text[i] == '\n') starts.Add(i + 1);
        return starts;
    }

    /// <summary>0-based line and UTF-16 column of a character offset.</summary>
    private static (int Line, int Column) Position(List<int> starts, int offset)
    {
        int line = starts.BinarySearch(offset);
        if (line < 0) line = ~line - 1;
        return (line, offset - starts[line]);
    }
}
