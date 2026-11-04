using System.Text;
using Corvus.Core.Mobile;

namespace Corvus.Services.Mobile;

/// <summary>Replaces static string decoder calls in decompiled Java with the string literals their DEX fold sites evaluate to.</summary>
public static class JavaStringFold
{
    /// <summary>The rewritten text with the calls replaced and the calls left as written.</summary>
    public sealed record Result(string Text, int Folded, int Unknown)
    {
        /// <summary>The one-line header naming both counts.</summary>
        public string Header => $"// simplified: {Folded} strings folded, {Unknown} unknown";
    }

    /// <summary>The header for output left unchanged because it is smali.</summary>
    public const string SmaliHeader = "// simplified: smali fallback left unchanged";

    /// <summary>The header for output of a class file, which carries no DEX decoder calls.</summary>
    public const string ClassFileHeader = "// simplified: class files carry no DEX decoder calls; nothing folded";

    /// <summary>True when the text is smali (a method body in smali mode or a smali class).</summary>
    public static bool IsSmali(string text)
    {
        var head = text.AsSpan(0, Math.Min(text.Length, 400));
        return head.Contains(", smali", StringComparison.Ordinal) || text.StartsWith(".class ", StringComparison.Ordinal)
            || text.Contains("\n.method ", StringComparison.Ordinal);
    }

    /// <summary>
    /// A Java string literal for the value: quotes, backslashes, control and non-ASCII characters escaped.
    /// </summary>
    public static string Literal(string value)
    {
        var sb = new StringBuilder(value.Length + 2).Append('"');
        foreach (var c in value)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case < ' ' or (> '~'): sb.Append("\\u").Append(((int)c).ToString("x4")); break;
                default: sb.Append(c); break;
            }
        }
        return sb.Append('"').ToString();
    }

    /// <summary>
    /// Replaces each call to a decoder of <paramref name="sites"/> in <paramref name="text"/>. A call is bound to a site
    /// by decoder class and method name; a decoder whose calls and sites differ in number, or whose sites in several
    /// methods give different values, stays as written and is counted unknown.
    /// </summary>
    /// <param name="text">Decompiled Java of a class or method.</param>
    /// <param name="sites">Static String decoder sites of the same class or method.</param>
    /// <param name="scope">Descriptors of the classes the text declares, whose decoders may be called unqualified.</param>
    public static Result Apply(string text, IReadOnlyList<DexFoldSite> sites, IReadOnlySet<string> scope)
    {
        var groups = new Dictionary<(string Class, string Name), List<DexFoldSite>>();
        foreach (var s in sites)
        {
            if (Split(s.Decoder) is not { } key) continue;
            if (!groups.TryGetValue(key, out var list)) groups[key] = list = [];
            list.Add(s);
        }
        if (groups.Count == 0) return new(text, 0, 0);

        var calls = Calls(text, groups, scope);
        var edits = new List<(int Start, int End, string Literal)>();
        int unknown = 0;
        foreach (var group in calls.GroupBy(c => c.Key))
        {
            var (key, found) = (group.Key, group.ToList());
            var list = groups[key];
            var bound = Bind(text, list, found);
            int i = 0;
            foreach (var call in found)
            {
                if (bound?[i++] is { } value) edits.Add((call.Start, call.End, Literal(value)));
                else unknown++;
            }
        }
        if (edits.Count == 0) return new(text, 0, unknown);
        var sb = new StringBuilder(text.Length);
        int at = 0;
        foreach (var (start, end, literal) in edits.OrderBy(e => e.Start))
        {
            sb.Append(text, at, start - at).Append(literal);
            at = end;
        }
        return new(sb.Append(text, at, text.Length - at).ToString(), edits.Count, unknown);
    }

    // The values per call in text order; null where the calls cannot be bound uniquely.
    private static string?[]? Bind(string text, List<DexFoldSite> sites, List<Call> calls)
    {
        if (sites.Count != calls.Count) return null;
        string?[] Values(IEnumerable<DexFoldSite> s) =>
            [.. s.OrderBy(x => x.Offset).Select(x => x.Fold is { Status: DexFoldStatus.Simplified, Value: { } v } ? v : null)];
        var methods = sites.GroupBy(s => s.Method, StringComparer.Ordinal).ToList();
        if (methods.Count == 1) return Values(sites);
        // Several methods: calls are grouped by the method declaration above them in the text.
        var names = methods.Select(g => g.Key[(g.Key.IndexOf("->", StringComparison.Ordinal) + 2)..g.Key.IndexOf('(')]).ToList();
        if (names.Distinct(StringComparer.Ordinal).Count() != names.Count) return null;
        var starts = names.Select(n => Declaration(text, n)).ToList();
        if (starts.Any(p => p < 0) || starts.Distinct().Count() != starts.Count) return null;
        var perMethod = methods.Select((g, i) => (Start: starts[i], Values: Values(g))).OrderBy(m => m.Start).ToList();
        var result = new string?[calls.Count];
        var taken = new int[perMethod.Count];
        for (int c = 0; c < calls.Count; c++)
        {
            int m = perMethod.FindLastIndex(x => x.Start <= calls[c].Start);
            if (m < 0 || taken[m] >= perMethod[m].Values.Length) return null;
            result[c] = perMethod[m].Values[taken[m]++];
        }
        return taken.Select((n, i) => n == perMethod[i].Values.Length).All(x => x) ? result : null;
    }

    // The start of the first declaration of a method of this name, -1 when none.
    private static int Declaration(string text, string name)
    {
        for (int at = text.IndexOf(name + "(", StringComparison.Ordinal); at >= 0; at = text.IndexOf(name + "(", at + 1, StringComparison.Ordinal))
            if ((at == 0 || !(char.IsLetterOrDigit(text[at - 1]) || text[at - 1] is '_' or '$' or '.')) && IsDeclaration(text, at)) return at;
        return -1;
    }
    private static (string Class, string Name)? Split(string decoder)
    {
        int arrow = decoder.IndexOf("->", StringComparison.Ordinal), paren = decoder.IndexOf('(');
        if (arrow < 0 || paren < arrow) return null;
        if (!decoder.EndsWith(")Ljava/lang/String;", StringComparison.Ordinal)) return null;
        var cls = decoder[..arrow].TrimEnd(';');
        cls = cls[(cls.LastIndexOf('/') + 1)..];
        cls = cls[(cls.LastIndexOf('$') + 1)..];
        return (cls, decoder[(arrow + 2)..paren]);
    }

    private sealed record Call((string Class, string Name) Key, int Start, int End);

    private static List<Call> Calls(string s, Dictionary<(string Class, string Name), List<DexFoldSite>> groups, IReadOnlySet<string> scope)
    {
        var found = new List<Call>();
        var unqualified = new Dictionary<string, (string Class, string Name)>(StringComparer.Ordinal);
        foreach (var key in groups.Keys)
            foreach (var site in groups[key])
                if (site.Decoder.IndexOf("->", StringComparison.Ordinal) is > 0 and var arrow && scope.Contains(site.Decoder[..arrow]))
                    unqualified[key.Name] = key;
        for (int i = 0; i < s.Length;)
        {
            char c = s[i];
            if (c == '"' || c == '\'') i = SkipLiteral(s, i);
            else if (c == '/' && i + 1 < s.Length && s[i + 1] == '/') i = s.IndexOf('\n', i) is var e and >= 0 ? e : s.Length;
            else if (c == '/' && i + 1 < s.Length && s[i + 1] == '*') i = s.IndexOf("*/", i + 2, StringComparison.Ordinal) is var e and >= 0 ? e + 2 : s.Length;
            else if (char.IsLetter(c) || c == '_' || c == '$')
            {
                int start = i;
                var parts = new List<string>();
                int end = i;
                while (true)
                {
                    int j = end;
                    while (j < s.Length && (char.IsLetterOrDigit(s[j]) || s[j] == '_' || s[j] == '$')) j++;
                    parts.Add(s[end..j]);
                    end = j;
                    if (end < s.Length && s[end] == '.' && end + 1 < s.Length && (char.IsLetter(s[end + 1]) || s[end + 1] == '_' || s[end + 1] == '$')) end++;
                    else break;
                }
                int paren = end;
                while (paren < s.Length && s[paren] is ' ' or '\t') paren++;
                i = end;
                if (paren >= s.Length || s[paren] != '(' || PreviousIsMember(s, start)) continue;
                var name = parts[^1];
                (string Class, string Name)? key = null;
                if (parts.Count >= 2 && groups.ContainsKey((parts[^2], name))) key = (parts[^2], name);
                else if (parts.Count == 1 && unqualified.TryGetValue(name, out var u) && !IsDeclaration(s, start)) key = u;
                if (key == null || ArgumentsEnd(s, paren) is not { } close) continue;
                found.Add(new(key.Value, start, close + 1));
                i = close + 1;
            }
            else i++;
        }
        return found;
    }

    // A chain after a closing bracket or a dot belongs to a longer expression.
    private static bool PreviousIsMember(string s, int start)
    {
        int p = start - 1;
        while (p >= 0 && char.IsWhiteSpace(s[p])) p--;
        return p >= 0 && (s[p] == '.' || s[p] == ')' || s[p] == ']');
    }

    // A method declaration has a type before its name; return and similar keywords are not types.
    private static bool IsDeclaration(string s, int start)
    {
        int p = start - 1;
        while (p >= 0 && char.IsWhiteSpace(s[p])) p--;
        if (p < 0 || !(char.IsLetterOrDigit(s[p]) || s[p] is '_' or '$' or '>')) return false;
        int e = p + 1;
        while (p >= 0 && (char.IsLetterOrDigit(s[p]) || s[p] is '_' or '$')) p--;
        return s[(p + 1)..e] is not ("return" or "throw" or "else" or "case" or "yield");
    }

    private static int SkipLiteral(string s, int i)
    {
        char q = s[i];
        for (i++; i < s.Length && s[i] != q && s[i] != '\n'; i++) if (s[i] == '\\') i++;
        return Math.Min(i + 1, s.Length);
    }

    // The index of the parenthesis closing the one at open; null when unbalanced.
    private static int? ArgumentsEnd(string s, int open)
    {
        int depth = 0;
        for (int i = open; i < s.Length; i++)
        {
            char c = s[i];
            if (c == '"' || c == '\'') i = SkipLiteral(s, i) - 1;
            else if (c == '(') depth++;
            else if (c == ')' && --depth == 0) return i;
            else if (c is ';' or '{' or '}') return null;
        }
        return null;
    }
}
