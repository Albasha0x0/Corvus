using System.Text;

namespace Corvus.Services.Analysis.Hunts;

/// <summary>A lexical check of the query shapes the writer emits: terminated literals, balanced brackets, known table, known columns and functions.</summary>
public static class KqlCheck
{
    private static readonly HashSet<string> Keywords = new(StringComparer.Ordinal)
        { "where", "project", "extend", "and", "or", "not", "in", "has", "contains", "startswith", "endswith", "by", "take", "true", "false" };

    private static readonly HashSet<string> Functions = new(StringComparer.Ordinal)
        { "tostring", "parse_json", "tolower", "isnotempty", "coalesce", "iff", "strcat", "substring", "strlen", "trim_end", "extract", "strcmp" };

    /// <summary>The problems of <paramref name="kql"/> against the columns of its first table; empty when none.</summary>
    public static IReadOnlyList<string> Diagnostics(string kql)
    {
        var problems = new List<string>();
        var tokens = Tokens(kql, problems);
        if (tokens.Count == 0) return ["The query is empty."];
        var table = tokens[0].Text;
        var columns = HuntSchema.Columns(table).Select(c => c.Name).ToHashSet(StringComparer.Ordinal);
        if (columns.Count == 0) problems.Add($"Table '{table}' is not in the schema.");
        // An alias is an identifier that a single = assigns.
        var aliases = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i + 1 < tokens.Count; i++)
            if (tokens[i].Kind == 'i' && tokens[i + 1].Text == "=") aliases.Add(tokens[i].Text);
        int depth = 0;
        for (int i = 1; i < tokens.Count; i++)
        {
            var t = tokens[i];
            if (t.Text == "(") depth++;
            else if (t.Text == ")" && --depth < 0) problems.Add("A closing parenthesis has no opening one.");
            if (t.Kind != 'i' || Keywords.Contains(t.Text) || tokens[i - 1].Text == ".") continue;
            bool call = i + 1 < tokens.Count && tokens[i + 1].Text == "(";
            if (call && !Functions.Contains(t.Text)) problems.Add($"Function '{t.Text}' is not allowed.");
            else if (!call && !columns.Contains(t.Text) && !aliases.Contains(t.Text)) problems.Add($"Name '{t.Text}' is not a column of {table}.");
        }
        if (depth > 0) problems.Add("A parenthesis is not closed.");
        return problems;
    }

    private readonly record struct Token(char Kind, string Text);

    // Kinds: i identifier, s string literal, n number, o operator or punctuation.
    private static List<Token> Tokens(string text, List<string> problems)
    {
        var tokens = new List<Token>();
        for (int i = 0; i < text.Length;)
        {
            char c = text[i];
            if (char.IsWhiteSpace(c)) { i++; continue; }
            // A verbatim literal has no escapes; a doubled quote is one quote.
            if (c == '@' && i + 1 < text.Length && text[i + 1] is '\'' or '"')
            {
                char q = text[i + 1];
                int end = i + 2;
                while (end < text.Length && text[end] is not ('\n' or '\r'))
                {
                    if (text[end] != q) { end++; continue; }
                    if (end + 1 < text.Length && text[end + 1] == q) { end += 2; continue; }
                    break;
                }
                if (end >= text.Length || text[end] != q) { problems.Add("A string literal is not terminated."); return tokens; }
                tokens.Add(new('s', text[i..(end + 1)]));
                i = end + 1;
            }
            else if (c is '\'' or '"')
            {
                int end = i + 1;
                while (end < text.Length && text[end] != c)
                {
                    if (text[end] == '\\') end++;
                    else if (text[end] is '\n' or '\r') break;
                    end++;
                }
                if (end >= text.Length || text[end] != c) { problems.Add("A string literal is not terminated."); return tokens; }
                tokens.Add(new('s', text[i..(end + 1)]));
                i = end + 1;
            }
            else if (char.IsAsciiLetter(c) || c == '_')
            {
                int end = i;
                while (end < text.Length && (char.IsAsciiLetterOrDigit(text[end]) || text[end] == '_')) end++;
                tokens.Add(new('i', text[i..end]));
                i = end;
            }
            else if (char.IsAsciiDigit(c))
            {
                int end = i;
                while (end < text.Length && char.IsAsciiLetterOrDigit(text[end])) end++;
                tokens.Add(new('n', text[i..end]));
                i = end;
            }
            else if (c is '|' or ',' or '(' or ')' or '.' or '=' or '!' or '~' or '<' or '>' or '-' or '+')
            {
                var sb = new StringBuilder().Append(c);
                while (c is '=' or '!' or '<' or '>' && i + sb.Length < text.Length && text[i + sb.Length] is '=' or '~') sb.Append(text[i + sb.Length]);
                tokens.Add(new('o', sb.ToString()));
                i += sb.Length;
            }
            else { problems.Add($"Character '{c}' is not allowed outside a literal."); i++; }
        }
        return tokens;
    }
}
