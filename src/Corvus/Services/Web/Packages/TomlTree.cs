using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Corvus.Services.Web.Packages;

/// <summary>Reads the TOML subset that agent settings use: tables, arrays of tables, dotted keys, strings, numbers, booleans, arrays and inline tables.</summary>
internal static class TomlTree
{
    private const int MaxDepth = 32, MaxNodes = 50_000, MaxSkipped = 1_000;

    /// <summary>The document as a tree; a line that cannot be read is skipped and counted in <paramref name="skipped"/>. Never throws.</summary>
    internal static PackageReview.JsonTree Parse(string text, out int skipped)
    {
        var reader = new Reader(text);
        reader.Run();
        skipped = reader.Skipped;
        return reader.Root;
    }

    private sealed class Reader(string s)
    {
        private int _pos, _nodes;
        private readonly List<int> _lines = LineStarts(s);

        public int Skipped { get; private set; }
        public PackageReview.JsonTree Root { get; } = Table(1);

        private static PackageReview.JsonTree Table(int line) => PackageReview.JsonTree.Node(JsonTokenType.StartObject, line, props: []);

        private static List<int> LineStarts(string text)
        {
            var starts = new List<int> { 0 };
            for (int i = 0; i < text.Length; i++) if (text[i] == '\n') starts.Add(i + 1);
            return starts;
        }

        private int LineAt(int pos)
        {
            int at = _lines.BinarySearch(pos);
            return (at >= 0 ? at : ~at - 1) + 1;
        }

        private bool More => _pos < s.Length;

        public void Run()
        {
            var current = Root;
            while (_nodes < MaxNodes && Skipped < MaxSkipped)
            {
                SkipBlank(newlines: true);
                if (!More) return;
                int start = _pos;
                if (s[_pos] == '[')
                {
                    bool array = _pos + 1 < s.Length && s[_pos + 1] == '[';
                    _pos += array ? 2 : 1;
                    var table = Header(array);
                    if (table == null) { Skip(start); table = Table(LineAt(start)); }
                    current = table;
                }
                else if (!Assign(current)) Skip(start);
            }
            Skipped++;
        }

        private void Skip(int from)
        {
            Skipped++;
            _pos = Math.Max(_pos, from);
            while (More && s[_pos] != '\n') _pos++;
        }

        private void SkipBlank(bool newlines)
        {
            while (More)
            {
                char c = s[_pos];
                if (c is ' ' or '\t' or '\r' || newlines && c == '\n') _pos++;
                else if (c == '#') { while (More && s[_pos] != '\n') _pos++; }
                else break;
            }
        }

        private PackageReview.JsonTree? Header(bool array)
        {
            int line = LineAt(_pos);
            var path = KeyPath();
            if (path == null) return null;
            if (!Eat(']') || array && !Eat(']')) return null;
            SkipBlank(newlines: false);
            if (More && s[_pos] != '\n') return null;
            var table = Descend(Root, path[..^1], line);
            if (table == null) return null;
            var last = path[^1];
            var existing = table.Props!.FirstOrDefault(p => p.Name == last).Value;
            if (array)
            {
                if (existing == null) { existing = PackageReview.JsonTree.Node(JsonTokenType.StartArray, line, items: []); Add(table, last, existing); }
                if (existing.Items == null) return null;
                var item = Table(line);
                existing.Items.Add(item);
                _nodes++;
                return item;
            }
            if (existing == null) { existing = Table(line); Add(table, last, existing); }
            return existing.Props != null ? existing : null;
        }

        private void Add(PackageReview.JsonTree table, string name, PackageReview.JsonTree value)
        {
            table.Props!.Add((name, value));
            _nodes++;
        }

        // A key that names an array of tables continues in its last table.
        private PackageReview.JsonTree? Descend(PackageReview.JsonTree from, IEnumerable<string> path, int line)
        {
            var node = from;
            foreach (var key in path)
            {
                var next = node.Props!.FirstOrDefault(p => p.Name == key).Value;
                if (next == null) { next = Table(line); Add(node, key, next); }
                if (next.Items is { Count: > 0 } items && items[^1].Props != null) next = items[^1];
                if (next.Props == null) return null;
                node = next;
            }
            return node;
        }

        private bool Assign(PackageReview.JsonTree table)
        {
            int line = LineAt(_pos);
            var path = KeyPath();
            if (path == null || !Eat('=')) return false;
            SkipBlank(newlines: false);
            var value = Value(0);
            if (value == null) return false;
            SkipBlank(newlines: false);
            if (More && s[_pos] != '\n') return false;
            return Place(table, path, value, line);
        }

        // A key set twice is invalid TOML; the first value stays.
        private bool Place(PackageReview.JsonTree table, List<string> path, PackageReview.JsonTree value, int line)
        {
            var parent = Descend(table, path[..^1], line);
            if (parent == null || parent.Props!.Any(p => p.Name == path[^1])) return false;
            Add(parent, path[^1], value);
            return true;
        }

        private bool Eat(char c)
        {
            if (!More || s[_pos] != c) return false;
            _pos++;
            return true;
        }

        /// <summary>A dotted key, with blanks around each part; the position is left after it.</summary>
        private List<string>? KeyPath()
        {
            var path = new List<string>();
            while (true)
            {
                SkipBlank(newlines: false);
                var key = Key();
                if (key == null || path.Count >= MaxDepth) return null;
                path.Add(key);
                SkipBlank(newlines: false);
                if (!Eat('.')) return path;
            }
        }

        private string? Key()
        {
            if (!More) return null;
            if (s[_pos] is '"' or '\'') return Quoted(multiline: false);
            int start = _pos;
            while (More && (char.IsAsciiLetterOrDigit(s[_pos]) || s[_pos] is '_' or '-')) _pos++;
            return _pos > start ? s[start.._pos] : null;
        }

        private PackageReview.JsonTree? Value(int depth)
        {
            if (!More || depth > MaxDepth || _nodes >= MaxNodes) return null;
            int line = LineAt(_pos);
            _nodes++;
            switch (s[_pos])
            {
                case '"' or '\'':
                    var text = Quoted(multiline: true);
                    return text == null ? null : PackageReview.JsonTree.Node(JsonTokenType.String, line, text);
                case '[':
                    return ArrayValue(line, depth);
                case '{':
                    return InlineTable(line, depth);
                default:
                    int start = _pos;
                    while (More && !char.IsWhiteSpace(s[_pos]) && s[_pos] is not (',' or ']' or '}' or '#')) _pos++;
                    var word = s[start.._pos];
                    if (word.Length == 0) return null;
                    if (word is "true" or "false")
                        return PackageReview.JsonTree.Node(word == "true" ? JsonTokenType.True : JsonTokenType.False, line, word);
                    return char.IsAsciiDigit(word[0]) || word[0] is '+' or '-' or 'i' or 'n' ? PackageReview.JsonTree.Node(JsonTokenType.Number, line, word) : null;
            }
        }

        private PackageReview.JsonTree? ArrayValue(int line, int depth)
        {
            _pos++;
            var items = new List<PackageReview.JsonTree>();
            while (true)
            {
                SkipBlank(newlines: true);
                if (Eat(']')) return PackageReview.JsonTree.Node(JsonTokenType.StartArray, line, items: items);
                var item = Value(depth + 1);
                if (item == null) return null;
                items.Add(item);
                SkipBlank(newlines: true);
                if (!Eat(',') && !(More && s[_pos] == ']')) return null;
            }
        }

        private PackageReview.JsonTree? InlineTable(int line, int depth)
        {
            _pos++;
            var table = Table(line);
            SkipBlank(newlines: false);
            if (Eat('}')) return table;
            while (true)
            {
                var path = KeyPath();
                if (path == null || !Eat('=')) return null;
                SkipBlank(newlines: false);
                var value = Value(depth + 1);
                if (value == null || !Place(table, path, value, line)) return null;
                SkipBlank(newlines: false);
                if (Eat('}')) return table;
                if (!Eat(',')) return null;
            }
        }

        /// <summary>A basic or literal string, triple-quoted when <paramref name="multiline"/> allows it; null when unterminated or invalid.</summary>
        private string? Quoted(bool multiline)
        {
            char quote = s[_pos];
            bool basic = quote == '"';
            bool triple = multiline && _pos + 2 < s.Length && s[_pos + 1] == quote && s[_pos + 2] == quote;
            _pos += triple ? 3 : 1;
            if (triple && More && s[_pos] == '\r') _pos++;
            if (triple && More && s[_pos] == '\n') _pos++;
            var sb = new StringBuilder();
            while (More)
            {
                char c = s[_pos];
                if (c == quote && (!triple || _pos + 2 < s.Length && s[_pos + 1] == quote && s[_pos + 2] == quote))
                {
                    _pos += triple ? 3 : 1;
                    return sb.ToString();
                }
                if (c == '\n' && !triple) return null;
                _pos++;
                if (c != '\\' || !basic) { sb.Append(c); continue; }
                if (!More) return null;
                char e = s[_pos++];
                switch (e)
                {
                    case 'b': sb.Append('\b'); break;
                    case 't': sb.Append('\t'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'r': sb.Append('\r'); break;
                    case 'u' or 'U':
                        int digits = e == 'u' ? 4 : 8;
                        if (_pos + digits > s.Length || !int.TryParse(s.AsSpan(_pos, digits), NumberStyles.AllowHexSpecifier, null, out var cp)
                            || cp is < 0 or > 0x10FFFF or (>= 0xD800 and <= 0xDFFF)) return null;
                        sb.Append(char.ConvertFromUtf32(cp));
                        _pos += digits;
                        break;
                    case '\r' or '\n' or ' ' or '\t' when triple:
                        while (More && char.IsWhiteSpace(s[_pos])) _pos++;
                        break;
                    default: sb.Append(e); break;
                }
            }
            return null;
        }
    }
}
