namespace Corvus.Services.Web.Packages;

/// <summary>A GitHub Actions workflow file read as a tree; the block subset of YAML the workflow fields use, with no anchors, tags or multiple documents.</summary>
internal sealed class WorkflowFile
{
    /// <summary>A mapping, sequence or scalar with the 1-based line it starts on.</summary>
    internal sealed class Node
    {
        public int Line { get; init; }

        /// <summary>A scalar's text; block scalars keep their line breaks. Null for a mapping or sequence.</summary>
        public string? Text { get; init; }

        public List<(string Key, Node Value)>? Map { get; init; }
        public List<Node>? Seq { get; init; }

        /// <summary>The first entry of that key, or null when absent or not a mapping.</summary>
        public Node? this[string key] => Map?.FirstOrDefault(e => e.Key == key).Value;
    }

    private const int MaxDepth = 32, MaxLines = 20_000;

    private readonly List<(int Indent, string Raw, int No)> _lines = [];
    private int _at;

    /// <summary>The tree of <paramref name="text"/>; null when it holds no mapping. Lines the subset does not cover are skipped.</summary>
    public static Node? Parse(string text)
    {
        var file = new WorkflowFile();
        int no = 0;
        foreach (var raw in text.Split('\n'))
        {
            if (++no > MaxLines) break;
            var line = raw.TrimEnd('\r');
            int indent = 0;
            while (indent < line.Length && line[indent] == ' ') indent++;
            file._lines.Add((indent, line, no));
        }
        file.SkipBlank();
        return file._at < file._lines.Count && file.Block(file._lines[file._at].Indent, 0) is { Map: not null } root ? root : null;
    }

    private static string Content(string raw)
    {
        bool single = false, @double = false;
        for (int i = 0; i < raw.Length; i++)
        {
            char c = raw[i];
            if (c == '\'' && !@double) single = !single;
            else if (c == '"' && !single && (i == 0 || raw[i - 1] != '\\')) @double = !@double;
            else if (c == '#' && !single && !@double && (i == 0 || raw[i - 1] is ' ' or '\t')) return raw[..i].TrimEnd();
        }
        return raw.TrimEnd();
    }

    private void SkipBlank()
    {
        while (_at < _lines.Count && Content(_lines[_at].Raw).Trim().Length == 0) _at++;
    }

    private Node? Block(int indent, int depth)
    {
        if (depth > MaxDepth) return null;
        var first = Content(_lines[_at].Raw).TrimStart();
        return first == "-" || first.StartsWith("- ", StringComparison.Ordinal) ? Sequence(indent, depth) : Mapping(indent, depth);
    }

    private Node Sequence(int indent, int depth)
    {
        int start = _lines[_at].No;
        var items = new List<Node>();
        while (_at < _lines.Count)
        {
            var (ind, raw, no) = _lines[_at];
            var text = Content(raw).TrimStart();
            if (ind != indent || text != "-" && !text.StartsWith("- ", StringComparison.Ordinal)) break;
            var rest = text[1..].TrimStart();
            if (rest.Length == 0)
            {
                _at++;
                SkipBlank();
                items.Add(_at < _lines.Count && _lines[_at].Indent > indent && Block(_lines[_at].Indent, depth + 1) is { } child ? child : new Node { Line = no, Text = "" });
                continue;
            }
            // The text after the dash becomes a line of its own at its own column.
            int column = ind + (text.Length - rest.Length);
            _lines[_at] = (column, new string(' ', column) + rest, no);
            items.Add(Block(column, depth + 1) ?? new Node { Line = no, Text = rest });
            SkipBlank();
        }
        return new Node { Line = start, Seq = items };
    }

    private Node Mapping(int indent, int depth)
    {
        int start = _lines[_at].No;
        var map = new List<(string, Node)>();
        while (_at < _lines.Count)
        {
            var (ind, raw, no) = _lines[_at];
            var text = Content(raw).TrimStart();
            if (ind < indent) break;
            if (ind != indent || KeySplit(text) is not { } kv)
            {
                // A continuation line of a multi-line value.
                _at++;
                SkipBlank();
                continue;
            }
            var (key, value) = kv;
            _at++;
            if (value.Length == 0)
            {
                SkipBlank();
                // A sequence may sit at the key's own indent.
                bool child = _at < _lines.Count && (_lines[_at].Indent > indent
                    || _lines[_at].Indent == indent && Content(_lines[_at].Raw).TrimStart() is "-" or ['-', ' ', ..]);
                map.Add((key, child && Block(_lines[_at].Indent, depth + 1) is { } node ? node : new Node { Line = no, Text = "" }));
            }
            else if (value[0] is '|' or '>') map.Add((key, BlockScalar(indent)));
            else map.Add((key, new Node { Line = no, Text = Scalar(value) }));
            SkipBlank();
        }
        return new Node { Line = start, Map = map };
    }

    private Node BlockScalar(int parentIndent)
    {
        int line = _at < _lines.Count ? _lines[_at].No : 0;
        var body = new List<string>();
        int strip = -1;
        while (_at < _lines.Count && (_lines[_at].Raw.Trim().Length == 0 || _lines[_at].Indent > parentIndent))
        {
            var (ind, raw, _) = _lines[_at++];
            if (raw.Trim().Length > 0 && strip < 0) strip = ind;
            body.Add(raw.Trim().Length == 0 ? "" : raw[Math.Min(strip < 0 ? ind : strip, ind)..]);
        }
        return new Node { Line = line, Text = string.Join('\n', body).TrimEnd('\n') };
    }

    private static (string Key, string Value)? KeySplit(string text)
    {
        int i = 0;
        string key;
        if (text.Length > 0 && text[0] is '"' or '\'')
        {
            i = text.IndexOf(text[0], 1);
            if (i < 0) return null;
            key = text[1..i];
            i++;
        }
        else
        {
            while (i < text.Length && !(text[i] == ':' && (i + 1 == text.Length || text[i + 1] is ' ' or '\t'))) i++;
            if (i >= text.Length) return null;
            key = text[..i].TrimEnd();
        }
        if (i >= text.Length || text[i] != ':' || key.Length == 0 || text[0] == '[' || text[0] == '{') return null;
        return (key, text[(i + 1)..].Trim());
    }

    private static string Scalar(string value)
    {
        if (value.Length >= 2 && value[0] == '"' && value[^1] == '"') return value[1..^1].Replace("\\\"", "\"", StringComparison.Ordinal);
        if (value.Length >= 2 && value[0] == '\'' && value[^1] == '\'') return value[1..^1].Replace("''", "'", StringComparison.Ordinal);
        return value;
    }

    /// <summary>The items of a flow sequence such as <c>[push, pull_request]</c>, or a one-item list for any other scalar.</summary>
    public static IEnumerable<string> Flow(string text)
    {
        text = text.Trim();
        if (text.Length >= 2 && text[0] == '[' && text[^1] == ']')
            return text[1..^1].Split(',').Select(s => Scalar(s.Trim())).Where(s => s.Length > 0);
        return text.Length > 0 ? [text] : [];
    }
}
