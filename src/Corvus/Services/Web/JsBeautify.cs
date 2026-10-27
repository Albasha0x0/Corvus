using System.Text;
using Acornima;
using Acornima.Ast;

namespace Corvus.Services.Web;

/// <summary>Reformats a script or module from its tokens, writing inserted semicolons and applying <see cref="JsNames"/> renames; throws <see cref="InvalidDataException"/> when it does not parse.</summary>
internal static class JsBeautify
{
    public const int MaxBytes = 64 << 20;
    private const string Indent = "  ";

    /// <summary>The formatted text, the original offset each output line starts at, the renames applied and notes (renames refused, parse notes).</summary>
    public sealed record Result(string Text, IReadOnlyList<int> Origins, IReadOnlyList<JsNames.Rename> Renames, IReadOnlyList<string> Notes);

    private enum Frame : byte { Block, Object, Inline, Switch, Template, Paren, ForHeader, Bracket }

    private sealed class Level(Frame kind)
    {
        public Frame Kind = kind;
        public int Ternaries;
        public bool CaseColon, CaseIndented;
    }

    private sealed class Parsed
    {
        public Acornima.Ast.Program? Tree;
        public readonly List<Token> Tokens = [];
        public readonly List<Comment> Comments = [];
        public readonly HashSet<int> Inserted = [];
    }

    public static Result Format(string text, string? renames, bool auto, CancellationToken ct)
    {
        if (text.Length > MaxBytes) throw new InvalidDataException($"{text.Length:N0} characters, over the {MaxBytes:N0} limit");
        Result? result = null;
        Exception? error = null;
        // A deep tree must not overflow the server's stack: a thread of its own with a large stack.
        var thread = new Thread(() =>
        {
            try { result = Run(text, renames, auto, ct); }
            catch (Exception ex) { error = ex; }
        }, 256 * 1024 * 1024);
        thread.Start();
        thread.Join();
        if (error is ParseErrorException parse) throw new InvalidDataException($"parse error: {parse.Message}", parse);
        if (error != null) throw error;
        return result!;
    }

    private static Parsed Parse(string text, bool module)
    {
        var p = new Parsed();
        var options = new ParserOptions
        {
            AllowHashBang = true,
            OnToken = (in Token t) => p.Tokens.Add(t),
            OnComment = (in Comment c) => p.Comments.Add(c),
            OnInsertedSemicolon = (int end, Position _) => p.Inserted.Add(end),
        };
        var parser = new Parser(options);
        p.Tree = module ? parser.ParseModule(text) : parser.ParseScript(text);
        return p;
    }

    private static Result Run(string text, string? renames, bool auto, CancellationToken ct)
    {
        Parsed parsed;
        // A script first; import / export make it a module.
        try { parsed = Parse(text, module: false); }
        catch (ParseErrorException) { parsed = Parse(text, module: true); }
        ct.ThrowIfCancellationRequested();
        var notes = new List<string>();
        var applied = new List<JsNames.Rename>();
        Dictionary<int, string> sites = [];
        if (renames != null || auto)
        {
            var names = new JsNames(parsed.Tree!);
            var lines = LineStarts(text);
            var refused = new List<string>();
            applied = names.Plan(renames, auto, offset => Position(lines, offset), refused);
            sites = names.Sites();
            notes.AddRange(refused.Select(r => "not renamed: " + r));
            notes.AddRange(names.Notes.Distinct());
        }
        var shape = new Shape();
        shape.Visit(parsed.Tree!, parsed.Tokens);
        var w = new Writer(text, parsed, shape, sites);
        w.Run(ct);
        return new Result(w.Output.ToString(), w.Origins, applied, notes);
    }

    internal static List<int> LineStarts(string text)
    {
        var starts = new List<int> { 0 };
        for (int i = 0; i < text.Length; i++)
            if (text[i] == '\n' || text[i] == '\r' && (i + 1 >= text.Length || text[i + 1] != '\n')) starts.Add(i + 1);
        return starts;
    }

    /// <summary>The 1-based line and column of <paramref name="offset"/>.</summary>
    internal static (int Line, int Column) Position(List<int> lines, int offset)
    {
        int i = lines.BinarySearch(offset);
        if (i < 0) i = ~i - 1;
        return (i + 1, offset - lines[i] + 1);
    }

    // Which braces open blocks, object literals or switch bodies, and which end a do-while body.
    private sealed class Shape
    {
        public readonly HashSet<int> Blocks = [], Objects = [], Switches = [], DoBodies = [];

        public void Visit(Node root, List<Token> tokens)
        {
            var stack = new Stack<Node>();
            stack.Push(root);
            while (stack.Count > 0)
            {
                var n = stack.Pop();
                switch (n)
                {
                    case StaticBlock sb: Blocks.Add(Next(tokens, sb.Start, "{")); break;
                    case BlockStatement or ClassBody: Blocks.Add(n.Start); break;
                    case ObjectExpression or ObjectPattern: Objects.Add(n.Start); break;
                    case SwitchStatement sw: Switches.Add(Next(tokens, sw.Discriminant.End, "{")); break;
                    case DoWhileStatement { Body: BlockStatement body }: DoBodies.Add(body.End); break;
                }
                foreach (var c in n.ChildNodes) stack.Push(c);
            }
        }

        private static int Next(List<Token> tokens, int from, string punctuator)
        {
            int lo = 0, hi = tokens.Count;
            while (lo < hi)
            {
                int mid = (lo + hi) / 2;
                if (tokens[mid].Start < from) lo = mid + 1; else hi = mid;
            }
            for (int i = lo; i < tokens.Count; i++)
                if (tokens[i].Kind == TokenKind.Punctuator && tokens[i].Value as string == punctuator) return tokens[i].Start;
            return -1;
        }
    }

    private sealed class Writer(string text, Parsed parsed, Shape shape, Dictionary<int, string> sites)
    {
        public readonly StringBuilder Output = new(text.Length + text.Length / 4);
        public readonly List<int> Origins = [];
        private readonly List<Level> _levels = [new(Frame.Block)];
        private int _indent, _comment;
        private bool _lineStart = true, _spaceNext, _afterBlock, _template;
        private string _prev = "";
        private TokenKind _prevKind = TokenKind.Unknown;
        private bool _prevOperand;
        private int _prevEnd;

        private Level Top => _levels[^1];

        public void Run(CancellationToken ct)
        {
            var tokens = parsed.Tokens;
            if (text.StartsWith("#!", StringComparison.Ordinal))
            {
                int end = text.IndexOfAny(['\r', '\n']);
                if (end < 0) end = text.Length;
                Write(text[..end], 0);
                NewLine();
                // The parser also reports the #! line as a comment.
                while (_comment < parsed.Comments.Count && parsed.Comments[_comment].Start < end) _comment++;
                _prevEnd = end;
            }
            for (int i = 0; i < tokens.Count; i++)
            {
                if ((i & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
                var t = tokens[i];
                if (t.Kind == TokenKind.EOF) break;
                if (_prevEnd > 0 && parsed.Inserted.Contains(_prevEnd) && !(_prevKind == TokenKind.Punctuator && _prev == ";")) Semicolon(t.Start, inserted: true);
                Comments(t.Start);
                string raw = text[t.Start..t.End];
                string next = i + 1 < tokens.Count && tokens[i + 1].Kind == TokenKind.Punctuator ? (string)tokens[i + 1].Value! : "";
                Token(t, raw, next, tokens, ref i);
                // An empty pair of braces consumes its closing token.
                var last = tokens[i];
                _prev = text[last.Start..last.End];
                _prevKind = last.Kind;
                _prevEnd = last.End;
            }
            if (_prevEnd > 0 && parsed.Inserted.Contains(_prevEnd) && _prev != ";") { Write(";", _prevEnd); }
            Comments(int.MaxValue);
            Trim();
            if (Output.Length > 0) Output.Append('\n');
        }

        private void Token(Token t, string raw, string next, List<Token> tokens, ref int i)
        {
            // Template text and the backquotes around it are written as they are.
            if (t.Kind == TokenKind.Template) { Write(raw, t.Start, space: false, exact: true); _prevOperand = false; return; }
            if (t.Kind != TokenKind.Punctuator)
            {
                string word = t.Kind == TokenKind.Identifier && sites.TryGetValue(t.Start, out var renamed) ? renamed : raw;
                if (t.Kind == TokenKind.Keyword) Keyword(raw, t.Start, next);
                else Write(word, t.Start, space: WordSpace());
                _prevOperand = t.Kind != TokenKind.Keyword || raw is "this" or "super" or "null" or "true" or "false";
                _spaceNext = false;
                return;
            }
            switch (raw)
            {
                case "`":
                    if (!_template) { Write(raw, t.Start, space: Space()); _template = true; }
                    else { Write(raw, t.Start, space: false); _template = false; _prevOperand = true; }
                    return;
                case "${":
                    Write(raw, t.Start, space: false, exact: true);
                    _levels.Add(new Level(Frame.Template));
                    _template = false;
                    return;
                case "{": Open(t, next, tokens, ref i); return;
                case "}": Close(t.Start, t.End); return;
                case "(":
                    Write(raw, t.Start, space: _prevKind == TokenKind.Keyword && _prev is not ("function" or "super" or "this" or "import") || _spaceNext || Binary());
                    _levels.Add(new Level(_prev == "for" ? Frame.ForHeader : Frame.Paren));
                    _spaceNext = false;
                    _prevOperand = false;
                    return;
                case ")" or "]":
                    if (_levels.Count > 1) _levels.RemoveAt(_levels.Count - 1);
                    Write(raw, t.Start, space: false);
                    _prevOperand = true;
                    return;
                case "[":
                    Write(raw, t.Start, space: !_prevOperand && (_spaceNext || Binary() || _prevKind == TokenKind.Keyword));
                    _levels.Add(new Level(Frame.Bracket));
                    _spaceNext = false;
                    _prevOperand = false;
                    return;
                case ";": Semicolon(t.Start, inserted: false); return;
                case ",":
                    Write(",", t.Start, space: false);
                    if (Top.Kind == Frame.Object) NewLine(); else _spaceNext = true;
                    _prevOperand = false;
                    return;
                case "?":
                    Top.Ternaries++;
                    Operator(raw, t.Start);
                    return;
                case ":":
                    if (Top.Ternaries > 0) { Top.Ternaries--; Operator(raw, t.Start); return; }
                    Write(":", t.Start, space: false);
                    if (Top.CaseColon && next == "{") { Top.CaseColon = false; _spaceNext = true; }
                    else if (Top.CaseColon)
                    {
                        Top.CaseColon = false;
                        Top.CaseIndented = true;
                        _indent++;
                        NewLine();
                    }
                    else _spaceNext = true;
                    _prevOperand = false;
                    return;
                case "." or "?.":
                    // A space keeps an integer literal from taking the dot as its decimal point.
                    Write(raw, t.Start, space: _prevKind == TokenKind.NumericLiteral && _prev.All(char.IsAsciiDigit));
                    _spaceNext = false;
                    _prevOperand = false;
                    return;
                case "...":
                    Write(raw, t.Start, space: Space());
                    _spaceNext = false;
                    _prevOperand = false;
                    return;
                case "++" or "--":
                    if (_prevOperand) { Write(raw, t.Start, space: false); return; }
                    Write(raw, t.Start, space: Space());
                    _spaceNext = false;
                    return;
                case "!" or "~":
                    Write(raw, t.Start, space: Space());
                    _spaceNext = false;
                    _prevOperand = false;
                    return;
                case "+" or "-" when !_prevOperand:
                    Write(raw, t.Start, space: Space());
                    _spaceNext = false;
                    return;
                default:
                    Operator(raw, t.Start);
                    return;
            }
        }

        private void Keyword(string raw, int start, string next)
        {
            if (_afterBlock && (raw is "else" or "catch" or "finally" || raw == "while" && shape.DoBodies.Contains(_prevEnd)))
            {
                _afterBlock = false;
                Write(raw, start, space: true);
                return;
            }
            if (raw is "case" or "default" && Top.Kind == Frame.Switch && _prev != "." && next != "." && !(raw == "default" && _prev == "export"))
            {
                if (Top.CaseIndented) { _indent--; Top.CaseIndented = false; }
                if (!_lineStart) NewLine();
                Write(raw, start, space: false);
                Top.CaseColon = true;
                return;
            }
            Write(raw, start, space: WordSpace());
        }

        private void Open(Token t, string next, List<Token> tokens, ref int i)
        {
            var kind = shape.Objects.Contains(t.Start) ? Frame.Object : shape.Switches.Contains(t.Start) ? Frame.Switch : shape.Blocks.Contains(t.Start) ? Frame.Block : Frame.Inline;
            bool space = !_lineStart && _prev is not ("(" or "[" or "${" or "...") && !(_prevKind == TokenKind.Punctuator && _prev is "!" or "~");
            Write("{", t.Start, space: space);
            if (next == "}" && !HasComment(tokens[i + 1].Start))
            {
                // An empty block or object stays on one line.
                i++;
                Write("}", tokens[i].Start, space: false);
                After(kind, tokens[i].End);
                return;
            }
            _levels.Add(new Level(kind));
            if (kind == Frame.Inline) _spaceNext = true;
            else
            {
                _indent++;
                NewLine();
            }
            _prevOperand = false;
        }

        private void Close(int start, int end)
        {
            var level = _levels.Count > 1 ? _levels[^1] : new Level(Frame.Inline);
            if (_levels.Count > 1) _levels.RemoveAt(_levels.Count - 1);
            if (level.Kind == Frame.Template)
            {
                Write("}", start, space: false);
                _template = true;
                return;
            }
            if (level.CaseIndented) _indent--;
            if (level.Kind == Frame.Inline) Write("}", start, space: true);
            else
            {
                _indent = Math.Max(0, _indent - 1);
                if (!_lineStart) NewLine();
                Write("}", start, space: false);
            }
            After(level.Kind, end);
        }

        // An object or inline brace ends an operand; a block ends a statement unless else, catch, a call or a comma follows.
        private void After(Frame kind, int end)
        {
            _prevEnd = end;
            if (kind is Frame.Block or Frame.Switch)
            {
                _afterBlock = true;
                _prevOperand = false;
            }
            else _prevOperand = true;
        }

        private void Semicolon(int start, bool inserted)
        {
            _afterBlock = false;
            Write(";", inserted ? _prevEnd : start, space: false);
            _prevOperand = false;
            if (Top.Kind == Frame.ForHeader) { _spaceNext = true; return; }
            NewLine();
            if (inserted) { _prev = ";"; _prevKind = TokenKind.Punctuator; }
        }

        private void Operator(string raw, int start)
        {
            Write(raw, start, space: true);
            _spaceNext = true;
            _prevOperand = false;
        }

        private bool Binary() => _prevKind == TokenKind.Punctuator && _prev is "=" or "==" or "===" or "!=" or "!==" or "<" or ">" or "<=" or ">=" or "&&" or "||" or "??" or "?" or ":" or "=>"
            or "+=" or "-=" or "*=" or "/=" or "%=" or "**=" or "&&=" or "||=" or "??=" or "|" or "&" or "^" or "<<" or ">>" or ">>>" or "*" or "/" or "%" or "**" or "|=" or "&=" or "^=" or "<<=" or ">>=" or ">>>=";

        private bool Space() => _spaceNext || Binary() || _prevKind == TokenKind.Keyword && _prev is not ("this" or "super" or "null" or "true" or "false");

        // Two words need a space; a word after a punctuator takes one only where the punctuator asked for it.
        private bool WordSpace() => _spaceNext || _prevKind is TokenKind.Identifier or TokenKind.Keyword or TokenKind.NumericLiteral or TokenKind.BigIntLiteral
            or TokenKind.BooleanLiteral or TokenKind.NullLiteral or TokenKind.StringLiteral or TokenKind.RegExpLiteral || _prevKind == TokenKind.Punctuator && (_prev is ")" or "]" or "}" || Binary());

        private bool HasComment(int before) => _comment < parsed.Comments.Count && parsed.Comments[_comment].Start < before;

        private void Comments(int before)
        {
            var comments = parsed.Comments;
            while (_comment < comments.Count && comments[_comment].Start < before)
            {
                var c = comments[_comment++];
                bool ownLine = _lineStart || text.AsSpan(_prevEnd, Math.Max(0, c.Start - _prevEnd)).IndexOfAny('\n', '\r') >= 0;
                if (ownLine && !_lineStart) NewLine();
                Write(text[c.Start..c.End], c.Start, space: !ownLine);
                if (c.Kind == CommentKind.Line || text.AsSpan(c.End, Math.Min(text.Length, before) - c.End).IndexOfAny('\n', '\r') >= 0) NewLine();
                _prevEnd = c.End;
            }
        }

        // exact: template text and ${ are written with nothing between them and what precedes.
        private void Write(string s, int origin, bool space = false, bool exact = false)
        {
            if (_afterBlock)
            {
                _afterBlock = false;
                if (!_lineStart && s is not ("," or ";" or ")" or "]" or "." or "?." or "(" or ":")) NewLine();
            }
            if (_lineStart)
            {
                for (int k = 0; k < _indent; k++) Output.Append(Indent);
                Origins.Add(origin);
                _lineStart = false;
            }
            else if (!exact && (space || Merges(s))) Output.Append(' ');
            Output.Append(s);
            // Lines inside a template or block comment start at the same origin, so Origins stays one entry per line.
            foreach (char c in s) if (c == '\n') Origins.Add(origin);
            _spaceNext = false;
        }

        // True when s written right after the output so far would join with it into another token.
        private bool Merges(string s)
        {
            if (Output.Length == 0 || s.Length == 0) return false;
            char a = Output[^1], b = s[0];
            if (Word(a) && Word(b)) return true;
            return a == b && a is '+' or '-' or '/' || a == '/' && b == '*' || a == '<' && b == '!' || a == '-' && b == '>';
        }

        private static bool Word(char c) => char.IsLetterOrDigit(c) || c is '_' or '$' or '\\' || c > 127;

        private void NewLine()
        {
            Trim();
            if (Output.Length > 0 && Output[^1] != '\n') Output.Append('\n');
            _lineStart = true;
            _spaceNext = false;
        }

        private void Trim()
        {
            int n = Output.Length;
            while (n > 0 && Output[n - 1] == ' ') n--;
            Output.Length = n;
        }
    }
}
