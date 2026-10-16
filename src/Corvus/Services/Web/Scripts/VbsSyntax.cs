using System.Globalization;
using System.Text;

namespace Corvus.Services.Web.Scripts;

internal enum VbTok { Number, String, Ident, Op, Newline, End }

internal readonly record struct VbToken(VbTok Kind, string Text, object? Value, int Start, int End)
{
    public bool Is(string text) => Kind is VbTok.Ident or VbTok.Op && Text.Equals(text, StringComparison.OrdinalIgnoreCase);
}

/// <summary>VBScript / VBA tokens: strings with doubled quotes, &amp;H / &amp;O numbers, comments and line continuations dropped, ':' as a line break.</summary>
internal static class VbLexer
{
    public static List<VbToken> Lex(string s, ScriptBudget budget)
    {
        var list = new List<VbToken>();
        int p = 0;
        while (p < s.Length)
        {
            if (!budget.Step()) break;
            char c = s[p];
            if (c is ' ' or '\t' or ' ' or '\f') { p++; continue; }
            if (c == '_' && Rest(s, p + 1)) { p = SkipLine(s, p) ; continue; } // continuation
            if (c is '\r' or '\n' or ':')
            {
                if (list.Count == 0 || list[^1].Kind != VbTok.Newline) list.Add(new VbToken(VbTok.Newline, "\n", null, p, p + 1));
                p++;
                continue;
            }
            if (c == '\'' || (c is 'r' or 'R') && At(s, p, "rem") && (p + 3 >= s.Length || !IsIdent(s[p + 3])) && (p == 0 || !IsIdent(s[p - 1])))
            {
                while (p < s.Length && s[p] is not ('\r' or '\n')) p++;
                continue;
            }
            int start = p;
            if (c is '"' or '“' or '”')
            {
                var sb = new StringBuilder();
                p++;
                while (p < s.Length)
                {
                    if (s[p] == '"' && p + 1 < s.Length && s[p + 1] == '"') { sb.Append('"'); p += 2; continue; }
                    if (s[p] is '"' or '“' or '”' or '\r' or '\n') break;
                    sb.Append(s[p++]);
                }
                if (p < s.Length && s[p] is not ('\r' or '\n')) p++;
                list.Add(new VbToken(VbTok.String, s[start..p], sb.ToString(), start, p));
                continue;
            }
            if (c == '&' && p + 1 < s.Length && s[p + 1] is 'h' or 'H' or 'o' or 'O' && p + 2 < s.Length && Uri.IsHexDigit(s[p + 2]))
            {
                bool hex = s[p + 1] is 'h' or 'H';
                p += 2;
                int q = p;
                while (p < s.Length && (hex ? Uri.IsHexDigit(s[p]) : s[p] is >= '0' and <= '7')) p++;
                long v = 0;
                try { v = Convert.ToInt64(s[q..p], hex ? 16 : 8); } catch (Exception ex) when (ex is FormatException or OverflowException or ArgumentException) { }
                if (p < s.Length && s[p] == '&') p++; // long suffix
                else if (hex && p - q <= 4 && v > 0x7FFF) v -= 0x10000; // &HFFFF is -1 as an Integer
                list.Add(new VbToken(VbTok.Number, s[start..p], v, start, p));
                continue;
            }
            if (char.IsDigit(c) || c == '.' && p + 1 < s.Length && char.IsDigit(s[p + 1]))
            {
                while (p < s.Length && (char.IsDigit(s[p]) || s[p] == '.')) p++;
                if (p < s.Length && s[p] is 'e' or 'E' && p + 1 < s.Length && (char.IsDigit(s[p + 1]) || s[p + 1] is '+' or '-')) { p += 2; while (p < s.Length && char.IsDigit(s[p])) p++; }
                var text = s[start..p];
                object v = long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var l) ? l
                    : double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : 0L;
                if (p < s.Length && s[p] is '&' or '%' or '#' or '!' or '@') p++;
                list.Add(new VbToken(VbTok.Number, s[start..p], v, start, p));
                continue;
            }
            if (IsIdent(c) || c == '[')
            {
                if (c == '[')
                {
                    int close = s.IndexOf(']', p);
                    if (close < 0) { p++; continue; }
                    list.Add(new VbToken(VbTok.Ident, s[(p + 1)..close], null, start, close + 1));
                    p = close + 1;
                    continue;
                }
                while (p < s.Length && IsIdent(s[p])) p++;
                if (p < s.Length && s[p] is '$' or '%' or '&' or '#' or '!' && (p + 1 >= s.Length || !IsIdent(s[p + 1]))) p++; // type suffix
                list.Add(new VbToken(VbTok.Ident, s[start..p].TrimEnd('$', '%', '&', '#', '!'), null, start, p));
                continue;
            }
            string op = p + 1 < s.Length && s.Substring(p, 2) is "<>" or "<=" or ">=" ? s.Substring(p, 2) : c.ToString();
            p += op.Length;
            list.Add(new VbToken(VbTok.Op, op, null, start, p));
        }
        list.Add(new VbToken(VbTok.Newline, "\n", null, s.Length, s.Length));
        list.Add(new VbToken(VbTok.End, "", null, s.Length, s.Length));
        return list;
    }

    private static bool IsIdent(char c) => char.IsLetterOrDigit(c) || c == '_';
    private static bool At(string s, int p, string word) => p + word.Length <= s.Length && string.Compare(s, p, word, 0, word.Length, StringComparison.OrdinalIgnoreCase) == 0;

    /// <summary>Whether only spaces follow up to the line end (a '_' line continuation).</summary>
    private static bool Rest(string s, int p)
    {
        while (p < s.Length && s[p] is ' ' or '\t') p++;
        return p >= s.Length || s[p] is '\r' or '\n';
    }

    private static int SkipLine(string s, int p)
    {
        while (p < s.Length && s[p] is not ('\r' or '\n')) p++;
        if (p < s.Length && s[p] == '\r') p++;
        if (p < s.Length && s[p] == '\n') p++;
        return p;
    }
}

// --- syntax tree ---

internal abstract class VbNode(int start, int end)
{
    public int Start { get; } = start;
    public int End { get; set; } = end;
}

internal abstract class VbExpr(int start, int end) : VbNode(start, end);

internal sealed class VbLiteral(int start, int end, object? value, bool raw) : VbExpr(start, end)
{
    public object? Value { get; } = value;
    public bool Raw { get; } = raw;
}

/// <summary>A name, a member (target.name) or a call / index (target(args)): resolved when evaluated.</summary>
internal sealed class VbName(int start, int end, VbExpr? target, string name) : VbExpr(start, end)
{
    public VbExpr? Target { get; } = target;
    public string Name { get; } = name;
}

internal sealed class VbCall(int start, int end, VbExpr callee, List<VbExpr?> args) : VbExpr(start, end)
{
    public VbExpr Callee { get; } = callee;
    public List<VbExpr?> Args { get; } = args;
}

internal sealed class VbBinary(int start, int end, string op, VbExpr left, VbExpr right) : VbExpr(start, end)
{
    public string Op { get; } = op;
    public VbExpr Left { get; } = left;
    public VbExpr Right { get; } = right;
}

internal sealed class VbUnary(int start, int end, string op, VbExpr operand) : VbExpr(start, end)
{
    public string Op { get; } = op;
    public VbExpr Operand { get; } = operand;
}

internal abstract class VbStatement(int start, int end) : VbNode(start, end);

internal sealed class VbAssign(int start, int end, VbExpr target, VbExpr value) : VbStatement(start, end)
{
    public VbExpr Target { get; } = target;
    public VbExpr Value { get; } = value;
}

/// <summary>A call statement: Foo a, b / Call Foo(a, b) / obj.Method a.</summary>
internal sealed class VbCallStatement(int start, int end, VbExpr callee, List<VbExpr?> args) : VbStatement(start, end)
{
    public VbExpr Callee { get; } = callee;
    public List<VbExpr?> Args { get; } = args;
}

internal sealed class VbIf(int start, int end, List<(VbExpr Condition, List<VbStatement> Body)> clauses, List<VbStatement>? otherwise) : VbStatement(start, end)
{
    public List<(VbExpr Condition, List<VbStatement> Body)> Clauses { get; } = clauses;
    public List<VbStatement>? Else { get; } = otherwise;
}

internal sealed class VbFor(int start, int end, string variable, VbExpr from, VbExpr to, VbExpr? step, List<VbStatement> body) : VbStatement(start, end)
{
    public string Variable { get; } = variable;
    public VbExpr From { get; } = from;
    public VbExpr To { get; } = to;
    public VbExpr? StepBy { get; } = step;
    public List<VbStatement> Body { get; } = body;
}

internal sealed class VbForEach(int start, int end, string variable, VbExpr collection, List<VbStatement> body) : VbStatement(start, end)
{
    public string Variable { get; } = variable;
    public VbExpr Collection { get; } = collection;
    public List<VbStatement> Body { get; } = body;
}

/// <param name="Kind">while (test first), until (test first), loop-while / loop-until (test after), or plain (no test).</param>
internal sealed class VbDo(int start, int end, string kind, VbExpr? condition, List<VbStatement> body) : VbStatement(start, end)
{
    public string Kind { get; } = kind;
    public VbExpr? Condition { get; } = condition;
    public List<VbStatement> Body { get; } = body;
}

internal sealed class VbProcedure(int start, int end, string name, bool function, List<string> parameters, List<VbStatement> body) : VbStatement(start, end)
{
    public string Name { get; } = name;
    public bool Function { get; } = function;
    public List<string> Parameters { get; } = parameters;
    public List<VbStatement> Body { get; } = body;
}

/// <summary>Dim name: a variable of the current procedure, Empty until set.</summary>
internal sealed class VbDim(int start, int end, string name) : VbStatement(start, end)
{
    public string Name { get; } = name;
}

internal sealed class VbExit(int start, int end, string what) : VbStatement(start, end)
{
    public string What { get; } = what;
}

internal sealed class VbBlock(int start, int end, List<VbStatement> body, List<VbExpr> exprs) : VbStatement(start, end)
{
    public List<VbStatement> Body { get; } = body;
    public List<VbExpr> Exprs { get; } = exprs;
}

/// <summary>A recursive-descent VBScript / VBA parser over tokens; an unreadable line is skipped.</summary>
internal sealed class VbParser
{
    private const int MaxDepth = 150;
    private readonly List<VbToken> _t;
    private readonly ScriptBudget _budget;
    private int _i, _depth;

    private VbParser(List<VbToken> tokens, ScriptBudget budget)
    {
        _t = tokens;
        _budget = budget;
    }

    public static List<VbStatement> Parse(string text, ScriptBudget budget) => new VbParser(VbLexer.Lex(text, budget), budget).Block(_ => false);

    private sealed class ParseError : Exception;

    private VbToken T => _t[Math.Min(_i, _t.Count - 1)];
    private VbToken Peek(int n) => _t[Math.Min(_i + n, _t.Count - 1)];
    private bool AtEnd => T.Kind == VbTok.End;
    private bool AtLineEnd => T.Kind is VbTok.Newline or VbTok.End;

    private void Expect(string text)
    {
        if (!T.Is(text)) throw new ParseError();
        _i++;
    }

    private void SkipLine()
    {
        while (!AtLineEnd) _i++;
        if (T.Kind == VbTok.Newline) _i++;
    }

    private void Enter()
    {
        if (++_depth > MaxDepth || !_budget.Step()) throw new ParseError();
    }

    /// <summary>Statements up to a line that <paramref name="stop"/> accepts (left unread).</summary>
    private List<VbStatement> Block(Func<VbToken, bool> stop)
    {
        var list = new List<VbStatement>();
        while (!AtEnd)
        {
            while (T.Kind == VbTok.Newline) _i++;
            if (AtEnd || stop(T)) break;
            int at = _i, depth = _depth;
            try
            {
                if (Statement() is { } st) list.Add(st);
            }
            catch (ParseError)
            {
                _depth = depth;
                if (_budget.Exhausted) break;
                _i = at;
                SkipLine();
            }
            if (_i == at) SkipLine();
        }
        return list;
    }

    private static bool EndOf(VbToken t, string word) => t.Is("end") || t.Is("next") || t.Is("loop") || t.Is("wend") || t.Is(word);

    private VbStatement? Statement()
    {
        var t = T;
        int start = t.Start;
        if (t.Kind != VbTok.Ident) { SkipLine(); return null; }
        var w = t.Text.ToLowerInvariant();
        switch (w)
        {
            case "dim" or "redim" or "public" or "private" or "static" or "global" when !(Peek(1).Is("sub") || Peek(1).Is("function") || Peek(1).Is("const") || Peek(1).Is("declare") || Peek(1).Is("property")):
            {
                _i++;
                if (T.Is("preserve")) _i++;
                var names = new List<VbStatement>();
                bool first = true;
                while (!AtLineEnd)
                {
                    if (first && T.Kind == VbTok.Ident) names.Add(new VbDim(T.Start, T.End, T.Text));
                    first = false;
                    _i++;
                    if (T.Is("(")) SkipParens();
                    if (T.Is(",")) { _i++; first = true; }
                }
                return new VbBlock(start, T.Start, names, []);
            }
            case "public" or "private" or "global" when Peek(1).Is("const"):
                _i++;
                return Statement();
            case "const":
            {
                _i++;
                var body = new List<VbStatement>();
                while (!AtLineEnd)
                {
                    var name = T;
                    _i++;
                    if (T.Is("as")) { _i += 2; }
                    Expect("=");
                    body.Add(new VbAssign(name.Start, 0, new VbName(name.Start, name.End, null, name.Text), Expr()) { End = _t[_i - 1].End });
                    if (T.Is(",")) _i++;
                }
                return new VbBlock(start, T.Start, body, []);
            }
            case "option" or "on" or "attribute" or "declare" or "goto" or "resume" or "erase" or "randomize" or "stop" or "debug" or "end" when !(w == "end" && Peek(1).Kind == VbTok.Ident && !AtLineEnd):
                SkipLine();
                return null;
            case "set" or "let":
                _i++;
                return Assignment(start);
            case "call":
            {
                _i++;
                var callee = Postfix(Primary());
                if (callee is VbCall call) return new VbCallStatement(start, call.End, call.Callee, call.Args);
                return new VbCallStatement(start, callee.End, callee, []);
            }
            case "if": return If();
            case "for": return Peek(1).Is("each") ? ForEach() : For();
            case "do": return Do();
            case "while":
            {
                _i++;
                var cond = Expr();
                var body = Block(x => x.Is("wend"));
                if (T.Is("wend")) _i++;
                return new VbDo(start, T.Start, "while", cond, body);
            }
            case "sub" or "function" or "property": return Procedure(start);
            case "public" or "private" or "friend" or "static" or "global":
                _i++;
                if (T.Is("default")) _i++;
                return Procedure(start);
            case "exit":
                _i++;
                var what = T.Text.ToLowerInvariant();
                _i++;
                return new VbExit(start, T.Start, what);
            case "select":
            {
                // Select Case: read the cases as blocks of their own, followed in the fold pass only
                _i++;
                if (T.Is("case")) _i++;
                var subject = Expr();
                var exprs = new List<VbExpr> { subject };
                var body = new List<VbStatement>();
                while (!AtEnd)
                {
                    while (T.Kind == VbTok.Newline) _i++;
                    if (T.Is("end")) { _i++; if (T.Is("select")) _i++; break; }
                    if (T.Is("case"))
                    {
                        _i++;
                        if (T.Is("else")) _i++;
                        else
                            while (!AtLineEnd)
                            {
                                if (T.Is("is")) { _i += 2; }
                                exprs.Add(Expr());
                                if (T.Is("to")) { _i++; exprs.Add(Expr()); }
                                if (T.Is(",")) _i++;
                                else break;
                            }
                        body.AddRange(Block(x => x.Is("case") || x.Is("end") && Peek(1).Is("select")));
                        continue;
                    }
                    break;
                }
                return new VbBlock(start, T.Start, body, exprs) { };
            }
            case "with":
            {
                _i++;
                var subject = Expr();
                var body = Block(x => x.Is("end") && Peek(1).Is("with"));
                if (T.Is("end")) _i += 2;
                return new VbBlock(start, T.Start, body, [subject]);
            }
            case "class":
            {
                _i++;
                var body = Block(x => x.Is("end") && Peek(1).Is("class"));
                if (T.Is("end")) _i += 2;
                return new VbBlock(start, T.Start, body, []);
            }
        }
        return Assignment(start);
    }

    private void SkipParens()
    {
        int nest = 0;
        do
        {
            if (T.Is("(")) nest++;
            else if (T.Is(")")) nest--;
            _i++;
        } while (nest > 0 && !AtLineEnd);
    }

    private VbStatement Assignment(int start)
    {
        var target = Postfix(Primary());
        if (T.Is("="))
        {
            _i++;
            var value = Expr();
            return new VbAssign(start, value.End, target, value);
        }
        // a call statement: Foo a, b  or  Foo(a)  or  obj.Method a
        if (AtLineEnd || T.Is("else"))
            return target is VbCall c ? new VbCallStatement(start, c.End, c.Callee, c.Args) : new VbCallStatement(start, target.End, target, []);
        var args = new List<VbExpr?>();
        var callee = target;
        if (target is VbCall paren && paren.Args.Count == 1 && _t[_i - 1].Is(")"))
        {
            // Foo (a), b: the parenthesized first argument
            callee = paren.Callee;
            args.Add(paren.Args[0]);
            if (T.Is(",")) _i++;
        }
        while (!AtLineEnd && !T.Is("else"))
        {
            if (T.Is(",")) { args.Add(null); _i++; continue; }
            args.Add(Expr());
            if (T.Is(",")) _i++;
            else break;
        }
        return new VbCallStatement(start, _t[_i - 1].End, callee, args);
    }

    private VbStatement If()
    {
        int start = T.Start;
        _i++;
        var cond = Expr();
        Expect("then");
        var clauses = new List<(VbExpr, List<VbStatement>)>();
        if (!AtLineEnd)
        {
            // single-line If: statements separated by ':' were turned into line breaks, so read one statement each side
            var then = Statement() is { } s1 ? new List<VbStatement> { s1 } : [];
            clauses.Add((cond, then));
            List<VbStatement>? other = null;
            if (T.Is("else")) { _i++; other = Statement() is { } s2 ? [s2] : []; }
            if (T.Is("end") && Peek(1).Is("if")) _i += 2;
            return new VbIf(start, T.Start, clauses, other);
        }
        var body = Block(x => x.Is("elseif") || x.Is("else") || x.Is("end") && Peek(1).Is("if"));
        clauses.Add((cond, body));
        List<VbStatement>? otherwise = null;
        while (!AtEnd)
        {
            if (T.Is("elseif"))
            {
                _i++;
                var c = Expr();
                Expect("then");
                clauses.Add((c, Block(x => x.Is("elseif") || x.Is("else") || x.Is("end") && Peek(1).Is("if"))));
                continue;
            }
            if (T.Is("else"))
            {
                _i++;
                if (T.Is("if")) { _i++; var c = Expr(); Expect("then"); clauses.Add((c, Block(x => x.Is("elseif") || x.Is("else") || x.Is("end") && Peek(1).Is("if")))); continue; }
                otherwise = Block(x => x.Is("end") && Peek(1).Is("if"));
                continue;
            }
            if (T.Is("end")) { _i += 2; break; }
            break;
        }
        return new VbIf(start, T.Start, clauses, otherwise);
    }

    private VbStatement For()
    {
        int start = T.Start;
        _i++;
        var variable = T.Text;
        _i++;
        Expect("=");
        var from = Expr();
        Expect("to");
        var to = Expr();
        VbExpr? step = null;
        if (T.Is("step")) { _i++; step = Expr(); }
        var body = Block(x => x.Is("next"));
        if (T.Is("next")) { _i++; while (!AtLineEnd) _i++; }
        return new VbFor(start, T.Start, variable, from, to, step, body);
    }

    private VbStatement ForEach()
    {
        int start = T.Start;
        _i += 2;
        var variable = T.Text;
        _i++;
        Expect("in");
        var coll = Expr();
        var body = Block(x => x.Is("next"));
        if (T.Is("next")) { _i++; while (!AtLineEnd) _i++; }
        return new VbForEach(start, T.Start, variable, coll, body);
    }

    private VbStatement Do()
    {
        int start = T.Start;
        _i++;
        string kind = "plain";
        VbExpr? cond = null;
        if (T.Is("while") || T.Is("until")) { kind = T.Text.ToLowerInvariant(); _i++; cond = Expr(); }
        var body = Block(x => x.Is("loop"));
        if (T.Is("loop"))
        {
            _i++;
            if (cond == null && (T.Is("while") || T.Is("until"))) { kind = "loop-" + T.Text.ToLowerInvariant(); _i++; cond = Expr(); }
        }
        return new VbDo(start, T.Start, kind, cond, body);
    }

    private VbStatement Procedure(int start)
    {
        var kind = T.Text.ToLowerInvariant();
        _i++;
        if (kind == "property") _i++; // Get / Let / Set
        var name = T.Text;
        _i++;
        var parameters = new List<string>();
        if (T.Is("("))
        {
            _i++;
            while (!AtLineEnd && !T.Is(")"))
            {
                if (T.Is("byval") || T.Is("byref") || T.Is("optional") || T.Is("paramarray")) { _i++; continue; }
                if (T.Kind == VbTok.Ident)
                {
                    parameters.Add(T.Text);
                    _i++;
                    if (T.Is("(")) SkipParens();
                    if (T.Is("as")) _i += 2;
                    if (T.Is("=")) { _i++; Expr(); }
                }
                if (T.Is(",")) _i++;
                else if (!T.Is(")")) _i++;
            }
            if (T.Is(")")) _i++;
        }
        while (!AtLineEnd) _i++;
        var body = Block(x => x.Is("end") && (Peek(1).Is("sub") || Peek(1).Is("function") || Peek(1).Is("property")));
        if (T.Is("end")) _i += 2;
        return new VbProcedure(start, T.Start, name, kind is "function" or "property", parameters, body);
    }

    // --- expressions ---

    private static readonly string[][] Levels =
    [
        ["imp"], ["eqv"], ["xor"], ["or"], ["and"], [], // Not sits between And and the comparisons
        ["=", "<>", "<", ">", "<=", ">=", "is", "like"], ["&"], ["+", "-"], ["mod"], ["\\"], ["*", "/"],
    ];

    public VbExpr Expr() => Binary(0);

    private VbExpr Binary(int level)
    {
        Enter();
        try
        {
            if (level >= Levels.Length) return Unary();
            if (Levels[level].Length == 0)
            {
                if (T.Is("not"))
                {
                    int s = T.Start;
                    _i++;
                    var operand = Binary(level);
                    return new VbUnary(s, operand.End, "not", operand);
                }
                return Binary(level + 1);
            }
            var left = Binary(level + 1);
            while (Levels[level].Any(op => T.Is(op)))
            {
                var op = T.Text.ToLowerInvariant();
                _i++;
                var right = Binary(level + 1);
                left = new VbBinary(left.Start, right.End, op, left, right);
            }
            return left;
        }
        finally { _depth--; }
    }

    private VbExpr Unary()
    {
        if (T.Is("-") || T.Is("+"))
        {
            int s = T.Start;
            var op = T.Text;
            _i++;
            Enter();
            try
            {
                var operand = Unary();
                return new VbUnary(s, operand.End, op, operand);
            }
            finally { _depth--; }
        }
        var e = Postfix(Primary());
        if (T.Is("^"))
        {
            _i++;
            var r = Unary();
            return new VbBinary(e.Start, r.End, "^", e, r);
        }
        return e;
    }

    private VbExpr Primary()
    {
        Enter();
        try
        {
            var t = T;
            switch (t.Kind)
            {
                case VbTok.Number: _i++; return new VbLiteral(t.Start, t.End, t.Value, raw: true);
                case VbTok.String: _i++; return new VbLiteral(t.Start, t.End, t.Value, raw: true);
                case VbTok.Ident:
                    _i++;
                    if (t.Is("new")) { var cls = T; _i++; return new VbCall(t.Start, cls.End, new VbName(t.Start, t.End, null, "new"), [new VbLiteral(cls.Start, cls.End, cls.Text, false)]); }
                    if (t.Is("nothing") || t.Is("null") || t.Is("empty")) return new VbLiteral(t.Start, t.End, null, raw: true);
                    if (t.Is("true")) return new VbLiteral(t.Start, t.End, true, raw: true);
                    if (t.Is("false")) return new VbLiteral(t.Start, t.End, false, raw: true);
                    return new VbName(t.Start, t.End, null, t.Text);
                case VbTok.Op when t.Text == "(":
                {
                    _i++;
                    var inner = Expr();
                    if (!T.Is(")")) throw new ParseError();
                    _i++;
                    return new VbCall(t.Start, _t[_i - 1].End, new VbName(t.Start, t.Start, null, "("), [inner]);
                }
                case VbTok.Op when t.Text == ".": // inside With: .Member
                {
                    _i++;
                    var name = T;
                    _i++;
                    return new VbName(t.Start, name.End, new VbName(t.Start, t.Start, null, "with"), name.Text);
                }
            }
            throw new ParseError();
        }
        finally { _depth--; }
    }

    private VbExpr Postfix(VbExpr e)
    {
        while (true)
        {
            if (T.Is("(") && _t[_i - 1].End == T.Start || T.Is("(") && e is VbName)
            {
                _i++;
                var args = new List<VbExpr?>();
                while (!AtLineEnd && !T.Is(")"))
                {
                    if (T.Is(",")) { args.Add(null); _i++; continue; }
                    args.Add(Expr());
                    if (T.Is(",")) _i++;
                    else if (!T.Is(")")) throw new ParseError();
                }
                if (!T.Is(")")) throw new ParseError();
                _i++;
                e = new VbCall(e.Start, _t[_i - 1].End, e, args);
                continue;
            }
            if (T.Is(".") || T.Is("!"))
            {
                _i++;
                var name = T;
                if (name.Kind != VbTok.Ident) throw new ParseError();
                _i++;
                e = new VbName(e.Start, name.End, e, name.Text);
                continue;
            }
            return e;
        }
    }
}
