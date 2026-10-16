using System.Text;

namespace Corvus.Services.Web.Scripts;

// The PowerShell syntax tree the reader folds: expressions, commands, pipelines and the statements a dropper uses.

internal abstract class PsNode(int start, int end)
{
    public int Start { get; } = start;
    public int End { get; set; } = end;
}

internal abstract class PsExpr(int start, int end) : PsNode(start, end);

/// <param name="Raw">True for a number or a single-quoted string written as is: folding it changes nothing.</param>
internal sealed class PsLiteral(int start, int end, object? value, bool raw) : PsExpr(start, end)
{
    public object? Value { get; } = value;
    public bool Raw { get; } = raw;
}

/// <summary>A double-quoted string: text parts and the variables and subexpressions it expands.</summary>
internal sealed class PsExpandable(int start, int end, List<object> parts) : PsExpr(start, end)
{
    public List<object> Parts { get; } = parts; // string or PsExpr
}

internal sealed class PsVariable(int start, int end, string name, bool braced) : PsExpr(start, end)
{
    public string Name { get; } = name;
    public bool Braced { get; } = braced;
}

internal sealed class PsTypeLiteral(int start, int end, string name) : PsExpr(start, end)
{
    public string Name { get; } = name;
}

internal sealed class PsCast(int start, int end, string type, PsExpr operand) : PsExpr(start, end)
{
    public string Type { get; } = type;
    public PsExpr Operand { get; } = operand;
}

internal sealed class PsBinary(int start, int end, string op, PsExpr left, PsExpr right) : PsExpr(start, end)
{
    public string Op { get; } = op;
    public PsExpr Left { get; } = left;
    public PsExpr Right { get; } = right;
}

internal sealed class PsUnary(int start, int end, string op, PsExpr operand, bool postfix = false) : PsExpr(start, end)
{
    public string Op { get; } = op;
    public PsExpr Operand { get; } = operand;
    public bool Postfix { get; } = postfix;
}

/// <summary>A comma list: an array.</summary>
internal sealed class PsArrayList(int start, int end, List<PsExpr> items) : PsExpr(start, end)
{
    public List<PsExpr> Items { get; } = items;
}

/// <summary>( pipeline ), $( statements ) or @( statements ).</summary>
internal sealed class PsGroup(int start, int end, char kind, List<PsStatement> body) : PsExpr(start, end)
{
    public char Kind { get; } = kind; // '(' '$' '@'
    public List<PsStatement> Body { get; } = body;
}

internal sealed class PsHash(int start, int end, List<(PsExpr Key, PsStatement Value)> entries) : PsExpr(start, end)
{
    public List<(PsExpr Key, PsStatement Value)> Entries { get; } = entries;
}

internal sealed class PsScriptBlockExpr(int start, int end, List<PsStatement> body, List<PsParam>? parameters) : PsExpr(start, end)
{
    public List<PsStatement> Body { get; } = body;
    public List<PsParam>? Parameters { get; } = parameters;
}

internal sealed class PsIndex(int start, int end, PsExpr target, PsExpr index) : PsExpr(start, end)
{
    public PsExpr Target { get; } = target;
    public PsExpr Index { get; } = index;
}

/// <summary>target.name or [type]::name; <see cref="Name"/> is a literal or a computed expression.</summary>
internal sealed class PsMember(int start, int end, PsExpr target, PsExpr name, bool isStatic, int nameStart) : PsExpr(start, end)
{
    public PsExpr Target { get; } = target;
    public PsExpr Name { get; } = name;
    public bool Static { get; } = isStatic;
    /// <summary>Where the member name starts (after the dot).</summary>
    public int NameStart { get; } = nameStart;
}

internal sealed class PsInvoke(int start, int end, PsMember member, List<PsExpr> args) : PsExpr(start, end)
{
    public PsMember Member { get; } = member;
    public List<PsExpr> Args { get; } = args;
}

internal sealed record PsParam(string Name, PsExpr? Default);

internal abstract class PsStatement(int start, int end) : PsNode(start, end);

/// <summary>A pipeline of elements; each is an expression or a command.</summary>
internal sealed class PsPipeline(int start, int end, List<PsNode> elements) : PsStatement(start, end)
{
    public List<PsNode> Elements { get; } = elements;
}

internal sealed record PsArgument(string? Parameter, PsExpr? Value, int Start, int End);

/// <summary>A command: a bareword name or an invocation (&amp; or .) of an expression, with its arguments.</summary>
internal sealed class PsCommand(int start, int end, PsExpr name, char invocation, List<PsArgument> args) : PsNode(start, end)
{
    public PsExpr Name { get; } = name;
    public char Invocation { get; } = invocation; // '\0', '&' or '.'
    public List<PsArgument> Args { get; } = args;
}

internal sealed class PsAssignment(int start, int end, PsExpr target, string op, PsStatement value) : PsStatement(start, end)
{
    public PsExpr Target { get; } = target;
    public string Op { get; } = op;
    public PsStatement Value { get; } = value;
}

internal sealed class PsIf(int start, int end, List<(PsStatement Condition, List<PsStatement> Body)> clauses, List<PsStatement>? otherwise) : PsStatement(start, end)
{
    public List<(PsStatement Condition, List<PsStatement> Body)> Clauses { get; } = clauses;
    public List<PsStatement>? Else { get; } = otherwise;
}

internal sealed class PsLoop(int start, int end, string kind, PsStatement? init, PsStatement? condition, PsStatement? iterator, List<PsStatement> body, string? variable = null)
    : PsStatement(start, end)
{
    public string Kind { get; } = kind; // foreach, for, while, do-while, do-until
    public PsStatement? Init { get; } = init;
    public PsStatement? Condition { get; } = condition; // foreach: the collection
    public PsStatement? Iterator { get; } = iterator;
    public List<PsStatement> Body { get; } = body;
    public string? Variable { get; } = variable;
}

internal sealed class PsFunction(int start, int end, string name, List<PsParam> parameters, List<PsStatement> body) : PsStatement(start, end)
{
    public string Name { get; } = name;
    public List<PsParam> Parameters { get; } = parameters;
    public List<PsStatement> Body { get; } = body;
}

internal sealed class PsFlow(int start, int end, string keyword, PsStatement? value) : PsStatement(start, end)
{
    public string Keyword { get; } = keyword; // return, break, continue, throw, exit
    public PsStatement? Value { get; } = value;
}

/// <summary>Statements read but not followed (try/catch bodies are read as blocks, switch and others as their blocks).</summary>
internal sealed class PsBlock(int start, int end, List<PsStatement> body) : PsStatement(start, end)
{
    public List<PsStatement> Body { get; } = body;
}

/// <summary>
/// A recursive-descent PowerShell parser over the text, scanning in expression or command mode as the language does.
/// It never throws on bad input: an unreadable statement is skipped to its end.
/// </summary>
internal sealed class PsParser
{
    private const int MaxDepth = 150;
    private readonly string _s;
    private int _p, _depth;
    private bool _noComma; // method arguments: a comma separates arguments
    private readonly ScriptBudget _budget;

    private PsParser(string text, ScriptBudget budget)
    {
        _s = text;
        _budget = budget;
    }

    public static List<PsStatement> Parse(string text, ScriptBudget budget)
    {
        var parser = new PsParser(text, budget);
        return parser.Statements('\0');
    }

    private sealed class ParseError : Exception;

    private char C => _p < _s.Length ? _s[_p] : '\0';
    private char At(int i) => _p + i < _s.Length ? _s[_p + i] : '\0';
    private bool End => _p >= _s.Length;

    private static bool IsDash(char c) => c is '-' or '–' or '—' or '―';
    private static bool IsSingleQuote(char c) => c is '\'' or '‘' or '’' or '‚' or '‛';
    private static bool IsDoubleQuote(char c) => c is '"' or '“' or '”' or '„';
    private static bool IsIdent(char c) => char.IsLetterOrDigit(c) || c == '_';

    /// <summary>Skips spaces, comments and line continuations; newlines too when <paramref name="newlines"/>.</summary>
    private void Skip(bool newlines)
    {
        while (!End)
        {
            char c = C;
            if (c is ' ' or '\t' or '\f' or ' ' or '\v' || newlines && c is '\r' or '\n') _p++;
            else if (c == '`' && At(1) is '\r' or '\n') { _p += At(1) == '\r' && At(2) == '\n' ? 3 : 2; }
            else if (c == '#') { while (!End && C is not ('\r' or '\n')) _p++; }
            else if (c == '<' && At(1) == '#')
            {
                int close = _s.IndexOf("#>", _p + 2, StringComparison.Ordinal);
                _p = close < 0 ? _s.Length : close + 2;
            }
            else break;
        }
    }

    private bool AtTerminator => End || C is ';' or '\r' or '\n' or '}' or ')' or '|';

    /// <summary>Guards recursion: callers pair it with <see cref="Leave"/> in a finally.</summary>
    private void Enter()
    {
        _depth++;
        if (_depth > MaxDepth || !_budget.Step()) throw new ParseError();
    }

    private void Leave() => _depth--;

    private List<PsStatement> Statements(char close)
    {
        var list = new List<PsStatement>();
        while (true)
        {
            Skip(true);
            while (C == ';') { _p++; Skip(true); }
            if (End || close != '\0' && C == close) break;
            if (close == '\0' && C is ')' or '}') { _p++; continue; } // stray closer at the top
            int start = _p;
            try
            {
                var st = Statement();
                if (st != null) list.Add(st);
            }
            catch (ParseError)
            {
                if (_budget.Exhausted || _depth >= MaxDepth) break;
            }
            if (_p == start) SkipStatement();
        }
        return list;
    }

    /// <summary>Moves past the current line, keeping brackets balanced.</summary>
    private void SkipStatement()
    {
        int nest = 0;
        while (!End)
        {
            char c = C;
            if (c is '(' or '{' or '[') nest++;
            else if (c is ')' or '}' or ']') { if (nest == 0) { _p++; return; } nest--; }
            else if (c is '\n' or ';' && nest == 0) { _p++; return; }
            else if (IsSingleQuote(c) || IsDoubleQuote(c)) { try { StringLiteral(); continue; } catch (ParseError) { } }
            _p++;
        }
    }

    private string? PeekKeyword()
    {
        int q = _p;
        while (q < _s.Length && char.IsLetter(_s[q])) q++;
        if (q == _p || q < _s.Length && (IsIdent(_s[q]) || IsDash(_s[q]) || _s[q] is '.' or '\\' or ':')) return null;
        var word = _s[_p..q].ToLowerInvariant();
        return word is "if" or "foreach" or "for" or "while" or "do" or "function" or "filter" or "return" or "break" or "continue" or "throw" or "exit"
            or "try" or "catch" or "finally" or "trap" or "param" or "switch" or "begin" or "process" or "end" or "dynamicparam" or "data" or "class" or "using"
            ? word : null;
    }

    private PsStatement? Statement()
    {
        int start = _p;
        switch (PeekKeyword())
        {
            case "if": return If();
            case "foreach": return ForEach();
            case "for": return For();
            case "while": return While();
            case "do": return Do();
            case "function" or "filter": return Function();
            case "return" or "throw" or "exit":
            {
                var kw = Word();
                Skip(false);
                var value = AtTerminator ? null : Pipeline();
                return new PsFlow(start, _p, kw.ToLowerInvariant(), value);
            }
            case "break" or "continue":
            {
                var kw = Word();
                Skip(false);
                if (!AtTerminator) Word();
                return new PsFlow(start, _p, kw.ToLowerInvariant(), null);
            }
            case "try" or "finally" or "begin" or "process" or "end" or "dynamicparam":
            {
                Word();
                Skip(true);
                return C == '{' ? new PsBlock(start, _p, Block()) : null;
            }
            case "catch" or "trap":
            {
                Word();
                Skip(true);
                while (C == '[') { TypeName(); Skip(true); if (C == ',') { _p++; Skip(true); } }
                return C == '{' ? new PsBlock(start, _p, Block()) : null;
            }
            case "param":
            {
                Word();
                Skip(true);
                if (C == '(') Params();
                return null;
            }
            case "switch":
            {
                Word();
                Skip(false);
                while (C == '-' ) { _p++; Word(); Skip(false); }
                if (C == '(') { _p++; Statements(')'); if (C == ')') _p++; }
                Skip(true);
                if (C == '{') Block();
                return null;
            }
            case "class" or "data" or "using":
                SkipStatement();
                return null;
        }
        return Pipeline();
    }

    private List<PsStatement> Block()
    {
        if (C != '{') throw new ParseError();
        _p++;
        var body = Statements('}');
        if (C == '}') _p++;
        return body;
    }

    private PsStatement Condition()
    {
        Skip(true);
        if (C != '(') throw new ParseError();
        _p++;
        Skip(true);
        var cond = Pipeline();
        Skip(true);
        if (C == ')') _p++;
        return cond;
    }

    private PsStatement If()
    {
        int start = _p;
        Word();
        var clauses = new List<(PsStatement, List<PsStatement>)>();
        var cond = Condition();
        Skip(true);
        clauses.Add((cond, Block()));
        List<PsStatement>? otherwise = null;
        while (true)
        {
            int save = _p;
            Skip(true);
            var kw = PeekKeyword() == null && char.IsLetter(C) ? Peek() : null;
            if (kw == "elseif")
            {
                Word();
                var c = Condition();
                Skip(true);
                clauses.Add((c, Block()));
            }
            else if (kw == "else")
            {
                Word();
                Skip(true);
                otherwise = Block();
                break;
            }
            else { _p = save; break; }
        }
        return new PsIf(start, _p, clauses, otherwise);
    }

    private string Peek()
    {
        int q = _p;
        while (q < _s.Length && char.IsLetter(_s[q])) q++;
        return _s[_p..q].ToLowerInvariant();
    }

    private PsStatement ForEach()
    {
        int start = _p;
        Word();
        Skip(true);
        if (C != '(') throw new ParseError();
        _p++;
        Skip(true);
        if (C != '$') throw new ParseError();
        var variable = (PsVariable)Variable();
        Skip(true);
        if (!Peek().Equals("in", StringComparison.Ordinal)) throw new ParseError();
        Word();
        Skip(true);
        var collection = Pipeline();
        Skip(true);
        if (C == ')') _p++;
        Skip(true);
        return new PsLoop(start, _p, "foreach", null, collection, null, Block(), variable.Name);
    }

    private PsStatement For()
    {
        int start = _p;
        Word();
        Skip(true);
        if (C != '(') throw new ParseError();
        _p++;
        PsStatement? Part(char end)
        {
            Skip(true);
            if (C == end) { _p++; return null; }
            var st = Pipeline();
            Skip(true);
            if (C == end) _p++;
            return st;
        }
        var init = Part(';');
        var cond = Part(';');
        var iter = Part(')');
        Skip(true);
        return new PsLoop(start, _p, "for", init, cond, iter, Block());
    }

    private PsStatement While()
    {
        int start = _p;
        Word();
        var cond = Condition();
        Skip(true);
        return new PsLoop(start, _p, "while", null, cond, null, Block());
    }

    private PsStatement Do()
    {
        int start = _p;
        Word();
        Skip(true);
        var body = Block();
        Skip(true);
        var kw = Peek();
        if (kw is not ("while" or "until")) throw new ParseError();
        Word();
        var cond = Condition();
        return new PsLoop(start, _p, "do-" + kw, null, cond, null, body);
    }

    private PsStatement Function()
    {
        int start = _p;
        Word();
        Skip(false);
        int nameStart = _p;
        while (!End && !char.IsWhiteSpace(C) && C is not ('{' or '(')) _p++;
        var name = _s[nameStart.._p].Replace("`", "");
        Skip(true);
        var parameters = new List<PsParam>();
        if (C == '(') parameters = Params();
        Skip(true);
        if (C != '{') throw new ParseError();
        _p++;
        Skip(true);
        if (PeekKeyword() == "param")
        {
            Word();
            Skip(true);
            if (C == '(') parameters = Params();
        }
        var body = Statements('}');
        if (C == '}') _p++;
        return new PsFunction(start, _p, name, parameters, body);
    }

    private List<PsParam> Params()
    {
        var list = new List<PsParam>();
        _p++; // (
        while (true)
        {
            Skip(true);
            if (End) break;
            if (C == ')') { _p++; break; }
            if (C == ',') { _p++; continue; }
            if (C == '[') { TypeName(); continue; }
            if (C == '$')
            {
                var v = (PsVariable)Variable();
                Skip(true);
                PsExpr? def = null;
                if (C == '=') { _p++; Skip(true); def = Expression(); }
                list.Add(new PsParam(v.Name, def));
                continue;
            }
            _p++;
        }
        return list;
    }

    private string Word()
    {
        int q = _p;
        while (!End && (IsIdent(C) || C == '-')) _p++;
        return _s[q.._p];
    }

    // --- pipelines and commands ---

    private PsStatement Pipeline()
    {
        Enter();
        try { return PipelineCore(); }
        finally { Leave(); }
    }

    private PsStatement PipelineCore()
    {
        int start = _p;
        // assignment: an lvalue expression followed by = or op=
        if (C == '$' || C == '[')
        {
            int save = _p;
            try
            {
                var target = Postfix(Primary());
                Skip(false);
                string? op = C == '=' && At(1) != '=' ? "=" : C is '+' or '-' or '*' or '/' or '%' && At(1) == '=' ? C + "=" : null;
                if (op != null && target is PsVariable or PsIndex or PsMember or PsCast)
                {
                    _p += op.Length;
                    Skip(true);
                    var value = Pipeline();
                    return new PsAssignment(start, _p, target, op, value);
                }
            }
            catch (ParseError) { }
            _p = save;
        }
        var elements = new List<PsNode>();
        while (true)
        {
            Skip(false);
            elements.Add(Element());
            Skip(false);
            // redirections are dropped
            while (C == '>' || C is '2' or '*' && At(1) == '>')
            {
                while (C is '>' or '2' or '*' or '&' or '1') _p++;
                Skip(false);
                if (!AtTerminator) Argument();
                Skip(false);
            }
            if (C == '|' && At(1) != '|') { _p++; Skip(true); continue; }
            if ((C == '&' && At(1) == '&' || C == '|' && At(1) == '|')) { _p += 2; Skip(true); continue; }
            break;
        }
        return new PsPipeline(start, elements[^1].End, elements);
    }

    private bool IsCommandStart()
    {
        char c = C;
        if (c is '&' && At(1) != '&') return true;
        if (c == '.' && (At(1) is ' ' or '\t' or '(' or '$' or '{' or '"' or '\'' || IsSingleQuote(At(1)) || IsDoubleQuote(At(1)))) return true;
        if (c is '%' or '?' && At(1) is ' ' or '\t' or '{') return true;
        if (char.IsDigit(c)) return false;
        if (IsDash(c) && (char.IsDigit(At(1)) || At(1) is '(' or '$' or '[' or '-' or '.')) return false;
        if (IsDash(c) && UnaryOperatorAhead()) return false;
        return char.IsLetter(c) || c is '_' or '`' or '\\' or '~' || c == '.' && At(1) is '\\' or '/' || IsDash(c) && char.IsLetter(At(1));
    }

    /// <summary>-join, -split, -not or -bnot followed by an operand: an expression, not a command.</summary>
    private bool UnaryOperatorAhead()
    {
        int q = _p + 1;
        while (q < _s.Length && char.IsLetter(_s[q])) q++;
        var word = _s[(_p + 1)..q].ToLowerInvariant();
        return word is "join" or "split" or "not" or "bnot";
    }

    private PsNode Element()
    {
        if (!IsCommandStart()) return Expression();
        int start = _p;
        char invocation = '\0';
        PsExpr name;
        if (C is '&' or '.' && !(C == '.' && At(1) is '\\' or '/'))
        {
            invocation = C;
            _p++;
            Skip(false);
            name = IsBareword() ? Bareword() : Postfix(Primary());
        }
        else name = Bareword();
        var args = new List<PsArgument>();
        int end = _p;
        while (true)
        {
            Skip(false);
            if (AtTerminator || C == '&' && At(1) == '&' || C == '>' || C is '2' or '*' && At(1) == '>') break;
            int before = _p;
            args.Add(Argument());
            if (_p == before) break;
            end = _p;
        }
        return new PsCommand(start, end, name, invocation, args);
    }

    private bool IsBareword() => !End && C is not ('$' or '(' or '@' or '{' or '[') && !IsSingleQuote(C) && !IsDoubleQuote(C) && !char.IsDigit(C);

    /// <summary>A generic token: up to whitespace or a token end; backtick escapes taken literally.</summary>
    private PsLiteral Bareword()
    {
        int start = _p;
        var sb = new StringBuilder();
        while (!End)
        {
            char c = C;
            if (char.IsWhiteSpace(c) || c is ';' or '|' or '(' or ')' or '{' or '}' or ',' || c == '&' && At(1) == '&') break;
            if (c == '`')
            {
                if (At(1) is '\r' or '\n' or '\0') break;
                sb.Append(At(1));
                _p += 2;
                continue;
            }
            if (IsSingleQuote(c) || IsDoubleQuote(c))
            {
                if (StringLiteral() is PsLiteral { Value: string part }) sb.Append(part);
                continue;
            }
            sb.Append(c);
            _p++;
        }
        if (_p == start) throw new ParseError();
        return new PsLiteral(start, _p, sb.ToString(), raw: false);
    }

    private PsArgument Argument()
    {
        int start = _p;
        if (IsDash(C) && (char.IsLetter(At(1)) || At(1) == '_'))
        {
            _p++;
            int q = _p;
            while (!End && (IsIdent(C) || C == '`')) _p++;
            var name = _s[q.._p].Replace("`", "");
            if (C == ':')
            {
                _p++;
                var v = ArgumentValue();
                return new PsArgument(name, v, start, _p);
            }
            return new PsArgument(name, null, start, _p);
        }
        if (IsDash(C) && IsDash(At(1)) && At(2) is ' ' or '\t') { _p += 2; return new PsArgument(null, new PsLiteral(start, _p, "--", true), start, _p); }
        var value = ArgumentValue();
        return new PsArgument(null, value, start, _p);
    }

    private PsExpr ArgumentValue()
    {
        int start = _p;
        PsExpr first = ArgumentItem();
        Skip(false);
        if (C != ',') return first;
        var items = new List<PsExpr> { first };
        while (C == ',')
        {
            _p++;
            Skip(true);
            items.Add(ArgumentItem());
            Skip(false);
        }
        return new PsArrayList(start, _p, items);
    }

    private PsExpr ArgumentItem()
    {
        if (C is '$' or '(' or '@' or '{' || IsSingleQuote(C) || IsDoubleQuote(C) || C == '[')
        {
            var e = Postfix(Primary());
            return e;
        }
        if (char.IsDigit(C) || IsDash(C) && char.IsDigit(At(1)))
        {
            int save = _p;
            var n = Number();
            if (End || char.IsWhiteSpace(C) || C is ';' or '|' or ')' or '}' or ',') return n;
            _p = save;
        }
        return Bareword();
    }

    // --- expressions ---

    private PsExpr Expression() => Logical();

    private string? DashOperator(params string[] names)
    {
        Skip(false);
        if (!IsDash(C)) return null;
        int q = _p + 1;
        while (q < _s.Length && char.IsLetter(_s[q])) q++;
        if (q == _p + 1) return null;
        var word = _s[(_p + 1)..q].ToLowerInvariant();
        foreach (var n in names)
            if (word == n || word.Length > 1 && word[0] is 'c' or 'i' && word[1..] == n && n is not ("f" or "and" or "or" or "xor" or "not" or "bxor" or "band" or "bor" or "bnot" or "shl" or "shr" or "join" or "as" or "is"))
            {
                _p = q;
                return word;
            }
        return null;
    }

    private void SkipAfterOperator() => Skip(true);

    private PsExpr Logical()
    {
        Enter();
        try
        {
            int start = _p;
            var left = Comparison();
            while (DashOperator("and", "or", "xor") is { } op)
            {
                SkipAfterOperator();
                left = new PsBinary(start, 0, op, left, Comparison()) { End = _p };
            }
            return left;
        }
        finally { Leave(); }
    }

    private static readonly string[] ComparisonOps =
    [
        "eq", "ne", "gt", "ge", "lt", "le", "like", "notlike", "match", "notmatch", "contains", "notcontains", "in", "notin",
        "replace", "split", "join", "is", "isnot", "as",
    ];

    private PsExpr Comparison()
    {
        int start = _p;
        var left = Bitwise();
        while (DashOperator(ComparisonOps) is { } op)
        {
            SkipAfterOperator();
            left = new PsBinary(start, 0, op, left, Bitwise()) { End = _p };
        }
        return left;
    }

    private PsExpr Bitwise()
    {
        int start = _p;
        var left = Additive();
        while (DashOperator("band", "bor", "bxor", "shl", "shr") is { } op)
        {
            SkipAfterOperator();
            left = new PsBinary(start, 0, op, left, Additive()) { End = _p };
        }
        return left;
    }

    private PsExpr Additive()
    {
        int start = _p;
        var left = Multiplicative();
        while (true)
        {
            Skip(false);
            if (C == '+' && At(1) is not ('+' or '=')) { _p++; SkipAfterOperator(); left = new PsBinary(start, 0, "+", left, Multiplicative()) { End = _p }; }
            else if (IsDash(C) && At(1) is not ('-' or '=') && !char.IsLetter(At(1))) { _p++; SkipAfterOperator(); left = new PsBinary(start, 0, "-", left, Multiplicative()) { End = _p }; }
            else return left;
        }
    }

    private PsExpr Multiplicative()
    {
        int start = _p;
        var left = Negation();
        while (true)
        {
            Skip(false);
            if (C is '*' or '/' or '%' && At(1) != '=')
            {
                var op = C.ToString();
                _p++;
                SkipAfterOperator();
                left = new PsBinary(start, 0, op, left, Negation()) { End = _p };
            }
            else return left;
        }
    }

    private PsExpr Negation()
    {
        Enter();
        try { return NegationCore(); }
        finally { Leave(); }
    }

    private PsExpr NegationCore()
    {
        Skip(false);
        int start = _p;
        if (IsDash(C) && !char.IsLetter(At(1)) && At(1) != '-' && !char.IsDigit(At(1)))
        {
            _p++;
            Skip(false);
            return new PsUnary(start, 0, "-", Negation()) { End = _p };
        }
        if (C == '+' && At(1) != '+')
        {
            _p++;
            Skip(false);
            return new PsUnary(start, 0, "+", Negation()) { End = _p };
        }
        return Format();
    }

    private PsExpr Format()
    {
        int start = _p;
        var left = Range();
        while (DashOperator("f") is { } op)
        {
            SkipAfterOperator();
            left = new PsBinary(start, 0, "f", left, Range()) { End = _p };
        }
        return left;
    }

    private PsExpr Range()
    {
        int start = _p;
        var left = Not();
        Skip(false);
        if (C == '.' && At(1) == '.')
        {
            _p += 2;
            SkipAfterOperator();
            left = new PsBinary(start, 0, "..", left, IsDash(C) ? Negation() : Not()) { End = _p };
        }
        return left;
    }

    private PsExpr Not()
    {
        Enter();
        try { return NotCore(); }
        finally { Leave(); }
    }

    private PsExpr NotCore()
    {
        Skip(false);
        int start = _p;
        if (C == '!' ) { _p++; Skip(false); return new PsUnary(start, 0, "not", Not()) { End = _p }; }
        int save = _p;
        if (DashOperator("not", "bnot") is { } op) { SkipAfterOperator(); return new PsUnary(start, 0, op, Not()) { End = _p }; }
        _p = save;
        return Comma();
    }

    private PsExpr Comma()
    {
        int start = _p;
        Skip(false);
        if (_noComma) return UnaryJoin();
        if (C == ',') // unary comma: a one-element array
        {
            _p++;
            Skip(true);
            return new PsArrayList(start, 0, [UnaryJoin()]) { End = _p };
        }
        var first = UnaryJoin();
        Skip(false);
        if (C != ',') return first;
        var items = new List<PsExpr> { first };
        while (C == ',')
        {
            _p++;
            Skip(true);
            items.Add(UnaryJoin());
            Skip(false);
        }
        return new PsArrayList(start, _p, items);
    }

    private PsExpr UnaryJoin()
    {
        Enter();
        try { return UnaryJoinCore(); }
        finally { Leave(); }
    }

    private PsExpr UnaryJoinCore()
    {
        Skip(false);
        int start = _p;
        int save = _p;
        if (DashOperator("join", "split") is { } op)
        {
            Skip(false);
            if (C is '(' or '$' or '\'' or '"' or '@' or '[' || IsSingleQuote(C) || IsDoubleQuote(C))
                return new PsUnary(start, 0, op, UnaryJoin()) { End = _p };
            _p = save;
        }
        if (C is '+' && At(1) == '+' || IsDash(C) && IsDash(At(1)))
        {
            var op2 = C == '+' ? "++" : "--";
            _p += 2;
            return new PsUnary(start, 0, op2, UnaryJoin()) { End = _p };
        }
        return Cast();
    }

    private PsExpr Cast()
    {
        Enter();
        try { return CastCore(); }
        finally { Leave(); }
    }

    private PsExpr CastCore()
    {
        Skip(false);
        int start = _p;
        if (C == '[')
        {
            var type = TypeName();
            int after = _p;
            Skip(false);
            // [type] followed by an operand is a cast; followed by :: or nothing it is the type itself
            if (C == ':' && At(1) == ':' || End || C is ')' or ';' or ',' or '}' or '\r' or '\n' or '|' or ']' or '=' || C == '.' && At(1) != '.' || IsDash(C) && char.IsLetter(At(1)) || C is '+' or '*' or '/')
            {
                _p = after;
                return Postfix(new PsTypeLiteral(start, _p, type));
            }
            var operand = Cast();
            return new PsCast(start, _p, type, operand);
        }
        var e = Postfix(Primary());
        Skip(false);
        if (C == '+' && At(1) == '+' || IsDash(C) && IsDash(At(1)) && !char.IsLetter(At(2)))
        {
            var op = C == '+' ? "++" : "--";
            _p += 2;
            return new PsUnary(start, _p, op, e, postfix: true);
        }
        return e;
    }

    /// <summary>[type name], nested brackets kept, whitespace and backticks dropped.</summary>
    private string TypeName()
    {
        int nest = 0;
        var sb = new StringBuilder();
        _p++; // [
        while (!End)
        {
            char c = C;
            if (c == '[') nest++;
            else if (c == ']') { if (nest == 0) { _p++; break; } nest--; }
            if (c == '`') { _p++; if (!End) sb.Append(C); _p++; continue; }
            if (!char.IsWhiteSpace(c)) sb.Append(c);
            _p++;
        }
        var name = sb.ToString();
        if (name.Length == 0) throw new ParseError();
        return name;
    }

    private PsExpr Postfix(PsExpr e)
    {
        int start = e.Start;
        while (!End)
        {
            if (C == '[' && _p > 0 && !char.IsWhiteSpace(_s[_p - 1]))
            {
                _p++;
                Skip(true);
                bool saved = _noComma;
                _noComma = false;
                PsExpr index;
                try { index = Expression(); }
                finally { _noComma = saved; }
                Skip(true);
                if (C != ']') throw new ParseError();
                _p++;
                e = new PsIndex(start, _p, e, index);
                continue;
            }
            bool isStatic = C == ':' && At(1) == ':';
            if (C == '.' && At(1) != '.' || isStatic || C == '?' && At(1) == '.')
            {
                _p += isStatic || C == '?' ? 2 : 1;
                int nameStart = _p;
                PsExpr name;
                if (IsIdent(C) || C == '`')
                {
                    var sb = new StringBuilder();
                    while (!End && (IsIdent(C) || C == '`'))
                    {
                        if (C == '`') { _p++; if (!End) sb.Append(C); _p++; }
                        else sb.Append(_s[_p++]);
                    }
                    name = new PsLiteral(nameStart, _p, sb.ToString(), raw: true);
                }
                else if (IsSingleQuote(C) || IsDoubleQuote(C)) name = StringLiteral();
                else if (C is '(' or '$') name = Primary();
                else throw new ParseError();
                var member = new PsMember(start, _p, e, name, isStatic, nameStart);
                if (C == '(')
                {
                    _p++;
                    var args = new List<PsExpr>();
                    Skip(true);
                    while (!End && C != ')')
                    {
                        args.Add(Logical0());
                        Skip(true);
                        if (C == ',') { _p++; Skip(true); }
                        else if (C != ')') throw new ParseError();
                    }
                    if (C != ')') throw new ParseError();
                    _p++;
                    e = new PsInvoke(start, _p, member, args);
                }
                else e = member;
                continue;
            }
            break;
        }
        return e;
    }

    /// <summary>A method argument: an expression without the comma operator.</summary>
    private PsExpr Logical0()
    {
        bool saved = _noComma;
        _noComma = true;
        try { return Expression(); }
        finally { _noComma = saved; }
    }

    private PsExpr Primary()
    {
        Enter();
        try { return PrimaryCore(); }
        finally { Leave(); }
    }

    private PsExpr PrimaryCore()
    {
        bool saved = _noComma;
        _noComma = false; // brackets of any kind start a full expression again
        try { return PrimaryInner(); }
        finally { _noComma = saved; }
    }

    private PsExpr PrimaryInner()
    {
        Skip(false);
        int start = _p;
        char c = C;
        PsExpr result;
        if (c == '$')
        {
            if (At(1) == '(')
            {
                _p += 2;
                var body = Statements(')');
                if (C == ')') _p++;
                result = new PsGroup(start, _p, '$', body);
            }
            else result = Variable();
        }
        else if (c == '@' && At(1) == '(')
        {
            _p += 2;
            var body = Statements(')');
            if (C == ')') _p++;
            result = new PsGroup(start, _p, '@', body);
        }
        else if (c == '@' && At(1) == '{') result = Hash();
        else if (c == '@' && (IsSingleQuote(At(1)) || IsDoubleQuote(At(1)))) result = HereString();
        else if (c == '(')
        {
            _p++;
            Skip(true);
            var body = new List<PsStatement>();
            if (C != ')') body.Add(Pipeline());
            Skip(true);
            while (C == ';' ) { _p++; Skip(true); if (C != ')') body.Add(Pipeline()); Skip(true); }
            if (C != ')') throw new ParseError();
            _p++;
            result = new PsGroup(start, _p, '(', body);
        }
        else if (c == '{')
        {
            _p++;
            Skip(true);
            List<PsParam>? parameters = null;
            if (PeekKeyword() == "param") { Word(); Skip(true); if (C == '(') parameters = Params(); }
            var body = Statements('}');
            if (C == '}') _p++;
            result = new PsScriptBlockExpr(start, _p, body, parameters);
        }
        else if (IsSingleQuote(c) || IsDoubleQuote(c)) result = StringLiteral();
        else if (char.IsDigit(c) || c == '.' && char.IsDigit(At(1)) || IsDash(c) && char.IsDigit(At(1))) result = Number();
        else if (c == '[') { var t = TypeName(); result = new PsTypeLiteral(start, _p, t); }
        else if (char.IsLetter(c) || c == '_')
        {
            // a bareword in expression position: a member name or a command-less literal (true/false via $ only)
            result = Bareword();
        }
        else throw new ParseError();
        return result;
    }

    private PsExpr Variable()
    {
        int start = _p;
        _p++; // $
        if (C == '{')
        {
            _p++;
            var sb = new StringBuilder();
            while (!End && C != '}')
            {
                if (C == '`') { _p++; if (!End) sb.Append(C); _p++; continue; }
                sb.Append(_s[_p++]);
            }
            if (C == '}') _p++;
            return new PsVariable(start, _p, sb.ToString(), braced: true);
        }
        if (C is '$' or '?' or '^' || C == '_' && !IsIdent(At(1)))
        {
            _p++;
            return new PsVariable(start, _p, _s[(_p - 1).._p], braced: false);
        }
        int q = _p;
        while (!End && (IsIdent(C) || C == ':' && IsIdent(At(1)) && _p > q)) _p++;
        if (_p == q) return new PsLiteral(start, _p, "$", raw: false);
        return new PsVariable(start, _p, _s[q.._p], braced: false);
    }

    private PsExpr Hash()
    {
        int start = _p;
        _p += 2;
        var entries = new List<(PsExpr, PsStatement)>();
        while (true)
        {
            Skip(true);
            while (C == ';') { _p++; Skip(true); }
            if (End || C == '}') break;
            PsExpr key = IsSingleQuote(C) || IsDoubleQuote(C) || C is '$' or '(' ? Postfix(Primary()) : Bareword0();
            Skip(true);
            if (C != '=') throw new ParseError();
            _p++;
            Skip(true);
            entries.Add((key, Pipeline()));
        }
        if (C == '}') _p++;
        return new PsHash(start, _p, entries);
    }

    private PsLiteral Bareword0()
    {
        int start = _p;
        while (!End && (IsIdent(C) || C is '-' or '.')) _p++;
        if (_p == start) throw new ParseError();
        return new PsLiteral(start, _p, _s[start.._p], raw: true);
    }

    private PsExpr Number()
    {
        int start = _p;
        bool negative = false;
        if (IsDash(C)) { negative = true; _p++; }
        object value;
        if (C == '0' && At(1) is 'x' or 'X')
        {
            _p += 2;
            int q = _p;
            while (!End && Uri.IsHexDigit(C)) _p++;
            var hex = _s[q.._p];
            if (hex.Length == 0) throw new ParseError();
            value = hex.Length <= 16 ? (long)Convert.ToUInt64(hex, 16) : 0L;
            if (hex.Length <= 8 && (long)value > int.MaxValue) value = (long)(int)(uint)(long)value; // 0xFFFFFFFF is -1 as Int32
        }
        else if (C == '0' && At(1) is 'b' or 'B' && At(2) is '0' or '1')
        {
            _p += 2;
            int q = _p;
            while (!End && C is '0' or '1') _p++;
            value = Convert.ToInt64(_s[q.._p], 2);
        }
        else
        {
            int q = _p;
            while (!End && char.IsDigit(C)) _p++;
            bool real = false;
            if (C == '.' && char.IsDigit(At(1))) { real = true; _p++; while (!End && char.IsDigit(C)) _p++; }
            if (C is 'e' or 'E' && (char.IsDigit(At(1)) || At(1) is '+' or '-' && char.IsDigit(At(2)))) { real = true; _p += 2; while (!End && char.IsDigit(C)) _p++; }
            var text = _s[q.._p];
            if (real) value = double.Parse(text, System.Globalization.CultureInfo.InvariantCulture);
            else if (long.TryParse(text, out var l)) value = l;
            else value = double.Parse(text, System.Globalization.CultureInfo.InvariantCulture);
        }
        // suffixes: l, d, u, kb, mb, gb, tb, pb
        long scale = 1;
        int sq = _p;
        while (!End && char.IsLetter(C)) _p++;
        switch (_s[sq.._p].ToLowerInvariant())
        {
            case "": case "l": case "d": case "u": case "ul": case "y": case "uy": case "s": case "us": case "n": break;
            case "kb": scale = 1L << 10; break;
            case "mb": scale = 1L << 20; break;
            case "gb": scale = 1L << 30; break;
            case "tb": scale = 1L << 40; break;
            case "pb": scale = 1L << 50; break;
            default: _p = sq; break;
        }
        if (scale != 1) value = value is long lv ? lv * scale : (double)value * scale;
        if (negative) value = value is long nl ? -nl : -(double)value;
        return new PsLiteral(start, _p, value, raw: scale == 1 && !negative);
    }

    private PsExpr StringLiteral()
    {
        int start = _p;
        if (IsSingleQuote(C))
        {
            _p++;
            var sb = new StringBuilder();
            while (true)
            {
                if (End) throw new ParseError();
                char c = C;
                if (IsSingleQuote(c))
                {
                    if (IsSingleQuote(At(1))) { sb.Append('\''); _p += 2; continue; }
                    _p++;
                    break;
                }
                sb.Append(c);
                _p++;
            }
            return new PsLiteral(start, _p, sb.ToString(), raw: _s[start] == '\'' && _s[_p - 1] == '\'');
        }
        if (!IsDoubleQuote(C)) throw new ParseError();
        _p++;
        var parts = ExpandableParts(close: true);
        return Expandable(start, parts);
    }

    private PsExpr Expandable(int start, List<object> parts)
    {
        if (parts.Count == 0) return new PsLiteral(start, _p, "", raw: false);
        if (parts is [string only]) return new PsLiteral(start, _p, only, raw: false);
        return new PsExpandable(start, _p, parts);
    }

    /// <summary>The parts of a double-quoted string up to its closing quote (or a here-string's end when <paramref name="close"/> is false).</summary>
    private List<object> ExpandableParts(bool close, int stop = -1)
    {
        var parts = new List<object>();
        var sb = new StringBuilder();
        void Flush()
        {
            if (sb.Length > 0) { parts.Add(sb.ToString()); sb.Clear(); }
        }
        while (true)
        {
            if (stop >= 0 ? _p >= stop : End)
            {
                if (close) throw new ParseError();
                break;
            }
            char c = C;
            if (close && IsDoubleQuote(c))
            {
                if (IsDoubleQuote(At(1))) { sb.Append('"'); _p += 2; continue; }
                _p++;
                break;
            }
            if (c == '`')
            {
                _p++;
                char e = C;
                _p++;
                switch (e)
                {
                    case '0': sb.Append('\0'); break;
                    case 'a': sb.Append('\a'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'e': sb.Append('\u001B'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'v': sb.Append('\v'); break;
                    case 'u' when C == '{':
                    {
                        int closeAt = _s.IndexOf('}', _p);
                        if (closeAt > _p && closeAt - _p <= 7 && int.TryParse(_s.AsSpan(_p + 1, closeAt - _p - 1), System.Globalization.NumberStyles.HexNumber, null, out var cp) && cp <= 0x10FFFF)
                        {
                            sb.Append(char.ConvertFromUtf32(cp));
                            _p = closeAt + 1;
                        }
                        else sb.Append('u');
                        break;
                    }
                    case '\0': break;
                    default: sb.Append(e); break;
                }
                continue;
            }
            if (c == '$' && At(1) == '(')
            {
                Flush();
                int s = _p;
                _p += 2;
                var body = Statements(')');
                if (C == ')') _p++;
                parts.Add(new PsGroup(s, _p, '$', body));
                continue;
            }
            if (c == '$' && (IsIdent(At(1)) || At(1) is '{' or '_' or '?' or '^' or '$'))
            {
                Flush();
                var v = Variable();
                if (v is PsVariable variable && variable.Name.EndsWith(':')) { sb.Append(_s[v.Start..v.End]); continue; }
                parts.Add(v);
                continue;
            }
            sb.Append(c);
            _p++;
        }
        Flush();
        return parts;
    }

    private PsExpr HereString()
    {
        int start = _p;
        bool expandable = IsDoubleQuote(At(1));
        _p += 2;
        while (!End && C is ' ' or '\t') _p++;
        if (C == '\r') _p++;
        if (C == '\n') _p++;
        int bodyStart = _p;
        // the closing quote then @ at the start of a line
        int closeAt = -1;
        for (int i = bodyStart; i < _s.Length - 1; i++)
        {
            if (_s[i] == '@' && i > 0 && (expandable ? IsDoubleQuote(_s[i - 1]) : IsSingleQuote(_s[i - 1])) && (i - 1 == bodyStart || _s[i - 2] == '\n'))
            {
                closeAt = i - 1;
                break;
            }
        }
        if (closeAt < 0) throw new ParseError();
        int bodyEnd = closeAt;
        if (bodyEnd > bodyStart && _s[bodyEnd - 1] == '\n') bodyEnd--;
        if (bodyEnd > bodyStart && _s[bodyEnd - 1] == '\r') bodyEnd--;
        if (!expandable)
        {
            _p = closeAt + 2;
            return new PsLiteral(start, _p, _s[bodyStart..bodyEnd], raw: false);
        }
        _p = bodyStart;
        var parts = ExpandableParts(close: false, stop: bodyEnd);
        _p = closeAt + 2;
        return Expandable(start, parts);
    }
}
