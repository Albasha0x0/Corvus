using System.Text;
using System.Text.RegularExpressions;
using Corvus.Core.Mobile;

namespace Corvus.Services.Mobile;

/// <summary>Puts original names into JADX's Java text; an identifier is replaced only when every DEX candidate agrees, never strings, comments or locals.</summary>
internal sealed partial class JavaSourceNames
{
    private enum Kind : byte { Ident, Punct, Other }

    private readonly record struct Token(Kind Kind, int Start, int Length, string Text);

    private sealed record Member(string Id, string Owner, string Name, int Arity, IReadOnlyList<string> Parameters, string? FieldType)
    {
        public bool IsMethod => FieldType == null;
    }

    private sealed class Scope(char kind, string? cls, string? method)
    {
        // 'c' class body, 'm' method body, 'b' block.
        public char Kind { get; } = kind;
        public string? Class { get; } = cls;
        public string? Method { get; } = method;
    }

    /// <summary>The source with original names, the number of identifiers replaced, and the names left because candidates disagree.</summary>
    public sealed record Result(string Text, int Renamed, IReadOnlyList<string> Undecided);

    private static readonly HashSet<string> Keywords = new(StringComparer.Ordinal)
    {
        "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const", "continue", "default", "do", "double",
        "else", "enum", "extends", "final", "finally", "float", "for", "goto", "if", "implements", "import", "instanceof", "int", "interface",
        "long", "native", "new", "package", "private", "protected", "public", "return", "short", "static", "strictfp", "super", "switch",
        "synchronized", "this", "throw", "throws", "transient", "try", "void", "volatile", "while", "true", "false", "null", "var", "record", "yield",
    };

    private static readonly HashSet<string> Primitives = new(StringComparer.Ordinal) { "boolean", "byte", "char", "short", "int", "long", "float", "double", "void" };

    private readonly DexNames _names;
    private readonly DexIndex _index;
    private readonly List<Token> _tokens;
    // Class descriptors the source writes.
    private readonly HashSet<string> _context;
    private readonly List<Member> _declared = [];
    // Method id to the members it references.
    private readonly Dictionary<string, List<Member>> _refsFrom = new(StringComparer.Ordinal);
    private readonly List<Member> _allRefs = [];
    private readonly Dictionary<string, List<string>> _typesBySimple = new(StringComparer.Ordinal);
    // Simple name to descriptor.
    private readonly Dictionary<string, string> _imports = new(StringComparer.Ordinal);
    private readonly bool[] _generic;
    private readonly Dictionary<int, (int Length, string Text)> _edits = [];
    private readonly SortedSet<string> _undecided = new(StringComparer.Ordinal);
    // Token index to the descriptor it resolved to.
    private readonly Dictionary<int, string> _typeAt = [];

    private JavaSourceNames(string source, DexNames names, DexIndex index, HashSet<string> context, CancellationToken ct)
    {
        _names = names;
        _index = index;
        _context = context;
        _tokens = Tokenize(source);
        _generic = GenericRanges();
        Collect(ct);
    }

    /// <summary>Puts original names into <paramref name="source"/>, the JADX text of <paramref name="descriptor"/> (a class or a method's class).</summary>
    public static Result Apply(string source, DexNames names, DexIndex index, string descriptor, CancellationToken ct)
    {
        int dollar = descriptor.IndexOf('$');
        var stem = dollar > 0 ? descriptor[..dollar] : descriptor.TrimEnd(';');
        var context = index.Classes.Keys.Where(d => d == stem + ";" || d.StartsWith(stem + "$", StringComparison.Ordinal)).ToHashSet(StringComparer.Ordinal);
        context.Add(descriptor);
        var r = new JavaSourceNames(source, names, index, context, ct);
        r.Walk(ct);
        var sb = new StringBuilder(source.Length + 256);
        int at = 0;
        foreach (var (start, edit) in r._edits.OrderBy(e => e.Key))
        {
            sb.Append(source, at, start - at).Append(edit.Text);
            at = start + edit.Length;
        }
        sb.Append(source, at, source.Length - at);
        return new Result(sb.ToString(), r._edits.Count, [.. r._undecided]);
    }

    // ---- collection ----

    private void Collect(CancellationToken ct)
    {
        // Code keys exist once the code is indexed.
        _index.EnsureCode(ct);
        var fromKeys = new Dictionary<int, string>();
        foreach (var d in _context)
        {
            if (!_index.Classes.TryGetValue(d, out var e)) continue;
            AddType(d);
            if (e.Class.SuperClass is { } s) AddType(s);
            foreach (var i in e.Class.Interfaces) AddType(i);
            var (fields, methods) = e.File.ClassData(e.Class);
            foreach (var f in fields)
            {
                var r = e.File.Field(f.FieldIndex);
                _declared.Add(FieldMember(r.Descriptor, r.Class, r.Name, r.Type));
                AddType(r.Type);
            }
            foreach (var m in methods)
            {
                var r = e.File.Method(m.MethodIndex);
                _declared.Add(MethodMember(r.Descriptor, r.Class, r.Name, r.Proto.Parameters));
                foreach (var p in r.Proto.Parameters.Append(r.Proto.ReturnType)) AddType(p);
                if (_index.FindKey(r.Descriptor) is { } key) fromKeys[key] = r.Descriptor;
            }
        }
        if (fromKeys.Count == 0) return;
        foreach (var r in _index.Refs)
        {
            if (!fromKeys.TryGetValue(r.From, out var from)) continue;
            var target = _index.KeyText(r.Target);
            Member? m = r.Kind switch
            {
                DexRefKind.Call => ParseMethod(target),
                DexRefKind.Read or DexRefKind.Write => ParseField(target),
                _ => null,
            };
            if (r.Kind == DexRefKind.Type) AddType(target);
            if (m == null) continue;
            if (!_refsFrom.TryGetValue(from, out var list)) _refsFrom[from] = list = [];
            list.Add(m);
            _allRefs.Add(m);
            AddType(m.Owner);
            foreach (var p in m.Parameters) AddType(p);
            if (m.FieldType != null) AddType(m.FieldType);
        }
    }

    private void AddType(string descriptor)
    {
        var d = descriptor.TrimStart('[');
        if (d.Length < 3 || d[0] != 'L' || d[^1] != ';') return;
        var simple = Simple(d);
        if (!_typesBySimple.TryGetValue(simple, out var list)) _typesBySimple[simple] = list = [];
        if (!list.Contains(d)) list.Add(d);
    }

    private static Member FieldMember(string id, string owner, string name, string type) => new(id, owner, name, 0, [], type);

    private static Member MethodMember(string id, string owner, string name, IReadOnlyList<string> parameters) => new(id, owner, name, parameters.Count, parameters, null);

    private static Member? ParseMethod(string id)
    {
        int arrow = id.IndexOf("->", StringComparison.Ordinal), open = id.IndexOf('('), close = id.IndexOf(')');
        if (arrow <= 0 || open < arrow || close < open) return null;
        return MethodMember(id, id[..arrow], id[(arrow + 2)..open], DexIndex.SplitParameters(id[(open + 1)..close]));
    }

    private static Member? ParseField(string id)
    {
        int arrow = id.IndexOf("->", StringComparison.Ordinal), colon = id.IndexOf(':', Math.Max(arrow, 0));
        return arrow <= 0 || colon < arrow ? null : FieldMember(id, id[..arrow], id[(arrow + 2)..colon], id[(colon + 1)..]);
    }

    /// <summary>"Lpkg/Outer$Inner;" to "Inner".</summary>
    private static string Simple(string descriptor)
    {
        var s = descriptor.TrimEnd(';');
        return s[(Math.Max(s.LastIndexOf('/'), s.LastIndexOf('$')) + 1)..];
    }

    private string Original(Member m)
    {
        if (_names.Member(m.Id) is not { } id) return m.Name;
        int arrow = id.IndexOf("->", StringComparison.Ordinal) + 2;
        int end = id.IndexOfAny(['(', ':'], arrow);
        return end > arrow ? id[arrow..end] : m.Name;
    }

    private string? OriginalSimple(string descriptor) => _names.Descriptor(descriptor) is { } o ? Simple(o) : null;

    // ---- tokens ----

    private static List<Token> Tokenize(string s)
    {
        var tokens = new List<Token>();
        int i = 0;
        while (i < s.Length)
        {
            char c = s[i];
            int start = i;
            if (char.IsWhiteSpace(c)) { i++; continue; }
            if (c == '/' && i + 1 < s.Length && s[i + 1] == '/') i = s.IndexOf('\n', i) is var e and >= 0 ? e : s.Length;
            else if (c == '/' && i + 1 < s.Length && s[i + 1] == '*') i = s.IndexOf("*/", i + 2, StringComparison.Ordinal) is var e and >= 0 ? e + 2 : s.Length;
            else if (c == '"' && i + 2 < s.Length && s[i + 1] == '"' && s[i + 2] == '"') i = s.IndexOf("\"\"\"", i + 3, StringComparison.Ordinal) is var e and >= 0 ? e + 3 : s.Length;
            else if (c is '"' or '\'')
            {
                for (i++; i < s.Length && s[i] != c && s[i] != '\n'; i++) if (s[i] == '\\') i++;
                i = Math.Min(i + 1, s.Length);
            }
            else if (char.IsLetter(c) || c is '_' or '$')
            {
                while (i < s.Length && (char.IsLetterOrDigit(s[i]) || s[i] is '_' or '$')) i++;
                tokens.Add(new Token(Kind.Ident, start, i - start, s[start..i]));
                continue;
            }
            else if (char.IsDigit(c))
            {
                while (i < s.Length && (char.IsLetterOrDigit(s[i]) || s[i] is '.' or '_')) i++;
            }
            else
            {
                i += s.AsSpan(i).StartsWith("...") ? 3 : 1;
                tokens.Add(new Token(Kind.Punct, start, i - start, s[start..i]));
                continue;
            }
            tokens.Add(new Token(Kind.Other, start, i - start, ""));
        }
        return tokens;
    }

    private string T(int i) => i >= 0 && i < _tokens.Count ? _tokens[i].Text : "";

    private bool IsIdent(int i) => i >= 0 && i < _tokens.Count && _tokens[i].Kind == Kind.Ident && !Keywords.Contains(_tokens[i].Text);

    /// <summary>Marks the tokens inside type argument lists (&lt;...&gt; holding only names, dots, commas, wildcards and brackets).</summary>
    private bool[] GenericRanges()
    {
        var marks = new bool[_tokens.Count];
        for (int i = 1; i < _tokens.Count; i++)
        {
            if (T(i) != "<" || _tokens[i - 1].Kind != Kind.Ident && T(i - 1) != ".") continue;
            int depth = 0, j = i;
            for (; j < _tokens.Count; j++)
            {
                var t = T(j);
                if (t == "<") depth++;
                else if (t == ">" && --depth == 0) break;
                else if (_tokens[j].Kind != Kind.Ident && t is not ("." or "," or "?" or "[" or "]" or "&")) { j = -1; break; }
            }
            if (j < 0 || j >= _tokens.Count) continue;
            for (int k = i; k <= j; k++) marks[k] = true;
            i = j;
        }
        return marks;
    }

    private int Matching(int open)
    {
        int depth = 0;
        for (int i = open; i < _tokens.Count; i++)
        {
            var t = T(i);
            if (t is "(" or "[" or "{") depth++;
            else if (t is ")" or "]" or "}" && --depth == 0) return i;
        }
        return _tokens.Count;
    }

    /// <summary>The argument count of the parenthesized list opening at <paramref name="open"/>.</summary>
    private int Arity(int open, out int close)
    {
        close = Matching(open);
        if (close == open + 1) return 0;
        int depth = 0, commas = 0;
        for (int i = open + 1; i < close; i++)
        {
            var t = T(i);
            if (t is "(" or "[" or "{") depth++;
            else if (t is ")" or "]" or "}") depth--;
            else if (t == "," && depth == 0 && !_generic[i]) commas++;
        }
        return commas + 1;
    }

    // ---- walk ----

    private void Walk(CancellationToken ct)
    {
        var scopes = new Stack<Scope>();
        (int Brace, char Kind, string? Class, string? Method)? pending = null;
        // After extends / implements / throws, until { or ;.
        bool typeList = false;
        for (int i = 0; i < _tokens.Count; i++)
        {
            if ((i & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            var tok = _tokens[i];
            var text = tok.Text;
            if (tok.Kind == Kind.Punct)
            {
                if (text == "{")
                {
                    typeList = false;
                    if (pending is { } p && p.Brace == i) scopes.Push(new Scope(p.Kind, p.Class, p.Method));
                    else if (T(i - 1) == ")" && AnonymousClass(i - 1)) scopes.Push(new Scope('c', null, null));
                    else scopes.Push(new Scope('b', null, null));
                    pending = null;
                }
                else if (text == "}" && scopes.Count > 0) scopes.Pop();
                else if (text == ";") typeList = false;
                continue;
            }
            if (tok.Kind != Kind.Ident) continue;
            var cls = scopes.FirstOrDefault(s => s.Kind == 'c')?.Class;
            var method = scopes.FirstOrDefault(s => s.Kind == 'm')?.Method;
            bool inMethod = scopes.FirstOrDefault(s => s.Kind is 'm' or 'c')?.Kind == 'm';
            switch (text)
            {
                case "package":
                    i = Package(i + 1);
                    continue;
                case "import":
                    i = Import(i + 1);
                    continue;
                case "class" or "interface" or "enum" or "record" when IsIdent(i + 1) && T(i - 1) != ".":
                {
                    var desc = ClassDeclaration(i + 1);
                    int brace = i + 1;
                    while (brace < _tokens.Count && T(brace) != "{" && T(brace) != ";") brace++;
                    pending = (brace, 'c', desc, null);
                    i++;
                    continue;
                }
                case "extends" or "implements" or "throws":
                    typeList = true;
                    continue;
                case "static" when T(i + 1) == "{" && !inMethod:
                    pending = (i + 1, 'm', null, cls is { } c0 ? c0[..^1] + ";-><clinit>()V" : null);
                    continue;
            }
            if (Keywords.Contains(text)) continue;
            if (Chain(i, inMethod ? method : null, out var end)) { i = end; continue; }

            var prev = T(i - 1);
            var next = T(i + 1);
            if (next == "(")
            {
                if (prev == "new") { Type(i); continue; }
                int arity = Arity(i + 1, out int close);
                var after = T(close + 1);
                bool declaration = (IsIdent(i - 1) || Primitives.Contains(prev) || prev is ">" or "]") && after is "{" or ";" or "throws" or "default";
                bool constructor = !declaration && cls != null && Decode(text, 'c') == Simple(cls) && after is "{" or "throws"
                                   && (prev is "public" or "protected" or "private" or "{" or "}" or ";" || i == 0);
                if (declaration || constructor)
                {
                    var resolved = MethodDeclaration(i, close, arity, cls, constructor);
                    if (after != ";")
                    {
                        int brace = close + 1;
                        while (brace < _tokens.Count && T(brace) != "{") brace++;
                        pending = (brace, 'm', cls, resolved);
                    }
                    continue;
                }
                var owner = prev == "." ? _typeAt.GetValueOrDefault(i - 2) : null;
                Rename(i, Decode(text, 'm'), m => m.IsMethod && m.Arity == arity && (owner == null || m.Owner == owner), method);
                continue;
            }
            if (_generic[i] || typeList && prev is "extends" or "implements" or "throws" or "," || TypePosition(i)) { Type(i); continue; }
            if (prev == ".")
            {
                var owner = _typeAt.GetValueOrDefault(i - 2);
                if (owner != null && _index.Classes.ContainsKey(owner[..^1] + "$" + text + ";")) { Type(i, owner[..^1] + "$" + text + ";"); continue; }
                Rename(i, Decode(text, 'f'), m => !m.IsMethod && (owner == null || m.Owner == owner), method);
                continue;
            }
            if (!inMethod && (IsIdent(i - 1) || Primitives.Contains(prev) || prev is ">" or "]") && next is ";" or "=" or ",")
            {
                var name = Decode(text, 'f');
                Decide(i, _declared.Where(m => !m.IsMethod && m.Name == name && (cls == null || m.Owner == cls)).ToList(), name);
                continue;
            }
            if (next == ".")
            {
                var name = Decode(text, 'f');
                var fields = Candidates(name, m => !m.IsMethod, inMethod ? method : null);
                var types = Types(text);
                if (types.Count > 0 && fields.Count > 0)
                {
                    var member = T(i + 2);
                    bool typeFits = _declared.Concat(_allRefs).Any(m => m.Name == member && types.Contains(m.Owner)) || types.Any(t => _index.Classes.ContainsKey(t[..^1] + "$" + member + ";"));
                    bool fieldFits = fields.Any(f => f.FieldType is ['[', ..] && member == "length" || _declared.Concat(_allRefs).Any(m => m.Name == member && m.Owner == f.FieldType));
                    if (typeFits == fieldFits) { _undecided.Add($"{text} (a field or a class)"); continue; }
                    if (typeFits) fields = [];
                    else types = [];
                }
                if (types.Count > 0) { Type(i); continue; }
                Decide(i, fields, name);
                continue;
            }
            // A value: a field of this class or one the method reads or writes.
            Rename(i, Decode(text, 'f'), m => !m.IsMethod, inMethod ? method : null, declaredFallback: !inMethod);
        }
    }

    /// <summary>The { at <paramref name="close"/>+1 opens an anonymous class: the parenthesized list follows new T.</summary>
    private bool AnonymousClass(int close)
    {
        int depth = 0;
        for (int i = close; i >= 0; i--)
        {
            var t = T(i);
            if (t == ")") depth++;
            else if (t == "(" && --depth == 0)
            {
                int j = i - 1;
                while (j > 0 && (_tokens[j].Kind == Kind.Ident && !Keywords.Contains(T(j)) || T(j) == "." || _generic[j])) j--;
                return T(j) == "new";
            }
        }
        return false;
    }

    /// <summary>A type in a declaration, cast, class literal, annotation, instanceof or array type.</summary>
    private bool TypePosition(int i)
    {
        var prev = T(i - 1);
        var next = T(i + 1);
        if (prev is "new" or "instanceof" or "@" or "catch") return true;
        if (IsIdent(i + 1) || next == "...") return true;
        if (next == "[" && T(i + 2) == "]") return true;
        if (next == "." && T(i + 2) == "class") return true;
        if (prev == "(" && next == ")")
        {
            var after = _tokens.ElementAtOrDefault(i + 2);
            return after.Kind is Kind.Ident or Kind.Other || T(i + 2) is "(" or "!" or "~";
        }
        return false;
    }

    /// <summary>The JADX name of a renamed member or class (f0a, m1a, C0001a: prefix, counter, DEX name) as the DEX name.</summary>
    private string Decode(string text, char kind)
    {
        if (_declared.Any(m => m.Name == text) || _allRefs.Any(m => m.Name == text) || _typesBySimple.ContainsKey(text)) return text;
        var m = JadxAlias().Match(text);
        return m.Success && m.Groups[1].Value[0] == (kind == 'c' ? 'C' : kind) ? m.Groups[2].Value : text;
    }

    private List<Member> Candidates(string name, Func<Member, bool> filter, string? method, bool declaredFallback = true)
    {
        if (method != null && _refsFrom.TryGetValue(method, out var refs))
        {
            var near = refs.Where(m => m.Name == name && filter(m)).ToList();
            if (near.Count > 0) return near;
        }
        if (method == null && !declaredFallback) return [];
        return _declared.Concat(_allRefs).Where(m => m.Name == name && filter(m)).ToList();
    }

    private bool Rename(int i, string name, Func<Member, bool> filter, string? method, bool declaredFallback = true) =>
        Decide(i, Candidates(name, filter, method, declaredFallback), name);

    /// <summary>Replaces token <paramref name="i"/> when every candidate has one original name other than its DEX name.</summary>
    private bool Decide(int i, List<Member> candidates, string name)
    {
        if (candidates.Count == 0) return false;
        var originals = candidates.Select(Original).Distinct(StringComparer.Ordinal).ToList();
        if (originals.Count > 1)
        {
            _undecided.Add($"{_tokens[i].Text} ({string.Join(" | ", originals.Take(4))})");
            return true;
        }
        if (originals[0] != name) Edit(i, originals[0]);
        return true;
    }

    private void Edit(int i, string text)
    {
        if (text != _tokens[i].Text) _edits[_tokens[i].Start] = (_tokens[i].Length, text);
    }

    private List<string> Types(string text)
    {
        var simple = Decode(text, 'c');
        if (_imports.TryGetValue(simple, out var imported)) return [imported];
        return _typesBySimple.GetValueOrDefault(simple) ?? [];
    }

    private void Type(int i, string? exact = null)
    {
        var types = exact != null ? [exact] : Types(_tokens[i].Text);
        if (types.Count == 0) return;
        var originals = types.Select(t => OriginalSimple(t) ?? Simple(t)).Distinct(StringComparer.Ordinal).ToList();
        if (originals.Count > 1) { _undecided.Add($"{_tokens[i].Text} ({string.Join(" | ", originals.Take(4))})"); return; }
        if (types.Count == 1) _typeAt[i] = types[0];
        if (types.Any(t => OriginalSimple(t) != null)) Edit(i, originals[0]);
    }

    private string? ClassDeclaration(int i)
    {
        var simple = Decode(T(i), 'c');
        var candidates = _context.Where(d => Simple(d) == simple).ToList();
        if (candidates.Count != 1) return null;
        _typeAt[i] = candidates[0];
        if (OriginalSimple(candidates[0]) is { } o) Edit(i, o);
        return candidates[0];
    }

    /// <summary>Resolves a method declaration by name, argument count and parameter types; returns its DEX id.</summary>
    private string? MethodDeclaration(int i, int close, int arity, string? cls, bool constructor)
    {
        var keys = ParameterKeys(i + 1, close);
        if (constructor)
        {
            Type(i, cls);
            return _declared.Where(m => m.Name == "<init>" && m.Owner == cls && m.Parameters.Select(ShortType).SequenceEqual(keys)).Select(m => m.Id).FirstOrDefault();
        }
        var name = Decode(T(i), 'm');
        var candidates = _declared.Where(m => m.IsMethod && m.Name == name && m.Arity == arity && (cls == null || m.Owner == cls)
                                              && m.Parameters.Select(ShortType).SequenceEqual(keys)).ToList();
        Decide(i, candidates, name);
        return candidates.Count == 1 ? candidates[0].Id : null;
    }

    /// <summary>The simple type of each declared parameter, generic arguments dropped: "int", "b", "String[]".</summary>
    private List<string> ParameterKeys(int open, int close)
    {
        var keys = new List<string>();
        var segment = new List<int>();
        int depth = 0;
        for (int i = open + 1; i <= close; i++)
        {
            var t = T(i);
            if (i == close || t == "," && depth == 0 && !_generic[i])
            {
                if (segment.Count > 0) keys.Add(ParameterKey(segment));
                segment.Clear();
                continue;
            }
            if (t is "(") depth++;
            else if (t is ")") depth--;
            segment.Add(i);
        }
        return keys;
    }

    private string ParameterKey(List<int> segment)
    {
        var kept = new List<int>();
        for (int k = 0; k < segment.Count; k++)
        {
            int i = segment[k];
            if (T(i) == "@")
            {
                // Skips an annotation's name and arguments.
                k++;
                while (k + 2 < segment.Count && T(segment[k + 1]) == ".") k += 2;
                if (k + 1 < segment.Count && T(segment[k + 1]) == "(") { int c = Matching(segment[k + 1]); while (k + 1 < segment.Count && segment[k + 1] <= c) k++; }
                continue;
            }
            if (T(i) != "final" && !_generic[i]) kept.Add(i);
        }
        // Drops the parameter's name.
        if (kept.Count > 0 && _tokens[kept[^1]].Kind == Kind.Ident) kept.RemoveAt(kept.Count - 1);
        int type = kept.LastOrDefault(i => _tokens[i].Kind == Kind.Ident, -1);
        int dims = kept.Count(i => T(i) is "[" or "...");
        return (type < 0 ? "" : Decode(T(type), 'c')) + string.Concat(Enumerable.Repeat("[]", dims));
    }

    private static string ShortType(string descriptor)
    {
        var java = DexFile.JavaName(descriptor);
        int b = java.IndexOf('[');
        var dims = b > 0 ? java[b..] : "";
        var element = b > 0 ? java[..b] : java;
        return element[(Math.Max(element.LastIndexOf('.'), element.LastIndexOf('$')) + 1)..] + dims;
    }

    // ---- qualified names ----

    /// <summary>Names a.b.c starting at <paramref name="i"/>: its token indexes and dotted text.</summary>
    private (List<int> Parts, int End) ReadChain(int i)
    {
        var parts = new List<int> { i };
        int j = i;
        while (T(j + 1) == "." && _tokens.ElementAtOrDefault(j + 2).Kind == Kind.Ident && !Keywords.Contains(T(j + 2))) { j += 2; parts.Add(j); }
        return (parts, j);
    }

    /// <summary>The longest prefix of a dotted name that is a class of the package; the descriptor and the part count.</summary>
    private (string Descriptor, int Count)? ClassPrefix(List<int> parts)
    {
        for (int n = parts.Count; n >= 2; n--)
        {
            var dotted = string.Join(".", parts.Take(n).Select(p => T(p)));
            foreach (var d in DexIndex.ToDescriptor(dotted))
                if (_index.Classes.ContainsKey(d) || _names.Descriptor(d) != null) return (d, n);
        }
        return null;
    }

    private void ReplaceChain(List<int> parts, int count, string descriptor)
    {
        if (_names.Descriptor(descriptor) is not { } original) return;
        var java = DexFile.JavaName(original).Replace('$', '.');
        var start = _tokens[parts[0]].Start;
        var last = _tokens[parts[count - 1]];
        _edits[start] = (last.Start + last.Length - start, java);
        _typeAt[parts[count - 1]] = descriptor;
    }

    /// <summary>A qualified class name in code (a.b.C.m()), unless its first part is a field or class name here.</summary>
    private bool Chain(int i, string? method, out int end)
    {
        end = i;
        if (T(i - 1) == "." || T(i + 1) != ".") return false;
        var (parts, _) = ReadChain(i);
        if (parts.Count < 2 || _typesBySimple.ContainsKey(T(i)) || Candidates(T(i), m => !m.IsMethod, method).Count > 0) return false;
        if (ClassPrefix(parts) is not { } found) return false;
        ReplaceChain(parts, found.Count, found.Descriptor);
        end = parts[found.Count - 1];
        return true;
    }

    private int Package(int i)
    {
        var (parts, end) = ReadChain(i);
        var dotted = string.Join(".", parts.Select(p => T(p)));
        var top = _context.Where(d => !d.Contains('$')).Select(d => (d, o: _names.Descriptor(d))).FirstOrDefault(x => x.o != null);
        if (top.o != null && DexFile.JavaName(top.d) is var j && j.LastIndexOf('.') is var dot and > 0 && j[..dot] == dotted)
        {
            var o = DexFile.JavaName(top.o);
            if (o.LastIndexOf('.') is var od and > 0)
                _edits[_tokens[parts[0]].Start] = (_tokens[end].Start + _tokens[end].Length - _tokens[parts[0]].Start, o[..od]);
        }
        return end;
    }

    private int Import(int i)
    {
        if (T(i) == "static") i++;
        var (parts, end) = ReadChain(i);
        if (ClassPrefix(parts) is { } found)
        {
            if (found.Count == parts.Count) _imports[T(parts[^1])] = found.Descriptor;
            ReplaceChain(parts, found.Count, found.Descriptor);
        }
        return end;
    }

    [GeneratedRegex(@"^([fmC])\d+(.+)$")]
    private static partial Regex JadxAlias();
}
