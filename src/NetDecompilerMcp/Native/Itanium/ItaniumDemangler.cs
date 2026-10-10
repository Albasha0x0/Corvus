using System.Globalization;
using System.Text;

namespace NetDecompilerMcp.Native.Itanium;

/// <summary>
/// Demangles Itanium C++ ABI names (GCC and Clang on ELF and Mach-O) into the text llvm-cxxfilt prints: templates,
/// substitutions, template parameters and packs, lambdas and unnamed types, ABI tags, special names (vtables,
/// typeinfo, thunks, guard variables), local names, literals and the common expressions, and clone suffixes
/// (".cold"). Names it cannot parse yield null; no input throws.
/// </summary>
public static class ItaniumDemangler
{
    /// <summary>Longest name accepted; longer input is returned as not demangled.</summary>
    public const int MaxLength = 1 << 16;

    internal sealed class TooDeep : Exception;

    /// <summary>
    /// The demangled form of <paramref name="name"/>, or null when it is not an Itanium mangled name.
    /// <paramref name="stripUnderscore"/> removes the extra leading underscore Mach-O symbol names carry.
    /// </summary>
    public static string? Demangle(string? name, bool stripUnderscore = false)
    {
        if (string.IsNullOrEmpty(name) || name.Length > MaxLength) return null;
        if (stripUnderscore && (name.StartsWith("__Z", StringComparison.Ordinal) || name.StartsWith("____Z", StringComparison.Ordinal))) name = name[1..];
        try
        {
            var node = new Parser(name).ParseTop();
            return node?.ToString();
        }
        catch (TooDeep) { return null; }
        catch (InsufficientExecutionStackException) { return null; }
    }

    /// <summary>Whether <paramref name="name"/> looks mangled (starts with _Z, or ___Z for blocks).</summary>
    public static bool IsMangled(string? name, bool stripUnderscore = false) =>
        name != null && (name.StartsWith("_Z", StringComparison.Ordinal) || name.StartsWith("___Z", StringComparison.Ordinal)
                         || stripUnderscore && name.StartsWith("__Z", StringComparison.Ordinal));

    private sealed class NameState
    {
        public bool CtorDtorConversion;
        public bool EndsWithTemplateArgs;
        public Cv Quals;
        public RefQualifier Ref;
        public int ForwardRefsBegin;
    }

    private sealed class Parser(string s)
    {
        private int pos;
        private readonly List<Node> subs = [];
        private List<List<Node>?> templateParams = [];
        private List<Node> outerParams = [];
        private readonly List<ForwardTemplateReference> forwardRefs = [];
        private bool tryTemplateArgs = true;
        private bool permitForwardRefs;
        private int lambdaParamsLevel = -1;
        private int depth;

        private char Look(int k = 0) => pos + k < s.Length ? s[pos + k] : '\0';
        private bool AtEnd => pos >= s.Length;

        private bool Consume(char c)
        {
            if (Look() != c) return false;
            pos++;
            return true;
        }

        private bool Consume(string t)
        {
            if (string.CompareOrdinal(s, pos, t, 0, t.Length) != 0) return false;
            pos += t.Length;
            return true;
        }

        private void Enter()
        {
            if (++depth > 192) throw new TooDeep();
        }

        public Node? ParseTop()
        {
            if (Consume("_Z"))
            {
                var encoding = ParseEncoding();
                if (encoding == null) return null;
                if (Look() == '.') encoding = new PostfixClone(encoding, s[pos..]);
                else if (!AtEnd) return null;
                return encoding;
            }
            if (Consume("___Z") || Consume("____Z"))
            {
                var encoding = ParseEncoding();
                if (encoding == null || !Consume("_block_invoke")) return null;
                bool hasNumber = Consume('_');
                if (ParseNumber().Length == 0 && hasNumber) return null;
                return AtEnd ? new SpecialName("invocation function for block in ", encoding) : null;
            }
            return null;
        }

        private sealed class PostfixClone(Node child, string suffix) : Node
        {
            public override void Left(Output o) { child.Print(o); o.Add(" (").Add(suffix).Add(')'); }
        }

        private bool IsEndOfEncoding() => AtEnd || Look() is 'E' or '.' or '_';

        private string ParseNumber(bool allowNegative = false)
        {
            int start = pos;
            if (allowNegative) Consume('n');
            if (!char.IsAsciiDigit(Look())) { pos = start; return ""; }
            while (char.IsAsciiDigit(Look())) pos++;
            return s[start..pos];
        }

        private bool ParsePositive(out long value)
        {
            value = 0;
            if (!char.IsAsciiDigit(Look())) return false;
            while (char.IsAsciiDigit(Look()))
            {
                value = value * 10 + (s[pos++] - '0');
                if (value > MaxLength) return false;
            }
            return true;
        }

        private string? ParseBareSourceName()
        {
            if (!ParsePositive(out long length) || length == 0 || pos + length > s.Length) return null;
            var name = s.Substring(pos, (int)length);
            pos += (int)length;
            return name;
        }

        private Cv ParseCv()
        {
            var q = Cv.None;
            if (Consume('r')) q |= Cv.Restrict;
            if (Consume('V')) q |= Cv.Volatile;
            if (Consume('K')) q |= Cv.Const;
            return q;
        }

        // <encoding> ::= <name> <bare-function-type> | <name> | <special-name>
        private Node? ParseEncoding()
        {
            Enter();
            try
            {
                var savedParams = templateParams;
                var savedOuter = outerParams;
                templateParams = [];
                outerParams = [];
                try { return ParseEncodingCore(); }
                finally
                {
                    templateParams = savedParams;
                    outerParams = savedOuter;
                }
            }
            finally { depth--; }
        }

        private Node? ParseEncodingCore()
        {
            if (Look() == 'G' || Look() == 'T') return ParseSpecialName();
            var state = new NameState { ForwardRefsBegin = forwardRefs.Count };
            var name = ParseName(state);
            if (name == null || !ResolveForwardRefs(state)) return null;
            if (IsEndOfEncoding()) return name;
            if (Consume("Ua9enable_ifI")) return null;
            Node? ret = null;
            if (!state.CtorDtorConversion && state.EndsWithTemplateArgs)
            {
                ret = ParseType();
                if (ret == null) return null;
            }
            var parameters = new List<Node>();
            if (!Consume('v'))
            {
                do
                {
                    var t = ParseType();
                    if (t == null) return null;
                    parameters.Add(t);
                } while (!IsEndOfEncoding() && Look() != 'Q');
            }
            if (Look() == 'Q') return null;
            return new FunctionEncoding(ret, name, parameters, state.Quals, state.Ref);
        }

        private bool ResolveForwardRefs(NameState state)
        {
            for (int i = state.ForwardRefsBegin; i < forwardRefs.Count; i++)
            {
                var r = forwardRefs[i];
                if (templateParams.Count == 0 || templateParams[0] is not { } level || r.Index >= level.Count) return false;
                r.Target = level[r.Index];
            }
            forwardRefs.RemoveRange(state.ForwardRefsBegin, forwardRefs.Count - state.ForwardRefsBegin);
            return true;
        }

        private Node? ParseSpecialName()
        {
            if (Consume("TV")) return Prefixed("vtable for ", ParseType());
            if (Consume("TT")) return Prefixed("VTT for ", ParseType());
            if (Consume("TI")) return Prefixed("typeinfo for ", ParseType());
            if (Consume("TS")) return Prefixed("typeinfo name for ", ParseType());
            if (Consume("Tc"))
            {
                if (!ParseCallOffset() || !ParseCallOffset()) return null;
                return Prefixed("covariant return thunk to ", ParseEncoding());
            }
            if (Consume("TC"))
            {
                var first = ParseType();
                if (first == null) return null;
                if (ParseNumber(true).Length == 0 || !Consume('_')) return null;
                var second = ParseType();
                return second == null ? null : new CtorVtableSpecialName(second, first);
            }
            if (Consume("TW")) return Prefixed("thread-local wrapper routine for ", ParseName(null));
            if (Consume("TH")) return Prefixed("thread-local initialization routine for ", ParseName(null));
            if (Consume("TA")) return Prefixed("template parameter object for ", ParseTemplateArg());
            if (Consume('T'))
            {
                bool isVirtual = Look() == 'v';
                if (!ParseCallOffset()) return null;
                return Prefixed(isVirtual ? "virtual thunk to " : "non-virtual thunk to ", ParseEncoding());
            }
            if (Consume("GV")) return Prefixed("guard variable for ", ParseName(null));
            if (Consume("GR"))
            {
                var name = ParseName(null);
                if (name == null) return null;
                // [<seq-id>] _
                while (char.IsAsciiDigit(Look()) || char.IsAsciiLetterUpper(Look())) pos++;
                if (!Consume('_')) return null;
                return new SpecialName("reference temporary for ", name);
            }
            if (Consume("GA")) return Prefixed("transaction clone for ", ParseEncoding());
            if (Consume("GTt")) return Prefixed("transaction clone for ", ParseEncoding());
            return null;

            static Node? Prefixed(string prefix, Node? child) => child == null ? null : new SpecialName(prefix, child);
        }

        // <call-offset> ::= h <nv-offset> _ | v <v-offset> _
        private bool ParseCallOffset()
        {
            if (Consume('h')) return ParseNumber(true).Length > 0 && Consume('_');
            if (Consume('v')) return ParseNumber(true).Length > 0 && Consume('_') && ParseNumber(true).Length > 0 && Consume('_');
            return false;
        }

        private Node? ParseName(NameState? state)
        {
            Enter();
            try
            {
                if (Look() == 'N') return ParseNestedName(state);
                if (Look() == 'Z') return ParseLocalName(state);
                var result = ParseUnscopedName(state, out bool isSubst);
                if (result == null) return null;
                if (Look() == 'I')
                {
                    if (!isSubst) subs.Add(result);
                    var args = ParseTemplateArgs(state != null);
                    if (args == null) return null;
                    if (state != null) state.EndsWithTemplateArgs = true;
                    return new NameWithTemplateArgs(result, args);
                }
                return isSubst ? null : result;
            }
            finally { depth--; }
        }

        private Node? ParseLocalName(NameState? state)
        {
            if (!Consume('Z')) return null;
            var encoding = ParseEncoding();
            if (encoding == null || !Consume('E')) return null;
            if (Consume('d'))
            {
                ParseNumber(true);
                if (!Consume('_')) return null;
                var n = ParseName(state);
                return n == null ? null : new LocalName(encoding, n);
            }
            if (Consume('s'))
            {
                ParseDiscriminator();
                return new LocalName(encoding, new NameNode("string literal"));
            }
            var entity = ParseName(state);
            if (entity == null) return null;
            ParseDiscriminator();
            return new LocalName(encoding, entity);
        }

        private void ParseDiscriminator()
        {
            if (Look() == '_')
            {
                if (char.IsAsciiDigit(Look(1))) pos += 2;
                else if (Look(1) == '_')
                {
                    int t = pos + 2;
                    while (t < s.Length && char.IsAsciiDigit(s[t])) t++;
                    if (t < s.Length && s[t] == '_') pos = t + 1;
                }
            }
            else if (char.IsAsciiDigit(Look()))
            {
                int t = pos + 1;
                while (t < s.Length && char.IsAsciiDigit(s[t])) t++;
                if (t == s.Length) pos = t;
            }
        }

        private Node? ParseUnscopedName(NameState? state, out bool isSubst)
        {
            isSubst = false;
            bool std = Consume("St");
            Node? result = null;
            if (Look() == 'S')
            {
                var sub = ParseSubstitution();
                if (sub == null || std) return null;
                result = sub;
                isSubst = true;
                return result;
            }
            result = ParseUnqualifiedName(state, null);
            return result != null && std ? new StdQualifiedName(result) : result;
        }

        private Node? ParseNestedName(NameState? state)
        {
            if (!Consume('N')) return null;
            var quals = ParseCv();
            if (state != null) state.Quals = quals;
            if (Consume('O')) { if (state != null) state.Ref = RefQualifier.RValue; }
            else if (Consume('R')) { if (state != null) state.Ref = RefQualifier.LValue; }

            Node? soFar = null;
            while (!Consume('E'))
            {
                if (state != null) state.EndsWithTemplateArgs = false;
                if (Look() == 'T')
                {
                    if (soFar != null) return null;
                    soFar = ParseTemplateParam();
                }
                else if (Look() == 'I')
                {
                    if (soFar == null || soFar is NameWithTemplateArgs) return null;
                    var args = ParseTemplateArgs(state != null);
                    if (args == null) return null;
                    if (state != null) state.EndsWithTemplateArgs = true;
                    soFar = new NameWithTemplateArgs(soFar, args);
                }
                else if (Look() == 'D' && Look(1) is 't' or 'T')
                {
                    if (soFar != null) return null;
                    soFar = ParseDecltype();
                }
                else
                {
                    if (Look() == 'S')
                    {
                        Node? sub;
                        if (Look(1) == 't')
                        {
                            pos += 2;
                            sub = new NameNode("std");
                        }
                        else sub = ParseSubstitution();
                        if (sub == null || soFar != null) return null;
                        soFar = sub;
                        continue;
                    }
                    soFar = ParseUnqualifiedName(state, soFar);
                }
                if (soFar == null) return null;
                subs.Add(soFar);
                Consume('M');
            }
            if (soFar == null || subs.Count == 0) return null;
            subs.RemoveAt(subs.Count - 1);
            return soFar;
        }

        private Node? ParseUnqualifiedName(NameState? state, Node? scope)
        {
            Consume('L');
            Node? result;
            char c = Look();
            if (char.IsAsciiDigit(c)) result = ParseSourceName();
            else if (c == 'U') result = ParseUnnamedTypeName(state);
            else if (Consume("DC"))
            {
                var names = new List<Node>();
                do
                {
                    var n = ParseSourceName();
                    if (n == null) return null;
                    names.Add(n);
                } while (!Consume('E'));
                result = new StructuredBinding(names);
            }
            else if (c is 'C' or 'D')
            {
                if (scope == null) return null;
                result = ParseCtorDtorName(ref scope, state);
            }
            else result = ParseOperatorName(state);
            if (result != null) result = ParseAbiTags(result);
            if (result != null && scope != null) result = new NestedName(scope, result);
            return result;
        }

        private sealed class StructuredBinding(IReadOnlyList<Node> names) : Node
        {
            public override void Left(Output o) { o.Add('['); PrintList(o, names); o.Add(']'); }
        }

        private Node? ParseSourceName()
        {
            var name = ParseBareSourceName();
            if (name == null) return null;
            return new NameNode(name.StartsWith("_GLOBAL__N", StringComparison.Ordinal) ? "(anonymous namespace)" : name);
        }

        private Node ParseAbiTags(Node node)
        {
            while (Consume('B'))
            {
                var tag = ParseBareSourceName();
                if (tag == null) return node;
                node = new AbiTagged(node, tag);
            }
            return node;
        }

        private Node? ParseCtorDtorName(ref Node scope, NameState? state)
        {
            if (scope is SpecialSubstitution special) scope = new SpecialSubstitution(special.Kind, expanded: true);
            if (Consume('C'))
            {
                bool inherited = Consume('I');
                if (Look() is not ('1' or '2' or '3' or '4' or '5')) return null;
                pos++;
                if (state != null) state.CtorDtorConversion = true;
                if (inherited && ParseName(state) == null) return null;
                return new CtorDtorName(scope, false);
            }
            if (Look() == 'D' && Look(1) is '0' or '1' or '2' or '4' or '5')
            {
                pos += 2;
                if (state != null) state.CtorDtorConversion = true;
                return new CtorDtorName(scope, true);
            }
            return null;
        }

        private Node? ParseUnnamedTypeName(NameState? state)
        {
            if (state != null) templateParams.Clear();
            if (Consume("Ut"))
            {
                var count = ParseNumber();
                return Consume('_') ? new UnnamedTypeName(count) : null;
            }
            if (Consume("Ul"))
            {
                int savedLevel = lambdaParamsLevel;
                lambdaParamsLevel = templateParams.Count;
                templateParams.Add([]);
                try
                {
                    var templateDecls = new List<Node>();
                    while (Look() == 'T' && Look(1) is 'y' or 'n' or 't' or 'p')
                    {
                        var decl = ParseTemplateParamDecl(templateParams[^1]!);
                        if (decl == null) return null;
                        templateDecls.Add(decl);
                    }
                    if (templateDecls.Count == 0) templateParams.RemoveAt(templateParams.Count - 1);
                    var parameters = new List<Node>();
                    if (!Consume("vE"))
                    {
                        do
                        {
                            var p = ParseType();
                            if (p == null) return null;
                            parameters.Add(p);
                        } while (Look() != 'E' && Look() != 'Q' && !AtEnd);
                        if (!Consume('E')) return null;
                    }
                    var count = ParseNumber();
                    return Consume('_') ? new ClosureTypeName(templateDecls, parameters, count) : null;
                }
                finally
                {
                    if (templateParams.Count > lambdaParamsLevel) templateParams.RemoveRange(lambdaParamsLevel, templateParams.Count - lambdaParamsLevel);
                    lambdaParamsLevel = savedLevel;
                }
            }
            if (Consume("Ub"))
            {
                ParseNumber();
                return Consume('_') ? new NameNode("'block-literal'") : null;
            }
            return null;
        }

        /// <summary>An explicit lambda template parameter (Ty, Tn type, Tt, Tp): named $T, $N, $TT in declaration order.</summary>
        private Node? ParseTemplateParamDecl(List<Node> level)
        {
            string NewName(string prefix)
            {
                int index = level.Count;
                var name = new NameNode(index == 0 ? prefix : prefix + (index - 1));
                level.Add(name);
                return name.Name;
            }
            if (Consume("Ty")) return new NameNode("typename " + NewName("$T"));
            if (Consume("Tn"))
            {
                var name = NewName("$N");
                var type = ParseType();
                return type == null ? null : new NameNode(type + " " + name);
            }
            return null;
        }

        private Node? ParseSubstitution()
        {
            if (!Consume('S')) return null;
            if (Look() is >= 'a' and <= 'z')
            {
                SpecialSubstitutionKind kind;
                switch (Look())
                {
                    case 'a': kind = SpecialSubstitutionKind.Allocator; break;
                    case 'b': kind = SpecialSubstitutionKind.BasicString; break;
                    case 's': kind = SpecialSubstitutionKind.String; break;
                    case 'i': kind = SpecialSubstitutionKind.IStream; break;
                    case 'o': kind = SpecialSubstitutionKind.OStream; break;
                    case 'd': kind = SpecialSubstitutionKind.IOStream; break;
                    default: return null;
                }
                pos++;
                Node special = new SpecialSubstitution(kind, false);
                var tagged = ParseAbiTags(special);
                if (tagged != special) subs.Add(tagged);
                return tagged;
            }
            if (Consume('_')) return subs.Count > 0 ? subs[0] : null;
            long index = 0;
            if (!char.IsAsciiDigit(Look()) && !char.IsAsciiLetterUpper(Look())) return null;
            while (char.IsAsciiDigit(Look()) || char.IsAsciiLetterUpper(Look()))
            {
                char c = s[pos++];
                index = index * 36 + (char.IsAsciiDigit(c) ? c - '0' : c - 'A' + 10);
                if (index > MaxLength) return null;
            }
            index++;
            if (!Consume('_') || index >= subs.Count) return null;
            return subs[(int)index];
        }

        private Node? ParseTemplateParam()
        {
            if (!Consume('T')) return null;
            long level = 0;
            if (Consume('L'))
            {
                if (!ParsePositive(out level)) return null;
                level++;
                if (!Consume('_')) return null;
            }
            long index = 0;
            if (!Consume('_'))
            {
                if (!ParsePositive(out index)) return null;
                index++;
                if (!Consume('_')) return null;
            }
            if (permitForwardRefs && level == 0)
            {
                var forward = new ForwardTemplateReference((int)index);
                forwardRefs.Add(forward);
                return forward;
            }
            if (level >= templateParams.Count || templateParams[(int)level] is not { } list || index >= list.Count)
            {
                if (lambdaParamsLevel == level && level <= templateParams.Count)
                {
                    if (level == templateParams.Count) templateParams.Add(null);
                    return new NameNode("auto");
                }
                return null;
            }
            return list[(int)index];
        }

        private TemplateArgs? ParseTemplateArgs(bool tagTemplates = false)
        {
            if (!Consume('I')) return null;
            if (tagTemplates)
            {
                templateParams.Clear();
                outerParams = [];
                templateParams.Add(outerParams);
            }
            var args = new List<Node>();
            while (!Consume('E'))
            {
                if (AtEnd) return null;
                if (!tagTemplates)
                {
                    var arg = ParseTemplateArg();
                    if (arg == null) return null;
                    args.Add(arg);
                    continue;
                }
                var saved = templateParams;
                templateParams = [.. saved];
                var tagged = ParseTemplateArg();
                templateParams = saved;
                if (tagged == null) return null;
                args.Add(tagged);
                outerParams.Add(tagged is TemplateArgumentPack pack ? new ParameterPack(pack.Elements) : tagged);
            }
            return new TemplateArgs(args);
        }

        private Node? ParseTemplateArg()
        {
            Enter();
            try
            {
                switch (Look())
                {
                    case 'X':
                    {
                        pos++;
                        var e = ParseExpr();
                        return e != null && Consume('E') ? e : null;
                    }
                    case 'J':
                    {
                        pos++;
                        var elements = new List<Node>();
                        while (!Consume('E'))
                        {
                            if (AtEnd) return null;
                            var a = ParseTemplateArg();
                            if (a == null) return null;
                            elements.Add(a);
                        }
                        return new TemplateArgumentPack(elements);
                    }
                    case 'L':
                        if (Look(1) == 'Z')
                        {
                            pos += 2;
                            var arg = ParseEncoding();
                            return arg != null && Consume('E') ? arg : null;
                        }
                        return ParseExprPrimary();
                    default:
                        return ParseType();
                }
            }
            finally { depth--; }
        }

        private Node? ParseDecltype()
        {
            if (!Consume('D') || !(Consume('t') || Consume('T'))) return null;
            var e = ParseExpr();
            return e != null && Consume('E') ? new EnclosingExpr("decltype(", e) : null;
        }

        private static readonly Dictionary<char, string> Builtins = new()
        {
            ['v'] = "void", ['w'] = "wchar_t", ['b'] = "bool", ['c'] = "char", ['a'] = "signed char", ['h'] = "unsigned char", ['s'] = "short",
            ['t'] = "unsigned short", ['i'] = "int", ['j'] = "unsigned int", ['l'] = "long", ['m'] = "unsigned long", ['x'] = "long long",
            ['y'] = "unsigned long long", ['n'] = "__int128", ['o'] = "unsigned __int128", ['f'] = "float", ['d'] = "double", ['e'] = "long double",
            ['g'] = "__float128", ['z'] = "...",
        };

        private static readonly Dictionary<char, string> DBuiltins = new()
        {
            ['d'] = "decimal64", ['e'] = "decimal128", ['f'] = "decimal32", ['h'] = "half", ['i'] = "char32_t", ['s'] = "char16_t", ['u'] = "char8_t",
            ['a'] = "auto", ['c'] = "decltype(auto)", ['n'] = "std::nullptr_t",
        };

        private Node? ParseType()
        {
            Enter();
            try { return ParseTypeCore(); }
            finally { depth--; }
        }

        private Node? ParseTypeCore()
        {
            Node? result;
            char c = Look();
            switch (c)
            {
                case 'r' or 'V' or 'K':
                {
                    int after = 0;
                    if (Look(after) == 'r') after++;
                    if (Look(after) == 'V') after++;
                    if (Look(after) == 'K') after++;
                    if (Look(after) == 'F' || (Look(after) == 'D' && Look(after + 1) is 'o' or 'O' or 'w' or 'x'))
                    {
                        result = ParseFunctionType();
                        break;
                    }
                    result = ParseQualifiedType();
                    break;
                }
                case 'U':
                    result = ParseQualifiedType();
                    break;
                case 'u':
                {
                    pos++;
                    var name = ParseBareSourceName();
                    if (name == null) return null;
                    if (Look() == 'I')
                    {
                        var args = ParseTemplateArgs();
                        if (args == null) return null;
                        result = new NameWithTemplateArgs(new NameNode(name), args);
                    }
                    else result = new NameNode(name);
                    break;
                }
                case 'D':
                    switch (Look(1))
                    {
                        case 'F':
                        {
                            pos += 2;
                            if (Consume("16b")) return new NameNode("std::bfloat16_t");
                            var bits = ParseNumber();
                            if (bits.Length == 0) return null;
                            if (Consume('x')) return new NameNode("_Float" + bits + "x");
                            return Consume('_') ? new NameNode("_Float" + bits) : null;
                        }
                        case 'B' or 'U':
                        {
                            bool signed = Look(1) == 'B';
                            pos += 2;
                            var size = ParseNumber();
                            if (size.Length == 0 || !Consume('_')) return null;
                            return new NameNode((signed ? "_BitInt(" : "unsigned _BitInt(") + size + ")");
                        }
                        case 't' or 'T':
                            result = ParseDecltype();
                            break;
                        case 'v':
                            result = ParseVectorType();
                            break;
                        case 'p':
                        {
                            pos += 2;
                            var child = ParseType();
                            if (child == null) return null;
                            result = new PackExpansion(child);
                            break;
                        }
                        case 'o' or 'O' or 'w' or 'x':
                            result = ParseFunctionType();
                            break;
                        default:
                            if (DBuiltins.TryGetValue(Look(1), out var d))
                            {
                                pos += 2;
                                return new NameNode(d);
                            }
                            return null;
                    }
                    break;
                case 'F':
                    result = ParseFunctionType();
                    break;
                case 'A':
                    result = ParseArrayType();
                    break;
                case 'M':
                {
                    pos++;
                    var cls = ParseType();
                    if (cls == null) return null;
                    var member = ParseType();
                    if (member == null) return null;
                    result = new PointerToMemberType(cls, member);
                    break;
                }
                case 'T':
                {
                    if (Look(1) is 's' or 'u' or 'e')
                    {
                        result = ParseClassEnumType();
                        break;
                    }
                    result = ParseTemplateParam();
                    if (result == null) return null;
                    if (tryTemplateArgs && Look() == 'I')
                    {
                        subs.Add(result);
                        var args = ParseTemplateArgs();
                        if (args == null) return null;
                        result = new NameWithTemplateArgs(result, args);
                    }
                    break;
                }
                case 'P' or 'R' or 'O' or 'C' or 'G':
                {
                    pos++;
                    var child = ParseType();
                    if (child == null) return null;
                    result = c switch
                    {
                        'P' => new PointerType(child),
                        'R' => new ReferenceType(child, false),
                        'O' => new ReferenceType(child, true),
                        'C' => new PostfixType(child, " complex"),
                        _ => new PostfixType(child, " imaginary"),
                    };
                    break;
                }
                case 'S':
                    if (Look(1) != 't')
                    {
                        result = ParseUnscopedName(null, out bool isSubst);
                        if (result == null) return null;
                        if (Look() == 'I' && (!isSubst || tryTemplateArgs))
                        {
                            if (!isSubst) subs.Add(result);
                            var args = ParseTemplateArgs();
                            if (args == null) return null;
                            result = new NameWithTemplateArgs(result, args);
                        }
                        else if (isSubst) return result;
                        break;
                    }
                    result = ParseClassEnumType();
                    break;
                default:
                    if (Builtins.TryGetValue(c, out var builtin))
                    {
                        pos++;
                        return new NameNode(builtin);
                    }
                    result = ParseClassEnumType();
                    break;
            }
            if (result != null) subs.Add(result);
            return result;
        }

        private Node? ParseQualifiedType()
        {
            Enter();
            try { return ParseQualifiedTypeCore(); }
            finally { depth--; }
        }

        private Node? ParseQualifiedTypeCore()
        {
            if (Consume('U'))
            {
                var qualifier = ParseBareSourceName();
                if (qualifier == null) return null;
                if (qualifier.StartsWith("objcproto", StringComparison.Ordinal))
                {
                    // U <length> objcproto <source-name>: an Objective-C protocol qualifier.
                    var inner = new Parser(qualifier["objcproto".Length..]);
                    var protocol = inner.ParseBareSourceName();
                    if (protocol == null) return null;
                    var qualified = ParseQualifiedType();
                    return qualified == null ? null : new ObjCProtoName(qualified, protocol);
                }
                TemplateArgs? args = null;
                if (Look() == 'I')
                {
                    args = ParseTemplateArgs();
                    if (args == null) return null;
                }
                var child = ParseQualifiedType();
                return child == null ? null : new VendorQualified(child, qualifier, args);
            }
            var quals = ParseCv();
            var type = ParseType();
            if (type == null) return null;
            return quals != Cv.None ? new QualifiedType(type, quals) : type;
        }

        private Node? ParseClassEnumType()
        {
            string? elaborated = null;
            if (Consume("Ts")) elaborated = "struct";
            else if (Consume("Tu")) elaborated = "union";
            else if (Consume("Te")) elaborated = "enum";
            var name = ParseName(null);
            if (name == null) return null;
            return elaborated == null ? name : new NameNode(elaborated + " " + name);
        }

        // <function-type> ::= [<CV-qualifiers>] [<exception-spec>] [Dx] F [Y] <bare-function-type> [<ref-qualifier>] E
        private Node? ParseFunctionType()
        {
            var quals = ParseCv();
            Node? exception = null;
            if (Consume("Do")) exception = new NoexceptSpec(null);
            else if (Consume("DO"))
            {
                var e = ParseExpr();
                if (e == null || !Consume('E')) return null;
                exception = new NoexceptSpec(e);
            }
            else if (Consume("Dw"))
            {
                var types = new List<Node>();
                while (!Consume('E'))
                {
                    var t = ParseType();
                    if (t == null) return null;
                    types.Add(t);
                }
                exception = new DynamicExceptionSpec(types);
            }
            Consume("Dx");
            if (!Consume('F')) return null;
            Consume('Y');
            var ret = ParseType();
            if (ret == null) return null;
            var refQual = RefQualifier.None;
            var parameters = new List<Node>();
            while (true)
            {
                if (Consume('E')) break;
                if (Consume('v')) continue;
                if (Consume("RE")) { refQual = RefQualifier.LValue; break; }
                if (Consume("OE")) { refQual = RefQualifier.RValue; break; }
                if (AtEnd) return null;
                var t = ParseType();
                if (t == null) return null;
                parameters.Add(t);
            }
            return new FunctionType(ret, parameters, quals, refQual, exception);
        }

        private Node? ParseArrayType()
        {
            if (!Consume('A')) return null;
            Node? dimension = null;
            if (char.IsAsciiDigit(Look()))
            {
                dimension = new NameNode(ParseNumber());
                if (!Consume('_')) return null;
            }
            else if (!Consume('_'))
            {
                dimension = ParseExpr();
                if (dimension == null || !Consume('_')) return null;
            }
            var element = ParseType();
            return element == null ? null : new ArrayType(element, dimension);
        }

        private Node? ParseVectorType()
        {
            if (!Consume("Dv")) return null;
            if (char.IsAsciiDigit(Look()))
            {
                var dimension = new NameNode(ParseNumber());
                if (!Consume('_')) return null;
                if (Consume('p')) return new VectorType(null!, dimension, true);
                var element = ParseType();
                return element == null ? null : new VectorType(element, dimension, false);
            }
            if (!Consume('_'))
            {
                var dimension = ParseExpr();
                if (dimension == null || !Consume('_')) return null;
                var element = ParseType();
                return element == null ? null : new VectorType(element, dimension, false);
            }
            var e2 = ParseType();
            return e2 == null ? null : new VectorType(e2, null, false);
        }

        private readonly record struct OperatorInfo(string Code, string Name, OperatorKind Kind, Prec Precedence);

        private enum OperatorKind { Binary, Prefix, Postfix, Array, Member, New, Del, Call, CCast, Conditional, NameOnly, CastNamed, OfIdOp }

        private static readonly OperatorInfo[] Operators =
        [
            new("aN", "&=", OperatorKind.Binary, Prec.Assign), new("aS", "=", OperatorKind.Binary, Prec.Assign), new("aa", "&&", OperatorKind.Binary, Prec.AndIf),
            new("ad", "&", OperatorKind.Prefix, Prec.Unary), new("an", "&", OperatorKind.Binary, Prec.And), new("at", "alignof ", OperatorKind.OfIdOp, Prec.Unary),
            new("aw", "co_await", OperatorKind.Prefix, Prec.Unary), new("az", "alignof ", OperatorKind.OfIdOp, Prec.Unary),
            new("cc", "const_cast", OperatorKind.CastNamed, Prec.Postfix), new("cl", "()", OperatorKind.Call, Prec.Postfix),
            new("cm", ",", OperatorKind.Binary, Prec.Comma), new("co", "~", OperatorKind.Prefix, Prec.Unary), new("cv", "<cast>", OperatorKind.CCast, Prec.Cast),
            new("dV", "/=", OperatorKind.Binary, Prec.Assign), new("da", "delete[] ", OperatorKind.Del, Prec.Unary),
            new("dc", "dynamic_cast", OperatorKind.CastNamed, Prec.Postfix), new("de", "*", OperatorKind.Prefix, Prec.Unary),
            new("dl", "delete ", OperatorKind.Del, Prec.Unary), new("ds", ".*", OperatorKind.Member, Prec.PtrMem), new("dt", ".", OperatorKind.Member, Prec.Postfix),
            new("dv", "/", OperatorKind.Binary, Prec.Multiplicative), new("eO", "^=", OperatorKind.Binary, Prec.Assign), new("eo", "^", OperatorKind.Binary, Prec.Xor),
            new("eq", "==", OperatorKind.Binary, Prec.Equality), new("ge", ">=", OperatorKind.Binary, Prec.Relational), new("gt", ">", OperatorKind.Binary, Prec.Relational),
            new("ix", "[]", OperatorKind.Array, Prec.Postfix), new("lS", "<<=", OperatorKind.Binary, Prec.Assign), new("le", "<=", OperatorKind.Binary, Prec.Relational),
            new("ls", "<<", OperatorKind.Binary, Prec.Shift), new("lt", "<", OperatorKind.Binary, Prec.Relational), new("mI", "-=", OperatorKind.Binary, Prec.Assign),
            new("mL", "*=", OperatorKind.Binary, Prec.Assign), new("mi", "-", OperatorKind.Binary, Prec.Additive), new("ml", "*", OperatorKind.Binary, Prec.Multiplicative),
            new("mm", "--", OperatorKind.Postfix, Prec.Postfix), new("na", "new[]", OperatorKind.New, Prec.Unary), new("ne", "!=", OperatorKind.Binary, Prec.Equality),
            new("ng", "-", OperatorKind.Prefix, Prec.Unary), new("nt", "!", OperatorKind.Prefix, Prec.Unary), new("nw", "new", OperatorKind.New, Prec.Unary),
            new("oR", "|=", OperatorKind.Binary, Prec.Assign), new("oo", "||", OperatorKind.Binary, Prec.OrIf), new("or", "|", OperatorKind.Binary, Prec.Ior),
            new("pL", "+=", OperatorKind.Binary, Prec.Assign), new("pl", "+", OperatorKind.Binary, Prec.Additive), new("pm", "->*", OperatorKind.Member, Prec.PtrMem),
            new("pp", "++", OperatorKind.Postfix, Prec.Postfix), new("ps", "+", OperatorKind.Prefix, Prec.Unary), new("pt", "->", OperatorKind.Member, Prec.Postfix),
            new("qu", "?", OperatorKind.Conditional, Prec.Conditional), new("rM", "%=", OperatorKind.Binary, Prec.Assign), new("rS", ">>=", OperatorKind.Binary, Prec.Assign),
            new("rc", "reinterpret_cast", OperatorKind.CastNamed, Prec.Postfix), new("rm", "%", OperatorKind.Binary, Prec.Multiplicative),
            new("rs", ">>", OperatorKind.Binary, Prec.Shift), new("sc", "static_cast", OperatorKind.CastNamed, Prec.Postfix),
            new("ss", "<=>", OperatorKind.Binary, Prec.Spaceship), new("st", "sizeof ", OperatorKind.OfIdOp, Prec.Unary), new("sz", "sizeof ", OperatorKind.OfIdOp, Prec.Unary),
            new("te", "typeid ", OperatorKind.OfIdOp, Prec.Postfix), new("ti", "typeid ", OperatorKind.OfIdOp, Prec.Postfix),
        ];

        private OperatorInfo? ParseOperatorEncoding()
        {
            if (pos + 2 > s.Length) return null;
            var code = s.Substring(pos, 2);
            foreach (var op in Operators)
                if (op.Code == code)
                {
                    pos += 2;
                    return op;
                }
            return null;
        }

        private static bool IsNameable(OperatorInfo op) => op.Kind is not (OperatorKind.CastNamed or OperatorKind.OfIdOp or OperatorKind.CCast or OperatorKind.Conditional) || op.Code == "qu";

        private Node? ParseOperatorName(NameState? state)
        {
            if (Look() == 'c' && Look(1) == 'v')
            {
                pos += 2;
                bool savedTry = tryTemplateArgs, savedPermit = permitForwardRefs;
                tryTemplateArgs = false;
                permitForwardRefs = permitForwardRefs || state != null;
                try
                {
                    var type = ParseType();
                    if (type == null) return null;
                    if (state != null) state.CtorDtorConversion = true;
                    return new ConversionOperatorType(type);
                }
                finally
                {
                    tryTemplateArgs = savedTry;
                    permitForwardRefs = savedPermit;
                }
            }
            if (Look() == 'l' && Look(1) == 'i')
            {
                pos += 2;
                var name = ParseSourceName();
                return name == null ? null : new NameNode("operator\"\" " + name);
            }
            if (Look() == 'v' && char.IsAsciiDigit(Look(1)))
            {
                pos += 2;
                var name = ParseSourceName();
                return name == null ? null : new NameNode("operator " + name);
            }
            int start = pos;
            if (ParseOperatorEncoding() is not { } op || !IsNameable(op))
            {
                pos = start;
                return null;
            }
            string text = op.Kind switch
            {
                OperatorKind.Call => "()",
                OperatorKind.Array => "[]",
                OperatorKind.New or OperatorKind.Del => " " + op.Name.TrimEnd(),
                _ => op.Name,
            };
            return new NameNode("operator" + text);
        }

        // <expr-primary> ::= L <type> <value> E | L <mangled-name> E | ...
        private Node? ParseExprPrimary()
        {
            if (!Consume('L')) return null;
            switch (Look())
            {
                case 'w': pos++; return ParseIntegerLiteral("wchar_t");
                case 'b':
                    if (Consume("b0E")) return new BoolLiteral(false);
                    if (Consume("b1E")) return new BoolLiteral(true);
                    return null;
                case 'c': pos++; return ParseIntegerLiteral("char");
                case 'a': pos++; return ParseIntegerLiteral("signed char");
                case 'h': pos++; return ParseIntegerLiteral("unsigned char");
                case 's': pos++; return ParseIntegerLiteral("short");
                case 't': pos++; return ParseIntegerLiteral("unsigned short");
                case 'i': pos++; return ParseIntegerLiteral("");
                case 'j': pos++; return ParseIntegerLiteral("u");
                case 'l': pos++; return ParseIntegerLiteral("l");
                case 'm': pos++; return ParseIntegerLiteral("ul");
                case 'x': pos++; return ParseIntegerLiteral("ll");
                case 'y': pos++; return ParseIntegerLiteral("ull");
                case 'n': pos++; return ParseIntegerLiteral("__int128");
                case 'o': pos++; return ParseIntegerLiteral("unsigned __int128");
                case 'f': pos++; return ParseFloatLiteral(8, "f");
                case 'd': pos++; return ParseFloatLiteral(16, "");
                case 'e': pos++; return ParseFloatLiteral(16, "L");
                case '_':
                    if (Consume("_Z"))
                    {
                        var e = ParseEncoding();
                        return e != null && Consume('E') ? e : null;
                    }
                    return null;
                case 'D':
                    if (Consume("Dn") && (Consume('0') || true) && Consume('E')) return new NameNode("nullptr");
                    return null;
                case 'T': return null;
                case 'U':
                {
                    if (Look(1) != 'l') return null;
                    var t = ParseUnnamedTypeName(null);
                    return t != null && Consume('E') ? new EnclosingExpr("[]", t, "{...}") : null;
                }
                default:
                {
                    var type = ParseType();
                    if (type == null) return null;
                    var n = ParseNumber(true);
                    if (n.Length == 0 || !Consume('E')) return null;
                    return new EnumLiteral(type, n);
                }
            }
        }

        private Node? ParseIntegerLiteral(string type)
        {
            var n = ParseNumber(true);
            return n.Length > 0 && Consume('E') ? new IntegerLiteral(type, n) : null;
        }

        /// <summary>A float literal: hex bytes of the value (big-endian) printed as printf "%a" with 13 hex digits, as llvm-cxxfilt does.</summary>
        private Node? ParseFloatLiteral(int digits, string suffix)
        {
            if (pos + digits > s.Length) return null;
            var hex = s.Substring(pos, digits);
            foreach (char c in hex) if (!char.IsAsciiHexDigitLower(c) && !char.IsAsciiDigit(c)) return null;
            pos += digits;
            if (!Consume('E')) return null;
            ulong bits = ulong.Parse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            double value = digits == 8 ? BitConverter.Int32BitsToSingle((int)bits) : BitConverter.Int64BitsToDouble((long)bits);
            return new FloatLiteral(HexFloat(value) + suffix);
        }

        private static string HexFloat(double value)
        {
            if (double.IsNaN(value)) return "nan";
            if (double.IsInfinity(value)) return value < 0 ? "-inf" : "inf";
            long bits = BitConverter.DoubleToInt64Bits(value);
            var sb = new StringBuilder();
            if (bits < 0) sb.Append('-');
            int exponent = (int)((bits >> 52) & 0x7FF);
            long mantissa = bits & 0xFFFFFFFFFFFFFL;
            int lead = exponent == 0 ? 0 : 1;
            int e = exponent == 0 ? (mantissa == 0 ? 0 : -1022) : exponent - 1023;
            sb.Append("0x").Append(lead).Append('.').Append(mantissa.ToString("x13", CultureInfo.InvariantCulture)).Append('p');
            sb.Append(e >= 0 ? "+" : "-").Append(Math.Abs(e).ToString(CultureInfo.InvariantCulture));
            return sb.ToString();
        }

        private Node? ParseExpr()
        {
            Enter();
            try { return ParseExprCore(); }
            finally { depth--; }
        }

        private Node? ParseExprCore()
        {
            bool global = Consume("gs");
            switch (Look())
            {
                case 'L': return ParseExprPrimary();
                case 'T': return ParseTemplateParam();
                case 'f':
                    if (Look(1) == 'p' || (Look(1) == 'L' && char.IsAsciiDigit(Look(2)))) return ParseFunctionParam();
                    break;
            }
            if (Consume("sZ"))
            {
                if (Look() == 'T')
                {
                    var p = ParseTemplateParam();
                    return p == null ? null : new EnclosingExpr("sizeof...(", p);
                }
                var fp = ParseFunctionParam();
                return fp == null ? null : new EnclosingExpr("sizeof...(", fp);
            }
            if (Consume("sp"))
            {
                var child = ParseExpr();
                return child == null ? null : new PackExpansion(child);
            }
            if (Consume("tw"))
            {
                var e = ParseExpr();
                return e == null ? null : new PrefixExpr("throw ", e, Prec.Assign);
            }
            if (Consume("tr")) return new NameNode("throw");
            if (Consume("nx"))
            {
                var e = ParseExpr();
                return e == null ? null : new EnclosingExpr("noexcept (", e);
            }
            if (Look() is 's' && Look(1) is 'r')
            {
                pos += 2;
                return ParseUnresolvedName(global, afterSr: true);
            }
            if (char.IsAsciiDigit(Look()) || Look() == 'o' && Look(1) == 'n') return ParseUnresolvedName(global, afterSr: false);

            int start = pos;
            if (ParseOperatorEncoding() is not { } op) return null;
            switch (op.Kind)
            {
                case OperatorKind.Binary:
                {
                    var l = ParseExpr();
                    var r = l == null ? null : ParseExpr();
                    return r == null ? null : new BinaryExpr(l!, op.Name, r, op.Precedence);
                }
                case OperatorKind.Prefix:
                {
                    var e = ParseExpr();
                    return e == null ? null : new PrefixExpr(op.Name, e, op.Precedence);
                }
                case OperatorKind.Postfix:
                {
                    if (Consume('_'))
                    {
                        var pre = ParseExpr();
                        return pre == null ? null : new PrefixExpr(op.Name, pre, op.Precedence);
                    }
                    var e = ParseExpr();
                    return e == null ? null : new PostfixExpr(e, op.Name, op.Precedence);
                }
                case OperatorKind.Array:
                {
                    var a = ParseExpr();
                    var i = a == null ? null : ParseExpr();
                    return i == null ? null : new ArraySubscriptExpr(a!, i);
                }
                case OperatorKind.Member:
                {
                    var l = ParseExpr();
                    var r = l == null ? null : ParseExpr();
                    return r == null ? null : new MemberExpr(l!, op.Name, r);
                }
                case OperatorKind.Call:
                {
                    var callee = ParseExpr();
                    if (callee == null) return null;
                    var args = new List<Node>();
                    while (!Consume('E'))
                    {
                        if (AtEnd) return null;
                        var a = ParseExpr();
                        if (a == null) return null;
                        args.Add(a);
                    }
                    return new CallExpr(callee, args);
                }
                case OperatorKind.CCast:
                {
                    bool savedTry = tryTemplateArgs;
                    tryTemplateArgs = false;
                    var type = ParseType();
                    tryTemplateArgs = savedTry;
                    if (type == null) return null;
                    var exprs = new List<Node>();
                    if (Consume('_'))
                    {
                        while (!Consume('E'))
                        {
                            if (AtEnd) return null;
                            var e = ParseExpr();
                            if (e == null) return null;
                            exprs.Add(e);
                        }
                    }
                    else
                    {
                        var e = ParseExpr();
                        if (e == null) return null;
                        exprs.Add(e);
                    }
                    return new ConversionExpr(type, exprs);
                }
                case OperatorKind.CastNamed:
                {
                    var type = ParseType();
                    var e = type == null ? null : ParseExpr();
                    return e == null ? null : new CastExpr(op.Name, type!, e);
                }
                case OperatorKind.Conditional:
                {
                    var c = ParseExpr();
                    var t = c == null ? null : ParseExpr();
                    var f = t == null ? null : ParseExpr();
                    return f == null ? null : new ConditionalExpr(c!, t!, f);
                }
                case OperatorKind.OfIdOp:
                {
                    // st / at / ti take a type, sz / az / te an expression.
                    Node? operand = op.Code is "st" or "at" or "ti" ? ParseType() : ParseExpr();
                    return operand == null ? null : new EnclosingExpr(op.Name + "(", operand);
                }
                default:
                    pos = start;
                    return null;
            }
        }

        private Node? ParseFunctionParam()
        {
            if (Consume("fp"))
            {
                ParseCv();
                var n = ParseNumber();
                return Consume('_') ? new NameNode("fp" + n) : null;
            }
            if (Consume("fL"))
            {
                if (ParseNumber().Length == 0 || !Consume('p')) return null;
                ParseCv();
                var n = ParseNumber();
                return Consume('_') ? new NameNode("fp" + n) : null;
            }
            return null;
        }

        /// <summary>The common forms of &lt;unresolved-name&gt;: a simple name with optional template args, and sr qualifiers.</summary>
        private Node? ParseUnresolvedName(bool global, bool afterSr)
        {
            Node? result;
            if (Look() == 'N')
            {
                pos++;
                result = ParseUnresolvedType();
                if (result == null) return null;
                if (Look() == 'I')
                {
                    var args = ParseTemplateArgs();
                    if (args == null) return null;
                    result = new NameWithTemplateArgs(result, args);
                }
                while (!Consume('E'))
                {
                    var q = ParseSimpleId();
                    if (q == null) return null;
                    result = new NestedName(result, q);
                }
                var b = ParseBaseUnresolvedName();
                return b == null ? null : new NestedName(result, b);
            }
            if (afterSr && char.IsAsciiDigit(Look()))
            {
                // sr <unresolved-qualifier-level>+ E <base-unresolved-name>
                result = ParseSimpleId();
                while (result != null && !Consume('E'))
                {
                    var q = ParseSimpleId();
                    result = q == null ? null : new NestedName(result, q);
                }
                var b = result == null ? null : ParseBaseUnresolvedName();
                return b == null ? null : new NestedName(result!, b);
            }
            if (char.IsAsciiDigit(Look()) || Look() == 'o' && Look(1) == 'n')
            {
                result = ParseBaseUnresolvedName();
                return result == null ? null : global ? new NameNode("::" + result) : result;
            }
            if (Look() is 'T' or 'D' or 'S')
            {
                result = ParseUnresolvedType();
                if (result == null) return null;
                if (Look() == 'I')
                {
                    var args = ParseTemplateArgs();
                    if (args == null) return null;
                    result = new NameWithTemplateArgs(result, args);
                }
                var b = ParseBaseUnresolvedName();
                return b == null ? null : new NestedName(result, b);
            }
            return null;
        }

        private Node? ParseUnresolvedType()
        {
            if (Look() == 'T')
            {
                var t = ParseTemplateParam();
                if (t != null) subs.Add(t);
                return t;
            }
            if (Look() == 'D')
            {
                var d = ParseDecltype();
                if (d != null) subs.Add(d);
                return d;
            }
            return ParseSubstitution();
        }

        private Node? ParseSimpleId()
        {
            var name = ParseSourceName();
            if (name == null) return null;
            if (Look() == 'I')
            {
                var args = ParseTemplateArgs();
                return args == null ? null : new NameWithTemplateArgs(name, args);
            }
            return name;
        }

        private Node? ParseBaseUnresolvedName()
        {
            if (char.IsAsciiDigit(Look())) return ParseSimpleId();
            if (Consume("dn"))
            {
                Node? d = char.IsAsciiDigit(Look()) ? ParseSimpleId() : ParseUnresolvedType();
                return d == null ? null : new NameNode("~" + d);
            }
            Consume("on");
            var op = ParseOperatorName(null);
            if (op == null) return null;
            if (Look() == 'I')
            {
                var args = ParseTemplateArgs();
                return args == null ? null : new NameWithTemplateArgs(op, args);
            }
            return op;
        }
    }
}
