using System.Text;

namespace NetDecompilerMcp.Native.Msvc;

/// <summary>
/// Recursive-descent parser for Microsoft C++ decorated names, producing the node tree in MsvcDemangler.Nodes.cs.
/// Errors throw <see cref="MangledNameException"/>; recursion depth is capped.
/// </summary>
internal sealed class MsvcParser(string text)
{
    private const int MaxBackrefs = 10;

    /// <summary>Back-reference tables: names ("0".."9" in name position) and parameter types ("0".."9" in parameter position).</summary>
    private sealed class Backrefs
    {
        public readonly List<Identifier> Names = new(MaxBackrefs);
        public readonly List<string> NameKeys = new(MaxBackrefs);
        public readonly List<TypeNode> Parameters = new(MaxBackrefs);
    }

    private readonly string s = text;
    private int pos;
    private int depth;
    private Backrefs refs = new();
    /// <summary>Characters left for rendering back-reference keys; bounds the work on pathological input.</summary>
    private long renderBudget = 4_000_000;

    public bool AtEnd => pos >= s.Length;

    public int Position => pos;

    // ---- cursor ----

    private char Peek(int k = 0) => pos + k < s.Length ? s[pos + k] : '\0';

    private char Next()
    {
        if (pos >= s.Length) Fail("unexpected end of name");
        return s[pos++];
    }

    private bool StartsWith(string prefix) => s.AsSpan(pos).StartsWith(prefix, StringComparison.Ordinal);

    private bool Consume(char c)
    {
        if (Peek() != c || AtEnd) return false;
        pos++;
        return true;
    }

    private bool Consume(string prefix)
    {
        if (!StartsWith(prefix)) return false;
        pos += prefix.Length;
        return true;
    }

    private void Expect(char c)
    {
        if (!Consume(c)) Fail($"expected '{c}'");
    }

    private bool StartsWithDigit => char.IsAsciiDigit(Peek());

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private void Fail(string message) => throw new MangledNameException(message, pos);

    private void Enter()
    {
        if (++depth > MsvcDemangler.MaxDepth) Fail("nesting too deep");
    }

    private void Leave() => depth--;

    // ---- symbols ----

    /// <summary>A complete symbol: "?name...", "??@md5@", or a type descriptor name ".?AV...".</summary>
    public SymbolNode ParseSymbol()
    {
        Enter();
        try
        {
            if (Peek() == '.') return ParseTypeinfoName();
            if (StartsWith("??@")) return ParseMd5();
            Expect('?');
            return ParseSpecialIntrinsic() ?? ParseDeclarator();
        }
        finally { Leave(); }
    }

    private SymbolNode ParseTypeinfoName()
    {
        pos++;
        var type = ParseType(QualMode.Result);
        if (!AtEnd) Fail("trailing characters after type");
        return new VariableSymbol { Type = type, Name = Synthesize("`RTTI Type Descriptor Name'"), SymbolKind = MsvcSymbolKind.TypeName };
    }

    /// <summary>"??@" + hash + "@": not reversible; the name is printed as is. "??_R4@" may follow for a complete object locator.</summary>
    private SymbolNode ParseMd5()
    {
        int start = pos;
        int end = s.IndexOf('@', pos + 3);
        if (end < 0) Fail("unterminated MD5 name");
        pos = end + 1;
        Consume("??_R4@");
        return new Md5Symbol(s[start..pos]);
    }

    private static QualifiedName Synthesize(string name) => new([new NamedIdentifier(name)]);

    private SymbolNode? ParseSpecialIntrinsic()
    {
        if (Consume("?_7")) return ParseSpecialTable("`vftable'", MsvcSymbolKind.SpecialTable);
        if (Consume("?_8")) return ParseSpecialTable("`vbtable'", MsvcSymbolKind.SpecialTable);
        if (Consume("?_9")) return ParseVcallThunk();
        if (Consume("?_B")) return ParseLocalStaticGuard(thread: false);
        if (Consume("?_C")) return ParseStringLiteral();
        if (Consume("?_R0")) return ParseRttiTypeDescriptor();
        if (Consume("?_R1")) return ParseRttiBaseClassDescriptor();
        if (Consume("?_R2")) return ParseUntypedVariable("`RTTI Base Class Array'", MsvcSymbolKind.RttiBaseClassArray);
        if (Consume("?_R3")) return ParseUntypedVariable("`RTTI Class Hierarchy Descriptor'", MsvcSymbolKind.RttiClassHierarchyDescriptor);
        if (Consume("?_R4")) return ParseSpecialTable("`RTTI Complete Object Locator'", MsvcSymbolKind.SpecialTable);
        if (Consume("?_S")) return ParseSpecialTable("`local vftable'", MsvcSymbolKind.SpecialTable);
        if (Consume("?__E")) return ParseInitFiniStub(destructor: false);
        if (Consume("?__F")) return ParseInitFiniStub(destructor: true);
        if (Consume("?__J")) return ParseLocalStaticGuard(thread: true);
        if (StartsWith("?_A")) Fail("`typeof' names are not supported");
        if (StartsWith("?_P")) Fail("`udt returning' names are not supported");
        return null;
    }

    private SymbolNode ParseSpecialTable(string name, MsvcSymbolKind kind)
    {
        var table = new SpecialTableSymbol { SymbolKind = kind, Name = ParseNameScopeChain(new NamedIdentifier(name)) };
        char c = Next();
        if (c != '6' && c != '7') Fail("expected '6' or '7' after a table name");
        table.Quals = ParseQualifiers().Quals;
        while (!Consume('@'))
        {
            if (AtEnd) Fail("unterminated table target list");
            table.Targets.Add(ParseFullyQualifiedTypeName());
        }
        return table;
    }

    private SymbolNode ParseVcallThunk()
    {
        var id = new VcallThunkIdentifier();
        var name = ParseNameScopeChain(id);
        if (!Consume("$B")) Fail("expected '$B' in vcall thunk");
        id.Offset = ParseUnsigned();
        Expect('A');
        var sig = new ThunkType { Class = FuncClass.NoParameterList, CallingConvention = ParseCallingConvention() };
        return new FunctionSymbol { Name = name, Signature = sig };
    }

    private SymbolNode ParseLocalStaticGuard(bool thread)
    {
        var id = new LocalStaticGuardIdentifier(thread);
        var guard = new LocalStaticGuardVariable { Name = ParseNameScopeChain(id) };
        if (Consume("4IA")) guard.IsVisible = false;
        else if (Consume('5')) guard.IsVisible = true;
        else Fail("expected '4IA' or '5' after a local static guard");
        if (!AtEnd) id.ScopeIndex = ParseUnsigned();
        return guard;
    }

    private SymbolNode ParseRttiTypeDescriptor()
    {
        var type = ParseType(QualMode.Result);
        if (!Consume("@8")) Fail("expected '@8' after RTTI type descriptor type");
        return new VariableSymbol { Type = type, Name = Synthesize("`RTTI Type Descriptor'"), SymbolKind = MsvcSymbolKind.RttiTypeDescriptor };
    }

    private SymbolNode ParseRttiBaseClassDescriptor()
    {
        var id = new RttiBaseClassDescriptorIdentifier
        {
            NonVirtualOffset = ParseSigned(),
            VBPtrOffset = ParseSigned(),
            VBTableOffset = ParseSigned(),
            Flags = ParseSigned(),
        };
        var name = ParseNameScopeChain(id);
        Expect('8');
        return new VariableSymbol { Name = name, SymbolKind = MsvcSymbolKind.RttiBaseClassDescriptor };
    }

    private SymbolNode ParseUntypedVariable(string name, MsvcSymbolKind kind)
    {
        var qn = ParseNameScopeChain(new NamedIdentifier(name));
        Expect('8');
        return new VariableSymbol { Name = qn, SymbolKind = kind };
    }

    /// <summary>"??__E" / "??__F": the compiler-generated function that constructs or destroys a global.</summary>
    private SymbolNode ParseInitFiniStub(bool destructor)
    {
        var id = new DynamicStructorIdentifier(destructor);
        bool knownStaticMember = Consume('?');
        var symbol = ParseDeclarator();
        FunctionSymbol function;
        if (symbol is VariableSymbol variable)
        {
            id.Variable = variable;
            for (int i = 0; i < (knownStaticMember ? 2 : 1); i++)
                Expect('@');
            function = ParseFunctionEncoding();
        }
        else
        {
            if (knownStaticMember) Fail("expected a variable in a dynamic initializer");
            function = (FunctionSymbol)symbol;
            id.Name = symbol.Name;
        }
        function.Name = new QualifiedName([id]);
        return function;
    }

    private SymbolNode ParseDeclarator()
    {
        var name = ParseFullyQualifiedSymbolName();
        var symbol = ParseEncodedSymbol();
        symbol.Name = name;
        if (name.Last is ConversionOperatorIdentifier conversion)
        {
            if (symbol is not FunctionSymbol { Signature.ReturnType: { } target } function)
                throw new MangledNameException("conversion operator without a target type", pos);
            target.Quals |= function.Signature.DroppedReturnQuals;
            conversion.Target = target;
        }
        return symbol;
    }

    private SymbolNode ParseEncodedSymbol()
    {
        // C++/CLI per-appdomain data
        Consume("$$Q");
        if (StartsWithDigit && Peek() != '9')
        {
            var sc = Next() switch
            {
                '0' => StorageClass.PrivateStatic,
                '1' => StorageClass.ProtectedStatic,
                '2' => StorageClass.PublicStatic,
                '3' => StorageClass.Global,
                '4' => StorageClass.FunctionLocalStatic,
                _ => (StorageClass)(-1),
            };
            if ((int)sc < 0) { pos--; Fail("unsupported storage class"); }
            return ParseVariableEncoding(sc);
        }
        return ParseFunctionEncoding();
    }

    private VariableSymbol ParseVariableEncoding(StorageClass sc)
    {
        var v = new VariableSymbol { StorageClass = sc, Type = ParseType(QualMode.Drop) };
        if (v.Type is PointerType pointer)
        {
            // The trailing qualifiers are the pointer object's own: "PBDB" is "char const * const".
            pointer.StoragePtr64 = (ParsePointerExtQualifiers() & Quals.Ptr64) != 0;
            var (cv, _) = ParseQualifiers();
            if (pointer.ClassParent != null)
                ParseFullyQualifiedTypeName();
            pointer.Quals = (pointer.Quals & ~(Quals.Const | Quals.Volatile)) | cv;
        }
        else
            v.Type!.Quals = ParseQualifiers().Quals;
        return v;
    }

    private FunctionSymbol ParseFunctionEncoding()
    {
        var extra = FuncClass.None;
        if (Consume("$$J0")) extra = FuncClass.ExternC;
        Consume("$$F");
        Consume("$$H");
        var fc = ParseFunctionClass() | extra;
        ThunkType? thunk = null;
        if ((fc & FuncClass.StaticThisAdjust) != 0)
            thunk = new ThunkType { StaticOffset = ParseSigned() };
        else if ((fc & FuncClass.VirtualThisAdjust) != 0)
        {
            thunk = new ThunkType();
            if ((fc & FuncClass.VirtualThisAdjustEx) != 0)
            {
                thunk.VBPtrOffset = ParseSigned();
                thunk.VBOffsetOffset = ParseSigned();
            }
            thunk.VtordispOffset = ParseSigned();
            thunk.StaticOffset = ParseSigned();
        }
        FunctionType sig = thunk ?? new FunctionType();
        if ((fc & FuncClass.NoParameterList) == 0)
            ParseFunctionType(sig, hasThisQuals: (fc & (FuncClass.Global | FuncClass.Static)) == 0);
        sig.Class = fc;
        return new FunctionSymbol { Signature = sig };
    }

    private FuncClass ParseFunctionClass()
    {
        const FuncClass Pri = FuncClass.Private, Pro = FuncClass.Protected, Pub = FuncClass.Public, V = FuncClass.Virtual,
            F = FuncClass.Far, S = FuncClass.Static, Adj = FuncClass.StaticThisAdjust;
        char c = Next();
        switch (c)
        {
            case '9': return FuncClass.ExternC | FuncClass.NoParameterList;
            case 'A': return Pri;
            case 'B': return Pri | F;
            case 'C': return Pri | S;
            case 'D': return Pri | S | F;
            case 'E': return Pri | V;
            case 'F': return Pri | V | F;
            case 'G': return Pri | V | Adj;
            case 'H': return Pri | V | Adj | F;
            case 'I': return Pro;
            case 'J': return Pro | F;
            case 'K': return Pro | S;
            case 'L': return Pro | S | F;
            case 'M': return Pro | V;
            case 'N': return Pro | V | F;
            case 'O': return Pro | V | Adj;
            case 'P': return Pro | V | Adj | F;
            case 'Q': return Pub;
            case 'R': return Pub | F;
            case 'S': return Pub | S;
            case 'T': return Pub | S | F;
            case 'U': return Pub | V;
            case 'V': return Pub | V | F;
            case 'W': return Pub | V | Adj;
            case 'X': return Pub | V | Adj | F;
            case 'Y': return FuncClass.Global;
            case 'Z': return FuncClass.Global | F;
            case '$':
            {
                var vflag = FuncClass.VirtualThisAdjust;
                if (Consume('R')) vflag |= FuncClass.VirtualThisAdjustEx;
                switch (Next())
                {
                    case '0': return Pri | V | vflag;
                    case '1': return Pri | V | vflag | F;
                    case '2': return Pro | V | vflag;
                    case '3': return Pro | V | vflag | F;
                    case '4': return Pub | V | vflag;
                    case '5': return Pub | V | vflag | F;
                }
                pos--;
                Fail("unknown vtordisp function class");
                break;
            }
        }
        pos--;
        Fail($"unknown function class '{c}'");
        return default;
    }

    private void ParseFunctionType(FunctionType fn, bool hasThisQuals)
    {
        Enter();
        if (hasThisQuals)
        {
            fn.Quals = ParsePointerExtQualifiers();
            Consume("$A"); // C++/CX ref class member
            if (Consume('G')) fn.RefQualifier = Affinity.Reference;
            else if (Consume('H')) fn.RefQualifier = Affinity.RValueReference;
            fn.Quals |= ParseQualifiers().Quals;
        }
        fn.CallingConvention = ParseCallingConvention();
        // '@': structors have no declared return type
        if (!Consume('@'))
        {
            fn.ReturnType = ParseType(QualMode.Result);
            // top-level cv of a returned pointer is not part of the signature
            if (fn.ReturnType is PointerType returned)
            {
                fn.DroppedReturnQuals = returned.Quals & (Quals.Const | Quals.Volatile);
                returned.Quals &= ~(Quals.Const | Quals.Volatile);
            }
        }
        fn.Parameters = ParseParameterList(out fn.IsVariadic);
        if (Consume("_E")) fn.IsNoexcept = true;
        else if (!Consume('Z')) Fail("expected 'Z' (throw specification)");
        Leave();
    }

    private string ParseCallingConvention()
    {
        char c = Next();
        switch (c)
        {
            case 'A': case 'B': return "__cdecl";
            case 'C': case 'D': return "__pascal";
            case 'E': case 'F': return "__thiscall";
            case 'G': case 'H': return "__stdcall";
            case 'I': case 'J': return "__fastcall";
            case 'M': case 'N': return "__clrcall";
            case 'O': case 'P': return "__eabi";
            case 'Q': return "__vectorcall";
            case 'S': return "__attribute__((__swiftcall__))";
            case 'W': return "__attribute__((__swiftasynccall__))";
        }
        pos--;
        Fail($"unknown calling convention '{c}'");
        return "";
    }

    private List<TypeNode>? ParseParameterList(out bool variadic)
    {
        variadic = false;
        if (Consume('X')) return null;
        var list = new List<TypeNode>();
        while (!AtEnd && Peek() != '@' && Peek() != 'Z')
        {
            if (list.Count > 1000) Fail("too many parameters");
            if (StartsWithDigit)
            {
                int n = Peek() - '0';
                if (n >= refs.Parameters.Count) Fail("parameter back-reference out of range");
                pos++;
                list.Add(refs.Parameters[n]);
                continue;
            }
            int start = pos;
            var type = ParseType(QualMode.Drop);
            // single-character types are not memorized
            if (refs.Parameters.Count < MaxBackrefs && pos - start > 1)
                refs.Parameters.Add(type);
            list.Add(type);
        }
        if (Consume('@')) return list;
        if (Consume('Z')) { variadic = true; return list; }
        Fail("unterminated parameter list");
        return null;
    }

    // ---- names ----

    private QualifiedName ParseFullyQualifiedSymbolName()
    {
        var id = ParseUnqualifiedSymbolName(memorize: true);
        var qn = ParseNameScopeChain(id);
        if (id is StructorIdentifier structor)
        {
            if (qn.Components.Count < 2) Fail("constructor or destructor outside a class");
            structor.Class = qn.Components[^2];
        }
        return qn;
    }

    private QualifiedName ParseFullyQualifiedTypeName()
    {
        var id = ParseUnqualifiedTypeName(memorize: true);
        return ParseNameScopeChain(id);
    }

    private Identifier ParseUnqualifiedSymbolName(bool memorize)
    {
        if (StartsWithDigit) return ParseBackrefName();
        if (TryParseGuardName() is { } guard) return guard;
        if (Consume("?$")) return ParseTemplateInstantiation(asScope: false);
        if (Consume('?')) return ParseFunctionIdentifierCode();
        return ParseSimpleName(memorize);
    }

    private Identifier ParseUnqualifiedTypeName(bool memorize)
    {
        if (StartsWithDigit) return ParseBackrefName();
        if (Consume("?$")) return ParseTemplateInstantiation(asScope: true);
        return ParseSimpleName(memorize);
    }

    /// <summary>"?$TSS0@" / "?$S1@": thread-safe static and local static guard variables, named "$TSS0" / "$S1".</summary>
    private Identifier? TryParseGuardName()
    {
        int p = pos + 2;
        if (!StartsWith("?$")) return null;
        if (s.AsSpan(p).StartsWith("TSS", StringComparison.Ordinal)) p += 3;
        else if (p < s.Length && s[p] == 'S') p += 1;
        else return null;
        int digits = p;
        while (p < s.Length && char.IsAsciiDigit(s[p])) p++;
        if (p == digits || p >= s.Length || s[p] != '@') return null;
        var name = "$" + s[(pos + 2)..p];
        pos = p + 1;
        Memorize(new NamedIdentifier(name), name);
        return new NamedIdentifier(name);
    }

    private QualifiedName ParseNameScopeChain(Identifier last)
    {
        Enter();
        var components = new List<Identifier> { last };
        while (!Consume('@'))
        {
            if (AtEnd) Fail("unterminated qualified name");
            components.Insert(0, ParseNameScopePiece());
        }
        Leave();
        return new QualifiedName(components);
    }

    private Identifier ParseNameScopePiece()
    {
        if (StartsWithDigit) return ParseBackrefName();
        if (Consume("?$")) return ParseTemplateInstantiation(asScope: true);
        if (StartsWith("?A")) return ParseAnonymousNamespace();
        if (Consume("?Q")) return new InterfaceScopeIdentifier(ParseFullyQualifiedTypeName());
        if (StartsWithLocalScope()) return ParseLocallyScopedName();
        return ParseSimpleName(memorize: true);
    }

    private Identifier ParseBackrefName()
    {
        int n = Next() - '0';
        if (n >= refs.Names.Count) { pos--; Fail("name back-reference out of range"); }
        return new BackrefIdentifier(refs.Names[n]);
    }

    /// <summary>Adds a name to the back-reference table unless it is full or the same text is already there.</summary>
    private void Memorize(Identifier id, string? key = null)
    {
        if (refs.Names.Count >= MaxBackrefs) return;
        if (key == null)
        {
            key = id.Render();
            renderBudget -= key.Length;
            if (renderBudget < 0) Fail("name too complex");
        }
        if (refs.NameKeys.Contains(key)) return;
        refs.Names.Add(id);
        refs.NameKeys.Add(key);
    }

    private Identifier ParseSimpleName(bool memorize)
    {
        var name = ParseSimpleString();
        // the table gets its own node: the returned one may still receive template arguments
        if (memorize) Memorize(new NamedIdentifier(name), name);
        return new NamedIdentifier(name);
    }

    private string ParseSimpleString()
    {
        int end = s.IndexOf('@', pos);
        if (end < 0) Fail("unterminated name");
        if (end == pos) Fail("empty name");
        var name = s[pos..end];
        pos = end + 1;
        return name;
    }

    /// <summary>A template name and its argument list, parsed with fresh back-reference tables.</summary>
    private Identifier ParseTemplateInstantiation(bool asScope)
    {
        Enter();
        var outer = refs;
        refs = new Backrefs();
        Identifier id;
        try
        {
            id = ParseUnqualifiedSymbolName(memorize: true);
            id.TemplateArgs = ParseTemplateArguments();
        }
        finally { refs = outer; }
        // Instantiations used as scopes or types are memorized as a whole; the symbol's own name is not.
        if (asScope)
        {
            if (id is StructorIdentifier or ConversionOperatorIdentifier) Fail("constructor or conversion operator used as a scope");
            Memorize(id);
        }
        Leave();
        return id;
    }

    private Identifier ParseAnonymousNamespace()
    {
        pos += 2;
        int end = s.IndexOf('@', pos);
        if (end < 0) Fail("unterminated anonymous namespace");
        pos = end + 1;
        var id = new NamedIdentifier("`anonymous namespace'");
        Memorize(id);
        return id;
    }

    /// <summary>"?" number "?" at the cursor: a name scoped to a function body.</summary>
    private bool StartsWithLocalScope()
    {
        if (Peek() != '?') return false;
        int end = s.IndexOf('?', pos + 1);
        if (end < 0) return false;
        var candidate = s.AsSpan(pos + 1, end - pos - 1);
        if (candidate.Length == 0) return false;
        if (candidate.Length == 1) return candidate[0] == '@' || char.IsAsciiDigit(candidate[0]);
        if (candidate[^1] != '@') return false;
        candidate = candidate[..^1];
        if (candidate[0] < 'B' || candidate[0] > 'P') return false;
        foreach (var c in candidate[1..])
            if (c < 'A' || c > 'P') return false;
        return true;
    }

    private Identifier ParseLocallyScopedName()
    {
        pos++;
        var (number, _) = ParseNumber();
        Expect('?');
        return new LocalScopeIdentifier(ParseSymbol(), number);
    }

    private Identifier ParseFunctionIdentifierCode()
    {
        if (Consume("__"))
        {
            char c = Next();
            switch (c)
            {
                case 'K': return new NamedIdentifier("operator \"\" " + ParseSimpleString());
                case 'L': return new NamedIdentifier("operator co_await");
                case 'M': return new NamedIdentifier("operator<=>");
            }
            if (DoubleUnderOperators.TryGetValue(c, out var name)) return new NamedIdentifier(name);
            pos--;
            Fail($"unknown operator code '__{c}'");
        }
        if (Consume('_'))
        {
            char c = Next();
            if (UnderOperators.TryGetValue(c, out var name)) return new NamedIdentifier(name);
            pos--;
            Fail($"unknown operator code '_{c}'");
        }
        char b = Next();
        switch (b)
        {
            case '0': return new StructorIdentifier(destructor: false);
            case '1': return new StructorIdentifier(destructor: true);
            case 'B': return new ConversionOperatorIdentifier();
        }
        if (BasicOperators.TryGetValue(b, out var op)) return new NamedIdentifier(op);
        pos--;
        Fail($"unknown operator code '{b}'");
        return null!;
    }

    private static readonly Dictionary<char, string> BasicOperators = new()
    {
        ['2'] = "operator new", ['3'] = "operator delete", ['4'] = "operator=", ['5'] = "operator>>", ['6'] = "operator<<",
        ['7'] = "operator!", ['8'] = "operator==", ['9'] = "operator!=", ['A'] = "operator[]", ['C'] = "operator->",
        ['D'] = "operator*", ['E'] = "operator++", ['F'] = "operator--", ['G'] = "operator-", ['H'] = "operator+",
        ['I'] = "operator&", ['J'] = "operator->*", ['K'] = "operator/", ['L'] = "operator%", ['M'] = "operator<",
        ['N'] = "operator<=", ['O'] = "operator>", ['P'] = "operator>=", ['Q'] = "operator,", ['R'] = "operator()",
        ['S'] = "operator~", ['T'] = "operator^", ['U'] = "operator|", ['V'] = "operator&&", ['W'] = "operator||",
        ['X'] = "operator*=", ['Y'] = "operator+=", ['Z'] = "operator-=",
    };

    private static readonly Dictionary<char, string> UnderOperators = new()
    {
        ['0'] = "operator/=", ['1'] = "operator%=", ['2'] = "operator>>=", ['3'] = "operator<<=", ['4'] = "operator&=",
        ['5'] = "operator|=", ['6'] = "operator^=", ['7'] = "`vftable'", ['8'] = "`vbtable'", ['9'] = "`vcall'",
        ['A'] = "`typeof'", ['B'] = "`local static guard'", ['C'] = "`string'", ['D'] = "`vbase destructor'",
        ['E'] = "`vector deleting destructor'", ['F'] = "`default constructor closure'", ['G'] = "`scalar deleting destructor'",
        ['H'] = "`vector constructor iterator'", ['I'] = "`vector destructor iterator'", ['J'] = "`vector vbase constructor iterator'",
        ['K'] = "`virtual displacement map'", ['L'] = "`eh vector constructor iterator'", ['M'] = "`eh vector destructor iterator'",
        ['N'] = "`eh vector vbase constructor iterator'", ['O'] = "`copy constructor closure'", ['S'] = "`local vftable'",
        ['T'] = "`local vftable constructor closure'", ['U'] = "operator new[]", ['V'] = "operator delete[]",
        ['X'] = "`placement delete closure'", ['Y'] = "`placement delete[] closure'",
    };

    private static readonly Dictionary<char, string> DoubleUnderOperators = new()
    {
        ['A'] = "`managed vector constructor iterator'", ['B'] = "`managed vector destructor iterator'",
        ['C'] = "`eh vector copy constructor iterator'", ['D'] = "`eh vector vbase copy constructor iterator'",
        ['G'] = "`vector copy constructor iterator'", ['H'] = "`vector vbase copy constructor iterator'",
        ['I'] = "`managed vector copy constructor iterator'", ['J'] = "`local static thread guard'",
    };

    // ---- template arguments ----

    private List<Node> ParseTemplateArguments()
    {
        var args = new List<Node>();
        while (!Consume('@'))
        {
            if (AtEnd) Fail("unterminated template argument list");
            if (args.Count > 1000) Fail("too many template arguments");
            // empty parameter packs and pack separators
            if (Consume("$S") || Consume("$$V") || Consume("$$$V") || Consume("$$Z"))
                continue;
            args.Add(ParseTemplateArgument());
        }
        return args;
    }

    private Node ParseTemplateArgument()
    {
        Enter();
        try
        {
            if (Consume("$$Y")) return new TagLessName(ParseFullyQualifiedTypeName());
            if (Consume("$$B")) return ParseType(QualMode.Drop);
            if (Consume("$$C")) return ParseType(QualMode.Mangle);
            if (StartsWith("$1") || StartsWith("$H") || StartsWith("$I") || StartsWith("$J"))
            {
                pos++;
                char inheritance = Next();
                var arg = new SymbolArgument();
                if (Peek() == '?')
                {
                    arg.Symbol = ParseSymbol();
                    if (arg.Symbol.Name != null) Memorize(arg.Symbol.Name.Last);
                }
                int count = inheritance switch { 'J' => 3, 'I' => 2, 'H' => 1, _ => 0 };
                for (int i = 0; i < count; i++) arg.Offsets.Add(ParseSigned());
                return arg;
            }
            if (StartsWith("$E?"))
            {
                pos += 2;
                return new SymbolArgument { Symbol = ParseSymbol(), IsReference = true };
            }
            if (StartsWith("$F") || StartsWith("$G"))
            {
                pos++;
                char inheritance = Next();
                var arg = new SymbolArgument();
                int count = inheritance == 'G' ? 3 : 2;
                for (int i = 0; i < count; i++) arg.Offsets.Add(ParseSigned());
                return arg;
            }
            if (Consume("$0"))
            {
                var (value, negative) = ParseNumber();
                return new IntegerLiteral(value, negative);
            }
            if (Consume("$M"))
            {
                // auto non-type parameter: the deduced type, then the value without its '$' ("0" number / "1" symbol)
                ParseType(QualMode.Drop);
                if (Consume('0'))
                {
                    var (value, negative) = ParseNumber();
                    return new IntegerLiteral(value, negative);
                }
                if (Consume('1'))
                {
                    var arg = new SymbolArgument();
                    if (Peek() == '?') arg.Symbol = ParseSymbol();
                    return arg;
                }
                return ParseTemplateArgument();
            }
            if (Consume("$D"))
            {
                var (value, _) = ParseNumber();
                return new TagLessName(Synthesize($"`template-parameter{value}'"));
            }
            if (Consume("$Q"))
            {
                var (value, _) = ParseNumber();
                return new TagLessName(Synthesize($"`non-type-template-parameter{value}'"));
            }
            if (Peek() == '$' && Peek(1) != '$') Fail($"unsupported template argument '${Peek(1)}'");
            return ParseType(QualMode.Drop);
        }
        finally { Leave(); }
    }

    /// <summary>A template-alias or placeholder argument printed as a bare name.</summary>
    private sealed class TagLessName(QualifiedName name) : Node
    {
        public override void Output(Printer p, OutFlags f = OutFlags.None) => name.Output(p, f);
    }

    // ---- numbers ----

    /// <summary>"0".."9" encode 1..10; otherwise hex digits A..P terminated by '@'; a leading '?' negates.</summary>
    private (ulong Value, bool Negative) ParseNumber()
    {
        bool negative = Consume('?');
        if (StartsWithDigit)
            return ((ulong)(Next() - '0' + 1), negative);
        ulong value = 0;
        int digits = 0;
        while (!AtEnd)
        {
            char c = Next();
            if (c == '@') return (value, negative);
            if (c < 'A' || c > 'P') { pos--; break; }
            if (++digits > 16) Fail("number too large");
            value = (value << 4) | (uint)(c - 'A');
        }
        Fail("bad number");
        return default;
    }

    private long ParseSigned()
    {
        var (value, negative) = ParseNumber();
        if (value > long.MaxValue) Fail("number too large");
        return negative ? -(long)value : (long)value;
    }

    private ulong ParseUnsigned()
    {
        var (value, negative) = ParseNumber();
        if (negative) Fail("unexpected negative number");
        return value;
    }

    // ---- types ----

    internal enum QualMode { Drop, Mangle, Result }

    private (Quals Quals, bool IsMember) ParseQualifiers()
    {
        char c = Next();
        switch (c)
        {
            case 'Q': return (Quals.None, true);
            case 'R': return (Quals.Const, true);
            case 'S': return (Quals.Volatile, true);
            case 'T': return (Quals.Const | Quals.Volatile, true);
            case 'A': return (Quals.None, false);
            case 'B': return (Quals.Const, false);
            case 'C': return (Quals.Volatile, false);
            case 'D': return (Quals.Const | Quals.Volatile, false);
        }
        pos--;
        Fail($"bad qualifier '{c}'");
        return default;
    }

    private Quals ParsePointerExtQualifiers()
    {
        var q = Quals.None;
        while (true)
        {
            if (Consume('E')) q |= Quals.Ptr64;
            else if (Consume('I')) q |= Quals.Restrict;
            else if (Consume('F')) q |= Quals.Unaligned;
            else return q;
        }
    }

    public TypeNode ParseType(QualMode mode)
    {
        Enter();
        var quals = Quals.None;
        if (mode == QualMode.Mangle)
            quals = ParseQualifiers().Quals;
        else if (mode == QualMode.Result && Consume('?'))
            quals = ParseQualifiers().Quals;
        if (AtEnd) Fail("unexpected end of type");

        TypeNode type;
        char c = Peek();
        if (c is 'T' or 'U' or 'V' or 'W')
            type = ParseTagType();
        else if (IsPointer())
            type = IsMemberPointer() ? ParseMemberPointerType() : ParsePointerType();
        else if (c == 'Y')
            type = ParseArrayType();
        else if (Consume("$$A8@@"))
        {
            var fn = new FunctionType();
            ParseFunctionType(fn, hasThisQuals: true);
            type = fn;
        }
        else if (Consume("$$A6"))
        {
            var fn = new FunctionType();
            ParseFunctionType(fn, hasThisQuals: false);
            type = fn;
        }
        else if (c == '?')
        {
            pos++;
            var id = ParseUnqualifiedTypeName(memorize: true);
            Expect('@');
            type = new CustomType(id);
        }
        else
            type = ParsePrimitiveType();
        type.Quals |= quals;
        Leave();
        return type;
    }

    private bool IsPointer()
    {
        char c = Peek();
        if (c is 'A' or 'B' or 'P' or 'Q' or 'R' or 'S') return true;
        return StartsWith("$$Q") || StartsWith("$$R");
    }

    /// <summary>After P/Q/R/S: '6' is a function pointer, '8' a member function pointer; else the pointee qualifiers decide.</summary>
    private bool IsMemberPointer()
    {
        char c = Peek();
        if (c is not ('P' or 'Q' or 'R' or 'S')) return false;
        char d = Peek(1);
        if (char.IsAsciiDigit(d))
        {
            if (d != '6' && d != '8') { pos++; Fail("bad function pointer"); }
            return d == '8';
        }
        int p = pos + 1;
        while (p < s.Length && s[p] is 'E' or 'I' or 'F') p++;
        if (p + 1 < s.Length && s[p] == '$' && s[p + 1] == 'A') p += 2;
        if (p + 1 < s.Length && s[p] == '$' && s[p + 1] == '0') return false;
        if (p >= s.Length) Fail("unexpected end of pointer type");
        return s[p] switch
        {
            'A' or 'B' or 'C' or 'D' => false,
            'Q' or 'R' or 'S' or 'T' => true,
            _ => throw new MangledNameException("bad pointee qualifier", p),
        };
    }

    private (Quals, Affinity) ParsePointerCvQualifiers()
    {
        if (Consume("$$Q")) return (Quals.None, Affinity.RValueReference);
        if (Consume("$$R")) return (Quals.Volatile, Affinity.RValueReference);
        return Next() switch
        {
            'A' => (Quals.None, Affinity.Reference),
            'B' => (Quals.Volatile, Affinity.Reference),
            'P' => (Quals.None, Affinity.Pointer),
            'Q' => (Quals.Const, Affinity.Pointer),
            'R' => (Quals.Volatile, Affinity.Pointer),
            _ => (Quals.Const | Quals.Volatile, Affinity.Pointer),
        };
    }

    private TypeNode ParsePointerType()
    {
        var pointer = new PointerType();
        (pointer.Quals, pointer.Affinity) = ParsePointerCvQualifiers();
        if (pointer.Affinity == Affinity.Pointer && Peek() == '$' && Peek(1) == '0' && char.IsAsciiDigit(Peek(2)))
        {
            // C++/CLI: "$0" rank, ext qualifiers, element qualifiers, element type
            pos += 2;
            var array = new CliArrayType { Rank = Next() - '0', Quals = pointer.Quals };
            array.Ptr64 = (ParsePointerExtQualifiers() & Quals.Ptr64) != 0;
            Consume("$A");
            var (elementQuals, _) = ParseQualifiers();
            array.Element = ParseType(QualMode.Drop);
            array.Element.Quals |= elementQuals;
            return array;
        }
        if (Consume('6'))
        {
            var fn = new FunctionType();
            ParseFunctionType(fn, hasThisQuals: false);
            pointer.Pointee = fn;
            return pointer;
        }
        pointer.Quals |= ParsePointerExtQualifiers();
        if (Consume("$A"))
            pointer.Affinity = pointer.Affinity == Affinity.Pointer ? Affinity.Handle : Affinity.TrackingReference;
        pointer.Pointee = ParseType(QualMode.Mangle);
        return pointer;
    }

    private TypeNode ParseMemberPointerType()
    {
        var pointer = new PointerType();
        (pointer.Quals, pointer.Affinity) = ParsePointerCvQualifiers();
        pointer.Quals |= ParsePointerExtQualifiers();
        if (Consume('8'))
        {
            pointer.ClassParent = ParseFullyQualifiedTypeName();
            var fn = new FunctionType();
            ParseFunctionType(fn, hasThisQuals: true);
            pointer.Pointee = fn;
        }
        else
        {
            var (pointeeQuals, _) = ParseQualifiers();
            pointer.ClassParent = ParseFullyQualifiedTypeName();
            pointer.Pointee = ParseType(QualMode.Drop);
            pointer.Pointee.Quals = pointeeQuals;
        }
        return pointer;
    }

    private TypeNode ParseArrayType()
    {
        pos++;
        var (rank, negative) = ParseNumber();
        if (negative || rank == 0 || rank > 64) Fail("bad array rank");
        var array = new ArrayType();
        for (ulong i = 0; i < rank; i++)
        {
            var (d, neg) = ParseNumber();
            if (neg) Fail("negative array dimension");
            array.Dimensions.Add(d);
        }
        if (Consume("$$C"))
        {
            var (q, member) = ParseQualifiers();
            if (member) Fail("member qualifier on an array");
            array.Quals = q;
        }
        array.Element = ParseType(QualMode.Drop);
        return array;
    }

    private TypeNode ParseTagType()
    {
        char c = Next();
        string tag = c switch { 'T' => "union", 'U' => "struct", 'V' => "class", _ => "enum" };
        if (c == 'W')
        {
            char k = Next();
            if (k < '0' || k > '7') { pos--; Fail("bad enum kind"); }
        }
        return new TagType(tag, ParseFullyQualifiedTypeName());
    }

    private TypeNode ParsePrimitiveType()
    {
        if (Consume("$$T")) return new PrimitiveType("std::nullptr_t");
        char c = Next();
        switch (c)
        {
            case 'X': return new PrimitiveType("void");
            case 'C': return new PrimitiveType("signed char");
            case 'D': return new PrimitiveType("char");
            case 'E': return new PrimitiveType("unsigned char");
            case 'F': return new PrimitiveType("short");
            case 'G': return new PrimitiveType("unsigned short");
            case 'H': return new PrimitiveType("int");
            case 'I': return new PrimitiveType("unsigned int");
            case 'J': return new PrimitiveType("long");
            case 'K': return new PrimitiveType("unsigned long");
            case 'M': return new PrimitiveType("float");
            case 'N': return new PrimitiveType("double");
            case 'O': return new PrimitiveType("long double");
            case '_':
                char d = Next();
                switch (d)
                {
                    case 'D': return new PrimitiveType("__int8");
                    case 'E': return new PrimitiveType("unsigned __int8");
                    case 'F': return new PrimitiveType("__int16");
                    case 'G': return new PrimitiveType("unsigned __int16");
                    case 'H': return new PrimitiveType("__int32");
                    case 'I': return new PrimitiveType("unsigned __int32");
                    case 'J': return new PrimitiveType("__int64");
                    case 'K': return new PrimitiveType("unsigned __int64");
                    case 'L': return new PrimitiveType("__int128");
                    case 'M': return new PrimitiveType("unsigned __int128");
                    case 'N': return new PrimitiveType("bool");
                    case 'P': return new PrimitiveType("auto");
                    case 'T': return new PrimitiveType("decltype(auto)");
                    case 'Q': return new PrimitiveType("char8_t");
                    case 'S': return new PrimitiveType("char16_t");
                    case 'U': return new PrimitiveType("char32_t");
                    case 'W': return new PrimitiveType("wchar_t");
                    case 'X': return new TagType("coclass", ParseFullyQualifiedTypeName());
                    case 'Y': return new TagType("cointerface", ParseFullyQualifiedTypeName());
                }
                pos--;
                Fail($"unknown type '_{d}'");
                break;
        }
        pos--;
        Fail($"unknown type '{c}'");
        return null!;
    }

    // ---- string literals ----

    /// <summary>"??_C@_" kind length crc "@" bytes "@": the bytes are the first 32 of the literal (wide: big-endian pairs).</summary>
    private SymbolNode ParseStringLiteral()
    {
        if (!Consume("@_")) Fail("expected '@_' in string literal");
        char kind = Next();
        if (kind != '0' && kind != '1') { pos--; Fail("bad string literal kind"); }
        bool wide = kind == '1';
        var (byteSize, negative) = ParseNumber();
        if (negative || byteSize < (wide ? 2UL : 1UL)) Fail("bad string literal length");
        int crcEnd = s.IndexOf('@', pos);
        if (crcEnd < 0) Fail("unterminated string literal checksum");
        pos = crcEnd + 1;
        if (AtEnd) Fail("unexpected end of string literal");
        var result = new StringLiteralSymbol();
        var sb = new StringBuilder();
        if (wide)
        {
            result.Prefix = "L";
            result.IsTruncated = byteSize > 64;
            while (!Consume('@'))
            {
                if (AtEnd) Fail("unterminated string literal");
                int hi = ParseCharLiteral(), lo = ParseCharLiteral();
                if (byteSize != 2 || result.IsTruncated)
                    Escape(sb, (uint)((hi << 8) | lo));
                byteSize = byteSize >= 2 ? byteSize - 2 : 0;
                if (sb.Length > MsvcDemangler.MaxOutputLength) Fail("string literal too long");
            }
        }
        else
        {
            const int MaxBytes = 32 * 4;
            var bytes = new List<byte>();
            while (!Consume('@'))
            {
                if (AtEnd || bytes.Count >= MaxBytes) Fail("bad string literal bytes");
                bytes.Add((byte)ParseCharLiteral());
            }
            result.IsTruncated = byteSize > (ulong)bytes.Count;
            int width = GuessCharWidth(bytes, byteSize);
            if (byteSize % (ulong)width != 0) width = 1;
            result.Prefix = width switch { 2 => "u", 4 => "U", _ => "" };
            int count = bytes.Count / width;
            for (int i = 0; i < count; i++)
            {
                uint ch = 0;
                for (int b = width - 1; b >= 0; b--) ch = (ch << 8) | bytes[i * width + b];
                if (i + 1 < count || result.IsTruncated)
                    Escape(sb, ch);
            }
        }
        result.Text = sb.ToString();
        return result;
    }

    private static int GuessCharWidth(List<byte> bytes, ulong byteSize)
    {
        if (byteSize % 2 == 1) return 1;
        if (byteSize < 32)
        {
            int trailing = 0;
            for (int i = bytes.Count - 1; i >= 0 && bytes[i] == 0; i--) trailing++;
            if (trailing >= 4 && byteSize % 4 == 0) return 4;
            if (trailing >= 2) return 2;
            return 1;
        }
        int nulls = 0;
        for (int i = 0; i + 1 < bytes.Count; i++) if (bytes[i] == 0) nulls++;
        if (nulls >= 2 * bytes.Count / 3 && byteSize % 4 == 0) return 4;
        if (nulls >= bytes.Count / 3) return 2;
        return 1;
    }

    /// <summary>One encoded byte: a plain character, "?$" + two A..P nibbles, "?" + digit (punctuation), "?a".."?z" / "?A".."?Z" (0xE1.. / 0xC1..).</summary>
    private int ParseCharLiteral()
    {
        char c = Next();
        if (c != '?') return c & 0xFF;
        if (Consume('$'))
        {
            char a = Next(), b = Next();
            if (a < 'A' || a > 'P' || b < 'A' || b > 'P') Fail("bad escaped byte");
            return ((a - 'A') << 4) | (b - 'A');
        }
        char d = Next();
        if (char.IsAsciiDigit(d)) return ",/\\:. \n\t'-"[d - '0'];
        if (d >= 'a' && d <= 'z') return 0xE1 + (d - 'a');
        if (d >= 'A' && d <= 'Z') return 0xC1 + (d - 'A');
        pos--;
        Fail("bad escaped character");
        return 0;
    }

    private static void Escape(StringBuilder sb, uint c)
    {
        switch (c)
        {
            case 0: sb.Append("\\0"); return;
            case '"': sb.Append("\\\""); return;
            case '\\': sb.Append("\\\\"); return;
            case '\a': sb.Append("\\a"); return;
            case '\b': sb.Append("\\b"); return;
            case '\f': sb.Append("\\f"); return;
            case '\n': sb.Append("\\n"); return;
            case '\r': sb.Append("\\r"); return;
            case '\t': sb.Append("\\t"); return;
            case '\v': sb.Append("\\v"); return;
        }
        if (c >= 0x20 && c <= 0x7E) sb.Append((char)c);
        else sb.Append("\\x").Append(c.ToString("X"));
    }
}
