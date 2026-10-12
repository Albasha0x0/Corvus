using System.Text;
using dnlib.DotNet;

namespace Corvus.Core;

/// <summary>C#-flavoured, compact signatures for dnlib members (used in listings and search results).</summary>
public static class Format
{
    /// <summary>"0x06000123", or "(new)" for members added by an edit (no token until the image is written).</summary>
    public static string Token(IMDTokenProvider p) => p.MDToken.Rid == 0 ? "(new)" : $"0x{p.MDToken.Raw:X8}";

    public static string Type(TypeSig? sig)
    {
        switch (sig)
        {
            case null: return "?";
            case CorLibTypeSig c:
                return c.ElementType switch
                {
                    ElementType.Void => "void",
                    ElementType.Boolean => "bool",
                    ElementType.Char => "char",
                    ElementType.I1 => "sbyte",
                    ElementType.U1 => "byte",
                    ElementType.I2 => "short",
                    ElementType.U2 => "ushort",
                    ElementType.I4 => "int",
                    ElementType.U4 => "uint",
                    ElementType.I8 => "long",
                    ElementType.U8 => "ulong",
                    ElementType.R4 => "float",
                    ElementType.R8 => "double",
                    ElementType.String => "string",
                    ElementType.Object => "object",
                    ElementType.I => "nint",
                    ElementType.U => "nuint",
                    _ => c.TypeName,
                };
            case GenericInstSig g:
                return $"{StripArity(g.GenericType?.TypeDefOrRef?.Name ?? "?")}<{string.Join(", ", g.GenericArguments.Select(Type))}>";
            case SZArraySig a:
                return Type(a.Next) + "[]";
            case ArraySig a:
                return Type(a.Next) + "[" + new string(',', (int)Math.Max(0, a.Rank - 1)) + "]";
            case ByRefSig b:
                return "ref " + Type(b.Next);
            case PtrSig p:
                return Type(p.Next) + "*";
            case GenericSig gs:
                return gs.GenericParam?.Name?.String is { Length: > 0 } n ? n : (gs.IsMethodVar ? "!!" : "!") + gs.Number;
            case FnPtrSig:
                return "delegate*";
            case TypeDefOrRefSig t:
                return TypeName(t.TypeDefOrRef);
            case NonLeafSig nl:
                return Type(nl.Next);
            default:
                return sig.TypeName;
        }
    }

    public static string TypeName(ITypeDefOrRef? t)
    {
        if (t == null) return "?";
        if (t is TypeSpec spec) return Type(spec.TypeSig);
        var name = StripArity(t.Name);
        if (t is TypeDef td && td.GenericParameters.Count > 0)
            name += "<" + string.Join(", ", td.GenericParameters.Select(gp => gp.Name.String)) + ">";
        return name;
    }

    public static string StripArity(string name)
    {
        int i = name.IndexOf('`');
        return i > 0 ? name[..i] : name;
    }

    public static string Access(TypeDef t) => t.Visibility switch
    {
        TypeAttributes.Public or TypeAttributes.NestedPublic => "public",
        TypeAttributes.NestedPrivate => "private",
        TypeAttributes.NestedFamily => "protected",
        TypeAttributes.NestedAssembly or TypeAttributes.NotPublic => "internal",
        TypeAttributes.NestedFamORAssem => "protected internal",
        TypeAttributes.NestedFamANDAssem => "private protected",
        _ => "internal",
    };

    public static string Access(MethodDef m) => m.Access switch
    {
        MethodAttributes.Public => "public",
        MethodAttributes.Private => "private",
        MethodAttributes.Family => "protected",
        MethodAttributes.Assembly => "internal",
        MethodAttributes.FamORAssem => "protected internal",
        MethodAttributes.FamANDAssem => "private protected",
        _ => "privatescope",
    };

    public static string Access(FieldDef f) => f.Access switch
    {
        FieldAttributes.Public => "public",
        FieldAttributes.Private => "private",
        FieldAttributes.Family => "protected",
        FieldAttributes.Assembly => "internal",
        FieldAttributes.FamORAssem => "protected internal",
        FieldAttributes.FamANDAssem => "private protected",
        _ => "privatescope",
    };

    public static string Kind(TypeDef t) =>
        t.IsInterface ? "interface"
        : t.IsEnum ? "enum"
        : t.IsDelegate ? "delegate"
        : t.IsValueType ? "struct"
        : (t.IsAbstract && t.IsSealed) ? "static class"
        : "class";

    public static string TypeHeader(TypeDef t)
    {
        var sb = new StringBuilder();
        sb.Append(Access(t)).Append(' ');
        if (!t.IsInterface && !t.IsValueType)
        {
            if (t.IsAbstract && t.IsSealed) sb.Append("static ");
            else if (t.IsAbstract) sb.Append("abstract ");
            else if (t.IsSealed && !t.IsDelegate) sb.Append("sealed ");
        }
        sb.Append(Kind(t) == "static class" ? "class" : Kind(t)).Append(' ').Append(TypeName(t));
        var bases = new List<string>();
        if (t.BaseType != null && !t.IsValueType && !t.IsEnum && !t.IsDelegate && t.BaseType.FullName != "System.Object")
            bases.Add(TypeName(t.BaseType));
        if (t.IsEnum && t.GetEnumUnderlyingType() is { } underlying && underlying.ElementType != ElementType.I4)
            bases.Add(Type(underlying));
        bases.AddRange(t.Interfaces.Select(i => TypeName(i.Interface)));
        if (bases.Count > 0)
            sb.Append(" : ").Append(string.Join(", ", bases));
        return sb.ToString();
    }

    public static string Method(MethodDef m, bool withModifiers = true)
    {
        var sb = new StringBuilder();
        if (withModifiers)
        {
            sb.Append(Access(m)).Append(' ');
            if (m.IsStatic) sb.Append("static ");
            if (m.IsAbstract && !m.DeclaringType.IsInterface) sb.Append("abstract ");
            else if (m.IsVirtual && !m.IsAbstract)
            {
                if (m.IsNewSlot) { if (!m.IsFinal) sb.Append("virtual "); }
                else sb.Append(m.IsFinal ? "sealed override " : "override ");
            }
            if (m.IsPinvokeImpl) sb.Append("extern ");
        }
        if (!m.IsConstructor)
            sb.Append(Type(m.ReturnType)).Append(' ');
        sb.Append(m.IsConstructor ? (m.IsStatic && !withModifiers ? "static " : "") + StripArity(m.DeclaringType.Name) : m.Name.String);
        if (m.GenericParameters.Count > 0)
            sb.Append('<').Append(string.Join(", ", m.GenericParameters.Select(g => g.Name.String))).Append('>');
        bool extension = withModifiers && m.IsStatic && m.Parameters.Any(p => p.IsNormalMethodParameter)
                         && m.CustomAttributes.IsDefined("System.Runtime.CompilerServices.ExtensionAttribute");
        sb.Append('(').Append(extension ? "this " : "").Append(Parameters(m)).Append(')');
        return sb.ToString();
    }

    public static string Parameters(MethodDef m) =>
        string.Join(", ", m.Parameters.Where(p => p.IsNormalMethodParameter).Select(p => $"{Type(p.Type)} {p.Name}".TrimEnd()));

    public static string ParameterTypes(MethodSig? sig) =>
        sig == null ? "" : string.Join(", ", sig.Params.Select(Type));

    public static string Field(FieldDef f)
    {
        var sb = new StringBuilder();
        sb.Append(Access(f)).Append(' ');
        if (f.IsLiteral) sb.Append("const ");
        else
        {
            if (f.IsStatic) sb.Append("static ");
            if (f.IsInitOnly) sb.Append("readonly ");
        }
        sb.Append(Type(f.FieldType)).Append(' ').Append(f.Name.String);
        if (f.IsLiteral && f.Constant != null)
            sb.Append(" = ").Append(Literal(f.Constant.Value));
        return sb.ToString();
    }

    public static string Property(PropertyDef p)
    {
        var accessor = p.GetMethod ?? p.SetMethod;
        var sb = new StringBuilder();
        if (accessor != null)
        {
            sb.Append(Access(accessor)).Append(' ');
            if (accessor.IsStatic) sb.Append("static ");
        }
        sb.Append(Type(p.PropertySig?.RetType)).Append(' ').Append(p.Name.String);
        if (p.PropertySig?.Params.Count > 0)
            sb.Append('[').Append(string.Join(", ", p.PropertySig.Params.Select(Type))).Append(']');
        sb.Append(" {");
        if (p.GetMethod != null) sb.Append(" get;");
        if (p.SetMethod != null) sb.Append(" set;");
        sb.Append(" }");
        return sb.ToString();
    }

    public static string Event(EventDef e)
    {
        var accessor = e.AddMethod ?? e.RemoveMethod;
        var prefix = accessor != null ? Access(accessor) + (accessor.IsStatic ? " static" : "") + " " : "";
        return $"{prefix}event {TypeName(e.EventType)} {e.Name}";
    }

    /// <summary>"Ns.Type::Method(int, string)", "Ns.Type::Method&lt;T&gt;(string)" for a generic method — unambiguous label for search/xref output.</summary>
    public static string MemberLabel(IMemberRef m) => m switch
    {
        TypeDef t => t.FullName,
        MethodDef md => $"{md.DeclaringType?.FullName}::{md.Name}{GenericParameters(md)}({ParameterTypes(md.MethodSig)})",
        MemberRef { IsFieldRef: true } fr => $"{fr.DeclaringType?.FullName}::{fr.Name}",
        IMethod im => $"{im.DeclaringType?.FullName}::{im.Name}{GenericParameters(im)}({ParameterTypes(im.MethodSig)})",
        IField f => $"{f.DeclaringType?.FullName}::{f.Name}",
        PropertyDef p => $"{p.DeclaringType?.FullName}::{p.Name}",
        EventDef e => $"{e.DeclaringType?.FullName}::{e.Name}",
        _ => m.FullName,
    };

    /// <summary>
    /// "&lt;T, U&gt;" for a generic method, so it differs from a non-generic overload with the same parameters. The method's own
    /// names when they are plain identifiers (the resolver counts commas), else T or T1..Tn.
    /// </summary>
    public static string GenericParameters(IMethod m)
    {
        int n = (int)(m.MethodSig?.GenParamCount ?? 0);
        if (n == 0) return "";
        var def = m as MethodDef ?? (m as MethodSpec)?.Method as MethodDef;
        var names = def?.GenericParameters.Count == n ? def.GenericParameters.Select(g => g.Name.String).ToList() : null;
        if (names == null || names.Any(x => x.Length == 0 || !x.All(c => char.IsLetterOrDigit(c) || c == '_')))
            names = n == 1 ? ["T"] : Enumerable.Range(1, n).Select(i => "T" + i.ToString(System.Globalization.CultureInfo.InvariantCulture)).ToList();
        return "<" + string.Join(", ", names) + ">";
    }

    public static string Literal(object? value) => value switch
    {
        null => "null",
        string s => "\"" + Escape(s) + "\"",
        UTF8String u => "\"" + Escape(u.String) + "\"",
        char c => "'" + Escape(c.ToString()) + "'",
        bool b => b ? "true" : "false",
        float f => f.ToString("R", System.Globalization.CultureInfo.InvariantCulture) + "f",
        double d => d.ToString("R", System.Globalization.CultureInfo.InvariantCulture),
        IFormattable fmt => fmt.ToString(null, System.Globalization.CultureInfo.InvariantCulture),
        _ => value.ToString() ?? "",
    };

    public static string Escape(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var ch in s)
        {
            sb.Append(ch switch
            {
                '\\' => "\\\\",
                '"' => "\\\"",
                '\n' => "\\n",
                '\r' => "\\r",
                '\t' => "\\t",
                '\0' => "\\0",
                _ when char.IsControl(ch) => $"\\u{(int)ch:x4}",
                _ => ch.ToString(),
            });
        }
        return sb.ToString();
    }

    /// <summary>
    /// Characters that print as nothing or reorder the text around them: format characters (zero-width and bidi
    /// controls such as U+202E), line and paragraph separators, and the Hangul fillers. Code transformers build names from them.
    /// </summary>
    public static bool IsInvisible(char ch) =>
        char.GetUnicodeCategory(ch) is System.Globalization.UnicodeCategory.Format or System.Globalization.UnicodeCategory.LineSeparator
            or System.Globalization.UnicodeCategory.ParagraphSeparator
        || ch is 'ᅟ' or 'ᅠ' or 'ㅤ' or 'ﾠ';

    /// <summary>Invisible characters (see <see cref="IsInvisible"/>) as \uXXXX, the way the decompiler escapes identifiers.</summary>
    public static string EscapeInvisible(string s)
    {
        int i = 0;
        while (i < s.Length && !IsInvisible(s[i])) i++;
        if (i == s.Length) return s;
        var sb = new StringBuilder(s.Length + 32).Append(s, 0, i);
        for (; i < s.Length; i++)
        {
            if (IsInvisible(s[i])) sb.Append("\\u").Append(((int)s[i]).ToString("x4"));
            else sb.Append(s[i]);
        }
        return sb.ToString();
    }

    /// <summary>The inverse of <see cref="EscapeInvisible"/>: \uXXXX of an invisible character becomes the character.</summary>
    public static string UnescapeInvisible(string s)
    {
        if (!s.Contains("\\u", StringComparison.OrdinalIgnoreCase)) return s;
        return System.Text.RegularExpressions.Regex.Replace(s, @"\\[uU]([0-9a-fA-F]{4})", m =>
        {
            var ch = (char)Convert.ToInt32(m.Groups[1].Value, 16);
            return IsInvisible(ch) ? ch.ToString() : m.Value;
        });
    }

    /// <summary>The line starts this server writes as markers; echoed content must not forge them (STANDARDS S10.4).</summary>
    public static readonly string[] Markers = ["Error (", "error (json):", "Next:", "[More:", "[End:", "[workspace]"];

    /// <summary>Put before a forged marker: the escaped form of U+2063 (invisible separator), visible as text.</summary>
    public const string MarkerEscape = "\\u2063";

    /// <summary>
    /// <see cref="EscapeInvisible"/>, then every line (after its indentation) that starts with one of <see cref="Markers"/>
    /// gets <see cref="MarkerEscape"/> in front, so file-derived text cannot pass for an error, a Next step or a footer.
    /// </summary>
    public static string EscapeMarkers(string s)
    {
        s = EscapeInvisible(s);
        if (!Markers.Any(m => s.Contains(m, StringComparison.Ordinal))) return s;
        var sb = new StringBuilder(s.Length + 16);
        int start = 0;
        while (start <= s.Length)
        {
            int end = s.IndexOfAny(['\n', '\r'], start);
            if (end < 0) end = s.Length;
            int text = start;
            while (text < end && s[text] is ' ' or '\t') text++;
            sb.Append(s, start, text - start);
            var line = s.AsSpan(text, end - text);
            foreach (var m in Markers)
                if (line.StartsWith(m, StringComparison.Ordinal)) { sb.Append(MarkerEscape); break; }
            sb.Append(s, text, end - text);
            if (end == s.Length) break;
            sb.Append(s[end]);
            start = end + 1;
        }
        return sb.ToString();
    }

    /// <summary>"[Name(args, Named = value)]" with the Attribute suffix dropped.</summary>
    public static string Attribute(CustomAttribute ca)
    {
        var name = StripArity(ca.AttributeType?.Name ?? "?");
        if (name.EndsWith("Attribute", StringComparison.Ordinal) && name.Length > "Attribute".Length)
            name = name[..^"Attribute".Length];
        if (!ca.HasConstructorArguments && !ca.HasNamedArguments)
            return $"[{name}]";
        var args = ca.ConstructorArguments.Select(AttributeArgument)
            .Concat(ca.NamedArguments.Select(n => $"{n.Name} = {AttributeArgument(n.Argument)}"));
        return $"[{name}({string.Join(", ", args)})]";
    }

    /// <summary>
    /// Formats an attribute argument as C#: arrays as new[] { ... }, boxed objects by value, types as typeof(...),
    /// enums by member name when resolvable, otherwise "(Enum)n".
    /// </summary>
    public static string AttributeArgument(CAArgument arg) => arg.Value switch
    {
        IList<CAArgument> items => $"new {(arg.Type is SZArraySig array ? Type(array.Next) : "")}[] {{ {string.Join(", ", items.Select(AttributeArgument))} }}",
        null when arg.Type is SZArraySig => "null",
        CAArgument boxed => AttributeArgument(boxed),
        TypeSig type => $"typeof({Type(type)})",
        _ when arg.Type is ValueTypeSig vt && MetadataUtil.Try(() => vt.TypeDefOrRef.ResolveTypeDef()) is { IsEnum: true } e => EnumValue(e, arg.Value),
        _ => Literal(arg.Value),
    };

    private static string EnumValue(TypeDef e, object? value)
    {
        var member = e.Fields.FirstOrDefault(f => f.IsLiteral && f.Constant != null && Equals(f.Constant.Value, value));
        return member != null ? $"{e.Name}.{member.Name}" : $"({e.Name}){Literal(value)}";
    }

    /// <summary>The primitive values inside an attribute argument (array elements and boxed values included).</summary>
    public static IEnumerable<object?> AttributeValues(CAArgument arg) => arg.Value switch
    {
        IList<CAArgument> items => items.SelectMany(AttributeValues),
        CAArgument boxed => AttributeValues(boxed),
        var v => [v],
    };

    /// <summary>Integral constants with their hex form, e.g. "256 (0x100)".</summary>
    public static string LiteralWithHex(object? value) => value switch
    {
        int i => $"{i} (0x{i:X})",
        uint u => $"{u} (0x{u:X})",
        long l => $"{l} (0x{l:X})",
        ulong ul => $"{ul} (0x{ul:X})",
        short sh => $"{sh} (0x{sh:X})",
        ushort us => $"{us} (0x{us:X})",
        byte b => $"{b} (0x{b:X})",
        sbyte sb => $"{sb} (0x{sb:X})",
        _ => Literal(value),
    };

    public static string Clip(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}
