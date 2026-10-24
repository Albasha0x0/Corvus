using System.Text;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using Corvus.Core;

namespace Corvus.Services;

/// <summary>
/// Which of the same-named dummy methods a script.json entry ("Ns.Type&lt;args&gt;$$Method&lt;args&gt;") instantiates.
/// The type key drops arity, so the candidates are every method of the name in every type of the key. They are narrowed
/// by the generic argument counts of the name, then by the parameter count of the entry's C prototype (its TypeSignature
/// when there is none), then by scoring the prototype's C types against each candidate's return and parameter types,
/// both as declared and with the name's generic arguments substituted. The best score wins only when no other candidate
/// has it; otherwise the entry is ambiguous between the tied candidates.
/// </summary>
public static partial class Il2CppOverloads
{
    public enum Outcome { Resolved, Ambiguous, Unmatched }

    /// <summary>
    /// <see cref="Methods"/>: the method (resolved), the tied candidates (ambiguous), or the candidates that fit the
    /// generic arity (unmatched: none has the prototype's parameter count). <see cref="Basis"/> says what decided;
    /// <see cref="Named"/> is how many methods share the name.
    /// </summary>
    public sealed record Match(Outcome Outcome, IReadOnlyList<MethodDef> Methods, string Basis, int Named)
    {
        public MethodDef? Method => Outcome == Outcome.Resolved ? Methods[0] : null;
        public bool Includes(MethodDef method) => Outcome != Outcome.Unmatched && Methods.Contains(method);
    }

    /// <summary>
    /// The candidate that <paramref name="typePart"/>$$<paramref name="methodPart"/> instantiates. <paramref name="read"/>
    /// reads the entry's signature; it is called only when the names leave more than one candidate.
    /// </summary>
    public static Match Resolve(IReadOnlyList<MethodDef> overloads, string typePart, string methodPart, Func<ScriptMethod> read)
    {
        if (overloads.Count <= 1) return new Match(overloads.Count == 1 ? Outcome.Resolved : Outcome.Unmatched, overloads, "the only method of the name", overloads.Count);
        var typeArgs = Il2CppNames.GenericArguments(typePart);
        var methodArgs = Il2CppNames.GenericArguments(methodPart);
        var candidates = overloads.Where(m => m.DeclaringType.GenericParameters.Count == typeArgs.Count && m.GenericParameters.Count == methodArgs.Count).ToList();
        if (candidates.Count == 0) candidates = overloads.ToList(); // names the dumper wrote another way
        if (candidates.Count == 1) return new Match(Outcome.Resolved, candidates, "generic arity", overloads.Count);

        var entry = read();
        var prototype = Prototype.Parse(entry.Signature);
        List<MethodDef> counted;
        if (prototype != null)
        {
            counted = candidates.Where(m => m.MethodSig.Params.Count == prototype.Parameters.Count && m.IsStatic != prototype.HasThis).ToList();
            if (counted.Count == 0) counted = candidates.Where(m => m.MethodSig.Params.Count == prototype.Parameters.Count).ToList();
        }
        else if (entry.TypeSignature is { Length: > 0 } ts) // return, this, parameters, MethodInfo
            counted = candidates.Where(m => ts.Length == m.MethodSig.Params.Count + (m.IsStatic ? 2 : 3)).ToList();
        else
            return new Match(Outcome.Ambiguous, candidates, "no signature in script.json", overloads.Count);
        if (counted.Count == 0) return new Match(Outcome.Unmatched, candidates, "parameter count", overloads.Count);
        if (counted.Count == 1) return new Match(Outcome.Resolved, counted, "parameter count", overloads.Count);
        if (prototype == null) return new Match(Outcome.Ambiguous, counted, "parameter count only (no C prototype)", overloads.Count);

        var scores = counted.Select(m => Score(m, prototype, typeArgs, methodArgs)).ToList();
        int best = scores.Max();
        var top = counted.Where((_, i) => scores[i] == best).ToList();
        return top.Count == 1 ? new Match(Outcome.Resolved, top, "parameter types", overloads.Count) : new Match(Outcome.Ambiguous, top, "the same C signature", overloads.Count);
    }

    private static int Score(MethodDef m, Prototype p, IReadOnlyList<string> typeArgs, IReadOnlyList<string> methodArgs)
    {
        var context = new Context(m, typeArgs, methodArgs);
        int score = p.Return is { } ret ? Score(DefShape.Of(m.MethodSig.RetType, context), ret) : 0;
        for (int i = 0; i < p.Parameters.Count; i++)
            score += Score(DefShape.Of(m.MethodSig.Params[i], context), p.Parameters[i]);
        return score;
    }

    // 3: the C type is this type; 1: it could be (a kind the C name does not settle, or a naming quirk); 0: it is not.
    private static int Score(DefShape d, CType c)
    {
        int s = c.Stars, depth = d.Depth;
        bool named = d.Names.Any(n => c.NameEndsWith(n));
        return d.Kind switch
        {
            DefKind.Any => named ? 3 : 1, // a fully shared argument: its own C struct, or anything
            DefKind.Primitive => c.Kind == CKind.Primitive && c.Name == d.Names[0] && s == depth ? 3 : 0,
            DefKind.Void => c.Kind == CKind.Void && s == depth ? 3 : 0,
            DefKind.Object => c.Kind == CKind.Object && s == depth + 1 ? 3 : 0,
            DefKind.Array => c.Kind == CKind.Array && s == depth + 1 ? named ? 3 : 1 : c.Kind == CKind.Other && s == depth + 1 ? 1 : 0,
            DefKind.Class => (c.Kind is CKind.Struct or CKind.Other) && s == depth + 1 ? named ? 3 : 1 : c.Kind == CKind.Object && s == depth + 1 ? 1 : 0,
            DefKind.Struct => (c.Kind is CKind.Struct or CKind.Other) && s == depth ? named ? 3 : 1 : !d.Resolved && c.Kind == CKind.Primitive && s == depth ? 1 : 0,
            _ => (c.Kind is CKind.Struct or CKind.Other) && (s == depth || s == depth + 1) ? named ? 3 : 1 // a generic argument of unknown kind
                : (c.Kind is CKind.Object or CKind.Array) && s == depth + 1 || c.Kind == CKind.Primitive && s == depth ? 1 : 0,
        };
    }

    private enum CKind { Primitive, Object, Array, Struct, Void, Other }

    /// <summary>
    /// A C type of the script.json prototypes: a primitive (int32_t ...), Il2CppObject, an array (X_array), a type's
    /// struct (X_o: a class through one pointer more than a value type), void, or another name; with its pointer count.
    /// </summary>
    private sealed record CType(CKind Kind, string Name, int Stars)
    {
        private string? _normalized;
        private List<int>? _boundaries;

        public static CType Parse(string text)
        {
            var t = text.Trim();
            if (t.StartsWith("const ", StringComparison.Ordinal)) t = t[6..].TrimStart();
            int stars = 0;
            while (t.EndsWith('*')) { stars++; t = t[..^1].TrimEnd(); }
            if (CPrimitives.TryGetValue(t, out var primitive)) return new CType(CKind.Primitive, primitive, stars);
            if (t == "Il2CppObject") return new CType(CKind.Object, "", stars);
            if (t == "void") return new CType(CKind.Void, "", stars);
            if (t.EndsWith("_array", StringComparison.Ordinal)) return new CType(CKind.Array, t[..^6], stars);
            if (t.EndsWith("_o", StringComparison.Ordinal)) return new CType(CKind.Struct, t[..^2], stars);
            return new CType(CKind.Other, t, stars);
        }

        /// <summary>Whether the name, from its start or from after one of its '_', normalizes to <paramref name="normalized"/>.</summary>
        public bool NameEndsWith(string normalized)
        {
            if (normalized.Length == 0) return false;
            if (_normalized == null)
            {
                var sb = new StringBuilder(Name.Length);
                _boundaries = [0];
                foreach (char ch in Name)
                {
                    if (ch == '_') _boundaries.Add(sb.Length);
                    else if (char.IsAsciiLetterOrDigit(ch)) sb.Append(char.ToLowerInvariant(ch));
                }
                _normalized = sb.ToString();
            }
            int at = _normalized.Length - normalized.Length;
            return at >= 0 && _boundaries!.Contains(at) && _normalized.EndsWith(normalized, StringComparison.Ordinal);
        }
    }

    private static readonly Dictionary<string, string> CPrimitives = new(StringComparer.Ordinal)
    {
        ["bool"] = "bool", ["uint8_t"] = "byte", ["int8_t"] = "sbyte", ["int16_t"] = "short", ["uint16_t"] = "ushort", ["Il2CppChar"] = "ushort",
        ["int32_t"] = "int", ["uint32_t"] = "uint", ["int64_t"] = "long", ["uint64_t"] = "ulong", ["float"] = "float", ["double"] = "double",
        ["intptr_t"] = "nint", ["uintptr_t"] = "nuint",
    };

    /// <summary>
    /// A C prototype: "RET NAME (TYPE NAME, ..., const MethodInfo* method);". The parameters exclude __this and the
    /// trailing MethodInfo; parameter names may be missing ("uint8_t , ...").
    /// </summary>
    private sealed record Prototype(CType? Return, List<CType> Parameters, bool HasThis)
    {
        public static Prototype? Parse(string? signature)
        {
            if (string.IsNullOrWhiteSpace(signature)) return null;
            int open = signature.IndexOf('('), close = signature.LastIndexOf(')');
            if (open < 0 || close < open) return null;
            var head = signature[..open].TrimEnd();
            int nameStart = head.LastIndexOf(' ');
            CType? ret = nameStart > 0 ? CType.Parse(head[..nameStart]) : null;
            var parts = signature[(open + 1)..close].Split(',').Select(p => p.Trim()).Where(p => p.Length > 0).Select(Split).ToList();
            bool hasThis = parts.Count > 0 && parts[0].Name == "__this";
            if (hasThis) parts.RemoveAt(0);
            if (parts.Count > 0 && MethodInfoType().IsMatch(parts[^1].Type)) parts.RemoveAt(parts.Count - 1);
            return new Prototype(ret, parts.Select(p => CType.Parse(p.Type)).ToList(), hasThis);
        }

        /// <summary>"TYPE NAME" → (TYPE, NAME); "TYPE" alone when the last word is not an identifier ("int32_t*", "uint8_t").</summary>
        private static (string Type, string? Name) Split(string parameter)
        {
            int space = parameter.LastIndexOf(' ');
            if (space < 0) return (parameter, null);
            var last = parameter[(space + 1)..];
            return last.All(ch => char.IsAsciiLetterOrDigit(ch) || ch == '_') && !CPrimitives.ContainsKey(last) && last is not ("void" or "Il2CppObject")
                ? (parameter[..space], last)
                : (parameter, null);
        }
    }

    private enum DefKind { Primitive, Object, Array, Class, Struct, Void, Any, Unknown }

    /// <summary>The generic parameters of a candidate and the arguments its instantiation's name gives them.</summary>
    private sealed record Context(MethodDef Method, IReadOnlyList<string> TypeArgs, IReadOnlyList<string> MethodArgs)
    {
        public (string? Argument, string Parameter) Lookup(GenericSig g)
        {
            bool onMethod = g is GenericMVar;
            var parameters = onMethod ? Method.GenericParameters : Method.DeclaringType.GenericParameters;
            var args = onMethod ? MethodArgs : TypeArgs;
            int n = (int)g.Number;
            var parameter = parameters.FirstOrDefault(p => p.Number == n)?.Name.String ?? (onMethod ? "M" : "T") + n;
            return (n < args.Count ? args[n] : null, parameter);
        }
    }

    /// <summary>
    /// A candidate's parameter or return type as a script.json C type would show it: kind, by-ref / pointer depth, and
    /// normalized names (with the instantiation's arguments substituted, and as declared) a C name may end with.
    /// </summary>
    private sealed record DefShape(DefKind Kind, string[] Names, int Depth, bool Resolved = true)
    {
        public static DefShape Of(TypeSig? sig, Context c)
        {
            int depth = 0;
            sig = sig?.RemovePinnedAndModifiers();
            while (sig is ByRefSig or PtrSig) { depth++; sig = sig.Next?.RemovePinnedAndModifiers(); }
            switch (sig)
            {
                case null: return new DefShape(DefKind.Any, [], depth);
                case GenericSig g:
                    var argument = c.Lookup(g).Argument;
                    return argument == null ? new DefShape(DefKind.Unknown, [], depth) : OfArgument(argument, depth);
                case SZArraySig or ArraySig:
                    return new DefShape(DefKind.Array, NamesOf(Render(sig.Next, c, true, true), Render(sig.Next, c, false, true)), depth);
                case CorLibTypeSig corlib:
                    return corlib.ElementType switch
                    {
                        ElementType.Void => new DefShape(DefKind.Void, [], depth),
                        ElementType.Object => new DefShape(DefKind.Object, [], depth),
                        ElementType.String => new DefShape(DefKind.Class, ["systemstring"], depth),
                        _ when Primitive(corlib.ElementType) is { } p => new DefShape(DefKind.Primitive, [p], depth),
                        _ => new DefShape(DefKind.Unknown, [], depth),
                    };
                case TypeDefOrRefSig or GenericInstSig:
                    var typeRef = sig is GenericInstSig gi ? gi.GenericType?.TypeDefOrRef : ((TypeDefOrRefSig)sig).TypeDefOrRef;
                    var def = typeRef == null ? null : MetadataUtil.Try(() => typeRef.ResolveTypeDef());
                    if (def is { IsEnum: true } && Primitive(def.GetEnumUnderlyingType()?.ElementType ?? ElementType.I4) is { } underlying)
                        return new DefShape(DefKind.Primitive, [underlying], depth);
                    var names = NamesOf(Render(sig, c, true, true), Render(sig, c, false, true));
                    bool valueType = def?.IsValueType ?? sig.IsValueType || sig is GenericInstSig { GenericType: ValueTypeSig };
                    return new DefShape(valueType ? DefKind.Struct : DefKind.Class, names, depth, def != null);
                default:
                    return new DefShape(DefKind.Unknown, [], depth);
            }
        }

        /// <summary>
        /// A generic argument as script.json names it ("int", "string", "List&lt;int&gt;", "byte[]", "Int32Enum"). The
        /// parameter's own name is no C name of it: "T" would match the tail of "System_Func_T_".
        /// </summary>
        private static DefShape OfArgument(string argument, int depth)
        {
            if (argument.StartsWith("__Il2CppFullyShared", StringComparison.Ordinal)) return new DefShape(DefKind.Any, NamesOf(argument), depth);
            if (argument == "object") return new DefShape(DefKind.Object, [], depth);
            if (argument == "string") return new DefShape(DefKind.Class, ["systemstring"], depth);
            if (KeywordPrimitives.TryGetValue(argument, out var p)) return new DefShape(DefKind.Primitive, [p], depth);
            if (argument.EndsWith("[]", StringComparison.Ordinal))
                return new DefShape(DefKind.Array, NamesOf(ClrName(argument[..^2])), depth);
            return new DefShape(DefKind.Unknown, NamesOf(argument), depth);
        }

        private static string[] NamesOf(params string[] renderings) => renderings.Select(Normalize).Where(n => n.Length > 0).Distinct().ToArray();
    }

    /// <summary>
    /// The script.json spelling of a type in C names: at the top, namespace and declaring types ("System.Int32" for a
    /// primitive); inside generic argument lists, declaring types only and C# keywords. Generic parameters are the
    /// instantiation's arguments (<paramref name="substitute"/>) or their declared names (the dumper writes either).
    /// </summary>
    private static string Render(TypeSig? sig, Context c, bool substitute, bool top)
    {
        sig = sig?.RemovePinnedAndModifiers();
        switch (sig)
        {
            case null: return "";
            case GenericSig g:
                var (argument, parameter) = c.Lookup(g);
                return substitute && argument != null ? top ? ClrName(argument) : argument : parameter;
            case SZArraySig or ArraySig: return Render(sig.Next, c, substitute, false) + "[]";
            case ByRefSig or PtrSig: return Render(sig.Next, c, substitute, top) + "*";
            case CorLibTypeSig corlib: return top ? corlib.FullName : Keyword(corlib);
            case GenericInstSig gi:
                return TypeName(gi.GenericType?.TypeDefOrRef, top) + "<" + string.Join(", ", gi.GenericArguments.Select(a => Render(a, c, substitute, false))) + ">";
            case TypeDefOrRefSig t: return TypeName(t.TypeDefOrRef, top);
            default: return sig.TypeName;
        }
    }

    private static string TypeName(ITypeDefOrRef? type, bool withNamespace)
    {
        if (type == null) return "";
        var name = Format.StripArity(type.Name);
        var outer = type.DeclaringType;
        if (outer != null) return TypeName(outer, withNamespace) + "." + name;
        return withNamespace && type.Namespace.Length > 0 ? type.Namespace + "." + name : name;
    }

    private static string Keyword(CorLibTypeSig corlib) => corlib.ElementType switch
    {
        ElementType.Object => "object", ElementType.String => "string", ElementType.I => "IntPtr", ElementType.U => "UIntPtr",
        ElementType.Char => "char", var e => Primitive(e) ?? corlib.TypeName,
    };

    /// <summary>The comparison key of a primitive (char is uint16_t in the prototypes); null for other element types.</summary>
    private static string? Primitive(ElementType e) => e switch
    {
        ElementType.Boolean => "bool", ElementType.Char => "ushort", ElementType.I1 => "sbyte", ElementType.U1 => "byte",
        ElementType.I2 => "short", ElementType.U2 => "ushort", ElementType.I4 => "int", ElementType.U4 => "uint",
        ElementType.I8 => "long", ElementType.U8 => "ulong", ElementType.R4 => "float", ElementType.R8 => "double",
        ElementType.I => "nint", ElementType.U => "nuint", _ => null,
    };

    private static readonly Dictionary<string, string> KeywordPrimitives = new(StringComparer.Ordinal)
    {
        ["bool"] = "bool", ["char"] = "ushort", ["sbyte"] = "sbyte", ["byte"] = "byte", ["short"] = "short", ["ushort"] = "ushort",
        ["int"] = "int", ["uint"] = "uint", ["long"] = "long", ["ulong"] = "ulong", ["float"] = "float", ["double"] = "double",
        ["IntPtr"] = "nint", ["UIntPtr"] = "nuint",
        // the enums Il2Cpp shares enum instantiations through
        ["SByteEnum"] = "sbyte", ["ByteEnum"] = "byte", ["Int16Enum"] = "short", ["UInt16Enum"] = "ushort",
        ["Int32Enum"] = "int", ["UInt32Enum"] = "uint", ["Int64Enum"] = "long", ["UInt64Enum"] = "ulong",
    };

    private static readonly Dictionary<string, string> ClrNames = new(StringComparer.Ordinal)
    {
        ["bool"] = "System.Boolean", ["char"] = "System.Char", ["sbyte"] = "System.SByte", ["byte"] = "System.Byte", ["short"] = "System.Int16",
        ["ushort"] = "System.UInt16", ["int"] = "System.Int32", ["uint"] = "System.UInt32", ["long"] = "System.Int64", ["ulong"] = "System.UInt64",
        ["float"] = "System.Single", ["double"] = "System.Double", ["string"] = "System.String", ["object"] = "System.Object",
        ["IntPtr"] = "System.IntPtr", ["UIntPtr"] = "System.UIntPtr",
    };

    private static string ClrName(string keyword) => ClrNames.GetValueOrDefault(keyword, keyword);

    /// <summary>Lower-case letters and digits only: how C names (any punctuation made '_') and C# names compare.</summary>
    private static string Normalize(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (char ch in name)
            if (char.IsAsciiLetterOrDigit(ch)) sb.Append(char.ToLowerInvariant(ch));
        return sb.ToString();
    }

    [GeneratedRegex(@"^(const\s+)?MethodInfo(_\w+)?\s*\*$")]
    private static partial Regex MethodInfoType();
}
