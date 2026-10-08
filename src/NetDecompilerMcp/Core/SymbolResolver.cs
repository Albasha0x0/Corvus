using System.Globalization;
using System.Text;
using dnlib.DotNet;

namespace NetDecompilerMcp.Core;

public enum SymbolKind { Any, Type, Method, Field, Property, Event, Member }

public sealed record ResolvedSymbol(LoadedAssembly Assembly, IMemberDef Member)
{
    public string Kind => Member switch
    {
        TypeDef => "type",
        MethodDef => "method",
        FieldDef => "field",
        PropertyDef => "property",
        EventDef => "event",
        _ => "member",
    };

    public string Label => Format.MemberLabel(Member);
    public override string ToString() => $"[{Assembly.Id}] {Kind} {Label} ({Format.Token(Member)})";
}

/// <summary>
/// Resolves loosely written symbol strings to exact definitions. Accepted forms:
///   Ns.Type | Ns.Outer+Inner | Ns.Outer/Inner | Ns.Outer.Inner | Type (short name) | List`1 | List&lt;T&gt;
///   Ns.Type::Member | Ns.Type.Member | Ns.Type::Method(int, string) | Ns.Type::.ctor | Ns.Type::ctor
///   0x06001234 (metadata token; scope it with the assembly parameter when several are loaded)
/// </summary>
public static class SymbolResolver
{
    /// <param name="referenced">
    /// Also match types that are only referenced (not defined) by loaded code, read from their defining file.
    /// Used by tools that search for usages, overrides or derived types.
    /// </param>
    public static IReadOnlyList<ResolvedSymbol> Resolve(AssemblyWorkspace ws, string? assembly, string symbol, SymbolKind kind = SymbolKind.Any, bool referenced = false)
    {
        if (string.IsNullOrWhiteSpace(symbol))
            throw new ToolError("Symbol is empty.");
        var scope = ws.Scope(assembly);
        // Names with invisible characters are shown escaped (see Format.EscapeInvisible); accept them back as shown.
        var query = Format.UnescapeInvisible(symbol.Trim());

        if (TryParseToken(query, out uint token))
            return ResolveToken(scope, token, kind, query);

        string? signature = null;
        int paren = query.IndexOf('(');
        if (paren >= 0)
        {
            int close = query.LastIndexOf(')');
            signature = close > paren ? query[(paren + 1)..close] : query[(paren + 1)..];
            query = query[..paren].Trim();
        }

        var results = new List<ResolvedSymbol>();
        string? memberPart = null;
        string typePart = query;

        int sep = query.IndexOf("::", StringComparison.Ordinal);
        if (sep >= 0)
        {
            typePart = query[..sep];
            memberPart = query[(sep + 2)..];
        }

        if (memberPart == null && kind is SymbolKind.Any or SymbolKind.Type && signature == null)
        {
            results.AddRange(FindTypes(scope, typePart));
            if (results.Count == 0 && referenced) results.AddRange(FindReferencedTypes(ws, scope, typePart));
            if (results.Count > 0 || kind == SymbolKind.Type)
                return Finish(results, symbol, scope, typePart, null);
        }

        if (memberPart == null && kind != SymbolKind.Type && IsBareIdentifier(query))
        {
            // Bare member name: search every type in scope; exact-case matches win over case-insensitive ones.
            foreach (var a in scope)
                foreach (var t in a.Module.GetTypes())
                    results.AddRange(FindMembers(new ResolvedSymbol(a, t), query, signature, kind).Where(r => r.Member is not TypeDef));
            if (results.Any(r => r.Member.Name == query))
                return results.Where(r => r.Member.Name == query).ToList();
            if (results.Count > 0)
                return results;
        }

        if (memberPart == null)
        {
            // "Ns.Type.Member": split at the last top-level dot, keeping ".ctor"/".cctor" intact.
            if (!TrySplitMember(query, out typePart, out memberPart))
                return Finish(results, symbol, scope, query, null);
        }

        var types = FindTypes(scope, typePart).ToList();
        if (types.Count == 0 && referenced) types = FindReferencedTypes(ws, scope, typePart).ToList();
        if (types.Count == 0)
            return Finish(results, symbol, scope, typePart, null);

        foreach (var t in types)
            results.AddRange(FindMembers(t, memberPart!, signature, kind));
        return Finish(results, symbol, scope, typePart, (types, memberPart!));
    }

    /// <summary>Resolves to exactly one symbol, or throws with the candidate list.</summary>
    public static ResolvedSymbol ResolveOne(AssemblyWorkspace ws, string? assembly, string symbol, SymbolKind kind = SymbolKind.Any, bool referenced = false)
    {
        var all = Resolve(ws, assembly, symbol, kind, referenced);
        if (all.Count == 1)
            return all[0];
        throw new ToolError($"'{symbol}' is ambiguous ({all.Count} matches). Pass a parameter signature like Method(int, string), " +
                            $"the assembly parameter, or a metadata token:\n" + string.Join("\n", all.Take(30).Select(r => "  " + r)));
    }

    private static IReadOnlyList<ResolvedSymbol> Finish(List<ResolvedSymbol> results, string original, IReadOnlyList<LoadedAssembly> scope,
        string typePart, (List<ResolvedSymbol> Types, string Member)? memberSearch)
    {
        if (results.Count > 0)
            return results;

        var msg = new StringBuilder($"Symbol '{original}' not found");
        msg.Append(scope.Count == 1 ? $" in {scope[0].Id}." : $" in {scope.Count} loaded assemblies.");

        if (memberSearch is { } ms)
        {
            var names = ms.Types.SelectMany(t => Members((TypeDef)t.Member)).Select(m => m.Name.String).Distinct().ToList();
            var close = names.Where(n => n.Contains(ms.Member, StringComparison.OrdinalIgnoreCase)
                                         || ms.Member.Contains(n, StringComparison.OrdinalIgnoreCase)).Take(20).ToList();
            msg.Append($" Type(s) found: {string.Join(", ", ms.Types.Take(5).Select(t => t.Label))}, but no member '{ms.Member}'.");
            if (close.Count > 0)
                msg.Append(" Similar members: ").Append(string.Join(", ", close));
            else if (names.Count <= 60)
                msg.Append(" Members: ").Append(string.Join(", ", names));
        }
        else
        {
            var last = LastSegment(typePart);
            var close = scope.SelectMany(a => a.Module.GetTypes())
                .Where(t => last.Length > 0 && t.Name.String.Contains(last, StringComparison.OrdinalIgnoreCase))
                .Take(15).Select(t => t.FullName).ToList();
            if (close.Count > 0)
                msg.Append(" Similar types: ").Append(string.Join(", ", close));
            msg.Append(" (Use search_symbols for a broader search.)");
        }
        throw new ToolError(msg.ToString());
    }

    internal static IEnumerable<ResolvedSymbol> FindTypes(IReadOnlyList<LoadedAssembly> scope, string typeQuery)
    {
        var q = NormalizeTypeName(typeQuery);
        var all = scope.SelectMany(a => a.Module.GetTypes().Select(t => (a, t))).ToList();

        bool HasNs(string s) => s.Contains('.') || s.Contains('/');
        var levels = new Func<TypeDef, bool>[]
        {
            t => t.FullName == q,
            t => Dotted(t.FullName) == Dotted(q) || Dotted(StripAllArity(t.FullName)) == Dotted(q),
            t => string.Equals(Dotted(t.FullName), Dotted(q), StringComparison.OrdinalIgnoreCase)
                 || string.Equals(Dotted(StripAllArity(t.FullName)), Dotted(q), StringComparison.OrdinalIgnoreCase),
            t => !HasNs(q) && (t.Name == q || Format.StripArity(t.Name) == q),
            t => !HasNs(q) && (string.Equals(t.Name, q, StringComparison.OrdinalIgnoreCase) || string.Equals(Format.StripArity(t.Name), q, StringComparison.OrdinalIgnoreCase)),
            // "Outer.Inner" or "Outer/Inner" without namespace
            t => HasNs(q) && Dotted(StripAllArity(t.FullName)).EndsWith("." + Dotted(q), StringComparison.Ordinal),
        };

        foreach (var level in levels)
        {
            var hits = all.Where(x => level(x.t)).Select(x => new ResolvedSymbol(x.a, x.t)).ToList();
            if (hits.Count > 0)
                return hits;
        }
        return [];
    }

    /// <summary>
    /// Types referenced but not defined in scope, resolved to their defining file; deduplicated by full name across
    /// forwarding facades.
    /// </summary>
    private static IEnumerable<ResolvedSymbol> FindReferencedTypes(AssemblyWorkspace ws, IReadOnlyList<LoadedAssembly> scope, string typeQuery)
    {
        var q = NormalizeTypeName(typeQuery);
        bool HasNs(string s) => s.Contains('.') || s.Contains('/');
        var refs = scope.SelectMany(a => a.Module.GetTypeRefs()).ToList();
        var levels = new Func<TypeRef, bool>[]
        {
            t => t.FullName == q,
            t => Dotted(t.FullName) == Dotted(q) || Dotted(StripAllArity(t.FullName)) == Dotted(q),
            t => !HasNs(q) && (t.Name == q || Format.StripArity(t.Name) == q),
        };
        foreach (var level in levels)
        {
            var hits = new List<ResolvedSymbol>();
            foreach (var group in refs.Where(level).GroupBy(t => t.FullName))
            {
                var def = group.Select(t => Services.MetadataUtil.Try(() => t.ResolveTypeDef())).FirstOrDefault(d => d != null);
                if (def?.Module is ModuleDefMD module && Services.MetadataUtil.IsReferenceOnly(def))
                    hits.Add(new ResolvedSymbol(ws.ReferenceView(module), def));
            }
            if (hits.Count > 0) return hits;
        }
        return [];
    }

    private static IEnumerable<IMemberDef> Members(TypeDef t) =>
        t.Methods.Cast<IMemberDef>().Concat(t.Fields).Concat(t.Properties).Concat(t.Events).Concat(t.NestedTypes);

    private static IEnumerable<ResolvedSymbol> FindMembers(ResolvedSymbol typeSym, string memberQuery, string? signature, SymbolKind kind)
    {
        var type = (TypeDef)typeSym.Member;
        var name = memberQuery.Trim();
        int lt = name.IndexOf('<');
        if (lt > 0) name = name[..lt];
        if (name is "ctor" or "#ctor" or ".ctor") name = ".ctor";
        if (name is "cctor" or "#cctor" or ".cctor") name = ".cctor";

        IEnumerable<IMemberDef> candidates = kind switch
        {
            SymbolKind.Method => type.Methods,
            SymbolKind.Field => type.Fields,
            SymbolKind.Property => type.Properties,
            SymbolKind.Event => type.Events,
            SymbolKind.Type => type.NestedTypes,
            SymbolKind.Member => type.Methods.Cast<IMemberDef>().Concat(type.Fields).Concat(type.Properties).Concat(type.Events),
            _ => Members(type),
        };
        var list = candidates.ToList();

        var hits = list.Where(m => m.Name == name).ToList();
        if (hits.Count == 0)
            hits = list.Where(m => string.Equals(m.Name, name, StringComparison.OrdinalIgnoreCase)).ToList();
        if (hits.Count == 0 && kind is SymbolKind.Any or SymbolKind.Type)
            hits = type.NestedTypes.Where(n => Format.StripArity(n.Name) == name).Cast<IMemberDef>().ToList();

        // A field-like event has a compiler-generated backing field with the same name: prefer the event.
        if (kind != SymbolKind.Field && hits.Any(h => h is EventDef))
            hits = hits.Where(h => h is not FieldDef).ToList();

        if (signature != null)
        {
            var wanted = NormalizeSignature(signature);
            hits = hits.Where(m => m is not MethodDef md || SignatureMatches(md, wanted)).ToList();
        }
        return hits.Select(m => new ResolvedSymbol(typeSym.Assembly, m));
    }

    private static string NormalizeSignature(string s) =>
        new string(s.Where(c => !char.IsWhiteSpace(c)).ToArray()).ToLowerInvariant();

    private static bool SignatureMatches(MethodDef m, string wanted)
    {
        var parameters = m.MethodSig?.Params ?? (IList<TypeSig>)Array.Empty<TypeSig>();
        var shortForm = NormalizeSignature(string.Join(",", parameters.Select(Format.Type)));
        var fullForm = NormalizeSignature(string.Join(",", parameters.Select(p => p.FullName)));
        // Also accept parameter names, e.g. "int a, string b".
        var named = NormalizeSignature(Format.Parameters(m));
        return wanted == shortForm || wanted == fullForm || wanted == named
               || NormalizeSignature(string.Join(",", wanted.Split(',').Select(p => p.Replace("system.", "")))) == shortForm.Replace("system.", "");
    }

    /// <summary>A plain identifier with no namespace, type separator or constructor name.</summary>
    private static bool IsBareIdentifier(string s) =>
        s.Length > 0 && (char.IsLetter(s[0]) || s[0] == '_') && s.All(c => char.IsLetterOrDigit(c) || c == '_');

    private static bool TrySplitMember(string query, out string typePart, out string memberPart)
    {
        foreach (var special in new[] { "..ctor", "..cctor" })
            if (query.EndsWith(special, StringComparison.Ordinal))
            {
                typePart = query[..^special.Length];
                memberPart = special[1..];
                return true;
            }

        int depth = 0;
        for (int i = query.Length - 1; i > 0; i--)
        {
            char c = query[i];
            if (c == '>') depth++;
            else if (c == '<') depth--;
            else if (depth == 0 && (c == '.' || c == '/' || c == '+'))
            {
                typePart = query[..i];
                memberPart = query[(i + 1)..];
                return memberPart.Length > 0;
            }
        }
        typePart = memberPart = "";
        return false;
    }

    /// <summary>Converts C#-style generics to metadata arity (Dictionary&lt;K,V&gt; -> Dictionary`2) and '+' to '/'.</summary>
    internal static string NormalizeTypeName(string name)
    {
        var sb = new StringBuilder();
        int i = 0;
        name = name.Trim().Replace('+', '/');
        while (i < name.Length)
        {
            char c = name[i];
            if (c == '<' && (i == 0 || name[i - 1] is '.' or '/'))
            {
                // Compiler-generated names (<Module>, <>c) start with '<'; not generic arguments.
                int close = name.IndexOf('>', i);
                if (close < 0) close = name.Length - 1;
                sb.Append(name, i, close - i + 1);
                i = close + 1;
                continue;
            }
            if (c == '<')
            {
                int depth = 0, commas = 0, j = i;
                for (; j < name.Length; j++)
                {
                    if (name[j] == '<') depth++;
                    else if (name[j] == '>') { depth--; if (depth == 0) break; }
                    else if (name[j] == ',' && depth == 1) commas++;
                }
                sb.Append('`').Append(commas + 1);
                i = j + 1;
                continue;
            }
            sb.Append(c);
            i++;
        }
        return sb.ToString();
    }

    private static string Dotted(string s) => s.Replace('/', '.');

    private static string StripAllArity(string s)
    {
        var sb = new StringBuilder(s.Length);
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] == '`')
            {
                while (i + 1 < s.Length && char.IsDigit(s[i + 1])) i++;
                continue;
            }
            sb.Append(s[i]);
        }
        return sb.ToString();
    }

    private static string LastSegment(string s)
    {
        var n = NormalizeTypeName(s);
        int i = n.LastIndexOfAny(['.', '/']);
        return Format.StripArity(i >= 0 ? n[(i + 1)..] : n);
    }

    public static bool TryParseToken(string s, out uint token)
    {
        token = 0;
        s = s.Trim();
        bool hex = s.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
        var digits = hex ? s[2..] : s;
        if (!hex && digits.Length != 8)
            return false;
        if (digits.Length is 0 or > 8 || !uint.TryParse(digits, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out token))
            return false;
        uint table = token >> 24;
        return table is 0x02 or 0x04 or 0x06 or 0x14 or 0x17;
    }

    private static IReadOnlyList<ResolvedSymbol> ResolveToken(IReadOnlyList<LoadedAssembly> scope, uint token, SymbolKind kind, string original)
    {
        var results = new List<ResolvedSymbol>();
        foreach (var a in scope)
        {
            if (a.Module.ResolveToken(token) is IMemberDef def)
            {
                var r = new ResolvedSymbol(a, def);
                if (kind == SymbolKind.Any || KindMatches(r, kind))
                    results.Add(r);
            }
        }
        if (results.Count == 0)
            throw new ToolError($"Token {original} does not resolve to a {(kind == SymbolKind.Any ? "definition" : kind.ToString().ToLowerInvariant())} in {string.Join(", ", scope.Select(s => s.Id))}.");
        if (results.Count > 1)
            throw new ToolError($"Token {original} exists in several assemblies; pass the assembly parameter: {string.Join(", ", results.Select(r => r.ToString()))}");
        return results;
    }

    private static bool KindMatches(ResolvedSymbol r, SymbolKind kind) => kind switch
    {
        SymbolKind.Type => r.Member is TypeDef,
        SymbolKind.Method => r.Member is MethodDef,
        SymbolKind.Field => r.Member is FieldDef,
        SymbolKind.Property => r.Member is PropertyDef,
        SymbolKind.Event => r.Member is EventDef,
        SymbolKind.Member => r.Member is not TypeDef,
        _ => true,
    };

    public static SymbolKind ParseKind(string? kind) => (kind ?? "any").Trim().ToLowerInvariant() switch
    {
        "" or "any" or "all" => SymbolKind.Any,
        "type" or "class" or "types" => SymbolKind.Type,
        "method" or "methods" => SymbolKind.Method,
        "field" or "fields" => SymbolKind.Field,
        "property" or "properties" => SymbolKind.Property,
        "event" or "events" => SymbolKind.Event,
        "member" or "members" => SymbolKind.Member,
        _ => throw new ToolError($"Unknown kind '{kind}'. Use any, type, method, field, property, event or member."),
    };
}
