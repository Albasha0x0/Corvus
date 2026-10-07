using System.Globalization;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;
using static NetDecompilerMcp.Services.MetadataUtil;

namespace NetDecompilerMcp.Services;

/// <summary>Name, string-literal, constant and IL-pattern search over loaded assemblies.</summary>
public sealed class SearchService
{
    public sealed record StringHit(LoadedAssembly Assembly, IMemberDef Owner, uint? ILOffset, string Value);

    public sealed record ConstantHit(LoadedAssembly Assembly, IMemberDef Owner, uint? ILOffset, string Kind, string Value);

    public sealed record IlMatch(LoadedAssembly Assembly, MethodDef Method, uint Offset, List<string> Instructions);

    // ------------------------------------------------------------------ symbols

    public SearchResult<ResolvedSymbol> SearchSymbols(string query, bool regex, SymbolKind kind, IReadOnlyList<LoadedAssembly> scope,
        string? namespaceFilter, int limit, CancellationToken ct)
    {
        var matcher = CreateMatcher(query, regex);
        bool matchFullName = regex || query.Contains('.') || query.Contains(':') || query.Contains('/');
        var hits = ParallelCollect<(ResolvedSymbol Symbol, int Rank)>(scope, (asm, type, found) =>
        {
            if (namespaceFilter != null && !TopLevel(type).Namespace.String.StartsWith(namespaceFilter, StringComparison.OrdinalIgnoreCase))
                return;
            foreach (var member in MembersOf(type, kind))
            {
                var name = member is TypeDef td ? Format.StripArity(td.Name) : member.Name.String;
                if (matcher(name) || (matchFullName && matcher(Format.MemberLabel(member))))
                    found.Add((new ResolvedSymbol(asm, member), Rank(name, query)));
            }
        }, ct);

        var ordered = hits.OrderBy(h => h.Rank).ThenBy(h => h.Symbol.Label.Length).Select(h => h.Symbol).ToList();
        return new(ordered.Take(limit).ToList(), ordered.Count);
    }

    internal static IEnumerable<IMemberDef> MembersOf(TypeDef type, SymbolKind kind)
    {
        if (kind is SymbolKind.Any or SymbolKind.Type) yield return type;
        if (kind is SymbolKind.Any or SymbolKind.Member or SymbolKind.Method)
            foreach (var m in type.Methods.Where(m => !IsAccessor(m))) yield return m;
        if (kind is SymbolKind.Any or SymbolKind.Member or SymbolKind.Field)
            foreach (var f in type.Fields) yield return f;
        if (kind is SymbolKind.Any or SymbolKind.Member or SymbolKind.Property)
            foreach (var p in type.Properties) yield return p;
        if (kind is SymbolKind.Any or SymbolKind.Member or SymbolKind.Event)
            foreach (var e in type.Events) yield return e;
    }

    internal static int Rank(string name, string query) =>
        name.Equals(query, StringComparison.Ordinal) ? 0
        : name.Equals(query, StringComparison.OrdinalIgnoreCase) ? 1
        : name.StartsWith(query, StringComparison.OrdinalIgnoreCase) ? 2
        : 3;

    // ------------------------------------------------------------------ strings

    public SearchResult<StringHit> SearchStrings(string query, bool regex, IReadOnlyList<LoadedAssembly> scope, int limit, CancellationToken ct)
    {
        var matcher = CreateMatcher(query, regex);
        var hits = ParallelCollect<StringHit>(scope, (asm, type, found) =>
        {
            foreach (var f in type.Fields)
                if (f.HasConstant && f.Constant.Value is string s && matcher(s))
                    found.Add(new StringHit(asm, f, null, s));
            foreach (var m in type.Methods)
                foreach (var instr in FastIlReader.Instructions(asm, m))
                    if (instr.OpCode.Code == Code.Ldstr && instr.Operand is string str && matcher(str))
                        found.Add(new StringHit(asm, m, instr.Offset, str));
        }, ct);
        return SearchResult<StringHit>.From(hits, limit);
    }

    // ------------------------------------------------------------------ constants

    /// <summary>
    /// A numeric constant as an IL literal (ldc.*), a const/enum field value, or a custom-attribute argument.
    /// </summary>
    public SearchResult<ConstantHit> SearchConstants(string value, IReadOnlyList<LoadedAssembly> scope, int limit, CancellationToken ct)
    {
        var target = ParseConstant(value);
        // tables (crypto round constants, CRC tables, S-boxes of words) live in array initializer data, not in IL;
        // values of 0x10000 and more only — small ones would match everywhere
        bool searchData = target == decimal.Truncate(target) && Math.Abs(target) >= 0x10000 && target >= long.MinValue && target <= ulong.MaxValue;
        var arrayHits = new System.Collections.Concurrent.ConcurrentBag<(LoadedAssembly Asm, FieldDef Field, int Index)>();
        var hits = ParallelCollect<ConstantHit>(scope, (asm, type, found) =>
        {
            foreach (var f in type.Fields)
            {
                if (f.HasConstant && NumericEquals(f.Constant.Value, target))
                    found.Add(new ConstantHit(asm, f, null, type.IsEnum ? "enum member" : "const field", Format.Literal(f.Constant.Value)));
                if (searchData && f.HasFieldRVA && MetadataUtil.Try(() => f.InitialValue) is { Length: >= 4 } data)
                    foreach (var index in ArrayElements(data, target))
                        arrayHits.Add((asm, f, index));
            }

            foreach (var m in type.Methods)
            {
                foreach (var ca in m.CustomAttributes)
                    foreach (var arg in ca.ConstructorArguments.Concat(ca.NamedArguments.Select(n => n.Argument)).SelectMany(Format.AttributeValues))
                        if (NumericEquals(arg, target))
                            found.Add(new ConstantHit(asm, m, null, $"attribute [{Format.StripArity(ca.AttributeType.Name)}]", Format.Literal(arg)));
                foreach (var instr in FastIlReader.Instructions(asm, m))
                {
                    object? literal = instr.IsLdcI4() ? instr.GetLdcI4Value()
                        : instr.OpCode.Code is Code.Ldc_I8 or Code.Ldc_R4 or Code.Ldc_R8 ? instr.Operand : null;
                    if (literal != null && NumericEquals(literal, target))
                        found.Add(new ConstantHit(asm, m, instr.Offset, instr.OpCode.Name, Format.Literal(literal)));
                }
            }
        }, ct);
        // the method that initializes each array (ldtoken of the data field) owns the hit
        foreach (var group in arrayHits.GroupBy(h => (h.Asm, h.Field)))
        {
            var (asm, field) = group.Key;
            var user = asm.Module.GetTypes().SelectMany(t => t.Methods)
                .FirstOrDefault(m => FastIlReader.Instructions(asm, m).Any(i => i.OpCode.Code == Code.Ldtoken && i.Operand is IField f && f.MDToken == field.MDToken));
            foreach (var (_, _, index) in group.OrderBy(h => h.Index))
                hits.Add(new ConstantHit(asm, (IMemberDef?)user ?? field, null,
                    $"array initializer element [{index}]{(user != null ? $" (data {field.Name})" : "")}", Format.Literal(target)));
        }
        return SearchResult<ConstantHit>.From(hits, limit);
    }

    /// <summary>Indexes of 4- or 8-byte little-endian elements equal to <paramref name="target"/> (signed or unsigned).</summary>
    private static IEnumerable<int> ArrayElements(byte[] data, decimal target)
    {
        bool fits32 = target >= int.MinValue && target <= uint.MaxValue;
        int width = fits32 ? 4 : 8;
        for (int i = 0, n = 0; i + width <= data.Length; i += width, n++)
        {
            bool match = fits32
                ? (target >= 0 ? BitConverter.ToUInt32(data, i) == (uint)target : BitConverter.ToInt32(data, i) == (int)target)
                : (target >= 0 ? BitConverter.ToUInt64(data, i) == (ulong)target : BitConverter.ToInt64(data, i) == (long)target);
            if (match) yield return n;
        }
    }

    private static decimal ParseConstant(string value)
    {
        var s = value.Trim().Replace("_", "");
        bool negative = s.StartsWith('-');
        if (negative) s = s[1..];
        decimal result;
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            && ulong.TryParse(s[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex))
            result = hex;
        else if (!decimal.TryParse(s.TrimEnd('f', 'F', 'd', 'D', 'L', 'l', 'u', 'U'), NumberStyles.Float, CultureInfo.InvariantCulture, out result))
            throw new ToolError($"'{value}' is not a number. Use search_strings for text.");
        return negative ? -result : result;
    }

    private static bool NumericEquals(object? value, decimal target)
    {
        try
        {
            return value switch
            {
                // IL stores uint/ulong literals as signed: 0xFFFFFFFF is ldc.i4 -1.
                int i => i == target || (target > int.MaxValue && target <= uint.MaxValue && unchecked((uint)i) == target),
                long l => l == target || (target > long.MaxValue && unchecked((ulong)l) == target),
                uint u => u == target,
                ulong ul => ul == target,
                short sh => sh == target,
                ushort us => us == target,
                sbyte sb => sb == target,
                byte b => b == target,
                char c => c == target,
                float f => float.IsFinite(f) && (decimal)f == target,
                double d => double.IsFinite(d) && Math.Abs(d) < 7.9e28 && (decimal)d == target,
                _ => false,
            };
        }
        catch (OverflowException)
        {
            return false;
        }
    }

    // ------------------------------------------------------------------ IL patterns

    private sealed record PatternElement(Func<string, bool>? OpCode, Func<string, bool>? Operand, bool IsGap);

    /// <summary>
    /// Finds instruction sequences. Pattern elements are separated by ';' or newlines; each is
    /// "opcode [operand]" with * / ? wildcards, e.g. "ldstr *password*; call *::Hash*", "ldc.i4 0x1F4", "callvirt *Encrypt*".
    /// "..." matches a gap of up to 16 instructions.
    /// </summary>
    public SearchResult<IlMatch> SearchIL(string pattern, IReadOnlyList<LoadedAssembly> scope, int limit, CancellationToken ct)
    {
        var elements = ParsePattern(pattern);
        var hits = ParallelCollect<IlMatch>(scope, (asm, type, found) =>
        {
            foreach (var m in type.Methods)
            {
                var instrs = FastIlReader.Instructions(asm, m);
                for (int start = 0; start < instrs.Count; start++)
                {
                    int end = MatchAt(instrs, start, elements, 0);
                    if (end < 0) continue;
                    found.Add(new IlMatch(asm, m, instrs[start].Offset,
                        instrs.Skip(start).Take(end - start).Select(i => $"IL_{i.Offset:X4}: {i.OpCode.Name} {OperandText(i)}".TrimEnd()).ToList()));
                    start = end - 1;
                }
            }
        }, ct);
        return SearchResult<IlMatch>.From(hits, limit);
    }

    /// <summary>Returns the index after the match, or -1.</summary>
    private static int MatchAt(IList<Instruction> instrs, int index, List<PatternElement> elements, int e)
    {
        if (e == elements.Count) return index;
        var el = elements[e];
        if (el.IsGap)
        {
            for (int skip = 0; skip <= 16 && index + skip <= instrs.Count; skip++)
            {
                int r = MatchAt(instrs, index + skip, elements, e + 1);
                if (r >= 0) return r;
            }
            return -1;
        }
        if (index >= instrs.Count) return -1;
        var instr = instrs[index];
        if (el.OpCode != null && !el.OpCode(instr.OpCode.Name)) return -1;
        if (el.Operand != null && !OperandForms(instr).Any(el.Operand)) return -1;
        return MatchAt(instrs, index + 1, elements, e + 1);
    }

    private static List<PatternElement> ParsePattern(string pattern)
    {
        var parts = pattern.Split([';', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length == 0)
            throw new ToolError("IL pattern is empty.");
        var list = new List<PatternElement>();
        foreach (var part in parts)
        {
            if (part == "...") { list.Add(new PatternElement(null, null, true)); continue; }
            int space = part.IndexOfAny([' ', '\t']);
            var op = space < 0 ? part : part[..space];
            var operand = space < 0 ? null : part[(space + 1)..].Trim();
            list.Add(new PatternElement(op == "*" ? null : Glob(op), string.IsNullOrEmpty(operand) || operand == "*" ? null : Glob(operand), false));
        }
        if (list.All(p => p.IsGap))
            throw new ToolError("IL pattern needs at least one instruction element.");
        return list;
    }

    private static Func<string, bool> Glob(string glob)
    {
        var re = new Regex("^" + Regex.Escape(glob.Trim('"')).Replace("\\*", ".*").Replace("\\?", ".") + "$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline, TimeSpan.FromSeconds(1));
        return s => re.IsMatch(s);
    }

    /// <summary>Text forms an operand pattern is tested against.</summary>
    private static IEnumerable<string> OperandForms(Instruction i)
    {
        switch (i.Operand)
        {
            case null: yield return ""; break;
            case string s: yield return s; break;
            case MemberRef { IsFieldRef: true } fr: yield return Format.MemberLabel(fr); yield return fr.FullName; break;
            case IMethod m: yield return Format.MemberLabel(m); yield return m.FullName; break;
            case IField f: yield return Format.MemberLabel(f); yield return f.FullName; break;
            case ITypeDefOrRef t: yield return t.FullName; yield return t.Name; break;
            case int n: yield return n.ToString(CultureInfo.InvariantCulture); yield return $"0x{n:X}"; break;
            case sbyte n: yield return n.ToString(CultureInfo.InvariantCulture); yield return $"0x{n:X}"; break;
            case long n: yield return n.ToString(CultureInfo.InvariantCulture); yield return $"0x{n:X}"; break;
            case float n: yield return n.ToString(CultureInfo.InvariantCulture); break;
            case double n: yield return n.ToString(CultureInfo.InvariantCulture); break;
            case Local l: yield return l.Index.ToString(CultureInfo.InvariantCulture); yield return l.Name ?? ""; break;
            case Parameter p: yield return p.Index.ToString(CultureInfo.InvariantCulture); yield return p.Name ?? ""; break;
            default: yield return i.Operand.ToString() ?? ""; break;
        }
        if (i.IsLdcI4() && i.Operand is null)
        {
            var v = i.GetLdcI4Value();
            yield return v.ToString(CultureInfo.InvariantCulture);
            yield return $"0x{v:X}";
        }
    }

    private static string OperandText(Instruction i) => i.Operand switch
    {
        null => "",
        string s => Format.Literal(Format.Clip(s, 120)),
        IMemberRef member and (IMethod or IField) => Format.MemberLabel(member),
        ITypeDefOrRef t => t.FullName,
        Instruction target => $"IL_{target.Offset:X4}",
        Instruction[] targets => "(" + string.Join(", ", targets.Select(t => $"IL_{t.Offset:X4}")) + ")",
        _ => Format.Literal(i.Operand),
    };

    // ------------------------------------------------------------------ helpers

    /// <summary>Builds a predicate: substring (case-insensitive), wildcard (* ?) or regex.</summary>
    public static Func<string, bool> CreateMatcher(string query, bool regex)
    {
        if (string.IsNullOrEmpty(query))
            throw new ToolError("Query is empty.");
        if (!regex && (query.Contains('*') || query.Contains('?')))
            return Glob(query);
        if (!regex)
            return s => s.Contains(query, StringComparison.OrdinalIgnoreCase);
        Regex re;
        try { re = new Regex(query, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)); }
        catch (ArgumentException ex) { throw new ToolError($"Invalid regex: {ex.Message}"); }
        return s =>
        {
            try { return re.IsMatch(s); }
            catch (RegexMatchTimeoutException) { return false; }
        };
    }
}
