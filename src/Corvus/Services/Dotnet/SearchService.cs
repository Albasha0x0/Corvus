using System.Globalization;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;
using static Corvus.Core.MetadataUtil;

namespace Corvus.Services;

/// <summary>Name, string-literal, constant and IL-pattern search over loaded assemblies.</summary>
public sealed class SearchService(ServerOptions? options = null)
{
    /// <summary>How long one search may run; past it the search fails with the results found so far as its partial result.</summary>
    public TimeSpan TimeLimit { get; set; } = TimeSpan.FromSeconds(options?.TimeoutSeconds ?? 180);

    /// <summary>Results listed in a timeout error's partial result.</summary>
    private const int PartialResults = 50;

    private static List<string> Labels<T>(List<T> found, Func<T, string> label) => found.Take(PartialResults).Select(label).ToList();

    public sealed record StringHit(LoadedAssembly Assembly, IMemberDef Owner, uint? ILOffset, string Value);

    public sealed record ConstantHit(LoadedAssembly Assembly, IMemberDef Owner, uint? ILOffset, string Kind, string Value);

    public sealed record IlMatch(LoadedAssembly Assembly, MethodDef Method, uint Offset, List<string> Instructions);

    public SearchResult<ResolvedSymbol> SearchSymbols(string query, bool regex, SymbolKind kind, IReadOnlyList<LoadedAssembly> scope,
        string? namespaceFilter, int limit, CancellationToken ct, RegexTimeouts? timeouts = null)
    {
        var matcher = CreateMatcher(query, regex, timeouts);
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
        }, ct, TimeLimit, sofar => Labels(sofar, h => $"{h.Symbol.Label}  [{h.Symbol.Assembly.Id}]"));

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

    public SearchResult<StringHit> SearchStrings(string query, bool regex, IReadOnlyList<LoadedAssembly> scope, int limit, CancellationToken ct,
        RegexTimeouts? timeouts = null)
    {
        var matcher = CreateMatcher(query, regex, timeouts);
        var hits = ParallelCollect<StringHit>(scope, (asm, type, found) =>
        {
            foreach (var f in type.Fields)
                if (f.HasConstant && f.Constant.Value is string s && matcher(s))
                    found.Add(new StringHit(asm, f, null, s));
            foreach (var m in type.Methods)
                foreach (var instr in FastIlReader.Instructions(asm, m))
                    if (instr.OpCode.Code == Code.Ldstr && instr.Operand is string str && matcher(str))
                        found.Add(new StringHit(asm, m, instr.Offset, str));
        }, ct, TimeLimit, sofar => Labels(sofar, h => $"{Format.Literal(Format.Clip(h.Value, 80))} in {Format.MemberLabel(h.Owner)}  [{h.Assembly.Id}]"));
        return SearchResult<StringHit>.From(hits, limit);
    }

    /// <summary>
    /// A numeric constant as an IL literal (ldc.*), a const/enum field value, or a custom-attribute argument.
    /// </summary>
    public SearchResult<ConstantHit> SearchConstants(string value, IReadOnlyList<LoadedAssembly> scope, int limit, CancellationToken ct)
    {
        var target = ParseConstant(value);
        // Constant tables (CRC, S-boxes, round constants) live in array initializer data, not IL; each is decoded
        // with the element type of the newarr / span creation that uses it.
        var dataFields = new System.Collections.Concurrent.ConcurrentBag<(LoadedAssembly Asm, FieldDef Field)>();
        // Every user: the compiler shares one data field between identical initializers in different methods.
        var users = new System.Collections.Concurrent.ConcurrentDictionary<FieldDef, System.Collections.Concurrent.ConcurrentDictionary<MethodDef, TypeSig?>>();
        var hits = ParallelCollect<ConstantHit>(scope, (asm, type, found) =>
        {
            foreach (var f in type.Fields)
            {
                if (f.HasConstant && NumericEquals(f.Constant.Value, target))
                    found.Add(new ConstantHit(asm, f, null, type.IsEnum ? "enum member" : "const field", Format.Literal(f.Constant.Value)));
                if (f.HasFieldRVA) dataFields.Add((asm, f));
            }

            foreach (var m in type.Methods)
            {
                foreach (var ca in m.CustomAttributes)
                    foreach (var arg in ca.ConstructorArguments.Concat(ca.NamedArguments.Select(n => n.Argument)).SelectMany(Format.AttributeValues))
                        if (NumericEquals(arg, target))
                            found.Add(new ConstantHit(asm, m, null, $"attribute [{Format.StripArity(ca.AttributeType.Name)}]", Format.Literal(arg)));
                List<Instruction>? il = null;
                int index = -1;
                foreach (var instr in FastIlReader.Instructions(asm, m))
                {
                    index++;
                    object? literal = instr.IsLdcI4() ? instr.GetLdcI4Value()
                        : instr.OpCode.Code is Code.Ldc_I8 or Code.Ldc_R4 or Code.Ldc_R8 ? instr.Operand : null;
                    if (literal != null && NumericEquals(literal, target))
                        found.Add(new ConstantHit(asm, m, instr.Offset, instr.OpCode.Name, Format.Literal(literal)));
                    if (instr.OpCode.Code is Code.Ldtoken or Code.Ldsflda && instr.Operand is FieldDef { HasFieldRVA: true } data
                        && !(users.TryGetValue(data, out var seen) && seen.ContainsKey(m)))
                    {
                        il ??= FastIlReader.Instructions(asm, m).ToList();
                        users.GetOrAdd(data, _ => new()).TryAdd(m, ElementTypeAround(il, index));
                    }
                }
            }
        }, ct, TimeLimit, sofar => Labels(sofar, h => $"{Format.MemberLabel(h.Owner)}{(h.ILOffset is { } o ? $" @IL_{o:X4}" : "")} {h.Kind}  [{h.Assembly.Id}]"));

        foreach (var (asm, field) in dataFields.OrderBy(d => d.Asm.Id, StringComparer.Ordinal).ThenBy(d => d.Field.MDToken.Raw))
        {
            if (MetadataUtil.Try(() => field.InitialValue) is not { Length: > 0 } data) continue;
            IEnumerable<(MethodDef? User, TypeSig? Element)> owners = users.TryGetValue(field, out var u)
                ? u.OrderBy(p => p.Key.MDToken.Raw).Select(p => ((MethodDef?)p.Key, p.Value))
                : [(null, null)];
            foreach (var (user, element) in owners)
            {
                var matches = ArrayMatches(data, element, target).ToList();
                if (matches.Count == 0) continue;
                string where = matches.Count == 1
                    ? $"element {matches[0]}"
                    : $"elements {string.Join(", ", matches.Take(10))}{(matches.Count > 10 ? $" (+{matches.Count - 10} more)" : "")}";
                hits.Add(new ConstantHit(asm, (IMemberDef?)user ?? field, null,
                    $"array initializer {where}{(element != null ? $" of {Format.Type(element)}[]" : "")} (data {field.Name})", Format.Literal(target)));
            }
        }
        return SearchResult<ConstantHit>.From(hits, limit);
    }

    /// <summary>
    /// Where the value is in the data, as "[index]": element by element for a known element type (and as the low /
    /// high half of a 64-bit element for a 32-bit value of 0x10000 or more, as in SHA-512's tables); without one,
    /// aligned 4- or 8-byte words for values of 0x10000 or more only (small values would match everywhere).
    /// </summary>
    private static IEnumerable<string> ArrayMatches(byte[] data, TypeSig? element, decimal target)
    {
        bool integral = target == decimal.Truncate(target);
        bool large = integral && Math.Abs(target) >= 0x10000;
        bool fits32 = target >= int.MinValue && target <= uint.MaxValue;
        var type = element?.ElementType;
        int size = ElementSize(element) ?? 0;
        if (size == 0)
        {
            if (!large || target < long.MinValue || target > ulong.MaxValue) yield break;
            int width = fits32 ? 4 : 8;
            for (int i = 0; i + width <= data.Length; i += width)
            {
                // unsigned or signed reading of the word
                decimal unsigned = width == 4 ? BitConverter.ToUInt32(data, i) : BitConverter.ToUInt64(data, i);
                decimal signed = width == 4 ? BitConverter.ToInt32(data, i) : BitConverter.ToInt64(data, i);
                if (unsigned == target || signed == target)
                    yield return $"at byte offset {i}";
            }
            yield break;
        }
        for (int i = 0, n = 0; i + size <= data.Length; i += size, n++)
        {
            decimal? value = type switch
            {
                ElementType.U1 => data[i],
                ElementType.I1 => (sbyte)data[i],
                ElementType.Boolean => data[i] != 0 ? 1 : 0,
                ElementType.U2 or ElementType.Char => BitConverter.ToUInt16(data, i),
                ElementType.I2 => BitConverter.ToInt16(data, i),
                ElementType.U4 => BitConverter.ToUInt32(data, i),
                ElementType.I4 => BitConverter.ToInt32(data, i),
                ElementType.U8 => BitConverter.ToUInt64(data, i),
                ElementType.I8 => BitConverter.ToInt64(data, i),
                ElementType.R4 => FloatValue(BitConverter.ToSingle(data, i)),
                ElementType.R8 => FloatValue(BitConverter.ToDouble(data, i)),
                _ => null,
            };
            if (value == target) yield return $"[{n}]";
            else if (size == 8 && large && fits32 && type is ElementType.U8 or ElementType.I8)
            {
                if (BitConverter.ToUInt32(data, i) == (uint)(target < 0 ? (int)target : (long)target)) yield return $"[{n}] (low half)";
                else if (BitConverter.ToUInt32(data, i + 4) == (uint)(target < 0 ? (int)target : (long)target)) yield return $"[{n}] (high half)";
            }
        }
    }

    private static decimal? FloatValue(double d)
    {
        if (double.IsNaN(d) || double.IsInfinity(d) || Math.Abs(d) > 7.9e28) return null;
        try { return (decimal)d; } catch (OverflowException) { return null; }
    }

    /// <summary>The element type of the array or span built from the data an instruction loads (within 3 instructions of it).</summary>
    internal static TypeSig? ElementTypeAround(List<Instruction> il, int at)
    {
        for (int k = Math.Max(0, at - 3); k <= Math.Min(il.Count - 1, at + 3); k++)
        {
            var sig = il[k].Operand switch
            {
                ITypeDefOrRef t when il[k].OpCode.Code == Code.Newarr => t.ToTypeSig(),
                MethodSpec { GenericInstMethodSig.GenericArguments.Count: 1 } ms when k > at => ms.GenericInstMethodSig.GenericArguments[0],
                IMethod { DeclaringType: TypeSpec { TypeSig: GenericInstSig { GenericArguments.Count: 1 } g } } when k > at
                    && il[k].OpCode.Code == Code.Newobj && g.GenericType.FullName.StartsWith("System.ReadOnlySpan", StringComparison.Ordinal) => g.GenericArguments[0],
                _ => null,
            };
            if (sig != null) return sig;
        }
        return null;
    }

    internal static int? ElementSize(TypeSig? sig) => sig?.ElementType switch
    {
        ElementType.U1 or ElementType.I1 or ElementType.Boolean => 1,
        ElementType.U2 or ElementType.I2 or ElementType.Char => 2,
        ElementType.U4 or ElementType.I4 or ElementType.R4 => 4,
        ElementType.U8 or ElementType.I8 or ElementType.R8 => 8,
        _ => null,
    };

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
            throw new ToolError(ErrorCode.InvalidArgument, $"'{value}' is not a number. Use search_strings for text.");
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
        }, ct, TimeLimit, sofar => Labels(sofar, h => $"{Format.MemberLabel(h.Method)} @IL_{h.Offset:X4}  [{h.Assembly.Id}]"));
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
            throw new ToolError(ErrorCode.InvalidArgument, "IL pattern is empty.");
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
            throw new ToolError(ErrorCode.InvalidArgument, "IL pattern needs at least one instruction element.");
        return list;
    }

    // Without a regex: a NonBacktracking automaton refuses a long pattern at construction.
    private static Func<string, bool> Glob(string glob)
    {
        var pattern = glob.Trim('"');
        return s => Wildcard.Matches(s, pattern);
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
            case MethodSig or StandAloneSig { MethodSig: not null }: yield return CalliSignature(i.Operand); break;
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
        MethodSig or StandAloneSig { MethodSig: not null } => CalliSignature(i.Operand),
        _ => Format.Literal(i.Operand),
    };

    /// <summary>The signature a calli takes, e.g. "unmanaged cdecl int(nint)".</summary>
    private static string CalliSignature(object operand)
    {
        var sig = operand as MethodSig ?? ((StandAloneSig)operand).MethodSig;
        var convention = (sig.CallingConvention & CallingConvention.Mask) switch
        {
            CallingConvention.C => "unmanaged cdecl ",
            CallingConvention.StdCall => "unmanaged stdcall ",
            CallingConvention.ThisCall => "unmanaged thiscall ",
            CallingConvention.FastCall => "unmanaged fastcall ",
            CallingConvention.Unmanaged => "unmanaged ",
            CallingConvention.VarArg => "vararg ",
            _ => "",
        };
        return $"{convention}{(sig.HasThis ? "instance " : "")}{Format.Type(sig.RetType)}({Format.ParameterTypes(sig)})";
    }

    /// <summary>Builds a predicate: substring (case-insensitive), wildcard (* ?) or regex; regex timeouts are counted in <paramref name="timeouts"/>.</summary>
    public static Func<string, bool> CreateMatcher(string query, bool regex, RegexTimeouts? timeouts = null)
    {
        if (string.IsNullOrEmpty(query))
            throw new ToolError(ErrorCode.InvalidArgument, "Query is empty.");
        if (!regex && (query.Contains('*') || query.Contains('?')))
            return Glob(query);
        if (!regex)
            return s => s.Contains(query, StringComparison.OrdinalIgnoreCase);
        Regex re;
        try { re = RegexTimeouts.Create(query, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant); }
        catch (ArgumentException ex) { throw new ToolError(ErrorCode.InvalidArgument, $"Invalid regex: {ex.Message}"); }
        timeouts ??= new RegexTimeouts();
        return s => timeouts.IsMatch(re, s);
    }
}
