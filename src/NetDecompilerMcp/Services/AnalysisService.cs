using System.Text.RegularExpressions;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services;

/// <summary>Searches and cross-references over every loaded assembly (dnlib metadata + IL scan).</summary>
public sealed class AnalysisService(AssemblyWorkspace workspace)
{
    public sealed record SearchResult<T>(List<T> Items, int Total);

    public sealed record StringHit(LoadedAssembly Assembly, IMemberDef Owner, uint? ILOffset, string Value);

    /// <summary>One usage site. Where = the member containing the usage.</summary>
    public sealed record Reference(LoadedAssembly Assembly, IMemberDef Where, uint? ILOffset, string Kind, string Detail);

    // ---------------------------------------------------------------- search

    public SearchResult<ResolvedSymbol> SearchSymbols(string query, bool regex, SymbolKind kind, IReadOnlyList<LoadedAssembly> scope,
        string? namespaceFilter, int limit, CancellationToken ct)
    {
        var matcher = CreateMatcher(query, regex);
        bool matchFull = regex || query.Contains('.') || query.Contains(':') || query.Contains('/');
        var hits = new List<(ResolvedSymbol Sym, int Rank)>();

        foreach (var asm in scope)
            foreach (var type in asm.Module.GetTypes())
            {
                ct.ThrowIfCancellationRequested();
                if (namespaceFilter != null && !TopLevel(type).Namespace.String.StartsWith(namespaceFilter, StringComparison.OrdinalIgnoreCase))
                    continue;
                foreach (var member in MembersOf(type, kind))
                {
                    var name = member is TypeDef td ? Format.StripArity(td.Name) : member.Name.String;
                    var label = Format.MemberLabel(member);
                    if (matcher(name) || (matchFull && matcher(label)))
                        hits.Add((new ResolvedSymbol(asm, member), Rank(name, query)));
                }
            }

        var ordered = hits.OrderBy(h => h.Rank).ThenBy(h => h.Sym.Label.Length).Select(h => h.Sym).ToList();
        return new(ordered.Take(limit).ToList(), ordered.Count);
    }

    private static IEnumerable<IMemberDef> MembersOf(TypeDef type, SymbolKind kind)
    {
        if (kind is SymbolKind.Any or SymbolKind.Type) yield return type;
        if (kind is SymbolKind.Any or SymbolKind.Member or SymbolKind.Method)
            foreach (var m in type.Methods.Where(m => !m.IsGetter && !m.IsSetter && !m.IsAddOn && !m.IsRemoveOn)) yield return m;
        if (kind is SymbolKind.Any or SymbolKind.Member or SymbolKind.Field)
            foreach (var f in type.Fields) yield return f;
        if (kind is SymbolKind.Any or SymbolKind.Member or SymbolKind.Property)
            foreach (var p in type.Properties) yield return p;
        if (kind is SymbolKind.Any or SymbolKind.Member or SymbolKind.Event)
            foreach (var e in type.Events) yield return e;
    }

    private static int Rank(string name, string query) =>
        name.Equals(query, StringComparison.Ordinal) ? 0
        : name.Equals(query, StringComparison.OrdinalIgnoreCase) ? 1
        : name.StartsWith(query, StringComparison.OrdinalIgnoreCase) ? 2
        : 3;

    public SearchResult<StringHit> SearchStrings(string query, bool regex, IReadOnlyList<LoadedAssembly> scope, int limit, CancellationToken ct)
    {
        var matcher = CreateMatcher(query, regex);
        var items = new List<StringHit>();
        int total = 0;

        void Add(StringHit hit)
        {
            total++;
            if (items.Count < limit) items.Add(hit);
        }

        foreach (var asm in scope)
            foreach (var type in asm.Module.GetTypes())
            {
                ct.ThrowIfCancellationRequested();
                foreach (var f in type.Fields)
                    if (f.HasConstant && f.Constant.Value is string s && matcher(s))
                        Add(new StringHit(asm, f, null, s));
                foreach (var m in type.Methods)
                    foreach (var instr in SafeInstructions(m))
                        if (instr.OpCode.Code == Code.Ldstr && instr.Operand is string str && matcher(str))
                            Add(new StringHit(asm, m, instr.Offset, str));
            }
        return new(items, total);
    }

    public sealed record ConstantHit(LoadedAssembly Assembly, IMemberDef Owner, uint? ILOffset, string Kind, string Value);

    /// <summary>
    /// Finds a numeric constant used as a literal in IL (ldc.i4/i8/r4/r8, incl. short forms), as a const/enum field
    /// value, or as a custom-attribute argument. Magic numbers, packet ids, enum flags, crypto constants.
    /// </summary>
    public SearchResult<ConstantHit> SearchConstants(string value, IReadOnlyList<LoadedAssembly> scope, int limit, CancellationToken ct)
    {
        var target = ParseConstant(value);
        var items = new List<ConstantHit>();
        int total = 0;
        void Add(ConstantHit h)
        {
            total++;
            if (items.Count < limit) items.Add(h);
        }

        foreach (var asm in scope)
            foreach (var type in asm.Module.GetTypes())
            {
                ct.ThrowIfCancellationRequested();
                foreach (var f in type.Fields)
                    if (f.HasConstant && NumericEquals(f.Constant.Value, target))
                        Add(new ConstantHit(asm, f, null, type.IsEnum ? "enum member" : "const field", Format.Literal(f.Constant.Value)));
                foreach (var m in type.Methods)
                {
                    foreach (var ca in m.CustomAttributes)
                        foreach (var arg in ca.ConstructorArguments.Select(a => a.Value).Concat(ca.NamedArguments.Select(n => n.Argument.Value)))
                            if (NumericEquals(arg, target))
                                Add(new ConstantHit(asm, m, null, $"attribute [{Format.StripArity(ca.AttributeType.Name)}]", Format.Literal(arg)));
                    foreach (var instr in SafeInstructions(m))
                    {
                        object? literal = instr.IsLdcI4() ? instr.GetLdcI4Value() : instr.OpCode.Code is Code.Ldc_I8 or Code.Ldc_R4 or Code.Ldc_R8 ? instr.Operand : null;
                        if (literal != null && NumericEquals(literal, target))
                            Add(new ConstantHit(asm, m, instr.Offset, instr.OpCode.Name, Format.Literal(literal)));
                    }
                }
            }
        return new(items, total);
    }

    private static decimal ParseConstant(string value)
    {
        var s = value.Trim().Replace("_", "");
        bool neg = s.StartsWith('-');
        if (neg) s = s[1..];
        decimal result;
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            ulong.TryParse(s[2..], System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out var hex))
            result = hex;
        else if (!decimal.TryParse(s.TrimEnd('f', 'F', 'd', 'D', 'L', 'l', 'u', 'U'), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out result))
            throw new ToolError($"'{value}' is not a number. Use search_strings for text.");
        return neg ? -result : result;
    }

    private static bool NumericEquals(object? value, decimal target)
    {
        try
        {
            return value switch
            {
                int i => i == target || (target > int.MaxValue && target <= uint.MaxValue && unchecked((uint)i) == target),
                long l => l == target || (target > long.MaxValue && unchecked((ulong)l) == target),
                uint u => u == target,
                ulong ul => ul == target,
                short sh => sh == target,
                ushort us => us == target,
                sbyte sb => sb == target,
                byte b => b == target,
                char c => c == target,
                float f => !float.IsNaN(f) && !float.IsInfinity(f) && (decimal)f == target,
                double d => !double.IsNaN(d) && !double.IsInfinity(d) && Math.Abs(d) < 7.9e28 && (decimal)d == target,
                _ => false,
            };
        }
        catch (OverflowException)
        {
            return false;
        }
    }

    /// <summary>Builds a predicate: substring (case-insensitive), wildcard (* ?) or regex.</summary>
    internal static Func<string, bool> CreateMatcher(string query, bool regex)
    {
        if (string.IsNullOrEmpty(query))
            throw new ToolError("Query is empty.");
        if (!regex && (query.Contains('*') || query.Contains('?')))
        {
            regex = true;
            query = "^" + Regex.Escape(query).Replace("\\*", ".*").Replace("\\?", ".") + "$";
        }
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

    // ---------------------------------------------------------------- references (who uses X)

    public SearchResult<Reference> FindReferences(ResolvedSymbol target, int limit, CancellationToken ct)
    {
        var items = new List<Reference>();
        int total = 0;
        void Add(Reference r)
        {
            total++;
            if (items.Count < limit) items.Add(r);
        }

        switch (target.Member)
        {
            case MethodDef method:
                ScanInstructions(ct, (asm, m, instr) =>
                {
                    if (instr.Operand is IMethod op && IsSameMethod(op, method))
                        Add(new Reference(asm, m, instr.Offset, instr.OpCode.Name, ""));
                });
                break;

            case FieldDef field:
                ScanInstructions(ct, (asm, m, instr) =>
                {
                    if (instr.Operand is IField op && IsSameField(op, field))
                        Add(new Reference(asm, m, instr.Offset, FieldAccessKind(instr.OpCode.Code), instr.OpCode.Name));
                });
                break;

            case PropertyDef prop:
                var accessors = prop.GetMethods.Select(a => (a, "get")).Concat(prop.SetMethods.Select(a => (a, "set"))).Concat(prop.OtherMethods.Select(a => (a, "other"))).ToList();
                ScanInstructions(ct, (asm, m, instr) =>
                {
                    if (instr.Operand is IMethod op)
                        foreach (var (acc, kind) in accessors)
                            if (IsSameMethod(op, acc))
                                Add(new Reference(asm, m, instr.Offset, kind, instr.OpCode.Name));
                });
                break;

            case EventDef ev:
                var evAccessors = new[] { (ev.AddMethod, "add"), (ev.RemoveMethod, "remove"), (ev.InvokeMethod, "raise") }.Where(x => x.Item1 != null).ToList();
                ScanInstructions(ct, (asm, m, instr) =>
                {
                    if (instr.Operand is IMethod op)
                        foreach (var (acc, kind) in evAccessors)
                            if (IsSameMethod(op, acc!))
                                Add(new Reference(asm, m, instr.Offset, kind, instr.OpCode.Name));
                });
                break;

            case TypeDef type:
                FindTypeReferences(type, Add, ct);
                break;
        }
        return new(items, total);
    }

    private void FindTypeReferences(TypeDef target, Action<Reference> add, CancellationToken ct)
    {
        foreach (var asm in workspace.Assemblies)
            foreach (var type in asm.Module.GetTypes())
            {
                ct.ThrowIfCancellationRequested();
                if (type == target) continue;
                if (IsSameType(type.BaseType, target)) add(new Reference(asm, type, null, "base type", ""));
                foreach (var i in type.Interfaces)
                    if (IsSameType(i.Interface, target)) add(new Reference(asm, type, null, "implements", ""));
                foreach (var ca in type.CustomAttributes)
                    if (IsSameType(ca.AttributeType, target)) add(new Reference(asm, type, null, "attribute", ""));

                foreach (var f in type.Fields)
                    if (Mentions(f.FieldType, target)) add(new Reference(asm, f, null, "field type", ""));
                foreach (var p in type.Properties)
                    if (Mentions(p.PropertySig?.RetType, target)) add(new Reference(asm, p, null, "property type", ""));
                foreach (var e in type.Events)
                    if (IsSameType(e.EventType, target)) add(new Reference(asm, e, null, "event type", ""));

                foreach (var m in type.Methods)
                {
                    if (m.MethodSig != null)
                    {
                        if (Mentions(m.MethodSig.RetType, target)) add(new Reference(asm, m, null, "return type", ""));
                        if (m.MethodSig.Params.Any(p => Mentions(p, target))) add(new Reference(asm, m, null, "parameter type", ""));
                    }
                    foreach (var ca in m.CustomAttributes)
                        if (IsSameType(ca.AttributeType, target)) add(new Reference(asm, m, null, "attribute", ""));

                    if (!m.HasBody) continue;
                    CilBody? body = SafeBody(m);
                    if (body == null) continue;
                    if (body.Variables.Any(v => Mentions(v.Type, target))) add(new Reference(asm, m, null, "local variable", ""));
                    foreach (var instr in body.Instructions)
                    {
                        switch (instr.Operand)
                        {
                            case ITypeDefOrRef t when IsSameType(t, target):
                                add(new Reference(asm, m, instr.Offset, instr.OpCode.Name, ""));
                                break;
                            case IMethod im when im.DeclaringType != null && IsSameType(im.DeclaringType, target):
                                add(new Reference(asm, m, instr.Offset, instr.OpCode.Name, im.Name));
                                break;
                            case IField fd when fd.DeclaringType != null && IsSameType(fd.DeclaringType, target):
                                add(new Reference(asm, m, instr.Offset, instr.OpCode.Name, fd.Name));
                                break;
                        }
                    }
                }
            }
    }

    // ---------------------------------------------------------------- callees (what X uses)

    public sealed record Callee(uint ILOffset, string OpCode, string Kind, string Target, LoadedAssembly? TargetAssembly);

    public List<Callee> FindCallees(MethodDef method)
    {
        var body = SafeBody(method) ?? throw new ToolError($"{Format.MemberLabel(method)} has no IL body (abstract, extern, runtime-implemented or an Il2Cpp stub).");
        var list = new List<Callee>();
        foreach (var instr in body.Instructions)
        {
            switch (instr.Operand)
            {
                case IMethod m:
                    var md = Try(() => m.ResolveMethodDef());
                    list.Add(new Callee(instr.Offset, instr.OpCode.Name, m.Name == ".ctor" ? "constructor" : "method", Format.MemberLabel(m), workspace.FindByModule(md?.Module)));
                    break;
                case IField f:
                    var fd = Try(() => f.ResolveFieldDef());
                    list.Add(new Callee(instr.Offset, instr.OpCode.Name, "field " + FieldAccessKind(instr.OpCode.Code), Format.MemberLabel(f), workspace.FindByModule(fd?.Module)));
                    break;
                case ITypeDefOrRef t:
                    list.Add(new Callee(instr.Offset, instr.OpCode.Name, "type", t.FullName, workspace.FindByModule(Try(() => t.ResolveTypeDef())?.Module)));
                    break;
                case string s:
                    list.Add(new Callee(instr.Offset, instr.OpCode.Name, "string", Format.Literal(s), null));
                    break;
            }
        }
        return list;
    }

    // ---------------------------------------------------------------- hierarchy

    public sealed record Hierarchy(List<string> BaseChain, List<string> Interfaces, List<ResolvedSymbol> Derived, int DerivedTotal);

    public Hierarchy GetHierarchy(TypeDef type, int limit, CancellationToken ct)
    {
        var chain = new List<string>();
        var interfaces = new SortedSet<string>(StringComparer.Ordinal);
        ITypeDefOrRef? current = type.BaseType;
        foreach (var i in type.Interfaces) interfaces.Add(i.Interface.FullName);
        for (int guard = 0; current != null && guard < 64; guard++)
        {
            var resolved = Try(() => current.ResolveTypeDef());
            chain.Add(current.FullName + (resolved == null ? "  (unresolved — load its assembly to go further)" : $"  [{workspace.FindByModule(resolved.Module)?.Id ?? resolved.Module.Name}]"));
            if (resolved == null) break;
            foreach (var i in resolved.Interfaces) interfaces.Add(i.Interface.FullName);
            current = resolved.BaseType;
        }

        var derived = new List<ResolvedSymbol>();
        int total = 0;
        foreach (var (asm, t) in AllTypes())
        {
            ct.ThrowIfCancellationRequested();
            if (t == type) continue;
            bool related = type.IsInterface
                ? t.Interfaces.Any(i => IsSameType(i.Interface, type))
                : IsSameType(t.BaseType, type);
            if (!related) continue;
            total++;
            if (derived.Count < limit) derived.Add(new ResolvedSymbol(asm, t));
        }
        return new Hierarchy(chain, interfaces.ToList(), derived, total);
    }

    /// <summary>All types deriving (transitively) from / implementing <paramref name="type"/>.</summary>
    private List<(LoadedAssembly Asm, TypeDef Type)> AllSubtypes(TypeDef type, CancellationToken ct)
    {
        var result = new List<(LoadedAssembly, TypeDef)>();
        var all = AllTypes().ToList();
        var frontier = new Queue<TypeDef>([type]);
        var seen = new HashSet<TypeDef> { type };
        while (frontier.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var current = frontier.Dequeue();
            foreach (var (asm, t) in all)
            {
                if (seen.Contains(t)) continue;
                bool related = IsSameType(t.BaseType, current) || (current.IsInterface && t.Interfaces.Any(i => IsSameType(i.Interface, current)));
                if (!related) continue;
                seen.Add(t);
                result.Add((asm, t));
                frontier.Enqueue(t);
            }
        }
        return result;
    }

    /// <summary>Methods that override a virtual method or implement an interface method.</summary>
    public List<ResolvedSymbol> FindOverrides(MethodDef baseMethod, CancellationToken ct)
    {
        var declaring = baseMethod.DeclaringType;
        if (!declaring.IsInterface && !baseMethod.IsVirtual)
            throw new ToolError($"{Format.MemberLabel(baseMethod)} is not virtual, abstract or an interface method, so nothing can override it.");

        int paramCount = baseMethod.MethodSig?.Params.Count ?? 0;
        var results = new List<ResolvedSymbol>();
        foreach (var (asm, t) in AllSubtypes(declaring, ct))
            foreach (var m in t.Methods)
            {
                bool explicitImpl = m.Overrides.Any(o => IsSameMethod(o.MethodDeclaration, baseMethod));
                bool implicitImpl = m.Name == baseMethod.Name && (m.MethodSig?.Params.Count ?? 0) == paramCount
                                    && (declaring.IsInterface ? (m.IsVirtual || m.IsPublic) : (m.IsVirtual && !m.IsNewSlot));
                if (explicitImpl || implicitImpl)
                    results.Add(new ResolvedSymbol(asm, m));
            }
        return results;
    }

    // ---------------------------------------------------------------- helpers

    private IEnumerable<(LoadedAssembly, TypeDef)> AllTypes() =>
        workspace.Assemblies.SelectMany(a => a.Module.GetTypes().Select(t => (a, t)));

    private void ScanInstructions(CancellationToken ct, Action<LoadedAssembly, MethodDef, Instruction> visit)
    {
        foreach (var asm in workspace.Assemblies)
            foreach (var type in asm.Module.GetTypes())
            {
                ct.ThrowIfCancellationRequested();
                foreach (var m in type.Methods)
                    foreach (var instr in SafeInstructions(m))
                        visit(asm, m, instr);
            }
    }

    internal static IList<Instruction> SafeInstructions(MethodDef m) => SafeBody(m)?.Instructions ?? (IList<Instruction>)Array.Empty<Instruction>();

    /// <summary>Method bodies of obfuscated/broken assemblies can throw on parse; treat them as empty.</summary>
    internal static CilBody? SafeBody(MethodDef m)
    {
        try { return m.HasBody ? m.Body : null; }
        catch { return null; }
    }

    private static T? Try<T>(Func<T?> f) where T : class
    {
        try { return f(); }
        catch { return null; }
    }

    private static TypeDef TopLevel(TypeDef t)
    {
        while (t.DeclaringType != null) t = t.DeclaringType;
        return t;
    }

    private static string FieldAccessKind(Code code) => code switch
    {
        Code.Ldfld or Code.Ldsfld => "read",
        Code.Stfld or Code.Stsfld => "write",
        Code.Ldflda or Code.Ldsflda => "address",
        Code.Ldtoken => "ldtoken",
        _ => code.ToString().ToLowerInvariant(),
    };

    internal static bool IsSameMethod(IMethod? op, MethodDef target)
    {
        if (op == null || op.Name != target.Name) return false;
        if (op is MethodDef md) return md == target;
        var resolved = Try(() => op.ResolveMethodDef());
        if (resolved != null) return resolved == target;
        // Target assembly not resolvable from the referencing module: fall back to name+signature.
        return new SigComparer(SigComparerOptions.DontCompareTypeScope).Equals(op is MethodSpec ms ? ms.Method : op, target);
    }

    internal static bool IsSameField(IField? op, FieldDef target)
    {
        if (op == null || op.Name != target.Name) return false;
        if (op is FieldDef fd) return fd == target;
        var resolved = Try(() => op.ResolveFieldDef());
        if (resolved != null) return resolved == target;
        return op.DeclaringType?.FullName == target.DeclaringType?.FullName;
    }

    internal static bool IsSameType(ITypeDefOrRef? t, TypeDef target)
    {
        switch (t)
        {
            case null: return false;
            case TypeDef td: return td == target;
            case TypeSpec ts: return Mentions(ts.TypeSig, target);
        }
        if (t.Name != target.Name || t.Namespace != target.Namespace) return false;
        var resolved = Try(() => t.ResolveTypeDef());
        return resolved != null ? resolved == target : t.FullName == target.FullName;
    }

    /// <summary>True if the signature uses the type anywhere (arrays, generic args, byref, pointers...).</summary>
    internal static bool Mentions(TypeSig? sig, TypeDef target, int depth = 0)
    {
        while (sig != null && depth < 32)
        {
            switch (sig)
            {
                case TypeDefOrRefSig tdr:
                    return IsSameType(tdr.TypeDefOrRef, target);
                case GenericInstSig gi:
                    return IsSameType(gi.GenericType?.TypeDefOrRef, target) || gi.GenericArguments.Any(a => Mentions(a, target, depth + 1));
                case FnPtrSig fn:
                    return Mentions(fn.MethodSig?.RetType, target, depth + 1) || (fn.MethodSig?.Params.Any(p => Mentions(p, target, depth + 1)) ?? false);
                default:
                    sig = sig.Next;
                    depth++;
                    break;
            }
        }
        return false;
    }
}
