using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace NetDecompilerMcp.Core;

/// <summary>A page of results plus the total number found.</summary>
public sealed record SearchResult<T>(List<T> Items, int Total)
{
    public static SearchResult<T> From(List<T> all, int limit) => new(all.Count <= limit ? all : all.GetRange(0, limit), all.Count);
}

/// <summary>
/// Defensive helpers over dnlib metadata. Transformed or Il2Cpp-generated assemblies routinely contain
/// bodies or references that throw when touched, so everything here degrades to "nothing" instead of failing.
/// </summary>
public static class MetadataUtil
{
    /// <summary>
    /// Visits every type of the given assemblies in parallel and returns the collected results in deterministic
    /// (assembly, type) order. The visitor must only read metadata; callers hold the workspace read lock.
    /// </summary>
    public static List<T> ParallelCollect<T>(IEnumerable<LoadedAssembly> scope, Action<LoadedAssembly, TypeDef, List<T>> visit, CancellationToken ct) =>
        ParallelCollect(scope, visit, ct, Timeout.InfiniteTimeSpan, null);

    /// <summary>
    /// As above, stopping after <paramref name="timeLimit"/>: a timeout error whose partial result counts the types searched
    /// and lists what <paramref name="describe"/> makes of the results found until then (keep it short: it travels with the error).
    /// </summary>
    public static List<T> ParallelCollect<T>(IEnumerable<LoadedAssembly> scope, Action<LoadedAssembly, TypeDef, List<T>> visit, CancellationToken ct,
        TimeSpan timeLimit, Func<List<T>, object?>? describe)
    {
        var work = scope.SelectMany(a => a.Module.GetTypes().Select(t => (Assembly: a, Type: t))).ToArray();
        var buckets = new List<T>?[work.Length];
        int searched = 0;
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (timeLimit == Timeout.InfiniteTimeSpan) { }
        else if (timeLimit <= TimeSpan.Zero) limit.Cancel();
        else limit.CancelAfter(timeLimit);
        try
        {
            Parallel.For(0, work.Length, new ParallelOptions { CancellationToken = limit.Token }, i =>
            {
                var found = new List<T>();
                visit(work[i].Assembly, work[i].Type, found);
                if (found.Count > 0) Volatile.Write(ref buckets[i], found);
                Interlocked.Increment(ref searched);
            });
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested && limit.IsCancellationRequested)
        {
            var sofar = Collect(buckets);
            throw new ToolError(ErrorCode.Timeout,
                $"stopped at the {timeLimit.TotalSeconds:0.#} s time limit after searching {Volatile.Read(ref searched):N0} of {work.Length:N0} types ({sofar.Count:N0} results so far).",
                "narrow the search (assembly=..., a more specific query); the server's --timeout option sets the limit")
            {
                Partial = new { typesSearched = Volatile.Read(ref searched), typesTotal = work.Length, resultsFound = sofar.Count, results = describe?.Invoke(sofar) },
            };
        }
        return Collect(buckets);

        static List<T> Collect(List<T>?[] buckets)
        {
            var result = new List<T>();
            for (int i = 0; i < buckets.Length; i++)
                if (Volatile.Read(ref buckets[i]) is { } b) result.AddRange(b);
            return result;
        }
    }

    public static CilBody? SafeBody(MethodDef m)
    {
        try { return m.HasBody ? m.Body : null; }
        catch { return null; }
    }

    public static IList<Instruction> SafeInstructions(MethodDef m) =>
        SafeBody(m)?.Instructions ?? (IList<Instruction>)Array.Empty<Instruction>();

    // dnlib's MemberRef implements both IMethod and IField: always classify operands through these two helpers.
    public static IMethod? AsMethod(object? operand) => operand switch
    {
        MemberRef { IsFieldRef: true } => null,
        IMethod m => m,
        _ => null,
    };

    public static IField? AsField(object? operand) => operand switch
    {
        MemberRef { IsMethodRef: true } => null,
        IField f => f,
        _ => null,
    };

    public static T? Try<T>(Func<T?> f) where T : class
    {
        try { return f(); }
        catch { return null; }
    }

    /// <summary>
    /// The types every tool counts and lists: all types, nested ones included, except the &lt;Module&gt; pseudo-type.
    /// A nested type belongs to the namespace of its top-level type (its own Namespace is empty).
    /// </summary>
    public static List<TypeDef> CountedTypes(ModuleDef module) => module.GetTypes().Where(t => t.FullName != "<Module>").ToList();

    /// <summary>Distinct namespaces of <paramref name="types"/>, nested types counted under their top-level type's.</summary>
    public static int NamespaceCount(IEnumerable<TypeDef> types) => types.Select(t => TopLevel(t).Namespace.String).Distinct().Count();

    /// <summary>A reference assembly ([ReferenceAssembly]): API surface only, every body is `throw null`.</summary>
    public static bool IsReferenceAssembly(ModuleDef module)
    {
        try { return module.Assembly?.CustomAttributes.IsDefined("System.Runtime.CompilerServices.ReferenceAssemblyAttribute") == true; }
        catch (Exception) { return false; }
    }

    public static TypeDef TopLevel(TypeDef t)
    {
        while (t.DeclaringType != null) t = t.DeclaringType;
        return t;
    }

    public static bool IsAccessor(MethodDef m) => m.IsGetter || m.IsSetter || m.IsAddOn || m.IsRemoveOn || m.IsFire;

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<ModuleDef, object> ReferenceOnly = new();

    /// <summary>Marks a module read only to resolve references (a framework or dependency file, not a loaded assembly).</summary>
    public static void MarkReferenceOnly(ModuleDef module) => ReferenceOnly.AddOrUpdate(module, true);

    /// <summary>
    /// A member of a reference-only module: the same API can come from several files (System.IDisposable from
    /// mscorlib for one assembly and System.Private.CoreLib for another), so such members match by name and signature.
    /// </summary>
    public static bool IsReferenceOnly(IMemberDef member) => member.Module is { } m && ReferenceOnly.TryGetValue(m, out _);

    /// <summary>
    /// Name, signature and declaring type, ignoring the assembly a type is referenced from. dnlib compares methods
    /// without their declaring type unless asked: every unresolved ".ctor()" would match every other.
    /// </summary>
    private const SigComparerOptions SameMember = SigComparerOptions.DontCompareTypeScope | SigComparerOptions.CompareMethodFieldDeclaringType;

    public static bool IsSameMethod(IMethod? op, MethodDef target)
    {
        if (op == null || op.Name != target.Name) return false;
        if (op is MethodDef md) return md == target;
        var resolved = Try(() => op.ResolveMethodDef());
        if (resolved != null)
            return resolved == target || (IsReferenceOnly(target) && IsReferenceOnly(resolved)
                                          && new SigComparer(SameMember).Equals(resolved, target));
        // Defining assembly not resolvable from the referencing module: compare name + signature.
        return new SigComparer(SameMember).Equals(op is MethodSpec ms ? ms.Method : op, target);
    }

    public static bool IsSameField(IField? op, FieldDef target)
    {
        if (op == null || op.Name != target.Name) return false;
        if (op is FieldDef fd) return fd == target;
        var resolved = Try(() => op.ResolveFieldDef());
        if (resolved != null)
            return resolved == target || (IsReferenceOnly(target) && IsReferenceOnly(resolved) && resolved.DeclaringType?.FullName == target.DeclaringType?.FullName);
        return op.DeclaringType?.FullName == target.DeclaringType?.FullName;
    }

    public static bool IsSameType(ITypeDefOrRef? t, TypeDef target)
    {
        switch (t)
        {
            case null: return false;
            case TypeDef td: return td == target;
            case TypeSpec ts: return Mentions(ts.TypeSig, target);
        }
        if (t.Name != target.Name || t.Namespace != target.Namespace) return false;
        var resolved = Try(() => t.ResolveTypeDef());
        return resolved != null
            ? resolved == target || (IsReferenceOnly(target) && IsReferenceOnly(resolved) && resolved.FullName == target.FullName)
            : t.FullName == target.FullName;
    }

    /// <summary>True if the signature uses the type anywhere (arrays, generic arguments, byref, pointers...).</summary>
    public static bool Mentions(TypeSig? sig, TypeDef target, int depth = 0)
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

    /// <summary>Resolved base type, or null when it is not loaded / not resolvable.</summary>
    public static TypeDef? BaseTypeDef(TypeDef t) => t.BaseType == null ? null : Try(() => t.BaseType.ResolveTypeDef());

    /// <summary>All interfaces implemented by the type, its base types, and inherited by those interfaces.</summary>
    public static List<TypeDef> AllInterfaces(TypeDef type)
    {
        var result = new List<TypeDef>();
        var seen = new HashSet<TypeDef>();
        var queue = new Queue<ITypeDefOrRef>();
        for (var t = type; t != null; t = BaseTypeDef(t))
            foreach (var i in t.Interfaces) queue.Enqueue(i.Interface);
        while (queue.Count > 0)
        {
            var def = Try(() => queue.Dequeue().ResolveTypeDef());
            if (def == null || !seen.Add(def)) continue;
            result.Add(def);
            foreach (var i in def.Interfaces) queue.Enqueue(i.Interface);
        }
        return result;
    }

    public static int ParamCount(MethodDef m) => m.MethodSig?.Params.Count ?? 0;

    public static string FieldAccessKind(Code code) => code switch
    {
        Code.Ldfld or Code.Ldsfld => "read",
        Code.Stfld or Code.Stsfld => "write",
        Code.Ldflda or Code.Ldsflda => "address",
        Code.Ldtoken => "ldtoken",
        _ => code.ToString().ToLowerInvariant(),
    };
}
