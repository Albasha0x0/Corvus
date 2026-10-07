using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services;

/// <summary>A page of results plus the total number found.</summary>
public sealed record SearchResult<T>(List<T> Items, int Total)
{
    public static SearchResult<T> From(List<T> all, int limit) => new(all.Count <= limit ? all : all.GetRange(0, limit), all.Count);
}

/// <summary>
/// Defensive helpers over dnlib metadata. Obfuscated or Il2Cpp-generated assemblies routinely contain
/// bodies or references that throw when touched, so everything here degrades to "nothing" instead of failing.
/// </summary>
public static class MetadataUtil
{
    /// <summary>
    /// Visits every type of the given assemblies in parallel and returns what the visitor collected, in a
    /// deterministic (assembly, type) order. Large workspaces have hundreds of thousands of method bodies, and the
    /// first scan pays for parsing them, so whole-workspace scans must not be single-threaded.
    /// The visitor must only read metadata; callers hold the workspace read lock.
    /// </summary>
    public static List<T> ParallelCollect<T>(IEnumerable<LoadedAssembly> scope, Action<LoadedAssembly, TypeDef, List<T>> visit, CancellationToken ct)
    {
        var work = scope.SelectMany(a => a.Module.GetTypes().Select(t => (Assembly: a, Type: t))).ToArray();
        var buckets = new List<T>?[work.Length];
        Parallel.For(0, work.Length, new ParallelOptions { CancellationToken = ct }, i =>
        {
            var found = new List<T>();
            visit(work[i].Assembly, work[i].Type, found);
            if (found.Count > 0) buckets[i] = found;
        });
        var result = new List<T>();
        foreach (var bucket in buckets)
            if (bucket != null) result.AddRange(bucket);
        return result;
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

    public static TypeDef TopLevel(TypeDef t)
    {
        while (t.DeclaringType != null) t = t.DeclaringType;
        return t;
    }

    public static bool IsAccessor(MethodDef m) => m.IsGetter || m.IsSetter || m.IsAddOn || m.IsRemoveOn || m.IsFire;

    public static bool IsSameMethod(IMethod? op, MethodDef target)
    {
        if (op == null || op.Name != target.Name) return false;
        if (op is MethodDef md) return md == target;
        var resolved = Try(() => op.ResolveMethodDef());
        if (resolved != null) return resolved == target;
        // Defining assembly not resolvable from the referencing module: compare name + signature.
        return new SigComparer(SigComparerOptions.DontCompareTypeScope).Equals(op is MethodSpec ms ? ms.Method : op, target);
    }

    public static bool IsSameField(IField? op, FieldDef target)
    {
        if (op == null || op.Name != target.Name) return false;
        if (op is FieldDef fd) return fd == target;
        var resolved = Try(() => op.ResolveFieldDef());
        if (resolved != null) return resolved == target;
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
        return resolved != null ? resolved == target : t.FullName == target.FullName;
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
