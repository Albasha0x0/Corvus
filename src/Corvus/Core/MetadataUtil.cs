using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Corvus.Core;

/// <summary>A page of results plus the total number found.</summary>
public sealed record SearchResult<T>(List<T> Items, int Total)
{
    public static SearchResult<T> From(List<T> all, int limit) => new(all.Count <= limit ? all : all.GetRange(0, limit), all.Count);
}

/// <summary>dnlib metadata helpers that return nothing instead of throwing on broken bodies or references.</summary>
public static class MetadataUtil
{
    /// <summary>Visits every type in parallel, results in (assembly, type) order; ends on completion or <paramref name="ct"/>.</summary>
    public static List<T> ParallelCollect<T>(IEnumerable<LoadedAssembly> scope, Action<LoadedAssembly, TypeDef, List<T>> visit, CancellationToken ct)
    {
        var work = scope.SelectMany(a => a.Module.GetTypes().Select(t => (Assembly: a, Type: t))).ToArray();
        var buckets = new List<T>?[work.Length];
        var progress = ScanProgress.Current;
        progress?.Start(work.Length);
        // Capped: uncapped, it took every pool thread and visitors waiting on pool work stalled.
        Parallel.For(0, work.Length, new ParallelOptions { CancellationToken = ct, MaxDegreeOfParallelism = Environment.ProcessorCount }, i =>
        {
            var found = new List<T>();
            // The visitor only reads, under the read lock.
            visit(work[i].Assembly, work[i].Type, found);
            if (found.Count > 0) Volatile.Write(ref buckets[i], found);
            progress?.Visited();
        });
        return [.. buckets.Where(b => b != null).SelectMany(b => b!)];
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

    /// <summary>All types including nested ones, except &lt;Module&gt;; a nested type belongs to its top-level type's namespace.</summary>
    public static List<TypeDef> CountedTypes(ModuleDef module) => module.GetTypes().Where(t => t.FullName != "<Module>").ToList();

    /// <summary>Concrete, non-native methods of <paramref name="types"/> that have no IL body.</summary>
    public static int CountBodyless(IEnumerable<TypeDef> types) =>
        types.SelectMany(t => t.Methods).Count(m => m.RVA == 0 && !m.IsAbstract && !m.IsPinvokeImpl && !m.IsInternalCall
                                                    && !m.IsRuntime && m.DeclaringType?.IsInterface != true);

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

    /// <summary>Whether a member is from a reference-only module, whose members match by name and signature across files.</summary>
    public static bool IsReferenceOnly(IMemberDef member) => member.Module is { } m && ReferenceOnly.TryGetValue(m, out _);

    /// <summary>Name, signature and declaring type, ignoring type scope; without the declaring type every ".ctor()" would match.</summary>
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
