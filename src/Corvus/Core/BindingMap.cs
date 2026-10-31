using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Corvus.Core;

/// <summary>
/// Maps script-visible names to the managed methods that implement them,
/// read from generated binder classes.
/// </summary>
public static class BindingMap
{
    /// <summary>
    /// One script name bound to a managed method by a registration method.
    /// BoundType is the nearest type token before the registration; null means
    /// the method has none, which is unknown. Registrar is the full name of
    /// the registering method.
    /// </summary>
    public sealed record Binding(string Binder, string? BoundType, string ScriptName, string Target, string Registrar);

    /// <summary>
    /// Bindings in method and instruction order. Unnamed lists methods
    /// registered without a script name. Empty lists binders that register
    /// nothing, and Unreadable lists methods whose body could not be read;
    /// both are unknown rather than none.
    /// </summary>
    public sealed record Result(
        IReadOnlyList<Binding> Bindings,
        IReadOnlyList<string> Unnamed,
        IReadOnlyList<string> Empty,
        IReadOnlyList<string> Unreadable);

    /// <summary>Suffix that marks a generated binder class.</summary>
    public const string BinderSuffix = "Wrap";

    // A name binds only when its ldstr is at most this far before the ldftn.
    private const int NameDistance = 2;

    /// <summary>Reads every binder class of <paramref name="module"/>; a module without binders gives empty lists.</summary>
    public static Result Read(ModuleDef module)
    {
        var bindings = new List<Binding>();
        var unnamed = new List<string>();
        var empty = new List<string>();
        var unreadable = new List<string>();
        foreach (var binder in module.GetTypes().Where(t => IsBinder(t) && !HasBinderOwner(t)))
        {
            int before = bindings.Count + unnamed.Count + unreadable.Count;
            foreach (var type in WithNested(binder))
                foreach (var method in type.Methods.Where(m => m.HasBody))
                    ReadMethod(binder, method, bindings, unnamed, unreadable);
            if (bindings.Count + unnamed.Count + unreadable.Count == before)
                empty.Add(binder.FullName);
        }
        return new Result(bindings.AsReadOnly(), unnamed.AsReadOnly(), empty.AsReadOnly(), unreadable.AsReadOnly());
    }

    private static bool IsBinder(TypeDef type) =>
        type.Name.EndsWith(BinderSuffix, StringComparison.Ordinal) && type.Name.Length > BinderSuffix.Length;

    private static bool HasBinderOwner(TypeDef type)
    {
        for (var owner = type.DeclaringType; owner != null; owner = owner.DeclaringType)
            if (IsBinder(owner)) return true;
        return false;
    }

    private static IEnumerable<TypeDef> WithNested(TypeDef type)
    {
        yield return type;
        foreach (var nested in type.NestedTypes)
            foreach (var inner in WithNested(nested))
                yield return inner;
    }

    private static void ReadMethod(
        TypeDef binder, MethodDef method, List<Binding> bindings, List<string> unnamed, List<string> unreadable)
    {
        string? pendingName = null;
        int namePosition = -1;
        string? lastType = null;
        int position = 0;
        var found = new List<(string? Name, string? Type, string Target)>();
        foreach (var instr in MetadataUtil.SafeInstructions(method))
        {
            switch (instr.OpCode.Code)
            {
                case Code.Ldstr:
                    pendingName = instr.Operand as string;
                    namePosition = position;
                    break;
                case Code.Ldtoken when instr.Operand is ITypeDefOrRef type:
                    lastType = type.FullName;
                    break;
                case Code.Ldftn when instr.Operand is IMethod target:
                    bool named = pendingName != null && position - namePosition <= NameDistance;
                    found.Add((named ? pendingName : null, lastType, target.FullName));
                    pendingName = null;
                    break;
                case Code.Call or Code.Callvirt or Code.Newobj or Code.Throw
                    or Code.Stfld or Code.Stsfld or Code.Pop:
                    pendingName = null;
                    break;
            }
            position++;
        }
        if (position == 0)
        {
            unreadable.Add(method.FullName);
            return;
        }
        foreach (var (name, type, target) in found)
        {
            if (name == null) unnamed.Add(target);
            else bindings.Add(new Binding(binder.FullName, type, name, target, method.FullName));
        }
    }
}
