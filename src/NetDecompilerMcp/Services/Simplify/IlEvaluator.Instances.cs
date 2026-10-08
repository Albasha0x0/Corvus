using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace NetDecompilerMcp.Services.Simplify;

/// <summary>
/// An instance of a class of the module (or a plain <c>new object()</c>, <see cref="Type"/> null) created by evaluated
/// code: its instance fields, those its base classes declare included.
/// </summary>
internal sealed class InstanceObject(TypeDef? type, Dictionary<FieldDef, object?> fields) : HeapObject
{
    public TypeDef? Type { get; } = type;
    public Dictionary<FieldDef, object?> Fields { get; } = fields;
}

internal sealed partial class IlEvaluator
{
    /// <summary>Deepest class hierarchy the evaluator dispatches through.</summary>
    private const int MaxHierarchyDepth = 8;

    private readonly Dictionary<TypeDef, (List<FieldDef> Fields, string? Why)> _classes = new();

    /// <summary>
    /// The instance fields of a class the evaluator models, or why it does not (unmodeled-instance): a non-generic class of
    /// this module whose base classes are classes of this module up to System.Object, with no finalizer, no events, no
    /// explicit layout and no COM import.
    /// </summary>
    private List<FieldDef> ClassModel(TypeDef type)
    {
        if (!_classes.TryGetValue(type, out var model))
        {
            model = Check(type);
            _classes[type] = model;
        }
        return model.Why == null ? model.Fields : throw Bail(FallbackReason.UnmodeledInstance, $"{type.FullName}: {model.Why}");

        static (List<FieldDef>, string?) Check(TypeDef type)
        {
            var fields = new List<FieldDef>();
            int depth = 0;
            for (TypeDef? t = type; t != null; depth++)
            {
                if (depth > MaxHierarchyDepth) return (fields, $"its class hierarchy is deeper than {MaxHierarchyDepth} levels");
                if (t.IsInterface || t.IsValueType) return (fields, "not a class");
                if (t.HasGenericParameters || t.DeclaringType?.HasGenericParameters == true) return (fields, "a generic class");
                if (t.IsImport || t.IsExplicitLayout) return (fields, "an interop class (COM import or explicit layout)");
                if (t.HasEvents) return (fields, $"{t.FullName} declares events");
                if (t.Methods.Any(m => m.Name == "Finalize" && m.IsVirtual && m.Parameters.Count == 1 && !m.IsStatic))
                    return (fields, $"{t.FullName} has a finalizer");
                fields.AddRange(t.Fields.Where(f => !f.IsStatic));
                var baseType = t.BaseType;
                if (baseType == null || baseType.FullName == "System.Object") break;
                if (baseType is not TypeDef next || next.Module != type.Module)
                    return (fields, $"its base class {baseType.FullName} belongs to another assembly");
                t = next;
            }
            return (fields, null);
        }
    }

    private InstanceObject NewInstance(MethodDef ctor, object?[] args)
    {
        var type = ctor.DeclaringType;
        var fields = ClassModel(type);
        if (type.IsAbstract) throw Bail(FallbackReason.InvalidCode, $"creates an instance of abstract {type.FullName}");
        Allocate(16 + 8L * fields.Count);
        var obj = new InstanceObject(type, fields.ToDictionary(f => f, f => Default(SlotOf(f.FieldType)))) { Shared = _cctorDepth > 0 };
        TriggerTypeInitializer(ctor);
        Execute(ctor, [obj, .. args]);
        return obj;
    }

    private InstanceObject NewPlainObject()
    {
        Allocate(16);
        return new InstanceObject(null, new()) { Shared = _cctorDepth > 0 };
    }

    private static bool IsObjectConstructor(IMethod method) => method.Name == ".ctor" && method.DeclaringType?.FullName == "System.Object";

    /// <summary>An instance method called on a modelled instance: dispatched within the module's classes.</summary>
    private object? InvokeInstance(InstanceObject obj, IMethod method, Code op, object?[] args)
    {
        if (IsObjectConstructor(method)) return Void;
        MethodDef target;
        if (op == Code.Callvirt && IsVirtual(method))
        {
            target = Dispatch(obj, method);
        }
        else
        {
            target = method as MethodDef ?? Resolve(method)
                ?? throw Bail(FallbackReason.VirtualDispatch, $"calls {Describe(method)}, which is not a method of the module, on an instance of {obj.Type?.FullName ?? "System.Object"}");
            if (target.Module != module) throw Bail(FallbackReason.VirtualDispatch, $"calls framework method {Describe(method)} on an instance");
            if (obj.Type == null || !Chain(obj.Type).Contains(target.DeclaringType))
                throw Bail(FallbackReason.InvalidCode, $"calls {Describe(target)} on an instance of another class");
        }
        if (target.IsAbstract) throw Bail(FallbackReason.VirtualDispatch, $"{Describe(target)} is abstract");
        TriggerTypeInitializer(target);
        var result = Execute(target, args);
        return HasReturnValue(target) ? result : Void;
    }

    private static MethodDef? Resolve(IMethod method)
    {
        try { return method.ResolveMethodDef(); }
        catch { return null; }
    }

    private static bool IsVirtual(IMethod method) => Resolve(method) is not { } def || def.IsVirtual;

    private static IEnumerable<TypeDef> Chain(TypeDef type)
    {
        for (TypeDef? t = type; t != null; t = t.BaseType as TypeDef) yield return t;
    }

    /// <summary>
    /// The method a virtual or interface call reaches on the instance: an explicit override, or a virtual method of the
    /// same name and signature, from the instance's class up. Anything that does not end at one method of the module
    /// bails (virtual-dispatch).
    /// </summary>
    private MethodDef Dispatch(InstanceObject obj, IMethod method)
    {
        if (obj.Type == null) throw Bail(FallbackReason.VirtualDispatch, $"calls {Describe(method)} on a plain object (the framework implementation)");
        var declared = Resolve(method);
        string signature = method.MethodSig?.ToString() ?? "";
        foreach (var t in Chain(obj.Type))
        {
            var match = t.Methods.FirstOrDefault(m => m.Overrides.Any(o => o.MethodDeclaration?.FullName == method.FullName))
                        ?? t.Methods.FirstOrDefault(m => m.IsVirtual && m.Name == method.Name && m.MethodSig?.ToString() == signature
                                                         && (m == declared || !m.IsNewSlot || declared?.DeclaringType.IsInterface == true));
            if (match != null) return match;
            if (t == declared?.DeclaringType) break;
        }
        throw Bail(FallbackReason.VirtualDispatch, $"{Describe(method)} on an instance of {obj.Type.FullName} does not resolve to a method of the module");
    }

    /// <summary>The field of a modelled instance an ldfld / stfld / ldflda addresses.</summary>
    private static FieldDef InstanceField(InstanceObject obj, object operand)
    {
        var field = operand as FieldDef ?? (operand as MemberRef)?.ResolveField();
        return field != null && obj.Fields.ContainsKey(field)
            ? field
            : throw Bail(FallbackReason.InvalidCode, $"accesses field {field?.Name ?? "?"}, which the instance does not have");
    }

    private bool IsInstanceOf(InstanceObject obj, string typeName)
    {
        if (typeName == "System.Object") return true;
        if (obj.Type == null) return false;
        foreach (var t in Chain(obj.Type))
            if (t.FullName == typeName || t.Interfaces.Any(i => i.Interface.FullName == typeName)) return true;
        return false;
    }
}
