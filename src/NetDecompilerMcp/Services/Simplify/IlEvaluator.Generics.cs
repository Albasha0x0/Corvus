using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace NetDecompilerMcp.Services.Simplify;

/// <summary>
/// A boxed value type: the value as its type stores it, immutable (unbox gives a read-only address). Comparisons are by
/// identity, as for any object.
/// </summary>
internal sealed class BoxedValue(TypeSig type, object? value) : HeapObject
{
    public TypeSig Type { get; } = type;
    public object? Value { get; } = value;

    /// <summary>Whether the boxed value is an instance of <paramref name="target"/> (isinst / castclass).</summary>
    public bool Is(TypeSig target)
    {
        var name = target.FullName;
        if (name == Type.FullName || name is "System.Object" or "System.ValueType") return true;
        if (name == "System.Enum") return IlEvaluator.IsEnum(Type);
        var td = target.ToTypeDefOrRef()?.ResolveTypeDef();
        if (td == null || td.IsInterface)
            throw new EvaluationBailout(FallbackReason.UnsupportedValue, $"type test of a boxed {Type.FullName} against {name}");
        return false;
    }
}

internal sealed partial class IlEvaluator
{
    /// <summary>The type an instruction names, with the frame's generic method arguments substituted.</summary>
    private static TypeSig TypeOperand(Frame f, Instruction ins)
    {
        var sig = Generics.Substitute(((ITypeDefOrRef)ins.Operand).ToTypeSig(), f.GenericArgs)!;
        return Generics.IsOpen(sig) ? throw Bail(FallbackReason.Generic, $"{ins.OpCode.Name} of a type parameter of a generic type") : sig;
    }

    /// <summary>A call's target as the frame's generic method instantiation sees it: !!n in its type arguments substituted.</summary>
    private IMethod Instantiated(Frame f, IMethod method)
    {
        if (f.GenericArgs == null) return method;
        switch (method)
        {
            case MethodSpec { Method: { } m, GenericInstMethodSig: { } inst } when inst.GenericArguments.Any(Generics.IsOpen):
                return new MethodSpecUser((IMethodDefOrRef)m, new GenericInstMethodSig(inst.GenericArguments.Select(a => Generics.Substitute(a, f.GenericArgs)!).ToList()));
            case MemberRef { Class: TypeSpec { TypeSig: { } owner } } r when Generics.IsOpen(owner):
                return new MemberRefUser(module, r.Name, r.MethodSig, new TypeSpecUser(Generics.Substitute(owner, f.GenericArgs)));
            default:
                return method;
        }
    }

    internal static bool IsEnum(TypeSig type) =>
        type.ElementType == ElementType.ValueType && type.ToTypeDefOrRef()?.ResolveTypeDef() is { IsEnum: true };

    /// <summary>box: a value type becomes a <see cref="BoxedValue"/>; a reference (box of a type argument that is a class) stays as it is.</summary>
    private object? Box(TypeSig type, object? value)
    {
        if (!type.IsValueType) return value;
        if (type is GenericInstSig { GenericType.FullName: "System.Nullable`1" })
            throw Bail(FallbackReason.UnsupportedValue, "box of a Nullable<T>");
        var stored = Store(SlotOf(type), value);
        Allocate(24);
        return new BoxedValue(type, stored is StructValue s ? s.Clone() : stored) { Shared = _cctorDepth > 0 };
    }

    /// <summary>
    /// The value in a box of <paramref name="type"/>, as unbox reads it: the box's own type, or an enum and its underlying
    /// integer type either way.
    /// </summary>
    private static object? Unbox(object? box, TypeSig type)
    {
        if (box == null) throw Bail(FallbackReason.RuntimeError, "null reference (unbox)");
        if (box is not BoxedValue b) throw Bail(FallbackReason.RuntimeError, $"invalid cast to {type.FullName}");
        if (b.Type.FullName == type.FullName) return b.Value;
        if (Underlying(b.Type) is { } x && Underlying(type) is { } y)
        {
            if (x == y) return b.Value;
            // Integers of the same size and other signedness: what the runtime allows here is not modelled.
            if (Width(x) == Width(y))
                throw Bail(FallbackReason.UnsupportedValue, $"unbox of a boxed {b.Type.FullName} as {type.FullName}");
        }
        throw Bail(FallbackReason.RuntimeError, $"invalid cast of a boxed {b.Type.FullName} to {type.FullName} (InvalidCastException)");
    }

    /// <summary>The integer element type of a primitive or enum type, or null.</summary>
    private static ElementType? Underlying(TypeSig type)
    {
        var t = IsEnum(type) ? type.ToTypeDefOrRef()?.ResolveTypeDef()?.GetEnumUnderlyingType()?.RemovePinnedAndModifiers() : type;
        return t?.ElementType is ElementType.Boolean or ElementType.Char or ElementType.I1 or ElementType.U1 or ElementType.I2 or ElementType.U2
            or ElementType.I4 or ElementType.U4 or ElementType.I8 or ElementType.U8 ? t.ElementType : null;
    }

    private static int Width(ElementType integer) => integer switch
    {
        ElementType.Boolean or ElementType.I1 or ElementType.U1 => 1,
        ElementType.Char or ElementType.I2 or ElementType.U2 => 2,
        ElementType.I4 or ElementType.U4 => 4,
        _ => 8,
    };

    /// <summary>sizeof of a primitive or enum type; anything else is not modelled (native sizes differ between platforms).</summary>
    private static int SizeOf(TypeSig type)
    {
        var t = IsEnum(type) ? type.ToTypeDefOrRef()?.ResolveTypeDef()?.GetEnumUnderlyingType()?.RemovePinnedAndModifiers() ?? type : type;
        return t.ElementType switch
        {
            ElementType.Boolean or ElementType.I1 or ElementType.U1 => 1,
            ElementType.Char or ElementType.I2 or ElementType.U2 => 2,
            ElementType.I4 or ElementType.U4 or ElementType.R4 => 4,
            ElementType.I8 or ElementType.U8 or ElementType.R8 => 8,
            ElementType.I or ElementType.U or ElementType.Ptr or ElementType.FnPtr or ElementType.Class or ElementType.Object or ElementType.String
                or ElementType.SZArray => throw Bail(FallbackReason.PlatformDependent, $"sizeof {type.FullName} differs between 32- and 64-bit platforms"),
            _ => throw Bail(FallbackReason.UnsupportedValue, $"sizeof {type.FullName}"),
        };
    }
}
