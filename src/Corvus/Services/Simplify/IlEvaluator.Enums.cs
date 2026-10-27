using dnlib.DotNet;

namespace Corvus.Services.Simplify;

internal sealed partial class IlEvaluator
{
    /// <summary>A type test of an array against System.Array or a primitive or enum vector of the same storage; reference arrays are refused.</summary>
    private bool IsArrayOf(ArrayObject array, TypeSig type)
    {
        if (type is not SZArraySig { Next: var element }) return true;
        if (array.Data is object?[]) throw Bail(FallbackReason.UnsupportedValue, $"type test of an array of references against {type.FullName}");
        var stored = element.RemovePinnedAndModifiers();
        if (!(stored.IsPrimitive || IsEnum(stored))) return false;
        return ElementClrType(stored) == array.Data.GetType().GetElementType()
            ? true
            : throw Bail(FallbackReason.UnsupportedValue, $"type test of a {array.Data.GetType().GetElementType()!.Name}[] against {type.FullName}");
    }

    /// <summary>Enum.GetValues of a module enum: its constants sorted by unsigned value, duplicates kept, as underlying integers.</summary>
    private ArrayObject EnumValues(object? type)
    {
        var t = TypeOf(type);
        var td = OwnType(t) ?? throw Bail(FallbackReason.OtherModule, $"Enum.GetValues of {t.Sig.FullName}, not a type of this module");
        if (!td.IsEnum) throw Bail(FallbackReason.RuntimeError, $"Enum.GetValues of {td.FullName}, which is not an enum (ArgumentException)");
        var elementType = ElementClrType(t.Sig);
        var bits = td.Fields.Where(f => f.IsLiteral && f.IsStatic && f.Constant?.Value is not null)
            .Select(f => Bits(f.Constant.Value) & Mask(elementType)).Order().ToList();
        var array = Array.CreateInstance(elementType, bits.Count);
        for (int i = 0; i < bits.Count; i++) array.SetValue(FromBits(bits[i], elementType), i);
        return NewArray(array);

        static ulong Bits(object v) => v switch
        {
            sbyte x => unchecked((ulong)x), short x => unchecked((ulong)x), int x => unchecked((ulong)x), long x => unchecked((ulong)x),
            byte x => x, ushort x => x, char x => x, uint x => x, ulong x => x, bool x => x ? 1UL : 0UL,
            _ => throw Bail(FallbackReason.InvalidCode, "an enum constant that is not an integer"),
        };
        static ulong Mask(Type e) => e == typeof(byte) || e == typeof(sbyte) ? 0xFF
            : e == typeof(short) || e == typeof(ushort) || e == typeof(char) ? 0xFFFF
            : e == typeof(int) || e == typeof(uint) ? 0xFFFFFFFF
            : ulong.MaxValue;
        static object FromBits(ulong b, Type e) => unchecked(
            e == typeof(byte) ? (byte)b : e == typeof(sbyte) ? (sbyte)b : e == typeof(short) ? (short)b : e == typeof(ushort) ? (ushort)b
            : e == typeof(char) ? (char)b : e == typeof(int) ? (int)b : e == typeof(uint) ? (uint)b : e == typeof(long) ? (long)b : (object)b);
    }
}
