// NativeFormat metadata record schema of .NET 7 to 10 (SchemaDef.cs and the generated readers in dotnet/runtime).

namespace Corvus.Native.NativeAot;

/// <summary>NativeFormat metadata record kinds; the values are the .NET 9+ HandleType numbers.</summary>
public enum MdRecord : byte
{
    Null,
    ArraySignature,
    ByReferenceSignature,
    ConstantBooleanArray,
    ConstantBooleanValue,
    ConstantByteArray,
    ConstantByteValue,
    ConstantCharArray,
    ConstantCharValue,
    ConstantDoubleArray,
    ConstantDoubleValue,
    ConstantEnumArray,
    /// <summary>ConstantBoxedEnumValue in the .NET 7 / 8 dialect.</summary>
    ConstantEnumValue,
    ConstantHandleArray,
    ConstantInt16Array,
    ConstantInt16Value,
    ConstantInt32Array,
    ConstantInt32Value,
    ConstantInt64Array,
    ConstantInt64Value,
    ConstantReferenceValue,
    ConstantSByteArray,
    ConstantSByteValue,
    ConstantSingleArray,
    ConstantSingleValue,
    ConstantStringArray,
    ConstantStringValue,
    ConstantUInt16Array,
    ConstantUInt16Value,
    ConstantUInt32Array,
    ConstantUInt32Value,
    ConstantUInt64Array,
    ConstantUInt64Value,
    CustomAttribute,
    Event,
    Field,
    FieldSignature,
    FunctionPointerSignature,
    GenericParameter,
    MemberReference,
    Method,
    MethodInstantiation,
    MethodSemantics,
    MethodSignature,
    MethodTypeVariableSignature,
    ModifiedType,
    NamedArgument,
    NamespaceDefinition,
    NamespaceReference,
    Parameter,
    PointerSignature,
    Property,
    PropertySignature,
    QualifiedField,
    QualifiedMethod,
    SZArraySignature,
    ScopeDefinition,
    ScopeReference,
    TypeDefinition,
    TypeForwarder,
    TypeInstantiationSignature,
    TypeReference,
    TypeSpecification,
    TypeVariableSignature,
}

/// <summary>
/// Field encodings of each record in schema order. Codes: h handle of any record (type in the low bits), t handle of a
/// fixed record (offset only), c collection of handles (count, then compressed integers), u / i compressed unsigned /
/// signed integer (also enums, char, short), l / j unsigned / signed long, b one byte (bool, byte, sbyte), f / d
/// float / double, s string (byte count, UTF-8), 1 / 2 / 4 / 8 collection of fixed-size primitives of that size.
/// </summary>
internal static class NativeAotSchema
{
    public sealed record Layout(MdRecord Record, string Codes, string Names)
    {
        public string[] FieldNames { get; } = Names.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        public int Index(string field) => Array.IndexOf(FieldNames, field) is var i and >= 0 ? i
            : throw new ArgumentException($"{Record} has no field {field}");
    }

    /// <summary>Identical in .NET 7–10 apart from the ConstantBoxedEnumValue / ConstantEnumValue rename.</summary>
    private static readonly Layout[] Common =
    [
        new(MdRecord.ArraySignature, "hi44", "elementType rank sizes lowerBounds"),
        new(MdRecord.ByReferenceSignature, "h", "type"),
        new(MdRecord.ConstantBooleanArray, "1", "value"),
        new(MdRecord.ConstantBooleanValue, "b", "value"),
        new(MdRecord.ConstantByteArray, "1", "value"),
        new(MdRecord.ConstantByteValue, "b", "value"),
        new(MdRecord.ConstantCharArray, "2", "value"),
        new(MdRecord.ConstantCharValue, "u", "value"),
        new(MdRecord.ConstantDoubleArray, "8", "value"),
        new(MdRecord.ConstantDoubleValue, "d", "value"),
        new(MdRecord.ConstantEnumArray, "hh", "elementType value"),
        new(MdRecord.ConstantEnumValue, "hh", "value type"),
        new(MdRecord.ConstantHandleArray, "c", "value"),
        new(MdRecord.ConstantInt16Array, "2", "value"),
        new(MdRecord.ConstantInt16Value, "i", "value"),
        new(MdRecord.ConstantInt32Array, "4", "value"),
        new(MdRecord.ConstantInt32Value, "i", "value"),
        new(MdRecord.ConstantInt64Array, "8", "value"),
        new(MdRecord.ConstantInt64Value, "j", "value"),
        new(MdRecord.ConstantReferenceValue, "", ""),
        new(MdRecord.ConstantSByteArray, "1", "value"),
        new(MdRecord.ConstantSByteValue, "b", "value"),
        new(MdRecord.ConstantSingleArray, "4", "value"),
        new(MdRecord.ConstantSingleValue, "f", "value"),
        new(MdRecord.ConstantStringArray, "c", "value"),
        new(MdRecord.ConstantStringValue, "s", "value"),
        new(MdRecord.ConstantUInt16Array, "2", "value"),
        new(MdRecord.ConstantUInt16Value, "u", "value"),
        new(MdRecord.ConstantUInt32Array, "4", "value"),
        new(MdRecord.ConstantUInt32Value, "u", "value"),
        new(MdRecord.ConstantUInt64Array, "8", "value"),
        new(MdRecord.ConstantUInt64Value, "l", "value"),
        new(MdRecord.CustomAttribute, "hcc", "constructor fixedArguments namedArguments"),
        new(MdRecord.Event, "uthcc", "flags name type methodSemantics customAttributes"),
        new(MdRecord.Field, "utthuc", "flags name signature defaultValue offset customAttributes"),
        new(MdRecord.FieldSignature, "h", "type"),
        new(MdRecord.FunctionPointerSignature, "t", "signature"),
        new(MdRecord.GenericParameter, "uuutcc", "number flags kind name constraints customAttributes"),
        new(MdRecord.MemberReference, "hth", "parent name signature"),
        new(MdRecord.Method, "uuttccc", "flags implFlags name signature parameters genericParameters customAttributes"),
        new(MdRecord.MethodInstantiation, "hc", "method genericTypeArguments"),
        new(MdRecord.MethodSemantics, "ut", "attributes method"),
        new(MdRecord.MethodSignature, "uihcc", "callingConvention genericParameterCount returnType parameters varArgParameters"),
        new(MdRecord.MethodTypeVariableSignature, "i", "number"),
        new(MdRecord.ModifiedType, "bhh", "isOptional modifierType type"),
        new(MdRecord.NamedArgument, "uthh", "flags name type value"),
        new(MdRecord.NamespaceDefinition, "htccc", "parentScopeOrNamespace name typeDefinitions typeForwarders namespaceDefinitions"),
        new(MdRecord.NamespaceReference, "ht", "parentScopeOrNamespace name"),
        new(MdRecord.Parameter, "uuthc", "flags sequence name defaultValue customAttributes"),
        new(MdRecord.PointerSignature, "h", "type"),
        new(MdRecord.Property, "uttchc", "flags name signature methodSemantics defaultValue customAttributes"),
        new(MdRecord.PropertySignature, "uhc", "callingConvention type parameters"),
        new(MdRecord.QualifiedField, "tt", "field enclosingType"),
        new(MdRecord.QualifiedMethod, "tt", "method enclosingType"),
        new(MdRecord.SZArraySignature, "h", "elementType"),
        new(MdRecord.ScopeDefinition, "utuuuuu1ttttct1c", "flags name hashAlgorithm majorVersion minorVersion buildNumber revisionNumber publicKey culture rootNamespaceDefinition entryPoint globalModuleType customAttributes moduleName mvid moduleCustomAttributes"),
        new(MdRecord.ScopeReference, "utuuuu1t", "flags name majorVersion minorVersion buildNumber revisionNumber publicKeyOrToken culture"),
        new(MdRecord.TypeDefinition, "uhttuutcccccccc", "flags baseType namespaceDefinition name size packingSize enclosingType nestedTypes methods fields properties events genericParameters interfaces customAttributes"),
        new(MdRecord.TypeForwarder, "ttc", "scope name nestedTypes"),
        new(MdRecord.TypeInstantiationSignature, "hc", "genericType genericTypeArguments"),
        new(MdRecord.TypeReference, "ht", "parentNamespaceOrType typeName"),
        new(MdRecord.TypeSpecification, "h", "signature"),
        new(MdRecord.TypeVariableSignature, "i", "number"),
    ];

    /// <summary>.NET 11 (main): one namespace-or-enclosing-type handle replaces the namespace and enclosing type fields.</summary>
    private static readonly Layout[] Net11Changes =
    [
        new(MdRecord.TypeDefinition, "uhhtuucccccccc", "flags baseType namespaceOrEnclosingType name size packingSize nestedTypes methods fields properties events genericParameters interfaces customAttributes"),
        new(MdRecord.TypeReference, "ht", "namespaceOrEnclosingType typeName"),
    ];

    private static readonly Layout[] Classic = ByRecord(Common);
    private static readonly Layout[] Net11 = ByRecord([.. Common.Where(l => !Net11Changes.Any(c => c.Record == l.Record)), .. Net11Changes]);
    private static readonly MdRecord[] Net7Types = RawTypes("ConstantBoxedEnumValue");
    private static readonly MdRecord[] Net9Types = RawTypes("ConstantEnumValue");

    private static Layout[] ByRecord(IEnumerable<Layout> layouts)
    {
        var table = new Layout[(int)MdRecord.TypeVariableSignature + 1];
        foreach (var l in layouts) table[(int)l.Record] = l;
        return table;
    }

    /// <summary>HandleType numbering: record names in ordinal order after Null (NativeFormatReaderCommonGen.cs).</summary>
    private static MdRecord[] RawTypes(string enumValueName)
    {
        var names = Enum.GetValues<MdRecord>().Where(r => r != MdRecord.Null)
            .Select(r => (Name: r == MdRecord.ConstantEnumValue ? enumValueName : r.ToString(), Record: r))
            .OrderBy(n => n.Name, StringComparer.Ordinal);
        return [MdRecord.Null, .. names.Select(n => n.Record)];
    }

    public static Layout For(MetadataDialect dialect, MdRecord record) =>
        (dialect == MetadataDialect.Net11 ? Net11 : Classic)[(int)record];

    /// <summary>The record kind of raw handle type <paramref name="raw"/>, or null when out of range.</summary>
    public static MdRecord? RecordOf(MetadataDialect dialect, uint raw)
    {
        var table = dialect == MetadataDialect.Net7 ? Net7Types : Net9Types;
        return raw < table.Length ? table[raw] : null;
    }

    /// <summary>The raw handle type of <paramref name="record"/> in <paramref name="dialect"/>.</summary>
    public static uint RawType(MetadataDialect dialect, MdRecord record) =>
        (uint)Array.IndexOf(dialect == MetadataDialect.Net7 ? Net7Types : Net9Types, record);
}
