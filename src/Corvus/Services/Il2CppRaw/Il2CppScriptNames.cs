using System.Text;
using LibCpp2IL;
using LibCpp2IL.BinaryStructures;
using LibCpp2IL.Metadata;

namespace Corvus.Services;

/// <summary>
/// script.json's names for types and methods, so that names from the built-in reader equal those of script.json:
/// "Ns.Outer.Inner&lt;int, string&gt;" (namespace once, nested types joined with '.', arity suffixes dropped, generic
/// arguments by simple name with C# keywords), "Ns.Type&lt;T&gt;" for a definition's own parameters, and "Type$$Method".
/// Works on the LibCpp2IL state; caches what it reads from the binary.
/// </summary>
internal sealed class Il2CppScriptNames(Il2CppMetadata metadata, Il2CppBinary binary)
{
    private readonly Dictionary<ulong, Il2CppGenericClass> _classes = new();
    private readonly Dictionary<ulong, Il2CppType[]> _instances = new();

    private static readonly Dictionary<Il2CppTypeEnum, string> Keywords = new()
    {
        [Il2CppTypeEnum.IL2CPP_TYPE_VOID] = "void", [Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN] = "bool", [Il2CppTypeEnum.IL2CPP_TYPE_CHAR] = "char",
        [Il2CppTypeEnum.IL2CPP_TYPE_I1] = "sbyte", [Il2CppTypeEnum.IL2CPP_TYPE_U1] = "byte", [Il2CppTypeEnum.IL2CPP_TYPE_I2] = "short",
        [Il2CppTypeEnum.IL2CPP_TYPE_U2] = "ushort", [Il2CppTypeEnum.IL2CPP_TYPE_I4] = "int", [Il2CppTypeEnum.IL2CPP_TYPE_U4] = "uint",
        [Il2CppTypeEnum.IL2CPP_TYPE_I8] = "long", [Il2CppTypeEnum.IL2CPP_TYPE_U8] = "ulong", [Il2CppTypeEnum.IL2CPP_TYPE_R4] = "float",
        [Il2CppTypeEnum.IL2CPP_TYPE_R8] = "double", [Il2CppTypeEnum.IL2CPP_TYPE_STRING] = "string", [Il2CppTypeEnum.IL2CPP_TYPE_TYPEDBYREF] = "TypedReference",
        [Il2CppTypeEnum.IL2CPP_TYPE_I] = "IntPtr", [Il2CppTypeEnum.IL2CPP_TYPE_U] = "UIntPtr", [Il2CppTypeEnum.IL2CPP_TYPE_OBJECT] = "object",
    };

    public Il2CppGenericClass GenericClass(Il2CppType type)
    {
        if (!_classes.TryGetValue(type.Data.GenericClass, out var c)) _classes[type.Data.GenericClass] = c = type.GetGenericClass();
        return c;
    }

    public Il2CppTypeDefinition Definition(Il2CppGenericClass generic) => Definition(generic, metadata, binary);

    /// <summary>
    /// The definition a generic instance instantiates. From metadata 27 on, through the binary's own (shared, possibly
    /// repaired) Il2CppType entry rather than a fresh read of it.
    /// </summary>
    public static Il2CppTypeDefinition Definition(Il2CppGenericClass generic, Il2CppMetadata metadata, Il2CppBinary binary) =>
        metadata.MetadataVersion >= 27f ? binary.GetIl2CppTypeFromPointer(generic.V27TypePointer).AsClass() : generic.TypeDefinition;

    public Il2CppType[] Instance(ulong pointer)
    {
        if (!_instances.TryGetValue(pointer, out var types))
            _instances[pointer] = types = pointer == 0 ? [] : binary.ReadReadableAtVirtualAddress<Il2CppGenericInst>(pointer).Types;
        return types;
    }

    public Il2CppType[] Instance(int index) => index < 0 ? [] : binary.GetGenericInst(index).Types;

    /// <summary>A type's script.json name; <paramref name="nested"/> leaves out generic arguments, as for a declaring type.</summary>
    public string TypeName(Il2CppType type, bool addNamespace, bool nested, int depth = 0)
    {
        if (depth > 32) return "?";
        switch (type.Type)
        {
            case Il2CppTypeEnum.IL2CPP_TYPE_ARRAY:
                var array = type.GetArrayType();
                return $"{TypeName(array.ElementType, addNamespace, false, depth + 1)}[{new string(',', Math.Max(0, array.rank - 1))}]";
            case Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
                return TypeName(type.GetEncapsulatedType(), addNamespace, false, depth + 1) + "[]";
            case Il2CppTypeEnum.IL2CPP_TYPE_PTR:
                return TypeName(type.GetEncapsulatedType(), addNamespace, false, depth + 1) + "*";
            case Il2CppTypeEnum.IL2CPP_TYPE_VAR or Il2CppTypeEnum.IL2CPP_TYPE_MVAR:
                return type.GetGenericParameterDef().Name ?? "T";
            case Il2CppTypeEnum.IL2CPP_TYPE_CLASS or Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE or Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                Il2CppGenericClass? generic = type.Type == Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST ? GenericClass(type) : null;
                var definition = generic != null ? Definition(generic) : type.AsClass();
                var sb = new StringBuilder();
                if (definition.DeclaringTypeIndex.Value >= 0) sb.Append(TypeName(binary.GetType(definition.DeclaringTypeIndex), addNamespace, true, depth + 1)).Append('.');
                else if (addNamespace && definition.Namespace is { Length: > 0 } ns) sb.Append(ns).Append('.');
                sb.Append(StripArity(definition.Name ?? ""));
                if (nested) return sb.ToString();
                if (generic != null) sb.Append(Arguments(Instance(generic.Context.class_inst), depth));
                else if (definition.GenericContainer is { } container) sb.Append(Parameters(container));
                return sb.ToString();
            default:
                return Keywords.GetValueOrDefault(type.Type, type.Type.ToString());
        }
    }

    /// <summary>A type definition's script.json name, with its own generic parameters when asked.</summary>
    public string TypeDefName(Il2CppTypeDefinition definition, bool addNamespace, bool genericParameters)
    {
        var sb = new StringBuilder();
        if (definition.DeclaringTypeIndex.Value >= 0) sb.Append(TypeName(binary.GetType(definition.DeclaringTypeIndex), addNamespace, true)).Append('.');
        else if (addNamespace && definition.Namespace is { Length: > 0 } ns) sb.Append(ns).Append('.');
        var name = definition.Name ?? "";
        if (definition.GenericContainerIndex.Value >= 0)
        {
            sb.Append(StripArity(name));
            if (genericParameters && definition.GenericContainer is { } container) sb.Append(Parameters(container));
        }
        else sb.Append(name);
        return sb.ToString();
    }

    /// <summary>A method instantiation's script.json name: the type part (with class arguments) and the method part (with method arguments).</summary>
    public (string Type, string Method) MethodSpecName(Il2CppMethodSpec spec, bool addNamespace)
    {
        var method = metadata.methodDefs[spec.methodDefinitionIndex.Value];
        var type = TypeDefName(metadata.typeDefs[method.declaringTypeIdx.Value], addNamespace, false);
        if (spec.classIndexIndex >= 0) type += Arguments(Instance(spec.classIndexIndex), 0);
        var name = method.Name ?? "";
        if (spec.methodIndexIndex >= 0) name += Arguments(Instance(spec.methodIndexIndex), 0);
        return (type, name);
    }

    private string Arguments(Il2CppType[] types, int depth) =>
        "<" + string.Join(", ", types.Select(t => TypeName(t, false, false, depth + 1))) + ">";

    private static string Parameters(Il2CppGenericContainer container) =>
        "<" + string.Join(", ", container.GenericParameters.Select(p => p.Name)) + ">";

    public static string StripArity(string name) => name.IndexOf('`') is var i and >= 0 ? name[..i] : name;

    /// <summary>The C struct name of a type name in script.json: every character other than a letter, digit or '_' becomes '_'.</summary>
    public static string StructName(string typeName)
    {
        var sb = new StringBuilder(typeName.Length);
        foreach (var c in typeName) sb.Append(char.IsAsciiLetterOrDigit(c) || c == '_' ? c : '_');
        return sb.ToString();
    }
}

/// <summary>LibCpp2IL's typed metadata indexes from plain numbers.</summary>
internal static class Il2CppIndex
{
    public static Il2CppVariableWidthIndex<T> Of<T>(int value) where T : LibCpp2IL.ReadableClass => Il2CppVariableWidthIndex<T>.MakeTemporaryForFixedWidthUsage(value);
}
