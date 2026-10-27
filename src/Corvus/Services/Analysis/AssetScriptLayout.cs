using dnlib.DotNet;
using Corvus.Core.Assets;

namespace Corvus.Services.Analysis;

/// <summary>Builds a MonoBehaviour's serialized type tree from its class; a field the assembly cannot lay out ends it, named in <see cref="Layout.Unknown"/>.</summary>
internal static class AssetScriptLayout
{
    /// <summary>The tree, and when it ends early the reason and the top-level field it stops before (null outside the fields).</summary>
    public sealed record Layout(List<AssetTypeNode> Tree, string? Unknown, string? UnknownField);

    private const int MaxDepth = 10;
    private const int Align = 0x4000;

    private static readonly HashSet<string> NativeBases =
        ["UnityEngine.MonoBehaviour", "UnityEngine.ScriptableObject", "UnityEngine.Behaviour", "UnityEngine.Component", "UnityEngine.Object", "System.Object", "System.ValueType"];

    /// <summary>Types the runtime serializes natively rather than from their C# fields.</summary>
    private static readonly HashSet<string> NativeLayouts = ["UnityEngine.Gradient", "UnityEngine.GUIStyle"];

    /// <summary>The layout of <paramref name="script"/>; without <paramref name="attributesKept"/> a private field is unknown unless attributes were read.</summary>
    public static Layout Build(TypeDef script, int format, bool attributesKept, string? engineVersion = null)
    {
        var b = new Builder(format, attributesKept, GenericFields(engineVersion), Version(engineVersion));
        b.Fields(script, null, 1, 0, "");
        return new Layout(b.Nodes, b.Stopped, b.StoppedField);
    }

    /// <summary>Whether fields of generic types are serialized (from 2020.1); null when the version is not known.</summary>
    private static bool? GenericFields(string? version) => Version(version) is { } v ? v >= new Version(2020, 1) : null;

    /// <summary>The major and minor version of a version string ("2021.3.5f1" is 2021.3), or null.</summary>
    private static Version? Version(string? version)
    {
        var m = version == null ? null : System.Text.RegularExpressions.Regex.Match(version, @"^(\d{1,4})\.(\d{1,2})");
        return m is { Success: true } ? new Version(int.Parse(m.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture),
            int.Parse(m.Groups[2].Value, System.Globalization.CultureInfo.InvariantCulture)) : null;
    }

    private abstract record Plan;
    private sealed record Skip : Plan;
    private sealed record Unknown(string Reason) : Plan;
    private sealed record Primitive(string Type, int Size, int Flags = 0) : Plan;
    private sealed record Text : Plan;
    private sealed record Pointer(string Type) : Plan;
    private sealed record Fixed(string FullName) : Plan;
    private sealed record Vector(Plan Element) : Plan;
    private sealed record Inline(TypeDef Type, IList<TypeSig>? Args) : Plan;

    private sealed class Builder(int format, bool attributesKept, bool? genericFields, Version? engine)
    {
        public readonly List<AssetTypeNode> Nodes = AssetScriptObject.BaseTree(format);
        public string? Stopped, StoppedField;

        /// <summary>Adds the serialized fields of <paramref name="type"/> and its bases; false once a field is unknown.</summary>
        public bool Fields(TypeDef type, IList<TypeSig>? args, int level, int depth, string path)
        {
            var chain = new List<(TypeDef Type, IList<TypeSig>? Args)>();
            for (var (t, targs) = (type, args); ;)
            {
                chain.Add((t, targs));
                if (t.BaseType is not { } baseRef || NativeBases.Contains(baseRef.FullName)) break;
                var target = baseRef;
                IList<TypeSig>? next = null;
                if (baseRef is TypeSpec { TypeSig: GenericInstSig g })
                {
                    target = g.GenericType.TypeDefOrRef;
                    next = [.. g.GenericArguments.Select(a => Bind(a, targs))];
                }
                if (target?.ResolveTypeDef() is not { } resolved) return Stop(path.Length > 0 ? path : type.Name, $"base class {target?.FullName ?? baseRef.FullName} is in an assembly that was not found");
                if (chain.Count > 32 || chain.Any(c => c.Type == resolved)) return Stop(type.Name, "a base class cycle");
                (t, targs) = (resolved, next);
            }
            chain.Reverse();
            foreach (var (t, targs) in chain)
                foreach (var f in t.Fields)
                {
                    if (f.IsStatic || f.IsLiteral || f.IsInitOnly || f.IsNotSerialized) continue;
                    var name = path.Length > 0 ? $"{path}.{f.Name}" : f.Name.String;
                    int mark = Nodes.Count;
                    if (!Field(f, targs, name, level, depth))
                    {
                        if (level == 1)
                        {
                            Nodes.RemoveRange(mark, Nodes.Count - mark);
                            StoppedField ??= f.Name;
                        }
                        return false;
                    }
                }
            return true;
        }

        private bool Field(FieldDef f, IList<TypeSig>? args, string name, int level, int depth)
        {
            if (Has(f, "UnityEngine.SerializeReference")) return Stop(name, "a [SerializeReference] field keeps managed references this reader does not lay out");
            // Without the binary every field type is one placeholder, so serialization is unknown before the private-field rule.
            if (f.FieldSig?.Type?.ToTypeDefOrRef() is { TypeName: AotMetadataOnly.Placeholder, Namespace: AotDummyBuilder.AttributeAssembly })
                return Stop(name, "a field whose type is in the AOT binary, which was not read");
            var plan = PlanOf(Bind(f.FieldSig?.Type, args), depth, element: false);
            if (plan is Skip) return true;
            if (!f.IsPublic && !Has(f, "UnityEngine.SerializeField"))
            {
                if (attributesKept || AotDummyBuilder.FieldAttributesRead(f.Module)) return true;
                return Stop(name, "a private field; whether it is [SerializeField] was not read from the AOT metadata");
            }
            return plan is Unknown u ? Stop(name, u.Reason) : Emit(plan, f.Name, level, depth, element: false, name);
        }

        private bool Stop(string field, string reason)
        {
            Stopped ??= $"{field}: {reason}";
            return false;
        }

        private bool Emit(Plan plan, string name, int level, int depth, bool element, string path)
        {
            switch (plan)
            {
                case Primitive p:
                    Nodes.Add(new AssetTypeNode(p.Type, name, level, p.Size, false, p.Flags | (!element && p.Size < 4 ? Align : 0)));
                    return true;
                case Text:
                    AssetScriptObject.String(Nodes, name, level);
                    return true;
                case Pointer p:
                    AssetScriptObject.Pointer(Nodes, $"PPtr<{p.Type}>", name, level, format);
                    return true;
                case Fixed f:
                    FixedStruct(f.FullName, name, level);
                    return true;
                case Vector v:
                    Nodes.Add(new AssetTypeNode("vector", name, level, -1, false, 0));
                    Nodes.Add(new AssetTypeNode("Array", "Array", level + 1, -1, true, Align));
                    Nodes.Add(new AssetTypeNode("int", "size", level + 2, 4, false, 0));
                    return Emit(v.Element, "data", level + 2, depth, element: true, path + "[]");
                case Inline i:
                {
                    int at = Nodes.Count;
                    Nodes.Add(new AssetTypeNode(i.Type.Name, name, level, -1, false, 0));
                    if (!Fields(i.Type, i.Args, level + 1, depth + 1, path)) return false;
                    if (Nodes.Count > at + 1) return true;
                    // A UnityEngine type with no serialized C# fields is serialized natively.
                    if (IsEngineModule(i.Type)) return Stop(path, $"type {i.Type.FullName}, which the runtime lays out natively");
                    Nodes[at] = Nodes[at] with { ByteSize = 0 };
                    return true;
                }
                default:
                    return Stop(path, "a field this reader does not lay out");
            }
        }

        private Plan PlanOf(TypeSig? sig, int depth, bool element)
        {
            sig = sig?.RemovePinnedAndModifiers();
            switch (sig?.ElementType)
            {
                case null: return new Unknown("a field without a signature");
                case ElementType.Boolean: return new Primitive("UInt8", 1, AssetTypeNode.BooleanFlag);
                case ElementType.Char: return new Primitive("UInt16", 2);
                case ElementType.I1 or ElementType.U1 or ElementType.I2 or ElementType.U2 or ElementType.I4 or ElementType.U4 or ElementType.I8 or ElementType.U8:
                    return Integer(sig.ElementType);
                case ElementType.R4: return new Primitive("float", 4);
                case ElementType.R8: return new Primitive("double", 8);
                case ElementType.String: return new Text();
                case ElementType.SZArray: return Elements(sig.Next, depth, element);
                case ElementType.GenericInst when sig is GenericInstSig g:
                {
                    if (g.GenericType.FullName == "System.Collections.Generic.List`1" && g.GenericArguments.Count == 1) return Elements(g.GenericArguments[0], depth, element);
                    if (IsCorlib(g.GenericType.TypeDefOrRef)) return new Skip();
                    if (g.GenericType.TypeDefOrRef.ResolveTypeDef() is not { } gd) return new Unknown($"type {g.GenericType.FullName} is in an assembly that was not found");
                    switch (DerivesFromObject(gd))
                    {
                        case true: return new Pointer(PointerName(gd));
                        case null: return new Unknown($"a base class of {gd.FullName} is in an assembly that was not found");
                    }
                    if (gd.IsInterface || gd.IsAbstract || !gd.IsSerializable) return new Skip();
                    return genericFields switch
                    {
                        null => new Unknown("a generic serializable type, serialized only from 2020.1; the version is not known"),
                        false => new Skip(),
                        true when depth + 1 >= MaxDepth => new Unknown($"nested deeper than the serializer's {MaxDepth} levels"),
                        true => new Inline(gd, g.GenericArguments),
                    };
                }
                case ElementType.ValueType or ElementType.Class:
                    return Named(sig.ToTypeDefOrRef(), depth);
                case ElementType.Var or ElementType.MVar:
                    return new Unknown("a field of a generic parameter type that is not bound");
                default:
                    return new Skip();
            }
        }

        private static Plan Integer(ElementType type) => type switch
        {
            ElementType.I1 => new Primitive("SInt8", 1),
            ElementType.U1 => new Primitive("UInt8", 1),
            ElementType.I2 => new Primitive("SInt16", 2),
            ElementType.U2 => new Primitive("UInt16", 2),
            ElementType.I4 => new Primitive("int", 4),
            ElementType.U4 => new Primitive("unsigned int", 4),
            ElementType.I8 => new Primitive("SInt64", 8),
            _ => new Primitive("UInt64", 8),
        };

        private Plan Elements(TypeSig? element, int depth, bool nested)
        {
            // Arrays of arrays or lists are not serialized.
            if (nested) return new Skip();
            var p = PlanOf(element, depth, element: true);
            return p switch { Unknown => p, Skip or Vector => new Skip(), _ => new Vector(p) };
        }

        private Plan Named(ITypeDefOrRef? type, int depth)
        {
            if (type == null) return new Unknown("a field whose type does not resolve");
            var full = type.FullName;
            if (FixedStructs.Contains(full)) return new Fixed(full);
            // Keyframes gained weights in 2018.1 and curves a rotation order in 5.3; older layouts are not modelled.
            if (full == "UnityEngine.AnimationCurve")
                return engine == null || engine < new Version(5, 3) ? new Unknown("an AnimationCurve, whose layout is known only from version 5.3; the version is older or unknown") : new Fixed(full);
            if (IsCorlib(type)) return new Skip();
            if (type.ResolveTypeDef() is not { } def) return new Unknown($"type {full} is in an assembly that was not found");
            if (def.IsEnum)
                return def.GetEnumUnderlyingType()?.ElementType is var e && e is >= ElementType.I1 and <= ElementType.U4
                    ? Integer(e.Value)
                    : new Unknown($"an enum with a {e?.ToString() ?? "unknown"} underlying type; only enums of 32 bits or less are serialized");
            switch (DerivesFromObject(def))
            {
                case true: return new Pointer(PointerName(def));
                case null: return new Unknown($"a base class of {full} is in an assembly that was not found");
            }
            if (def.IsInterface || def.IsAbstract || def.BaseType?.FullName == "System.MulticastDelegate") return new Skip();
            if (NativeLayouts.Contains(full)) return new Unknown($"type {full}, which the runtime lays out natively");
            if (!def.IsSerializable) return IsEngineModule(def) ? new Unknown($"type {full}, which the runtime lays out natively") : new Skip();
            if (def.HasGenericParameters) return new Unknown("a generic type without its arguments");
            if (depth + 1 >= MaxDepth) return new Unknown($"nested deeper than the serializer's {MaxDepth} levels");
            return new Inline(def, null);
        }

        /// <summary>True when the class derives from UnityEngine.Object, false when not, null when a base does not resolve.</summary>
        private static bool? DerivesFromObject(TypeDef def)
        {
            for (var t = def; t != null;)
            {
                if (t.FullName == "UnityEngine.Object") return true;
                if (t.BaseType is not { } b || b.FullName is "System.Object" or "System.ValueType" or "System.Enum") return false;
                if (b.FullName == "UnityEngine.Object") return true;
                t = (b is TypeSpec { TypeSig: GenericInstSig g } ? g.GenericType.TypeDefOrRef : b).ResolveTypeDef();
                if (t == null) return null;
            }
            return false;
        }

        /// <summary><paramref name="sig"/> with the class's generic parameters replaced by <paramref name="args"/>.</summary>
        [return: System.Diagnostics.CodeAnalysis.NotNullIfNotNull(nameof(sig))]
        private static TypeSig? Bind(TypeSig? sig, IList<TypeSig>? args) => args == null ? sig : sig switch
        {
            GenericVar v when v.Number < args.Count => args[(int)v.Number],
            SZArraySig a => new SZArraySig(Bind(a.Next, args)),
            GenericInstSig g => new GenericInstSig(g.GenericType, [.. g.GenericArguments.Select(x => Bind(x, args))]),
            _ => sig,
        };

        /// <summary>UnityEngine and UnityEngine.*Module assemblies, whose types may be serialized natively.</summary>
        private static bool IsEngineModule(TypeDef def) =>
            def.Module?.Assembly?.Name.String is { } name && (name == "UnityEngine" || name.StartsWith("UnityEngine.", StringComparison.Ordinal) && name.EndsWith("Module", StringComparison.Ordinal));

        /// <summary>The PPtr type name of a script field: the class name with a leading $.</summary>
        private static string PointerName(TypeDef def) => "$" + def.Name;

        private static bool IsCorlib(ITypeDefOrRef type) => type.Namespace == "System" || type.Namespace.StartsWith("System.", StringComparison.Ordinal);

        private static bool Has(IHasCustomAttribute member, string attribute) => member.CustomAttributes.Any(a => a.TypeFullName == attribute);

        private static readonly HashSet<string> FixedStructs =
        [
            "UnityEngine.Vector2", "UnityEngine.Vector3", "UnityEngine.Vector4", "UnityEngine.Quaternion", "UnityEngine.Color", "UnityEngine.Color32",
            "UnityEngine.Rect", "UnityEngine.Bounds", "UnityEngine.Matrix4x4", "UnityEngine.LayerMask", "UnityEngine.Vector2Int", "UnityEngine.Vector3Int",
            "UnityEngine.RectInt", "UnityEngine.BoundsInt", "UnityEngine.RectOffset",
        ];

        /// <summary>Appends a fixed struct as the type tree names it (Vector3f, ColorRGBA, Rectf).</summary>
        private void FixedStruct(string full, string name, int level)
        {
            void Group(string type, string field, int at, string leaf, int size, params string[] names)
            {
                Nodes.Add(new AssetTypeNode(type, field, at, names.Length * size, false, 0));
                foreach (var n in names) Nodes.Add(new AssetTypeNode(leaf, n, at + 1, size, false, 0));
            }
            switch (full)
            {
                case "UnityEngine.Vector2": Group("Vector2f", name, level, "float", 4, "x", "y"); break;
                case "UnityEngine.Vector3": Group("Vector3f", name, level, "float", 4, "x", "y", "z"); break;
                case "UnityEngine.Vector4": Group("Vector4f", name, level, "float", 4, "x", "y", "z", "w"); break;
                case "UnityEngine.Quaternion": Group("Quaternionf", name, level, "float", 4, "x", "y", "z", "w"); break;
                case "UnityEngine.Color": Group("ColorRGBA", name, level, "float", 4, "r", "g", "b", "a"); break;
                case "UnityEngine.Color32": Group("ColorRGBA", name, level, "unsigned int", 4, "rgba"); break;
                case "UnityEngine.Rect": Group("Rectf", name, level, "float", 4, "x", "y", "width", "height"); break;
                case "UnityEngine.LayerMask": Group("BitField", name, level, "unsigned int", 4, "m_Bits"); break;
                case "UnityEngine.Vector2Int": Group("int2_storage", name, level, "int", 4, "m_X", "m_Y"); break;
                case "UnityEngine.Vector3Int": Group("int3_storage", name, level, "int", 4, "m_X", "m_Y", "m_Z"); break;
                case "UnityEngine.RectInt": Group("RectInt", name, level, "int", 4, "m_XMin", "m_YMin", "m_Width", "m_Height"); break;
                case "UnityEngine.RectOffset": Group("RectOffset", name, level, "int", 4, "m_Left", "m_Right", "m_Top", "m_Bottom"); break;
                case "UnityEngine.AnimationCurve":
                    Nodes.Add(new AssetTypeNode("AnimationCurve", name, level, -1, false, 0));
                    Nodes.Add(new AssetTypeNode("vector", "m_Curve", level + 1, -1, false, 0));
                    Nodes.Add(new AssetTypeNode("Array", "Array", level + 2, -1, true, Align));
                    Nodes.Add(new AssetTypeNode("int", "size", level + 3, 4, false, 0));
                    bool weighted = engine >= new Version(2018, 1);
                    Nodes.Add(new AssetTypeNode("Keyframe", "data", level + 3, weighted ? 28 : 16, false, 0));
                    foreach (var key in new[] { "time", "value", "inSlope", "outSlope" }) Nodes.Add(new AssetTypeNode("float", key, level + 4, 4, false, 0));
                    if (weighted)
                    {
                        Nodes.Add(new AssetTypeNode("int", "weightedMode", level + 4, 4, false, 0));
                        Nodes.Add(new AssetTypeNode("float", "inWeight", level + 4, 4, false, 0));
                        Nodes.Add(new AssetTypeNode("float", "outWeight", level + 4, 4, false, 0));
                    }
                    foreach (var key in new[] { "m_PreInfinity", "m_PostInfinity", "m_RotationOrder" }) Nodes.Add(new AssetTypeNode("int", key, level + 1, 4, false, 0));
                    break;
                case "UnityEngine.Matrix4x4":
                    Group("Matrix4x4f", name, level, "float", 4, [.. from r in "0123" from c in "0123" select $"e{r}{c}"]);
                    break;
                case "UnityEngine.Bounds":
                    Nodes.Add(new AssetTypeNode("AABB", name, level, 24, false, 0));
                    Group("Vector3f", "m_Center", level + 1, "float", 4, "x", "y", "z");
                    Group("Vector3f", "m_Extent", level + 1, "float", 4, "x", "y", "z");
                    break;
                case "UnityEngine.BoundsInt":
                    Nodes.Add(new AssetTypeNode("BoundsInt", name, level, 24, false, 0));
                    Group("int3_storage", "m_Position", level + 1, "int", 4, "m_X", "m_Y", "m_Z");
                    Group("int3_storage", "m_Size", level + 1, "int", 4, "m_X", "m_Y", "m_Z");
                    break;
            }
        }
    }
}
