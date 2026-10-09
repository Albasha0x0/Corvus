using System.Text;
using dnlib.DotNet;
using NetDecompilerMcp.Core;
using static NetDecompilerMcp.Services.MetadataUtil;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Bindings of generic type definitions: a C++ template over the type parameters (the C++ type of each type argument,
/// a pointer for a reference type), resolved on an instantiation's class, since the class a lookup by name finds is the
/// definition, whose fields have no offsets of their own.
/// </summary>
public sealed partial class CppBindingGenerator
{
    /// <summary>Whether the type being rendered is a generic definition: its type parameters are template parameters.</summary>
    [ThreadStatic] private static bool _template;

    /// <summary>Stands for type parameter <paramref name="number"/> until the template parameter names are put in.</summary>
    private static string TypeParameter(int number) => $"$GP{number}$";

    private static bool IsTypeParameter(string cpp) => cpp.StartsWith("$GP", StringComparison.Ordinal);

    /// <summary>The template parameter names of a generic definition (empty for other types), unique and not C++ keywords.</summary>
    private static List<string> TemplateParameters(TypeDef type)
    {
        var names = new List<string>();
        foreach (var p in type.GenericParameters.OrderBy(p => p.Number))
        {
            var name = Identifier(p.Name);
            if (CppReserved.Contains(name)) name += "_";
            while (names.Contains(name)) name += "_";
            names.Add(name);
        }
        return names;
    }

    /// <summary>
    /// The struct up to the start of Resolve's body: for a generic definition the template line, the argument and
    /// result helpers, Definition() (the class found by name) and Resolve on an instantiation's class.
    /// <paramref name="objectType"/> null: no Result helper (the host's Invoke returns void*).
    /// </summary>
    private static void StructHead(StringBuilder sb, TypeDef type, string classType, string apiParameter, string find, string? objectType, StringBuilder decls)
    {
        bool generic = type.HasGenericParameters;
        if (generic)
        {
            sb.AppendLine("// Generic definition: instantiate the template with the C++ type of each type argument (a pointer for a reference");
            sb.AppendLine("// type) and Resolve on that instantiation's class (an object's class, or a class the runtime inflated).");
            sb.AppendLine($"template <{string.Join(", ", type.GenericParameters.Select((_, i) => "class " + TypeParameter(i)))}>");
        }
        sb.AppendLine($"struct {StructName(type)} {{");
        sb.AppendLine($"    {classType} klass = nullptr;");
        sb.Append(decls);
        sb.AppendLine();
        if (generic)
        {
            sb.AppendLine("    // A type-parameter argument as the runtime takes it: the object itself, or a pointer to the value.");
            sb.AppendLine("    template <class U> static void* Arg(U& value) { if constexpr (std::is_pointer_v<U>) return reinterpret_cast<void*>(value); else return &value; }");
            if (objectType != null)
            {
                var api = apiParameter[..apiParameter.LastIndexOf(' ')];
                sb.AppendLine($"    template <class U> static U Result({api} api, {objectType}* result) {{");
                sb.AppendLine("        if constexpr (std::is_pointer_v<U>) return reinterpret_cast<U>(result);");
                sb.AppendLine("        else { U value{}; if (result) std::memcpy(&value, api.object_unbox(result), sizeof value); return value; }");
                sb.AppendLine("    }");
            }
            sb.AppendLine();
            sb.AppendLine($"    static {classType} Definition({apiParameter}) {{ return {find}; }}");
            sb.AppendLine();
            sb.AppendLine($"    bool Resolve({apiParameter}, {classType} instance) {{");
            sb.AppendLine("        klass = instance;");
        }
        else
        {
            sb.AppendLine($"    bool Resolve({apiParameter}) {{");
            sb.AppendLine($"        klass = {find};");
        }
        sb.AppendLine("        if (!klass) return false;");
    }

    /// <summary>
    /// The instance layout of a generic definition as Il2Cpp lays out its instantiations: a template whose members are
    /// the fields in declaration order at natural alignment, each class level starting at a pointer-aligned offset, after
    /// the object header. A type parameter is its template parameter; references are pointers; closed value types are
    /// embedded as aligned bytes. Fields from the first one whose layout depends on a type argument inside another value
    /// type on are left out (the comment says so). Null when the definition has no instance fields.
    /// </summary>
    private static string? LayoutTemplate(TypeDef type)
    {
        var layout = new Il2CppLayout();
        var body = new StringBuilder();
        var used = new HashSet<string>(StringComparer.Ordinal) { "klass", "monitor" };
        if (!type.IsValueType)
        {
            body.AppendLine("    void* klass;");
            body.AppendLine("    void* monitor;");
        }
        int members = 0;
        string? stopped = null;
        foreach (var (level, args) in Levels(type))
        {
            bool first = true;
            foreach (var f in level.Fields.Where(f => !f.IsStatic && !f.IsLiteral))
            {
                var sig = args == null ? f.FieldType : Substitute(f.FieldType, args);
                var member = Il2CppLayout.Identifier(f.Name);
                while (!used.Add(member)) member += "_";
                var align = first && !type.IsValueType ? "alignas(8) " : "";
                first = false;
                if (MirrorType(layout, sig) is not { } m)
                {
                    stopped = $"{f.Name} ({Format.Type(f.FieldType)}) and the fields after it depend on a type argument inside a value type: not laid out";
                    break;
                }
                body.AppendLine(m.Bytes is { } bytes
                    ? $"    alignas({bytes.Align}) {align}nd_bytes {member}[{bytes.Size}];  // {Format.Type(sig)}"
                    : $"    {align}{m.Cpp} {member};  // {Format.Type(sig)}");
                members++;
            }
            if (stopped != null) break;
        }
        if (members == 0) return null;
        var sb = new StringBuilder();
        sb.AppendLine($"// Instance layout of {type.FullName} as Il2Cpp lays out an instantiation (object header first for a class).");
        if (stopped != null) sb.AppendLine($"// {stopped}.");
        sb.AppendLine($"template <{string.Join(", ", type.GenericParameters.Select((_, i) => "class " + TypeParameter(i)))}>");
        sb.AppendLine($"struct {BaseName(type)}Layout {{");
        sb.AppendLine("    using nd_bytes = unsigned char;");
        sb.Append(body);
        sb.AppendLine("};");
        return sb.ToString();
    }

    /// <summary>Base classes first, each with its type arguments in terms of the definition's own parameters (null: not generic).</summary>
    private static List<(TypeDef Type, IList<TypeSig>? Args)> Levels(TypeDef type)
    {
        var levels = new List<(TypeDef, IList<TypeSig>?)>();
        TypeDef? t = type;
        IList<TypeSig>? args = type.GenericParameters.OrderBy(p => p.Number).Select(p => (TypeSig)new GenericVar(p.Number, type)).ToList();
        while (t != null && levels.Count < 32 && t.FullName != "System.Object")
        {
            levels.Add((t, args));
            if (t.IsValueType) break;
            if (t.BaseType is TypeSpec { TypeSig: GenericInstSig baseInst })
            {
                var current = args;
                args = baseInst.GenericArguments.Select(g => current == null ? g : Substitute(g, current)).ToList();
                t = Try(() => baseInst.GenericType.TypeDefOrRef.ResolveTypeDef());
            }
            else
            {
                t = BaseTypeDef(t);
                args = null;
            }
        }
        levels.Reverse();
        return levels;
    }

    private static TypeSig Substitute(TypeSig sig, IList<TypeSig> args)
    {
        sig = sig.RemovePinnedAndModifiers();
        return sig switch
        {
            GenericVar v => v.Number < args.Count ? args[(int)v.Number] : sig,
            GenericInstSig gi => new GenericInstSig(gi.GenericType, gi.GenericArguments.Select(g => Substitute(g, args)).ToList()),
            SZArraySig sz => new SZArraySig(Substitute(sz.Next, args)),
            _ => sig,
        };
    }

    private static bool IsOpen(TypeSig sig) => sig.RemovePinnedAndModifiers() switch
    {
        GenericVar or GenericMVar => true,
        GenericInstSig gi => gi.GenericArguments.Any(IsOpen),
        { Next: { } next } => IsOpen(next),
        _ => false,
    };

    /// <summary>A member's C++ type in the layout template; <c>Bytes</c> for an embedded closed value type; null when it cannot be laid out.</summary>
    private static (string Cpp, (ulong Size, ulong Align)? Bytes)? MirrorType(Il2CppLayout layout, TypeSig sig)
    {
        sig = sig.RemovePinnedAndModifiers();
        if (sig is GenericVar v) return (TypeParameter((int)v.Number), null);
        var (cpp, isPointer, isStruct) = CppType(sig);
        if (!isStruct) return (isPointer ? "void*" : cpp, null);
        if (IsOpen(sig)) return null;
        var t = layout.TypeOf(sig);
        return t.Name.StartsWith("nd_u8 /*", StringComparison.Ordinal) ? null : ("", (t.Size, t.Align));
    }
}
