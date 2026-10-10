using System.Text;
using dnlib.DotNet;
using NetDecompilerMcp.Core;
using static NetDecompilerMcp.Core.MetadataUtil;

namespace NetDecompilerMcp.Services;

/// <summary>
/// C layouts of Il2Cpp types (64-bit): the dumped offsets where the dummy DLLs have them, and for instances of generic
/// types, whose definitions are dumped with offset 0, the fields of the instantiation laid out in declaration order at
/// their natural alignment, as Il2Cpp lays them out, after the base type's fields. A dumped offset wins over a computed
/// one. Structs are created on demand and listed with the structs they embed first.
/// </summary>
internal sealed class Il2CppLayout
{
    public const ulong PointerSize = 8;
    public const ulong ObjectHeader = 0x10;

    /// <summary>A C member: <see cref="Count"/> elements of <see cref="CType"/> when it is a fixed buffer. <see cref="Computed"/>: laid out here, not dumped.</summary>
    public sealed record Member(string Name, string Owner, ulong Offset, string CType, ulong Size, ulong Align, string Managed, bool Computed, ulong Count = 0);

    public sealed class Struct(string cname, string title, bool isValueType, bool statics)
    {
        public string CName { get; } = cname;
        /// <summary>The static fields of a type, at offsets in its static data.</summary>
        public bool Statics { get; } = statics;
        /// <summary>The managed type, as the comment above the struct.</summary>
        public string Title { get; } = title;
        public bool IsValueType { get; } = isValueType;
        public List<Member> Members { get; } = new();
        public ulong Size { get; set; }
        public ulong Align { get; set; } = 1;
    }

    /// <summary>A C type with its size and alignment.</summary>
    public readonly record struct CType(string Name, ulong Size, ulong Align);

    private readonly Dictionary<(TypeDef Type, string Args, bool Statics), Struct?> _structs = new();
    private readonly HashSet<(TypeDef, string, bool)> _building = new();
    private readonly HashSet<string> _names = new(StringComparer.Ordinal);
    private readonly List<Struct> _ordered = new();

    /// <summary>Every struct created so far, each after the structs it embeds.</summary>
    public IReadOnlyList<Struct> Structs => _ordered;

    /// <summary>The instance layout of a type definition that is not generic; null for an open generic definition or a class without fields.</summary>
    public Struct? Of(TypeDef type) => type.HasGenericParameters || IsInGenericType(type) ? null : Of(type, null, statics: false);

    /// <summary>The static fields of a type definition that is not generic, at their dumped offsets in the type's static data.</summary>
    public Struct? StaticsOf(TypeDef type) => type.HasGenericParameters || IsInGenericType(type) ? null : Of(type, null, statics: true);

    /// <summary>The C type of a field, parameter or return value; value types are embedded, references are pointers.</summary>
    public CType TypeOf(TypeSig sig)
    {
        sig = sig.RemovePinnedAndModifiers();
        switch (sig.ElementType)
        {
            case ElementType.Boolean: case ElementType.U1: return new("nd_u8", 1, 1);
            case ElementType.I1: return new("nd_i8", 1, 1);
            case ElementType.Char: case ElementType.U2: return new("nd_u16", 2, 2);
            case ElementType.I2: return new("nd_i16", 2, 2);
            case ElementType.I4: return new("nd_i32", 4, 4);
            case ElementType.U4: return new("nd_u32", 4, 4);
            case ElementType.I8: return new("nd_i64", 8, 8);
            case ElementType.U8: return new("nd_u64", 8, 8);
            case ElementType.R4: return new("float", 4, 4);
            case ElementType.R8: return new("double", 8, 8);
            case ElementType.ByRef: return new(TypeOf(sig.Next).Name + "*", PointerSize, PointerSize);
        }
        // The dumpers write type arguments as classes whatever they are: the definition tells a value type.
        if (sig is TypeDefOrRefSig tr && Try(() => tr.TypeDefOrRef.ResolveTypeDef()) is { IsValueType: true } td)
        {
            if (td.IsEnum && td.GetEnumUnderlyingType() is { } underlying) return TypeOf(underlying);
            if (td.Namespace == "System" && Primitive(td.Name) is { } primitive) return primitive;
            if (!td.HasGenericParameters && Of(td, null, statics: false) is { } s) return new($"struct {s.CName}", s.Size, s.Align);
            return new($"nd_u8 /* {td.Name} */", 1, 1);
        }
        if (sig is ValueTypeSig unresolved) return new($"nd_u8 /* {unresolved.TypeName} */", 1, 1);
        if (sig is GenericInstSig gi && Try(() => gi.GenericType.TypeDefOrRef.ResolveTypeDef()) is { IsValueType: true } def)
        {
            if (gi.GenericArguments.All(IsClosed) && Of(def, gi.GenericArguments, statics: false) is { } s)
                return new($"struct {s.CName}", s.Size, s.Align);
            return new($"nd_u8 /* {Format.Type(gi)} */", 1, 1);
        }
        if (sig is GenericInstSig { GenericType: ValueTypeSig }) return new($"nd_u8 /* {Format.Type(sig)} */", 1, 1);
        // Classes, strings, arrays, interfaces, delegates, generic class instances, native ints and pointers; a type
        // parameter stands for a reference in the shared code the dummy's address belongs to.
        return new("nd_ptr", PointerSize, PointerSize);
    }

    private Struct? Of(TypeDef type, IList<TypeSig>? args, bool statics)
    {
        var key = (type, args == null ? "" : string.Join(",", args.Select(a => a.FullName)), statics);
        if (_structs.TryGetValue(key, out var done)) return done;
        if (!_building.Add(key)) return null; // a value type that embeds itself is invalid metadata
        try
        {
            var s = Build(type, args, statics);
            _structs[key] = s;
            if (s != null) _ordered.Add(s);
            return s;
        }
        finally
        {
            _building.Remove(key);
        }
    }

    private Struct? Build(TypeDef type, IList<TypeSig>? args, bool statics)
    {
        bool valueType = type.IsValueType && !statics;
        var title = args == null ? type.FullName : $"{type.FullName}<{string.Join(", ", args.Select(Format.Type))}>";
        var members = new List<Member>();
        if (statics)
        {
            foreach (var f in type.Fields.Where(f => f.IsStatic && !f.IsLiteral))
                if (OffsetOf(f) is { } offset && offset < 0x8000_0000 && !IsThreadStatic(f))
                    members.Add(Place(f, f.FieldType, offset, computed: false));
            if (members.Count == 0) return null;
        }
        else
        {
            ulong position = valueType ? 0 : ObjectHeader;
            foreach (var (level, levelArgs) in valueType ? [(type, args)] : Chain(type, args))
            {
                // A class's fields start at its base's size rounded up to the pointer size.
                if (!valueType) position = AlignUp(position, PointerSize);
                foreach (var f in level.Fields.Where(f => !f.IsStatic && !f.IsLiteral))
                {
                    if (levelArgs != null)
                    {
                        var m = Place(f, Substitute(f.FieldType, levelArgs), AlignUp(position, FieldType(f, Substitute(f.FieldType, levelArgs), out _).Align), computed: true);
                        members.Add(m);
                        position = m.Offset + m.Size;
                    }
                    else if (OffsetOf(f) is { } offset)
                    {
                        var m = Place(f, f.FieldType, offset, computed: false);
                        members.Add(m);
                        position = Math.Max(position, offset + m.Size);
                    }
                }
            }
            if (members.Count == 0 && !valueType) return null;
        }

        var s = new Struct(UniqueName(statics ? Identifier(title) + "_StaticFields" : Identifier(title)), title + (statics ? " (static fields)" : ""), valueType, statics);
        // Dumped offsets are the runtime's: a computed member that overlaps one gives way; then the first of two that overlap stays.
        var dumped = members.Where(m => !m.Computed).ToList();
        ulong end = 0;
        foreach (var m in members.Where(m => !m.Computed || !dumped.Any(d => d.Offset < m.Offset + m.Size && m.Offset < d.Offset + d.Size))
                     .OrderBy(m => m.Offset).ThenBy(m => m.Computed))
        {
            if (m.Offset < end) continue;
            s.Members.Add(m);
            end = m.Offset + m.Size;
            s.Align = Math.Max(s.Align, m.Align);
        }
        // An overlapped field (explicit layout: a ulong over two ints) still aligns the struct.
        foreach (var m in dumped) s.Align = Math.Max(s.Align, m.Align);
        s.Size = valueType ? Math.Max(AlignUp(end, s.Align), Math.Max(args == null ? type.ClassLayout?.ClassSize ?? 0 : 0, 1)) : end;
        return s;
    }

    private Member Place(FieldDef f, TypeSig sig, ulong offset, bool computed)
    {
        var t = FieldType(f, sig, out ulong count);
        return new Member(f.Name, f.DeclaringType.Name, offset, t.Name, count == 0 ? t.Size : t.Size * count, t.Align, Format.Type(sig), computed, count);
    }

    /// <summary>
    /// The C type of a field; for a fixed buffer (<c>fixed byte b[576]</c>, whose nested struct the dummy DLLs declare with
    /// one element), the element type, with the element count.
    /// </summary>
    private CType FieldType(FieldDef f, TypeSig sig, out ulong count)
    {
        count = 0;
        var buffer = f.CustomAttributes.FirstOrDefault(a => a.TypeFullName == "System.Runtime.CompilerServices.FixedBufferAttribute");
        if (buffer is { ConstructorArguments: [{ Value: TypeSig element }, { Value: int length }] } && length > 0)
        {
            var t = TypeOf(element);
            if (!t.Name.StartsWith("struct ", StringComparison.Ordinal) && !t.Name.StartsWith("nd_u8 /*", StringComparison.Ordinal))
            {
                count = (ulong)length;
                return t;
            }
        }
        return TypeOf(sig);
    }

    /// <summary>Base classes first, each with the type arguments of the instance the derived class extends (null: not generic).</summary>
    private static List<(TypeDef Type, IList<TypeSig>? Args)> Chain(TypeDef type, IList<TypeSig>? args)
    {
        var chain = new List<(TypeDef, IList<TypeSig>?)>();
        TypeDef? t = type;
        var a = args;
        while (t != null && chain.Count < 32)
        {
            chain.Add((t, a));
            if (t.BaseType is TypeSpec { TypeSig: GenericInstSig baseInst })
            {
                var substituted = baseInst.GenericArguments.Select(g => a == null ? g : Substitute(g, a)).ToList();
                t = Try(() => baseInst.GenericType.TypeDefOrRef.ResolveTypeDef());
                a = substituted.All(IsClosed) ? substituted : null;
                if (a == null) break; // a base instance over the derived type's own parameters: an open definition
            }
            else
            {
                t = BaseTypeDef(t);
                a = null;
            }
        }
        chain.Reverse();
        return chain;
    }

    /// <summary>Type parameters of the type replaced by <paramref name="args"/>.</summary>
    private static TypeSig Substitute(TypeSig sig, IList<TypeSig> args)
    {
        sig = sig.RemovePinnedAndModifiers();
        return sig switch
        {
            GenericVar v => v.Number < args.Count ? args[(int)v.Number] : sig,
            GenericInstSig gi => new GenericInstSig(gi.GenericType, gi.GenericArguments.Select(g => Substitute(g, args)).ToList()),
            SZArraySig sz => new SZArraySig(Substitute(sz.Next, args)),
            ByRefSig r => new ByRefSig(Substitute(r.Next, args)),
            PtrSig p => new PtrSig(Substitute(p.Next, args)),
            _ => sig,
        };
    }

    private static bool IsClosed(TypeSig sig) => sig.RemovePinnedAndModifiers() switch
    {
        GenericVar or GenericMVar => false,
        GenericInstSig gi => gi.GenericArguments.All(IsClosed),
        { Next: { } next } => IsClosed(next),
        _ => true,
    };

    private static bool IsInGenericType(TypeDef t)
    {
        for (var d = t.DeclaringType; d != null; d = d.DeclaringType)
            if (d.HasGenericParameters) return true;
        return false;
    }

    private static bool IsThreadStatic(FieldDef f) => f.CustomAttributes.Any(a => a.TypeFullName == "System.ThreadStaticAttribute");

    public static ulong? OffsetOf(FieldDef f)
    {
        var attr = Il2CppService.GetAttributes(f).FirstOrDefault(a => a.Name == "FieldOffsetAttribute");
        return attr != null && attr.Values.TryGetValue("Offset", out var v) ? Il2CppService.ParseNumber(v) : null;
    }

    private static CType? Primitive(string name) => name switch
    {
        "Boolean" or "Byte" => new("nd_u8", 1, 1), "SByte" => new("nd_i8", 1, 1), "Char" or "UInt16" => new("nd_u16", 2, 2),
        "Int16" => new("nd_i16", 2, 2), "Int32" => new("nd_i32", 4, 4), "UInt32" => new("nd_u32", 4, 4), "Int64" => new("nd_i64", 8, 8),
        "UInt64" => new("nd_u64", 8, 8), "Single" => new("float", 4, 4), "Double" => new("double", 8, 8),
        "IntPtr" or "UIntPtr" => new("nd_ptr", PointerSize, PointerSize),
        _ => null,
    };

    private static ulong AlignUp(ulong value, ulong align) => align <= 1 ? value : (value + align - 1) / align * align;

    private string UniqueName(string name)
    {
        var unique = name;
        for (int i = 2; !_names.Add(unique); i++) unique = $"{name}_{i}";
        return unique;
    }

    /// <summary>Microsoft-extension and C11 spellings that IDA's and MSVC-compatible parsers treat as keywords.</summary>
    private static readonly System.Text.RegularExpressions.Regex ReservedSpelling = new(
        "^_+(int8|int16|int32|int64|ptr32|ptr64|w64|asm|cdecl|stdcall|fastcall|thiscall|vectorcall|declspec|inline|forceinline|based|unaligned|restrict|" +
        "Bool|Complex|Imaginary|Alignas|Alignof|Atomic|Generic|Noreturn|Static_assert|Thread_local|far|near|huge|pascal|fortran|segment|self|try|except|finally|leave)$",
        System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>Keywords of C and C++ (the header is also included from C++), and GNU C's asm / typeof.</summary>
    private static readonly HashSet<string> Keywords = new(StringComparer.Ordinal)
    {
        "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum", "extern", "float", "for", "goto", "if",
        "inline", "int", "long", "register", "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
        "unsigned", "void", "volatile", "while", "asm", "typeof", "alignas", "alignof", "and", "and_eq", "bitand", "bitor", "bool", "catch", "char8_t",
        "char16_t", "char32_t", "class", "compl", "concept", "consteval", "constexpr", "constinit", "const_cast", "co_await", "co_return", "co_yield",
        "decltype", "delete", "dynamic_cast", "explicit", "export", "false", "friend", "mutable", "namespace", "new", "noexcept", "not", "not_eq",
        "nullptr", "operator", "or", "or_eq", "private", "protected", "public", "reinterpret_cast", "requires", "static_assert", "static_cast",
        "template", "this", "thread_local", "throw", "true", "try", "typeid", "typename", "using", "virtual", "wchar_t", "xor", "xor_eq",
    };

    public static string Identifier(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (char c in name) sb.Append(char.IsLetterOrDigit(c) || c == '_' ? c : '_');
        var s = sb.ToString();
        if (s.Length == 0 || char.IsDigit(s[0])) s = "_" + s;
        if (ReservedSpelling.IsMatch(s) || s.StartsWith("__", StringComparison.Ordinal)) s = "f" + s;
        return Keywords.Contains(s) ? s + "_" : s;
    }
}
