using System.Text;
using static NetDecompilerMcp.Native.Pdb.PdbTypeModel;

namespace NetDecompilerMcp.Native.Pdb;

/// <summary>
/// C declarations of a PDB's types for an engine without a PDB loader of its own: structs, classes and unions (data
/// members, base subobjects and the vftable pointer at the offsets the PDB records, bit fields, gaps padded), enums,
/// the S_UDT type names that differ from their tag (typedefs), and a prototype per procedure with an address.
/// Declared under <c>#pragma pack(push, 1)</c> with explicit padding, so every offset and size is the PDB's.
/// <see cref="Records"/>: type records read from the TPI stream; <see cref="Skipped"/>: members and records left out,
/// by reason (unsupported_leaf, overlapping_member, member_type_unwritable, ...).
/// </summary>
public sealed record PdbTypeDeclarations(
    string Declarations,
    IReadOnlyList<(uint Rva, string Declaration)> Prototypes,
    int Structs,
    int Unions,
    int Enums,
    int Typedefs,
    int Records,
    IReadOnlyDictionary<string, int> Skipped,
    IReadOnlyList<string> Notes);

/// <summary>Writes the types of a <see cref="PdbTypeModel"/> as C declarations.</summary>
public sealed class PdbTypes
{
    /// <summary>Most aggregates and prototypes written.</summary>
    public const int MaxAggregates = 60_000, MaxPrototypes = 300_000;

    private readonly PdbTypeModel _model;
    private readonly Dictionary<string, int> _skipped = [];
    private readonly List<string> _notes = [];

    private PdbTypes(PdbTypeModel model)
    {
        _model = model;
        _notes.AddRange(model.Notes);
    }

    /// <summary>
    /// The declarations for <paramref name="pdb"/> (read again from its file for the type streams); the image's
    /// pointer size decides simple pointer types. Malformed records are skipped and counted, never thrown.
    /// </summary>
    public static PdbTypeDeclarations Build(PdbFile pdb, int pointerSize, CancellationToken ct = default) =>
        new PdbTypes(PdbTypeModel.Read(pdb, pointerSize, ct)).Write(pdb, ct);

    private void Skip(string reason) => _skipped[reason] = _skipped.GetValueOrDefault(reason) + 1;

    private readonly Dictionary<uint, string> _identOf = [];
    private readonly HashSet<string> _idents = new(StringComparer.Ordinal);

    private static string Identifier(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (char c in name)
        {
            bool ok = char.IsAsciiLetterOrDigit(c) || c == '_';
            if (ok) sb.Append(c);
            else if (sb.Length > 0 && sb[^1] != '_') sb.Append('_');
        }
        var s = sb.ToString().TrimEnd('_');
        if (s.Length == 0) return "anon";
        if (char.IsAsciiDigit(s[0])) s = "_" + s;
        return Keywords.Contains(s) ? s + "_" : s;
    }

    /// <summary>C and C++ keywords and the engine's type words: not usable as names in a declaration.</summary>
    private static readonly HashSet<string> Keywords = new(StringComparer.Ordinal)
    {
        "alignas", "alignof", "and", "and_eq", "asm", "auto", "bitand", "bitor", "bool", "break", "case", "catch", "char", "char8_t", "char16_t",
        "char32_t", "class", "compl", "concept", "const", "consteval", "constexpr", "constinit", "const_cast", "continue", "co_await", "co_return",
        "co_yield", "decltype", "default", "delete", "do", "double", "dynamic_cast", "else", "enum", "explicit", "export", "extern", "false", "float",
        "for", "friend", "goto", "if", "inline", "int", "long", "mutable", "namespace", "new", "noexcept", "not", "not_eq", "nullptr", "operator",
        "or", "or_eq", "private", "protected", "public", "register", "reinterpret_cast", "requires", "restrict", "return", "short", "signed",
        "sizeof", "static", "static_assert", "static_cast", "struct", "switch", "template", "this", "thread_local", "throw", "true", "try",
        "typedef", "typeid", "typename", "union", "unsigned", "using", "virtual", "void", "volatile", "wchar_t", "while", "xor", "xor_eq",
        "_Bool", "_Complex", "_Imaginary", "_Alignas", "_Alignof", "_Atomic", "_Generic", "_Noreturn", "_Static_assert", "_Thread_local",
        "__int8", "__int16", "__int32", "__int64", "__int128", "__cdecl", "__stdcall", "__fastcall", "__thiscall", "__vectorcall", "__usercall",
        "__userpurge", "__pascal", "__ptr32", "__ptr64", "__unaligned", "__restrict", "__declspec", "__hidden", "__return_ptr", "__struct_ptr",
        "__array_ptr", "__spoils", "__shifted", "__near", "__far", "__huge", "__based", "__sptr", "__uptr", "__w64", "__int3264", "__export",
        "__import", "_BYTE", "_WORD", "_DWORD", "_QWORD", "_OWORD", "_TBYTE", "_UNKNOWN", "_BOOL1", "_BOOL2", "_BOOL4", "_BOOL8",
    };

    private string IdentOf(Aggregate a)
    {
        if (_identOf.TryGetValue(a.Index, out var id)) return id;
        var basis = Unnamed(a.Name) ? $"anon_{a.Index:X}" : Identifier(a.Name);
        id = basis;
        for (int i = 2; !_idents.Add(id); i++) id = $"{basis}_{i}";
        _identOf[a.Index] = id;
        return id;
    }

    private static string Join(string type, string declarator) => declarator.Length == 0 ? type : type.EndsWith('*') ? type + declarator : $"{type} {declarator}";

    /// <summary>
    /// <paramref name="declarator"/> declared with type <paramref name="index"/> ("int *x", "struct S (*p)[4]"); null
    /// when the type cannot be written (unsupported leaf, a struct without a definition used by value).
    /// <paramref name="thisName"/> names a member function's this parameter (prototypes only).
    /// </summary>
    private string? Declare(uint index, string declarator, int depth = 0, string? thisName = null)
    {
        if (depth > MaxDepth) return null;
        if (index < 0x1000)
        {
            uint mode = (index >> 8) & 0xF;
            var name = SimpleName(index & 0xFF);
            if (name == null) return index == 0 ? null : mode != 0 ? Join("void", "*" + declarator) : null;
            return mode != 0 ? Join(name, "*" + declarator) : Join(name, declarator);
        }
        if (!_model.TryGet(index, out var kind, out var d)) return null;
        switch (kind)
        {
            case LF_MODIFIER:
            {
                uint target = U32(d, 0);
                ushort attr = U16(d, 4);
                bool pointerTarget = target >= 0x1000 ? _model.TryGet(target, out var tk, out _) && tk == LF_POINTER : ((target >> 8) & 0xF) != 0;
                var inner = Declare(target, declarator, depth + 1);
                return inner == null || pointerTarget || (attr & 3) == 0 ? inner : ((attr & 1) != 0 ? "const " : "") + ((attr & 2) != 0 ? "volatile " : "") + inner;
            }
            case LF_POINTER:
            {
                uint attr = U32(d, 4);
                uint mode = (attr >> 5) & 7;
                if (mode is 2 or 3)
                {
                    // pointer to member: an integer of its size
                    long size = (attr >> 13) & 0x3F;
                    return size switch { 4 => Join("unsigned int", declarator), 8 => Join("unsigned __int64", declarator), _ => Join("unsigned char", $"{declarator}[{Math.Max(1, size)}]") };
                }
                return Declare(U32(d, 0), "*" + declarator, depth + 1) ?? Join("void", "*" + declarator);
            }
            case LF_ARRAY:
            {
                uint element = U32(d, 0);
                int at = 8;
                if (d.Length < 10 || !Numeric(d, ref at, out var bytes)) return null;
                long es = _model.SizeOf(element, depth + 1);
                if (es <= 0) return null;
                var inner = declarator.StartsWith('*') ? $"({declarator})" : declarator;
                return Declare(element, $"{inner}[{bytes / es}]", depth + 1);
            }
            case LF_CLASS or LF_STRUCTURE or LF_INTERFACE or LF_UNION or LF_CLASS2 or LF_STRUCTURE2 or LF_INTERFACE2 or LF_UNION2:
            {
                var a = _model.Definition(index) ?? _model.ReadAggregate(index);
                if (a == null) return null;
                if (_model.Definition(index) == null)
                {
                    // only a forward declaration: pointers to it work, values do not
                    if (!declarator.StartsWith('*')) return null;
                    return Join("void", declarator);
                }
                Use(a);
                return Join((a.IsUnion ? "union " : "struct ") + IdentOf(a), declarator);
            }
            case LF_ENUM:
            {
                var a = _model.Definition(index);
                if (a == null) return _model.SizeOf(index) is var s and > 0 ? Join(IntOfSize(s), declarator) : Join("int", declarator);
                Use(a);
                return Join("enum " + IdentOf(a), declarator);
            }
            case LF_PROCEDURE or LF_MFUNCTION:
            {
                bool member = kind == LF_MFUNCTION;
                uint ret = U32(d, 0);
                uint thisType = member ? U32(d, 8) : 0;
                byte cc = member ? (d.Length > 12 ? d[12] : (byte)0) : (d.Length > 4 ? d[4] : (byte)0);
                uint argList = member ? U32(d, 16) : U32(d, 8);
                var args = new List<string>();
                if (member && thisType != 0)
                    args.Add(Declare(thisType, thisName ?? "", depth + 1) ?? Join("void", "*" + (thisName ?? "")));
                if (_model.TryGet(argList, out var ak, out var ad) && ak == LF_ARGLIST)
                {
                    uint count = U32(ad, 0);
                    for (int i = 0; i < count && 4 + 4 * i + 4 <= ad.Length; i++)
                    {
                        uint t = U32(ad, 4 + 4 * i);
                        if (t == 0) { args.Add("..."); continue; }
                        args.Add(Declare(t, "", depth + 1) ?? (_model.SizeOf(t) is var s and > 0 ? IntOfSize(s) : "int"));
                    }
                }
                if (args.Count == 0) args.Add("void");
                // C has no "f(...)": an empty list leaves the arguments unspecified
                else if (args is ["..."]) args.Clear();
                var inner = declarator.StartsWith('*') ? $"({CallingConvention(cc)} {declarator})" : $"{CallingConvention(cc)} {declarator}".TrimEnd();
                return Declare(ret, $"{inner}({string.Join(", ", args)})", depth + 1) ?? Join("int", $"{inner}({string.Join(", ", args)})");
            }
            default:
                return null;
        }
    }

    private static string IntOfSize(long size) => size switch { 1 => "unsigned char", 2 => "unsigned short", 8 => "unsigned __int64", _ => "unsigned int" };

    private readonly HashSet<uint> _used = [];
    private readonly Queue<uint> _pending = new();

    private void Use(Aggregate a)
    {
        if (_used.Add(a.Index)) _pending.Enqueue(a.Index);
    }

    private sealed record Member(long Offset, string Name, uint Type, int BitLength = -1, int BitPosition = 0, bool Base = false);

    /// <summary>The data members, base subobjects and vftable pointer of a field list; unread members counted as skipped.</summary>
    private List<Member> Members(Aggregate a, out List<(string Name, long Value)> enumerators)
    {
        var skipped = new List<string>();
        var members = _model.Members(a, out var values, skipped);
        foreach (var reason in skipped) Skip(reason);
        enumerators = values.Select(e => (e.Name, e.Value)).ToList();
        return members.Where(m => m.Kind is PdbMemberKind.Data or PdbMemberKind.Base or PdbMemberKind.Vfptr)
            .Select(m => new Member(m.Offset, m.Name, m.Type, m.BitLength, m.BitPosition, m.Kind == PdbMemberKind.Base)).ToList();
    }

    /// <summary>The body of a struct or union, its by-value dependencies collected into <paramref name="needs"/>.</summary>
    private string? Body(Aggregate a, HashSet<uint> needs)
    {
        var members = Members(a, out _);
        var sb = new StringBuilder();
        var names = new HashSet<string>(StringComparer.Ordinal);
        string Unique(string name)
        {
            var basis = Unnamed(name) || name.Length == 0 ? "field" : Identifier(name);
            var n = basis;
            for (int i = 2; !names.Add(n); i++) n = $"{basis}_{i}";
            return n;
        }
        void Need(uint type)
        {
            // the aggregate a member holds by value (through modifiers and arrays)
            for (int depth = 0; depth < MaxDepth && type >= 0x1000 && _model.TryGet(type, out var k, out var d); depth++)
            {
                if (k == LF_MODIFIER) type = U32(d, 0);
                else if (k == LF_ARRAY) type = U32(d, 0);
                else
                {
                    if (_model.Definition(type) is { IsEnum: false } def) needs.Add(def.Index);
                    return;
                }
            }
        }
        string Plain(Member m, string name)
        {
            var decl = Declare(m.Type, name);
            if (decl != null) { Need(m.Type); return decl; }
            Skip("member_type_unwritable");
            long size = _model.SizeOf(m.Type);
            return size > 0 ? $"unsigned char {name}[{size}]" : $"unsigned char {name}[1]";
        }

        if (a.IsUnion)
        {
            long largest = 0;
            foreach (var m in members.Where(m => m.Offset == 0))
            {
                if (m.BitLength >= 0)
                {
                    sb.Append("  ").Append(Declare(m.Type, "") ?? "unsigned int").Append(' ').Append(Unique(m.Name)).Append(" : ").Append(m.BitLength).Append(";\n");
                    largest = Math.Max(largest, _model.SizeOf(m.Type));
                    continue;
                }
                sb.Append("  ").Append(Plain(m, Unique(m.Name))).Append(";\n");
                largest = Math.Max(largest, _model.SizeOf(m.Type));
            }
            if (members.Any(m => m.Offset != 0)) Skip("overlapping_member");
            if (a.Size > largest) sb.Append($"  unsigned char __size[{a.Size}];\n");
            return sb.Length == 0 ? null : sb.ToString();
        }

        long end = 0;
        int pad = 0;
        var ordered = members.Select((m, i) => (m, i)).OrderBy(x => x.m.Offset).ThenBy(x => x.i).Select(x => x.m).ToList();
        for (int i = 0; i < ordered.Count; i++)
        {
            var m = ordered[i];
            if (m.Offset < end || m.Offset < 0) { Skip("overlapping_member"); continue; }
            if (m.Offset > end) sb.Append($"  unsigned char __pad{pad++}[{m.Offset - end}];\n");
            if (m.BitLength >= 0)
            {
                // the bit fields sharing this storage unit, in bit order, unused bits as unnamed fields
                long unitSize = _model.SizeOf(m.Type);
                if (unitSize <= 0) { Skip("member_type_unwritable"); continue; }
                var unitType = Declare(m.Type, "") ?? IntOfSize(unitSize);
                int bit = 0;
                var group = ordered.Skip(i).TakeWhile(x => x.Offset == m.Offset && x.BitLength >= 0 && x.Type == m.Type).OrderBy(x => x.BitPosition).ToList();
                foreach (var f in group)
                {
                    if (f.BitPosition < bit) { Skip("overlapping_member"); continue; }
                    if (f.BitPosition > bit) sb.Append($"  {unitType} : {f.BitPosition - bit};\n");
                    sb.Append($"  {unitType} {Unique(f.Name)} : {f.BitLength};\n");
                    bit = f.BitPosition + f.BitLength;
                }
                if (bit < unitSize * 8) sb.Append($"  {unitType} : {unitSize * 8 - bit};\n");
                i += group.Count - 1;
                end = m.Offset + unitSize;
                continue;
            }
            long size = _model.SizeOf(m.Type);
            if (size < 0) { Skip("member_type_unwritable"); continue; }
            // a zero-length array is only valid as the last member
            if (size == 0 && m.Offset < a.Size) { Skip("zero_size_member"); continue; }
            sb.Append("  ").Append(Plain(m, Unique(m.Name))).Append(";\n");
            end = m.Offset + size;
        }
        if (a.Size > end) sb.Append($"  unsigned char __pad{pad}[{a.Size - end}];\n");
        return sb.Length == 0 ? null : sb.ToString();
    }

    private string EnumBody(Aggregate a, HashSet<string> enumerators)
    {
        Members(a, out var values);
        var sb = new StringBuilder();
        var id = IdentOf(a);
        foreach (var (name, value) in values)
        {
            // enumerator names are global in C: a clash takes the enum's name as prefix
            var n = Identifier(name);
            if (!enumerators.Add(n)) { n = $"{id}__{n}"; if (!enumerators.Add(n)) continue; }
            sb.Append($"  {n} = {value},\n");
        }
        return sb.ToString();
    }

    private PdbTypeDeclarations Write(PdbFile pdb, CancellationToken ct)
    {
        // prototypes of the procedures with addresses
        var prototypes = new List<(uint, string)>();
        var done = new HashSet<uint>();
        foreach (var s in pdb.Symbols)
        {
            if (s.Kind is not (PdbSymbolKind.GlobalProc or PdbSymbolKind.LocalProc) || s.Rva is not { } rva || s.TypeIndex == 0 || !done.Add(rva)) continue;
            if (prototypes.Count >= MaxPrototypes) { _notes.Add($"prototypes beyond {MaxPrototypes:N0} are not written"); break; }
            uint type = _model.FunctionTypeOf(s.TypeIndex);
            if (type == 0) { Skip("prototype_not_a_function_type"); continue; }
            var decl = Declare(type, "f", thisName: "this");
            if (decl == null) { Skip("prototype_unwritable"); continue; }
            prototypes.Add((rva, decl + ";"));
        }

        // S_UDT names: tags are emitted as used, names differing from their tag become typedefs
        var typedefs = new List<string>();
        foreach (var t in pdb.Typedefs)
        {
            if (typedefs.Count >= MaxAggregates) break;
            if (t.TypeIndex >= 0x1000 && _model.Definition(t.TypeIndex) is { } a && !Unnamed(a.Name) && Identifier(t.Name) == Identifier(a.Name))
            {
                if (_used.Count < MaxAggregates) Use(a);
                continue;
            }
            var name = Identifier(t.Name);
            if (!_idents.Add(name)) continue;
            var decl = Declare(t.TypeIndex, name);
            if (decl == null) { _idents.Remove(name); Skip("typedef_unwritable"); continue; }
            typedefs.Add($"typedef {decl};");
        }

        // bodies of every aggregate used (a body can use more)
        var bodies = new Dictionary<uint, (string Text, HashSet<uint> Needs)>();
        var enums = new List<string>();
        var enumerators = new HashSet<string>(StringComparer.Ordinal);
        int structs = 0, unions = 0;
        while (_pending.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var a = _model.ReadAggregate(_pending.Dequeue())!;
            if (bodies.Count + enums.Count >= MaxAggregates) { _notes.Add($"types beyond {MaxAggregates:N0} are declared without members"); break; }
            if (a.IsEnum)
            {
                var underlying = Declare(a.Underlying, "") ?? "int";
                enums.Add($"enum {IdentOf(a)} : {underlying}\n{{\n{EnumBody(a, enumerators)}}};");
                continue;
            }
            var needs = new HashSet<uint>();
            var body = Body(a, needs);
            if (body == null) continue;
            bodies[a.Index] = (body, needs);
            if (a.IsUnion) unions++;
            else structs++;
        }

        // forward declarations, enums, then bodies with what they hold by value first
        var sb = new StringBuilder("#pragma pack(push, 1)\n");
        foreach (var index in _used)
            if (_model.ReadAggregate(index) is { IsEnum: false } a) sb.Append(a.IsUnion ? "union " : "struct ").Append(IdentOf(a)).Append(";\n");
        foreach (var e in enums) sb.Append(e).Append('\n');
        var emitted = new HashSet<uint>();
        var visiting = new HashSet<uint>();
        void Emit(uint index, int depth)
        {
            if (emitted.Contains(index) || !bodies.TryGetValue(index, out var b) || !visiting.Add(index)) return;
            // nesting by value deeper than this is not real code: the rest of the chain follows in table order
            if (depth < 256)
                foreach (var n in b.Needs) Emit(n, depth + 1);
            visiting.Remove(index);
            emitted.Add(index);
            var a = _model.ReadAggregate(index)!;
            sb.Append(a.IsUnion ? "union " : "struct ").Append(IdentOf(a)).Append("\n{\n").Append(b.Text).Append("};\n");
        }
        foreach (var index in bodies.Keys) Emit(index, 0);
        foreach (var t in typedefs) sb.Append(t).Append('\n');
        sb.Append("#pragma pack(pop)\n");
        return new PdbTypeDeclarations(sb.ToString(), prototypes, structs, unions, enums.Count, typedefs.Count, _model.Records,
            new Dictionary<string, int>(_skipped), _notes);
    }
}
