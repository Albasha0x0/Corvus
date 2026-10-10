using System.Buffers.Binary;
using System.Text;

namespace NetDecompilerMcp.Native.NativeAot;

/// <summary>Malformed NativeAOT data; stages catch it and report themselves partial or absent.</summary>
public sealed class NativeAotFormatException(string message) : Exception(message);

/// <summary>A metadata handle: record kind and offset of the record in the metadata blob.</summary>
public readonly record struct MdHandle(MdRecord Record, uint Offset)
{
    public bool IsNull => Record == MdRecord.Null || Offset == 0;
}

/// <summary>A method name recovered from metadata; <see cref="Full"/> is "Ns.Type::Name&lt;inst&gt;(params)".</summary>
public sealed record NativeAotMethodName(string Owner, string Name, string? Signature = null, string? Instantiation = null)
{
    public string Full => $"{Owner}::{Name}{Instantiation}{Signature}";
    public string Short => $"{Owner}::{Name}{Instantiation}";
}

/// <summary>
/// Reader of the NativeFormat metadata blob of a NativeAOT image (EmbeddedMetadata, header 0xDEADDFFD then the
/// ScopeDefinition collection). Records are sequences of NativeFormat integers in schema order
/// (<see cref="NativeAotSchema"/>); the handle encodings follow <see cref="MetadataDialect"/>. Every read is bounds-checked;
/// malformed data throws <see cref="NativeAotFormatException"/>. Thread-safe.
/// </summary>
public sealed class NativeAotMetadata
{
    public const uint Signature = 0xDEADDFFD;
    private const int MaxDepth = 24;
    private readonly byte[] data;
    private readonly MetadataDialect dialect;
    private readonly int recordTypeBits;
    private readonly int tokenShift;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<MdHandle, string> typeNames = [];
    private readonly Lazy<Dictionary<uint, uint>> methodOwners;

    public NativeAotMetadata(byte[] blob, NativeAotFormat format)
    {
        data = blob;
        dialect = format.Metadata;
        recordTypeBits = format.RecordHandleTypeBits;
        tokenShift = format.TokenShift;
        if (blob.Length < 5 || BinaryPrimitives.ReadUInt32LittleEndian(blob) != Signature)
            throw new NativeAotFormatException("the metadata blob does not start with the NativeFormat signature 0xDEADDFFD");
        uint at = 4;
        ScopeDefinitions = ReadOffsets(ref at);
        methodOwners = new(IndexMethods);
    }

    public int Size => data.Length;
    public MetadataDialect Dialect => dialect;
    public IReadOnlyList<uint> ScopeDefinitions { get; }

    // ---- primitives ----

    private byte U8(uint at) => at < data.Length ? data[at] : throw Outside(at);

    private NativeAotFormatException Outside(uint at) => new($"metadata read at offset 0x{at:X} is past the end of the {data.Length}-byte blob");

    internal uint DecodeUnsigned(ref uint at)
    {
        uint b = U8(at);
        uint value;
        if ((b & 1) == 0) { value = b >> 1; at += 1; }
        else if ((b & 2) == 0) { value = (b >> 2) | ((uint)U8(at + 1) << 6); at += 2; }
        else if ((b & 4) == 0) { value = (b >> 3) | ((uint)U8(at + 1) << 5) | ((uint)U8(at + 2) << 13); at += 3; }
        else if ((b & 8) == 0) { value = (b >> 4) | ((uint)U8(at + 1) << 4) | ((uint)U8(at + 2) << 12) | ((uint)U8(at + 3) << 20); at += 4; }
        else if ((b & 16) == 0) { value = (uint)(U8(at + 1) | U8(at + 2) << 8 | U8(at + 3) << 16 | U8(at + 4) << 24); at += 5; }
        else throw new NativeAotFormatException($"bad NativeFormat integer at metadata offset 0x{at:X}");
        return value;
    }

    internal int DecodeSigned(ref uint at)
    {
        int b = U8(at);
        int value;
        if ((b & 1) == 0) { value = (sbyte)b >> 1; at += 1; }
        else if ((b & 2) == 0) { value = (b >> 2) | ((sbyte)U8(at + 1) << 6); at += 2; }
        else if ((b & 4) == 0) { value = (b >> 3) | (U8(at + 1) << 5) | ((sbyte)U8(at + 2) << 13); at += 3; }
        else if ((b & 8) == 0) { value = (b >> 4) | (U8(at + 1) << 4) | (U8(at + 2) << 12) | ((sbyte)U8(at + 3) << 20); at += 4; }
        else if ((b & 16) == 0) { value = U8(at + 1) | U8(at + 2) << 8 | U8(at + 3) << 16 | U8(at + 4) << 24; at += 5; }
        else throw new NativeAotFormatException($"bad NativeFormat integer at metadata offset 0x{at:X}");
        return value;
    }

    private uint Count(ref uint at, int elementSize)
    {
        uint count = DecodeUnsigned(ref at);
        if ((ulong)count * (uint)Math.Max(1, elementSize) > (ulong)(data.Length - Math.Min(at, (uint)data.Length)))
            throw new NativeAotFormatException($"collection of {count} elements at metadata offset 0x{at:X} exceeds the blob");
        return count;
    }

    private List<uint> ReadOffsets(ref uint at)
    {
        uint count = Count(ref at, 1);
        var list = new List<uint>((int)count);
        for (uint i = 0; i < count; i++) list.Add(DecodeUnsigned(ref at));
        return list;
    }

    private void Skip(char code, ref uint at)
    {
        switch (code)
        {
            case 'h' or 't' or 'u' or 'i':
                DecodeUnsigned(ref at);
                break;
            case 'l' or 'j':
                if ((U8(at) & 31) == 31) at += 9;
                else DecodeUnsigned(ref at);
                break;
            case 'b': at += 1; break;
            case 'f': at += 4; break;
            case 'd': at += 8; break;
            case 's':
                uint n = Count(ref at, 1);
                at += n;
                break;
            case 'c':
                uint items = Count(ref at, 1);
                for (uint i = 0; i < items; i++) DecodeUnsigned(ref at);
                break;
            default:
                int size = code - '0';
                uint elements = Count(ref at, size);
                at += elements * (uint)size;
                break;
        }
    }

    // ---- handles and fields ----

    /// <summary>A handle stored inside a record: type in the low <see cref="NativeAotFormat.RecordHandleTypeBits"/> bits.</summary>
    public MdHandle RecordHandle(uint raw)
    {
        uint type = raw & ((1u << recordTypeBits) - 1);
        return new MdHandle(NativeAotSchema.RecordOf(dialect, type) ?? throw new NativeAotFormatException($"unknown metadata handle type {type}"), raw >> recordTypeBits);
    }

    /// <summary>A full metadata token (type &lt;&lt; <see cref="NativeAotFormat.TokenShift"/> | offset), as stack-trace and type maps store them.</summary>
    public MdHandle FromToken(uint token)
    {
        uint type = token >> tokenShift;
        return new MdHandle(NativeAotSchema.RecordOf(dialect, type) ?? throw new NativeAotFormatException($"unknown metadata token type {type}"), token & ((1u << tokenShift) - 1));
    }

    /// <summary>Start of <paramref name="field"/> of the record at <paramref name="record"/>.</summary>
    private uint FieldAt(MdHandle record, int index, out char code)
    {
        var layout = NativeAotSchema.For(dialect, record.Record);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, layout.Codes.Length);
        uint at = record.Offset;
        for (int i = 0; i < index; i++) Skip(layout.Codes[i], ref at);
        code = layout.Codes[index];
        return at;
    }

    private int Index(MdHandle record, string field) => NativeAotSchema.For(dialect, record.Record).Index(field);

    public MdHandle Handle(MdHandle record, string field) => Handle(record, Index(record, field));

    public MdHandle Handle(MdHandle record, int index)
    {
        uint at = FieldAt(record, index, out char code);
        uint raw = DecodeUnsigned(ref at);
        return code == 'h' ? RecordHandle(raw) : throw new ArgumentException($"{record.Record} field {index} is not a handle");
    }

    /// <summary>The offset of a fixed-kind handle field (0 when null).</summary>
    public uint Ref(MdHandle record, string field)
    {
        uint at = FieldAt(record, Index(record, field), out char code);
        return code is 't' or 'u' ? DecodeUnsigned(ref at) : throw new ArgumentException($"{record.Record}.{field} is not a reference");
    }

    public int Int(MdHandle record, string field)
    {
        uint at = FieldAt(record, Index(record, field), out char code);
        return code == 'i' ? DecodeSigned(ref at) : (int)DecodeUnsigned(ref at);
    }

    /// <summary>The raw integers of a handle collection: offsets for fixed-kind handles, encoded handles otherwise.</summary>
    public List<uint> Collection(MdHandle record, string field)
    {
        uint at = FieldAt(record, Index(record, field), out char code);
        return code == 'c' ? ReadOffsets(ref at) : throw new ArgumentException($"{record.Record}.{field} is not a collection");
    }

    public List<MdHandle> Handles(MdHandle record, string field) => [.. Collection(record, field).Select(RecordHandle)];

    /// <summary>The text of the ConstantStringValue at <paramref name="offset"/>; null for offset 0.</summary>
    public string? String(uint offset)
    {
        if (offset == 0) return null;
        uint at = offset;
        uint n = Count(ref at, 1);
        return Encoding.UTF8.GetString(data, (int)at, (int)n);
    }

    public string? StringField(MdHandle record, string field) => String(Ref(record, field));

    // ---- names ----

    /// <summary>"Ns.Outer+Inner`1" for definitions and references, "Gen&lt;int, Ns.T&gt;" for instantiations, "T[]", "T*", "T&amp;".</summary>
    public string FormatType(MdHandle handle) => FormatType(handle, 0, keywords: false);

    private string FormatType(MdHandle h, int depth, bool keywords)
    {
        if (h.IsNull) return "?";
        if (depth > MaxDepth) return "…";
        if (!keywords && typeNames.TryGetValue(h, out var cached)) return cached;
        string name = h.Record switch
        {
            MdRecord.TypeDefinition => DefinitionName(h, depth),
            MdRecord.TypeReference => ReferenceName(h, depth),
            MdRecord.TypeSpecification => FormatType(Handle(h, "signature"), depth + 1, keywords),
            MdRecord.TypeInstantiationSignature => InstantiationName(h, depth),
            MdRecord.SZArraySignature => FormatType(Handle(h, "elementType"), depth + 1, true) + "[]",
            MdRecord.ArraySignature => FormatType(Handle(h, "elementType"), depth + 1, true) + "[" + new string(',', Math.Clamp(Int(h, "rank") - 1, 0, 31)) + "]",
            MdRecord.PointerSignature => FormatType(Handle(h, "type"), depth + 1, true) + "*",
            MdRecord.ByReferenceSignature => FormatType(Handle(h, "type"), depth + 1, true) + "&",
            MdRecord.ModifiedType => FormatType(Handle(h, "type"), depth + 1, keywords),
            MdRecord.FunctionPointerSignature => "delegate*" + FunctionPointer(Ref(h, "signature"), depth),
            MdRecord.TypeVariableSignature => "!" + Int(h, "number"),
            MdRecord.MethodTypeVariableSignature => "!!" + Int(h, "number"),
            _ => $"<{h.Record}>",
        };
        if (keywords) return Keyword(name);
        typeNames[h] = name;
        return name;
    }

    private string DefinitionName(MdHandle h, int depth)
    {
        string name = StringField(h, "name") ?? "?";
        if (dialect == MetadataDialect.Net11)
        {
            var parent = Handle(h, "namespaceOrEnclosingType");
            return parent.Record == MdRecord.TypeDefinition ? FormatType(parent, depth + 1, false) + "+" + name : Qualify(parent, name, depth);
        }
        uint enclosing = Ref(h, "enclosingType");
        if (enclosing != 0) return FormatType(new MdHandle(MdRecord.TypeDefinition, enclosing), depth + 1, false) + "+" + name;
        return Qualify(new MdHandle(MdRecord.NamespaceDefinition, Ref(h, "namespaceDefinition")), name, depth);
    }

    private string ReferenceName(MdHandle h, int depth)
    {
        string name = String(Ref(h, NativeAotSchema.For(dialect, MdRecord.TypeReference).FieldNames[1])) ?? "?";
        var parent = Handle(h, 0);
        return parent.Record is MdRecord.TypeReference or MdRecord.TypeDefinition
            ? FormatType(parent, depth + 1, false) + "+" + name
            : Qualify(parent, name, depth);
    }

    /// <summary>Prefixes the namespace chain of <paramref name="ns"/> (namespace definitions or references up to the scope).</summary>
    private string Qualify(MdHandle ns, string name, int depth)
    {
        var parts = new List<string>();
        while (!ns.IsNull && ns.Record is MdRecord.NamespaceDefinition or MdRecord.NamespaceReference && depth++ < 64)
        {
            if (StringField(ns, "name") is { Length: > 0 } part) parts.Add(part);
            ns = Handle(ns, "parentScopeOrNamespace");
        }
        parts.Reverse();
        return parts.Count == 0 ? name : string.Join('.', parts) + "." + name;
    }

    private string InstantiationName(MdHandle h, int depth)
    {
        string generic = FormatType(Handle(h, "genericType"), depth + 1, false);
        int tick = generic.LastIndexOf('`');
        if (tick > generic.LastIndexOf('+') && tick > generic.LastIndexOf('.')) generic = generic[..tick];
        var args = Handles(h, "genericTypeArguments").Select(a => FormatType(a, depth + 1, true));
        return $"{generic}<{string.Join(", ", args)}>";
    }

    private string FunctionPointer(uint signature, int depth)
    {
        if (signature == 0) return "<?>";
        var sig = new MdHandle(MdRecord.MethodSignature, signature);
        var types = Handles(sig, "parameters").Select(p => FormatType(p, depth + 1, true)).Append(FormatType(Handle(sig, "returnType"), depth + 1, true));
        return $"<{string.Join(", ", types)}>";
    }

    /// <summary>"(int, string)" for the MethodSignature at <paramref name="offset"/>.</summary>
    public string FormatSignature(uint offset)
    {
        if (offset == 0) return "";
        var sig = new MdHandle(MdRecord.MethodSignature, offset);
        return "(" + string.Join(", ", Handles(sig, "parameters").Select(p => FormatType(p, 1, true))) + ")";
    }

    /// <summary>The C# keyword of a built-in type name, as nested names (arguments, elements, parameters) use it.</summary>
    internal static string Keyword(string name) => name switch
    {
        "System.Void" => "void",
        "System.Boolean" => "bool",
        "System.Char" => "char",
        "System.SByte" => "sbyte",
        "System.Byte" => "byte",
        "System.Int16" => "short",
        "System.UInt16" => "ushort",
        "System.Int32" => "int",
        "System.UInt32" => "uint",
        "System.Int64" => "long",
        "System.UInt64" => "ulong",
        "System.IntPtr" => "nint",
        "System.UIntPtr" => "nuint",
        "System.Single" => "float",
        "System.Double" => "double",
        "System.Object" => "object",
        "System.String" => "string",
        _ => name,
    };

    /// <summary>
    /// The name of a method handle: Method (owner found through the type definitions), QualifiedMethod, MemberReference
    /// or MethodInstantiation.
    /// </summary>
    public NativeAotMethodName FormatMethod(MdHandle h, int depth = 0)
    {
        if (depth > MaxDepth) throw new NativeAotFormatException("method handle chain is too deep");
        switch (h.Record)
        {
            case MdRecord.Method:
                return new NativeAotMethodName(MethodOwner(h.Offset) ?? "?", StringField(h, "name") ?? "?", FormatSignature(Ref(h, "signature")));
            case MdRecord.QualifiedMethod:
                var method = new MdHandle(MdRecord.Method, Ref(h, "method"));
                return new NativeAotMethodName(FormatType(new MdHandle(MdRecord.TypeDefinition, Ref(h, "enclosingType"))),
                    StringField(method, "name") ?? "?", FormatSignature(Ref(method, "signature")));
            case MdRecord.MemberReference:
                var signature = Handle(h, "signature");
                return new NativeAotMethodName(FormatType(Handle(h, "parent")), StringField(h, "name") ?? "?",
                    signature.Record == MdRecord.MethodSignature ? FormatSignature(signature.Offset) : null);
            case MdRecord.MethodInstantiation:
                var generic = FormatMethod(Handle(h, "method"), depth + 1);
                var args = Handles(h, "genericTypeArguments").Select(a => FormatType(a, 1, true));
                return generic with { Instantiation = $"<{string.Join(", ", args)}>" };
            default:
                throw new NativeAotFormatException($"{h.Record} is not a method handle");
        }
    }

    /// <summary>The strings of the ConstantStringArray at <paramref name="offset"/>.</summary>
    public List<string> StringArray(uint offset)
    {
        var result = new List<string>();
        if (offset == 0) return result;
        foreach (var item in Handles(new MdHandle(MdRecord.ConstantStringArray, offset), "value"))
            result.Add(item.Record == MdRecord.ConstantStringValue ? String(item.Offset) ?? "?" : "?");
        return result;
    }

    /// <summary>The full name of the type definition declaring the Method record at <paramref name="methodOffset"/>.</summary>
    public string? MethodOwner(uint methodOffset)
    {
        return methodOwners.Value.TryGetValue(methodOffset, out uint type) ? FormatType(new MdHandle(MdRecord.TypeDefinition, type)) : null;
    }

    /// <summary>Every type definition reachable from the scopes, nested types included (bounded by the blob size).</summary>
    public List<uint> TypeDefinitions()
    {
        var types = new List<uint>();
        var seen = new HashSet<uint>();
        var namespaces = new Stack<uint>();
        foreach (uint scope in ScopeDefinitions)
            namespaces.Push(Ref(new MdHandle(MdRecord.ScopeDefinition, scope), "rootNamespaceDefinition"));
        var pending = new Stack<uint>();
        while (namespaces.Count > 0)
        {
            var ns = new MdHandle(MdRecord.NamespaceDefinition, namespaces.Pop());
            if (ns.IsNull || !seen.Add(ns.Offset)) continue;
            foreach (uint t in Collection(ns, "typeDefinitions")) pending.Push(t);
            foreach (uint child in Collection(ns, "namespaceDefinitions")) namespaces.Push(child);
        }
        while (pending.Count > 0)
        {
            uint t = pending.Pop();
            if (t == 0 || !seen.Add(t)) continue;
            types.Add(t);
            foreach (uint nested in Collection(new MdHandle(MdRecord.TypeDefinition, t), "nestedTypes")) pending.Push(nested);
        }
        return types;
    }

    private Dictionary<uint, uint> IndexMethods()
    {
        var owners = new Dictionary<uint, uint>();
        foreach (uint t in TypeDefinitions())
            foreach (uint m in Collection(new MdHandle(MdRecord.TypeDefinition, t), "methods"))
                owners.TryAdd(m, t);
        return owners;
    }
}
