using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core;

/// <summary>Compiled code of a Dart AOT snapshot: its offset in the instructions image and the name the VM prints for it.</summary>
public sealed record DartCode(uint Offset, string Name);

/// <summary>
/// The code names of a Dart AOT snapshot. <see cref="Unsupported"/> names why nothing was read (another layout, a
/// truncated stream); the names are then unknown, not absent.
/// </summary>
public sealed record DartProgram(IReadOnlyList<DartCode> Code, int Functions, int CodeObjects, string? Unsupported)
{
    /// <summary>Instructions-table entries left unnamed: VM stubs and type-test stubs.</summary>
    public int Unnamed { get; init; }
}

/// <summary>
/// Reads the clustered object stream of a Dart AOT snapshot far enough to name its code: strings, Code, Function,
/// Class, PatchClass and ClosureData objects, and the instructions table that places each Code. Names follow the VM's
/// Function::PrintName with user-visible names, as its DWARF and stack traces print them. Read layout: the single
/// program snapshot of Dart 3.13 (kDartSnapshotData), product mode, 64-bit, with or without compressed pointers; any
/// other layout is refused as unsupported.
/// </summary>
public static class DartProgramReader
{
    // Class ids of Dart 3.13 (runtime/vm/class_id.h).
    private const int ClassCid = 5, PatchClassCid = 6, FunctionCid = 7, TypeParametersCid = 8, ClosureDataCid = 9, CodeCid = 18,
        ObjectPoolCid = 23, PcDescriptorsCid = 24, CodeSourceMapCid = 25, CompressedStackMapsCid = 26, LocalVarDescriptorsCid = 27,
        ExceptionHandlersCid = 28, ContextCid = 29, ContextScopeCid = 30, InstanceCid = 45, TypeArgumentsCid = 47, TypeCid = 49,
        FunctionTypeCid = 50, RecordTypeCid = 51, TypeParameterCid = 52, ClosureCid = 57, MintCid = 61, DoubleCid = 62,
        Float32x4Cid = 64, Int32x4Cid = 65, Float64x2Cid = 66, RecordCid = 67, ConstMapCid = 87, ConstSetCid = 89, ArrayCid = 90,
        ImmutableArrayCid = 91, GrowableObjectArrayCid = 92, StringCid = 93, OneByteStringCid = 94, TwoByteStringCid = 95,
        FirstFfiCid = 97, LastFfiCid = 112, FirstTypedDataCid = 113, LastTypedDataCid = 168,
        NumPredefinedCids = 176, WeakArrayCid = 17;
    // Serializer's kDeltaEncodedTypedDataCid reuses kNativePointerCid.
    private const int DeltaEncodedTypedDataCid = 1;
    private const int TopLevelCidOffset = 1 << 20;
    private const int MaxObjects = 50_000_000;

    private enum Alloc { Fixed, Lengths, RoData, Code, Instance, Mint }

    private sealed class Cluster
    {
        public int Cid, Start, Stop, Count, NextField;
        public bool Canonical;
        public Alloc Alloc;
        public long[]? Offsets;
    }

    private sealed class Truncated : Exception;

    /// <summary>Reads <paramref name="snapshot"/> (a header <see cref="DartScan"/> found in <paramref name="data"/>); never throws on bad input.</summary>
    public static DartProgram Read(ReadOnlySpan<byte> data, DartSnapshot snapshot, CancellationToken ct = default)
    {
        var tokens = snapshot.Features.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        string? refused = snapshot.Symbol != "kDartSnapshotData" ? "a separate VM and isolate snapshot (Dart before 3.13)"
            : snapshot.Kind != "full-aot" ? $"a {snapshot.Kind} snapshot"
            : !tokens.Contains("product") ? "a non-product (profile or debug) snapshot"
            : snapshot.Architecture is not ("x64" or "arm64" or "riscv64") ? $"the {snapshot.Architecture ?? "unknown"} architecture"
            : null;
        if (refused != null) return Refuse("layout not read: " + refused);
        try { return ReadCore(data, snapshot, tokens.Contains("compressed-pointers"), ct); }
        catch (Truncated) { return Refuse($"the object stream of snapshot {snapshot.Hash} does not parse as the Dart 3.13 layout"); }
    }

    private static DartProgram Refuse(string reason) => new([], 0, 0, reason);

    private static DartProgram ReadCore(ReadOnlySpan<byte> data, DartSnapshot snapshot, bool compressed, CancellationToken ct)
    {
        long total = snapshot.Length + 4;
        int features = (int)snapshot.Offset + 52;
        int end = features < data.Length && data[features..].IndexOf((byte)0) is var nul and >= 0 ? features + nul : -1;
        long dataImage = snapshot.Offset + (total + 63) / 64 * 64;
        if (end < 0 || dataImage >= data.Length) throw new Truncated();
        var s = new Reader(data, end + 1);
        long baseObjects = s.Unsigned(), objects = s.Unsigned(), clusterCount = s.Unsigned();
        s.Unsigned();
        long tableAt = s.Unsigned();
        if (objects > MaxObjects || baseObjects > objects || clusterCount > objects + 1) throw new Truncated();

        // Alloc phase: assigns each cluster its ref range.
        int next = 1 + (int)baseObjects;
        var clusters = new List<Cluster>((int)clusterCount);
        for (long i = 0; i < clusterCount; i++)
        {
            if ((i & 63) == 0) ct.ThrowIfCancellationRequested();
            uint tags = (uint)s.Signed(32);
            var c = new Cluster { Cid = (int)(tags >> 12), Canonical = (tags & 2) != 0, Start = next };
            c.Alloc = AllocOf(c.Cid, compressed);
            long count = s.Unsigned();
            if (count > objects - (next - 1)) throw new Truncated();
            c.Count = (int)count;
            switch (c.Alloc)
            {
                case Alloc.Fixed: break;
                case Alloc.Lengths:
                    for (long k = 0; k < count; k++) s.Unsigned();
                    break;
                case Alloc.Mint:
                    for (long k = 0; k < count; k++) s.Signed(64);
                    break;
                case Alloc.Instance:
                    c.NextField = (int)s.Signed(32);
                    s.Signed(32);
                    break;
                case Alloc.RoData:
                    c.Offsets = new long[count];
                    long running = 0;
                    for (long k = 0; k < count; k++) c.Offsets[k] = running += s.Unsigned() << 4;
                    break;
                case Alloc.Code:
                    for (long k = 0; k < count; k++) s.Signed(32);
                    long deferred = s.Unsigned();
                    for (long k = 0; k < deferred; k++) s.Signed(32);
                    count += deferred;
                    break;
            }
            next += (int)count;
            if (next - 1 > objects) throw new Truncated();
            c.Stop = next;
            if (c.Canonical && c.Cid is TypeArgumentsCid or TypeCid or FunctionTypeCid or RecordTypeCid or TypeParameterCid
                || c.Canonical && c.Cid == StringCid)
            {
                s.Unsigned();
                long first = s.Unsigned();
                for (long k = c.Start + first; k < c.Stop; k++) s.Unsigned();
            }
            clusters.Add(c);
        }
        if (next - 1 != objects) throw new Truncated();

        var strings = new Dictionary<int, string>();
        foreach (var c in clusters)
            if (c.Alloc == Alloc.RoData && c.Cid is StringCid or OneByteStringCid or TwoByteStringCid)
                for (int k = 0; k < c.Offsets!.Length; k++)
                    if (RoString(data, dataImage + c.Offsets[k]) is { } text) strings[c.Start + k] = text;

        // InstructionsTable::Data: canonical stack map offset, length, first entry with code, padding; then {pc, stack map} pairs.
        long table = dataImage + tableAt + 16;
        if (tableAt <= 0 || table + 16 > data.Length) throw new Truncated();
        int length = BinaryPrimitives.ReadInt32LittleEndian(data[(int)(table + 4)..]);
        int firstWithCode = BinaryPrimitives.ReadInt32LittleEndian(data[(int)(table + 8)..]);
        if (length < 0 || firstWithCode < 0 || firstWithCode > length || table + 16 + 8L * length > data.Length) throw new Truncated();
        var pcs = new uint[length];
        for (int i = 0; i < length; i++) pcs[i] = BinaryPrimitives.ReadUInt32LittleEndian(data[(int)(table + 16 + 8L * i)..]);
        uint Entry(int i) => pcs[i];

        var codeOwner = new Dictionary<int, (uint? Pc, int Owner)>();
        var codeRefs = new List<int>();
        var functions = new Dictionary<int, (int Name, int Owner, int Data, uint Kind, long CodeIndex)>();
        var classes = new Dictionary<int, (int Name, int Cid)>();
        var patches = new Dictionary<int, int>();
        var parents = new Dictionary<int, int>();
        int codeIndex = 0;
        bool done = false;

        // Fill phase, up to ClosureData: clusters keep their class id order after the early ones, so later clusters are not read.
        foreach (var c in clusters)
        {
            ct.ThrowIfCancellationRequested();
            int n = c.Stop - c.Start;
            switch (c.Cid)
            {
                case var _ when c.Alloc is Alloc.RoData or Alloc.Mint: break;
                case ObjectPoolCid:
                    for (int k = 0; k < n; k++)
                    {
                        long entries = s.Unsigned();
                        for (long e = 0; e < entries; e++)
                        {
                            int bits = s.Byte();
                            // SnapshotBehaviorBits (bits 5-7) other than kSnapshotable carry no value; TypeBits 0 is an immediate, 1 an object.
                            if ((bits >> 5 & 7) != 0) continue;
                            if ((bits & 15) == 1) s.Ref();
                            else if ((bits & 15) == 0) s.Signed(64);
                        }
                    }
                    break;
                case LocalVarDescriptorsCid:
                    for (int k = 0; k < n; k++)
                    {
                        long count = s.Unsigned();
                        s.Refs(count);
                        for (long e = 0; e < count; e++) { s.Signed(32); s.Signed(32); s.Signed(32); s.Signed(32); s.Signed(64); }
                    }
                    break;
                case ExceptionHandlersCid:
                    for (int k = 0; k < n; k++)
                    {
                        long count = s.Unsigned() >> 1;
                        s.Ref();
                        for (long e = 0; e < count; e++) { s.Signed(32); s.Signed(16); s.Byte(); s.Byte(); s.Byte(); }
                    }
                    break;
                case ContextScopeCid:
                    for (int k = 0; k < n; k++)
                    {
                        long count = s.Unsigned();
                        s.Byte();
                        // VariableDesc: ten fields per variable.
                        s.Refs(10 * count);
                    }
                    break;
                case ArrayCid or ImmutableArrayCid or WeakArrayCid:
                    for (int k = 0; k < n; k++)
                    {
                        long count = s.Unsigned();
                        s.Refs(c.Cid == WeakArrayCid ? count : count + 1);
                    }
                    break;
                case DoubleCid:
                    for (int k = 0; k < n; k++) s.Signed(64);
                    break;
                case PcDescriptorsCid or CodeSourceMapCid:
                    for (int k = 0; k < n; k++) s.Skip(s.Unsigned());
                    break;
                case CompressedStackMapsCid:
                    // Flags and size: the size starts at bit 2.
                    for (int k = 0; k < n; k++) s.Skip(s.Unsigned() >> 2);
                    break;
                case StringCid:
                    for (int r = c.Start; r < c.Stop; r++)
                    {
                        // Length and cid: bit 0 marks two-byte characters.
                        long encoded = s.Unsigned();
                        var chars = s.Bytes((encoded >> 1) * ((encoded & 1) + 1));
                        strings[r] = (encoded & 1) == 0 ? Encoding.Latin1.GetString(chars) : Encoding.Unicode.GetString(chars);
                    }
                    break;
                case Float32x4Cid or Int32x4Cid or Float64x2Cid:
                    for (int k = 0; k < n; k++) s.Skip(16);
                    break;
                case TypeParameterCid:
                    for (int k = 0; k < n; k++) { s.Refs(3); s.Signed(16); s.Signed(16); s.Byte(); }
                    break;
                case TypeCid:
                    for (int k = 0; k < n; k++) { s.Refs(3); s.Unsigned(); }
                    break;
                case FunctionTypeCid:
                    for (int k = 0; k < n; k++) { s.Refs(6); s.Byte(); s.Signed(32); s.Signed(16); }
                    break;
                case RecordTypeCid:
                    for (int k = 0; k < n; k++) { s.Refs(4); s.Byte(); }
                    break;
                case TypeArgumentsCid:
                    for (int k = 0; k < n; k++)
                    {
                        long count = s.Unsigned();
                        s.Signed(32);
                        s.Unsigned();
                        s.Refs(count + 1);
                    }
                    break;
                case CodeCid:
                    s.Ref();
                    s.Ref();
                    for (int r = c.Start; r < c.Stop; r++)
                    {
                        bool deferred = r >= c.Start + c.Count;
                        uint? pc = null;
                        if (!deferred)
                        {
                            s.Unsigned();
                            int at = firstWithCode + codeIndex++;
                            if (at >= length) throw new Truncated();
                            pc = Entry(at);
                        }
                        int owner = s.Ref();
                        s.Refs(5);
                        codeOwner[r] = (pc, owner);
                        codeRefs.Add(r);
                    }
                    break;
                case FunctionCid:
                    for (int r = c.Start; r < c.Stop; r++)
                    {
                        int name = s.Ref(), owner = s.Ref();
                        s.Ref();
                        int fdata = s.Ref();
                        long index = s.Unsigned();
                        uint kind = (uint)s.Signed(32);
                        functions[r] = (name, owner, fdata, kind, index);
                    }
                    break;
                case ClosureCid:
                    for (int k = 0; k < n; k++) s.Refs(s.Unsigned() + 3);
                    break;
                case RecordCid:
                    for (int k = 0; k < n; k++) s.Refs(s.Unsigned() & 0xFFFF);
                    break;
                case ConstMapCid or ConstSetCid:
                    s.Refs(5L * n);
                    break;
                case GrowableObjectArrayCid:
                    s.Refs(3L * n);
                    break;
                case DeltaEncodedTypedDataCid:
                    for (int k = 0; k < n; k++)
                    {
                        long count = s.Unsigned() >> 1;
                        for (long e = 0; e < count; e++) s.Unsigned();
                    }
                    break;
                case var _ when c.Alloc == Alloc.Instance:
                    ulong unboxed = (ulong)s.Unsigned();
                    // Fields follow the 8-byte header, in words of 4 bytes with compressed pointers.
                    for (int k = 0; k < n; k++)
                        for (int w = compressed ? 2 : 1; w < c.NextField; w++)
                        {
                            if (w < 64 && (unboxed >> w & 1) != 0) { s.Signed(32); s.Signed(32); }
                            else s.Ref();
                        }
                    break;
                case ClassCid:
                    for (int r = c.Start; r < c.Stop; r++)
                    {
                        // name .. invocation_dispatcher_cache: the product AOT snapshot fields.
                        int name = s.Ref();
                        s.Refs(12);
                        int cid = (int)s.Signed(32);
                        s.Signed(32); s.Signed(32); s.Signed(32); s.Signed(16); s.Signed(16); s.Signed(32);
                        if (cid < TopLevelCidOffset) s.Unsigned();
                        classes[r] = (name, cid);
                    }
                    break;
                case PatchClassCid:
                    for (int r = c.Start; r < c.Stop; r++) { patches[r] = s.Ref(); s.Ref(); }
                    break;
                case TypeParametersCid:
                    s.Refs(4L * n);
                    break;
                case ClosureDataCid:
                    for (int r = c.Start; r < c.Stop; r++)
                    {
                        parents[r] = s.Ref();
                        s.Ref();
                        s.Unsigned();
                    }
                    done = true;
                    break;
                default:
                    throw new Truncated();
            }
            if (done) break;
        }
        if (!done) throw new Truncated();

        string? OwnerName(int owner)
        {
            if (patches.TryGetValue(owner, out var wrapped)) owner = wrapped;
            if (!classes.TryGetValue(owner, out var cls)) return null;
            return PublicName(cls.Cid) ?? ClassName(strings.GetValueOrDefault(cls.Name));
        }

        string FunctionName(int f, int depth)
        {
            var (name, owner, fdata, kind, _) = functions[f];
            var raw = strings.GetValueOrDefault(name) ?? "<unnamed>";
            var shown = Scrub(raw, raw.Length > 1 && raw.Contains('|'));
            // Function::PrintName: a closure prints its parent first; a constructor prints "new" instead of its class.
            switch (kind & 0x1F)
            {
                case 1:
                    var parent = parents.TryGetValue(fdata, out var p) && functions.ContainsKey(p) && depth < 32 ? FunctionName(p, depth + 1) : "<optimized out>";
                    return parent + "." + shown;
                case 5:
                    return "new " + shown;
            }
            return OwnerName(owner) is { } cls ? cls + "." + shown : shown;
        }

        var named = new Dictionary<uint, string>();
        int namedFunctions = 0;
        foreach (var (f, fn) in functions)
        {
            if (fn.CodeIndex == 0) continue;
            long index = fn.CodeIndex - 1;
            uint? pc = index < firstWithCode ? (index < length ? Entry((int)index) : null)
                : index - firstWithCode < codeRefs.Count ? codeOwner[codeRefs[(int)(index - firstWithCode)]].Pc : null;
            if (pc is not { } at) continue;
            namedFunctions++;
            named.TryAdd(at, FunctionName(f, 0));
        }
        // Allocation stubs belong to their class.
        foreach (var r in codeRefs)
            if (codeOwner[r] is { Pc: { } at } code && !named.ContainsKey(at) && classes.ContainsKey(code.Owner) && OwnerName(code.Owner) is { } cls)
                named[at] = "new " + cls;
        var list = named.OrderBy(kv => kv.Key).Select(kv => new DartCode(kv.Key, kv.Value)).ToList();
        return new DartProgram(list, namedFunctions, codeRefs.Count, null) { Unnamed = Math.Max(0, length - list.Count) };
    }

    // With compressed pointers the VM writes no read-only data image: these objects are in the stream.
    private static Alloc AllocOf(int cid, bool compressed)
    {
        if (cid >= NumPredefinedCids || cid == InstanceCid || cid is >= FirstFfiCid and <= LastFfiCid) return Alloc.Instance;
        if (cid is >= FirstTypedDataCid and <= LastTypedDataCid)
            return (cid - FirstTypedDataCid) % 4 == 0 ? Alloc.Lengths : Alloc.Fixed;
        return cid switch
        {
            PcDescriptorsCid or CodeSourceMapCid or CompressedStackMapsCid or StringCid or OneByteStringCid or TwoByteStringCid
                => compressed ? Alloc.Lengths : Alloc.RoData,
            TypeArgumentsCid or ObjectPoolCid or LocalVarDescriptorsCid or ExceptionHandlersCid or ContextCid or ContextScopeCid or ClosureCid or RecordCid
                or ArrayCid or ImmutableArrayCid or WeakArrayCid or DeltaEncodedTypedDataCid => Alloc.Lengths,
            CodeCid => Alloc.Code,
            MintCid => Alloc.Mint,
            _ => Alloc.Fixed,
        };
    }

    /// <summary>A one- or two-byte string object of the data image: tags, Smi length at +8, characters at +16.</summary>
    private static string? RoString(ReadOnlySpan<byte> data, long at)
    {
        if (at < 0 || at + 16 > data.Length) return null;
        int cid = (int)(BinaryPrimitives.ReadUInt32LittleEndian(data[(int)at..]) >> 12);
        long n = BinaryPrimitives.ReadInt64LittleEndian(data[(int)(at + 8)..]) >> 1;
        int size = cid == OneByteStringCid ? 1 : cid == TwoByteStringCid ? 2 : 0;
        if (size == 0 || n < 0 || at + 16 + n * size > data.Length) return null;
        var chars = data.Slice((int)(at + 16), (int)(n * size));
        return size == 1 ? Encoding.Latin1.GetString(chars) : Encoding.Unicode.GetString(chars);
    }

    /// <summary>String::ScrubName: drops private keys (@digits), getter and setter prefixes and a trailing dot.</summary>
    internal static string Scrub(string name, bool extension = false)
    {
        var u = new StringBuilder(name.Length);
        for (int i = 0; i < name.Length; i++)
        {
            if (name[i] == '@' && i + 1 < name.Length && char.IsAsciiDigit(name[i + 1]))
            {
                i++;
                while (i + 1 < name.Length && char.IsAsciiDigit(name[i + 1])) i++;
            }
            else u.Append(name[i]);
        }
        var text = u.ToString();
        string prefix = "";
        bool setter = false;
        if (extension && text.IndexOf('|') is var bar and >= 0)
        {
            // Ext|member, or get:Ext|member for an accessor.
            var head = text[..bar];
            if (head.StartsWith("get:", StringComparison.Ordinal) || head.StartsWith("set:", StringComparison.Ordinal))
            {
                setter = head[0] == 's';
                head = head[4..];
            }
            prefix = head + ".";
            text = text[(bar + 1)..];
        }
        int start = 0, dot = -1;
        for (int i = 0; i < text.Length; i++)
        {
            char ch = text[i];
            if (ch == ':' || extension && ch == '#')
            {
                if (start != 0) { start = 0; dot = -1; break; }
                if (text[0] == 's') setter = true;
                start = i + 1;
            }
            else if (ch == '.')
            {
                if (dot != -1) { start = 0; dot = -1; break; }
                dot = i;
            }
        }
        if (!extension && start == 0 && dot == -1) return text;
        int stop = dot + 1 == text.Length ? dot : text.Length;
        return prefix + text[start..stop] + (setter ? "=" : "");
    }

    /// <summary>A class's printed name; a mixin application (Super&amp;Mixin) prints its mixin. Null for the top-level class.</summary>
    private static string? ClassName(string? raw)
    {
        if (raw is null or "::") return null;
        int amp = raw.LastIndexOf('&');
        return Scrub(amp >= 0 ? raw[(amp + 1)..] : raw);
    }

    /// <summary>Class::GenerateUserVisibleName for predefined classes: implementation classes print their public type.</summary>
    private static string? PublicName(int cid) => cid switch
    {
        MintCid or 59 or 60 => "int",
        DoubleCid => "double",
        OneByteStringCid or TwoByteStringCid => "String",
        ArrayCid or ImmutableArrayCid or GrowableObjectArrayCid => "List",
        Float32x4Cid => "Float32x4",
        Int32x4Cid => "Int32x4",
        Float64x2Cid => "Float64x2",
        72 => "Pointer",
        73 => "DynamicLibrary",
        46 => "LibraryPrefix",
        172 => "Null",
        173 => "dynamic",
        174 => "void",
        175 => "Never",
        >= FirstTypedDataCid and <= LastTypedDataCid when (cid - FirstTypedDataCid) % 4 is 0 or 2 => TypedListNames[(cid - FirstTypedDataCid) / 4],
        _ => null,
    };

    private static readonly string[] TypedListNames =
    [
        "Int8List", "Uint8List", "Uint8ClampedList", "Int16List", "Uint16List", "Int32List", "Uint32List", "Int64List", "Uint64List",
        "Float32List", "Float64List", "Float32x4List", "Int32x4List", "Float64x2List",
    ];

    /// <summary>The snapshot stream's encodings (runtime/vm/datastream.h); reads past the end throw <see cref="Truncated"/>.</summary>
    private ref struct Reader(ReadOnlySpan<byte> data, int position)
    {
        private readonly ReadOnlySpan<byte> _data = data;
        private int _at = position;

        public int Byte() => _at < _data.Length ? _data[_at++] : throw new Truncated();

        public void Skip(long n)
        {
            if (n < 0 || n > _data.Length - _at) throw new Truncated();
            _at += (int)n;
        }

        public ReadOnlySpan<byte> Bytes(long n)
        {
            var start = _at;
            Skip(n);
            return _data.Slice(start, (int)n);
        }

        /// <summary>ReadUnsigned: 7-bit groups, low first; a byte above 127 ends the value.</summary>
        public long Unsigned()
        {
            int b = Byte();
            if (b > 127) return b - 128;
            long r = 0;
            int shift = 0;
            while (b <= 127)
            {
                r |= (long)b << shift;
                shift += 7;
                if (shift > 63) throw new Truncated();
                b = Byte();
            }
            return r | ((long)(b - 128) << shift);
        }

        /// <summary>Read&lt;T&gt; for 16-, 32- and 64-bit types: as <see cref="Unsigned"/> with end marker 192, sign-extended to <paramref name="bits"/>.</summary>
        public long Signed(int bits)
        {
            int b = Byte();
            long r;
            if (b > 127) r = b - 192;
            else
            {
                r = 0;
                int shift = 0;
                while (b <= 127)
                {
                    r |= (long)b << shift;
                    shift += 7;
                    if (shift > 63) throw new Truncated();
                    b = Byte();
                }
                r |= (long)(b - 192) << shift;
            }
            return bits == 64 ? r : r << (64 - bits) >> (64 - bits);
        }

        /// <summary>ReadRefId: 7-bit groups, high first, ending at a byte with the top bit set.</summary>
        public int Ref()
        {
            long r = 0;
            for (int i = 0; i < 5; i++)
            {
                int b = (sbyte)Byte();
                r = (r << 7) + b;
                if (b < 0) return (int)(r + 128);
            }
            throw new Truncated();
        }

        public void Refs(long n)
        {
            if (n < 0 || n > _data.Length - _at) throw new Truncated();
            for (long i = 0; i < n; i++) Ref();
        }
    }
}
