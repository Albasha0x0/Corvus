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

    /// <summary>The Dart release whose layout the snapshot was read with ("3.13"); null when nothing was read.</summary>
    public string? Layout { get; init; }
}

/// <summary>
/// Reads the clustered object stream of a Dart AOT snapshot far enough to name its code: strings, Code, Function,
/// Class, PatchClass and ClosureData objects, and the instructions table that places each Code. Names follow the VM's
/// Function::PrintName with user-visible names, as its DWARF and stack traces print them. Read layouts: product mode,
/// 64-bit, with or without compressed pointers, of the single program snapshot of Dart 3.13 (kDartSnapshotData) and the
/// VM and isolate snapshots of Dart 3.12; any other layout is refused as unsupported.
/// </summary>
public static class DartProgramReader
{
    /// <summary>Class ids one Dart release assigns (runtime/vm/class_id.h).</summary>
    private sealed record Cids(int Class, int PatchClass, int Function, int TypeParameters, int ClosureData, int WeakArray, int Code,
        int ObjectPool, int PcDescriptors, int CodeSourceMap, int CompressedStackMaps, int LocalVarDescriptors, int ExceptionHandlers,
        int Context, int ContextScope, int LibraryPrefix, int Instance, int TypeArguments, int Type, int FunctionType, int RecordType,
        int TypeParameter, int Closure, int Integer, int Smi, int Mint, int Double, int Float32x4, int Int32x4, int Float64x2, int Record,
        int Pointer, int DynamicLibrary, int ConstMap, int ConstSet, int Array, int ImmutableArray, int GrowableObjectArray,
        int String, int OneByteString, int TwoByteString, int FirstFfi, int LastFfi, int FirstTypedData, int LastTypedData, int Null,
        int NumPredefined);

    /// <summary>
    /// One release's stream format. Split: a VM snapshot whose objects are the isolate snapshot's base objects.
    /// PredefinedClasses: the Class cluster lists the predefined classes it fills before the new ones. FixedClosures:
    /// a Closure has no length. CodeStubRefs: the Code cluster starts with the LazyCompile and UnknownDartCode refs.
    /// PublicFuture: the release's names print dart:async's _Future as Future.
    /// </summary>
    private sealed record Layout(string Release, Cids C, bool Split, bool PredefinedClasses, bool FixedClosures, bool CodeStubRefs, bool PublicFuture);

    // Class ids generated from each release's class_id.h; formats from its app_snapshot.cc.
    private static readonly Layout[] Layouts =
    [
        new("3.13", new(Class: 5, PatchClass: 6, Function: 7, TypeParameters: 8, ClosureData: 9, WeakArray: 17, Code: 18, ObjectPool: 23,
            PcDescriptors: 24, CodeSourceMap: 25, CompressedStackMaps: 26, LocalVarDescriptors: 27, ExceptionHandlers: 28, Context: 29,
            ContextScope: 30, LibraryPrefix: 46, Instance: 45, TypeArguments: 47, Type: 49, FunctionType: 50, RecordType: 51,
            TypeParameter: 52, Closure: 57, Integer: 59, Smi: 60, Mint: 61, Double: 62, Float32x4: 64, Int32x4: 65, Float64x2: 66,
            Record: 67, Pointer: 72, DynamicLibrary: 73, ConstMap: 87, ConstSet: 89, Array: 90, ImmutableArray: 91,
            GrowableObjectArray: 92, String: 93, OneByteString: 94, TwoByteString: 95, FirstFfi: 97, LastFfi: 112, FirstTypedData: 113,
            LastTypedData: 168, Null: 172, NumPredefined: 176),
            Split: false, PredefinedClasses: false, FixedClosures: false, CodeStubRefs: true, PublicFuture: false),
        new("3.12", new(Class: 5, PatchClass: 6, Function: 7, TypeParameters: 8, ClosureData: 9, WeakArray: 17, Code: 18, ObjectPool: 23,
            PcDescriptors: 24, CodeSourceMap: 25, CompressedStackMaps: 26, LocalVarDescriptors: 27, ExceptionHandlers: 28, Context: 29,
            ContextScope: 30, LibraryPrefix: 46, Instance: 45, TypeArguments: 47, Type: 49, FunctionType: 50, RecordType: 51,
            TypeParameter: 52, Closure: 57, Integer: 59, Smi: 60, Mint: 61, Double: 62, Float32x4: 64, Int32x4: 65, Float64x2: 66,
            Record: 67, Pointer: 72, DynamicLibrary: 73, ConstMap: 87, ConstSet: 89, Array: 90, ImmutableArray: 91,
            GrowableObjectArray: 92, String: 93, OneByteString: 94, TwoByteString: 95, FirstFfi: 96, LastFfi: 111, FirstTypedData: 112,
            LastTypedData: 167, Null: 171, NumPredefined: 175),
            Split: true, PredefinedClasses: true, FixedClosures: true, CodeStubRefs: false, PublicFuture: true),
    ];

    // Serializer's kDeltaEncodedTypedDataCid reuses kNativePointerCid.
    private const int DeltaEncodedTypedDataCid = 1;
    private const int TopLevelCidOffset = 1 << 20;
    private const int MaxObjects = 50_000_000;

    private enum Alloc { Fixed, Lengths, RoData, Code, Instance, Mint, Classes }

    private sealed class Cluster
    {
        public int Cid, Start, Stop, Count, NextField;
        public bool Canonical;
        public Alloc Alloc;
        public long[]? Offsets;
    }

    private sealed class Truncated : Exception;

    /// <summary>The objects a stream defines that naming needs, by ref.</summary>
    private sealed class Objects
    {
        public readonly Dictionary<int, string> Strings = [];
        public readonly Dictionary<int, (uint? Pc, int Owner)> CodeOwner = [];
        public readonly List<int> CodeRefs = [];
        public readonly Dictionary<int, (int Name, int Owner, int Data, uint Kind, long CodeIndex)> Functions = [];
        public readonly Dictionary<int, (int Name, int Cid)> Classes = [];
        public readonly Dictionary<int, int> Patches = [];
        public readonly Dictionary<int, int> Parents = [];
        public uint[] Pcs = [];
        public int FirstWithCode;
        public long Count;
    }

    /// <summary>Reads <paramref name="snapshot"/>, a program snapshot (kDartSnapshotData) <see cref="DartScan"/> found in <paramref name="data"/>; never throws on bad input.</summary>
    public static DartProgram Read(ReadOnlySpan<byte> data, DartSnapshot snapshot, CancellationToken ct = default) => Read(data, null, snapshot, ct);

    /// <summary>
    /// Reads <paramref name="snapshot"/>: a program snapshot (kDartSnapshotData), or an isolate snapshot
    /// (kDartIsolateSnapshotData) with the <paramref name="vm"/> snapshot its base objects come from. Never throws on bad input.
    /// </summary>
    public static DartProgram Read(ReadOnlySpan<byte> data, DartSnapshot? vm, DartSnapshot snapshot, CancellationToken ct = default)
    {
        var tokens = snapshot.Features.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        bool split = snapshot.Symbol == "kDartIsolateSnapshotData";
        string? refused = snapshot.Symbol is not ("kDartSnapshotData" or "kDartIsolateSnapshotData") ? "no program or isolate snapshot symbol"
            : split && vm == null ? "an isolate snapshot without its VM snapshot"
            : snapshot.Kind != "full-aot" ? $"a {snapshot.Kind} snapshot"
            : !tokens.Contains("product") ? "a non-product (profile or debug) snapshot"
            : snapshot.Architecture is not ("x64" or "arm64" or "riscv64") ? $"the {snapshot.Architecture ?? "unknown"} architecture"
            : null;
        if (refused != null) return Refuse("layout not read: " + refused);
        bool compressed = tokens.Contains("compressed-pointers");
        var tried = new List<string>();
        foreach (var layout in Layouts.Where(l => l.Split == split))
        {
            ct.ThrowIfCancellationRequested();
            tried.Add(layout.Release);
            try
            {
                var vmObjects = split ? Parse(data, vm!, layout, compressed, null, ct) : null;
                return Name(Parse(data, snapshot, layout, compressed, vmObjects, ct), layout);
            }
            catch (Truncated) { }
        }
        return Refuse($"the object stream of snapshot {snapshot.Hash} does not parse as the Dart {string.Join(" or ", tried)} layout");
    }

    private static DartProgram Refuse(string reason) => new([], 0, 0, reason);

    /// <summary>
    /// The objects of one stream. With <paramref name="vm"/> null, the stream is a VM snapshot and only its strings are
    /// read; otherwise refs up to its base object count are the VM snapshot's.
    /// </summary>
    private static Objects Parse(ReadOnlySpan<byte> data, DartSnapshot snapshot, Layout layout, bool compressed, Objects? vm, CancellationToken ct)
    {
        var C = layout.C;
        bool vmOnly = layout.Split && vm == null;
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
        var o = new Objects { Count = objects };
        if (vm != null)
        {
            // The isolate snapshot's base objects are the VM snapshot's objects, in order.
            if (baseObjects != vm.Count) throw new Truncated();
            foreach (var (r, text) in vm.Strings) o.Strings[r] = text;
        }

        // Alloc phase: assigns each cluster its ref range.
        int next = 1 + (int)baseObjects;
        var clusters = new List<Cluster>((int)clusterCount);
        for (long i = 0; i < clusterCount; i++)
        {
            if ((i & 63) == 0) ct.ThrowIfCancellationRequested();
            uint tags = (uint)s.Signed(32);
            var c = new Cluster { Cid = (int)(tags >> 12), Canonical = (tags & 2) != 0, Start = next };
            c.Alloc = AllocOf(layout, c.Cid, compressed);
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
                case Alloc.Classes:
                    // The predefined classes by cid, then the count of new ones.
                    for (long k = 0; k < count; k++) s.Signed(32);
                    long added = s.Unsigned();
                    count += added;
                    break;
            }
            next += (int)count;
            if (next - 1 > objects) throw new Truncated();
            c.Stop = next;
            if (c.Canonical && (c.Cid == C.TypeArguments || c.Cid == C.Type || c.Cid == C.FunctionType || c.Cid == C.RecordType
                || c.Cid == C.TypeParameter || c.Cid == C.String))
            {
                s.Unsigned();
                long first = s.Unsigned();
                for (long k = c.Start + first; k < c.Stop; k++) s.Unsigned();
            }
            clusters.Add(c);
        }
        if (next - 1 != objects) throw new Truncated();

        foreach (var c in clusters)
            if (c.Alloc == Alloc.RoData && (c.Cid == C.String || c.Cid == C.OneByteString || c.Cid == C.TwoByteString))
                for (int k = 0; k < c.Offsets!.Length; k++)
                    if (RoString(layout, data, dataImage + c.Offsets[k]) is { } text) o.Strings[c.Start + k] = text;
        // A VM snapshot's strings come first in its fill phase; without compressed pointers they are all in the data image.
        if (vmOnly && !compressed) return o;

        int length = 0, firstWithCode = 0;
        if (!vmOnly)
        {
            // InstructionsTable::Data: canonical stack map offset, length, first entry with code, padding; then {pc, stack map} pairs.
            long table = dataImage + tableAt + 16;
            if (tableAt <= 0 || table + 16 > data.Length) throw new Truncated();
            length = BinaryPrimitives.ReadInt32LittleEndian(data[(int)(table + 4)..]);
            firstWithCode = BinaryPrimitives.ReadInt32LittleEndian(data[(int)(table + 8)..]);
            if (length < 0 || firstWithCode < 0 || firstWithCode > length || table + 16 + 8L * length > data.Length) throw new Truncated();
            o.Pcs = new uint[length];
            for (int i = 0; i < length; i++) o.Pcs[i] = BinaryPrimitives.ReadUInt32LittleEndian(data[(int)(table + 16 + 8L * i)..]);
            o.FirstWithCode = firstWithCode;
        }

        int codeIndex = 0;
        bool done = false;
        // Fill phase, up to the ClosureData cluster: later clusters name nothing.
        foreach (var c in clusters)
        {
            ct.ThrowIfCancellationRequested();
            int n = c.Stop - c.Start;
            int cid = c.Cid;
            if (vmOnly && cid != C.String && c.Alloc != Alloc.RoData) { done = true; break; }
            switch (c.Alloc)
            {
                case Alloc.RoData or Alloc.Mint:
                    continue;
                case Alloc.Instance:
                    ulong unboxed = (ulong)s.Unsigned();
                    // Fields follow the 8-byte header, in words of 4 bytes with compressed pointers.
                    for (int k = 0; k < n; k++)
                        for (int w = compressed ? 2 : 1; w < c.NextField; w++)
                        {
                            if (w < 64 && (unboxed >> w & 1) != 0) { s.Signed(32); s.Signed(32); }
                            else s.Ref();
                        }
                    continue;
            }
            if (cid == C.ObjectPool)
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
            else if (cid == C.LocalVarDescriptors)
                for (int k = 0; k < n; k++)
                {
                    long count = s.Unsigned();
                    s.Refs(count);
                    for (long e = 0; e < count; e++) { s.Signed(32); s.Signed(32); s.Signed(32); s.Signed(32); s.Signed(64); }
                }
            else if (cid == C.ExceptionHandlers)
                for (int k = 0; k < n; k++)
                {
                    long count = s.Unsigned() >> 1;
                    s.Ref();
                    for (long e = 0; e < count; e++) { s.Signed(32); s.Signed(16); s.Byte(); s.Byte(); s.Byte(); }
                }
            else if (cid == C.ContextScope)
                for (int k = 0; k < n; k++)
                {
                    long count = s.Unsigned();
                    s.Byte();
                    // VariableDesc: ten fields per variable.
                    s.Refs(10 * count);
                }
            else if (cid == C.Array || cid == C.ImmutableArray || cid == C.WeakArray)
                for (int k = 0; k < n; k++)
                {
                    long count = s.Unsigned();
                    s.Refs(cid == C.WeakArray ? count : count + 1);
                }
            else if (cid == C.Double)
                for (int k = 0; k < n; k++) s.Signed(64);
            else if (cid == C.PcDescriptors || cid == C.CodeSourceMap)
                for (int k = 0; k < n; k++) s.Skip(s.Unsigned());
            else if (cid == C.CompressedStackMaps)
                // Flags and size: the size starts at bit 2.
                for (int k = 0; k < n; k++) s.Skip(s.Unsigned() >> 2);
            else if (cid == C.String)
                for (int r = c.Start; r < c.Stop; r++)
                {
                    // Length and cid: bit 0 marks two-byte characters.
                    long encoded = s.Unsigned();
                    var chars = s.Bytes((encoded >> 1) * ((encoded & 1) + 1));
                    o.Strings[r] = (encoded & 1) == 0 ? Encoding.Latin1.GetString(chars) : Encoding.Unicode.GetString(chars);
                }
            else if (cid == C.Float32x4 || cid == C.Int32x4 || cid == C.Float64x2)
                for (int k = 0; k < n; k++) s.Skip(16);
            else if (cid == C.TypeParameter)
                for (int k = 0; k < n; k++) { s.Refs(3); s.Signed(16); s.Signed(16); s.Byte(); }
            else if (cid == C.Type)
                for (int k = 0; k < n; k++) { s.Refs(3); s.Unsigned(); }
            else if (cid == C.FunctionType)
                for (int k = 0; k < n; k++) { s.Refs(6); s.Byte(); s.Signed(32); s.Signed(16); }
            else if (cid == C.RecordType)
                for (int k = 0; k < n; k++) { s.Refs(4); s.Byte(); }
            else if (cid == C.TypeArguments)
                for (int k = 0; k < n; k++)
                {
                    long count = s.Unsigned();
                    s.Signed(32);
                    s.Unsigned();
                    s.Refs(count + 1);
                }
            else if (cid == C.Code)
            {
                if (layout.CodeStubRefs) { s.Ref(); s.Ref(); }
                for (int r = c.Start; r < c.Stop; r++)
                {
                    bool deferred = r >= c.Start + c.Count;
                    uint? pc = null;
                    if (!deferred)
                    {
                        s.Unsigned();
                        int at = firstWithCode + codeIndex++;
                        if (at >= length) throw new Truncated();
                        pc = o.Pcs[at];
                    }
                    int owner = s.Ref();
                    s.Refs(5);
                    o.CodeOwner[r] = (pc, owner);
                    o.CodeRefs.Add(r);
                }
            }
            else if (cid == C.Function)
                for (int r = c.Start; r < c.Stop; r++)
                {
                    int name = s.Ref(), owner = s.Ref();
                    s.Ref();
                    int fdata = s.Ref();
                    long index = s.Unsigned();
                    uint kind = (uint)s.Signed(32);
                    o.Functions[r] = (name, owner, fdata, kind, index);
                }
            else if (cid == C.Closure)
            {
                if (layout.FixedClosures) s.Refs(6L * n);
                else for (int k = 0; k < n; k++) s.Refs(s.Unsigned() + 3);
            }
            else if (cid == C.Record)
                for (int k = 0; k < n; k++) s.Refs(s.Unsigned() & 0xFFFF);
            else if (cid == C.ConstMap || cid == C.ConstSet)
                s.Refs(5L * n);
            else if (cid == C.GrowableObjectArray)
                s.Refs(3L * n);
            else if (cid == DeltaEncodedTypedDataCid)
                for (int k = 0; k < n; k++)
                {
                    long count = s.Unsigned() >> 1;
                    for (long e = 0; e < count; e++) s.Unsigned();
                }
            else if (cid == C.Class)
            {
                int predefined = c.Alloc == Alloc.Classes ? c.Count : 0;
                for (int r = c.Start; r < c.Stop; r++)
                {
                    // name .. invocation_dispatcher_cache: the product AOT snapshot fields.
                    int name = s.Ref();
                    s.Refs(12);
                    int classId = (int)s.Signed(32);
                    s.Signed(32); s.Signed(32); s.Signed(32); s.Signed(16); s.Signed(16); s.Signed(32);
                    // A predefined class always has an unboxed fields bitmap; a new one unless it is a top-level class.
                    if (r < c.Start + predefined || classId < TopLevelCidOffset) s.Unsigned();
                    o.Classes[r] = (name, classId);
                }
            }
            else if (cid == C.PatchClass)
                for (int r = c.Start; r < c.Stop; r++) { o.Patches[r] = s.Ref(); s.Ref(); }
            else if (cid == C.TypeParameters)
                s.Refs(4L * n);
            else if (cid == C.ClosureData)
            {
                for (int r = c.Start; r < c.Stop; r++)
                {
                    o.Parents[r] = s.Ref();
                    s.Ref();
                    s.Unsigned();
                }
                done = true;
            }
            else throw new Truncated();
            if (done) break;
        }
        if (!done && !(vmOnly && clusters.Count > 0)) throw new Truncated();
        return o;
    }

    private static DartProgram Name(Objects o, Layout layout)
    {
        var C = layout.C;
        int length = o.Pcs.Length, firstWithCode = o.FirstWithCode;

        string? OwnerName(int owner)
        {
            if (o.Patches.TryGetValue(owner, out var wrapped)) owner = wrapped;
            if (!o.Classes.TryGetValue(owner, out var cls)) return null;
            return PublicName(C, cls.Cid) ?? ClassName(o.Strings.GetValueOrDefault(cls.Name), layout.PublicFuture);
        }

        string FunctionName(int f, int depth)
        {
            var (name, owner, fdata, kind, _) = o.Functions[f];
            var raw = o.Strings.GetValueOrDefault(name) ?? "<unnamed>";
            var shown = Scrub(raw, raw.Length > 1 && raw.Contains('|'));
            // Function::PrintName: a closure prints its parent first; a constructor prints "new" instead of its class.
            switch (kind & 0x1F)
            {
                case 1:
                    var parent = o.Parents.TryGetValue(fdata, out var p) && o.Functions.ContainsKey(p) && depth < 32 ? FunctionName(p, depth + 1) : "<optimized out>";
                    return parent + "." + shown;
                case 5:
                    return "new " + shown;
            }
            return OwnerName(owner) is { } cls ? cls + "." + shown : shown;
        }

        var named = new Dictionary<uint, string>();
        int namedFunctions = 0;
        foreach (var (f, fn) in o.Functions)
        {
            if (fn.CodeIndex == 0) continue;
            long index = fn.CodeIndex - 1;
            uint? pc = index < firstWithCode ? (index < length ? o.Pcs[(int)index] : null)
                : index - firstWithCode < o.CodeRefs.Count ? o.CodeOwner[o.CodeRefs[(int)(index - firstWithCode)]].Pc : null;
            if (pc is not { } at) continue;
            namedFunctions++;
            named.TryAdd(at, FunctionName(f, 0));
        }
        // Allocation stubs belong to their class.
        foreach (var r in o.CodeRefs)
            if (o.CodeOwner[r] is { Pc: { } at } code && !named.ContainsKey(at) && o.Classes.ContainsKey(code.Owner) && OwnerName(code.Owner) is { } cls)
                named[at] = "new " + cls;
        var list = named.OrderBy(kv => kv.Key).Select(kv => new DartCode(kv.Key, kv.Value)).ToList();
        return new DartProgram(list, namedFunctions, o.CodeRefs.Count, null) { Unnamed = Math.Max(0, length - list.Count), Layout = layout.Release };
    }

    // With compressed pointers the VM writes no read-only data image: these objects are in the stream.
    private static Alloc AllocOf(Layout layout, int cid, bool compressed)
    {
        var C = layout.C;
        if (cid >= C.NumPredefined || cid == C.Instance || cid >= C.FirstFfi && cid <= C.LastFfi) return Alloc.Instance;
        if (cid >= C.FirstTypedData && cid <= C.LastTypedData)
            return (cid - C.FirstTypedData) % 4 == 0 ? Alloc.Lengths : Alloc.Fixed;
        if (cid == C.PcDescriptors || cid == C.CodeSourceMap || cid == C.CompressedStackMaps || cid == C.String || cid == C.OneByteString || cid == C.TwoByteString)
            return compressed ? Alloc.Lengths : Alloc.RoData;
        if (cid == C.TypeArguments || cid == C.ObjectPool || cid == C.LocalVarDescriptors || cid == C.ExceptionHandlers || cid == C.Context
            || cid == C.ContextScope || cid == C.Record || cid == C.Array || cid == C.ImmutableArray || cid == C.WeakArray || cid == DeltaEncodedTypedDataCid
            || cid == C.Closure && !layout.FixedClosures)
            return Alloc.Lengths;
        if (cid == C.Code) return Alloc.Code;
        if (cid == C.Mint) return Alloc.Mint;
        if (cid == C.Class && layout.PredefinedClasses) return Alloc.Classes;
        return Alloc.Fixed;
    }

    /// <summary>A one- or two-byte string object of the data image: tags, Smi length at +8, characters at +16.</summary>
    private static string? RoString(Layout layout, ReadOnlySpan<byte> data, long at)
    {
        if (at < 0 || at + 16 > data.Length) return null;
        int cid = (int)(BinaryPrimitives.ReadUInt32LittleEndian(data[(int)at..]) >> 12);
        long n = BinaryPrimitives.ReadInt64LittleEndian(data[(int)(at + 8)..]) >> 1;
        int size = cid == layout.C.OneByteString ? 1 : cid == layout.C.TwoByteString ? 2 : 0;
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
    private static string? ClassName(string? raw, bool publicFuture)
    {
        if (raw is null or "::") return null;
        int amp = raw.LastIndexOf('&');
        var name = Scrub(amp >= 0 ? raw[(amp + 1)..] : raw);
        // Class::GenerateUserVisibleName checks _Future's library too; libraries are past the clusters read.
        return publicFuture && name == "_Future" ? "Future" : name;
    }

    /// <summary>Class::GenerateUserVisibleName for predefined classes: implementation classes print their public type.</summary>
    private static string? PublicName(Cids c, int cid)
    {
        if (cid == c.Mint || cid == c.Integer || cid == c.Smi) return "int";
        if (cid == c.Double) return "double";
        if (cid == c.OneByteString || cid == c.TwoByteString) return "String";
        if (cid == c.Array || cid == c.ImmutableArray || cid == c.GrowableObjectArray) return "List";
        if (cid == c.Float32x4) return "Float32x4";
        if (cid == c.Int32x4) return "Int32x4";
        if (cid == c.Float64x2) return "Float64x2";
        if (cid == c.Pointer) return "Pointer";
        if (cid == c.DynamicLibrary) return "DynamicLibrary";
        if (cid == c.LibraryPrefix) return "LibraryPrefix";
        if (cid >= c.Null && cid < c.NumPredefined) return Predefined[cid - c.Null];
        if (cid >= c.FirstTypedData && cid <= c.LastTypedData && (cid - c.FirstTypedData) % 4 is 0 or 2) return TypedListNames[(cid - c.FirstTypedData) / 4];
        return null;
    }

    private static readonly string[] Predefined = ["Null", "dynamic", "void", "Never"];

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
