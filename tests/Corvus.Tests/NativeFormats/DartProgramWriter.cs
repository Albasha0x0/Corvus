using System.Buffers.Binary;
using System.Text;

namespace Corvus.Tests.NativeFormats;

/// <summary>
/// Builds a Dart 3.13 AOT program snapshot (product, x64) in an ELF image: one-byte strings, then Code, Function, Class
/// and ClosureData clusters, and an instructions table that places each code. Strings go in the data image, or in the
/// stream when <see cref="Features"/> names compressed-pointers. Ref 1 is the only base object (null). With
/// <see cref="Split"/>, a Dart 3.12 VM snapshot holds the first half of the strings and an isolate snapshot the rest,
/// numbered on from the VM snapshot's objects; classes with predefined cids lead the Class cluster.
/// </summary>
internal sealed class DartProgramWriter
{
    public const string DefaultFeatures = "product no-dwarf_stack_traces x64 linux no-compressed-pointers";
    public const int CodeSpacing = 0x20;

    private readonly List<string> _strings = [];
    private readonly List<(int Name, int Cid)> _classes = [];
    private readonly List<(int Name, int Owner, int Kind, int Data, int? Code, bool Discarded)> _functions = [];
    private readonly List<int> _closureParents = [];
    private readonly List<int?> _codeOwners = [];
    private int _discarded;

    public string Features { get; init; } = DefaultFeatures;
    public bool Split { get; init; }

    // Dart 3.12's kNumPredefinedCids.
    private const int Predefined312 = 175;

    // Ref layout: 1 null, then strings, codes, functions, classes, closure data.
    private int StringRef(int i) => 2 + i;
    private int CodeRef(int i) => 2 + _strings.Count + i;
    private int FunctionRef(int i) => CodeRef(_codeOwners.Count) + i;
    private int ClassRef(int i) => FunctionRef(_functions.Count) + i;
    private int ClosureDataRef(int i) => ClassRef(_classes.Count) + i;

    private int Text(string s)
    {
        int i = _strings.IndexOf(s);
        if (i < 0) { i = _strings.Count; _strings.Add(s); }
        return i;
    }

    /// <summary>Adds a class (a cid at or above 1 &lt;&lt; 20 is a library's top-level class) and returns its index.</summary>
    public int Class(string name, int cid)
    {
        _classes.Add((Text(name), cid));
        return _classes.Count - 1;
    }

    /// <summary>
    /// Adds a function of <paramref name="kind"/> (UntaggedFunction::Kind) owned by class <paramref name="owner"/>, with
    /// code of its own unless <paramref name="discarded"/> (code kept only in the instructions table); returns its index.
    /// </summary>
    public int Function(string name, int owner, int kind = 0, int? closureParent = null, bool discarded = false)
    {
        int data = -1;
        if (closureParent is { } parent)
        {
            data = _closureParents.Count;
            _closureParents.Add(parent);
        }
        int? code = null;
        if (discarded) _discarded++;
        else
        {
            code = _codeOwners.Count;
            _codeOwners.Add(-1 - _functions.Count);
        }
        _functions.Add((Text(name), owner, kind, data, code, discarded));
        return _functions.Count - 1;
    }

    /// <summary>Adds code owned by class <paramref name="owner"/> (an allocation stub), or by nothing (a VM stub).</summary>
    public void Stub(int? owner) => _codeOwners.Add(owner);

    /// <summary>The address <see cref="Build"/> gives function <paramref name="index"/>'s code: the text start plus its table entry.</summary>
    public uint AddressOf(int index)
    {
        var f = _functions[index];
        int entry = f.Discarded ? _functions.Take(index + 1).Count(x => x.Discarded) - 1 : _discarded + f.Code!.Value;
        return ElfWriter.TextRva + (uint)(entry * CodeSpacing);
    }

    public uint StubAddress(int codeIndex) => ElfWriter.TextRva + (uint)((_discarded + codeIndex) * CodeSpacing);

    public int CodeCount => _codeOwners.Count;

    public byte[] Build()
    {
        bool compressed = Features.Split(' ').Contains("compressed-pointers");
        int vmStrings = Split ? _strings.Count / 2 : 0;
        int predefined = Split ? _classes.TakeWhile(c => c.Cid < Predefined312).Count() : 0;
        if (Split && _classes.Skip(predefined).Any(c => c.Cid < Predefined312)) throw new InvalidOperationException("predefined classes go first");
        var stream = new List<byte>();
        int objects = 1 + _strings.Count + _codeOwners.Count + _functions.Count + _classes.Count + _closureParents.Count;
        var isolateStrings = _strings.Skip(vmStrings).ToList();
        int clusters = isolateStrings.Count > 0 ? 5 : 4;

        // Data image: strings at 16-byte aligned offsets, then InstructionsTable::Data as a one-byte string's payload.
        var image = new List<byte>(new byte[16]);
        var offsets = StringObjects(image, isolateStrings);
        int tableAt = image.Count;
        int entries = _discarded + _codeOwners.Count;
        var table = new byte[16 + 8 * entries];
        BinaryPrimitives.WriteInt32LittleEndian(table.AsSpan(4), entries);
        BinaryPrimitives.WriteInt32LittleEndian(table.AsSpan(8), _discarded);
        for (int i = 0; i < entries; i++) BinaryPrimitives.WriteUInt32LittleEndian(table.AsSpan(16 + 8 * i), (uint)(i * CodeSpacing));
        image.AddRange(StringObject(94, table));

        Unsigned(stream, 1 + vmStrings);
        Unsigned(stream, objects);
        Unsigned(stream, clusters);
        Unsigned(stream, entries);
        Unsigned(stream, tableAt);

        if (isolateStrings.Count > 0) StringAlloc(stream, isolateStrings, offsets, compressed);
        Signed(stream, 18 << 12);
        Unsigned(stream, _codeOwners.Count);
        foreach (var _ in _codeOwners) Signed(stream, 0);
        Unsigned(stream, 0);
        Signed(stream, 7 << 12);
        Unsigned(stream, _functions.Count);
        Signed(stream, 5 << 12);
        if (Split)
        {
            // Predefined classes by cid, then the count of new ones.
            Unsigned(stream, predefined);
            foreach (var (_, cid) in _classes.Take(predefined)) Signed(stream, cid);
            Unsigned(stream, _classes.Count - predefined);
        }
        else Unsigned(stream, _classes.Count);
        Signed(stream, 9 << 12);
        Unsigned(stream, _closureParents.Count);

        // Fill: strings when in the stream, then Code, Function, Class, ClosureData.
        if (compressed) StringFill(stream, isolateStrings);
        if (!Split)
        {
            Ref(stream, 1);
            Ref(stream, 1);
        }
        foreach (var owner in _codeOwners)
        {
            Unsigned(stream, 0);
            Ref(stream, owner switch { null => 1, < 0 => FunctionRef(-1 - owner.Value), _ => ClassRef(owner.Value) });
            for (int k = 0; k < 5; k++) Ref(stream, 1);
        }
        int discardedSeen = 0;
        foreach (var f in _functions)
        {
            Ref(stream, StringRef(f.Name));
            Ref(stream, ClassRef(f.Owner));
            Ref(stream, 1);
            Ref(stream, f.Data >= 0 ? ClosureDataRef(f.Data) : 1);
            Unsigned(stream, f.Discarded ? 1 + discardedSeen++ : 1 + _discarded + f.Code!.Value);
            Signed(stream, f.Kind);
        }
        for (int i = 0; i < _classes.Count; i++)
        {
            var (name, cid) = _classes[i];
            Ref(stream, StringRef(name));
            for (int k = 0; k < 12; k++) Ref(stream, 1);
            Signed(stream, cid);
            for (int k = 0; k < 3; k++) Signed(stream, 2);
            Signed(stream, 0);
            Signed(stream, 0);
            Signed(stream, 0);
            if (i < predefined || cid < 1 << 20) Unsigned(stream, 0);
        }
        foreach (var parent in _closureParents)
        {
            Ref(stream, FunctionRef(parent));
            Ref(stream, 1);
            Unsigned(stream, 0);
        }

        var isolate = Block(stream, image, Split ? 3 : 2);
        var vm = Array.Empty<byte>();
        if (Split)
        {
            // The VM snapshot: null, then its strings; no instructions table.
            var vmStream = new List<byte>();
            var vmImage = new List<byte>(new byte[16]);
            var vmText = _strings.Take(vmStrings).ToList();
            var vmOffsets = StringObjects(vmImage, vmText);
            Unsigned(vmStream, 1);
            Unsigned(vmStream, 1 + vmStrings);
            Unsigned(vmStream, vmStrings > 0 ? 1 : 0);
            Unsigned(vmStream, 0);
            Unsigned(vmStream, 0);
            if (vmStrings > 0)
            {
                StringAlloc(vmStream, vmText, vmOffsets, compressed);
                if (compressed) StringFill(vmStream, vmText);
            }
            var block = Block(vmStream, vmImage, 3);
            vm = new byte[(block.Length + 63) / 64 * 64];
            block.CopyTo(vm, 0);
        }
        byte[] data = [.. vm, .. isolate];

        var text = new byte[Math.Max(1, entries) * CodeSpacing];
        Array.Fill(text, (byte)0xC3);
        uint isolateRva = ElfWriter.DataRva + (uint)vm.Length;
        return new ElfWriter
        {
            Machine = ElfWriter.EmX64, Text = text, Data = data,
            Symbols = Split
                ?
                [
                    new("_kDartVmSnapshotInstructions", ElfWriter.TextRva, 0, Type: 2),
                    new("_kDartIsolateSnapshotInstructions", ElfWriter.TextRva, (uint)text.Length, Type: 2),
                    new("_kDartVmSnapshotData", ElfWriter.DataRva, (uint)vm.Length, Type: 1),
                    new("_kDartIsolateSnapshotData", isolateRva, (uint)isolate.Length, Type: 1),
                ]
                :
                [
                    new("_kDartSnapshotText", ElfWriter.TextRva, (uint)text.Length, Type: 2),
                    new("_kDartSnapshotData", ElfWriter.DataRva, (uint)data.Length, Type: 1),
                ],
        }.Build();
    }

    private static List<int> StringObjects(List<byte> image, List<string> strings)
    {
        var offsets = new List<int>();
        foreach (var s in strings)
        {
            offsets.Add(image.Count);
            image.AddRange(StringObject(94, Encoding.Latin1.GetBytes(s)));
        }
        return offsets;
    }

    /// <summary>A string cluster's alloc. In the stream a string's length and cid are one value: length &lt;&lt; 1, bit 0 for two-byte characters.</summary>
    private static void StringAlloc(List<byte> stream, List<string> strings, List<int> offsets, bool compressed)
    {
        Signed(stream, (compressed ? 93 : 94) << 12);
        Unsigned(stream, strings.Count);
        int previous = 0;
        if (compressed) foreach (var t in strings) Unsigned(stream, t.Length << 1);
        else foreach (var o in offsets) { Unsigned(stream, (o - previous) >> 4); previous = o; }
    }

    private static void StringFill(List<byte> stream, List<string> strings)
    {
        foreach (var t in strings)
        {
            Unsigned(stream, t.Length << 1);
            stream.AddRange(Encoding.Latin1.GetBytes(t));
        }
    }

    /// <summary>A snapshot of <paramref name="kind"/>: header, features, the stream, then its data image at the next 64-byte boundary.</summary>
    private byte[] Block(List<byte> stream, List<byte> image, int kind)
    {
        var header = new List<byte>(new byte[20]);
        header.AddRange(Encoding.ASCII.GetBytes("0451907c2eaa8467e848c0067bfe8ed4"));
        header.AddRange(Encoding.ASCII.GetBytes(Features));
        header.Add(0);
        header.AddRange(stream);
        var snapshot = header.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(snapshot, 0xdcdcf5f5);
        BinaryPrimitives.WriteInt64LittleEndian(snapshot.AsSpan(4), snapshot.Length - 4);
        BinaryPrimitives.WriteInt64LittleEndian(snapshot.AsSpan(12), kind);
        var data = new byte[(snapshot.Length + 63) / 64 * 64 + image.Count];
        snapshot.CopyTo(data, 0);
        image.CopyTo(data, (snapshot.Length + 63) / 64 * 64);
        return data;
    }

    /// <summary>A string object: tags with the class id, a Smi length at +8, the bytes at +16, padded to 16.</summary>
    private static byte[] StringObject(int cid, byte[] bytes)
    {
        var o = new byte[(16 + bytes.Length + 15) / 16 * 16];
        BinaryPrimitives.WriteUInt32LittleEndian(o, (uint)cid << 12);
        BinaryPrimitives.WriteInt64LittleEndian(o.AsSpan(8), (long)bytes.Length << 1);
        bytes.CopyTo(o, 16);
        return o;
    }

    /// <summary>WriteUnsigned: 7-bit groups, low first; the last byte has the high bit set.</summary>
    internal static void Unsigned(List<byte> to, long v)
    {
        for (; v > 127; v >>= 7) to.Add((byte)(v & 127));
        to.Add((byte)(v + 128));
    }

    /// <summary>Write&lt;T&gt; for multi-byte types: 7-bit groups, low first; the last group biased by 192.</summary>
    internal static void Signed(List<byte> to, long v)
    {
        for (; v is < -64 or > 63; v >>= 7) to.Add((byte)(v & 127));
        to.Add((byte)(v + 192));
    }

    /// <summary>WriteRefId: the ref's high 7-bit groups first, then its low group with the top bit set.</summary>
    internal static void Ref(List<byte> to, int r)
    {
        var high = new Stack<byte>();
        for (int q = r >> 7; q > 0; q >>= 7) high.Push((byte)(q & 127));
        to.AddRange(high);
        to.Add((byte)(0x80 | (r & 127)));
    }
}
