using System.Buffers.Binary;
using Iced.Intel;

namespace NetDecompilerMcp.Native.NativeAot;

public enum NativeAotStaticsKind
{
    /// <summary>A GC statics slot: holds the statics object at run time; fields at [slot] + pointer size + offset.</summary>
    Gc,
    /// <summary>Non-GC statics data in the image; fields at the base + offset.</summary>
    NonGc,
    /// <summary>A thread statics index cell: the type's offset in the module's thread-local block (or its index there).</summary>
    Thread,
}

/// <summary>A static field from the metadata with its offset in the type's statics block.</summary>
public sealed record NativeAotStaticField(string Name, string Type, uint Offset);

/// <summary>
/// A statics base of a type. <see cref="Origin"/> tells how the owner is known: "class constructor context" (the cctor
/// pointer in front of the non-GC statics), "class constructor" (the type's .cctor references it), "code" (most of the
/// named methods that reference it belong to the type) or null when unknown. <see cref="Size"/> is the statics object's
/// field bytes for GC statics and the field extent for non-GC statics (0 when unknown).
/// </summary>
public sealed record NativeAotStaticBase(NativeAotStaticsKind Kind, uint Rva, string? Owner, string? Origin, uint Size, IReadOnlyList<NativeAotStaticField> Fields)
{
    /// <summary>Thread statics: the offset in the module's inlined thread-local block, or the index of a separate block.</summary>
    public long? ThreadIndex { get; init; }
    public bool Preinitialized { get; init; }
}

/// <summary>
/// The statics of a NativeAOT module: GC statics slots from the GCStaticRegion (201; relative pointers from .NET 8,
/// pointers before), each a pointer to its GCStaticEEType with flag bits (GCStaticsNode.cs); non-GC statics behind
/// class constructor contexts (a pointer to the type's .cctor, plus a zero pointer on .NET 7, NonGCStaticsNode.cs);
/// thread statics index cells (TypeManager indirection pointer + natural int, TypeThreadStaticIndexNode.cs). Owners come
/// from the contexts and from the named methods that reference a slot (x64, ARM64 and x86 code); field names from the
/// metadata when it keeps the type's static fields (reflection-visible types only).
/// </summary>
public sealed class NativeAotStatics
{
    private const int MaxFunctionBytes = 1 << 16, MaxStatics = 1_000_000;
    private const uint Uninitialized = 1, HasPreInitializedData = 2;

    private NativeAotStatics() { }

    public IReadOnlyList<NativeAotStaticBase> Bases { get; private set; } = [];
    public NativeAotStage Stage { get; private set; } = new("statics", NativeAotStage.Absent);
    private uint[] starts = [];

    /// <summary>The base at <paramref name="rva"/>, or the non-GC statics whose known extent contains it.</summary>
    public NativeAotStaticBase? At(uint rva)
    {
        int i = Array.BinarySearch(starts, rva);
        if (i >= 0) return Bases[i];
        i = ~i - 1;
        return i >= 0 && Bases[i] is { Kind: NativeAotStaticsKind.NonGc, Size: > 0 } b && rva < b.Rva + b.Size ? b : null;
    }

    public static NativeAotStatics Read(NativeAotImage aot, CancellationToken ct = default)
    {
        var statics = new NativeAotStatics();
        var image = aot.Hydrated;
        uint ptr = (uint)image.PointerSize;
        bool net7 = aot.Format.Layout == MethodTableLayout.Net7;
        var bases = new Dictionary<uint, NativeAotStaticBase>();

        // GC statics slots.
        if (aot.Header.Section(201) is { HasEnd: true } region)
        {
            uint stride = net7 ? ptr : 4;
            for (uint at = region.StartRva; at + stride <= region.EndRva && bases.Count < MaxStatics; at += stride)
            {
                uint? slot = net7 ? image.PointerAt(at) : image.RelativeAt(at);
                if (slot is not { } s || !IsData(aot, s)) continue;
                // The slot holds the GCStaticEEType with the flags in its low bits.
                uint? tagged = net7 ? RawPointer(image, s) : image.RelativeAt(s);
                uint flags = (tagged ?? 0) & 3, size = 0;
                if (tagged is { } t && Read32(image, (t & ~3u) + 4) is { } baseSize && baseSize >= 2 * ptr && baseSize < 1 << 24) size = baseSize - 2 * ptr;
                bases[s] = new NativeAotStaticBase(NativeAotStaticsKind.Gc, s, null, null, size, []) { Preinitialized = (flags & HasPreInitializedData) != 0 };
            }
        }

        // Non-GC statics behind class constructor contexts, and thread statics index cells.
        var cctors = aot.Names.MethodAt.Where(kv => kv.Value.Name.Name == ".cctor").ToDictionary(kv => kv.Key, kv => kv.Value.Name.Owner);
        var frozen = aot.Header.Section(SectionId.FrozenObjectRegion);
        uint header = aot.Header.Rva, headerEnd = header + 16 + (uint)aot.Header.Sections.Count * (2 * ptr + 8);
        uint? typeManager = aot.Header.Section(204)?.StartRva;
        int threadCells = aot.Header.Section(202) is { HasEnd: true } tls ? (int)(tls.Length / ptr) : 0;
        var cells = new Dictionary<uint, uint>(); // indirection cells pointing at GC statics slots
        foreach (uint slot in image.PointerSlots)
        {
            if ((slot & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
            if (bases.Count >= MaxStatics || frozen is { HasEnd: true } f && slot >= f.StartRva && slot < f.EndRva || slot >= header && slot < headerEnd) continue;
            if (image.PointerAt(slot) is not { } target) continue;
            if (bases.TryGetValue(target, out var gcBase) && gcBase.Kind == NativeAotStaticsKind.Gc)
                cells[slot] = target;
            else if (cctors.TryGetValue(aot.CodeAddress(target), out var owner))
            {
                uint at = slot + (net7 ? 2 * ptr : ptr);
                bases.TryAdd(at, new NativeAotStaticBase(NativeAotStaticsKind.NonGc, at, owner, "class constructor context", 0, []));
            }
            else if (target == typeManager && ReadNatural(image, slot + ptr) is { } index && index >= -(1 << 24) && index < Math.Max(threadCells, 1))
            {
                // Inlined thread statics store -(offset + pointer size); others the index of their block.
                long value = index < 0 ? -index - ptr : index;
                bases.TryAdd(slot, new NativeAotStaticBase(NativeAotStaticsKind.Thread, slot, null, null, 0, []) { ThreadIndex = value });
            }
        }

        // Owners of GC slots and thread cells from the code that references them: a static base helper that also references
        // a class constructor context of the type, the type's .cctor, else most of the named methods.
        var contexts = new Dictionary<uint, string>();
        foreach (var b in bases.Values.Where(b => b.Kind == NativeAotStaticsKind.NonGc))
        {
            contexts[b.Rva] = b.Owner!;
            contexts.TryAdd(b.Rva - (net7 ? 2 * ptr : ptr), b.Owner!);
        }
        var wanted = bases.Values.Where(b => b.Owner == null).Select(b => b.Rva).ToHashSet();
        var refs = References(aot, [.. wanted, .. contexts.Keys, .. cells.Keys], ct);
        string? scanned = refs == null ? $"no reference scan for {aot.Image.Arch} code" : null;
        var byTarget = new Dictionary<uint, List<uint>>();
        foreach (var (fn, targets) in refs ?? [])
            foreach (uint t in targets.Select(t => cells.GetValueOrDefault(t, t)).Where(wanted.Contains))
            {
                if (!byTarget.TryGetValue(t, out var list)) byTarget[t] = list = [];
                list.Add(fn);
            }
        foreach (var (rva, functions) in byTarget)
        {
            var b = bases[rva];
            // A static base helper is an unnamed stub that touches one type's class constructor context and statics.
            var helper = functions.Where(fn => !aot.Names.MethodAt.ContainsKey(fn) && refs![fn].Count(wanted.Contains) == 1)
                .SelectMany(fn => refs![fn]).Where(contexts.ContainsKey).Select(t => contexts[t]).Distinct().ToList();
            if (helper.Count == 1)
            {
                bases[rva] = b with { Owner = helper[0], Origin = "static base helper" };
                continue;
            }
            // Votes of the named methods referencing it, a .cctor counting three; the owner needs most of them. Preinitialized
            // statics have no .cctor and are read inline by their users, so only a .cctor vote counts for them.
            var votes = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (uint fn in functions.Distinct())
                if (aot.Names.MethodAt.TryGetValue(fn, out var m) && m.Name.Owner != "?")
                    votes[m.Name.Owner] = votes.GetValueOrDefault(m.Name.Owner) + (m.Name.Name == ".cctor" ? 3 : 1);
            if (votes.Count == 0 || b.Preinitialized && !functions.Any(fn => aot.Names.MethodAt.TryGetValue(fn, out var m) && m.Name.Name == ".cctor")) continue;
            var best = votes.OrderByDescending(v => v.Value).ThenBy(v => v.Key, StringComparer.Ordinal).First();
            if (best.Value >= 2 && 2 * best.Value > votes.Values.Sum())
                bases[rva] = b with { Owner = best.Key, Origin = "code" };
        }

        var fields = new FieldLayout(aot);
        foreach (var rva in bases.Keys.ToList())
            if (bases[rva] is { Kind: not NativeAotStaticsKind.Thread, Owner: { } owner } b && fields.Of(owner, b.Kind) is { Count: > 0 } list)
                bases[rva] = b with { Fields = list, Size = b.Kind == NativeAotStaticsKind.NonGc ? fields.Extent(list) : b.Size };

        var sorted = bases.Values.OrderBy(b => b.Rva).ToList();
        statics.Bases = sorted;
        statics.starts = [.. sorted.Select(b => b.Rva)];
        int gc = sorted.Count(b => b.Kind == NativeAotStaticsKind.Gc), nonGc = sorted.Count(b => b.Kind == NativeAotStaticsKind.NonGc),
            thread = sorted.Count(b => b.Kind == NativeAotStaticsKind.Thread), owned = sorted.Count(b => b.Owner != null), withFields = sorted.Count(b => b.Fields.Count > 0);
        string detail = $"{gc} GC, {nonGc} non-GC, {thread} thread statics; {owned} with their type, {withFields} with field names" + (scanned != null ? $"; {scanned}" : "");
        statics.Stage = sorted.Count == 0 ? new("statics", NativeAotStage.Absent, "no statics found")
            : new("statics", scanned == null ? NativeAotStage.Complete : NativeAotStage.Partial, detail);
        return statics;
    }

    private static bool IsData(NativeAotImage aot, uint rva) => aot.Image.SectionAt(rva) is { IsExecutable: false };

    private static uint? Read32(HydratedImage image, uint rva)
    {
        Span<byte> b = stackalloc byte[4];
        return image.Read(rva, b) == 4 ? BinaryPrimitives.ReadUInt32LittleEndian(b) : null;
    }

    /// <summary>A pointer-sized value as an RVA without bounds checks on the low bits (tagged pointers).</summary>
    private static uint? RawPointer(HydratedImage image, uint rva)
    {
        Span<byte> b = stackalloc byte[8];
        var slot = b[..image.PointerSize];
        if (image.Read(rva, slot) != slot.Length) return null;
        ulong va = slot.Length == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(slot) : BinaryPrimitives.ReadUInt32LittleEndian(slot);
        return va >= image.Image.ImageBase && va - image.Image.ImageBase < image.Image.SizeOfImage ? (uint)(va - image.Image.ImageBase) : null;
    }

    private static long? ReadNatural(HydratedImage image, uint rva)
    {
        Span<byte> b = stackalloc byte[8];
        var slot = b[..image.PointerSize];
        if (image.Read(rva, slot) != slot.Length) return null;
        return slot.Length == 8 ? BinaryPrimitives.ReadInt64LittleEndian(slot) : BinaryPrimitives.ReadInt32LittleEndian(slot);
    }

    /// <summary>
    /// The addresses of <paramref name="wanted"/> each function references (functions from the names and unwind tables):
    /// RIP-relative operands (x64), ADRP pages completed by ADD or a load/store offset (ARM64), relocated absolute
    /// operands (x86). Null for other code.
    /// </summary>
    private static Dictionary<uint, HashSet<uint>>? References(NativeAotImage aot, HashSet<uint> wanted, CancellationToken ct)
    {
        var image = aot.Image;
        if (image.Arch is not (NativeArch.X64 or NativeArch.Arm64 or NativeArch.X86)) return null;
        var result = new Dictionary<uint, HashSet<uint>>();
        if (wanted.Count == 0) return result;
        var starts = aot.Names.MethodAt.Keys.Union(aot.UnwindStarts()).Order().ToArray();
        var relocations = image.Arch == NativeArch.X86 ? image.RelocationRvas.ToArray() : [];
        var buffer = new byte[MaxFunctionBytes];
        void Hit(uint target, uint fn)
        {
            if (!wanted.Contains(target)) return;
            if (!result.TryGetValue(fn, out var set)) result[fn] = set = [];
            set.Add(target);
        }
        for (int i = 0; i < starts.Length; i++)
        {
            if ((i & 0x3FF) == 0) ct.ThrowIfCancellationRequested();
            uint start = starts[i];
            if (image.SectionAt(start) is not { IsExecutable: true }) continue;
            uint end = i + 1 < starts.Length ? starts[i + 1] : start + MaxFunctionBytes;
            int length = (int)Math.Min(end - start, MaxFunctionBytes);
            int n = image.Read(start, buffer.AsSpan(0, length));
            switch (image.Arch)
            {
                case NativeArch.X64:
                    var decoder = Decoder.Create(64, new ByteArrayCodeReader(buffer, 0, n));
                    decoder.IP = image.ImageBase + start;
                    while (decoder.IP < image.ImageBase + start + (ulong)n)
                    {
                        decoder.Decode(out var ins);
                        if (ins.IsInvalid) break;
                        if (ins.IsIPRelativeMemoryOperand && ins.IPRelativeMemoryAddress - image.ImageBase is var t and < uint.MaxValue) Hit((uint)t, start);
                    }
                    break;
                case NativeArch.Arm64:
                    Arm64Pages(buffer.AsSpan(0, n & ~3), start, target => Hit(target, start));
                    break;
                case NativeArch.X86:
                    int r = Array.BinarySearch(relocations, start);
                    for (r = r < 0 ? ~r : r; r < relocations.Length && relocations[r] + 4 <= start + (uint)n; r++)
                    {
                        uint at = relocations[r] - start;
                        uint va = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan((int)at));
                        if (va >= image.ImageBase) Hit((uint)(va - image.ImageBase), start);
                    }
                    break;
            }
        }
        return result;
    }

    /// <summary>ADRP Xd, page then ADD Xd', Xd, #imm or LDR/STR (unsigned offset) via Xd within the next few instructions.</summary>
    private static void Arm64Pages(ReadOnlySpan<byte> code, uint start, Action<uint> hit)
    {
        const int Window = 8;
        Span<long> page = stackalloc long[32];
        Span<int> age = stackalloc int[32];
        age.Fill(int.MaxValue);
        for (int i = 0; i + 4 <= code.Length; i += 4)
        {
            uint w = BinaryPrimitives.ReadUInt32LittleEndian(code[i..]);
            uint pc = start + (uint)i;
            for (int r = 0; r < 32; r++) if (age[r] != int.MaxValue) age[r]++;
            if ((w & 0x9F000000) == 0x90000000) // ADRP
            {
                long imm = ((w >> 29) & 3) | (((long)(w >> 5) & 0x7FFFF) << 2);
                if ((imm & (1L << 20)) != 0) imm -= 1L << 21;
                int rd = (int)(w & 31);
                page[rd] = (pc & ~0xFFFL) + (imm << 12);
                age[rd] = 0;
                continue;
            }
            int rn = (int)((w >> 5) & 31);
            if (age[rn] > Window) continue;
            if ((w & 0xFF800000) == 0x91000000) // ADD Xd, Xn, #imm12 (no shift)
                Emit(page[rn] + ((w >> 10) & 0xFFF));
            else if ((w & 0x3B400000) == 0x39400000 || (w & 0x3B400000) == 0x39000000) // LDR/STR (unsigned immediate), any size
            {
                int scale = (int)(w >> 30);
                if ((w & 0x04800000) == 0x04800000) scale = 4; // 128-bit SIMD
                Emit(page[rn] + (((w >> 10) & 0xFFF) << scale));
            }
        }

        void Emit(long target)
        {
            if (target is > 0 and < uint.MaxValue) hit((uint)target);
        }
    }

    /// <summary>
    /// Static field offsets from the metadata (declaration order, each aligned to its size up to a pointer; references and
    /// structs with references in the GC block). A type is described only when every static field's size is known.
    /// </summary>
    private sealed class FieldLayout(NativeAotImage aot)
    {
        private const int Static = 0x10, Literal = 0x40, HasFieldRva = 0x100;
        private readonly Lazy<Dictionary<string, uint>> definitions = new(() => Definitions(aot));
        private readonly Dictionary<string, NativeAotMethodTable> types = aot.Types.ByRva.Values.GroupBy(t => t.Name, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);

        private static Dictionary<string, uint> Definitions(NativeAotImage aot)
        {
            var result = new Dictionary<string, uint>(StringComparer.Ordinal);
            if (aot.Metadata is not { } md) return result;
            foreach (uint t in md.TypeDefinitions()) result.TryAdd(md.FormatType(new MdHandle(MdRecord.TypeDefinition, t)), t);
            return result;
        }

        public uint Extent(IReadOnlyList<NativeAotStaticField> fields) =>
            fields.Count == 0 ? 0 : fields.Max(f => f.Offset + Size(f.Type).Size);

        public List<NativeAotStaticField>? Of(string owner, NativeAotStaticsKind kind)
        {
            if (aot.Metadata is not { } md || !definitions.Value.TryGetValue(owner, out uint definition)) return null;
            uint gcOffset = 0, nonGcOffset = 0;
            var result = new List<NativeAotStaticField>();
            try
            {
                foreach (uint offset in md.Collection(new MdHandle(MdRecord.TypeDefinition, definition), "fields"))
                {
                    var field = new MdHandle(MdRecord.Field, offset);
                    int flags = md.Int(field, "flags");
                    if ((flags & Static) == 0 || (flags & (Literal | HasFieldRva)) != 0) continue;
                    var signature = new MdHandle(MdRecord.FieldSignature, md.Ref(field, "signature"));
                    string type = NativeAotMetadata.Keyword(md.FormatType(md.Handle(signature, "type")));
                    var (size, gc) = Size(type);
                    if (size == 0) return null;
                    uint align = Math.Min(size, (uint)aot.Hydrated.PointerSize);
                    ref uint at = ref gc ? ref gcOffset : ref nonGcOffset;
                    at = (at + align - 1) / align * align;
                    if (gc == (kind == NativeAotStaticsKind.Gc)) result.Add(new NativeAotStaticField(md.StringField(field, "name") ?? "?", type, at));
                    at += size;
                }
            }
            catch (Exception e) when (e is NativeAotFormatException or ReadyToRun.R2RFormatException or ArgumentException) { return null; }
            return result;
        }

        /// <summary>A field type's size and whether it holds GC references; size 0 when unknown.</summary>
        private (uint Size, bool Gc) Size(string type)
        {
            uint ptr = (uint)aot.Hydrated.PointerSize;
            switch (type)
            {
                case "bool" or "byte" or "sbyte": return (1, false);
                case "char" or "short" or "ushort": return (2, false);
                case "int" or "uint" or "float": return (4, false);
                case "long" or "ulong" or "double": return (8, false);
                case "nint" or "nuint": return (ptr, false);
                case "string" or "object": return (ptr, true);
            }
            if (type.EndsWith('*')) return (ptr, false);
            if (type.EndsWith(']')) return (ptr, true);
            if (!types.TryGetValue(type, out var mt)) return (0, false);
            return mt.ElementType switch
            {
                NativeAotElementType.Class or NativeAotElementType.Interface or NativeAotElementType.SystemArray => (ptr, true),
                >= NativeAotElementType.Boolean and <= NativeAotElementType.Double => (Primitive(mt.ElementType, ptr), false), // enums
                _ => (0, false), // structs: padding and GC layout are not recorded
            };
        }

        private static uint Primitive(NativeAotElementType e, uint ptr) => e switch
        {
            NativeAotElementType.Boolean or NativeAotElementType.SByte or NativeAotElementType.Byte => 1,
            NativeAotElementType.Char or NativeAotElementType.Int16 or NativeAotElementType.UInt16 => 2,
            NativeAotElementType.Int32 or NativeAotElementType.UInt32 or NativeAotElementType.Single => 4,
            NativeAotElementType.IntPtr or NativeAotElementType.UIntPtr => ptr,
            _ => 8,
        };
    }
}
