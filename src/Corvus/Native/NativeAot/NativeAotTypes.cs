using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;

namespace Corvus.Native.NativeAot;

/// <summary>EETypeElementType (MethodTable.Constants.cs); identical in .NET 7–11.</summary>
public enum NativeAotElementType : byte
{
    Unknown = 0x00, Void = 0x01, Boolean = 0x02, Char = 0x03, SByte = 0x04, Byte = 0x05, Int16 = 0x06, UInt16 = 0x07,
    Int32 = 0x08, UInt32 = 0x09, Int64 = 0x0A, UInt64 = 0x0B, IntPtr = 0x0C, UIntPtr = 0x0D, Single = 0x0E, Double = 0x0F,
    ValueType = 0x10, Nullable = 0x12, Class = 0x14, Interface = 0x15, SystemArray = 0x16, Array = 0x17, SzArray = 0x18,
    ByRef = 0x19, Pointer = 0x1A, FunctionPointer = 0x1B,
}

/// <summary>A MethodTable; addresses are RVAs (0 for null); <see cref="NameOrigin"/> names where its name came from.</summary>
public sealed record NativeAotMethodTable(uint Rva, uint Flags, ushort ComponentSize, uint BaseSize, NativeAotElementType ElementType,
    string Kind, uint RelatedType, IReadOnlyList<uint> Vtable, IReadOnlyList<uint> Interfaces)
{
    public uint GenericDefinition { get; init; }
    public IReadOnlyList<uint> GenericArguments { get; init; } = [];
    public bool HasFinalizer { get; init; }
    public bool HasDispatchMap { get; init; }
    /// <summary>The interface dispatch map (.NET 8+), 0 when none or unreadable.</summary>
    public uint DispatchMap { get; init; }
    /// <summary>The sealed vtable: 32-bit relative pointers to the code of slots past <see cref="Vtable"/> (.NET 8+), 0 when none.</summary>
    public uint SealedVTable { get; init; }
    public string Name { get; init; } = "";
    public string NameOrigin { get; init; } = "generated";
}

/// <summary>An interface method a type implements: the interface's MethodTable (0 when out of range), its slot, and the implementing slot and code.</summary>
public sealed record NativeAotInterfaceImpl(uint Interface, int InterfaceSlot, int ImplSlot, uint Code);

/// <summary>Discovers and names the MethodTables of a NativeAOT module (.NET 7 to 9+ layouts) by a fixed point from seeds.</summary>
public sealed class NativeAotTypes
{
    private const int MaxSlots = 4096, MaxInterfaces = 1024, MaxTypes = 1_000_000, MaxNameDepth = 16;

    private NativeAotTypes() { }

    public IReadOnlyDictionary<uint, NativeAotMethodTable> ByRva { get; private set; } = new Dictionary<uint, NativeAotMethodTable>();
    public NativeAotStage Stage { get; private set; } = new("method tables", NativeAotStage.Absent);
    private Reader? reader;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<uint, NativeAotMethodTable?> others = new();

    /// <summary>The MethodTable at <paramref name="rva"/>: a found one, else one read on demand (not crawled), null when invalid.</summary>
    public NativeAotMethodTable? At(uint rva) =>
        ByRva.TryGetValue(rva, out var mt) ? mt
        : reader == null ? null
        : others.GetOrAdd(rva, r => reader.TryRead(r, out var read) ? read with { Name = $"MT_{r:X}" } : null);

    /// <summary>The code of vtable slot <paramref name="slot"/>, past the end from the sealed vtable; 0 when unknown.</summary>
    public uint SlotCode(NativeAotMethodTable mt, int slot)
    {
        if (slot < 0) return 0;
        if (slot < mt.Vtable.Count) return mt.Vtable[slot];
        int sealedSlot = slot - mt.Vtable.Count;
        if (mt.SealedVTable == 0 || hydrated == null || sealedSlot >= MaxSlots) return 0;
        return hydrated.RelativeAt(mt.SealedVTable + 4 * (uint)sealedSlot) is { } code && hydrated.Image.SectionAt(code) is { IsExecutable: true } ? NativeAotImage.CodeAddress(hydrated.Image, code) : 0;
    }

    /// <summary>Instance interface methods <paramref name="mt"/> implements itself, from its dispatch map; inherited ones are not listed.</summary>
    public IReadOnlyList<NativeAotInterfaceImpl> Implementations(NativeAotMethodTable mt)
    {
        var result = new List<NativeAotInterfaceImpl>();
        if (mt.DispatchMap == 0 || hydrated == null) return result;
        Span<byte> b = stackalloc byte[6];
        if (hydrated.Read(mt.DispatchMap, b[..2]) != 2) return result;
        int count = BinaryPrimitives.ReadUInt16LittleEndian(b);
        for (int i = 0; i < count; i++)
        {
            if (hydrated.Read(mt.DispatchMap + 8 + 6 * (uint)i, b) != 6) break;
            int index = BinaryPrimitives.ReadUInt16LittleEndian(b), interfaceSlot = BinaryPrimitives.ReadUInt16LittleEndian(b[2..]),
                implSlot = BinaryPrimitives.ReadUInt16LittleEndian(b[4..]);
            result.Add(new NativeAotInterfaceImpl(index < mt.Interfaces.Count ? mt.Interfaces[index] : 0, interfaceSlot, implSlot, SlotCode(mt, implSlot)));
        }
        return result;
    }

    private HydratedImage? hydrated;

    public static NativeAotTypes Read(NativeAotImage aot, CancellationToken ct = default)
    {
        var types = new NativeAotTypes();
        var reader = types.reader = new Reader(aot);
        types.hydrated = aot.Hydrated;
        var found = reader.Crawl(ct);
        var named = new Namer(aot, found).NameAll();
        types.ByRva = named;
        var origins = named.Values.GroupBy(m => m.NameOrigin).OrderBy(g => g.Key, StringComparer.Ordinal).Select(g => $"{g.Count()} {g.Key}");
        string detail = $"{named.Count} found ({string.Join(", ", origins)}); seeds: {reader.SeedSummary}" + (reader.Truncated ? "; stopped at the type limit" : "");
        types.Stage = new("method tables", aot.Format.Exact && !reader.Truncated ? NativeAotStage.Complete : NativeAotStage.Partial, detail);
        return types;
    }

    /// <summary>Flag masks of one layout.</summary>
    private sealed record Masks(uint ElementShift, uint ElementMask, uint KindMask, uint KindParameterized, uint KindGenericDefinition, uint KindFunctionPointer,
        uint HasComponentSize, uint HasFinalizer, uint HasDispatchMap, uint HasSealedVTable, uint GenericVariance, uint OptionalFields, uint IsGeneric)
    {
        public static Masks For(MethodTableLayout layout) => layout switch
        {
            MethodTableLayout.Net7 => new(11, 0x1F, 0x3, 0x2, 0x3, uint.MaxValue, 0, 0x10, 0, 0, 0x80, 0x100, 0x400),
            MethodTableLayout.Net8 => new(26, 0x1F, 0x30000, 0x20000, 0x30000, 0x10000, 0x80000000, 0x100000, 0x40000, 0x400000, 0x800000, 0x01000000, 0x02000000),
            _ => new(26, 0x1F, 0x30000, 0x20000, 0x30000, 0x10000, 0x80000000, 0x100000, 0x40000, 0x400000, 0x800000, 0, 0x02000000),
        };
    }

    /// <summary>Offset of vtable slot 0: flags, BaseSize, RelatedType, slot and interface counts, hash code (MethodTable.h).</summary>
    public static uint VtableOffset(int pointerSize) => 16 + (uint)pointerSize;

    private sealed class Reader(NativeAotImage aot)
    {
        private readonly HydratedImage image = aot.Hydrated;
        private readonly uint ptr = (uint)aot.Hydrated.PointerSize;
        private uint VtableStart => VtableOffset((int)ptr);
        private readonly MethodTableLayout layout = aot.Format.Layout;
        private readonly Masks masks = Masks.For(aot.Format.Layout);
        private readonly NativeAotSection? frozen = aot.Header.Section(SectionId.FrozenObjectRegion);
        private readonly Dictionary<uint, NativeAotMethodTable> known = [];
        public string SeedSummary { get; private set; } = "";
        public bool Truncated { get; private set; }

        private bool IsData(uint rva) => image.Image.SectionAt(rva) is { IsExecutable: false };

        private bool IsCode(uint rva) => image.Image.SectionAt(rva) is { IsExecutable: true };

        private bool InFrozen(uint rva) => frozen is { HasEnd: true } f && rva >= f.StartRva && rva < f.EndRva;

        public Dictionary<uint, NativeAotMethodTable> Crawl(CancellationToken ct)
        {
            var work = new Stack<uint>();
            int typeMap = 0, fixups = 0, objects = 0;
            void Seed(uint rva, ref int count)
            {
                if (TryAdd(rva, work)) count++;
            }
            foreach (uint mt in aot.Names.TypeNames.Keys) Seed(mt, ref typeMap);
            foreach (uint target in aot.Names.CommonFixups) if (target != 0 && IsData(target)) Seed(target, ref fixups);
            foreach (uint obj in ObjectCandidates(ct)) Seed(obj, ref objects);
            SeedSummary = $"{typeMap} type map, {fixups} fixups, {objects} System.Object";

            // Every pointer slot by target: a known MethodTable's referrers at slot - 8 may be MethodTables whose RelatedType it is.
            var referrers = new Dictionary<uint, List<uint>>();
            foreach (uint slot in image.PointerSlots)
            {
                if (InFrozen(slot) || slot < 8) continue;
                if (image.PointerAt(slot) is not { } target) continue;
                if (!referrers.TryGetValue(target, out var list)) referrers[target] = list = [];
                list.Add(slot);
            }
            while (work.Count > 0)
            {
                ct.ThrowIfCancellationRequested();
                var mt = known[work.Pop()];
                if (referrers.TryGetValue(mt.Rva, out var slots))
                    foreach (uint slot in slots) TryAdd(slot - 8, work);
                foreach (uint i in mt.Interfaces) TryAdd(i, work);
                TryAdd(mt.RelatedType, work);
                TryAdd(mt.GenericDefinition, work);
                foreach (uint a in mt.GenericArguments) TryAdd(a, work);
            }
            return known;
        }

        private bool TryAdd(uint rva, Stack<uint> work)
        {
            if (rva == 0 || known.ContainsKey(rva) || InFrozen(rva) || !IsData(rva)) return false;
            if (known.Count >= MaxTypes) { Truncated = true; return false; }
            if (!TryRead(rva, out var mt)) return false;
            known[rva] = mt;
            work.Push(rva);
            return true;
        }

        /// <summary>System.Object: a class with a BaseSize of three pointers, no related type, no interfaces and three virtual slots (ToString, Equals, GetHashCode) into code.</summary>
        private IEnumerable<uint> ObjectCandidates(CancellationToken ct)
        {
            var found = new List<uint>();
            foreach (var section in image.Image.Sections)
            {
                if (section.IsExecutable) continue;
                ct.ThrowIfCancellationRequested();
                var bytes = new byte[NativeAotLocator.FileBytes(image.Image, section)];
                int n = image.Read(section.Rva, bytes);
                int counts = 8 + (int)ptr;
                for (int at = 0; at + VtableStart + 3 * ptr <= n; at += (int)ptr)
                {
                    var b = bytes.AsSpan(at);
                    ulong related = ptr == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(b[8..]) : BinaryPrimitives.ReadUInt32LittleEndian(b[8..]);
                    if (BinaryPrimitives.ReadUInt32LittleEndian(b[4..]) != 3 * ptr || related != 0
                        || BinaryPrimitives.ReadUInt16LittleEndian(b[counts..]) != 3 || BinaryPrimitives.ReadUInt16LittleEndian(b[(counts + 2)..]) != 0) continue;
                    uint rva = section.Rva + (uint)at;
                    if (InFrozen(rva) || !TryRead(rva, out var mt) || mt.ElementType != NativeAotElementType.Class || mt.Vtable.Any(v => v == 0)) continue;
                    found.Add(rva);
                    // Ambiguous: rely on the other seeds.
                    if (found.Count > 1) return [];
                }
            }
            return found;
        }

        private uint U32(uint rva)
        {
            Span<byte> b = stackalloc byte[4];
            return image.Read(rva, b) == 4 ? BinaryPrimitives.ReadUInt32LittleEndian(b) : throw new NativeAotFormatException("outside the image");
        }

        private ushort U16(uint rva)
        {
            Span<byte> b = stackalloc byte[2];
            return image.Read(rva, b) == 2 ? BinaryPrimitives.ReadUInt16LittleEndian(b) : throw new NativeAotFormatException("outside the image");
        }

        /// <summary>Pointer at <paramref name="rva"/>: 0 for null, null when the slot holds anything but an image address.</summary>
        private uint? Pointer(uint rva)
        {
            Span<byte> b = stackalloc byte[8];
            var slot = b[..(int)ptr];
            if (image.Read(rva, slot) != slot.Length) return null;
            ulong v = ptr == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(slot) : BinaryPrimitives.ReadUInt32LittleEndian(slot);
            if (v == 0) return 0;
            return image.PointerAt(rva);
        }

        public bool TryRead(uint rva, [NotNullWhen(true)] out NativeAotMethodTable? mt)
        {
            mt = null;
            try { return Read(rva, out mt); }
            catch (Exception e) when (e is NativeAotFormatException or ReadyToRun.R2RFormatException) { return false; }
        }

        private bool Read(uint rva, [NotNullWhen(true)] out NativeAotMethodTable? mt)
        {
            mt = null;
            uint flags;
            ushort component = 0;
            if (layout == MethodTableLayout.Net7)
            {
                component = U16(rva);
                flags = U16(rva + 2);
            }
            else
            {
                flags = U32(rva);
                if ((flags & masks.HasComponentSize) != 0) component = (ushort)flags;
            }
            var element = (NativeAotElementType)((flags >> (int)masks.ElementShift) & masks.ElementMask);
            if ((byte)element > 0x1B || element is (NativeAotElementType)0x11 or (NativeAotElementType)0x13) return false;
            uint kind = flags & masks.KindMask;
            uint baseSize = U32(rva + 4);
            if (Pointer(rva + 8) is not { } related || related != 0 && !IsData(related)) return false;
            ushort slots = U16(rva + 8 + ptr), interfaces = U16(rva + 10 + ptr);
            if (slots > MaxSlots || interfaces > MaxInterfaces) return false;
            bool canonical = kind == 0;
            // String's base size is 2 pointers + 6.
            if (canonical && element is not NativeAotElementType.Interface && (baseSize < (ptr == 8 ? 0x10u : 12u) || baseSize > 1 << 24)) return false;
            // Statics bases and instantiation cells are the usual look-alikes: a boxed primitive or enum is exactly
            // header + MethodTable pointer + 8 bytes (4 or 8 on 32-bit), and only classes, structs and interfaces are generic.
            if (element == NativeAotElementType.Unknown) return false;
            if (element <= NativeAotElementType.Double && (!canonical || (ptr == 8 ? baseSize != 0x18 : baseSize is not (12 or 16)))) return false;
            if (kind == masks.KindGenericDefinition && element is not (NativeAotElementType.Class or NativeAotElementType.ValueType
                    or NativeAotElementType.Interface or NativeAotElementType.Nullable)) return false;

            var vtable = new uint[slots];
            for (int i = 0; i < slots; i++)
            {
                // Code, or data for the generic dictionary slot of types deriving from a generic instantiation.
                if (Pointer(rva + VtableStart + ptr * (uint)i) is not { } target) return false;
                vtable[i] = IsCode(target) ? aot.CodeAddress(target) : target;
            }
            uint at = rva + VtableStart + ptr * (uint)slots;
            var ifaces = new uint[interfaces];
            for (int i = 0; i < interfaces; i++)
            {
                if (Pointer(at + ptr * (uint)i) is not { } target || target == 0 || !IsData(target)) return false;
                ifaces[i] = target;
            }
            at += ptr * (uint)interfaces;
            string kindName = Kind(kind, element);
            mt = new NativeAotMethodTable(rva, flags, component, baseSize, element, kindName, related, vtable, ifaces)
            {
                HasFinalizer = (flags & masks.HasFinalizer) != 0,
                HasDispatchMap = (flags & masks.HasDispatchMap) != 0,
            };
            mt = layout == MethodTableLayout.Net7 ? Tail7(mt, at, kind) : Tail(mt, at, kind);
            return true;
        }

        /// <summary>.NET 7 tail fields after the interfaces (32-bit relative pointers).</summary>
        private NativeAotMethodTable Tail7(NativeAotMethodTable mt, uint at, uint kind)
        {
            const uint HasSealedVTableEntries = 0x200;
            at += 8; // TypeManager indirection, writable data
            if (mt.HasFinalizer) at += 4;
            uint rare = 0;
            if ((mt.Flags & masks.OptionalFields) != 0)
            {
                if (image.RelativeAt(at) is { } fields && IsData(fields))
                {
                    var optional = OptionalFields(fields);
                    rare = optional.GetValueOrDefault(0);
                    // The table's row has a start only.
                    if (optional.TryGetValue(1, out uint index) && aot.Header.Section(203) is { } table && index < MaxTypes
                        && image.PointerAt(table.StartRva + index * ptr) is { } map && IsData(map))
                        mt = mt with { DispatchMap = map, HasDispatchMap = true };
                }
                at += 4;
            }
            if ((rare & HasSealedVTableEntries) != 0)
            {
                mt = mt with { SealedVTable = image.RelativeAt(at) is { } sealedSlots && IsData(sealedSlots) ? sealedSlots : 0 };
                at += 4;
            }
            if ((mt.Flags & masks.IsGeneric) == 0 || kind == masks.KindGenericDefinition) return mt;
            uint definition = Direct(image.RelativeAt(at) ?? 0);
            if (definition == 0 || !IsData(definition)) return mt;
            mt = mt with { GenericDefinition = definition };
            if (image.RelativeAt(at + 4) is not { } composition || !IsData(composition)) return mt;
            uint arity = U16(composition);
            if (arity is 0 or > 64) return mt;
            var args = new uint[arity];
            for (uint i = 0; i < arity; i++)
            {
                uint arg = Direct(Pointer(composition + ptr + i * ptr) ?? 0);
                if (arg == 0 || !IsData(arg)) return mt;
                args[i] = arg;
            }
            return mt with { GenericArguments = args };
        }

        /// <summary>A type reference that may go through an indirection cell (low bit set): the MethodTable it names.</summary>
        private uint Direct(uint target) => (target & 1) == 0 ? target : image.PointerAt(target & ~1u) ?? 0;

        /// <summary>The .NET 7 optional fields: tag bytes (0x80 on the last) each followed by a NativeFormat unsigned value.</summary>
        private Dictionary<int, uint> OptionalFields(uint rva)
        {
            var fields = new Dictionary<int, uint>();
            for (int i = 0; i < 8; i++)
            {
                byte tag = U8(rva++);
                rva = ReadyToRun.NativeFormat.DecodeUnsigned(image.View, rva, out uint value);
                fields[tag & 0x7F] = value;
                if ((tag & 0x80) != 0) break;
            }
            return fields;
        }

        private byte U8(uint rva)
        {
            Span<byte> b = stackalloc byte[1];
            return image.Read(rva, b) == 1 ? b[0] : throw new NativeAotFormatException("outside the image");
        }

        private string Kind(uint kind, NativeAotElementType element)
        {
            if (kind == masks.KindGenericDefinition) return "generic definition";
            if (kind == masks.KindFunctionPointer) return "function pointer";
            return element switch
            {
                NativeAotElementType.Interface => "interface",
                NativeAotElementType.Class or NativeAotElementType.SystemArray => "class",
                NativeAotElementType.SzArray or NativeAotElementType.Array => "array",
                NativeAotElementType.Pointer => "pointer",
                NativeAotElementType.ByRef => "byref",
                NativeAotElementType.Nullable => "nullable",
                NativeAotElementType.ValueType => "struct",
                <= NativeAotElementType.Double => "primitive",
                _ => "other",
            };
        }

        /// <summary>.NET 8+ tail fields after the interfaces (32-bit relative pointers).</summary>
        private NativeAotMethodTable Tail(NativeAotMethodTable mt, uint at, uint kind)
        {
            at += 8; // TypeManager indirection, writable data
            if (mt.HasDispatchMap)
            {
                mt = mt with { DispatchMap = image.RelativeAt(at) is { } map && IsData(map) ? map : 0 };
                at += 4;
            }
            if (mt.HasFinalizer) at += 4;
            if ((mt.Flags & masks.OptionalFields) != 0) at += 4;
            if ((mt.Flags & masks.HasSealedVTable) != 0)
            {
                mt = mt with { SealedVTable = image.RelativeAt(at) is { } sealedSlots && IsData(sealedSlots) ? sealedSlots : 0 };
                at += 4;
            }
            if ((mt.Flags & masks.IsGeneric) == 0 || kind == masks.KindGenericDefinition) return mt;
            uint definition = image.RelativeAt(at) ?? 0;
            if (definition == 0 || !IsData(definition)) return mt;
            // The definition's generic parameter count: its ComponentSize on .NET 8, its BaseSize from .NET 9.
            uint arity = (layout == MethodTableLayout.Net8 ? U32(definition) : U32(definition + 4)) & 0xFFFF;
            if (arity is 0 or > 64) return mt with { GenericDefinition = definition };
            uint composition = at + 4;
            uint list = arity == 1 ? composition : image.RelativeAt(composition) ?? 0;
            if (list == 0) return mt with { GenericDefinition = definition };
            var args = new uint[arity];
            for (uint i = 0; i < arity; i++)
            {
                uint arg = image.RelativeAt(list + 4 * i) ?? 0;
                if (arg == 0 || !IsData(arg)) return mt with { GenericDefinition = definition };
                args[i] = arg;
            }
            return mt with { GenericDefinition = definition, GenericArguments = args };
        }
    }

    /// <summary>Names: type map, then generic composition, element types, the owner of the methods a class introduces, else MT_&lt;rva&gt;.</summary>
    private sealed class Namer(NativeAotImage aot, Dictionary<uint, NativeAotMethodTable> types)
    {
        private readonly Dictionary<uint, (string Name, string Origin)> names = [];

        public Dictionary<uint, NativeAotMethodTable> NameAll()
        {
            var result = new Dictionary<uint, NativeAotMethodTable>(types.Count);
            foreach (var (rva, mt) in types)
            {
                var (name, origin) = Name(rva, 0);
                result[rva] = mt with { Name = name, NameOrigin = origin };
            }
            return result;
        }

        private (string Name, string Origin) Name(uint rva, int depth)
        {
            if (names.TryGetValue(rva, out var cached)) return cached;
            if (aot.Names.TypeNames.TryGetValue(rva, out var mapped)) return names[rva] = (mapped, "typemap");
            if (!types.TryGetValue(rva, out var mt)) return ($"MT_{rva:X}", "generated");
            if (depth > MaxNameDepth) return ($"MT_{rva:X}", "generated");
            (string, string) named;
            if (mt.GenericDefinition != 0 && mt.GenericArguments.Count > 0)
            {
                string definition = Name(mt.GenericDefinition, depth + 1).Name;
                int tick = definition.LastIndexOf('`');
                if (tick > definition.LastIndexOf('+') && tick > definition.LastIndexOf('.')) definition = definition[..tick];
                named = ($"{definition}<{string.Join(", ", mt.GenericArguments.Select(a => NativeAotMetadata.Keyword(Name(a, depth + 1).Name)))}>", "composition");
            }
            else if (mt.ElementType is NativeAotElementType.SzArray or NativeAotElementType.Array or NativeAotElementType.Pointer or NativeAotElementType.ByRef
                     && mt.RelatedType != 0 && mt.Kind is not "generic definition")
            {
                string element = NativeAotMetadata.Keyword(Name(mt.RelatedType, depth + 1).Name);
                string suffix = mt.ElementType switch
                {
                    NativeAotElementType.SzArray => "[]",
                    NativeAotElementType.Array => "[*]",
                    NativeAotElementType.Pointer => "*",
                    _ => "&",
                };
                named = (element + suffix, "element");
            }
            else if (VtableOwner(mt) is { } owner)
            {
                named = (owner, "vtable");
            }
            else
            {
                named = ($"MT_{rva:X}", "generated");
            }
            return names[rva] = named;
        }

        /// <summary>The most common owner of the named methods in the slots a class introduces or overrides.</summary>
        private string? VtableOwner(NativeAotMethodTable mt)
        {
            if (mt.ElementType is not (NativeAotElementType.Class or NativeAotElementType.ValueType) || mt.Kind != "class" && mt.Kind != "struct") return null;
            types.TryGetValue(mt.RelatedType, out var parent);
            var owners = new Dictionary<string, int>(StringComparer.Ordinal);
            for (int i = 0; i < mt.Vtable.Count; i++)
            {
                uint target = mt.Vtable[i];
                if (target == 0 || parent != null && i < parent.Vtable.Count && parent.Vtable[i] == target) continue;
                if (aot.Names.MethodAt.TryGetValue(target, out var method) && method.Name.Owner != "?")
                    owners[method.Name.Owner] = owners.GetValueOrDefault(method.Name.Owner) + 1;
            }
            return owners.Count == 0 ? null : owners.OrderByDescending(o => o.Value).ThenBy(o => o.Key, StringComparer.Ordinal).First().Key;
        }
    }
}
