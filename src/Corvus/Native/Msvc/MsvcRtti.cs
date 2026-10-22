using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Corvus.Native.Msvc;

/// <summary>A class recovered from MSVC RTTI: its hierarchy and the vftables of its subobjects.</summary>
/// <param name="Name">Qualified name, demangled ("ns::Widget").</param>
/// <param name="DecoratedName">Type descriptor name (".?AVWidget@ns@@").</param>
/// <param name="Kind">"class" or "struct".</param>
/// <param name="Bases">The hierarchy descriptor's base class array without the class itself, in its (preorder) order.</param>
/// <param name="Vtables">One per complete object locator, ordered by subobject offset.</param>
/// <param name="Issues">Inconsistencies between locators of this class; the class is still reported.</param>
/// <param name="Pascal">The VMT's own data for an Object Pascal class; null for C++.</param>
public sealed record MsvcRttiClass(
    string Name,
    string DecoratedName,
    string Kind,
    uint TypeDescriptorRva,
    uint HierarchyRva,
    MsvcHierarchyAttributes Attributes,
    IReadOnlyList<MsvcRttiBase> Bases,
    IReadOnlyList<MsvcRttiVtable> Vtables,
    IReadOnlyList<string> Issues,
    Pascal.PascalClass? Pascal = null);

[Flags]
public enum MsvcHierarchyAttributes : uint
{
    None = 0,
    MultipleInheritance = 1,
    VirtualInheritance = 2,
    Ambiguous = 4,
}

[Flags]
public enum MsvcBaseAttributes : uint
{
    None = 0,
    NotVisible = 0x01,
    Ambiguous = 0x02,
    PrivateOrProtectedBase = 0x04,
    PrivateOrProtectedInCompleteObject = 0x08,
    VirtualBaseOfContainedObject = 0x10,
    NonPolymorphic = 0x20,
    HasHierarchyDescriptor = 0x40,
}

/// <summary>
/// One entry of a base class array. <see cref="Mdisp"/> is the member displacement; for a virtual base
/// (<see cref="Pdisp"/> &gt;= 0) the base is found through the vbtable at <see cref="Pdisp"/>, entry <see cref="Vdisp"/>.
/// </summary>
/// <param name="Depth">1 for a direct base, 2 for a base of a direct base, ...</param>
/// <param name="Parent">Index in <see cref="MsvcRttiClass.Bases"/> of the base this one belongs to; null for direct bases.</param>
public sealed record MsvcRttiBase(
    string Name,
    uint TypeDescriptorRva,
    uint DescriptorRva,
    int ContainedBases,
    int Mdisp,
    int Pdisp,
    int Vdisp,
    MsvcBaseAttributes Attributes,
    int Depth,
    int? Parent)
{
    public bool IsVirtual => Pdisp >= 0;
}

/// <param name="Offset">Offset of the subobject this vftable belongs to in the complete object.</param>
/// <param name="ConstructorDisplacementOffset">Offset of the constructor displacement (vtordisp) field, 0 when none.</param>
/// <param name="SlotRvas">Targets of the slots, in order.</param>
/// <param name="EndReason">Why slot enumeration stopped.</param>
public sealed record MsvcRttiVtable(
    uint LocatorRva,
    uint Offset,
    uint ConstructorDisplacementOffset,
    uint VftableRva,
    IReadOnlyList<uint> SlotRvas,
    string EndReason);

/// <summary>A candidate structure that did not pass validation.</summary>
public sealed record MsvcRttiSkip(uint Rva, string Kind, string Reason);

public sealed record MsvcRttiStats(
    int TypeDescriptors,
    int Locators,
    int Classes,
    int Vtables,
    int TypeDescriptorCandidatesRejected,
    int LocatorCandidatesRejected,
    int LocatorsWithoutVtable,
    long BytesScanned,
    bool UsedRelocations,
    int CodeReferences,
    TimeSpan Elapsed);

/// <param name="TypeDescriptors">Every validated class/struct/union/enum type descriptor (RVA, decorated name), including types without vftables.</param>
/// <param name="Skipped">Rejected candidates with the reason, capped at <see cref="MsvcRttiOptions.MaxSkippedReported"/>; the totals are in <see cref="Stats"/>.</param>
/// <param name="Notes">Whole-image observations: why nothing was scanned, limits reached.</param>
public sealed record MsvcRttiResult(
    IReadOnlyList<MsvcRttiClass> Classes,
    IReadOnlyList<(uint Rva, string Name)> TypeDescriptors,
    IReadOnlyList<MsvcRttiSkip> Skipped,
    IReadOnlyList<string> Notes,
    MsvcRttiStats Stats);

public sealed record MsvcRttiOptions
{
    public static readonly MsvcRttiOptions Default = new();

    public int MaxSkippedReported { get; init; } = 1000;
    public int MaxSlots { get; init; } = 4096;
    public int MaxBaseClasses { get; init; } = 4096;
    /// <summary>Sections larger than this are not scanned (reported in the notes).</summary>
    public long MaxSectionBytes { get; init; } = 512L << 20;

    /// <summary>
    /// Data addresses (RVAs) that code references, e.g. from a disassembly cross-reference index. A vftable ends before a
    /// slot that code references, since that is the start of another table. When null, references are collected from the
    /// image: on x86 from relocated absolute operands in code, on x64 from RIP-relative LEA/MOV operands.
    /// </summary>
    public IReadOnlyCollection<uint>? CodeReferences { get; init; }
}

/// <summary>
/// Recovers MSVC RTTI from an image: type descriptors (".?AV" names after the type_info vftable pointer), complete
/// object locators (x64/ARM64 signature 1 with image-relative fields and a self RVA; x86 signature 0 with VAs),
/// class hierarchy descriptors and base class arrays, and the vftables that follow a pointer to a locator.
/// Every structure is validated against the others; candidates that fail are reported with the reason.
/// </summary>
public static class MsvcRtti
{
    private const string TypeDescriptorKind = "type descriptor";
    private const string LocatorKind = "complete object locator";

    public static MsvcRttiResult Analyze(INativeImage image, MsvcRttiOptions? options = null, CancellationToken ct = default)
    {
        options ??= MsvcRttiOptions.Default;
        var sw = Stopwatch.StartNew();
        var a = new Analyzer(image, options, ct);
        a.Run();
        sw.Stop();
        return a.Result(sw.Elapsed);
    }

    private sealed record TypeDescriptor(uint Rva, string Name, string Bare, string Kind);

    private sealed record Hierarchy(uint Rva, MsvcHierarchyAttributes Attributes, uint ClassTypeDescriptor, List<MsvcRttiBase> Bases);

    private sealed record Locator(uint Rva, uint Offset, uint CdOffset, uint TypeDescriptor, uint Hierarchy);

    private sealed class Analyzer(INativeImage image, MsvcRttiOptions options, CancellationToken ct)
    {
        private readonly bool is64 = image.Is64Bit;
        private readonly int ptr = image.Is64Bit ? 8 : 4;
        /// <summary>x86 and ARM32 locators hold VAs (signature 0); 64-bit ones hold RVAs (signature 1).</summary>
        private readonly bool rvaBased = image.Is64Bit;
        private readonly Dictionary<NativeSection, byte[]> data = [];
        private readonly List<NativeSection> sections = image.Sections.OrderBy(s => s.Rva).ToList();
        private readonly Dictionary<uint, TypeDescriptor?> typeDescriptors = [];
        private readonly Dictionary<uint, (Hierarchy? Value, string? Error)> hierarchies = [];
        /// <summary>Hierarchy descriptors being read (a base class descriptor may point back to one of them).</summary>
        private readonly HashSet<uint> reading = [];
        private readonly List<Locator> locators = [];
        private readonly List<MsvcRttiSkip> skipped = [];
        private readonly List<string> notes = [];
        private readonly HashSet<uint> relocations = image.RelocationRvas.Count > 0 ? [.. image.RelocationRvas] : [];
        private readonly Dictionary<uint, List<MsvcRttiVtable>> vtablesByLocator = [];
        private HashSet<uint> codeReferences = [];
        private int tdRejected, colRejected, colWithoutVtable;
        private long bytesScanned;

        private bool UseRelocations => relocations.Count > 0;

        public void Run()
        {
            if (image.Arch == NativeArch.Unknown)
            {
                notes.Add("unknown architecture: nothing scanned");
                return;
            }
            LoadSections();
            FindTypeDescriptors();
            FindLocators();
            FindVtables();
        }

        private void LoadSections()
        {
            foreach (var s in sections)
            {
                if (s.RawSize == 0 || s.MappedSize == 0 || s.Rva >= image.SizeOfImage) continue;
                // RTTI is initialized data: the zero fill past a section's file bytes holds none.
                long length = image.FileBytesLength(s);
                if (length == 0) continue;
                if (length > options.MaxSectionBytes || bytesScanned + length > 2 * options.MaxSectionBytes)
                {
                    notes.Add($"section {s.Name} ({length} bytes) is larger than the scan limit; not scanned");
                    continue;
                }
                var buffer = new byte[length];
                int n = image.Read(s.Rva, buffer);
                if (n < buffer.Length) Array.Resize(ref buffer, n);
                data[s] = buffer;
                bytesScanned += buffer.Length;
            }
        }

        private bool TryGet(uint rva, int length, out ReadOnlySpan<byte> span)
        {
            span = default;
            foreach (var s in sections)
            {
                if (!s.Contains(rva)) continue;
                if (!data.TryGetValue(s, out var buffer)) return false;
                ulong off = rva - s.Rva;
                if (off + (ulong)length > (ulong)buffer.Length) return false;
                span = buffer.AsSpan((int)off, length);
                return true;
            }
            return false;
        }

        private bool TryU32(uint rva, out uint value)
        {
            value = 0;
            if (!TryGet(rva, 4, out var s)) return false;
            value = BinaryPrimitives.ReadUInt32LittleEndian(s);
            return true;
        }

        private bool TryI32(uint rva, out int value)
        {
            bool ok = TryU32(rva, out var u);
            value = unchecked((int)u);
            return ok;
        }

        private bool TryPointer(uint rva, out ulong value)
        {
            value = 0;
            if (!TryGet(rva, ptr, out var s)) return false;
            value = ptr == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(s) : BinaryPrimitives.ReadUInt32LittleEndian(s);
            return true;
        }

        /// <summary>A VA inside the image, as an RVA.</summary>
        private bool TryVaToRva(ulong va, out uint rva)
        {
            rva = 0;
            if (va < image.ImageBase) return false;
            ulong r = va - image.ImageBase;
            if (r >= image.SizeOfImage || r > uint.MaxValue) return false;
            rva = (uint)r;
            return true;
        }

        /// <summary>A locator/descriptor reference: an RVA in 64-bit images, a VA (32-bit field) otherwise.</summary>
        private bool TryReference(uint fieldRva, out uint target)
        {
            target = 0;
            if (!TryU32(fieldRva, out var raw)) return false;
            if (rvaBased)
            {
                if (raw == 0 || raw >= image.SizeOfImage) return false;
                target = raw;
                return true;
            }
            return raw != 0 && TryVaToRva(raw, out target);
        }

        private bool IsExecutable(uint rva) => image.SectionAt(rva) is { IsExecutable: true };

        private void Skip(uint rva, string kind, string reason)
        {
            if (skipped.Count < options.MaxSkippedReported)
                skipped.Add(new MsvcRttiSkip(rva, kind, reason));
        }

        private void FindTypeDescriptors()
        {
            ReadOnlySpan<byte> marker = ".?A"u8;
            foreach (var (s, buffer) in data)
            {
                int at = 0;
                while (at < buffer.Length)
                {
                    ct.ThrowIfCancellationRequested();
                    int k = buffer.AsSpan(at).IndexOf(marker);
                    if (k < 0) break;
                    int nameOffset = at + k;
                    at = nameOffset + 1;
                    long tdOffset = nameOffset - 2L * ptr;
                    if (tdOffset < 0) continue;
                    uint rva = s.Rva + (uint)tdOffset;
                    if (typeDescriptors.ContainsKey(rva)) continue;
                    var td = ReadTypeDescriptor(rva, out var reason);
                    typeDescriptors[rva] = td;
                    if (td == null)
                    {
                        tdRejected++;
                        Skip(rva, TypeDescriptorKind, reason!);
                    }
                }
            }
        }

        /// <summary>Validated on first use; also called for descriptors referenced by locators and base class descriptors.</summary>
        private TypeDescriptor? GetTypeDescriptor(uint rva, out string? reason)
        {
            reason = null;
            if (typeDescriptors.TryGetValue(rva, out var known))
            {
                if (known == null) reason = "type descriptor failed validation";
                return known;
            }
            var td = ReadTypeDescriptor(rva, out reason);
            typeDescriptors[rva] = td;
            return td;
        }

        private TypeDescriptor? ReadTypeDescriptor(uint rva, out string? reason)
        {
            reason = null;
            if (rva % ptr != 0) { reason = "not pointer-aligned"; return null; }
            if (!TryPointer(rva, out var vfptr) || !TryPointer(rva + (uint)ptr, out var spare)) { reason = "unreadable"; return null; }
            if (!TryVaToRva(vfptr, out _)) { reason = $"type_info vftable pointer 0x{vfptr:X} is outside the image"; return null; }
            if (spare != 0) { reason = "runtime cache field is not zero"; return null; }
            var name = ReadName(rva + 2u * (uint)ptr, out reason);
            if (name == null) return null;
            var decoded = MsvcDemangler.DemangleTypeDescriptorName(name);
            if (decoded == null) { reason = $"name {name} does not demangle"; return null; }
            var kind = name.StartsWith(".?AU", StringComparison.Ordinal) ? "struct"
                : name.StartsWith(".?AV", StringComparison.Ordinal) ? "class"
                : name.StartsWith(".?AT", StringComparison.Ordinal) ? "union" : "enum";
            return new TypeDescriptor(rva, name, decoded.Value.Name, kind);
        }

        private string? ReadName(uint rva, out string? reason)
        {
            reason = null;
            var sb = new StringBuilder();
            for (int i = 0; i < 4096; i++)
            {
                if (!TryGet(rva + (uint)i, 1, out var b)) { reason = "name runs past the section"; return null; }
                byte c = b[0];
                if (c == 0) return sb.ToString();
                if (c < 0x21 || c > 0x7E) { reason = $"name has byte 0x{c:X2}"; return null; }
                sb.Append((char)c);
            }
            reason = "name longer than 4096 bytes";
            return null;
        }

        private void FindLocators()
        {
            var tdVas = rvaBased ? null : typeDescriptors.Where(t => t.Value != null).Select(t => (uint)(image.ImageBase + t.Key)).ToHashSet();
            uint tdLow = tdVas?.Count > 0 ? tdVas.Min() : 0, tdHigh = tdVas?.Count > 0 ? tdVas.Max() : 0;
            if (!rvaBased && tdVas!.Count == 0) return;
            foreach (var (s, buffer) in data)
            {
                var words = Words(s, buffer, out var baseRva);
                int i = 0;
                while (i < words.Length)
                {
                    ct.ThrowIfCancellationRequested();
                    uint rva;
                    if (rvaBased)
                    {
                        // signature 1, then offset, cdOffset, descriptor RVAs, and the locator's own RVA at +20
                        int k = words[i..].IndexOf(1u);
                        if (k < 0) break;
                        i += k;
                        rva = baseRva + 4u * (uint)i;
                        bool candidate = i + 6 <= words.Length && words[i + 5] == rva;
                        i++;
                        if (!candidate) continue;
                    }
                    else
                    {
                        // a type descriptor VA at +12 of a signature 0 locator with plausible offsets and a descriptor VA in the image
                        int k = words[i..].IndexOfAnyInRange(tdLow, tdHigh);
                        if (k < 0) break;
                        i += k;
                        int at = i - 3;
                        i++;
                        if (at < 0 || at + 5 > words.Length || words[at] != 0 || !tdVas!.Contains(words[at + 3])) continue;
                        if (words[at + 1] > 0x1000_0000 || words[at + 2] > 0x1000_0000 || !TryVaToRva(words[at + 4], out _)) continue;
                        rva = baseRva + 4u * (uint)at;
                    }
                    var col = ReadLocator(rva, out var reason);
                    if (col == null)
                    {
                        colRejected++;
                        Skip(rva, LocatorKind, reason!);
                        continue;
                    }
                    locators.Add(col);
                }
            }
        }

        /// <summary>The 4-aligned words of a section; <paramref name="baseRva"/> is the RVA of the first one.</summary>
        private static ReadOnlySpan<uint> Words(NativeSection s, byte[] buffer, out uint baseRva)
        {
            int first = (int)(((s.Rva + 3) & ~3u) - s.Rva);
            baseRva = s.Rva + (uint)first;
            if (first >= buffer.Length) return default;
            return MemoryMarshal.Cast<byte, uint>(buffer.AsSpan(first, (buffer.Length - first) & ~3));
        }

        private Locator? ReadLocator(uint rva, out string? reason)
        {
            reason = null;
            if (!TryU32(rva + 4, out var offset) || !TryU32(rva + 8, out var cdOffset)) { reason = "unreadable"; return null; }
            if (offset > 0x1000_0000 || cdOffset > 0x1000_0000) { reason = $"implausible offsets {offset}/{cdOffset}"; return null; }
            if (!TryReference(rva + 12, out var tdRva)) { reason = "type descriptor reference is outside the image"; return null; }
            if (!TryReference(rva + 16, out var chdRva)) { reason = "hierarchy descriptor reference is outside the image"; return null; }
            var td = GetTypeDescriptor(tdRva, out var tdReason);
            if (td == null) { reason = $"type descriptor at 0x{tdRva:X}: {tdReason}"; return null; }
            var chd = GetHierarchy(chdRva, out var chdReason);
            if (chd == null) { reason = $"hierarchy descriptor at 0x{chdRva:X}: {chdReason}"; return null; }
            if (chd.ClassTypeDescriptor != tdRva) { reason = "hierarchy descriptor describes a different class"; return null; }
            return new Locator(rva, offset, cdOffset, tdRva, chdRva);
        }

        private Hierarchy? GetHierarchy(uint rva, out string? reason)
        {
            if (!hierarchies.TryGetValue(rva, out var entry))
            {
                if (reading.Count >= 64)
                {
                    reason = "hierarchy descriptors nested more than 64 deep";
                    return null;
                }
                reading.Add(rva);
                var h = ReadHierarchy(rva, out var error);
                reading.Remove(rva);
                hierarchies[rva] = entry = (h, error);
            }
            reason = entry.Error;
            return entry.Value;
        }

        private Hierarchy? ReadHierarchy(uint rva, out string? reason)
        {
            reason = null;
            if (rva % 4 != 0) { reason = "not 4-aligned"; return null; }
            if (!TryU32(rva, out var signature) || !TryU32(rva + 4, out var attributes) || !TryI32(rva + 8, out var count)) { reason = "unreadable"; return null; }
            if (signature != 0) { reason = $"signature {signature}, expected 0"; return null; }
            if ((attributes & ~7u) != 0) { reason = $"unknown attribute bits 0x{attributes:X}"; return null; }
            if (count < 1 || count > options.MaxBaseClasses) { reason = $"base class count {count}"; return null; }
            if (!TryReference(rva + 12, out var arrayRva)) { reason = "base class array reference is outside the image"; return null; }

            var entries = new List<(uint Rva, TypeDescriptor Td, int Contained, int Mdisp, int Pdisp, int Vdisp, uint Attributes)>(count);
            for (int i = 0; i < count; i++)
            {
                ct.ThrowIfCancellationRequested();
                if (!TryReference(arrayRva + 4u * (uint)i, out var bcd)) { reason = $"base class array entry {i} is outside the image"; return null; }
                var e = ReadBaseDescriptor(bcd, out var bcdReason);
                if (e == null) { reason = $"base class descriptor {i} at 0x{bcd:X}: {bcdReason}"; return null; }
                // only the class's own entry may point back to a hierarchy that is still being read: this one
                if (e.Value.PendingHierarchy is uint pending && (i != 0 || pending != rva))
                {
                    reason = $"base class descriptor {i} points to hierarchy descriptor 0x{pending:X}, which is still being read (a cycle)";
                    return null;
                }
                entries.Add((bcd, e.Value.Td, e.Value.Contained, e.Value.Mdisp, e.Value.Pdisp, e.Value.Vdisp, e.Value.Attributes));
            }

            // entry 0 is the class itself and contains all others; the rest is a preorder tree of nested ranges
            var self = entries[0];
            if (self.Contained != count - 1) { reason = $"class entry contains {self.Contained} bases, array has {count - 1}"; return null; }
            if (self.Mdisp != 0 || self.Pdisp != -1 || self.Vdisp != 0) { reason = "class entry has a non-zero displacement"; return null; }
            var bases = new List<MsvcRttiBase>(count - 1);
            var stack = new Stack<(int Index, int End)>();
            stack.Push((0, count - 1));
            for (int i = 1; i < count; i++)
            {
                while (i > stack.Peek().End) stack.Pop();
                var (parent, parentEnd) = stack.Peek();
                var e = entries[i];
                int end = i + e.Contained;
                if (e.Contained < 0 || end > parentEnd) { reason = $"base {i} contains {e.Contained} bases past its parent's range"; return null; }
                bases.Add(new MsvcRttiBase(e.Td.Bare, e.Td.Rva, e.Rva, e.Contained, e.Mdisp, e.Pdisp, e.Vdisp,
                    (MsvcBaseAttributes)e.Attributes, stack.Count, parent == 0 ? null : parent - 1));
                stack.Push((i, end));
            }
            return new Hierarchy(rva, (MsvcHierarchyAttributes)attributes, self.Td.Rva, bases);
        }

        /// <summary>A base class descriptor; <c>PendingHierarchy</c> is set when its own hierarchy pointer leads to one being read.</summary>
        private (TypeDescriptor Td, int Contained, int Mdisp, int Pdisp, int Vdisp, uint Attributes, uint? PendingHierarchy)? ReadBaseDescriptor(uint rva, out string? reason)
        {
            reason = null;
            if (rva % 4 != 0) { reason = "not 4-aligned"; return null; }
            if (!TryReference(rva, out var tdRva)) { reason = "type descriptor reference is outside the image"; return null; }
            if (!TryI32(rva + 4, out var contained) || !TryI32(rva + 8, out var mdisp) || !TryI32(rva + 12, out var pdisp)
                || !TryI32(rva + 16, out var vdisp) || !TryU32(rva + 20, out var attributes)) { reason = "unreadable"; return null; }
            if ((attributes & ~0x7Fu) != 0) { reason = $"unknown attribute bits 0x{attributes:X}"; return null; }
            if (contained < 0 || contained > options.MaxBaseClasses) { reason = $"contained base count {contained}"; return null; }
            if (mdisp < 0 || mdisp > 0x1000_0000) { reason = $"member displacement {mdisp}"; return null; }
            if (pdisp < -1 || pdisp > 0x1000_0000) { reason = $"vbptr displacement {pdisp}"; return null; }
            if (pdisp == -1 ? vdisp != 0 : vdisp < 0 || vdisp % 4 != 0) { reason = $"vbtable displacement {vdisp} with vbptr displacement {pdisp}"; return null; }
            var td = GetTypeDescriptor(tdRva, out var tdReason);
            if (td == null) { reason = $"type descriptor at 0x{tdRva:X}: {tdReason}"; return null; }
            uint? pending = null;
            if ((attributes & (uint)MsvcBaseAttributes.HasHierarchyDescriptor) != 0)
            {
                if (!TryReference(rva + 24, out var chdRva)) { reason = "own hierarchy descriptor reference is outside the image"; return null; }
                if (reading.Contains(chdRva))
                    pending = chdRva;
                else
                {
                    var chd = GetHierarchy(chdRva, out var chdReason);
                    if (chd == null) { reason = $"own hierarchy descriptor at 0x{chdRva:X}: {chdReason}"; return null; }
                    if (chd.ClassTypeDescriptor != tdRva) { reason = "own hierarchy descriptor describes a different class"; return null; }
                }
            }
            return (td, contained, mdisp, pdisp, vdisp, attributes, pending);
        }

        private void FindVtables()
        {
            if (locators.Count == 0) return;
            var byVa = locators.ToDictionary(l => image.ImageBase + l.Rva, l => l);
            ulong low = byVa.Keys.Min(), high = byVa.Keys.Max();
            var metaSlots = new HashSet<uint>();
            var found = new List<(uint Slot, Locator Col)>();
            void Hit(uint rva, ulong value)
            {
                if (!byVa.TryGetValue(value, out var col)) return;
                if (UseRelocations && !relocations.Contains(rva)) return; // a constant that happens to equal the address
                metaSlots.Add(rva);
                found.Add((rva, col));
            }
            foreach (var (s, buffer) in data)
            {
                ct.ThrowIfCancellationRequested();
                int first = (int)((((s.Rva + (uint)ptr - 1) & ~((uint)ptr - 1))) - s.Rva);
                if (first >= buffer.Length) continue;
                var bytes = buffer.AsSpan(first, (buffer.Length - first) & ~(ptr - 1));
                uint baseRva = s.Rva + (uint)first;
                if (ptr == 8)
                {
                    var values = MemoryMarshal.Cast<byte, ulong>(bytes);
                    for (int i = 0; ; i++)
                    {
                        int k = values[i..].IndexOfAnyInRange(low, high);
                        if (k < 0) break;
                        i += k;
                        Hit(baseRva + 8u * (uint)i, values[i]);
                    }
                }
                else
                {
                    var values = MemoryMarshal.Cast<byte, uint>(bytes);
                    for (int i = 0; ; i++)
                    {
                        int k = values[i..].IndexOfAnyInRange((uint)low, (uint)high);
                        if (k < 0) break;
                        i += k;
                        Hit(baseRva + 4u * (uint)i, values[i]);
                    }
                }
            }
            codeReferences = CollectCodeReferences();
            foreach (var (slot, col) in found)
            {
                uint vftable = slot + (uint)ptr;
                var slots = new List<uint>();
                string end = EnumerateSlots(vftable, metaSlots, slots);
                if (slots.Count == 0) continue; // not a vftable: the next slot is not code
                if (!vtablesByLocator.TryGetValue(col.Rva, out var list)) vtablesByLocator[col.Rva] = list = [];
                list.Add(new MsvcRttiVtable(col.Rva, col.Offset, col.CdOffset, vftable, slots, end));
            }
            foreach (var col in locators)
                if (!vtablesByLocator.ContainsKey(col.Rva))
                {
                    colWithoutVtable++;
                    Skip(col.Rva, LocatorKind, "no vftable follows a pointer to this locator");
                }
        }

        /// <summary>
        /// Data RVAs referenced from code: x86 absolute operands (relocated words in executable sections), x64 RIP-relative
        /// "lea/mov r64, [rip+disp32]" operands. Targets in executable sections are kept too: images that merge read-only
        /// data into code keep their vftables there, and a code address never coincides with a slot.
        /// </summary>
        private HashSet<uint> CollectCodeReferences()
        {
            if (options.CodeReferences != null) return [.. options.CodeReferences];
            var refs = new HashSet<uint>();
            if (!is64 && image.Arch == NativeArch.X86)
            {
                if (!UseRelocations)
                {
                    notes.Add("no base relocations: vftable ends are not checked against code references");
                    return refs;
                }
                foreach (var r in image.RelocationRvas)
                    if (IsExecutable(r) && TryU32(r, out var va) && TryVaToRva(va, out var target))
                        refs.Add(target);
            }
            else if (image.Arch == NativeArch.X64)
            {
                foreach (var (s, buffer) in data)
                {
                    if (!s.IsExecutable) continue;
                    ct.ThrowIfCancellationRequested();
                    var code = buffer.AsSpan();
                    // opcode at p, REX.W prefix at p - 1, ModRM (mod 00, r/m 101) at p + 1, disp32 at p + 2
                    for (int p = 1; p + 6 <= code.Length; p++)
                    {
                        int k = code[p..].IndexOfAny((byte)0x8D, (byte)0x8B);
                        if (k < 0) break;
                        p += k;
                        if (p + 6 > code.Length) break;
                        if ((code[p - 1] & 0xFA) != 0x48 || (code[p + 1] & 0xC7) != 0x05) continue;
                        long target = s.Rva + (long)p + 6 + BinaryPrimitives.ReadInt32LittleEndian(code[(p + 2)..]);
                        if (target > 0 && target < image.SizeOfImage)
                            refs.Add((uint)target);
                    }
                }
            }
            else
                notes.Add($"vftable ends are not checked against code references on {image.Arch}");
            return refs;
        }

        private string EnumerateSlots(uint vftable, HashSet<uint> metaSlots, List<uint> slots)
        {
            for (uint at = vftable; ; at += (uint)ptr)
            {
                if (slots.Count >= options.MaxSlots) return $"slot limit {options.MaxSlots}";
                if (slots.Count > 0 && metaSlots.Contains(at)) return "next vftable's locator pointer";
                if (slots.Count > 0 && codeReferences.Contains(at)) return "start of a table referenced from code";
                if (UseRelocations && !relocations.Contains(at)) return "slot not relocated";
                if (!TryPointer(at, out var value)) return "end of section";
                if (!TryVaToRva(value, out var target) || !IsExecutable(target)) return "not a code pointer";
                slots.Add(target);
            }
        }

        public MsvcRttiResult Result(TimeSpan elapsed)
        {
            var classes = new List<MsvcRttiClass>();
            foreach (var group in locators.GroupBy(l => l.TypeDescriptor))
            {
                var td = typeDescriptors[group.Key]!;
                var issues = new List<string>();
                var chdRvas = group.Select(l => l.Hierarchy).Distinct().ToList();
                if (chdRvas.Count > 1)
                    issues.Add($"locators reference {chdRvas.Count} different hierarchy descriptors; the first is reported");
                var chd = hierarchies[chdRvas[0]].Value!;
                var vtables = group.SelectMany(l => vtablesByLocator.GetValueOrDefault(l.Rva) ?? [])
                    .OrderBy(v => v.Offset).ThenBy(v => v.VftableRva).ToList();
                foreach (var dup in vtables.GroupBy(v => v.LocatorRva).Where(g => g.Count() > 1))
                    issues.Add($"locator 0x{dup.Key:X} is referenced by {dup.Count()} vftables");
                classes.Add(new MsvcRttiClass(td.Bare, td.Name, td.Kind, td.Rva, chd.Rva, chd.Attributes, chd.Bases, vtables, issues));
            }
            classes.Sort((x, y) => string.CompareOrdinal(x.Name, y.Name) is var c && c != 0 ? c : x.TypeDescriptorRva.CompareTo(y.TypeDescriptorRva));
            var tds = typeDescriptors.Values.Where(t => t != null).Select(t => (t!.Rva, t.Name)).OrderBy(t => t.Rva).ToList();
            if (!UseRelocations && image.Arch != NativeArch.Unknown)
                notes.Add("no base relocations: vftable references and slots are not cross-checked against relocated locations");
            var stats = new MsvcRttiStats(tds.Count, locators.Count, classes.Count, classes.Sum(c => c.Vtables.Count), tdRejected, colRejected,
                colWithoutVtable, bytesScanned, UseRelocations, codeReferences.Count, elapsed);
            return new MsvcRttiResult(classes, tds, skipped, notes, stats);
        }
    }
}
