using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;
using Corvus.Native.Msvc;

namespace Corvus.Native.Itanium;

/// <summary>Class metadata of any image in the one class model: C++ RTTI (MSVC on PE, Itanium on ELF and Mach-O) plus Object Pascal VMTs.</summary>
public static class CppRtti
{
    public static MsvcRttiResult Analyze(INativeImage image, CancellationToken ct = default)
    {
        var cpp = image.Format == ImageFormat.Pe ? MsvcRtti.Analyze(image, ct: ct) : ItaniumRtti.Analyze(image, ct);
        var pascal = Pascal.PascalVmt.Analyze(image, ct);
        if (pascal.Classes.Count == 0) return cpp;
        // Rejected counts stay C++ only: VMT candidates fail far more often and say nothing about the classes found.
        var classes = cpp.Classes.Concat(pascal.Classes)
            .OrderBy(c => c.Name, StringComparer.Ordinal).ThenBy(c => c.TypeDescriptorRva).ToList();
        var (a, b) = (cpp.Stats, pascal.Stats);
        var stats = new MsvcRttiStats(a.TypeDescriptors + b.TypeDescriptors, a.Locators + b.Locators, a.Classes + b.Classes, a.Vtables + b.Vtables,
            a.TypeDescriptorCandidatesRejected, a.LocatorCandidatesRejected, a.LocatorsWithoutVtable, a.BytesScanned + b.BytesScanned, a.UsedRelocations,
            a.CodeReferences, a.Elapsed + b.Elapsed);
        return new MsvcRttiResult(classes, [.. cpp.TypeDescriptors, .. pascal.TypeDescriptors], [.. cpp.Skipped, .. pascal.Skipped],
            [.. cpp.Notes, .. pascal.Notes], stats);
    }
}

/// <summary>Recovers Itanium C++ ABI RTTI (typeinfos, bases, vtables) into the MSVC model; a slot bound to an import (__cxa_pure_virtual) is 0.</summary>
public static class ItaniumRtti
{
    // MSVC model: TypeDescriptorRva is the typeinfo, LocatorRva the offset-to-top word, Offset the subobject
    // offset (minus offset-to-top), and a virtual base's Vdisp the vtable offset of its offset.
    private const int MaxSlots = 4096;
    private const int MaxBases = 64;
    private const long MaxSectionBytes = 512L << 20;

    private enum Kind : byte { Class, Single, Multiple }

    private static readonly Dictionary<string, Kind> Vtables = new(StringComparer.Ordinal)
    {
        ["_ZTVN10__cxxabiv117__class_type_infoE"] = Kind.Class,
        ["_ZTVN10__cxxabiv120__si_class_type_infoE"] = Kind.Single,
        ["_ZTVN10__cxxabiv121__vmi_class_type_infoE"] = Kind.Multiple,
    };

    private sealed record DirectBase(uint Rva, string Name, long Offset, bool Virtual, bool Public);

    private sealed record TypeInfo(uint Rva, Kind Kind, string Mangled, string Name, uint Size, List<DirectBase> Bases, uint Flags);

    public static MsvcRttiResult Analyze(INativeImage image, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var a = new Analyzer(image, ct);
        a.Run();
        return a.Result(sw.Elapsed);
    }

    /// <summary>A symbol name without the Mach-O underscore.</summary>
    private static string Bare(INativeImage image, string name) => image.Format == ImageFormat.MachO && name.StartsWith('_') ? name[1..] : name;

    /// <summary>"ns::Widget" for the mangled type "N2ns6WidgetE"; the mangled text when it does not demangle.</summary>
    internal static string TypeName(string mangled)
    {
        const string Prefix = "typeinfo name for ";
        var text = ItaniumDemangler.Demangle("_ZTS" + mangled);
        return text != null && text.StartsWith(Prefix, StringComparison.Ordinal) ? text[Prefix.Length..] : mangled;
    }

    private sealed class Analyzer(INativeImage image, CancellationToken ct)
    {
        private readonly int _ptr = image.Is64Bit ? 8 : 4;
        private readonly Dictionary<uint, NativeImport> _importAt = [];
        private readonly Dictionary<uint, TypeInfo> _types = [];
        private readonly List<MsvcRttiSkip> _skipped = [];
        private readonly List<string> _notes = [];
        private readonly Dictionary<uint, List<MsvcRttiVtable>> _vtables = [];
        /// <summary>Starts of the other typeinfo objects (pointer, fundamental, function types): 4 words each at most.</summary>
        private readonly List<uint> _otherTypeInfos = [];
        /// <summary>_ZTI symbols the image defines, by name.</summary>
        private readonly Dictionary<string, uint> _definedTypeInfos = new(StringComparer.Ordinal);
        private int _rejected;
        private long _scanned;

        public void Run()
        {
            foreach (var imp in image.Imports) _importAt.TryAdd(imp.SlotRva, imp);
            var candidates = new Dictionary<uint, Kind>();
            foreach (var imp in image.Imports)
            {
                if (imp.Name == null) continue;
                var name = Bare(image, imp.Name);
                if (Vtables.TryGetValue(name, out var kind)) candidates.TryAdd(imp.SlotRva, kind);
                else if (name.StartsWith("_ZTVN10__cxxabiv1", StringComparison.Ordinal)) _otherTypeInfos.Add(imp.SlotRva);
            }
            // Statically linked runtimes and copy relocations: the vtables are defined here and typeinfos point 2 words in.
            var defined = new Dictionary<ulong, Kind>();
            foreach (var sym in image.Symbols)
            {
                var name = Bare(image, sym.Name);
                if (Vtables.TryGetValue(name, out var kind)) defined.TryAdd(image.ImageBase + sym.Rva + 2 * (ulong)_ptr, kind);
                else if (name.StartsWith("_ZTI", StringComparison.Ordinal)) _definedTypeInfos.TryAdd(name, sym.Rva);
            }
            if (defined.Count > 0)
                foreach (var (rva, value) in Words(executable: false))
                    if (defined.TryGetValue(value, out var kind)) candidates.TryAdd(rva, kind);
            if (candidates.Count == 0)
            {
                _notes.Add("no Itanium RTTI: no typeinfo points to a __class_type_info vtable");
                return;
            }
            foreach (var (rva, kind) in candidates.OrderBy(c => c.Key))
            {
                ct.ThrowIfCancellationRequested();
                if (Read(rva, kind) is { } t) _types[rva] = t;
            }
            FindVtables();
        }

        private TypeInfo? Read(uint rva, Kind kind)
        {
            if (NameAt(rva + (uint)_ptr) is not { } mangled) return Skip(rva, "typeinfo name pointer does not lead to a type name");
            var bases = new List<DirectBase>();
            uint size = (uint)(2 * _ptr), flags = 0;
            switch (kind)
            {
                case Kind.Single:
                    if (Base(rva + size) is not { } single) return Skip(rva, "single-inheritance typeinfo without a base typeinfo");
                    bases.Add(new DirectBase(single.Rva, single.Name, 0, false, true));
                    size += (uint)_ptr;
                    break;
                case Kind.Multiple:
                {
                    if (!TryU32(rva + size, out flags) || !TryU32(rva + size + 4, out uint count) || count is 0 or > MaxBases)
                        return Skip(rva, "multiple-inheritance typeinfo with an unreadable base count");
                    size += 8;
                    for (int i = 0; i < count; i++, size += 2 * (uint)_ptr)
                    {
                        if (Base(rva + size) is not { } b || !TryPointer(rva + size + (uint)_ptr, out var raw, name: false))
                            return Skip(rva, $"base {i} of a multiple-inheritance typeinfo is unreadable");
                        long offsetFlags = _ptr == 8 ? (long)raw : (int)(uint)raw;
                        bases.Add(new DirectBase(b.Rva, b.Name, offsetFlags >> 8, (offsetFlags & 1) != 0, (offsetFlags & 2) != 0));
                    }
                    break;
                }
            }
            return new TypeInfo(rva, kind, mangled, TypeName(mangled), size, bases, flags);
        }

        private TypeInfo? Skip(uint rva, string reason)
        {
            _rejected++;
            if (_skipped.Count < 1000) _skipped.Add(new MsvcRttiSkip(rva, "typeinfo", reason));
            return null;
        }

        /// <summary>The mangled type name a typeinfo's name field gives: a string in the image, or a _ZTS symbol bound by name (weak definitions).</summary>
        private string? NameAt(uint at)
        {
            if (_importAt.TryGetValue(at, out var imp))
                return imp.Name != null && Bare(image, imp.Name) is var n && n.StartsWith("_ZTS", StringComparison.Ordinal) && n.Length > 4 ? n[4..] : null;
            return TryPointer(at, out var va, name: true) && ToRva(va, out var rva) ? ReadString(rva) : null;
        }

        /// <summary>A base typeinfo reference: a typeinfo in the image, or an import (RVA 0).</summary>
        private (uint Rva, string Name)? Base(uint at)
        {
            if (_importAt.TryGetValue(at, out var imp) && imp.Name != null)
            {
                var n = Bare(image, imp.Name);
                if (!n.StartsWith("_ZTI", StringComparison.Ordinal)) return (0, n);
                return (_definedTypeInfos.GetValueOrDefault(n), TypeName(n[4..]));
            }
            if (!TryPointer(at, out var va, name: false) || !ToRva(va, out var rva)) return null;
            return (rva, NameAt(rva + (uint)_ptr) is { } mangled ? TypeName(mangled) : $"typeinfo_{image.ImageBase + rva:X}");
        }

        /// <summary>Vtable address points: words holding a typeinfo address after an offset-to-top (0 or negative) and before a code pointer.</summary>
        private void FindVtables()
        {
            var byVa = _types.Keys.ToDictionary(r => image.ImageBase + r, r => r);
            var inside = _types.Values.Select(t => (t.Rva, End: t.Rva + t.Size)).Concat(_otherTypeInfos.Select(r => (Rva: r, End: r + 4 * (uint)_ptr)))
                .OrderBy(t => t.Rva).ToArray();
            bool InTypeInfo(uint rva)
            {
                int lo = 0, hi = inside.Length - 1;
                while (lo <= hi)
                {
                    int mid = (lo + hi) >>> 1;
                    if (inside[mid].End <= rva) lo = mid + 1;
                    else if (inside[mid].Rva > rva) hi = mid - 1;
                    else return true;
                }
                return false;
            }
            void Vtable(uint rva, uint type)
            {
                if (InTypeInfo(rva) || rva < _ptr || !TryPointer(rva - (uint)_ptr, out var raw, name: false) || _importAt.ContainsKey(rva - (uint)_ptr)) return;
                long offsetToTop = _ptr == 8 ? (long)raw : (int)(uint)raw;
                if (offsetToTop > 0 || offsetToTop < -(1L << 24)) return;
                var slots = new List<uint>();
                var end = Slots(rva + (uint)_ptr, slots, byVa);
                if (slots.Count == 0) return;
                if (!_vtables.TryGetValue(type, out var list)) _vtables[type] = list = [];
                list.Add(new MsvcRttiVtable(rva - (uint)_ptr, (uint)-offsetToTop, 0, rva + (uint)_ptr, slots, end));
            }
            foreach (var (rva, value) in Words(executable: false))
                if (byVa.TryGetValue(value, out var type)) Vtable(rva, type);
            // A typeinfo slot bound by name (weak definitions on Mach-O); a name two typeinfos share (internal linkage) binds neither.
            var byName = _types.Values.GroupBy(t => "_ZTI" + t.Mangled, StringComparer.Ordinal).Where(g => g.Count() == 1)
                .ToDictionary(g => g.Key, g => g.First().Rva, StringComparer.Ordinal);
            foreach (var imp in image.Imports)
                if (imp.Name != null && byName.TryGetValue(Bare(image, imp.Name), out var type)) Vtable(imp.SlotRva, type);
        }

        private string Slots(uint at, List<uint> slots, Dictionary<ulong, uint> typeInfos)
        {
            for (; slots.Count < MaxSlots; at += (uint)_ptr)
            {
                if (_importAt.TryGetValue(at, out var imp))
                {
                    // A function bound by name (__cxa_pure_virtual, a base's method in another library); data imports end the table.
                    if (imp.Name == null || Bare(image, imp.Name).StartsWith("_ZT", StringComparison.Ordinal)) return "a data import";
                    slots.Add(0);
                    continue;
                }
                if (!TryPointer(at, out var value, name: false)) return "end of the section";
                if (typeInfos.ContainsKey(value)) return "a typeinfo pointer (the next vtable)";
                if (image.Arch == NativeArch.Arm) value &= ~1UL;
                if (!ToRva(value, out var target) || image.SectionAt(target) is not { IsExecutable: true }) return "not a code pointer";
                slots.Add(target);
            }
            return $"more than {MaxSlots} slots";
        }

        /// <summary>Every pointer-aligned word of the data sections (or the code sections), as the loader maps it.</summary>
        private IEnumerable<(uint Rva, ulong Value)> Words(bool executable)
        {
            foreach (var s in image.Sections)
            {
                if (s.IsExecutable != executable || s.MappedSize < _ptr || IsMetadata(s.Name)) continue;
                long length = image.FileBytesLength(s);
                if (length > MaxSectionBytes) { _notes.Add($"section {s.Name} ({length} bytes) is too large to scan"); continue; }
                ct.ThrowIfCancellationRequested();
                var bytes = image.ReadFileBytes(s);
                int n = bytes.Length;
                _scanned += n;
                uint first = (uint)((_ptr - s.Rva % _ptr) % _ptr);
                for (uint i = first; i + _ptr <= n; i += (uint)_ptr)
                    yield return (s.Rva + i, _ptr == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan((int)i)) : BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan((int)i)));
            }
        }

        /// <summary>Unwind data and the loader's tables (symbols, strings, relocations, hashes, versions, notes): never vtables or typeinfos.</summary>
        private static bool IsMetadata(string name) =>
            name is ".eh_frame" or ".eh_frame_hdr" or ".gcc_except_table" or ".dynamic" or ".interp" or ".comment"
            || name.EndsWith("__eh_frame", StringComparison.Ordinal) || name.EndsWith("__gcc_except_tab", StringComparison.Ordinal)
            || name.EndsWith("__unwind_info", StringComparison.Ordinal)
            || name.StartsWith(".dyn", StringComparison.Ordinal) || name.StartsWith(".sym", StringComparison.Ordinal) || name.StartsWith(".str", StringComparison.Ordinal)
            || name.StartsWith(".rel", StringComparison.Ordinal) || name.StartsWith(".hash", StringComparison.Ordinal) || name.StartsWith(".gnu", StringComparison.Ordinal)
            || name.StartsWith(".note", StringComparison.Ordinal) || name.StartsWith(".debug", StringComparison.Ordinal);

        private bool TryPointer(uint rva, out ulong value, bool name)
        {
            Span<byte> b = stackalloc byte[8];
            value = 0;
            if (image.Read(rva, b[.._ptr]) != _ptr) return false;
            value = _ptr == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b);
            // The type name pointer's top bit marks a name compared by string (arm64 Apple non-unique RTTI).
            if (name && _ptr == 8) value &= ~(1UL << 63);
            return true;
        }

        private bool TryU32(uint rva, out uint value)
        {
            Span<byte> b = stackalloc byte[4];
            value = 0;
            if (image.Read(rva, b) != 4) return false;
            value = BinaryPrimitives.ReadUInt32LittleEndian(b);
            return true;
        }

        private bool ToRva(ulong va, out uint rva)
        {
            rva = 0;
            if (va < image.ImageBase || va - image.ImageBase >= image.SizeOfImage) return false;
            rva = (uint)(va - image.ImageBase);
            return true;
        }

        /// <summary>A mangled type name: printable, nonempty, at most 4096 bytes and terminated.</summary>
        private string? ReadString(uint rva)
        {
            Span<byte> b = stackalloc byte[256];
            var sb = new StringBuilder();
            while (sb.Length < 4096)
            {
                int n = image.Read(rva + (uint)sb.Length, b);
                if (n <= 0) return null;
                for (int i = 0; i < n; i++)
                {
                    if (b[i] == 0) return sb.Length > 0 && (char.IsAsciiLetterOrDigit(sb[0]) || sb[0] == '_') ? sb.ToString() : null;
                    if (b[i] is < 0x21 or > 0x7E) return null;
                    sb.Append((char)b[i]);
                }
            }
            return null;
        }

        public MsvcRttiResult Result(TimeSpan elapsed)
        {
            var classes = new List<MsvcRttiClass>();
            foreach (var t in _types.Values)
            {
                var bases = new List<MsvcRttiBase>();
                var issues = new List<string>();
                Expand(t, 1, null, 0, bases, [t.Rva], issues);
                var attributes = MsvcHierarchyAttributes.None;
                if (t.Bases.Count > 1 || (t.Flags & 3) != 0) attributes |= MsvcHierarchyAttributes.MultipleInheritance;
                if (bases.Any(b => b.IsVirtual)) attributes |= MsvcHierarchyAttributes.VirtualInheritance;
                var vtables = (_vtables.GetValueOrDefault(t.Rva) ?? []).OrderBy(v => v.Offset).ThenBy(v => v.VftableRva).ToList();
                classes.Add(new MsvcRttiClass(t.Name, "_ZTI" + t.Mangled, "class", t.Rva, t.Rva, attributes, bases, vtables, issues));
            }
            classes.Sort((x, y) => string.CompareOrdinal(x.Name, y.Name) is var c && c != 0 ? c : x.TypeDescriptorRva.CompareTo(y.TypeDescriptorRva));
            var tds = _types.Values.Select(t => (t.Rva, "_ZTI" + t.Mangled)).OrderBy(t => t.Rva).ToList();
            int count = classes.Sum(c => c.Vtables.Count);
            var stats = new MsvcRttiStats(tds.Count, count, classes.Count, count, _rejected, 0, 0, _scanned, false, 0, elapsed);
            return new MsvcRttiResult(classes, tds, _skipped, _notes, stats);
        }

        /// <summary>The bases of <paramref name="t"/> in preorder, offsets in the complete object (from the virtual base below a virtual one).</summary>
        private int Expand(TypeInfo t, int depth, int? parent, long at, List<MsvcRttiBase> bases, HashSet<uint> path, List<string> issues)
        {
            int added = 0;
            foreach (var b in t.Bases)
            {
                if (bases.Count >= 4096 || depth > 32) { issues.Add("base class tree truncated"); break; }
                int index = bases.Count;
                var attributes = b.Public ? MsvcBaseAttributes.None : MsvcBaseAttributes.PrivateOrProtectedBase;
                bases.Add(b.Virtual
                    ? new MsvcRttiBase(b.Name, b.Rva, 0, 0, 0, 0, (int)b.Offset, attributes, depth, parent)
                    : new MsvcRttiBase(b.Name, b.Rva, 0, 0, (int)(at + b.Offset), -1, 0, attributes, depth, parent));
                int below = 0;
                if (b.Rva != 0 && _types.TryGetValue(b.Rva, out var inner) && path.Add(b.Rva))
                {
                    below = Expand(inner, depth + 1, index, b.Virtual ? 0 : at + b.Offset, bases, path, issues);
                    path.Remove(b.Rva);
                }
                bases[index] = bases[index] with { ContainedBases = below };
                added += 1 + below;
            }
            return added;
        }
    }
}
