using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;
using Corvus.Native.Msvc;

namespace Corvus.Native.Pascal;

/// <summary>Object Pascal class metadata read from a class's VMT.</summary>
/// <param name="Compiler">"Delphi", "Delphi (before 2009)" or "Free Pascal": the VMT layout.</param>
/// <param name="VmtRva">The VMT address: where an object's VMT pointer points.</param>
/// <param name="Unit">The declaring unit, from the class's type info; null without type info.</param>
/// <param name="VirtualMethods">The VMT's method slots, TObject's own first.</param>
public sealed record PascalClass(
    string Compiler,
    uint VmtRva,
    uint InstanceSize,
    string? Unit,
    IReadOnlyList<PascalMethod> VirtualMethods,
    IReadOnlyList<PascalMethod> PublishedMethods,
    IReadOnlyList<PascalField> PublishedFields);

/// <param name="Name">Published methods: the name. Virtual methods: Class.Name when a method table or TObject names the slot, else Class.vmt_N, Class introducing the slot.</param>
/// <param name="Offset">Virtual methods: byte offset of the slot from the VMT address (N × pointer size for vmt_N); published methods: -1.</param>
public sealed record PascalMethod(string Name, uint Rva, int Offset);

/// <param name="Type">The field's class, from the field table's class table; null when unresolved.</param>
public sealed record PascalField(string Name, uint Offset, string? Type);

/// <summary>
/// Recovers Object Pascal classes (Delphi, Free Pascal) from their VMTs, any pointer size. Delphi VMTs are anchored by the
/// self pointer (vmtSelfPtr equals the VMT address), Free Pascal ones by the instance size followed by its negation. Every
/// candidate is validated: table pointers inside the image, a class name of identifier characters, an instance size not
/// below the parent's, and a parent chain that ends at TObject or an import. The result uses the C++ RTTI model:
/// <see cref="MsvcRttiClass.TypeDescriptorRva"/> is the VMT, the bases are the parent chain, and the vftable holds the
/// slots from the first virtual method an object's VMT pointer reaches at a non-negative offset (Delphi: offset 0;
/// Free Pascal: Destroy).
/// </summary>
public static class PascalVmt
{
    private const int MaxSlots = 4096;
    private const int MaxEntries = 8192;
    private const long MaxSectionBytes = 512L << 20;
    private const uint MaxInstanceSize = 1u << 26;

    /// <summary>Field positions in pointer-size units from the VMT address (System unit constants: vmtSelfPtr... / TVmt).</summary>
    private sealed record Layout(string Compiler, bool Fpc, int SelfPtr, int ClassName, int InstanceSize, int Parent, int TypeInfo, int FieldTable,
        int MethodTable, int[] Tables, int Standard, string[] StandardNames)
    {
        public int HeaderStart => Fpc ? 0 : SelfPtr;
    }

    private static readonly string[] DelphiVirtuals =
        ["Equals", "GetHashCode", "ToString", "SafeCallException", "AfterConstruction", "BeforeDestruction", "Dispatch", "DefaultHandler", "NewInstance", "FreeInstance", "Destroy"];

    private static readonly Layout[] Layouts =
    [
        new("Delphi", false, -22, -14, -13, -12, -18, -17, -16, [-21, -20, -19, -18, -17, -16, -15, -14], -11, DelphiVirtuals),
        // CPP_ABI_SUPPORT targets (64-bit Windows and the LLVM platforms): three more TObject virtual methods after Destroy
        new("Delphi", false, -25, -17, -16, -15, -21, -20, -19, [-24, -23, -22, -21, -20, -19, -18, -17], -14, [.. DelphiVirtuals, "CPP_ABI_1", "CPP_ABI_2", "CPP_ABI_3"]),
        new("Delphi (before 2009)", false, -19, -11, -10, -9, -15, -14, -13, [-18, -17, -16, -15, -14, -13, -12, -11], -8, DelphiVirtuals[3..]),
        new("Free Pascal", true, 0, 3, 0, 2, 7, 6, 5, [3, 4, 5, 6, 7, 8, 9, 10, 11], 12,
            ["Destroy", "NewInstance", "FreeInstance", "SafeCallException", "DefaultHandler", "AfterConstruction", "BeforeDestruction",
             "DefaultHandlerStr", "Dispatch", "DispatchStr", "Equals", "GetHashCode", "ToString"]),
    ];

    private sealed class Candidate(uint vmt, Layout layout, string name, uint size, ulong parentField)
    {
        public uint Vmt = vmt;
        public Layout Layout = layout;
        public string Name = name;
        public uint Size = size;
        public ulong ParentField = parentField;
        public Candidate? Parent;
        public string? ExternalParent;
        public bool Valid = true;
    }

    public static MsvcRttiResult Analyze(INativeImage image, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var a = new Analyzer(image, ct);
        a.Run();
        return a.Result(sw.Elapsed);
    }

    private sealed class Analyzer(INativeImage image, CancellationToken ct)
    {
        private readonly int _ptr = image.Is64Bit ? 8 : 4;
        private readonly Dictionary<uint, NativeImport> _importAt = [];
        private readonly Dictionary<uint, Candidate> _byVmt = [];
        private readonly List<MsvcRttiSkip> _skipped = [];
        private int _rejected;
        private long _scanned;

        public void Run()
        {
            foreach (var imp in image.Imports) _importAt.TryAdd(imp.SlotRva, imp);
            foreach (var s in image.Sections)
            {
                if (s.RawSize == 0 || s.MappedSize < 4 * _ptr || s.Rva >= image.SizeOfImage || IsMetadata(s.Name)) continue;
                // VMTs are initialized data: only the section's file bytes
                long length = image.FileBackedLength(s.Rva, Math.Min(s.MappedSize, (long)image.SizeOfImage - s.Rva));
                if (length < 4 * _ptr || length > MaxSectionBytes || _scanned + length > 2 * MaxSectionBytes) continue;
                ct.ThrowIfCancellationRequested();
                var bytes = new byte[length];
                int n = image.Read(s.Rva, bytes);
                _scanned += n;
                uint first = (4 - s.Rva % 4) % 4;
                for (uint i = first; i + 2 * _ptr <= n; i += 4)
                {
                    ulong value = Word(bytes, i), next = Word(bytes, i + (uint)_ptr);
                    uint rva = s.Rva + i;
                    // Delphi: the self pointer holds the VMT address a fixed distance above it
                    foreach (var l in Layouts)
                        if (!l.Fpc && value == image.ImageBase + rva + (ulong)(-l.SelfPtr * _ptr)) Consider(rva + (uint)(-l.SelfPtr * _ptr), l);
                    // Free Pascal: InstanceSize, then -InstanceSize
                    if (value is > 0 and < MaxInstanceSize && next == ((ulong)-(long)value & Mask)) Consider(rva, Layouts[^1]);
                }
            }
            Resolve();
        }

        private ulong Mask => _ptr == 8 ? ulong.MaxValue : uint.MaxValue;

        private ulong Word(byte[] b, uint at) =>
            _ptr == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan((int)at)) : BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan((int)at));

        private void Consider(uint vmt, Layout l)
        {
            if (_byVmt.ContainsKey(vmt)) return;
            if (vmt % 4 != 0 || (long)vmt + (long)l.HeaderStart * _ptr < 0) { Reject(vmt, "misaligned"); return; }
            if (!TryField(vmt, l.ClassName, out var nameVa) || !ToRva(nameVa, out var nameRva) || ShortString(nameRva) is not { } name)
            {
                Reject(vmt, "class name is not a short string of identifier characters");
                return;
            }
            if (!TryField(vmt, l.InstanceSize, out var size) || size < (ulong)_ptr || size >= MaxInstanceSize) { Reject(vmt, $"instance size {size}"); return; }
            foreach (var t in l.Tables)
                if (!TryField(vmt, t, out var va) || (va != 0 && !ToRva(va, out _))) { Reject(vmt, "a table pointer is outside the image"); return; }
            if (!TryField(vmt, l.Parent, out var parent) || (parent != 0 && !ToRva(parent, out _))) { Reject(vmt, "parent pointer is outside the image"); return; }
            _byVmt[vmt] = new Candidate(vmt, l, name, (uint)size, parent);
        }

        private void Reject(uint vmt, string reason)
        {
            _rejected++;
            if (_skipped.Count < 1000) _skipped.Add(new MsvcRttiSkip(vmt, "vmt", reason));
        }

        /// <summary>Links each candidate to its parent and drops those whose chain does not end at TObject or an import.</summary>
        private void Resolve()
        {
            foreach (var c in _byVmt.Values)
            {
                if (c.ParentField == 0) continue;
                ToRva(c.ParentField, out var at);
                // Free Pascal before 3.1 points at the parent VMT itself; Delphi and later Free Pascal at a pointer to it
                if (c.Layout.Fpc && _byVmt.TryGetValue(at, out var direct) && direct.Layout == c.Layout) c.Parent = direct;
                else if (_importAt.TryGetValue(at, out var imp)) c.ExternalParent = imp.Name is { } n ? ImportedClass(n) : $"{imp.Module}#{imp.Ordinal}";
                else if (TryPointer(at, out var va) && ToRva(va, out var p) && _byVmt.TryGetValue(p, out var parent) && parent.Layout == c.Layout) c.Parent = parent;
                else { c.Valid = false; Reject(c.Vmt, "parent pointer does not lead to a VMT"); }
            }
            foreach (var c in _byVmt.Values)
            {
                if (!c.Valid) continue;
                var seen = new HashSet<Candidate>();
                string? reason = null;
                for (var k = c; ; k = k.Parent)
                {
                    if (!k.Valid || !seen.Add(k) || seen.Count > 256) { reason = "parent chain does not resolve"; break; }
                    if (k.Parent is { } up && up.Size > k.Size) { reason = "instance size below the parent's"; break; }
                    if (k.Parent == null)
                    {
                        if (k.ExternalParent == null && (k.ParentField != 0 || k.Name != "TObject")) reason = "parent chain does not end at TObject";
                        break;
                    }
                }
                if (reason != null) { c.Valid = false; Reject(c.Vmt, reason); }
            }
            // a class whose ancestor was dropped later in the pass
            bool changed = true;
            while (changed)
            {
                changed = false;
                foreach (var c in _byVmt.Values)
                    if (c.Valid && c.Parent is { Valid: false }) { c.Valid = false; changed = true; Reject(c.Vmt, "parent chain does not resolve"); }
            }
            foreach (var k in _byVmt.Where(kv => !kv.Value.Valid).Select(kv => kv.Key).ToList()) _byVmt.Remove(k);
        }

        /// <summary>"System.Classes.TComponent" for the Delphi package symbol "@System@Classes@TComponent@".</summary>
        private static string ImportedClass(string symbol) => symbol.Trim('@').Replace('@', '.');

        public MsvcRttiResult Result(TimeSpan elapsed)
        {
            // structure starts: a slot run ends at the next one
            var starts = new SortedSet<uint>();
            foreach (var c in _byVmt.Values)
            {
                starts.Add((uint)(c.Vmt + c.Layout.HeaderStart * _ptr));
                foreach (var t in c.Layout.Tables)
                    if (TryField(c.Vmt, t, out var va) && va != 0 && ToRva(va, out var r)) starts.Add(r);
            }
            var published = new Dictionary<Candidate, List<PascalMethod>>();
            foreach (var c in _byVmt.Values) published[c] = Methods(c);
            var slotsOf = new Dictionary<Candidate, (List<uint> Slots, string End)>();
            foreach (var c in _byVmt.Values) slotsOf[c] = Slots(c, starts);

            var classes = new List<MsvcRttiClass>();
            foreach (var c in _byVmt.Values)
            {
                ct.ThrowIfCancellationRequested();
                var l = c.Layout;
                var issues = new List<string>();
                var bases = new List<MsvcRttiBase>();
                int depth = 1;
                for (var k = c.Parent; k != null; k = k.Parent, depth++)
                    bases.Add(new MsvcRttiBase(k.Name, k.Vmt, 0, 0, 0, -1, 0, MsvcBaseAttributes.None, depth, depth == 1 ? null : depth - 2));
                var top = bases.Count > 0 ? bases[^1] : null;
                var root = c.Parent == null ? c : _byVmt[top!.TypeDescriptorRva];
                if (root.ExternalParent != null)
                    bases.Add(new MsvcRttiBase(root.ExternalParent, 0, 0, 0, 0, -1, 0, MsvcBaseAttributes.None, depth, depth == 1 ? null : depth - 2));
                for (int i = 0; i < bases.Count; i++) bases[i] = bases[i] with { ContainedBases = bases.Count - 1 - i };

                var (slots, end) = slotsOf[c];
                if (c.Parent != null && slotsOf[c.Parent].Slots.Count > slots.Count)
                    issues.Add($"{slots.Count} slots, fewer than the parent's {slotsOf[c.Parent].Slots.Count}");
                var virtuals = Virtuals(c, slots, published, slotsOf);
                var unit = UnitOf(c);
                var info = new PascalClass(l.Compiler, c.Vmt, c.Size, unit, virtuals, published[c], Fields(c));
                // the model's vftable: the slots at non-negative offsets
                int skip = l.Fpc ? 0 : -l.Standard;
                var userSlots = l.Fpc ? slots : slots.Skip(skip).ToList();
                uint table = l.Fpc ? (uint)(c.Vmt + l.Standard * _ptr) : c.Vmt;
                List<MsvcRttiVtable> vtables = userSlots.Count > 0 ? [new MsvcRttiVtable(c.Vmt, 0, 0, table, userSlots, end)] : [];
                classes.Add(new MsvcRttiClass(c.Name, unit != null ? unit + "." + c.Name : c.Name, "class", c.Vmt, c.Vmt, MsvcHierarchyAttributes.None,
                    bases, vtables, issues, info));
            }
            classes.Sort((x, y) => string.CompareOrdinal(x.Name, y.Name) is var cmp && cmp != 0 ? cmp : x.TypeDescriptorRva.CompareTo(y.TypeDescriptorRva));
            var tds = classes.Select(k => (k.TypeDescriptorRva, k.DecoratedName)).OrderBy(t => t.TypeDescriptorRva).ToList();
            int count = classes.Sum(k => k.Vtables.Count);
            var notes = new List<string>();
            if (classes.Count == 0) notes.Add("no Object Pascal VMTs");
            var stats = new MsvcRttiStats(tds.Count, count, classes.Count, count, _rejected, 0, 0, _scanned, false, 0, elapsed);
            return new MsvcRttiResult(classes, tds, _skipped, notes, stats);
        }

        /// <summary>
        /// The slots from TObject's first virtual method on: code pointers up to a structure start, a word that is not a
        /// code pointer or a known structure's address (Free Pascal ends the run with nil).
        /// </summary>
        private (List<uint>, string) Slots(Candidate c, SortedSet<uint> starts)
        {
            var slots = new List<uint>();
            uint at = (uint)(c.Vmt + c.Layout.Standard * _ptr);
            uint limit = starts.GetViewBetween(c.Vmt + 1, uint.MaxValue).Min;
            if (limit == 0) limit = uint.MaxValue;
            for (; slots.Count < MaxSlots; at += (uint)_ptr)
            {
                if (at >= limit) return (slots, "the next class structure");
                if (_importAt.ContainsKey(at)) return (slots, "an import slot");
                if (!TryPointer(at, out var value)) return (slots, "end of the section");
                if (value == 0) return (slots, "nil");
                if (!ToRva(value, out var target) || image.SectionAt(target) is not { IsExecutable: true }) return (slots, "not a code pointer");
                if (starts.Contains(target) || _byVmt.ContainsKey(target)) return (slots, "a class structure's address");
                slots.Add(target);
            }
            return (slots, $"more than {MaxSlots} slots");
        }

        private List<PascalMethod> Virtuals(Candidate c, List<uint> slots, Dictionary<Candidate, List<PascalMethod>> published,
            Dictionary<Candidate, (List<uint> Slots, string End)> slotsOf)
        {
            var l = c.Layout;
            // a published method of the class or an ancestor names the slot it fills
            var names = new Dictionary<uint, string>();
            for (var k = c; k != null; k = k.Parent)
                foreach (var m in published[k]) names.TryAdd(m.Rva, k.Name + "." + m.Name);
            var list = new List<PascalMethod>(slots.Count);
            for (int i = 0; i < slots.Count; i++)
            {
                int index = l.Standard + i;
                string name;
                if (i < l.StandardNames.Length) name = "TObject." + l.StandardNames[i];
                else if (names.TryGetValue(slots[i], out var n)) name = n;
                else
                {
                    var intro = c;
                    while (intro.Parent is { } up && slotsOf[up].Slots.Count > i) intro = up;
                    name = $"{intro.Name}.vmt_{index}";
                }
                list.Add(new PascalMethod(name, slots[i], index * _ptr));
            }
            return list;
        }

        /// <summary>The method table: Delphi Count (word), then entries of size (word), code, name; Free Pascal Count (dword), then name and code pointers.</summary>
        private List<PascalMethod> Methods(Candidate c)
        {
            var list = new List<PascalMethod>();
            if (!TryField(c.Vmt, c.Layout.MethodTable, out var va) || va == 0 || !ToRva(va, out var at)) return list;
            if (c.Layout.Fpc)
            {
                if (!TryU32(at, out var count) || count > MaxEntries) return list;
                for (uint i = 0, e = at + 4; i < count; i++, e += 2 * (uint)_ptr)
                {
                    if (!TryPointer(e, out var nameVa) || !ToRva(nameVa, out var nameRva) || ShortString(nameRva) is not { } name) break;
                    if (!TryPointer(e + (uint)_ptr, out var code) || !IsCode(code, out var rva)) break;
                    list.Add(new PascalMethod(name, rva, -1));
                }
                return list;
            }
            if (!TryU16(at, out var n)) return list;
            for (uint i = 0, e = at + 2; i < n; i++)
            {
                if (!TryU16(e, out var size) || !TryPointer(e + 2, out var code) || !IsCode(code, out var rva)) break;
                if (ShortString(e + 2 + (uint)_ptr) is not { } name || size < 2 + _ptr + 1 + name.Length) break;
                list.Add(new PascalMethod(name, rva, -1));
                e += size;
            }
            return list;
        }

        /// <summary>The field table: Count (word), class table pointer, then entries of offset (Delphi dword, Free Pascal pointer size), class index (word), name.</summary>
        private List<PascalField> Fields(Candidate c)
        {
            var list = new List<PascalField>();
            if (!TryField(c.Vmt, c.Layout.FieldTable, out var va) || va == 0 || !ToRva(va, out var at) || !TryU16(at, out var count)) return list;
            var types = new List<string?>();
            if (TryPointer(at + 2, out var tabVa) && tabVa != 0 && ToRva(tabVa, out var tab) && TryU16(tab, out var tabCount))
                for (uint i = 0; i < tabCount; i++)
                    types.Add(TryPointer(tab + 2 + i * (uint)_ptr, out var refVa) && ToRva(refVa, out var refRva) ? ClassAt(refRva) : null);
            int offsetSize = c.Layout.Fpc ? _ptr : 4;
            // Free Pascal numbers the class table from 1
            int bias = c.Layout.Fpc ? 1 : 0;
            for (uint i = 0, e = at + 2 + (uint)_ptr; i < count; i++)
            {
                ulong offset;
                if (offsetSize == 8) { if (!TryPointer(e, out offset)) break; }
                else if (TryU32(e, out var small)) offset = small;
                else break;
                if (!TryU16(e + (uint)offsetSize, out var index) || offset >= c.Size) break;
                if (ShortString(e + (uint)offsetSize + 2) is not { } name) break;
                int t = index - bias;
                list.Add(new PascalField(name, (uint)offset, t >= 0 && t < types.Count ? types[t] : null));
                e += (uint)(offsetSize + 2 + 1 + name.Length);
            }
            return list;
        }

        /// <summary>The class a class reference slot holds: a VMT address, or an import of one.</summary>
        private string? ClassAt(uint slot)
        {
            if (_importAt.TryGetValue(slot, out var imp)) return imp.Name is { } n ? ImportedClass(n) : null;
            return TryPointer(slot, out var va) && ToRva(va, out var vmt) && _byVmt.TryGetValue(vmt, out var k) ? k.Name : null;
        }

        /// <summary>The unit name of the class's type info: kind, name (the class name), then ClassType (the VMT), parent info, property count, unit name.</summary>
        private string? UnitOf(Candidate c)
        {
            if (!TryField(c.Vmt, c.Layout.TypeInfo, out var va) || va == 0 || !ToRva(va, out var ti)) return null;
            if (ShortString(ti + 1) is not { } name || !string.Equals(name, c.Name, StringComparison.OrdinalIgnoreCase)) return null;
            uint data = ti + 2 + (uint)name.Length;
            // newer Free Pascal puts an attribute table pointer before ClassType
            foreach (var at in new[] { data, data + (uint)_ptr })
                if (TryPointer(at, out var cls) && cls == image.ImageBase + c.Vmt)
                    return ShortString(at + 2 * (uint)_ptr + 2);
            return null;
        }

        private bool IsCode(ulong va, out uint rva) => ToRva(va, out rva) && image.SectionAt(rva) is { IsExecutable: true };

        private bool TryField(uint vmt, int slot, out ulong value) => TryPointer((uint)(vmt + slot * _ptr), out value);

        private bool TryPointer(uint rva, out ulong value)
        {
            Span<byte> b = stackalloc byte[8];
            value = 0;
            if (image.Read(rva, b[.._ptr]) != _ptr) return false;
            value = _ptr == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b);
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

        private bool TryU16(uint rva, out ushort value)
        {
            Span<byte> b = stackalloc byte[2];
            value = 0;
            if (image.Read(rva, b) != 2) return false;
            value = BinaryPrimitives.ReadUInt16LittleEndian(b);
            return true;
        }

        private bool ToRva(ulong va, out uint rva)
        {
            rva = 0;
            if (va < image.ImageBase || va - image.ImageBase >= image.SizeOfImage) return false;
            rva = (uint)(va - image.ImageBase);
            return true;
        }

        /// <summary>
        /// A length-prefixed name: a letter or underscore, then letters, digits and the punctuation of qualified and generic
        /// names (. &lt; &gt; , $).
        /// </summary>
        private string? ShortString(uint rva)
        {
            Span<byte> b = stackalloc byte[256];
            if (image.Read(rva, b[..1]) != 1 || b[0] == 0) return null;
            int n = b[0];
            if (image.Read(rva + 1, b[..n]) != n) return null;
            if (!(char.IsAsciiLetter((char)b[0]) || b[0] == '_')) return null;
            for (int i = 0; i < n; i++)
            {
                char ch = (char)b[i];
                if (!(char.IsAsciiLetterOrDigit(ch) || ch is '_' or '.' or '<' or '>' or ',' or '$')) return null;
            }
            return Encoding.ASCII.GetString(b[..n]);
        }

        /// <summary>Sections that never hold a VMT: resources, relocations, unwind data, import and export tables, debug data.</summary>
        private static bool IsMetadata(string name) =>
            name is ".rsrc" or ".reloc" or ".pdata" or ".xdata" or ".idata" or ".edata" or ".didata" or ".tls" or ".debug" or ".eh_frame" or ".eh_frame_hdr"
            || name.StartsWith(".debug", StringComparison.Ordinal) || name.StartsWith(".rel", StringComparison.Ordinal)
            || name.StartsWith(".dyn", StringComparison.Ordinal) || name.StartsWith(".sym", StringComparison.Ordinal);
    }
}
