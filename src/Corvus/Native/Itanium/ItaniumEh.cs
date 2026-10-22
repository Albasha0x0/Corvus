using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using Corvus.Native.Calls;
using Corvus.Native.Elf;

namespace Corvus.Native.Itanium;

/// <summary>One entry of an LSDA call-site table: [Start, End) unwinds to <see cref="LandingPad"/> (none: the exception passes through).</summary>
/// <param name="Actions">"cleanup", "catch (T)", "catch (...)" or "throw() filter", in the order the personality tries them.</param>
public sealed record ItaniumCallSite(uint Start, uint End, uint? LandingPad, IReadOnlyList<string> Actions);

/// <summary>
/// The exception handling of one function: where its unwind data comes from, the personality routine, its LSDA
/// (.gcc_except_table / __gcc_except_tab) and the call-site table read from it.
/// </summary>
/// <param name="Source">"DWARF CFI" (.eh_frame / __eh_frame), "compact unwind" (__unwind_info) or "ARM EHABI" (.ARM.exidx / .ARM.extab).</param>
public sealed record ItaniumEhFunction(uint Begin, uint End, string Source, string? Personality, uint? Lsda, IReadOnlyList<ItaniumCallSite> CallSites,
    IReadOnlyList<string> Notes);

/// <summary>The exception handling tables of an ELF or Mach-O image, by function.</summary>
public sealed class ItaniumEhTable
{
    private readonly ItaniumEhFunction[] _functions;

    internal ItaniumEhTable(ItaniumEhFunction[] functions, int fdes, int compact, int exidx, IReadOnlyList<string> notes)
    {
        _functions = functions;
        Fdes = fdes;
        CompactEntries = compact;
        ExidxEntries = exidx;
        Notes = notes;
    }

    /// <summary>Sorted by start; FDEs first where both tables cover a function.</summary>
    public IReadOnlyList<ItaniumEhFunction> Functions => _functions;
    public int Fdes { get; }
    public int CompactEntries { get; }
    /// <summary>32-bit ARM .ARM.exidx entries.</summary>
    public int ExidxEntries { get; }
    public IReadOnlyList<string> Notes { get; }

    public ItaniumEhFunction? At(uint rva)
    {
        int lo = 0, hi = _functions.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            var f = _functions[mid];
            if (rva < f.Begin) hi = mid - 1;
            else if (rva >= f.End && f.End > f.Begin) lo = mid + 1;
            else return f;
        }
        return null;
    }
}

/// <summary>
/// Itanium C++ ABI exception handling on ELF and Mach-O: .eh_frame FDEs (CIE augmentation: personality, LSDA), Mach-O
/// compact unwind entries (personality index, LSDA index), 32-bit ARM .ARM.exidx / .ARM.extab entries (EHABI personality,
/// unwind opcodes, the LSDA of a generic personality), the LSDA call-site, action and type tables, and the frame a
/// function's CFA rules or unwind opcodes describe (for the dossier).
/// </summary>
public static class ItaniumEh
{
    private const int MaxFdes = 1 << 20;
    private const int MaxCallSites = 4096;
    private static readonly ConditionalWeakTable<INativeImage, ItaniumEhTable> Tables = new();

    public static ItaniumEhTable Of(INativeImage image) => Tables.GetValue(image, i => Build(i, names: true));

    /// <summary>
    /// The landing pads of every function with exception tables, with whether one catches (else it only cleans up). Not cached
    /// and without names: the code index reads it once per build.
    /// </summary>
    internal static List<(uint Function, uint Pad, bool Catches)> LandingPads(INativeImage image) =>
        [.. Build(image, names: false).Functions.SelectMany(f => f.CallSites.Where(c => c.LandingPad != null)
            .Select(c => (f.Begin, c.LandingPad!.Value, c.Actions.Any(a => a.StartsWith("catch", StringComparison.Ordinal)))))];

    private static NativeSection? Section(INativeImage image, string elf, string macho) =>
        image.Sections.FirstOrDefault(s => s.Name == (image.Format == ImageFormat.MachO ? macho : elf));

    private static byte[] Bytes(INativeImage image, NativeSection s) => image.ReadFileBytes(s, 256L << 20);

    private sealed record CfiData(ByteView View, List<CfiFde> Fdes);
    private static readonly ConditionalWeakTable<INativeImage, CfiData> Cfi = new();

    /// <summary>The .eh_frame bytes and its FDEs, read once per image.</summary>
    private static CfiData CfiOf(INativeImage image) => Cfi.GetValue(image, i =>
    {
        if (Section(i, ".eh_frame", "__TEXT,__eh_frame") is not { } eh) return new CfiData(new ByteView([], false), []);
        var view = new ByteView(Bytes(i, eh), false);
        var fdes = EhFrame.WalkFull(view, i.ImageBase + eh.Rva, i.Is64Bit, MaxFdes);
        fdes.Sort((a, b) => a.Start.CompareTo(b.Start));
        return new CfiData(view, fdes);
    });

    private static List<CfiFde> Fdes(INativeImage image) => CfiOf(image).Fdes;

    private static ItaniumEhTable Build(INativeImage image, bool names)
    {
        var notes = new List<string>();
        var imports = new Dictionary<uint, NativeImport>();
        foreach (var i in image.Imports) imports.TryAdd(i.SlotRva, i);
        var types = names ? CppRtti.Analyze(image).Classes.ToDictionary(c => c.TypeDescriptorRva, c => c.Name) : [];
        var lsda = new Lsda(image, imports, types, names);
        var list = new List<ItaniumEhFunction>();
        var fdes = Fdes(image);
        foreach (var f in fdes)
        {
            if (!Rva(image, f.Start, out uint begin)) continue;
            var personality = f.Cie.Personality is { } p ? lsda.PointerName(p, (f.Cie.PersonalityEncoding & 0x80) != 0) : null;
            uint? lsdaRva = f.Lsda is { } l && Rva(image, l, out uint r) ? r : null;
            uint end = begin + (uint)Math.Min(f.Range, uint.MaxValue - begin);
            var sites = lsdaRva is { } at ? lsda.CallSites(at, begin, end, out var why) : (List<ItaniumCallSite>?)null;
            list.Add(new ItaniumEhFunction(begin, end, "DWARF CFI", personality, lsdaRva, sites ?? [],
                sites == null && lsdaRva != null ? ["LSDA not readable"] : []));
        }
        int compact = 0;
        if (image.Format == ImageFormat.MachO)
            foreach (var e in CompactEntries(image, notes))
            {
                compact++;
                if (e.Lsda == null && e.Personality == null) continue;
                var personality = e.Personality is { } p ? lsda.PointerName(image.ImageBase + p, indirect: true) : null;
                var sites = e.Lsda is { } at ? lsda.CallSites(at, e.Start, e.End, out _) : null;
                list.Add(new ItaniumEhFunction(e.Start, e.End, "compact unwind", personality, e.Lsda, sites ?? [], []));
            }
        var exidx = Exidx(image);
        foreach (var e in exidx)
        {
            var eh = new List<string>();
            if (e.CantUnwind) eh.Add("EXIDX_CANTUNWIND: the function cannot be unwound through");
            if (e.Note != null) eh.Add(e.Note);
            var sites = e.Lsda is not { } at ? null : e.PersonalityIndex is 1 or 2 ? lsda.ArmScopes(at, e.Begin, wide: e.PersonalityIndex == 2) : lsda.CallSites(at, e.Begin, e.End, out _);
            if (sites == null && e.Lsda != null) eh.Add(e.PersonalityIndex is 1 or 2 ? "scope descriptors not readable" : "LSDA not readable");
            var personality = e.PersonalityIndex is { } k ? $"__aeabi_unwind_cpp_pr{k}" : e.Personality is { } p ? lsda.PointerName(p, indirect: false) : null;
            list.Add(new ItaniumEhFunction(e.Begin, e.End, "ARM EHABI", personality, e.Lsda, sites ?? [], eh));
        }
        list.Sort((a, b) => a.Begin.CompareTo(b.Begin));
        var distinct = list.DistinctBy(f => f.Begin).ToArray();
        return new ItaniumEhTable(distinct, fdes.Count, compact, exidx.Count, notes);
    }

    private static bool Rva(INativeImage image, ulong va, out uint rva)
    {
        rva = 0;
        if (va < image.ImageBase || va - image.ImageBase >= image.SizeOfImage) return false;
        rva = (uint)(va - image.ImageBase);
        return true;
    }

    /// <summary>Reads LSDAs: call sites, actions and the catch types (typeinfos by RTTI name, import name or address).</summary>
    private sealed class Lsda(INativeImage image, Dictionary<uint, NativeImport> imports, Dictionary<uint, string> types, bool names)
    {
        private readonly int _ptr = image.Is64Bit ? 8 : 4;
        // read once per section: a large image has hundreds of thousands of LSDAs in one section
        private readonly Dictionary<uint, byte[]> _sections = [];

        private byte[] SectionBytes(NativeSection s)
        {
            if (!_sections.TryGetValue(s.Rva, out var bytes)) _sections[s.Rva] = bytes = Bytes(image, s);
            return bytes;
        }

        /// <summary>The name of what a (possibly indirect) pointer leads to: an import bound at the slot, a typeinfo, a symbol ("?" without names).</summary>
        public string PointerName(ulong va, bool indirect)
        {
            if (!names) return "?";
            if (!Rva(image, va, out uint rva)) return $"0x{va:X}";
            if (indirect)
            {
                if (imports.TryGetValue(rva, out var imp) && imp.Name != null) return Plain(imp.Name);
                Span<byte> b = stackalloc byte[8];
                b.Clear();
                if (image.Read(rva, b[.._ptr]) != _ptr) return $"[0x{va:X}]";
                ulong target = BinaryPrimitives.ReadUInt64LittleEndian(b);
                if (!Rva(image, target, out rva)) return $"[0x{va:X}]";
            }
            if (types.TryGetValue(rva, out var type)) return type;
            if (image is ElfFile elf && elf.PltEntries.FirstOrDefault(p => p.StubRva == rva) is { Symbol: { } plt }) return Plain(plt);
            var symbol = image.Symbols.FirstOrDefault(s => s.Rva == rva);
            if (symbol != null) return Plain(symbol.Name);
            return TypeInfoName(rva) ?? $"0x{image.ImageBase + rva:X}";
        }

        /// <summary>The type a typeinfo object at <paramref name="rva"/> names (its second word points to the mangled type), or null.</summary>
        private string? TypeInfoName(uint rva)
        {
            Span<byte> b = stackalloc byte[8];
            b.Clear();
            if (image.Read(rva + (uint)_ptr, b[.._ptr]) != _ptr) return null;
            ulong name = BinaryPrimitives.ReadUInt64LittleEndian(b) & ~(1UL << 63);
            if (!Rva(image, name, out uint at)) return null;
            var text = new byte[256];
            int n = image.Read(at, text);
            int end = Array.IndexOf(text, (byte)0, 0, n);
            if (end <= 0 || text.AsSpan(0, end).IndexOfAnyExceptInRange((byte)0x21, (byte)0x7E) >= 0) return null;
            var mangled = System.Text.Encoding.ASCII.GetString(text, 0, end);
            var plain = ItaniumRtti.TypeName(mangled);
            return plain != mangled ? plain : null;
        }

        private string Plain(string name)
        {
            bool macho = image.Format == ImageFormat.MachO;
            var bare = macho && name.StartsWith('_') ? name[1..] : name;
            if (bare.StartsWith("_ZTI", StringComparison.Ordinal)) return ItaniumRtti.TypeName(bare[4..]);
            return ItaniumDemangler.Demangle(bare) ?? bare;
        }

        public List<ItaniumCallSite>? CallSites(uint at, uint functionStart, uint functionEnd, out string? why)
        {
            why = null;
            var section = image.SectionAt(at);
            if (section == null) { why = "outside the image"; return null; }
            var bytes = SectionBytes(section);
            var d = new ByteView(bytes, at - section.Rva, Math.Min(bytes.Length - (long)(at - section.Rva), 1 << 20), false);
            int n = (int)d.Length;
            ulong va = image.ImageBase + at;
            long pos = 0;
            byte lpEnc = d.U8(pos++);
            ulong lpStart = image.ImageBase + functionStart;
            if (lpEnc != EhFrame.Omit && !EhFrame.TryReadPointer(d, ref pos, (byte)(lpEnc & 0x7F), va, 0, image.Is64Bit, out lpStart)) { why = "landing pad base"; return null; }
            byte ttEnc = d.U8(pos++);
            long typeBase = -1;
            if (ttEnc != EhFrame.Omit)
            {
                var r = new LebReader(d.Span(pos, 16));
                ulong off = r.Uleb();
                pos += r.Position;
                typeBase = pos + (long)Math.Min(off, (ulong)n);
            }
            byte csEnc = d.U8(pos++);
            var lr = new LebReader(d.Span(pos, 16));
            ulong csLength = lr.Uleb();
            pos += lr.Position;
            long csEnd = pos + (long)Math.Min(csLength, (ulong)n), actions = csEnd;
            var result = new List<ItaniumCallSite>();
            while (pos < csEnd && result.Count < MaxCallSites)
            {
                if (!EhFrame.TryReadPointer(d, ref pos, csEnc, va, 0, image.Is64Bit, out var start)
                    || !EhFrame.TryReadPointer(d, ref pos, csEnc, va, 0, image.Is64Bit, out var length)
                    || !EhFrame.TryReadPointer(d, ref pos, csEnc, va, 0, image.Is64Bit, out var pad)) { why = "call-site table"; break; }
                var ar = new LebReader(d.Span(pos, 16));
                ulong action = ar.Uleb();
                pos += ar.Position;
                ulong s = lpStart + start;
                // call sites lie in their function: one outside is not a GCC table (NativeAOT's own EH data has the same slot)
                if (!Rva(image, s, out uint sr) || sr < functionStart || sr >= functionEnd) { why = "call-site table"; break; }
                uint? padRva = pad != 0 && Rva(image, lpStart + pad, out uint pr) ? pr : null;
                var names = new List<string>();
                if (padRva != null && action == 0) names.Add("cleanup");
                else if (action != 0) Actions(d, actions + (long)action - 1, typeBase, ttEnc, va, names);
                result.Add(new ItaniumCallSite(sr, sr + (uint)Math.Min(length, uint.MaxValue), padRva, names));
            }
            return result;
        }

        /// <summary>
        /// The scope descriptors of the ARM personalities (EHABI 9.2) from <paramref name="at"/> to a zero word: a scope (16-bit
        /// length and offset for pr1, 32-bit for pr2; bit 0 of each gives the kind), then a cleanup's landing pad, a catch's
        /// landing pad and type (-1: any, -2: a no-throw region), or an exception specification's types and optional landing pad.
        /// </summary>
        public List<ItaniumCallSite>? ArmScopes(uint at, uint functionStart, bool wide)
        {
            var section = image.SectionAt(at);
            if (section == null) return null;
            uint limit = section.Rva + section.MappedSize;
            var result = new List<ItaniumCallSite>();
            bool Word(out uint value)
            {
                Span<byte> b = stackalloc byte[4];
                value = 0;
                if (at + 4 > limit || image.Read(at, b) != 4) return false;
                value = BinaryPrimitives.ReadUInt32LittleEndian(b);
                at += 4;
                return true;
            }
            // a Thumb landing pad's bit 0 is dropped
            uint? Prel31(uint word, uint from) => ((from + (uint)((int)(word << 1) >> 1)) & ~1u) is var r && image.SectionAt(r) != null ? r : null;
            // R_ARM_TARGET2 as Linux and Android resolve it: pc-relative, indirect through a GOT slot
            string Type(uint word, uint from) => PointerName((ulong)((long)image.ImageBase + from + (int)word), indirect: true);
            while (result.Count < MaxCallSites && Word(out uint first) && first != 0)
            {
                uint length, offset;
                if (wide) { length = first; if (!Word(out offset)) return result; }
                else { length = first & 0xFFFF; offset = first >> 16; }
                uint start = functionStart + (offset & ~1u), end = start + (length & ~1u);
                switch ((offset & 1) << 1 | length & 1)
                {
                    case 0:
                        if (!Word(out uint cleanup)) return result;
                        result.Add(new ItaniumCallSite(start, end, Prel31(cleanup, at - 4), ["cleanup"]));
                        break;
                    case 1:
                    {
                        if (!Word(out uint handler)) return result;
                        uint handlerAt = at - 4;
                        if (!Word(out uint type)) return result;
                        var action = type switch
                        {
                            0xFFFFFFFF => "catch (...)",
                            0xFFFFFFFE => "no-throw region (terminate)",
                            _ => $"catch ({Type(type, at - 4)}{((handler & 0x80000000) != 0 ? "&" : "")})",
                        };
                        result.Add(new ItaniumCallSite(start, end, Prel31(handler, handlerAt), [action]));
                        break;
                    }
                    case 2:
                    {
                        if (!Word(out uint count)) return result;
                        var types = new List<string>();
                        for (uint k = 0; k < (count & 0x7FFFFFFF) && k < 256; k++)
                        {
                            if (!Word(out uint type)) return result;
                            types.Add(Type(type, at - 4));
                        }
                        uint? unexpected = null;
                        if ((count & 0x80000000) != 0)
                        {
                            if (!Word(out uint p)) return result;
                            unexpected = Prel31(p, at - 4);
                        }
                        result.Add(new ItaniumCallSite(start, end, unexpected, [$"exception specification throw({string.Join(", ", types)})"]));
                        break;
                    }
                    default: return result; // reserved kind: the rest cannot be parsed
                }
            }
            return result;
        }

        /// <summary>The action chain from <paramref name="at"/>: filters &gt; 0 catch a type, 0 is a cleanup, &lt; 0 an exception specification.</summary>
        private void Actions(ByteView d, long at, long typeBase, byte ttEnc, ulong va, List<string> names)
        {
            int size = (ttEnc & 0x0F) switch { 0x02 or 0x0A => 2, 0x03 or 0x0B => 4, 0x04 or 0x0C => 8, _ => _ptr };
            for (int guard = 0; guard < 64 && at >= 0 && at < d.Length; guard++)
            {
                var r = new LebReader(d.Span(at, 16));
                long filter = r.Sleb();
                long nextAt = at + r.Position;
                var r2 = new LebReader(d.Span(nextAt, 16));
                long next = r2.Sleb();
                if (r.Failed || r2.Failed) return;
                if (filter == 0) names.Add("cleanup");
                else if (filter < 0) names.Add("exception specification");
                else if (typeBase >= 0)
                {
                    long p = typeBase - filter * size;
                    // a zero entry is catch (...) under any encoding, pc-relative ones included
                    if (d.Has(p, size) && d.Span(p, size).IndexOfAnyExcept((byte)0) < 0) names.Add("catch (...)");
                    else if (!EhFrame.TryReadPointer(d, ref p, (byte)(ttEnc & 0x7F), va, 0, image.Is64Bit, out var ti)) names.Add("catch (?)");
                    else names.Add(ti == 0 ? "catch (...)" : $"catch ({PointerName(ti, (ttEnc & 0x80) != 0)})");
                }
                if (next == 0) return;
                at = nextAt + next;
            }
        }
    }

    private readonly record struct Compact(uint Start, uint End, uint Encoding, uint? Lsda, uint? Personality);

    /// <summary>
    /// One .ARM.exidx entry: [Begin, End) to the next entry (merged neighbors share one), the ARM-defined personality index
    /// (compact model) or the generic personality's address, the unwind opcodes, and the LSDA following them.
    /// </summary>
    private sealed record EhabiEntry(uint Begin, uint End, bool CantUnwind, int? PersonalityIndex, ulong? Personality, byte[] Opcodes, uint? Lsda, string? Note);

    private static readonly ConditionalWeakTable<INativeImage, List<EhabiEntry>> ExidxTables = new();

    private static List<EhabiEntry> Exidx(INativeImage image) => ExidxTables.GetValue(image, ReadExidx);

    private static List<EhabiEntry> ReadExidx(INativeImage image)
    {
        var result = new List<EhabiEntry>();
        if (image.Arch != NativeArch.Arm || image.Format != ImageFormat.Elf || Section(image, ".ARM.exidx", "") is not { } section) return result;
        var t = new ByteView(Bytes(image, section), false);
        static uint Prel31(uint word, uint at) => at + (uint)((int)(word << 1) >> 1);
        var raw = new List<(uint Begin, uint Word, uint At)>();
        for (long at = 0; at + 8 <= t.Length && raw.Count < MaxFdes; at += 8)
        {
            uint entry = section.Rva + (uint)at;
            raw.Add((Prel31(t.U32(at), entry) & ~1u, t.U32(at + 4), entry + 4));
        }
        uint textEnd = image.SectionAt(raw.Count > 0 ? raw[^1].Begin : 0) is { } text ? text.Rva + text.VirtualSize : 0;
        Span<byte> w = stackalloc byte[8];
        for (int i = 0; i < raw.Count; i++)
        {
            var (begin, word, wordAt) = raw[i];
            uint end = i + 1 < raw.Count && raw[i + 1].Begin > begin ? raw[i + 1].Begin : Math.Max(begin, textEnd);
            // the linker's sentinel past the end of .text
            if (image.SectionAt(begin) is not { IsExecutable: true }) continue;
            if (word == 1) { result.Add(new EhabiEntry(begin, end, true, null, null, [], null, null)); continue; }
            if ((word & 0x80000000) != 0)
            {
                result.Add(new EhabiEntry(begin, end, false, (int)(word >> 24 & 0xF), null, [(byte)(word >> 16), (byte)(word >> 8), (byte)word], null, null));
                continue;
            }
            uint extab = Prel31(word, wordAt);
            if (image.Read(extab, w) < 8) { result.Add(new EhabiEntry(begin, end, false, null, null, [], null, ".ARM.extab entry not readable")); continue; }
            uint e0 = BinaryPrimitives.ReadUInt32LittleEndian(w), e1 = BinaryPrimitives.ReadUInt32LittleEndian(w[4..]);
            var ops = new List<byte>();
            void Words(uint from, int count)
            {
                Span<byte> b = stackalloc byte[4];
                for (int k = 0; k < count && image.Read(from + 4 * (uint)k, b) == 4; k++)
                {
                    uint x = BinaryPrimitives.ReadUInt32LittleEndian(b);
                    ops.AddRange([(byte)(x >> 24), (byte)(x >> 16), (byte)(x >> 8), (byte)x]);
                }
            }
            if ((e0 & 0x80000000) != 0)
            {
                int index = (int)(e0 >> 24 & 0xF);
                if (index == 0) ops.AddRange([(byte)(e0 >> 16), (byte)(e0 >> 8), (byte)e0]);
                else
                {
                    ops.AddRange([(byte)(e0 >> 8), (byte)e0]);
                    Words(extab + 4, (int)(e0 >> 16 & 0xFF));
                }
                // pr1 / pr2: the scope descriptors follow the unwind opcodes
                uint? descriptors = index is 1 or 2 ? extab + 4 + 4 * (e0 >> 16 & 0xFF) : null;
                result.Add(new EhabiEntry(begin, end, false, index, null, [.. ops], descriptors, null));
                continue;
            }
            int extra = (int)(e1 >> 24);
            ops.AddRange([(byte)(e1 >> 16), (byte)(e1 >> 8), (byte)e1]);
            Words(extab + 8, extra);
            result.Add(new EhabiEntry(begin, end, false, null, image.ImageBase + Prel31(e0, extab), [.. ops], extab + 8 + 4 * (uint)extra, null));
        }
        return result;
    }

    /// <summary>__unwind_info entries with their encodings, LSDAs (the LSDA index) and personality slots (the personality array).</summary>
    private static List<Compact> CompactEntries(INativeImage image, List<string> notes)
    {
        var result = new List<Compact>();
        if (Section(image, "", "__TEXT,__unwind_info") is not { } section) return result;
        var u = new ByteView(Bytes(image, section), false);
        if (u.Length < 28 || u.U32(0) != 1) { notes.Add($"__unwind_info version {u.U32(0)} is not 1"); return result; }
        uint commonAt = u.U32(4), commonCount = u.U32(8), personalityAt = u.U32(12), personalityCount = u.U32(16), indexAt = u.U32(20), indexCount = u.U32(24);
        var entries = new List<(uint Start, uint Encoding)>();
        var lsdas = new Dictionary<uint, uint>();
        for (uint i = 0; i < indexCount && entries.Count < MaxFdes; i++)
        {
            long e = indexAt + 12L * i;
            if (!u.Has(e, 12)) break;
            uint first = u.U32(e), page = u.U32(e + 4), lsdaAt = u.U32(e + 8);
            if (i + 1 < indexCount)
                for (uint l = lsdaAt, end = u.U32(e + 12 + 8); l + 8 <= end && u.Has(l, 8); l += 8) lsdas.TryAdd(u.U32(l), u.U32(l + 4));
            if (page == 0) continue;
            uint kind = u.U32(page);
            if (kind == 2)
            {
                uint at = page + u.U16(page + 4), count = u.U16(page + 6);
                for (uint k = 0; k < count && u.Has(at + 8L * k, 8); k++) entries.Add((u.U32(at + 8L * k), u.U32(at + 8L * k + 4)));
            }
            else if (kind == 3)
            {
                uint at = page + u.U16(page + 4), count = u.U16(page + 6), encAt = page + u.U16(page + 8), encCount = u.U16(page + 10);
                for (uint k = 0; k < count && u.Has(at + 4L * k, 4); k++)
                {
                    uint word = u.U32(at + 4L * k), x = word >> 24;
                    uint enc = x < commonCount ? u.U32(commonAt + 4L * x) : x - commonCount < encCount ? u.U32(encAt + 4L * (x - commonCount)) : 0;
                    entries.Add((first + (word & 0xFFFFFF), enc));
                }
            }
        }
        uint last = indexCount > 0 ? u.U32(indexAt + 12L * (indexCount - 1)) : 0;
        for (int i = 0; i < entries.Count; i++)
        {
            var (start, enc) = entries[i];
            uint end = i + 1 < entries.Count ? entries[i + 1].Start : last;
            uint personality = (enc >> 28) & 3;
            uint? slot = personality > 0 && personality <= personalityCount ? u.U32(personalityAt + 4L * (personality - 1)) : null;
            uint? lsda = (enc & 0x40000000) != 0 && lsdas.TryGetValue(start, out var l) ? l : null;
            result.Add(new Compact(start, end, enc, lsda, slot));
        }
        return result;
    }

    // ---- frames ----

    private static readonly string[] X64Dwarf = ["rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"];
    private static readonly string[] X86Dwarf = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip"];

    private static string RegisterName(INativeImage image, int reg) => image.Arch switch
    {
        NativeArch.X64 when reg < X64Dwarf.Length => X64Dwarf[reg],
        NativeArch.X64 when reg is >= 17 and <= 32 => $"xmm{reg - 17}",
        NativeArch.X86 when reg < X86Dwarf.Length => X86Dwarf[reg],
        NativeArch.Arm64 when reg == 29 => "fp",
        NativeArch.Arm64 when reg == 30 => "lr",
        NativeArch.Arm64 when reg == 31 => "sp",
        NativeArch.Arm64 when reg < 29 => $"x{reg}",
        NativeArch.Arm64 when reg is >= 64 and < 96 => $"d{reg - 64}",
        NativeArch.Arm when reg < 16 => reg switch { 13 => "sp", 14 => "lr", 15 => "pc", _ => $"r{reg}" },
        _ => $"r{reg}",
    };

    private sealed class CfaState
    {
        public int Register = -1;
        public long Offset;
        public Dictionary<int, long> Saved = [];
        public CfaState Clone() => new() { Register = Register, Offset = Offset, Saved = new(Saved) };
    }

    /// <summary>
    /// The frame the CFI of the function at <paramref name="rva"/> sets up: the CFA rule and saved registers where the prologue
    /// ends (the deepest state before the first rule that shrinks it), or the compact unwind encoding on Mach-O.
    /// </summary>
    public static UnwindFrame? Frame(INativeImage image, uint rva)
    {
        var cfi = CfiOf(image);
        ulong va = image.ImageBase + rva;
        int lo = 0, hi = cfi.Fdes.Count - 1, found = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (cfi.Fdes[mid].Start <= va) { found = mid; lo = mid + 1; } else hi = mid - 1;
        }
        if (found >= 0 && cfi.Fdes[found] is var fde && va < fde.Start + fde.Range && Rva(image, fde.Start, out uint begin))
            return FromCfi(image, cfi.View, fde, begin);
        if (image.Format == ImageFormat.MachO && CompactEntries(image, []).FirstOrDefault(e => rva >= e.Start && rva < e.End) is { Encoding: not 0 } c)
            return FromCompact(image, c);
        if (Exidx(image) is { Count: > 0 } exidx)
        {
            lo = 0; hi = exidx.Count - 1; found = -1;
            while (lo <= hi)
            {
                int mid = (lo + hi) >>> 1;
                if (exidx[mid].Begin <= rva) { found = mid; lo = mid + 1; } else hi = mid - 1;
            }
            if (found >= 0 && rva < exidx[found].End) return FromEhabi(exidx[found]);
        }
        return null;
    }

    private static UnwindFrame FromCfi(INativeImage image, ByteView d, CfiFde fde, uint begin)
    {
        var state = new CfaState();
        var notes = new List<string>();
        var stack = new Stack<CfaState>();
        CfaState? best = null;
        ulong loc = 0, bestLoc = 0;
        bool shrunk = false;
        void Run(long from, long to, bool initial)
        {
            var r = new LebReader(d.Span(from, to - from));
            while (!r.AtEnd && !r.Failed)
            {
                byte op = r.Byte();
                int high = op & 0xC0, low = op & 0x3F;
                var before = state.Clone();
                if (high == 0x40) { loc += (ulong)low * fde.Cie.CodeAlign; continue; }
                if (high == 0x80) { state.Saved[low] = (long)r.Uleb() * fde.Cie.DataAlign; }
                else if (high == 0xC0) { state.Saved.Remove(low); shrunk |= !initial; }
                else switch (op)
                {
                    case 0x00: break;
                    case 0x01: r.Position += image.Is64Bit ? 8 : 4; break;
                    case 0x02: loc += r.Byte() * fde.Cie.CodeAlign; continue;
                    case 0x03: loc += (ulong)(r.Byte() | r.Byte() << 8) * fde.Cie.CodeAlign; continue;
                    case 0x04: loc += (uint)(r.Byte() | r.Byte() << 8 | r.Byte() << 16 | r.Byte() << 24) * fde.Cie.CodeAlign; continue;
                    case 0x05: { int reg = (int)r.Uleb(); state.Saved[reg] = (long)r.Uleb() * fde.Cie.DataAlign; break; }
                    case 0x06 or 0x07 or 0x08: state.Saved.Remove((int)r.Uleb()); shrunk |= !initial && op == 0x06; break;
                    case 0x09: r.Uleb(); r.Uleb(); break;
                    case 0x0A: stack.Push(state.Clone()); break;
                    case 0x0B: if (stack.Count > 0) state = stack.Pop(); shrunk |= !initial; break;
                    case 0x0C: state.Register = (int)r.Uleb(); state.Offset = (long)r.Uleb(); break;
                    case 0x0D: state.Register = (int)r.Uleb(); break;
                    case 0x0E: state.Offset = (long)r.Uleb(); break;
                    case 0x0F: { ulong n = r.Uleb(); r.Position += (int)Math.Min(n, 1 << 16); notes.Add("CFA from a DWARF expression"); break; }
                    case 0x10 or 0x16: { r.Uleb(); ulong n = r.Uleb(); r.Position += (int)Math.Min(n, 1 << 16); break; }
                    case 0x11: { int reg = (int)r.Uleb(); state.Saved[reg] = r.Sleb() * fde.Cie.DataAlign; break; }
                    case 0x12: state.Register = (int)r.Uleb(); state.Offset = r.Sleb() * fde.Cie.DataAlign; break;
                    case 0x13: state.Offset = r.Sleb() * fde.Cie.DataAlign; break;
                    case 0x14: r.Uleb(); r.Uleb(); break;
                    case 0x15: r.Uleb(); r.Sleb(); break;
                    case 0x2D: break; // AArch64 return-address signing state
                    case 0x2E: r.Uleb(); break;
                    case 0x2F: { int reg = (int)r.Uleb(); state.Saved[reg] = -(long)r.Uleb() * fde.Cie.DataAlign; break; }
                    default: notes.Add($"unknown CFA instruction 0x{op:X2}"); return;
                }
                if (initial || shrunk) continue;
                if (state.Offset < before.Offset && state.Register == before.Register) { shrunk = true; continue; }
                if (best == null || state.Offset != best.Offset || state.Register != best.Register || state.Saved.Count > best.Saved.Count)
                {
                    best = state.Clone();
                    bestLoc = loc;
                }
            }
        }
        Run(fde.Cie.Instructions, fde.Cie.InstructionsEnd, true);
        best = state.Clone();
        Run(fde.Instructions, fde.InstructionsEnd, false);
        var final = best ?? state;
        int sp = image.Arch switch { NativeArch.X64 => 7, NativeArch.X86 => 4, NativeArch.Arm64 => 31, NativeArch.Arm => 13, _ => -1 };
        string cfaReg = final.Register >= 0 ? RegisterName(image, final.Register) : "?";
        notes.Insert(0, $"CFA = {cfaReg}+0x{final.Offset:X}");
        if (fde.Cie.Personality != null) notes.Add("has a personality routine" + (fde.Lsda != null ? " and an LSDA (get_exception_info)" : ""));
        var saved = final.Saved.Where(kv => kv.Key != fde.Cie.ReturnColumn || image.Arch is NativeArch.Arm64 or NativeArch.Arm)
            .OrderBy(kv => kv.Value).Select(kv => $"{RegisterName(image, kv.Key)} at [CFA{(kv.Value < 0 ? "-" : "+")}{Math.Abs(kv.Value):X}h]").ToList();
        // x86 / x64: the CFA counts the return address the call pushed
        long allocation = final.Offset - (image.Arch is NativeArch.X64 or NativeArch.X86 ? (image.Is64Bit ? 8 : 4) : 0);
        return new UnwindFrame("DWARF CFI", begin, begin + (uint)Math.Min(fde.Range, uint.MaxValue - begin), (int)Math.Min(bestLoc, int.MaxValue), allocation, saved,
            final.Register >= 0 && final.Register != sp ? cfaReg : null, notes);
    }

    /// <summary>
    /// The frame EHABI unwind opcodes undo: the stack popped before anything else (the allocation), registers restored, vsp
    /// from a frame register.
    /// </summary>
    private static UnwindFrame FromEhabi(EhabiEntry e)
    {
        var saved = new List<string>();
        var notes = new List<string>();
        string? fp = null;
        long allocation = 0;
        bool leading = true;
        static string R(int r) => r switch { 13 => "sp", 14 => "lr", 15 => "pc", _ => $"r{r}" };
        void D(int first, int count) => saved.Add(count == 0 ? $"d{first}" : $"d{first}-d{first + count}");
        var ops = e.Opcodes;
        if (e.CantUnwind) notes.Add("EXIDX_CANTUNWIND");
        for (int i = 0; i < ops.Length;)
        {
            byte b = ops[i++];
            if (b < 0x40) { if (leading) allocation += ((b & 0x3F) << 2) + 4; continue; }
            if (b is not 0xB2) leading &= b == 0xB0;
            if (b < 0x80) continue; // vsp -= n: part of a frame restore
            if (b < 0x90)
            {
                int mask = i < ops.Length ? (b & 0xF) << 8 | ops[i++] : 0;
                if (mask == 0) { notes.Add("refuses to unwind"); break; }
                for (int k = 0; k < 12; k++) if ((mask & 1 << k) != 0) saved.Add(R(4 + k));
            }
            else if (b < 0xA0) { if ((b & 0xF) is not (13 or 15)) fp = R(b & 0xF); }
            else if (b < 0xB0)
            {
                for (int r = 4; r <= 4 + (b & 7); r++) saved.Add(R(r));
                if ((b & 8) != 0) saved.Add("lr");
            }
            else if (b == 0xB0) break;
            else if (b == 0xB1) { int m = i < ops.Length ? ops[i++] & 0xF : 0; for (int k = 0; k < 4; k++) if ((m & 1 << k) != 0) saved.Add(R(k)); }
            else if (b == 0xB2)
            {
                ulong v = 0;
                for (int shift = 0; i < ops.Length && shift < 32; shift += 7) { byte x = ops[i++]; v |= (ulong)(x & 0x7F) << shift; if (x < 0x80) break; }
                if (leading) allocation += 0x204 + ((long)v << 2);
            }
            else if (b is 0xB3 or 0xC8 or 0xC9) { int x = i < ops.Length ? ops[i++] : 0; D((b == 0xC8 ? 16 : 0) + (x >> 4), x & 0xF); }
            else if (b is >= 0xB8 and < 0xC0 or >= 0xD0 and < 0xD8) D(8, b & 7);
            else if (b is >= 0xC0 and < 0xC8) { if (b is 0xC6 or 0xC7) i++; notes.Add("iWMMXt registers"); }
            else { notes.Add($"spare unwind opcode 0x{b:X2}"); break; }
        }
        if (e.Note != null) notes.Add(e.Note);
        if (e.Lsda != null) notes.Add("has an LSDA (get_exception_info)");
        return new UnwindFrame("ARM EHABI", e.Begin, e.End, 0, allocation, saved, fp, notes);
    }

    private static UnwindFrame FromCompact(INativeImage image, Compact c)
    {
        uint e = c.Encoding, mode = (e >> 24) & 0xF;
        var saved = new List<string>();
        var notes = new List<string> { $"encoding 0x{e:X8}" };
        string? fp = null;
        long allocation = 0;
        if (image.Arch == NativeArch.X64)
        {
            string[] regs = ["", "rbx", "r12", "r13", "r14", "r15", "rbp"];
            switch (mode)
            {
                case 1:
                    fp = "rbp";
                    allocation = 8 * ((e >> 16) & 0xFF);
                    for (int i = 0; i < 5; i++) if (((e >> (3 * i)) & 7) is var r and > 0 and < 7) saved.Add($"{regs[r]} at [rbp-{allocation - 8 * i:X}h]");
                    notes.Add("rbp frame");
                    break;
                case 2: allocation = 8 * ((e >> 16) & 0xFF) - 8; notes.Add("frameless, immediate stack size"); break;
                case 3: notes.Add("frameless, stack size in the sub instruction"); break;
                case 4: notes.Add("described by DWARF CFI"); break;
            }
        }
        else if (image.Arch == NativeArch.Arm64)
        {
            switch (mode)
            {
                case 2: allocation = 16 * ((e >> 12) & 0xFFF); notes.Add("frameless"); break;
                case 3: notes.Add("described by DWARF CFI"); break;
                case 4:
                    fp = "fp";
                    string[] pairs = ["x19/x20", "x21/x22", "x23/x24", "x25/x26", "x27/x28", "d8/d9", "d10/d11", "d12/d13", "d14/d15"];
                    for (int i = 0; i < pairs.Length; i++) if ((e & (1u << i)) != 0) saved.Add(pairs[i]);
                    notes.Add("fp / lr frame");
                    break;
            }
        }
        if (c.Lsda != null) notes.Add("has an LSDA (get_exception_info)");
        return new UnwindFrame("compact unwind", c.Start, c.End, 0, allocation, saved, fp, notes);
    }
}
