using System.Buffers.Binary;
using System.Text;

namespace Corvus.Native.Dwarf;

/// <summary>Bounds-checked reads over one unit's bytes; past the end every read returns 0 and sets <see cref="Overrun"/>.</summary>
internal ref struct DwarfCursor(ReadOnlySpan<byte> data, bool bigEndian)
{
    private readonly ReadOnlySpan<byte> _data = data;
    public int Pos;
    public bool Overrun;
    public readonly int Length => _data.Length;
    public readonly bool AtEnd => Pos >= _data.Length;

    private bool Need(int n)
    {
        if (Pos >= 0 && Pos + n <= _data.Length) return true;
        Overrun = true;
        Pos = _data.Length;
        return false;
    }

    public byte U8() => Need(1) ? _data[Pos++] : (byte)0;

    public ushort U16()
    {
        if (!Need(2)) return 0;
        var v = bigEndian ? BinaryPrimitives.ReadUInt16BigEndian(_data[Pos..]) : BinaryPrimitives.ReadUInt16LittleEndian(_data[Pos..]);
        Pos += 2;
        return v;
    }

    public uint U24()
    {
        if (!Need(3)) return 0;
        var s = _data.Slice(Pos, 3);
        Pos += 3;
        return bigEndian ? (uint)(s[0] << 16 | s[1] << 8 | s[2]) : (uint)(s[2] << 16 | s[1] << 8 | s[0]);
    }

    public uint U32()
    {
        if (!Need(4)) return 0;
        var v = bigEndian ? BinaryPrimitives.ReadUInt32BigEndian(_data[Pos..]) : BinaryPrimitives.ReadUInt32LittleEndian(_data[Pos..]);
        Pos += 4;
        return v;
    }

    public ulong U64()
    {
        if (!Need(8)) return 0;
        var v = bigEndian ? BinaryPrimitives.ReadUInt64BigEndian(_data[Pos..]) : BinaryPrimitives.ReadUInt64LittleEndian(_data[Pos..]);
        Pos += 8;
        return v;
    }

    public ulong Sized(int size) => size switch { 1 => U8(), 2 => U16(), 4 => U32(), 8 => U64(), _ => Skip(size) };

    private ulong Skip(int n)
    {
        if (Need(Math.Max(0, n))) Pos += n;
        return 0;
    }

    public void Advance(long n)
    {
        if (n < 0 || n > _data.Length - Pos) { Overrun = true; Pos = _data.Length; }
        else Pos += (int)n;
    }

    public ulong Uleb()
    {
        ulong result = 0;
        int shift = 0;
        while (true)
        {
            if (!Need(1)) return result;
            byte b = _data[Pos++];
            if (shift < 64) result |= (ulong)(b & 0x7F) << shift;
            shift += 7;
            if ((b & 0x80) == 0) return result;
        }
    }

    public long Sleb()
    {
        long result = 0;
        int shift = 0;
        byte b;
        do
        {
            if (!Need(1)) return result;
            b = _data[Pos++];
            if (shift < 64) result |= (long)(b & 0x7F) << shift;
            shift += 7;
        } while ((b & 0x80) != 0);
        if (shift < 64 && (b & 0x40) != 0) result |= -1L << shift;
        return result;
    }

    /// <summary>A NUL-terminated string's bytes (the terminator skipped).</summary>
    public ReadOnlySpan<byte> CStringBytes()
    {
        if (Pos >= _data.Length) { Overrun = true; return []; }
        var rest = _data[Pos..];
        int z = rest.IndexOf((byte)0);
        if (z < 0) { Pos = _data.Length; Overrun = true; return rest; }
        Pos += z + 1;
        return rest[..z];
    }

    public readonly ReadOnlySpan<byte> Span(int start, int length) =>
        start >= 0 && length >= 0 && start + length <= _data.Length ? _data.Slice(start, length) : [];
}

/// <summary>One abbreviation: tag, children flag and the attribute specifications.</summary>
internal sealed class DwarfAbbrev(int tag, bool children, int[] attributes, int[] forms, long[] implicitValues)
{
    public readonly int Tag = tag;
    public readonly bool Children = children;
    public readonly int[] Attributes = attributes;
    public readonly int[] Forms = forms;
    public readonly long[] Implicit = implicitValues;
}

/// <summary>
/// One debugging information entry, with the attributes the debug-info layer reads. References are absolute section
/// offsets (<see cref="DwarfReader.TypesFlag"/> marks .debug_types); -1 when absent.
/// </summary>
internal sealed class DwarfDie
{
    public long Offset;
    public int Tag;
    public int Parent = -1;
    public bool HasChildren;
    public string? Name, LinkageName;
    public long Type = -1, Specification = -1, AbstractOrigin = -1, SignatureTarget = -1;
    public ulong LowPc, HighPc;
    /// <summary>1: low_pc, 2: high_pc, 4: high_pc is an offset from low_pc.</summary>
    public byte Pc;
    /// <summary>A range list: a section offset (DWARF 2-4 .debug_ranges, 5 .debug_rnglists), or a DW_FORM_rnglistx index with <see cref="RangesIndexed"/>.</summary>
    public long Ranges = -1;
    public bool RangesIndexed;
    public long ByteSize = -1, BitSize = -1, DataBitOffset = -1, BitOffset = -1, MemberLocation = -1, Count = -1;
    public long UpperBound = long.MinValue, LowerBound;
    public long ConstValue;
    /// <summary>0: no constant; 255: signed (sdata); else the data form's byte count (sign decided by the type).</summary>
    public byte ConstSize;
    public bool External, Declaration, Artificial;
    public int Encoding, Virtuality;
    public ulong Location;
    public bool HasLocation;
    /// <summary>A variable's or parameter's location: its expression, or a location list (a section offset, or a DW_FORM_loclistx index when indexed).</summary>
    public byte[]? LocationExpr;
    public long LocationList = -1;
    public bool LocationListIndexed;
    /// <summary>A function's DW_AT_frame_base expression.</summary>
    public byte[]? FrameBase;
    public int DeclFile, DeclLine, CallFile, CallLine;
}

/// <summary>A unit's header and its entries in section order (<see cref="Dies"/>[0] is the unit entry).</summary>
internal sealed class DwarfUnit
{
    public long Offset, End, DieStart;
    public int Version, UnitType, AddressSize, OffsetSize;
    public long AbbrevOffset;
    public ulong TypeSignature;
    public long TypeOffset = -1;
    public bool InTypes;
    public int Index;
    /// <summary>Skeleton and split units: the DWO id (DWARF 5 header, or DW_AT_GNU_dwo_id); 0 otherwise.</summary>
    public ulong DwoId;
    /// <summary>A skeleton unit's DW_AT_dwo_name / DW_AT_GNU_dwo_name: the split unit's file.</summary>
    public string? DwoName;
    public List<DwarfDie> Dies = [];
    public ulong BaseAddress;
    public long StrOffsetsBase = -1, AddrBase = -1, RnglistsBase = -1, LoclistsBase = -1;
    public string? Name, CompDir;
    public long StmtList = -1;
    /// <summary>Why the entries stop early, or null.</summary>
    public string? Problem;

    public DwarfDie? At(long offset)
    {
        int lo = 0, hi = Dies.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            long o = Dies[mid].Offset;
            if (o == offset) return Dies[mid];
            if (o < offset) lo = mid + 1;
            else hi = mid - 1;
        }
        return null;
    }

    public int IndexOf(DwarfDie die)
    {
        int lo = 0, hi = Dies.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            long o = Dies[mid].Offset;
            if (o == die.Offset) return mid;
            if (o < die.Offset) lo = mid + 1;
            else hi = mid - 1;
        }
        return -1;
    }

    public DwarfDie? ParentOf(DwarfDie die) => die.Parent >= 0 && die.Parent < Dies.Count ? Dies[die.Parent] : null;

    /// <summary>The direct children of the entry at <paramref name="index"/>.</summary>
    public IEnumerable<DwarfDie> Children(int index)
    {
        if (index < 0 || index >= Dies.Count || !Dies[index].HasChildren) yield break;
        for (int i = index + 1; i < Dies.Count; i++)
        {
            var d = Dies[i];
            if (d.Parent == index) yield return d;
            else if (d.Parent < index) yield break;
        }
    }
}

/// <summary>A unit header found by <see cref="DwarfReader.Headers"/>.</summary>
internal readonly record struct DwarfUnitHeader(long Offset, long End, int Version, bool InTypes, int UnitType, ulong TypeSignature, long TypeOffset);

/// <summary>
/// Reads DWARF 2-5 units: headers, abbreviation tables, entries and their attributes (every standard form plus the
/// GNU index forms), string forms through .debug_str / .debug_line_str / .debug_str_offsets, address indices through
/// .debug_addr, and range lists (.debug_ranges, .debug_rnglists). Malformed data ends a unit with a
/// <see cref="DwarfUnit.Problem"/>, never an exception. A unit is parsed on its own (its bytes and entries live
/// while it is used); references into other units go through a small unit cache. Readers of one read share a
/// <see cref="DwarfReaders"/> family (a dwz supplementary file, split units): each owns an offset space, and
/// references, entries and ranges of another space are answered by its reader.
/// </summary>
internal sealed class DwarfReader : IDisposable
{
    /// <summary>Marks offsets in .debug_types (DWARF 4 type units).</summary>
    public const long TypesFlag = 1L << 48;
    /// <summary>Most entries one unit holds.</summary>
    public const int MaxDiesPerUnit = 8_000_000;
    private const int CachedUnits = 6;
    private const int MaxAbbrevTables = 4096;

    private readonly DwarfSection? _info, _types, _abbrev, _str, _lineStr, _strOffsets, _addr, _ranges, _rnglists;
    public readonly bool BigEndian;
    public readonly int DefaultAddressSize;
    private readonly Dictionary<(bool, long), Dictionary<ulong, DwarfAbbrev>> _abbrevs = [];
    private readonly Dictionary<ulong, long> _signatures = [];
    private readonly List<DwarfUnitHeader> _headers = [];
    private readonly LinkedList<DwarfUnit> _cache = new();
    private readonly object _gate = new();

    public DwarfSection? Line { get; }
    public IReadOnlyList<DwarfUnitHeader> UnitHeaders => _headers;
    public List<string> Problems { get; } = [];
    /// <summary>The readers of this read; the first is the main file's.</summary>
    public DwarfReaders Family { get; }
    /// <summary>This reader's offset space (high bits of every unit, entry and reference offset it gives out).</summary>
    public long Space { get; }
    /// <summary>The dwz supplementary file's reader (DW_FORM_GNU_ref_alt, DW_FORM_ref_sup, DW_FORM_GNU_strp_alt, DW_FORM_strp_sup).</summary>
    public DwarfReader? Supplement { get; set; }
    /// <summary>Split units: the skeleton's .debug_addr base, low_pc and DWARF 4 ranges base, which split units do not carry.</summary>
    internal long SplitAddrBase = -1, SplitRangesBase = -1;
    internal ulong SplitBaseAddress;
    internal bool Split;

    public DwarfReader(DebugContainer c) : this(c.Section, c.BigEndian, c.Is64 ? 8 : 4, null) { }

    /// <summary>A reader over the sections <paramref name="section"/> gives (by their .debug_* names), joining <paramref name="family"/>.</summary>
    public DwarfReader(Func<string, DwarfSection?> section, bool bigEndian, int addressSize, DwarfReaders? family)
    {
        BigEndian = bigEndian;
        DefaultAddressSize = addressSize;
        Family = family ?? new DwarfReaders();
        Space = Family.Add(this);
        if (Space == 0) Family.MainSections = section;
        _info = section(".debug_info");
        _types = section(".debug_types");
        _abbrev = section(".debug_abbrev");
        _str = section(".debug_str");
        _lineStr = section(".debug_line_str");
        _strOffsets = section(".debug_str_offsets");
        _addr = section(".debug_addr");
        _ranges = section(".debug_ranges");
        _rnglists = section(".debug_rnglists");
        Line = section(".debug_line");
        Loclists = section(".debug_loclists");
        Loc = section(".debug_loc");
        ScanHeaders(_info, false);
        ScanHeaders(_types, true);
    }

    /// <summary>DWARF 5 location lists (.debug_loclists) and DWARF 2-4 ones (.debug_loc).</summary>
    public DwarfSection? Loclists { get; }
    public DwarfSection? Loc { get; }

    /// <summary>Disposes the family's files when this is the family's main reader.</summary>
    public void Dispose()
    {
        if (Space == 0) Family.Dispose();
    }

    public bool HasInfo => _info != null && _abbrev != null;

    /// <summary>The reader owning <paramref name="offset"/>'s space: this one, or another of the family.</summary>
    private DwarfReader? Owner(long offset) => (offset & DwarfReaders.SpaceMask) == Space ? this : Family.For(offset);

    private void ScanHeaders(DwarfSection? section, bool types)
    {
        if (section == null) return;
        for (long at = 0; at + 11 <= section.Length;)
        {
            var head = section.Slice(at, 40).Span;
            var c = new DwarfCursor(head, BigEndian);
            ulong length = c.U32();
            int offsetSize = 4;
            if (length == 0xFFFFFFFF) { length = c.U64(); offsetSize = 8; }
            else if (length >= 0xFFFFFFF0) { Problems.Add($"{section.Name} unit at 0x{at:X}: reserved length 0x{length:X}; the rest of the section is not read"); return; }
            long end = at + c.Pos + (long)Math.Min(length, (ulong)long.MaxValue / 2);
            if (length == 0 || end > section.Length) { Problems.Add($"{section.Name} unit at 0x{at:X}: length 0x{length:X} runs past the section; the rest is not read"); return; }
            int version = c.U16();
            int unitType = Dw.UtCompile;
            ulong signature = 0;
            long typeOffset = -1;
            if (version >= 5)
            {
                unitType = c.U8();
                c.U8();
                c.Sized(offsetSize);
                if (unitType is Dw.UtType or Dw.UtSplitType) { signature = c.U64(); typeOffset = (long)c.Sized(offsetSize); }
            }
            else if (types)
            {
                unitType = Dw.UtType;
                c.Sized(offsetSize);
                c.U8();
                signature = c.U64();
                typeOffset = (long)c.Sized(offsetSize);
            }
            if (version is >= 2 and <= 5)
            {
                _headers.Add(new DwarfUnitHeader(at, end, version, types, unitType, signature, typeOffset));
                if (signature != 0 && typeOffset > 0) _signatures.TryAdd(signature, at + typeOffset + (types ? TypesFlag : 0) + Space);
            }
            else Problems.Add($"{section.Name} unit at 0x{at:X}: DWARF version {version} is not read");
            at = end;
        }
    }

    /// <summary>The entry a type signature names (DW_FORM_ref_sig8): this reader's type units first, then the family's; -1 when none.</summary>
    public long BySignature(ulong signature) => _signatures.TryGetValue(signature, out var o) ? o : Family.BySignature(signature, this);

    internal bool OwnSignature(ulong signature, out long offset) => _signatures.TryGetValue(signature, out offset);

    private Dictionary<ulong, DwarfAbbrev>? Abbrevs(long offset, bool types, List<string> problems)
    {
        lock (_abbrevs)
        {
            if (_abbrevs.TryGetValue((types, offset), out var cached)) return cached;
            if (_abbrev == null || offset < 0 || offset >= _abbrev.Length) { problems.Add($"abbreviation table offset 0x{offset:X} is outside .debug_abbrev"); return null; }
            var bytes = _abbrev.From(offset, 16 << 20);
            var c = new DwarfCursor(bytes.Span, BigEndian);
            var table = new Dictionary<ulong, DwarfAbbrev>();
            var attrs = new List<int>();
            var forms = new List<int>();
            var implicits = new List<long>();
            while (!c.AtEnd)
            {
                ulong code = c.Uleb();
                if (code == 0) break;
                int tag = (int)c.Uleb();
                bool children = c.U8() != 0;
                attrs.Clear(); forms.Clear(); implicits.Clear();
                while (!c.AtEnd)
                {
                    int at = (int)c.Uleb(), form = (int)c.Uleb();
                    if (at == 0 && form == 0) break;
                    attrs.Add(at);
                    forms.Add(form);
                    implicits.Add(form == Dw.FormImplicitConst ? c.Sleb() : 0);
                }
                table[code] = new DwarfAbbrev(tag, children, [.. attrs], [.. forms], [.. implicits]);
            }
            if (_abbrevs.Count >= MaxAbbrevTables) _abbrevs.Clear();
            _abbrevs[(types, offset)] = table;
            return table;
        }
    }

    /// <summary>Parses the unit of <paramref name="h"/>: its header, then every entry.</summary>
    public DwarfUnit Parse(DwarfUnitHeader h, int index, CancellationToken ct = default)
    {
        var section = h.InTypes ? _types! : _info!;
        long flag = (h.InTypes ? TypesFlag : 0) + Space;
        var bytes = section.Slice(h.Offset, h.End - h.Offset);
        var u = new DwarfUnit { Offset = h.Offset + flag, End = h.End + flag, Version = h.Version, InTypes = h.InTypes, Index = index, UnitType = h.UnitType,
            TypeSignature = h.TypeSignature };
        var c = new DwarfCursor(bytes.Span, BigEndian);
        ulong length = c.U32();
        u.OffsetSize = 4;
        if (length == 0xFFFFFFFF) { c.U64(); u.OffsetSize = 8; }
        c.U16();
        if (h.Version >= 5)
        {
            c.U8();
            u.AddressSize = c.U8();
            u.AbbrevOffset = (long)c.Sized(u.OffsetSize);
            if (h.UnitType is Dw.UtSkeleton or Dw.UtSplitCompile) u.DwoId = c.U64();
            else if (h.UnitType is Dw.UtType or Dw.UtSplitType) { c.U64(); u.TypeOffset = (long)c.Sized(u.OffsetSize); }
        }
        else
        {
            u.AbbrevOffset = (long)c.Sized(u.OffsetSize);
            u.AddressSize = c.U8();
            if (h.InTypes) { c.U64(); u.TypeOffset = (long)c.Sized(u.OffsetSize); }
        }
        if (u.AddressSize is not (2 or 4 or 8)) u.AddressSize = DefaultAddressSize;
        u.DieStart = h.Offset + c.Pos + flag;
        var problems = new List<string>();
        var abbrevs = Abbrevs(u.AbbrevOffset, h.InTypes, problems);
        if (abbrevs == null) { u.Problem = problems.FirstOrDefault(); return u; }

        // the unit entry first, for the bases its own string and address forms need (DWARF 5 puts them after the name)
        int start = c.Pos;
        var probe = new DwarfCursor(bytes.Span, BigEndian) { Pos = start };
        ReadEntries(ref probe, u, abbrevs, bytes.Span, flag, rootOnly: true, ct);
        u.Dies.Clear();
        if (Split)
        {
            if (u.AddrBase < 0) u.AddrBase = SplitAddrBase;
            if (u.RnglistsBase < 0 && u.Version < 5) u.RnglistsBase = SplitRangesBase;
            // DWARF 4 split units (GNU) index .debug_str_offsets.dwo from 0; DWARF 5 ones from past its header
            if (u.StrOffsetsBase < 0 && u.Version < 5) u.StrOffsetsBase = 0;
            u.BaseAddress = SplitBaseAddress;
        }
        ReadEntries(ref c, u, abbrevs, bytes.Span, flag, rootOnly: false, ct);
        if (u.Dies.Count > 0)
        {
            var root = u.Dies[0];
            u.Name = root.Name;
            if ((root.Pc & 1) != 0) u.BaseAddress = root.LowPc;
        }
        return u;
    }

    private void ReadEntries(ref DwarfCursor c, DwarfUnit u, Dictionary<ulong, DwarfAbbrev> abbrevs, ReadOnlySpan<byte> unit, long flag, bool rootOnly, CancellationToken ct)
    {
        int parent = -1;
        var stack = new List<int>();
        while (!c.AtEnd)
        {
            long offset = u.Offset + c.Pos;
            ulong code = c.Uleb();
            if (code == 0)
            {
                if (stack.Count == 0) { if (u.Dies.Count > 0) break; continue; }
                parent = stack[^1];
                stack.RemoveAt(stack.Count - 1);
                continue;
            }
            if (!abbrevs.TryGetValue(code, out var a)) { u.Problem = $"entry at 0x{offset - flag:X}: abbreviation code {code} is not defined; the unit's other entries are not read"; return; }
            if (u.Dies.Count >= MaxDiesPerUnit) { u.Problem = $"more than {MaxDiesPerUnit:N0} entries; the rest are not read"; return; }
            if ((u.Dies.Count & 0x3FFF) == 0) ct.ThrowIfCancellationRequested();
            var die = new DwarfDie { Offset = offset, Tag = a.Tag, Parent = parent, HasChildren = a.Children };
            for (int i = 0; i < a.Attributes.Length; i++)
            {
                if (!ReadAttribute(ref c, u, die, a.Attributes[i], a.Forms[i], a.Implicit[i], unit, flag, rootOnly))
                {
                    u.Problem = $"entry at 0x{offset - flag:X}: form 0x{a.Forms[i]:X} of attribute 0x{a.Attributes[i]:X} is not supported; the unit's other entries are not read";
                    return;
                }
            }
            if (c.Overrun) { u.Problem = $"entry at 0x{offset - flag:X} runs past the end of its unit"; return; }
            u.Dies.Add(die);
            if (rootOnly) return;
            if (a.Children)
            {
                stack.Add(parent);
                parent = u.Dies.Count - 1;
            }
        }
    }

    private bool ReadAttribute(ref DwarfCursor c, DwarfUnit u, DwarfDie die, int attr, int form, long implicitValue, ReadOnlySpan<byte> unit, long flag, bool root)
    {
        ulong value = 0;
        long signed = 0;
        int kind; // 0 constant, 1 signed constant, 2 address, 3 reference, 4 string, 5 skip, 6 block, 7 flag, 8 section offset, 9 rnglistx, 10 data16
        string? text = null;
        int blockStart = 0, blockLength = 0;
        int dataSize = 0;
        while (form == Dw.FormIndirect) form = (int)c.Uleb();
        switch (form)
        {
            case Dw.FormAddr: value = c.Sized(u.AddressSize); kind = 2; break;
            case Dw.FormData1: value = c.U8(); kind = 0; dataSize = 1; break;
            case Dw.FormData2: value = c.U16(); kind = 0; dataSize = 2; break;
            case Dw.FormData4: value = c.U32(); kind = 0; dataSize = 4; break;
            case Dw.FormData8: value = c.U64(); kind = 0; dataSize = 8; break;
            case Dw.FormData16: c.Advance(16); kind = 10; break;
            case Dw.FormSdata: signed = c.Sleb(); value = (ulong)signed; kind = 1; break;
            case Dw.FormUdata: value = c.Uleb(); kind = 0; dataSize = 8; break;
            case Dw.FormImplicitConst: signed = implicitValue; value = (ulong)signed; kind = 1; break;
            case Dw.FormFlag: value = c.U8(); kind = 7; break;
            case Dw.FormFlagPresent: value = 1; kind = 7; break;
            case Dw.FormString:
            {
                var s = c.CStringBytes();
                text = Wanted(attr) ? Encoding.UTF8.GetString(s) : null;
                kind = 4;
                break;
            }
            case Dw.FormStrp: value = c.Sized(u.OffsetSize); kind = 4; text = Wanted(attr) ? _str?.CString((long)value) : null; break;
            case Dw.FormLineStrp: value = c.Sized(u.OffsetSize); kind = 4; text = Wanted(attr) ? _lineStr?.CString((long)value) : null; break;
            case Dw.FormStrpSup or Dw.FormGnuStrpAlt: value = c.Sized(u.OffsetSize); kind = 4; text = Wanted(attr) ? Supplement?._str?.CString((long)value) : null; break;
            case Dw.FormStrx or Dw.FormGnuStrIndex: value = c.Uleb(); kind = 4; text = Wanted(attr) && !root ? StrIndex(u, value) : null; break;
            case Dw.FormStrx1: value = c.U8(); kind = 4; text = Wanted(attr) && !root ? StrIndex(u, value) : null; break;
            case Dw.FormStrx2: value = c.U16(); kind = 4; text = Wanted(attr) && !root ? StrIndex(u, value) : null; break;
            case Dw.FormStrx3: value = c.U24(); kind = 4; text = Wanted(attr) && !root ? StrIndex(u, value) : null; break;
            case Dw.FormStrx4: value = c.U32(); kind = 4; text = Wanted(attr) && !root ? StrIndex(u, value) : null; break;
            case Dw.FormAddrx or Dw.FormGnuAddrIndex: value = root ? 0 : Address(u, c.Uleb()); if (root) c.Uleb(); kind = 2; break;
            case Dw.FormAddrx1: { var i = c.U8(); value = root ? 0 : Address(u, i); kind = 2; break; }
            case Dw.FormAddrx2: { var i = c.U16(); value = root ? 0 : Address(u, i); kind = 2; break; }
            case Dw.FormAddrx3: { var i = c.U24(); value = root ? 0 : Address(u, i); kind = 2; break; }
            case Dw.FormAddrx4: { var i = c.U32(); value = root ? 0 : Address(u, i); kind = 2; break; }
            case Dw.FormRef1: value = (ulong)(u.Offset + c.U8()); kind = 3; break;
            case Dw.FormRef2: value = (ulong)(u.Offset + c.U16()); kind = 3; break;
            case Dw.FormRef4: value = (ulong)(u.Offset + c.U32()); kind = 3; break;
            case Dw.FormRef8: value = (ulong)(u.Offset + (long)c.U64()); kind = 3; break;
            case Dw.FormRefUdata: value = (ulong)(u.Offset + (long)c.Uleb()); kind = 3; break;
            case Dw.FormRefAddr: value = c.Sized(u.Version <= 2 ? u.AddressSize : u.OffsetSize) + (ulong)Space; kind = 3; break;
            case Dw.FormRefSig8:
            {
                long target = BySignature(c.U64());
                value = (ulong)target;
                kind = target >= 0 ? 3 : 5;
                break;
            }
            case Dw.FormRefSup4 or Dw.FormRefSup8 or Dw.FormGnuRefAlt:
                value = form == Dw.FormRefSup4 ? c.U32() : form == Dw.FormRefSup8 ? c.U64() : c.Sized(u.OffsetSize);
                if (Supplement != null) { value += (ulong)Supplement.Space; kind = 3; }
                else kind = 5;
                break;
            case Dw.FormSecOffset: value = c.Sized(u.OffsetSize); kind = 8; break;
            case Dw.FormLoclistx: value = c.Uleb(); kind = 11; break;
            case Dw.FormRnglistx: value = c.Uleb(); kind = 9; break;
            case Dw.FormExprloc or Dw.FormBlock: blockLength = (int)Math.Min(c.Uleb(), int.MaxValue); blockStart = c.Pos; c.Advance(blockLength); kind = 6; break;
            case Dw.FormBlock1: blockLength = c.U8(); blockStart = c.Pos; c.Advance(blockLength); kind = 6; break;
            case Dw.FormBlock2: blockLength = c.U16(); blockStart = c.Pos; c.Advance(blockLength); kind = 6; break;
            case Dw.FormBlock4: blockLength = (int)Math.Min(c.U32(), int.MaxValue); blockStart = c.Pos; c.Advance(blockLength); kind = 6; break;
            default: return false;
        }
        if (root)
        {
            // only the bases and the line table are needed from the first pass
            switch (attr)
            {
                case Dw.AtStrOffsetsBase: u.StrOffsetsBase = (long)value; break;
                case Dw.AtAddrBase or Dw.AtGnuAddrBase: u.AddrBase = (long)value; break;
                case Dw.AtRnglistsBase or Dw.AtGnuRangesBase: u.RnglistsBase = (long)value; break;
                case Dw.AtStmtList: u.StmtList = (long)value; break;
                case Dw.AtLoclistsBase: u.LoclistsBase = (long)value; break;
            }
            return true;
        }
        switch (attr)
        {
            case Dw.AtName: die.Name = text; break;
            case Dw.AtLinkageName or Dw.AtMipsLinkageName: die.LinkageName = text; break;
            case Dw.AtCompDir: u.CompDir = text; break;
            case Dw.AtDwoName or Dw.AtGnuDwoName: u.DwoName = text; break;
            case Dw.AtGnuDwoId when kind == 0: u.DwoId = value; break;
            case Dw.AtType when kind == 3: die.Type = (long)value; break;
            case Dw.AtSpecification when kind == 3: die.Specification = (long)value; break;
            case Dw.AtAbstractOrigin when kind == 3: die.AbstractOrigin = (long)value; break;
            case Dw.AtSignature when kind == 3: die.SignatureTarget = (long)value; break;
            case Dw.AtLowPc when kind == 2: die.LowPc = value; die.Pc |= 1; break;
            case Dw.AtHighPc when kind == 2: die.HighPc = value; die.Pc |= 2; break;
            case Dw.AtHighPc when kind is 0 or 1: die.HighPc = value; die.Pc |= 2 | 4; break;
            case Dw.AtRanges when kind is 8 or 0: die.Ranges = (long)value; break;
            case Dw.AtRanges when kind == 9: die.Ranges = (long)value; die.RangesIndexed = true; break;
            case Dw.AtByteSize when kind is 0 or 1: die.ByteSize = (long)value; break;
            case Dw.AtBitSize when kind is 0 or 1: die.BitSize = (long)value; break;
            case Dw.AtBitOffset when kind is 0 or 1: die.BitOffset = (long)value; break;
            case Dw.AtDataBitOffset when kind is 0 or 1: die.DataBitOffset = (long)value; break;
            case Dw.AtDataMemberLocation when kind is 0 or 1: die.MemberLocation = (long)value; break;
            case Dw.AtDataMemberLocation when kind == 6: die.MemberLocation = PlusUconst(c.Span(blockStart, blockLength)); break;
            case Dw.AtCount when kind is 0 or 1: die.Count = (long)value; break;
            case Dw.AtUpperBound when kind is 0 or 1: die.UpperBound = kind == 1 ? signed : (long)value; break;
            case Dw.AtLowerBound when kind is 0 or 1: die.LowerBound = kind == 1 ? signed : (long)value; break;
            case Dw.AtConstValue when kind is 0 or 1: die.ConstValue = (long)value; die.ConstSize = kind == 1 ? (byte)255 : (byte)dataSize; break;
            case Dw.AtExternal: die.External = value != 0; break;
            case Dw.AtDeclaration: die.Declaration = value != 0; break;
            case Dw.AtArtificial: die.Artificial = value != 0; break;
            case Dw.AtEncoding: die.Encoding = (int)value; break;
            case Dw.AtVirtuality: die.Virtuality = (int)value; break;
            case Dw.AtDeclFile: die.DeclFile = (int)value; break;
            case Dw.AtDeclLine: die.DeclLine = (int)value; break;
            case Dw.AtCallFile: die.CallFile = (int)value; break;
            case Dw.AtCallLine: die.CallLine = (int)value; break;
            case Dw.AtLocation when kind == 6:
                if (StaticAddress(c.Span(blockStart, blockLength), u) is { } address) { die.Location = address; die.HasLocation = true; }
                if (die.Tag is Dw.TagVariable or Dw.TagFormalParameter) die.LocationExpr = c.Span(blockStart, blockLength).ToArray();
                break;
            case Dw.AtLocation when kind is 8 or 0 && die.Tag is Dw.TagVariable or Dw.TagFormalParameter: die.LocationList = (long)value; break;
            case Dw.AtLocation when kind == 11: die.LocationList = (long)value; die.LocationListIndexed = true; break;
            case Dw.AtFrameBase when kind == 6: die.FrameBase = c.Span(blockStart, blockLength).ToArray(); break;
        }
        return true;
    }

    private static bool Wanted(int attr) => attr is Dw.AtName or Dw.AtLinkageName or Dw.AtMipsLinkageName or Dw.AtCompDir or Dw.AtDwoName or Dw.AtGnuDwoName;

    /// <summary>DW_OP_plus_uconst n (DWARF 2 member locations), else -1.</summary>
    private long PlusUconst(ReadOnlySpan<byte> expr)
    {
        var c = new DwarfCursor(expr, BigEndian);
        if (c.U8() != 0x23) return -1;
        var v = c.Uleb();
        return c.AtEnd && !c.Overrun ? (long)v : -1;
    }

    /// <summary>The address of a location that is exactly DW_OP_addr / DW_OP_addrx / DW_OP_GNU_addr_index, else null (TLS and computed locations).</summary>
    private ulong? StaticAddress(ReadOnlySpan<byte> expr, DwarfUnit u)
    {
        var c = new DwarfCursor(expr, BigEndian);
        ulong address;
        switch (c.U8())
        {
            case 0x03: address = c.Sized(u.AddressSize); break;
            case 0xA1 or 0xFB: address = Address(u, c.Uleb()); break;
            default: return null;
        }
        return c.AtEnd && !c.Overrun ? address : null;
    }

    private string? StrIndex(DwarfUnit u, ulong index)
    {
        if (_strOffsets == null || _str == null) return null;
        long b = u.StrOffsetsBase >= 0 ? u.StrOffsetsBase : u.OffsetSize == 8 ? 16 : 8;
        long at = b + (long)index * u.OffsetSize;
        var c = new DwarfCursor(_strOffsets.Slice(at, u.OffsetSize).Span, BigEndian);
        ulong offset = c.Sized(u.OffsetSize);
        return c.Overrun ? null : _str.CString((long)offset);
    }

    /// <summary>Entry <paramref name="index"/> of the unit's .debug_addr table; 0 when out of range.</summary>
    public ulong Address(DwarfUnit u, ulong index)
    {
        if (Owner(u.Offset) is { } owner && owner != this) return owner.Address(u, index);
        if (_addr == null) return 0;
        long b = u.AddrBase >= 0 ? u.AddrBase : 8;
        var c = new DwarfCursor(_addr.Slice(b + (long)index * u.AddressSize, u.AddressSize).Span, BigEndian);
        return c.Sized(u.AddressSize);
    }

    /// <summary>The address ranges of an entry: [low, high) pairs from low_pc/high_pc or its range list.</summary>
    public List<(ulong Low, ulong High)> RangesOf(DwarfUnit u, DwarfDie d)
    {
        if (Owner(u.Offset) is { } owner && owner != this) return owner.RangesOf(u, d);
        var list = new List<(ulong, ulong)>();
        if ((d.Pc & 3) == 3)
        {
            ulong high = (d.Pc & 4) != 0 ? d.LowPc + d.HighPc : d.HighPc;
            if (high > d.LowPc) list.Add((d.LowPc, high));
        }
        else if (d.Ranges >= 0)
        {
            if (u.Version >= 5) RngLists(u, d, list);
            else Ranges(u, (ulong)d.Ranges + (ulong)(Split && u.RnglistsBase > 0 ? u.RnglistsBase : 0), list);
        }
        else if ((d.Pc & 1) != 0) list.Add((d.LowPc, d.LowPc + 1));
        return list;
    }

    private const int MaxRanges = 1 << 16;

    private void Ranges(DwarfUnit u, ulong offset, List<(ulong, ulong)> list)
    {
        if (_ranges == null) return;
        var c = new DwarfCursor(_ranges.From((long)offset, 1 << 22).Span, BigEndian);
        ulong max = u.AddressSize == 8 ? ulong.MaxValue : u.AddressSize == 4 ? uint.MaxValue : ushort.MaxValue;
        ulong b = u.BaseAddress;
        while (!c.AtEnd && list.Count < MaxRanges)
        {
            ulong start = c.Sized(u.AddressSize), end = c.Sized(u.AddressSize);
            if (c.Overrun || start == 0 && end == 0) return;
            if (start == max) { b = end; continue; }
            if (end > start) list.Add((start + b, end + b));
        }
    }

    private void RngLists(DwarfUnit u, DwarfDie d, List<(ulong, ulong)> list)
    {
        if (_rnglists == null) return;
        long offset = d.Ranges;
        if (d.RangesIndexed)
        {
            long b = u.RnglistsBase >= 0 ? u.RnglistsBase : u.OffsetSize == 8 ? 20 : 12;
            var ic = new DwarfCursor(_rnglists.Slice(b + offset * u.OffsetSize, u.OffsetSize).Span, BigEndian);
            offset = b + (long)ic.Sized(u.OffsetSize);
            if (ic.Overrun) return;
        }
        else if (u.UnitType is Dw.UtSplitCompile && u.RnglistsBase >= 0) offset += u.RnglistsBase;
        var c = new DwarfCursor(_rnglists.From(offset, 1 << 22).Span, BigEndian);
        ulong b2 = u.BaseAddress;
        while (!c.AtEnd && list.Count < MaxRanges)
        {
            switch (c.U8())
            {
                case 0: return; // end_of_list
                case 1: b2 = Address(u, c.Uleb()); break; // base_addressx
                case 2: { ulong s = Address(u, c.Uleb()), e = Address(u, c.Uleb()); if (e > s) list.Add((s, e)); break; } // startx_endx
                case 3: { ulong s = Address(u, c.Uleb()), n = c.Uleb(); if (n > 0) list.Add((s, s + n)); break; } // startx_length
                case 4: { ulong s = c.Uleb(), e = c.Uleb(); if (e > s) list.Add((b2 + s, b2 + e)); break; } // offset_pair
                case 5: b2 = c.Sized(u.AddressSize); break; // base_address
                case 6: { ulong s = c.Sized(u.AddressSize), e = c.Sized(u.AddressSize); if (e > s) list.Add((s, e)); break; } // start_end
                case 7: { ulong s = c.Sized(u.AddressSize), n = c.Uleb(); if (n > 0) list.Add((s, s + n)); break; } // start_length
                default: return;
            }
            if (c.Overrun) return;
        }
    }

    /// <summary>The unit holding <paramref name="offset"/> (parsed, or from the cache), or null.</summary>
    public DwarfUnit? UnitAt(long offset, CancellationToken ct = default)
    {
        if (Owner(offset) is not { } owner) return null;
        if (owner != this) return owner.UnitAt(offset, ct);
        lock (_gate)
        {
            foreach (var cached in _cache)
                if (offset >= cached.Offset && offset < cached.End)
                {
                    _cache.Remove(cached);
                    _cache.AddFirst(cached);
                    return cached;
                }
        }
        long raw = offset - Space;
        bool types = raw >= TypesFlag;
        if (types) raw -= TypesFlag;
        int lo = 0, hi = _headers.Count - 1, found = -1;
        while (lo <= hi)
        {
            // headers: .debug_info ones in order, then .debug_types ones in order
            int mid = (lo + hi) >>> 1;
            var h = _headers[mid];
            int cmp = h.InTypes != types ? (h.InTypes ? 1 : -1) : h.End <= raw ? -1 : h.Offset > raw ? 1 : 0;
            if (cmp == 0) { found = mid; break; }
            if (cmp < 0) lo = mid + 1;
            else hi = mid - 1;
        }
        if (found < 0) return null;
        var unit = Parse(_headers[found], found, ct);
        Remember(unit);
        return unit;
    }

    /// <summary>Keeps <paramref name="unit"/> in the small cache that cross-unit references and lookups use.</summary>
    public void Remember(DwarfUnit unit)
    {
        lock (_gate)
        {
            foreach (var cached in _cache)
                if (cached.Offset == unit.Offset) return;
            _cache.AddFirst(unit);
            while (_cache.Count > CachedUnits) _cache.RemoveLast();
        }
    }

    /// <summary>The entry at an absolute offset (in <paramref name="near"/> when it holds it), or null.</summary>
    public (DwarfUnit Unit, DwarfDie Die)? Entry(long offset, DwarfUnit near)
    {
        if (offset < 0) return null;
        if (offset >= near.Offset && offset < near.End) return near.At(offset) is { } d ? (near, d) : null;
        var u = UnitAt(offset);
        return u?.At(offset) is { } die ? (u, die) : null;
    }
}
