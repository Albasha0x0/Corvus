using System.Buffers.Binary;
using System.Text;
using Corvus.Native.Pe;

namespace Corvus.Native.Pdb;

public enum PdbSymbolKind
{
    /// <summary>S_GPROC32 / S_GPROC32_ID: a global function with its code size.</summary>
    GlobalProc,
    /// <summary>S_LPROC32 / S_LPROC32_ID: a file-static function.</summary>
    LocalProc,
    /// <summary>S_PUB32 flagged as code.</summary>
    PublicFunction,
    /// <summary>S_PUB32 not flagged as code (data, or a public without type information).</summary>
    PublicData,
    /// <summary>S_THUNK32: incremental-linking and adjustor thunks.</summary>
    Thunk,
    /// <summary>S_GDATA32.</summary>
    GlobalData,
    /// <summary>S_LDATA32 (file statics and function statics).</summary>
    LocalData,
}

/// <summary>
/// One symbol with an address. <see cref="Rva"/> is null when the segment:offset does not map into the image.
/// <see cref="TypeIndex"/>: the type record of a procedure or data symbol (TPI; IPI for the _ID procedure kinds), 0 for others.
/// </summary>
public sealed record PdbSymbol(PdbSymbolKind Kind, string Name, ushort Segment, uint Offset, uint? Rva, uint Size, int Module, uint TypeIndex = 0)
{
    /// <summary>DWARF: the linkage (mangled) name, when there is one.</summary>
    public string? LinkageName { get; init; }
    /// <summary>DWARF: a function's parameter names in order (null where unnamed).</summary>
    public IReadOnlyList<string?>? ParameterNames { get; init; }

    public bool IsFunction => Kind is PdbSymbolKind.GlobalProc or PdbSymbolKind.LocalProc or PdbSymbolKind.PublicFunction or PdbSymbolKind.Thunk;
    public bool IsPublic => Kind is PdbSymbolKind.PublicFunction or PdbSymbolKind.PublicData;
}

/// <summary>An S_UDT record of the global symbols: a type name (typedef or tag) and its type record.</summary>
public sealed record PdbTypedef(string Name, uint TypeIndex);

/// <summary>A compiland of the DBI module list.</summary>
public sealed record PdbModule(int Index, string Name, string ObjectFile, int SymbolStream, uint SymbolBytes)
{
    /// <summary>Bytes of C11 line information after the symbols in the module stream (old compilers).</summary>
    public uint C11Bytes { get; init; }
    /// <summary>Bytes of C13 debug subsections (lines, file checksums) after the C11 lines.</summary>
    public uint C13Bytes { get; init; }
}

/// <summary>Where debug information came from: a PDB, or DWARF (an ELF or Mach-O image, a separate debug file, a dSYM).</summary>
public enum DebugInfoFormat { Pdb, Dwarf }

/// <summary>A source position in <see cref="Function"/> (an inlined function in a frame).</summary>
public sealed record DebugSourceFrame(string Function, string? File, int Line);

/// <summary>
/// What debug information says about an address: its source line and the functions there, innermost first; an
/// inlined frame's line is its call site in the next frame. The last frame is the function itself.
/// </summary>
public sealed record DebugSourceInfo(string? File, int Line, IReadOnlyList<DebugSourceFrame> Frames)
{
    /// <summary>DWARF: the parameters and locals in scope at the address, with their locations there.</summary>
    public IReadOnlyList<DebugVariable>? Variables { get; init; }
}

/// <summary>A parameter or local variable at an address: its type, where it is ("rdi", "[rbp-0x14]"), and the inlined function it belongs to.</summary>
public sealed record DebugVariable(string Name, string? Type, string Location, bool Parameter, string? InlinedIn);

/// <summary>Source lines and inlined functions by address, read on demand (debug files can be large).</summary>
public interface IDebugSourceLookup
{
    /// <summary>One answer per RVA; null where the debug information has none.</summary>
    IReadOnlyList<DebugSourceInfo?> Lookup(IReadOnlyList<uint> rvas, CancellationToken ct = default);
    /// <summary>Units with a line table.</summary>
    int LineTables { get; }
    /// <summary>Inlined function instances.</summary>
    int InlinedInstances { get; }
}

/// <summary>A section of the image as the PDB recorded it (IMAGE_SECTION_HEADER).</summary>
public sealed record PdbSection(string Name, uint VirtualAddress, uint VirtualSize, uint Characteristics);

/// <summary>
/// A native PDB (MSF 7.0): identity (PDB info stream GUID and age, DBI age), module list, section headers, OMAP, and
/// the symbols with addresses (publics, global and local data, and functions from the module streams). Type records
/// (TPI) are read on demand by <see cref="PdbTypeModel"/>. Only the superblock check throws; every
/// later problem is recorded in <see cref="Issues"/> and the readable part is kept.
/// </summary>
public sealed class PdbFile
{
    private const int InfoStream = 1;
    private const int DbiStream = 3;

    public string Path { get; }
    public long FileSize { get; }
    public uint BlockSize { get; }
    public int StreamCount { get; }
    /// <summary>PDB info stream version (20000404 for VC7.0 and later); 0 when the stream is missing.</summary>
    public uint Version { get; private set; }
    public Guid Guid { get; private set; }
    /// <summary>Age in the PDB info stream (incremented on every PDB write).</summary>
    public uint InfoAge { get; private set; }
    /// <summary>Age in the DBI stream: the one the image's CodeView record carries; 0 when the DBI stream is missing.</summary>
    public uint DbiAge { get; private set; }
    public ushort Machine { get; private set; }
    public IReadOnlyList<PdbModule> Modules { get; private set; } = [];
    public IReadOnlyList<PdbSection> Sections { get; private set; } = [];
    /// <summary>The image was rearranged after linking (OMAP present): addresses map through it.</summary>
    public bool HasOmap { get; private set; }
    /// <summary>Sorted by RVA (unmapped symbols last).</summary>
    public IReadOnlyList<PdbSymbol> Symbols { get; private set; } = [];
    /// <summary>Type names of the global symbols (S_UDT), in stream order.</summary>
    public IReadOnlyList<PdbTypedef> Typedefs => _typedefs;
    /// <summary>Everything a limit cut short.</summary>
    public IReadOnlyList<string> Truncations => _truncations;
    public IReadOnlyList<ParseIssue> Issues { get; private set; } = [];
    public DebugInfoFormat Format { get; private init; }
    /// <summary>DWARF: the debug file's GNU build-id or Mach-O UUID (lowercase hex), else null.</summary>
    public string? BuildId { get; private init; }
    /// <summary>Source lines (and for DWARF inlined functions); null when the debug information has no line tables.</summary>
    public IDebugSourceLookup? Source { get; private set; }
    /// <summary>DWARF: its types as CodeView records (TPI body, record offsets, notes); null for a PDB, whose types are read from its file.</summary>
    internal (byte[] Bytes, int[] Offsets, IReadOnlyList<string> Notes)? TypeRecords { get; private init; }

    private readonly List<string> _truncations = [];
    private readonly List<PdbTypedef> _typedefs = [];
    /// <summary>Most S_UDT records kept.</summary>
    public const int MaxTypedefs = 1_000_000;
    private readonly IssueLog _log = new("pdb");
    private (uint From, uint To)[] _omap = [];
    private IReadOnlyList<PdbSection> _addressSections = [];

    private PdbFile(string path, long fileSize)
    {
        Path = path;
        FileSize = fileSize;
    }

    /// <summary>Debug information of another format (DWARF) in the PDB model: symbols with RVAs, units as modules, type records.</summary>
    internal static PdbFile FromDebugInfo(string path, long fileSize, string? buildId, IReadOnlyList<PdbModule> modules, List<PdbSymbol> symbols,
        IEnumerable<PdbTypedef> typedefs, (byte[] Bytes, int[] Offsets, IReadOnlyList<string> Notes) types, IReadOnlyList<ParseIssue> issues,
        IEnumerable<string> truncations, IDebugSourceLookup? source)
    {
        symbols.Sort((a, b) => a.Rva is { } x ? b.Rva is { } y ? x.CompareTo(y) : -1 : b.Rva is null ? 0 : 1);
        var pdb = new PdbFile(path, fileSize)
        {
            Format = DebugInfoFormat.Dwarf, BuildId = buildId, Modules = modules, Symbols = symbols, Issues = issues, TypeRecords = types, Source = source,
        };
        pdb._typedefs.AddRange(typedefs);
        foreach (var t in truncations) pdb.AddTruncation(t);
        return pdb;
    }

    private PdbFile(string path, MsfFile msf)
    {
        Path = path;
        FileSize = msf.FileLength;
        BlockSize = msf.BlockSize;
        StreamCount = msf.StreamCount;
    }

    /// <summary>
    /// Reads a PDB file page by page. <paramref name="imageSections"/> (the image's section table) maps addresses when the
    /// PDB has no section header stream.
    /// </summary>
    public static PdbFile Open(string path, IReadOnlyList<NativeSection>? imageSections = null, CancellationToken ct = default)
    {
        using var msf = MsfFile.Open(path);
        var full = System.IO.Path.GetFullPath(path);
        return Read(msf, full, imageSections, () => MsfFile.Open(full), ct);
    }

    public static PdbFile FromBytes(byte[] bytes, IReadOnlyList<NativeSection>? imageSections = null, CancellationToken ct = default)
    {
        using var msf = MsfFile.FromBytes(bytes);
        return Read(msf, "", imageSections, () => MsfFile.FromBytes(bytes), ct);
    }

    /// <summary>Only the identity (info stream GUID/age and DBI age): cheap, for matching candidates.</summary>
    public static (Guid Guid, uint InfoAge, uint DbiAge) ReadIdentity(string path)
    {
        using var msf = MsfFile.Open(path);
        var pdb = new PdbFile(path, msf);
        pdb.ReadInfo(msf);
        var dbi = msf.ReadStream(DbiStream, 64);
        uint dbiAge = dbi.Length >= 12 ? BinaryPrimitives.ReadUInt32LittleEndian(dbi.AsSpan(8)) : 0;
        return (pdb.Guid, pdb.InfoAge, dbiAge);
    }

    /// <summary>Whether this PDB belongs to an image with CodeView record <paramref name="cv"/> (RSDS: GUID and age).</summary>
    public bool Matches(PeCodeView cv) => Format == DebugInfoFormat.Pdb && cv.Format == "RSDS" && cv.Guid == Guid && cv.Age == (DbiAge != 0 ? DbiAge : InfoAge);

    private static PdbFile Read(MsfFile msf, string path, IReadOnlyList<NativeSection>? imageSections, Func<MsfFile> reopen, CancellationToken ct)
    {
        var pdb = new PdbFile(path, msf);
        int names = pdb.ReadInfo(msf);
        var symbols = new List<PdbSymbol>();
        pdb.ReadDbi(msf, imageSections, symbols, ct);
        symbols.Sort((a, b) => a.Rva is { } x ? b.Rva is { } y ? x.CompareTo(y) : -1 : b.Rva is null ? 0 : 1);
        pdb.Symbols = symbols;
        if (pdb.Modules.Any(m => m.C13Bytes > 0)) pdb.Source = new PdbLines(pdb, reopen, names);
        pdb.Issues = [.. msf.Issues, .. pdb._log.ToList()];
        return pdb;
    }

    /// <summary>Reads the identity; returns the /names stream from the named stream map, or -1.</summary>
    private int ReadInfo(MsfFile msf)
    {
        var info = msf.ReadStream(InfoStream, 1 << 20);
        if (info.Length < 28)
        {
            _log.Add("the PDB info stream (1) is missing or shorter than 28 bytes: no GUID and age");
            return -1;
        }
        Version = BinaryPrimitives.ReadUInt32LittleEndian(info);
        InfoAge = BinaryPrimitives.ReadUInt32LittleEndian(info.AsSpan(8));
        Guid = new Guid(info.AsSpan(12, 16));
        return NamedStream(info.AsSpan(28), "/names");
    }

    /// <summary>
    /// A stream of the named stream map after the info header: the names buffer, then a hash table (size, capacity, present
    /// and deleted bit vectors, then one (name offset, stream) pair per present bucket); -1 when absent or malformed.
    /// </summary>
    internal static int NamedStream(ReadOnlySpan<byte> map, string wanted)
    {
        if (map.Length < 4) return -1;
        int bufferSize = (int)Le32(map, 0);
        if (bufferSize < 0 || 4 + (long)bufferSize + 12 > map.Length) return -1;
        var buffer = map.Slice(4, bufferSize);
        int at = 4 + bufferSize;
        int capacity = (int)Le32(map, at + 4);
        at += 8;
        int presentWords = (int)Le32(map, at);
        if (presentWords < 0 || at + 4 + (long)presentWords * 4 + 4 > map.Length) return -1;
        var present = map.Slice(at + 4, presentWords * 4);
        at += 4 + presentWords * 4;
        int deletedWords = (int)Le32(map, at);
        if (deletedWords < 0 || at + 4 + (long)deletedWords * 4 > map.Length) return -1;
        at += 4 + deletedWords * 4;
        for (int bucket = 0; bucket < capacity && bucket < presentWords * 32; bucket++)
        {
            if ((present[bucket / 8] & (1 << (bucket % 8))) == 0) continue;
            if (at + 8 > map.Length) return -1;
            uint nameOffset = Le32(map, at), stream = Le32(map, at + 4);
            at += 8;
            if (nameOffset >= (uint)buffer.Length) continue;
            int end = buffer[(int)nameOffset..].IndexOf((byte)0);
            if (end >= 0 && Encoding.UTF8.GetString(buffer.Slice((int)nameOffset, end)) == wanted) return (int)stream;
        }
        return -1;
    }

    private void ReadDbi(MsfFile msf, IReadOnlyList<NativeSection>? imageSections, List<PdbSymbol> symbols, CancellationToken ct)
    {
        long dbiSize = msf.StreamSize(DbiStream);
        var header = msf.ReadStream(DbiStream, 64);
        if (header.Length < 64)
        {
            _log.Add("the DBI stream (3) is missing or shorter than its 64-byte header: no modules, sections or symbols");
            UseImageSections(imageSections);
            return;
        }
        var h = header.AsSpan();
        DbiAge = Le32(h, 8);
        int globalStream = Le16(h, 12);
        int publicStream = Le16(h, 16);
        int symRecordStream = Le16(h, 20);
        long modInfoSize = (int)Le32(h, 24), secContribSize = (int)Le32(h, 28), secMapSize = (int)Le32(h, 32);
        long sourceInfoSize = (int)Le32(h, 36), typeServerSize = (int)Le32(h, 40), dbgHeaderSize = (int)Le32(h, 48);
        long ecSize = (int)Le32(h, 52);
        Machine = Le16(h, 58);
        _ = globalStream; _ = publicStream;

        long[] sizes = [modInfoSize, secContribSize, secMapSize, sourceInfoSize, typeServerSize, ecSize, dbgHeaderSize];
        long at = 64;
        var offsets = new long[sizes.Length];
        for (int i = 0; i < sizes.Length; i++)
        {
            if (sizes[i] < 0 || at + sizes[i] > dbiSize)
            {
                _log.Add($"DBI substream {i} (size {sizes[i]}) does not fit in the {dbiSize}-byte DBI stream; it and those after it are skipped");
                for (int j = i; j < sizes.Length; j++) sizes[j] = 0;
                break;
            }
            offsets[i] = at;
            at += sizes[i];
        }

        ReadSectionHeaders(msf, offsets[6], sizes[6], imageSections);
        Modules = ReadModules(msf, offsets[0], sizes[0]);

        // the symbol record stream holds publics and global data (and references to module procedures)
        if (symRecordStream != 0xFFFF && msf.HasStream(symRecordStream))
            ReadSymbols(msf, symRecordStream, 0, msf.StreamSize(symRecordStream), -1, symbols, ct);
        else if (symRecordStream == 0xFFFF || symRecordStream >= msf.StreamCount)
            _log.Add("no symbol record stream: no public or global data symbols");

        foreach (var m in Modules)
        {
            ct.ThrowIfCancellationRequested();
            if (m.SymbolStream == 0xFFFF || m.SymbolBytes <= 4) continue;
            if (!msf.HasStream(m.SymbolStream))
            {
                _log.Add($"module {m.Index} ({m.Name}): symbol stream {m.SymbolStream} is missing");
                continue;
            }
            // the module stream starts with a 4-byte signature (4 = C13)
            ReadSymbols(msf, m.SymbolStream, 4, m.SymbolBytes - 4, m.Index, symbols, ct);
            if (symbols.Count >= PdbLimits.MaxSymbols) break;
        }
    }

    private void UseImageSections(IReadOnlyList<NativeSection>? imageSections)
    {
        if (imageSections == null || Sections.Count > 0) return;
        Sections = imageSections.Select(s => new PdbSection(s.Name, s.Rva, s.VirtualSize, s.Characteristics)).ToList();
        _addressSections = Sections;
    }

    private void ReadSectionHeaders(MsfFile msf, long offset, long size, IReadOnlyList<NativeSection>? imageSections)
    {
        // optional debug header: stream numbers of FPO, exception, fixup, OMAP to/from source, section headers, ...
        int count = (int)Math.Min(size / 2, 16);
        var streams = new int[11];
        Array.Fill(streams, 0xFFFF);
        if (count > 0)
        {
            var buf = new byte[count * 2];
            msf.Read(DbiStream, offset, buf);
            for (int i = 0; i < Math.Min(count, streams.Length); i++) streams[i] = BinaryPrimitives.ReadUInt16LittleEndian(buf.AsSpan(i * 2));
        }
        Sections = ReadSectionStream(msf, streams[5]);
        _addressSections = Sections;
        if (msf.HasStream(streams[4]) && msf.HasStream(streams[10]))
        {
            // the image was rearranged after linking: symbols address the original sections, mapped through OMAP
            var original = ReadSectionStream(msf, streams[10]);
            var omap = ReadOmap(msf, streams[4]);
            if (original.Count > 0 && omap.Length > 0)
            {
                _addressSections = original;
                _omap = omap;
                HasOmap = true;
            }
        }
        if (Sections.Count == 0)
        {
            if (imageSections != null) _log.Add("no section header stream in the PDB: addresses use the image's section table");
            else _log.Add("no section header stream in the PDB: symbol addresses are not mapped");
            UseImageSections(imageSections);
        }
    }

    private List<PdbSection> ReadSectionStream(MsfFile msf, int stream)
    {
        var list = new List<PdbSection>();
        if (stream == 0xFFFF || !msf.HasStream(stream)) return list;
        var bytes = msf.ReadStream(stream, PdbLimits.MaxSections * 40);
        if (msf.StreamSize(stream) > (long)PdbLimits.MaxSections * 40) AddTruncation($"section headers beyond {PdbLimits.MaxSections}");
        for (int i = 0; i + 40 <= bytes.Length; i += 40)
        {
            var s = bytes.AsSpan(i, 40);
            int len = s[..8].IndexOf((byte)0);
            string name = Encoding.UTF8.GetString(len < 0 ? s[..8] : s[..len]);
            list.Add(new PdbSection(name, Le32(s, 12), Le32(s, 8), Le32(s, 36)));
        }
        return list;
    }

    private (uint, uint)[] ReadOmap(MsfFile msf, int stream)
    {
        long size = msf.StreamSize(stream);
        long n = Math.Min(size / 8, PdbLimits.MaxOmapEntries);
        if (size / 8 > n) AddTruncation($"OMAP entries beyond {PdbLimits.MaxOmapEntries}");
        var bytes = msf.ReadStream(stream, (int)(n * 8));
        var map = new (uint, uint)[bytes.Length / 8];
        for (int i = 0; i < map.Length; i++)
            map[i] = (BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i * 8)), BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i * 8 + 4)));
        bool sorted = true;
        for (int i = 1; i < map.Length && sorted; i++) sorted = map[i - 1].Item1 <= map[i].Item1;
        if (!sorted)
        {
            _log.Add("OMAP entries are not sorted; sorted before use");
            Array.Sort(map, (a, b) => a.Item1.CompareTo(b.Item1));
        }
        return map;
    }

    /// <summary>segment:offset to an RVA (through OMAP when present); null when it maps nowhere.</summary>
    public uint? ToRva(ushort segment, uint offset)
    {
        if (segment == 0 || segment > _addressSections.Count) return null;
        ulong rva = (ulong)_addressSections[segment - 1].VirtualAddress + offset;
        if (rva > uint.MaxValue) return null;
        if (!HasOmap) return (uint)rva;
        int lo = 0, hi = _omap.Length - 1, found = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (_omap[mid].From <= rva) { found = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        if (found < 0 || _omap[found].To == 0) return null;
        ulong mapped = _omap[found].To + (rva - _omap[found].From);
        return mapped <= uint.MaxValue ? (uint)mapped : null;
    }

    private List<PdbModule> ReadModules(MsfFile msf, long offset, long size)
    {
        var list = new List<PdbModule>();
        if (size <= 0) return list;
        var r = new MsfStreamReader(msf, DbiStream, offset, size);
        var fixedPart = new byte[64];
        var nameBuf = new byte[PdbLimits.MaxNameLength * 2 + 2];
        while (r.Remaining >= 64)
        {
            if (list.Count >= PdbLimits.MaxModules) { AddTruncation($"modules beyond {PdbLimits.MaxModules}"); break; }
            long start = r.Position;
            r.TryRead(fixedPart);
            int stream = Le16(fixedPart, 34);
            uint symBytes = Le32(fixedPart, 36), c11Bytes = Le32(fixedPart, 40), c13Bytes = Le32(fixedPart, 44);
            // two zero-terminated names follow (module name, object file name), then padding to 4
            int avail = (int)Math.Min(nameBuf.Length, r.Remaining);
            int got = msf.Read(DbiStream, r.Position, nameBuf.AsSpan(0, avail));
            var span = nameBuf.AsSpan(0, got);
            int z1 = span.IndexOf((byte)0);
            if (z1 < 0) { _log.Add($"module {list.Count}: name is not terminated; the module list ends here", start); break; }
            int z2 = span[(z1 + 1)..].IndexOf((byte)0);
            if (z2 < 0) { _log.Add($"module {list.Count}: object file name is not terminated; the module list ends here", start); break; }
            string name = Encoding.UTF8.GetString(span[..z1]);
            string obj = Encoding.UTF8.GetString(span.Slice(z1 + 1, z2));
            long next = r.Position + z1 + 1 + z2 + 1;
            next = (next - offset + 3) / 4 * 4 + offset;
            list.Add(new PdbModule(list.Count, name, obj, stream, symBytes) { C11Bytes = c11Bytes, C13Bytes = c13Bytes });
            r.Position = Math.Min(next, r.End);
        }
        return list;
    }

    private void ReadSymbols(MsfFile msf, int stream, long start, long length, int module, List<PdbSymbol> symbols, CancellationToken ct)
    {
        long avail = msf.StreamSize(stream) - start;
        if (length > avail)
        {
            _log.Add($"symbols of {(module < 0 ? "the symbol record stream" : $"module {module}")}: {length} bytes declared, {Math.Max(0, avail)} in stream {stream}");
            length = Math.Max(0, avail);
        }
        if (length > PdbLimits.MaxSymbolStreamBytes)
        {
            AddTruncation($"symbol stream {stream} beyond {PdbLimits.MaxSymbolStreamBytes} bytes");
            length = PdbLimits.MaxSymbolStreamBytes;
        }
        var r = new MsfStreamReader(msf, stream, start, length);
        var record = new byte[ushort.MaxValue + 1];
        int n = 0;
        while (r.Remaining >= 4)
        {
            if ((++n & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
            long at = r.Position;
            r.TryReadU16(out var len);
            if (len < 2)
            {
                _log.Add($"stream {stream}: symbol record at 0x{at:X} has length {len}; the rest of the stream is skipped");
                return;
            }
            if (len > r.Remaining)
            {
                _log.Add($"stream {stream}: symbol record at 0x{at:X} (length {len}) runs past the end; the rest is skipped");
                return;
            }
            var body = record.AsSpan(0, len);
            r.TryRead(body);
            ushort kind = BinaryPrimitives.ReadUInt16LittleEndian(body);
            var data = body[2..];
            if (Parse(kind, data, module) is { } sym)
            {
                if (symbols.Count >= PdbLimits.MaxSymbols) { AddTruncation($"symbols beyond {PdbLimits.MaxSymbols}"); return; }
                symbols.Add(sym);
            }
        }
    }

    private PdbSymbol? Parse(ushort kind, ReadOnlySpan<byte> d, int module)
    {
        switch (kind)
        {
            case 0x110E: // S_PUB32: flags, offset, segment, name
                if (d.Length < 10) return Short(kind);
                return Make(((Le32(d, 0) & 2) != 0) ? PdbSymbolKind.PublicFunction : PdbSymbolKind.PublicData, d, 4, 8, 10, 0, module, -1);
            case 0x110D or 0x110C: // S_GDATA32 / S_LDATA32: type, offset, segment, name
                if (d.Length < 10) return Short(kind);
                return Make(kind == 0x110D ? PdbSymbolKind.GlobalData : PdbSymbolKind.LocalData, d, 4, 8, 10, 0, module, 0);
            case 0x1110 or 0x1147 or 0x110F or 0x1146 or 0x1155 or 0x1156:
                // S_GPROC32(_ID) / S_LPROC32(_ID) / S_LPROC32_DPC(_ID): parent, end, next, length, dbg start/end, type, offset, segment, flags, name
                if (d.Length < 35) return Short(kind);
                return Make(kind is 0x1110 or 0x1147 ? PdbSymbolKind.GlobalProc : PdbSymbolKind.LocalProc, d, 28, 32, 35, Le32(d, 12), module, 24);
            case 0x1102: // S_THUNK32: parent, end, next, offset, segment, length, ordinal, name
                if (d.Length < 21) return Short(kind);
                return Make(PdbSymbolKind.Thunk, d, 12, 16, 21, Le16(d, 18), module, -1);
            case 0x1108 when module < 0: // S_UDT of the global symbols: type, name
                if (d.Length < 5) return Short(kind);
                if (_typedefs.Count >= MaxTypedefs) { AddTruncation($"type names (S_UDT) beyond {MaxTypedefs}"); return null; }
                var udt = d[4..];
                int end = udt.IndexOf((byte)0);
                if (end > 0 && end <= PdbLimits.MaxNameLength) _typedefs.Add(new PdbTypedef(Encoding.UTF8.GetString(udt[..end]), Le32(d, 0)));
                return null;
            default:
                return null;
        }
    }

    private PdbSymbol? Short(ushort kind)
    {
        _log.Add($"symbol record of kind 0x{kind:X4} is shorter than its fixed fields");
        return null;
    }

    private PdbSymbol? Make(PdbSymbolKind kind, ReadOnlySpan<byte> d, int offsetAt, int segmentAt, int nameAt, uint size, int module, int typeAt)
    {
        var rest = d[nameAt..];
        int len = rest.IndexOf((byte)0);
        if (len < 0) len = rest.Length;
        if (len == 0) return null;
        if (len > PdbLimits.MaxNameLength) len = PdbLimits.MaxNameLength;
        string name = Encoding.UTF8.GetString(rest[..len]);
        uint offset = Le32(d, offsetAt);
        ushort segment = Le16(d, segmentAt);
        return new PdbSymbol(kind, name, segment, offset, ToRva(segment, offset), size, module, typeAt >= 0 ? Le32(d, typeAt) : 0);
    }

    private void AddTruncation(string text)
    {
        if (!_truncations.Contains(text)) _truncations.Add(text);
    }

    private static uint Le32(ReadOnlySpan<byte> s, int at) => BinaryPrimitives.ReadUInt32LittleEndian(s[at..]);
    private static ushort Le16(ReadOnlySpan<byte> s, int at) => BinaryPrimitives.ReadUInt16LittleEndian(s[at..]);
}
