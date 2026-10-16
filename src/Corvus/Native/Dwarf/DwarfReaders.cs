using System.Buffers.Binary;
using Corvus.Core;

namespace Corvus.Native.Dwarf;

/// <summary>
/// The readers of one debug read: the main file's, a dwz supplementary file's (.gnu_debugaltlink, .debug_sup) and one
/// per split unit (a .dwo file, or a unit of a .dwp package). Each owns an offset space: bits from
/// <see cref="SpaceShift"/> up of every offset it gives out. Owns the files it opened.
/// </summary>
internal sealed class DwarfReaders : IDisposable
{
    public const int SpaceShift = 50;
    public const long SpaceMask = ~((1L << SpaceShift) - 1);
    /// <summary>Most readers of one read (13 bits of offset space); split units past it are reported, not read.</summary>
    public const int MaxReaders = 1 << 13;

    private readonly List<DwarfReader> _readers = [];
    private readonly List<IDisposable> _owned = [];
    private readonly object _gate = new();
    private SplitUnits? _splits;

    /// <summary>The main file's sections: a split unit reads its addresses (.debug_addr) and DWARF 4 ranges there.</summary>
    public Func<string, DwarfSection?>? MainSections { get; set; }

    public bool Full { get { lock (_gate) return _readers.Count >= MaxReaders; } }

    public long Add(DwarfReader reader)
    {
        lock (_gate)
        {
            if (_readers.Count >= MaxReaders) throw new InvalidOperationException("offset spaces are exhausted");
            _readers.Add(reader);
            return (long)(_readers.Count - 1) << SpaceShift;
        }
    }

    public DwarfReader? For(long offset)
    {
        int index = (int)((ulong)offset >> SpaceShift);
        lock (_gate) return index < _readers.Count ? _readers[index] : null;
    }

    public long BySignature(ulong signature, DwarfReader asking)
    {
        DwarfReader[] all;
        lock (_gate) all = [.. _readers];
        foreach (var r in all)
            if (r != asking && r.OwnSignature(signature, out long offset)) return offset;
        return -1;
    }

    public void Own(IDisposable resource)
    {
        lock (_gate) _owned.Add(resource);
    }

    public void Dispose()
    {
        lock (_gate)
        {
            foreach (var o in _owned) o.Dispose();
            _owned.Clear();
        }
    }

    /// <summary>The split units of skeletons read from the debug file at <paramref name="debugFile"/>.</summary>
    public SplitUnits Splits(string debugFile)
    {
        lock (_gate) return _splits ??= new SplitUnits(this, debugFile);
    }

    /// <summary>
    /// Attaches the dwz supplementary file named by <paramref name="container"/>'s .gnu_debugaltlink or .debug_sup to
    /// <paramref name="main"/>: found by its recorded path, beside the debug file, under <see cref="DwarfLocator.DirsVariable"/>
    /// (as recorded and by build-id), and checked by build-id when the link carries one. Null when attached, else why not.
    /// </summary>
    public static string? AttachSupplement(DwarfReader main, DebugContainer container)
    {
        string? name = null, buildId = null;
        if (container.AltLink is { } alt) (name, buildId) = alt;
        else if (container.Section(".debug_sup") is { } sup && sup.Slice(0, 4096).ToArray() is { Length: > 3 } d && d[2] == 0)
        {
            int z = Array.IndexOf(d, (byte)0, 3);
            if (z > 3) name = System.Text.Encoding.UTF8.GetString(d, 3, z - 3);
        }
        if (name == null) return null;
        string dir = Path.GetDirectoryName(container.Path) ?? "";
        var candidates = new List<string>();
        if (Path.IsPathRooted(name)) candidates.Add(name);
        if (dir.Length > 0) { candidates.Add(Path.Combine(dir, name)); candidates.Add(Path.Combine(dir, Path.GetFileName(name))); }
        foreach (var root in DwarfLocator.Roots())
        {
            if (buildId is { Length: > 2 }) candidates.Add(Path.Combine(root, ".build-id", buildId[..2], buildId[2..] + ".debug"));
            var relative = name.Replace('\\', '/');
            int at = relative.IndexOf("/.dwz/", StringComparison.Ordinal);
            if (at >= 0) candidates.Add(Path.Combine(root, relative[(at + 1)..]));
            candidates.Add(Path.Combine(root, Path.GetFileName(name)));
        }
        var tried = new List<string>();
        foreach (var c in candidates.Distinct())
        {
            string full;
            try { full = Path.GetFullPath(c); }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { continue; }
            if (!File.Exists(full)) continue;
            DebugContainer? file = null;
            try
            {
                file = DebugContainer.Open(full);
                if (buildId != null && file.BuildId != buildId) { tried.Add($"{full} (build-id {file.BuildId ?? "none"})"); file.Dispose(); continue; }
                main.Family.Own(file);
                main.Supplement = new DwarfReader(file.Section, file.BigEndian, file.Is64 ? 8 : 4, main.Family);
                return null;
            }
            catch (ToolError e) { tried.Add($"{full} ({e.Message})"); file?.Dispose(); }
        }
        return $"the supplementary file {name}{(buildId != null ? $" (build-id {buildId})" : "")} is not found" +
               (tried.Count > 0 ? "; not matching: " + string.Join(", ", tried) : $"; set {DwarfLocator.DirsVariable} to its folder") +
               ": names and types moved there are not read";
    }
}

/// <summary>
/// Split DWARF: the split unit of each skeleton unit, from the debug file's .dwp package (&lt;file&gt;.dwp) or the
/// skeleton's .dwo file (DW_AT_dwo_name under DW_AT_comp_dir, else beside the debug file). The split unit's DWO id
/// must match the skeleton's.
/// </summary>
internal sealed class SplitUnits(DwarfReaders family, string debugFile)
{
    private readonly Dictionary<ulong, DwarfReader?> _byId = [];
    private (DebugContainer File, DwpIndex Index)? _dwp;
    private bool _dwpTried;
    private readonly object _gate = new();

    /// <summary>Split units read, and skeletons whose split unit was not found.</summary>
    public int Read, Missing;
    public List<string> Problems { get; } = [];

    /// <summary>The split unit of <paramref name="skeleton"/>, parsed; null when it cannot be found (see <see cref="Problems"/>).</summary>
    public DwarfUnit? Resolve(DwarfUnit skeleton, CancellationToken ct = default)
    {
        DwarfReader? reader;
        lock (_gate)
        {
            if (!_byId.TryGetValue(skeleton.DwoId, out reader))
            {
                reader = Open(skeleton);
                if (skeleton.DwoId != 0) _byId[skeleton.DwoId] = reader;
                if (reader == null) Missing++; else Read++;
            }
        }
        if (reader == null || reader.UnitHeaders.Count == 0) return null;
        var header = reader.UnitHeaders.FirstOrDefault(h => !h.InTypes && h.UnitType is Dw.UtCompile or Dw.UtSplitCompile);
        var unit = reader.Parse(header.End > 0 ? header : reader.UnitHeaders[0], 0, ct);
        reader.Remember(unit);
        return unit;
    }

    private DwarfReader? Open(DwarfUnit skeleton)
    {
        if (family.Full) { Note($"more than {DwarfReaders.MaxReaders} split units; the rest are not read"); return null; }
        if (Dwp() is { } dwp && dwp.Index.Find(skeleton.DwoId) is { } row)
            return Reader(skeleton, name => dwp.Index.Section(dwp.File, row, name), dwp.File);
        foreach (var path in DwoCandidates(skeleton))
        {
            if (!File.Exists(path)) continue;
            DebugContainer file;
            try { file = DebugContainer.Open(path); }
            catch (ToolError e) { Note($"{path}: {e.Message}"); continue; }
            var reader = Reader(skeleton, name => file.Section(name + ".dwo"), file);
            var head = reader.UnitHeaders.FirstOrDefault();
            if (skeleton.DwoId != 0 && head.End > 0 && reader.Parse(head, 0) is { DwoId: var id } && id != 0 && id != skeleton.DwoId)
            {
                Note($"{path}: DWO id 0x{id:X16}, the skeleton wants 0x{skeleton.DwoId:X16} (another build)");
                continue;
            }
            family.Own(file);
            return reader;
        }
        Note($"split unit {skeleton.DwoName ?? "?"} (DWO id 0x{skeleton.DwoId:X16}) is not found: no {Path.GetFileName(debugFile)}.dwp and no .dwo at its recorded path or beside the debug file");
        return null;
    }

    private DwarfReader Reader(DwarfUnit skeleton, Func<string, DwarfSection?> dwo, DebugContainer file)
    {
        var main = family.MainSections;
        DwarfSection? Section(string name) => name is ".debug_addr" or ".debug_ranges" ? main?.Invoke(name) : name == ".debug_line" ? null : dwo(name);
        return new DwarfReader(Section, file.BigEndian, file.Is64 ? 8 : 4, family)
        {
            Split = true, SplitAddrBase = skeleton.AddrBase, SplitRangesBase = skeleton.RnglistsBase, SplitBaseAddress = skeleton.BaseAddress,
        };
    }

    private IEnumerable<string> DwoCandidates(DwarfUnit skeleton)
    {
        if (skeleton.DwoName is not { Length: > 0 } name) yield break;
        string dir = Path.GetDirectoryName(debugFile) ?? "";
        if (Path.IsPathRooted(name)) yield return name;
        if (skeleton.CompDir is { Length: > 0 } comp && !Path.IsPathRooted(name)) yield return Path.Combine(comp, name);
        if (dir.Length > 0)
        {
            if (!Path.IsPathRooted(name)) yield return Path.Combine(dir, name);
            yield return Path.Combine(dir, Path.GetFileName(name.Replace('\\', '/').Split('/')[^1]));
        }
    }

    private (DebugContainer File, DwpIndex Index)? Dwp()
    {
        if (_dwpTried) return _dwp;
        _dwpTried = true;
        foreach (var path in new[] { debugFile + ".dwp", debugFile.EndsWith(".debug", StringComparison.OrdinalIgnoreCase) ? debugFile[..^6] + ".dwp" : null })
        {
            if (path == null || !File.Exists(path)) continue;
            try
            {
                var file = DebugContainer.Open(path);
                if (DwpIndex.Read(file) is { } index)
                {
                    family.Own(file);
                    return _dwp = (file, index);
                }
                Note($"{path}: no .debug_cu_index");
                file.Dispose();
            }
            catch (ToolError e) { Note($"{path}: {e.Message}"); }
        }
        return null;
    }

    private void Note(string text)
    {
        if (Problems.Count < 20 && !Problems.Contains(text)) Problems.Add(text);
    }
}

/// <summary>A .dwp package's unit index (.debug_cu_index, version 2 GNU or 5): each unit's contribution to each section.</summary>
internal sealed class DwpIndex
{
    private readonly Dictionary<ulong, int> _rows = [];
    private readonly int[] _columns = [];
    private readonly uint[] _offsets = [], _sizes = [];
    private readonly int _version;

    private DwpIndex(int version, int[] columns, uint[] offsets, uint[] sizes)
    {
        _version = version;
        _columns = columns;
        _offsets = offsets;
        _sizes = sizes;
    }

    public static DwpIndex? Read(DebugContainer file)
    {
        if ((file.Section(".debug_cu_index.dwo") ?? file.Section(".debug_cu_index")) is not { } section) return null;
        var d = section.Slice(0, section.Length).ToArray();
        if (d.Length < 16) return null;
        uint U32(int at) => at + 4 <= d.Length ? file.BigEndian ? BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(at)) : BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(at)) : 0;
        ulong U64(int at) => at + 8 <= d.Length ? file.BigEndian ? BinaryPrimitives.ReadUInt64BigEndian(d.AsSpan(at)) : BinaryPrimitives.ReadUInt64LittleEndian(d.AsSpan(at)) : 0;
        uint first = U32(0);
        int version = (first & 0xFFFF) == 5 ? 5 : (int)first;
        if (version is not (2 or 5)) return null;
        long n = U32(4), units = U32(8), slots = U32(12);
        long need = 16 + slots * 12 + n * 4 + units * n * 8;
        if (n is <= 0 or > 16 || units > 1 << 22 || slots > 1 << 23 || need > d.Length) return null;
        int at = 16;
        var signatures = new ulong[slots];
        for (int i = 0; i < slots; i++, at += 8) signatures[i] = U64(at);
        var rowOf = new uint[slots];
        for (int i = 0; i < slots; i++, at += 4) rowOf[i] = U32(at);
        var columns = new int[n];
        for (int i = 0; i < n; i++, at += 4) columns[i] = (int)U32(at);
        var offsets = new uint[units * n];
        for (int i = 0; i < offsets.Length; i++, at += 4) offsets[i] = U32(at);
        var sizes = new uint[units * n];
        for (int i = 0; i < sizes.Length; i++, at += 4) sizes[i] = U32(at);
        var index = new DwpIndex(version, columns, offsets, sizes);
        for (int i = 0; i < slots; i++)
            if (rowOf[i] is > 0 and var row && row <= units) index._rows.TryAdd(signatures[i], (int)row - 1);
        return index;
    }

    public int? Find(ulong dwoId) => _rows.TryGetValue(dwoId, out int row) ? row : null;

    /// <summary>The unit's slice of <paramref name="name"/> (a .debug_* name; the package's .dwo section); whole when the index has no column for it.</summary>
    public DwarfSection? Section(DebugContainer file, int row, string name)
    {
        if (file.Section(name + ".dwo") is not { } whole) return null;
        int id = (_version, name) switch
        {
            (_, ".debug_info") => 1,
            (2, ".debug_types") => 2,
            (_, ".debug_abbrev") => 3,
            (_, ".debug_line") => 4,
            (5, ".debug_loclists") or (2, ".debug_loc") => 5,
            (_, ".debug_str_offsets") => 6,
            (5, ".debug_rnglists") => 8,
            _ => 0,
        };
        int column = id == 0 ? -1 : Array.IndexOf(_columns, id);
        if (column < 0) return id == 0 ? whole : null;
        long cell = (long)row * _columns.Length + column;
        return new DwarfSection(whole.Name, whole.Slice(_offsets[cell], _sizes[cell]));
    }
}
