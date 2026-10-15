using System.Buffers.Binary;
using System.Text;

namespace Corvus.Native.Pdb;

/// <summary>A source position that has code: the file as the PDB names it, its line and the code address.</summary>
public sealed record PdbLineAddress(string File, int Line, uint Rva);

/// <summary>
/// Source lines of a native PDB: each module's C13 line subsections (DEBUG_S_LINES) with its file checksums
/// (DEBUG_S_FILECHKSMS) and the /names string table. Read from the file on the first lookup, since most uses of a PDB
/// never ask for lines.
/// </summary>
public sealed class PdbLines : IDebugSourceLookup
{
    private const uint DebugSLines = 0xF2, DebugSFileChecksums = 0xF4;
    // line numbers the compiler uses to mark hidden code (no source line)
    private const int HiddenLine = 0xFEEFEE, HiddenLine2 = 0xF00F00;

    /// <summary>Most line entries kept (16 bytes each).</summary>
    public const int MaxEntries = 8_000_000;

    private readonly PdbFile _pdb;
    private readonly Func<MsfFile> _open;
    private readonly int _namesStream;
    private readonly Lazy<Table> _table;

    internal PdbLines(PdbFile pdb, Func<MsfFile> open, int namesStream)
    {
        _pdb = pdb;
        _open = open;
        _namesStream = namesStream;
        _table = new Lazy<Table>(Read);
    }

    /// <summary>Line runs sorted by start: [Start, End) has <see cref="Lines"/>[i] of file <see cref="Files"/>[i].</summary>
    private sealed record Table(uint[] Starts, uint[] Ends, int[] Lines, int[] Files, string[] FileNames, int Blocks, IReadOnlyList<string> Notes);

    public int LineTables => _table.Value.Blocks;
    public int InlinedInstances => 0;
    /// <summary>What reading the line tables could not take (malformed subsections, the entry limit).</summary>
    public IReadOnlyList<string> Notes => _table.Value.Notes;
    /// <summary>The source files the line tables name.</summary>
    public IReadOnlyList<string> SourceFiles => _table.Value.FileNames;

    public IReadOnlyList<DebugSourceInfo?> Lookup(IReadOnlyList<uint> rvas, CancellationToken ct = default)
    {
        var t = _table.Value;
        var result = new DebugSourceInfo?[rvas.Count];
        for (int k = 0; k < rvas.Count; k++)
        {
            ct.ThrowIfCancellationRequested();
            int i = Array.BinarySearch(t.Starts, rvas[k]);
            if (i < 0) i = ~i - 1;
            if (i < 0 || rvas[k] >= t.Ends[i]) continue;
            var file = t.FileNames[t.Files[i]];
            var function = FunctionAt(rvas[k]) ?? "";
            result[k] = new DebugSourceInfo(file, t.Lines[i], [new DebugSourceFrame(function, file, t.Lines[i])]);
        }
        return result;
    }

    /// <summary>
    /// The code addresses of <paramref name="line"/> in the files whose path ends with <paramref name="file"/> (whole path
    /// components, any case or separator); a line with no code moves to the next line that has some, as debuggers place a
    /// stop point. Empty when no file matches.
    /// </summary>
    public IReadOnlyList<PdbLineAddress> Addresses(string file, int line)
    {
        var t = _table.Value;
        var wanted = Components(file);
        var files = Enumerable.Range(0, t.FileNames.Length).Where(f => EndsWith(Components(t.FileNames[f]), wanted)).ToHashSet();
        var result = new List<PdbLineAddress>();
        foreach (var f in files)
        {
            int best = int.MaxValue;
            for (int i = 0; i < t.Lines.Length; i++)
                if (t.Files[i] == f && t.Lines[i] >= line && t.Lines[i] < best) best = t.Lines[i];
            if (best == int.MaxValue) continue;
            for (int i = 0; i < t.Lines.Length; i++)
                if (t.Files[i] == f && t.Lines[i] == best) result.Add(new PdbLineAddress(t.FileNames[f], best, t.Starts[i]));
        }
        return [.. result.OrderBy(r => r.Rva)];
    }

    private static string[] Components(string path) =>
        path.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);

    private static bool EndsWith(string[] path, string[] tail) =>
        tail.Length > 0 && tail.Length <= path.Length
        && tail.Select((c, i) => string.Equals(c, path[path.Length - tail.Length + i], StringComparison.OrdinalIgnoreCase)).All(x => x);

    private string? FunctionAt(uint rva)
    {
        string? name = null;
        foreach (var s in _pdb.Symbols)
        {
            if (s.Rva is not { } at || at > rva) break;
            if (s.Kind is PdbSymbolKind.GlobalProc or PdbSymbolKind.LocalProc && rva < at + Math.Max(1, s.Size)) name = s.Name;
        }
        return name;
    }

    private Table Read()
    {
        var notes = new List<string>();
        var runs = new List<(uint Start, uint End, int Line, int File)>();
        var fileIds = new Dictionary<string, int>(StringComparer.Ordinal);
        var fileNames = new List<string>();
        int blocks = 0;
        using var msf = _open();
        var names = _namesStream >= 0 && msf.HasStream(_namesStream) ? msf.ReadStream(_namesStream) : [];
        if (names.Length < 12 || BinaryPrimitives.ReadUInt32LittleEndian(names) != 0xEFFEEFFE)
        {
            notes.Add("no /names string table: source files are named by their checksum entry");
            names = [];
        }

        string NameAt(uint offset)
        {
            long at = 12 + (long)offset;
            if (names.Length == 0 || at >= names.Length) return $"file@{offset:X}";
            int end = names.AsSpan((int)at).IndexOf((byte)0);
            return Encoding.UTF8.GetString(names, (int)at, end < 0 ? names.Length - (int)at : end);
        }

        foreach (var m in _pdb.Modules)
        {
            if (m.C13Bytes == 0 || m.SymbolStream == 0xFFFF || !msf.HasStream(m.SymbolStream)) continue;
            // a damaged module record can claim more than its stream holds
            long c13At = (long)m.SymbolBytes + m.C11Bytes, available = msf.StreamSize(m.SymbolStream) - c13At;
            if (available <= 0) continue;
            var bytes = new byte[Math.Min(m.C13Bytes, Math.Min(available, 1L << 28))];
            int got = msf.Read(m.SymbolStream, c13At, bytes);
            var c13 = bytes.AsSpan(0, got);
            // the checksum subsection first: the line blocks name files by their offset in it
            var checksums = ReadOnlySpan<byte>.Empty;
            var subsections = Subsections(c13, notes, m);
            foreach (var (kind, start, length) in subsections)
                if (kind == DebugSFileChecksums) { checksums = c13.Slice(start, length); break; }
            foreach (var (kind, start, length) in subsections)
            {
                var data = c13.Slice(start, length);
                if (kind != DebugSLines || data.Length < 12) continue;
                uint offCon = BinaryPrimitives.ReadUInt32LittleEndian(data);
                ushort segCon = BinaryPrimitives.ReadUInt16LittleEndian(data[4..]);
                bool columns = (BinaryPrimitives.ReadUInt16LittleEndian(data[6..]) & 1) != 0;
                uint cbCon = BinaryPrimitives.ReadUInt32LittleEndian(data[8..]);
                if (_pdb.ToRva(segCon, offCon) is not { } conStart) continue;
                int at = 12;
                while (at + 12 <= data.Length)
                {
                    uint fileId = BinaryPrimitives.ReadUInt32LittleEndian(data[at..]);
                    int count = (int)BinaryPrimitives.ReadUInt32LittleEndian(data[(at + 4)..]);
                    int cbBlock = (int)BinaryPrimitives.ReadUInt32LittleEndian(data[(at + 8)..]);
                    if (cbBlock < 12 || at + cbBlock > data.Length || count < 0 || 12 + (long)count * (columns ? 12 : 8) > cbBlock)
                    {
                        notes.Add($"module {m.Index} ({m.Name}): a line block does not fit its subsection; the rest of it is skipped");
                        break;
                    }
                    blocks++;
                    string file = fileId + 4 <= checksums.Length ? NameAt(BinaryPrimitives.ReadUInt32LittleEndian(checksums[(int)fileId..])) : $"file@{fileId:X}";
                    if (!fileIds.TryGetValue(file, out int fileIndex)) { fileIndex = fileNames.Count; fileIds[file] = fileIndex; fileNames.Add(file); }
                    for (int i = 0; i < count; i++)
                    {
                        var e = data.Slice(at + 12 + i * 8, 8);
                        uint offset = BinaryPrimitives.ReadUInt32LittleEndian(e);
                        int line = (int)(BinaryPrimitives.ReadUInt32LittleEndian(e[4..]) & 0xFFFFFF);
                        uint next = i + 1 < count ? BinaryPrimitives.ReadUInt32LittleEndian(data[(at + 12 + (i + 1) * 8)..]) : cbCon;
                        if (line is HiddenLine or HiddenLine2 || next <= offset) continue;
                        if (runs.Count >= MaxEntries) { notes.Add($"line entries beyond {MaxEntries:N0} left out"); goto done; }
                        runs.Add((conStart + offset, conStart + next, line, fileIndex));
                    }
                    at += cbBlock;
                }
            }
        }
    done:
        runs.Sort((a, b) => a.Start.CompareTo(b.Start));
        return new Table([.. runs.Select(r => r.Start)], [.. runs.Select(r => r.End)], [.. runs.Select(r => r.Line)], [.. runs.Select(r => r.File)],
            [.. fileNames], blocks, notes);
    }

    /// <summary>The C13 subsections of a module: (kind, data offset, length), each 4-byte aligned; a malformed one ends the list with a note.</summary>
    private static List<(uint Kind, int Start, int Length)> Subsections(ReadOnlySpan<byte> c13, List<string> notes, PdbModule m)
    {
        var list = new List<(uint, int, int)>();
        int at = 0;
        while (at + 8 <= c13.Length)
        {
            uint kind = BinaryPrimitives.ReadUInt32LittleEndian(c13[at..]);
            int length = (int)BinaryPrimitives.ReadUInt32LittleEndian(c13[(at + 4)..]);
            if (length < 0 || at + 8 + (long)length > c13.Length)
            {
                notes.Add($"module {m.Index} ({m.Name}): C13 subsection 0x{kind:X} does not fit the module stream; the rest is skipped");
                break;
            }
            // kinds with the high bit set are ignorable; their data is skipped like any other
            list.Add((kind & 0x7FFFFFFF, at + 8, length));
            at += 8 + (length + 3) / 4 * 4;
        }
        return list;
    }
}
