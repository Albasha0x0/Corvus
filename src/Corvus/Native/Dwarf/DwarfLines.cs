namespace Corvus.Native.Dwarf;

/// <summary>One row of a line table: the address where a source line's code starts; <see cref="End"/> closes a sequence.</summary>
internal readonly record struct DwarfLineRow(ulong Address, int File, int Line, bool End);

/// <summary>
/// A unit's line table (DWARF 2-5 line number program): the file names and the rows, sorted by address within each
/// sequence. Malformed programs keep the rows decoded so far and say why in <see cref="Problem"/>.
/// </summary>
internal sealed class DwarfLineTable
{
    /// <summary>Most rows decoded per table.</summary>
    public const int MaxRows = 4_000_000;

    public IReadOnlyList<string> Files { get; private init; } = [];
    public DwarfLineRow[] Rows { get; private init; } = [];
    public string? Problem { get; private init; }
    /// <summary>File numbering starts at 0 (DWARF 5) or 1 (earlier).</summary>
    public int FirstFile { get; private init; }

    /// <summary>The file name of a file number (directory joined), or null.</summary>
    public string? File(int index)
    {
        int i = index - FirstFile;
        return i >= 0 && i < Files.Count ? Files[i] : null;
    }

    /// <summary>The row covering <paramref name="address"/> (the last row at or before it in a sequence that has not ended), or null.</summary>
    public DwarfLineRow? At(ulong address)
    {
        // sequences are sorted by start; the last row at or before the address covers it unless it ends a sequence
        int lo = 0, hi = Rows.Length - 1, found = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (Rows[mid].Address <= address) { found = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        return found >= 0 && !Rows[found].End ? Rows[found] : null;
    }

    public static DwarfLineTable Read(DwarfSection section, long offset, int addressSize, bool bigEndian, string? compDir, DwarfSection? str, DwarfSection? lineStr,
        DwarfReaderStrings strx)
    {
        var head = section.Slice(offset, 12).Span;
        var hc = new DwarfCursor(head, bigEndian);
        ulong length = hc.U32();
        int offsetSize = 4;
        if (length == 0xFFFFFFFF) { length = hc.U64(); offsetSize = 8; }
        if (hc.Overrun || length == 0 || length > (ulong)(section.Length - offset)) return new DwarfLineTable { Problem = $"line table at 0x{offset:X}: length 0x{length:X} runs past .debug_line" };
        var bytes = section.Slice(offset, (long)length + hc.Pos);
        var c = new DwarfCursor(bytes.Span, bigEndian) { Pos = hc.Pos };
        int version = c.U16();
        if (version is < 2 or > 5) return new DwarfLineTable { Problem = $"line table at 0x{offset:X}: version {version} is not read" };
        if (version >= 5) { addressSize = c.U8(); c.U8(); }
        long headerLength = (long)c.Sized(offsetSize);
        int programStart = c.Pos + (int)Math.Min(headerLength, bytes.Length);
        int minInst = c.U8();
        if (version >= 4) c.U8(); // maximum_operations_per_instruction (VLIW only)
        c.U8(); // default_is_stmt: every row is kept
        sbyte lineBase = (sbyte)c.U8();
        int lineRange = c.U8();
        int opcodeBase = c.U8();
        var lengths = new byte[Math.Max(0, opcodeBase - 1)];
        for (int i = 0; i < lengths.Length; i++) lengths[i] = c.U8();
        if (lineRange == 0) return new DwarfLineTable { Problem = $"line table at 0x{offset:X}: line_range is 0" };

        var dirs = new List<string>();
        var files = new List<string>();
        if (version >= 5)
        {
            var dirFormat = Formats(ref c);
            ulong dirCount = c.Uleb();
            for (ulong i = 0; i < dirCount && !c.Overrun && dirs.Count < 1 << 20; i++) dirs.Add(Entry(ref c, dirFormat, offsetSize, str, lineStr, strx, out _) ?? "");
            var fileFormat = Formats(ref c);
            ulong fileCount = c.Uleb();
            for (ulong i = 0; i < fileCount && !c.Overrun && files.Count < 1 << 20; i++)
            {
                var name = Entry(ref c, fileFormat, offsetSize, str, lineStr, strx, out int dir) ?? "";
                files.Add(Join(dir >= 0 && dir < dirs.Count ? dirs[dir] : null, name));
            }
        }
        else
        {
            dirs.Add(compDir ?? "");
            while (!c.Overrun)
            {
                var d = c.CStringBytes();
                if (d.Length == 0) break;
                dirs.Add(System.Text.Encoding.UTF8.GetString(d));
            }
            while (!c.Overrun)
            {
                var f = c.CStringBytes();
                if (f.Length == 0) break;
                int dir = (int)c.Uleb();
                c.Uleb();
                c.Uleb();
                files.Add(Join(dir < dirs.Count ? dirs[dir] : null, System.Text.Encoding.UTF8.GetString(f)));
            }
        }
        c.Pos = programStart;
        var rows = new List<DwarfLineRow>();
        string? problem = null;
        ulong address = 0;
        int file = 1, line = 1;
        var sequence = new List<DwarfLineRow>();
        void Flush()
        {
            // a sequence is sorted by construction; sequences are merged afterwards
            rows.AddRange(sequence);
            sequence.Clear();
        }
        while (!c.AtEnd)
        {
            if (rows.Count + sequence.Count >= MaxRows) { problem = $"more than {MaxRows:N0} rows; the rest are not read"; break; }
            byte op = c.U8();
            if (op >= opcodeBase)
            {
                int adjusted = op - opcodeBase;
                address += (ulong)(adjusted / lineRange * minInst);
                line += lineBase + adjusted % lineRange;
                sequence.Add(new DwarfLineRow(address, file, line, false));
                continue;
            }
            switch (op)
            {
                case 0:
                {
                    ulong len = c.Uleb();
                    int end = c.Pos + (int)Math.Min(len, int.MaxValue);
                    if (len == 0) break;
                    byte ext = c.U8();
                    switch (ext)
                    {
                        case 1:
                            sequence.Add(new DwarfLineRow(address, file, line, true));
                            Flush();
                            address = 0; file = 1; line = 1;
                            break;
                        case 2: address = c.Sized((int)len - 1); break;
                    }
                    c.Pos = Math.Min(end, c.Length);
                    break;
                }
                case 1: sequence.Add(new DwarfLineRow(address, file, line, false)); break;
                case 2: address += c.Uleb() * (ulong)minInst; break;
                case 3: line += (int)c.Sleb(); break;
                case 4: file = (int)c.Uleb(); break;
                case 5: c.Uleb(); break;
                case 6 or 7 or 10 or 11: break;
                case 8: address += (ulong)((255 - opcodeBase) / lineRange * minInst); break;
                case 9: address += c.U16(); break;
                default:
                    for (int i = 0; i < (op - 1 < lengths.Length ? lengths[op - 1] : 0); i++) c.Uleb();
                    break;
            }
            if (c.Overrun) { problem = $"line table at 0x{offset:X}: the program runs past its end"; break; }
        }
        Flush();
        var sorted = SortSequences(rows);
        return new DwarfLineTable { Files = files, Rows = sorted, Problem = problem, FirstFile = version >= 5 ? 0 : 1 };
    }

    /// <summary>
    /// Orders whole sequences by start address (each is already ascending). Sequences of discarded code (the linker's
    /// tombstones: address 0, or -1 / -2) are dropped: they would overlap real code.
    /// </summary>
    private static DwarfLineRow[] SortSequences(List<DwarfLineRow> rows)
    {
        var sequences = new List<(int Start, int Count)>();
        for (int i = 0, start = 0; i < rows.Count; i++)
            if (rows[i].End || i == rows.Count - 1)
            {
                ulong first = rows[start].Address;
                if (!Tombstone(first)) sequences.Add((start, i - start + 1));
                start = i + 1;
            }
        sequences.Sort((a, b) => rows[a.Start].Address.CompareTo(rows[b.Start].Address));
        var result = new DwarfLineRow[sequences.Sum(s => s.Count)];
        int at = 0;
        foreach (var (s, n) in sequences)
        {
            rows.CopyTo(s, result, at, n);
            at += n;
        }
        return result;
    }

    /// <summary>An address the linker writes for discarded code (0, or -1 / -2 in either width).</summary>
    public static bool Tombstone(ulong a) => a is 0 or 0xFFFF_FFFF or 0xFFFF_FFFE or >= 0xFFFF_FFFF_FFFF_FFFE;

    private static string Join(string? dir, string name)
    {
        if (string.IsNullOrEmpty(dir) || name.StartsWith('/') || (name.Length > 2 && name[1] == ':')) return name;
        return dir.EndsWith('/') || dir.EndsWith('\\') ? dir + name : dir + "/" + name;
    }

    private static List<(int Type, int Form)> Formats(ref DwarfCursor c)
    {
        int count = c.U8();
        var list = new List<(int, int)>(count);
        for (int i = 0; i < count && !c.Overrun; i++) list.Add(((int)c.Uleb(), (int)c.Uleb()));
        return list;
    }

    /// <summary>One directory or file entry of a DWARF 5 header: its path (DW_LNCT_path) and directory index.</summary>
    private static string? Entry(ref DwarfCursor c, List<(int Type, int Form)> format, int offsetSize, DwarfSection? str, DwarfSection? lineStr, DwarfReaderStrings strx,
        out int dir)
    {
        string? path = null;
        dir = 0;
        foreach (var (type, form) in format)
        {
            ulong v = 0;
            string? s = null;
            switch (form)
            {
                case Dw.FormString: s = System.Text.Encoding.UTF8.GetString(c.CStringBytes()); break;
                case Dw.FormLineStrp: s = lineStr?.CString((long)c.Sized(offsetSize)); break;
                case Dw.FormStrp: s = str?.CString((long)c.Sized(offsetSize)); break;
                case Dw.FormStrx or Dw.FormGnuStrIndex: s = strx(c.Uleb()); break;
                case Dw.FormStrx1: s = strx(c.U8()); break;
                case Dw.FormStrx2: s = strx(c.U16()); break;
                case Dw.FormStrx3: s = strx(c.U24()); break;
                case Dw.FormStrx4: s = strx(c.U32()); break;
                case Dw.FormUdata: v = c.Uleb(); break;
                case Dw.FormData1: v = c.U8(); break;
                case Dw.FormData2: v = c.U16(); break;
                case Dw.FormData4: v = c.U32(); break;
                case Dw.FormData8: v = c.U64(); break;
                case Dw.FormData16: c.Advance(16); break;
                case Dw.FormBlock: c.Advance((long)c.Uleb()); break;
                default: c.Advance(long.MaxValue); return path;
            }
            if (type == 1) path = s;
            else if (type == 2) dir = (int)v;
        }
        return path;
    }
}

/// <summary>A unit's DW_FORM_strx resolver, for DWARF 5 line table headers.</summary>
internal delegate string? DwarfReaderStrings(ulong index);
