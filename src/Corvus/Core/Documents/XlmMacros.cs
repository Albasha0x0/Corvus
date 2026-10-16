using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Xml;

namespace Corvus.Core.Documents;

/// <summary>A sheet of a workbook: its kind (worksheet, macro sheet, chart, VBA module) and visibility.</summary>
internal sealed record WorkbookSheet(string Name, string Type, string State);

/// <summary>A formula cell of an Excel 4.0 macro sheet.</summary>
internal sealed record XlmCell(string Sheet, string Cell, string Formula);

/// <summary>
/// Excel 4.0 (XLM) macros of a workbook: sheets with their kind and visibility, defined names (Auto_Open and the other
/// built-in names) and the formulas of the macro sheets. Reads the BIFF8 / BIFF5 Workbook stream of an .xls and the
/// macrosheets parts of an .xlsm; formulas are decoded from their parsed tokens to text.
/// </summary>
internal sealed class XlmMacros
{
    public List<WorkbookSheet> Sheets { get; } = [];
    public List<string> Names { get; } = [];
    public List<XlmCell> Cells { get; } = [];
    public List<string> Notes { get; } = [];
    public bool Encrypted { get; private set; }

    /// <summary>Most formula cells kept.</summary>
    private const int MaxCells = 20_000;

    public bool HasMacroSheets => Sheets.Any(s => s.Type == "macro sheet");

    /// <summary>The macro text as olevba scans it: one line per defined name and per formula cell.</summary>
    public string Text => string.Join("\n", Names.Concat(Cells.Select(c => $"{c.Sheet}!{c.Cell}: {c.Formula}")));

    private static readonly string[] BuiltInNames =
        ["Consolidate_Area", "Auto_Open", "Auto_Close", "Extract", "Database", "Criteria", "Print_Area", "Print_Titles", "Recorder", "Data_Form",
         "Auto_Activate", "Auto_Deactivate", "Sheet_Title", "_FilterDatabase"];

    /// <summary>The macros of a BIFF Workbook (or Book) stream.</summary>
    public static XlmMacros FromBiff(byte[] stream, CancellationToken ct)
    {
        var x = new XlmMacros();
        var positions = new List<(uint At, string Name)>();
        bool biff8 = true;
        int pos = 0, records = 0;
        while (pos + 4 <= stream.Length)
        {
            if ((++records & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            int id = BinaryPrimitives.ReadUInt16LittleEndian(stream.AsSpan(pos));
            int len = BinaryPrimitives.ReadUInt16LittleEndian(stream.AsSpan(pos + 2));
            if (pos + 4 + len > stream.Length) break;
            var d = stream.AsSpan(pos + 4, len);
            pos += 4 + len;
            switch (id)
            {
                case 0x0809 when len >= 2 && records == 1:
                    biff8 = BinaryPrimitives.ReadUInt16LittleEndian(d) >= 0x0600;
                    break;
                case 0x002F:
                    x.Encrypted = true;
                    x.Notes.Add("the workbook is encrypted (FILEPASS): records after it are not readable");
                    return x;
                case 0x0085 when len >= 7:
                    var name = ShortString(d[6..], biff8);
                    int dt = d[5];
                    var type = dt switch { 0 => "worksheet", 1 => "macro sheet", 2 => "chart", 6 => "VBA module", _ => $"type {dt}" };
                    var state = (d[4] & 3) switch { 0 => "visible", 1 => "hidden", 2 => "very hidden", _ => "unknown" };
                    x.Sheets.Add(new WorkbookSheet(name, type, state));
                    if (dt == 1) positions.Add((BinaryPrimitives.ReadUInt32LittleEndian(d), name));
                    break;
                case 0x0018 when len >= 14:
                    x.ReadName(d, biff8);
                    break;
                case 0x000A:
                    pos = stream.Length; // end of the globals substream
                    break;
            }
        }
        foreach (var (at, sheet) in positions) x.ReadSheet(stream, at, sheet, biff8, ct);
        return x;
    }

    private void ReadName(ReadOnlySpan<byte> d, bool biff8)
    {
        int grbit = BinaryPrimitives.ReadUInt16LittleEndian(d);
        int cch = d[3];
        int cce = BinaryPrimitives.ReadUInt16LittleEndian(d[4..]);
        int at = 14;
        string name;
        if (biff8)
        {
            if (at >= d.Length) return;
            bool wide = (d[at] & 1) != 0;
            at++;
            int bytes = wide ? cch * 2 : cch;
            if (at + bytes > d.Length) return;
            name = wide ? Encoding.Unicode.GetString(d.Slice(at, bytes)) : Encoding.Latin1.GetString(d.Slice(at, bytes));
            at += bytes;
        }
        else
        {
            if (at + cch > d.Length) return;
            name = Encoding.Latin1.GetString(d.Slice(at, cch));
            at += cch;
        }
        if ((grbit & 0x20) != 0 && name.Length > 0 && name[0] < BuiltInNames.Length) name = BuiltInNames[name[0]] + name[1..];
        var formula = at + cce <= d.Length ? Formula(d.Slice(at, cce), biff8) : "";
        Names.Add($"Name {name}{((grbit & 1) != 0 ? " (hidden)" : "")} = {formula}");
    }

    private void ReadSheet(byte[] stream, uint at, string sheet, bool biff8, CancellationToken ct)
    {
        if (at >= stream.Length) { Notes.Add($"macro sheet {sheet}: its substream offset lies past the stream"); return; }
        int pos = (int)at, records = 0;
        while (pos + 4 <= stream.Length)
        {
            if ((++records & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            int id = BinaryPrimitives.ReadUInt16LittleEndian(stream.AsSpan(pos));
            int len = BinaryPrimitives.ReadUInt16LittleEndian(stream.AsSpan(pos + 2));
            if (pos + 4 + len > stream.Length) break;
            var d = stream.AsSpan(pos + 4, len);
            pos += 4 + len;
            if (id == 0x000A) break;
            if (id != 0x0006 || len < 22) continue;
            if (Cells.Count >= MaxCells) { Notes.Add($"stopped at {MaxCells:N0} formula cells"); return; }
            int row = BinaryPrimitives.ReadUInt16LittleEndian(d), col = BinaryPrimitives.ReadUInt16LittleEndian(d[2..]);
            int cce = BinaryPrimitives.ReadUInt16LittleEndian(d[20..]);
            var rgce = d[22..];
            Cells.Add(new XlmCell(sheet, Cell(row, col & 0xFF), Formula(rgce[..Math.Min(cce, rgce.Length)], biff8)));
        }
    }

    private static string ShortString(ReadOnlySpan<byte> d, bool biff8)
    {
        if (d.Length < 1) return "";
        int cch = d[0];
        if (!biff8) return Encoding.Latin1.GetString(d.Slice(1, Math.Min(cch, d.Length - 1)));
        if (d.Length < 2) return "";
        bool wide = (d[1] & 1) != 0;
        var chars = d[2..];
        return wide ? Encoding.Unicode.GetString(chars[..Math.Min(cch * 2, chars.Length & ~1)]) : Encoding.Latin1.GetString(chars[..Math.Min(cch, chars.Length)]);
    }

    private static string Cell(int row, int col)
    {
        var letters = "";
        for (int c = col + 1; c > 0; c = (c - 1) / 26) letters = (char)('A' + (c - 1) % 26) + letters;
        return letters + (row + 1).ToString(CultureInfo.InvariantCulture);
    }

    private static string Ref(int row, int colField, bool biff8) =>
        biff8 ? Cell(row, colField & 0x3FFF) : Cell(row & 0x3FFF, colField);

    private static readonly string[] Binary = ["+", "-", "*", "/", "^", "&", "<", "<=", "=", ">=", ">", "<>", " ", ",", ":"];

    /// <summary>A parsed formula (rgce) as text; a token it does not know ends it with "?".</summary>
    public static string Formula(ReadOnlySpan<byte> f, bool biff8)
    {
        var stack = new Stack<string>();
        int i = 0;
        string Pop() => stack.Count > 0 ? stack.Pop() : "";
        int length = f.Length;
        bool Need(int n) => i + n <= length;
        while (i < f.Length)
        {
            int ptg = f[i++];
            int baseId = ptg < 0x20 ? ptg : (ptg & 0x1F) | 0x20;
            switch (baseId)
            {
                case 0x01 or 0x02: if (!Need(4)) return Done(stack, true); i += 4; break;
                case >= 0x03 and <= 0x11:
                    var right = Pop(); var left = Pop();
                    stack.Push(left + Binary[baseId - 3] + right);
                    break;
                case 0x12: stack.Push("+" + Pop()); break;
                case 0x13: stack.Push("-" + Pop()); break;
                case 0x14: stack.Push(Pop() + "%"); break;
                case 0x15: stack.Push("(" + Pop() + ")"); break;
                case 0x16: stack.Push(""); break;
                case 0x17:
                    if (!Need(biff8 ? 2 : 1)) return Done(stack, true);
                    int cch = f[i++];
                    bool wide = biff8 && (f[i++] & 1) != 0;
                    int bytes = wide ? cch * 2 : cch;
                    if (!Need(bytes)) return Done(stack, true);
                    var s = wide ? Encoding.Unicode.GetString(f.Slice(i, bytes)) : Encoding.Latin1.GetString(f.Slice(i, bytes));
                    i += bytes;
                    stack.Push("\"" + s.Replace("\"", "\"\"") + "\"");
                    break;
                case 0x19:
                    if (!Need(3)) return Done(stack, true);
                    int grbit = f[i];
                    int w = BinaryPrimitives.ReadUInt16LittleEndian(f[(i + 1)..]);
                    i += 3;
                    if ((grbit & 0x04) != 0) { if (!Need((w + 1) * 2)) return Done(stack, true); i += (w + 1) * 2; }
                    if ((grbit & 0x10) != 0) stack.Push("SUM(" + Pop() + ")");
                    break;
                case 0x1C: if (!Need(1)) return Done(stack, true); stack.Push("#ERR" + f[i++]); break;
                case 0x1D: if (!Need(1)) return Done(stack, true); stack.Push(f[i++] != 0 ? "TRUE" : "FALSE"); break;
                case 0x1E: if (!Need(2)) return Done(stack, true); stack.Push(BinaryPrimitives.ReadUInt16LittleEndian(f[i..]).ToString(CultureInfo.InvariantCulture)); i += 2; break;
                case 0x1F: if (!Need(8)) return Done(stack, true); stack.Push(BinaryPrimitives.ReadDoubleLittleEndian(f[i..]).ToString("R", CultureInfo.InvariantCulture)); i += 8; break;
                case 0x20: if (!Need(biff8 ? 7 : 7)) return Done(stack, true); i += 7; stack.Push("{array}"); break;
                case 0x21:
                {
                    if (!Need(biff8 ? 2 : 1)) return Done(stack, true);
                    int id = biff8 ? BinaryPrimitives.ReadUInt16LittleEndian(f[i..]) : f[i];
                    i += biff8 ? 2 : 1;
                    stack.Push(Call(stack, XlmFunctions.Name(id), XlmFunctions.Arity(id)));
                    break;
                }
                case 0x22:
                {
                    if (!Need(biff8 ? 3 : 2)) return Done(stack, true);
                    int args = f[i] & 0x7F;
                    int id = biff8 ? BinaryPrimitives.ReadUInt16LittleEndian(f[(i + 1)..]) : f[i + 1];
                    i += biff8 ? 3 : 2;
                    stack.Push(Call(stack, XlmFunctions.Name(id), args));
                    break;
                }
                case 0x23: if (!Need(biff8 ? 4 : 14)) return Done(stack, true); stack.Push("Name#" + BinaryPrimitives.ReadUInt16LittleEndian(f[i..])); i += biff8 ? 4 : 14; break;
                case 0x24 or 0x2C:
                    if (!Need(biff8 ? 4 : 3)) return Done(stack, true);
                    stack.Push(biff8 ? Ref(BinaryPrimitives.ReadUInt16LittleEndian(f[i..]), BinaryPrimitives.ReadUInt16LittleEndian(f[(i + 2)..]), true)
                        : Ref(BinaryPrimitives.ReadUInt16LittleEndian(f[i..]), f[i + 2], false));
                    i += biff8 ? 4 : 3;
                    break;
                case 0x25 or 0x2D:
                    if (!Need(biff8 ? 8 : 6)) return Done(stack, true);
                    if (biff8)
                        stack.Push(Ref(BinaryPrimitives.ReadUInt16LittleEndian(f[i..]), BinaryPrimitives.ReadUInt16LittleEndian(f[(i + 4)..]), true) + ":" +
                                   Ref(BinaryPrimitives.ReadUInt16LittleEndian(f[(i + 2)..]), BinaryPrimitives.ReadUInt16LittleEndian(f[(i + 6)..]), true));
                    else
                        stack.Push(Ref(BinaryPrimitives.ReadUInt16LittleEndian(f[i..]), f[i + 4], false) + ":" + Ref(BinaryPrimitives.ReadUInt16LittleEndian(f[(i + 2)..]), f[i + 5], false));
                    i += biff8 ? 8 : 6;
                    break;
                case 0x26 or 0x27 or 0x28: if (!Need(6)) return Done(stack, true); i += 6; break;
                case 0x29: if (!Need(2)) return Done(stack, true); i += 2; break;
                case 0x2A: if (!Need(biff8 ? 4 : 3)) return Done(stack, true); i += biff8 ? 4 : 3; stack.Push("#REF!"); break;
                case 0x2B: if (!Need(biff8 ? 8 : 6)) return Done(stack, true); i += biff8 ? 8 : 6; stack.Push("#REF!"); break;
                case 0x39: if (!Need(biff8 ? 6 : 24)) return Done(stack, true); stack.Push("NameX#" + BinaryPrimitives.ReadUInt16LittleEndian(f[(i + (biff8 ? 2 : 10))..])); i += biff8 ? 6 : 24; break;
                case 0x3A when biff8:
                    if (!Need(6)) return Done(stack, true);
                    stack.Push("!" + Ref(BinaryPrimitives.ReadUInt16LittleEndian(f[(i + 2)..]), BinaryPrimitives.ReadUInt16LittleEndian(f[(i + 4)..]), true));
                    i += 6;
                    break;
                case 0x3B when biff8:
                    if (!Need(10)) return Done(stack, true);
                    stack.Push("!" + Ref(BinaryPrimitives.ReadUInt16LittleEndian(f[(i + 2)..]), BinaryPrimitives.ReadUInt16LittleEndian(f[(i + 6)..]), true) + ":" +
                               Ref(BinaryPrimitives.ReadUInt16LittleEndian(f[(i + 4)..]), BinaryPrimitives.ReadUInt16LittleEndian(f[(i + 8)..]), true));
                    i += 10;
                    break;
                case 0x3C when biff8: if (!Need(6)) return Done(stack, true); i += 6; stack.Push("#REF!"); break;
                case 0x3D when biff8: if (!Need(10)) return Done(stack, true); i += 10; stack.Push("#REF!"); break;
                default: return Done(stack, true);
            }
        }
        return Done(stack, false);
    }

    private static string Call(Stack<string> stack, string name, int args)
    {
        var list = new string[Math.Min(args, stack.Count)];
        for (int k = list.Length - 1; k >= 0; k--) list[k] = stack.Pop();
        return name + "(" + string.Join(",", list) + ")";
    }

    private static string Done(Stack<string> stack, bool cut) => string.Join(" ", stack.Reverse()) + (cut ? " ?" : "");

    /// <summary>Whether the bytes are a SYLK (.slk) file.</summary>
    public static bool IsSylk(ReadOnlySpan<byte> b) => b.StartsWith("ID;"u8);

    /// <summary>A SYLK file's macro sheet: an O record with the E option marks it; NN records name cells, C records' E fields are formulas.</summary>
    public static XlmMacros FromSylk(byte[] data)
    {
        var x = new XlmMacros();
        bool macro = false;
        int row = 1, col = 1;
        foreach (var raw in Encoding.Latin1.GetString(data).Split('\n'))
        {
            var fields = raw.TrimEnd('\r').Split(';');
            switch (fields[0])
            {
                case "O" when fields.Skip(1).Any(f => f.StartsWith('E')):
                    macro = true;
                    x.Sheets.Add(new WorkbookSheet("SLK", "macro sheet", "visible"));
                    break;
                case "NN" when macro:
                    var name = fields.FirstOrDefault(f => f.StartsWith('N') && f != "NN");
                    var target = fields.FirstOrDefault(f => f.StartsWith('E'));
                    if (name != null) x.Names.Add($"Name {name[1..]} = {target?[1..]}");
                    break;
                case "C" when macro:
                    foreach (var f in fields.Skip(1))
                    {
                        if (f.StartsWith('Y') && int.TryParse(f[1..], out var y)) row = y;
                        else if (f.StartsWith('X') && int.TryParse(f[1..], out var c)) col = c;
                    }
                    if (fields.FirstOrDefault(f => f.StartsWith('E')) is { } e && x.Cells.Count < MaxCells) x.Cells.Add(new XlmCell("SLK", Cell(row - 1, col - 1), e[1..]));
                    break;
            }
        }
        return x;
    }

    /// <summary>The macro sheets of an .xlsm / .xltm: workbook.xml for sheets and names, xl/macrosheets/*.xml for formulas.</summary>
    public static XlmMacros? FromOoxml(System.IO.Compression.ZipArchive zip, CancellationToken ct)
    {
        var workbook = zip.GetEntry("xl/workbook.xml");
        var macroParts = zip.Entries.Where(e => e.FullName.StartsWith("xl/macrosheets/", StringComparison.OrdinalIgnoreCase) && e.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)).ToList();
        if (workbook == null && macroParts.Count == 0) return null;
        var x = new XlmMacros();
        var targets = Relationships(zip, "xl/_rels/workbook.xml.rels");
        var partNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (workbook != null)
        {
            var doc = Load(workbook);
            foreach (XmlElement s in doc.GetElementsByTagName("sheet"))
            {
                var name = s.GetAttribute("name");
                var rid = s.GetAttribute("id", "http://schemas.openxmlformats.org/officeDocument/2006/relationships");
                var target = targets.GetValueOrDefault(rid);
                var type = target != null && target.Contains("macrosheets/", StringComparison.OrdinalIgnoreCase) ? "macro sheet"
                    : target != null && target.Contains("chartsheets/", StringComparison.OrdinalIgnoreCase) ? "chart" : "worksheet";
                var state = s.GetAttribute("state") switch { "hidden" => "hidden", "veryHidden" => "very hidden", _ => "visible" };
                x.Sheets.Add(new WorkbookSheet(name, type, state));
                if (target != null) partNames["xl/" + target.TrimStart('/').Replace("xl/", "", StringComparison.OrdinalIgnoreCase)] = name;
            }
            foreach (XmlElement n in doc.GetElementsByTagName("definedName"))
            {
                var name = n.GetAttribute("name");
                if (name.StartsWith("_xlnm.", StringComparison.Ordinal)) name = name[6..];
                x.Names.Add($"Name {name}{(n.GetAttribute("hidden") == "1" ? " (hidden)" : "")} = {n.InnerText}");
            }
        }
        foreach (var part in macroParts)
        {
            ct.ThrowIfCancellationRequested();
            var sheet = partNames.GetValueOrDefault(part.FullName) ?? Path.GetFileNameWithoutExtension(part.Name);
            if (!x.Sheets.Any(s => s.Name == sheet)) x.Sheets.Add(new WorkbookSheet(sheet, "macro sheet", "visible"));
            foreach (XmlElement c in Load(part).GetElementsByTagName("c"))
            {
                if (x.Cells.Count >= MaxCells) { x.Notes.Add($"stopped at {MaxCells:N0} formula cells"); return x; }
                if (c.GetElementsByTagName("f") is { Count: > 0 } f) x.Cells.Add(new XlmCell(sheet, c.GetAttribute("r"), f[0]!.InnerText));
            }
        }
        if (zip.Entries.Any(e => e.FullName.StartsWith("xl/macrosheets/", StringComparison.OrdinalIgnoreCase) && e.FullName.EndsWith(".bin", StringComparison.OrdinalIgnoreCase)))
            x.Notes.Add("binary macro sheets (.xlsb) are listed, not decoded");
        return x;
    }

    internal static Dictionary<string, string> Relationships(System.IO.Compression.ZipArchive zip, string part)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        if (zip.GetEntry(part) is not { } rels) return map;
        foreach (XmlElement r in Load(rels).GetElementsByTagName("Relationship"))
            map[r.GetAttribute("Id")] = r.GetAttribute("Target");
        return map;
    }

    /// <summary>An XML part read without DTDs or external entities, within 64 MiB.</summary>
    internal static XmlDocument Load(System.IO.Compression.ZipArchiveEntry entry)
    {
        if (entry.Length > 64 << 20) throw new ToolError(ErrorCode.LimitExceeded, $"{entry.FullName} is over 64 MiB.");
        using var s = entry.Open();
        var doc = new XmlDocument { XmlResolver = null };
        try
        {
            using var reader = XmlReader.Create(s, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
            doc.Load(reader);
        }
        catch (XmlException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{entry.FullName} is not well-formed XML: {ex.Message}"); }
        return doc;
    }
}
