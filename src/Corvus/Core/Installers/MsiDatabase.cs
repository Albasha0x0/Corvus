using System.Buffers.Binary;
using System.Text;
using Corvus.Core.Documents;

namespace Corvus.Core.Installers;

/// <summary>A table of an installer database: its column names and its rows (strings, integers or null).</summary>
internal sealed record MsiTable(string Name, IReadOnlyList<string> Columns, IReadOnlyList<object?[]> Rows)
{
    public int Index(string column) => Columns.ToList().FindIndex(c => string.Equals(c, column, StringComparison.OrdinalIgnoreCase));

    /// <summary>Each row by column name (the first of duplicate names in a damaged table).</summary>
    public IEnumerable<Dictionary<string, object?>> Records()
    {
        foreach (var r in Rows)
        {
            var d = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < Columns.Count; i++) d.TryAdd(Columns[i], i < r.Length ? r[i] : null);
            yield return d;
        }
    }
}

/// <summary>
/// A Windows Installer database (.msi, .msp, .mst): a compound file whose stream names are packed two characters per UTF-16
/// unit; the string pool (with its code page and 2- or 3-byte references), _Tables and _Columns read first, then every table
/// stored column by column (integers offset by 0x8000 / 0x80000000, zero for null). Binary columns name a stream.
/// </summary>
internal sealed class MsiDatabase
{
    private static readonly Guid Package = new("000C1084-0000-0000-C000-000000000046");
    private static readonly Guid Patch = new("000C1086-0000-0000-C000-000000000046");
    private static readonly Guid Transform = new("000C1082-0000-0000-C000-000000000046");

    /// <summary>The kind ("msi", "msp", "mst") from the root entry's class id, read without parsing the file; null for other compound files.</summary>
    public static string? KindOf(ReadOnlySpan<byte> b)
    {
        if (!CompoundFile.Looks(b)) return null;
        int shift = BinaryPrimitives.ReadUInt16LittleEndian(b[30..]);
        if (shift is not (9 or 12)) return null;
        long at = ((long)BinaryPrimitives.ReadUInt32LittleEndian(b[48..]) + 1) * (1 << shift) + 80;
        if (at + 16 > b.Length) return null;
        var clsid = new Guid(b.Slice((int)at, 16));
        return clsid == Package ? "msi" : clsid == Patch ? "msp" : clsid == Transform ? "mst" : null;
    }

    public static bool Looks(ReadOnlySpan<byte> b) => KindOf(b) != null;

    public CompoundFile File { get; }
    public string Kind { get; }
    public int CodePage { get; private set; }
    public Dictionary<string, MsiTable> Tables { get; } = new(StringComparer.Ordinal);
    /// <summary>Streams by decoded name ("Binary.NewBinary1", "#cab1.cab" as "cab1.cab", "\u0005SummaryInformation").</summary>
    public Dictionary<string, CompoundEntry> Streams { get; } = new(StringComparer.Ordinal);
    public List<string> Notes { get; } = [];

    private readonly List<string?> _strings = [null];
    private int _refSize = 2;
    private Encoding _encoding = Encoding.Latin1;

    private const long MaxTable = 256L << 20;

    private MsiDatabase(CompoundFile cf, string kind)
    {
        File = cf;
        Kind = kind;
        foreach (var e in cf.Entries.Where(e => !e.IsStorage && !e.Path.Contains('/'))) Streams[DecodeName(e.Name)] = e;
    }

    public static MsiDatabase Read(byte[] data, string name, CancellationToken ct)
    {
        var kind = KindOf(data) ?? throw new ToolError(ErrorCode.MalformedInput, $"{name} is not a Windows Installer database.");
        var db = new MsiDatabase(CompoundFile.Read(data, name), kind);
        db.ReadStrings();
        db.ReadTables(ct);
        db.Notes.AddRange(db.File.Notes);
        return db;
    }

    private const string Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";

    /// <summary>A stream name decoded: units 0x3800-0x47FF hold two characters of the 64-letter alphabet, 0x4800-0x483F one, 0x4840 marks a table ("!").</summary>
    public static string DecodeName(string name)
    {
        var sb = new StringBuilder();
        foreach (char ch in name)
        {
            int c = ch;
            if (c >= 0x3800 && c < 0x4800)
            {
                c -= 0x3800;
                sb.Append(Alphabet[c & 0x3F]);
                sb.Append(Alphabet[(c >> 6) & 0x3F]);
            }
            else if (c >= 0x4800 && c < 0x4840) sb.Append(Alphabet[c - 0x4800]);
            else if (c == 0x4840) sb.Append('!');
            else sb.Append(ch);
        }
        return sb.ToString();
    }

    private byte[] Stream(string name) => Streams.TryGetValue(name, out var e) ? File.Read(e, MaxTable) : [];

    public byte[]? StreamData(string name, long max) => Streams.TryGetValue(name, out var e) ? File.Read(e, max) : null;

    private void ReadStrings()
    {
        var pool = Stream("!_StringPool");
        var data = Stream("!_StringData");
        if (pool.Length < 4) { Notes.Add("no string pool"); return; }
        CodePage = BinaryPrimitives.ReadUInt16LittleEndian(pool);
        if ((BinaryPrimitives.ReadUInt16LittleEndian(pool.AsSpan(2)) & 0x8000) != 0) _refSize = 3;
        try { _encoding = CodePage is 0 or 65001 ? Encoding.UTF8 : CodePagesEncodingProvider.Instance.GetEncoding(CodePage) ?? Encoding.Latin1; }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException) { _encoding = Encoding.Latin1; }
        int at = 0;
        for (int i = 4; i + 4 <= pool.Length; i += 4)
        {
            long len = BinaryPrimitives.ReadUInt16LittleEndian(pool.AsSpan(i));
            int refs = BinaryPrimitives.ReadUInt16LittleEndian(pool.AsSpan(i + 2));
            if (len == 0 && refs != 0 && i + 8 <= pool.Length)
            {
                // a long string: its length in the next entry
                i += 4;
                len = BinaryPrimitives.ReadUInt16LittleEndian(pool.AsSpan(i)) | ((long)BinaryPrimitives.ReadUInt16LittleEndian(pool.AsSpan(i + 2)) << 16);
            }
            if (at + len > data.Length) { Notes.Add($"string {_strings.Count} runs past the string data"); _strings.Add(null); continue; }
            _strings.Add(len == 0 ? (refs == 0 ? null : "") : _encoding.GetString(data, at, (int)len));
            at += (int)len;
        }
    }

    private string? Str(int id) => id > 0 && id < _strings.Count ? _strings[id] : null;

    private sealed record Column(string Name, int Number, int Type);

    private static bool IsString(int type) => (type & 0x0800) != 0;
    private static bool IsBinary(int type) => (type & ~0x1000) == 0x0900;

    private int Width(int type) => IsBinary(type) ? 2 : IsString(type) ? _refSize : (type & 0xFF) <= 2 ? 2 : 4;

    /// <summary>A table's rows, its columns given; null when the stream's size does not divide into rows.</summary>
    private List<object?[]>? Rows(string table, List<Column> columns)
    {
        var data = Stream("!" + table);
        int rowSize = columns.Sum(c => Width(c.Type));
        if (rowSize == 0 || data.Length % rowSize != 0)
        {
            if (data.Length > 0) Notes.Add($"table {table}: {data.Length:N0} bytes do not divide into {rowSize}-byte rows");
            if (rowSize == 0 || data.Length < rowSize) return [];
        }
        int count = data.Length / rowSize;
        var rows = new List<object?[]>(count);
        for (int r = 0; r < count; r++) rows.Add(new object?[columns.Count]);
        int offset = 0;
        for (int c = 0; c < columns.Count; c++)
        {
            int w = Width(columns[c].Type);
            for (int r = 0; r < count; r++)
            {
                int at = offset + r * w;
                int raw = w == 2 ? BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(at)) : w == 3 ? data[at] | data[at + 1] << 8 | data[at + 2] << 16 : BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(at));
                rows[r][c] = IsString(columns[c].Type) && !IsBinary(columns[c].Type) ? Str(raw)
                    : IsBinary(columns[c].Type) ? (raw == 0 ? null : "[stream]")
                    : raw == 0 ? null : w == 2 ? raw - 0x8000 : unchecked(raw - int.MinValue);
            }
            offset += w * count;
        }
        return rows;
    }

    private void ReadTables(CancellationToken ct)
    {
        var tableNames = Rows("_Tables", [new Column("Name", 1, 0x0DFF)])?.Select(r => r[0] as string).Where(n => n != null).Cast<string>().ToList() ?? [];
        var columnRows = Rows("_Columns", [new Column("Table", 1, 0x0DFF), new Column("Number", 2, 0x0502), new Column("Name", 3, 0x0DFF), new Column("Type", 4, 0x0502)]) ?? [];
        var byTable = columnRows.Where(r => r[0] is string && r[1] is int && r[2] is string && r[3] is int)
            .GroupBy(r => (string)r[0]!)
            .ToDictionary(g => g.Key, g => g.OrderBy(r => (int)r[1]!).Select(r => new Column((string)r[2]!, (int)r[1]!, (int)r[3]! & 0xFFFF)).ToList(), StringComparer.Ordinal);
        foreach (var name in tableNames.Distinct())
        {
            ct.ThrowIfCancellationRequested();
            if (!byTable.TryGetValue(name, out var columns)) { Notes.Add($"table {name} has no columns"); continue; }
            Tables[name] = new MsiTable(name, columns.Select(c => c.Name).ToList(), Rows(name, columns) ?? []);
        }
    }

    public MsiTable? Table(string name) => Tables.GetValueOrDefault(name);

    /// <summary>The Property table as a dictionary.</summary>
    public Dictionary<string, string> Properties() =>
        Table("Property")?.Rows.Where(r => r.Length >= 2 && r[0] is string).GroupBy(r => (string)r[0]!).ToDictionary(g => g.Key, g => g.First()[1]?.ToString() ?? "", StringComparer.Ordinal) ?? [];
}
