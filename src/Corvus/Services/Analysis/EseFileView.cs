using System.Buffers.Binary;
using System.Text;
using Corvus.Core;
using Corvus.Core.Databases;

namespace Corvus.Services.Analysis;

/// <summary>view=ese: an ESE database's format, state, tables, a page of one table's records (table=, offset=, limit=), and on request recoverable records.</summary>
internal sealed class EseFileView : IFileSummaryView
{
    private const int DefaultLimit = 50, MaxLimit = 1000, MaxRecovered = 200, MaxText = 200;

    public sealed record TableEntry(string Name, int Columns, IReadOnlyList<string> Indexes, string? Template);

    /// <summary>A record: column name to value (null columns left out), and for a recovered one where it was found.</summary>
    public sealed record Entry(IReadOnlyDictionary<string, string> Fields, string? Source = null);

    public sealed record Facts(int PageSize, string Format, string State, long Pages, IReadOnlyList<TableEntry> Tables, string Table,
        IReadOnlyList<string> Columns, long Offset, long? Next, IReadOnlyList<Entry> Records, IReadOnlyList<Entry>? Recovered, IReadOnlyList<string> Notes);

    public string Name => "ese";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (!Ese.Looks(file.Head)) return null;
        Ese db;
        try { db = new Ese(file.OpenRead()); }
        catch (InvalidDataException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{Path.GetFileName(file.Path)}: not a readable ESE database: {ex.Message}"); }
        using (db)
        {
            bool asked = file.Options.Wants(Name);
            string? wanted = asked ? file.Options.Table : null;
            var table = wanted == null
                ? db.Tables.FirstOrDefault(t => !t.Name.StartsWith("MSys", StringComparison.Ordinal)) ?? db.Tables.FirstOrDefault()
                : db.Tables.FirstOrDefault(t => t.Name == wanted) ?? db.Tables.FirstOrDefault(t => t.Name.Equals(wanted, StringComparison.OrdinalIgnoreCase));
            if (table == null && wanted != null)
                throw new ToolError(ErrorCode.InvalidArgument, $"no table named '{wanted}'; tables: {string.Join(", ", db.Tables.Select(t => t.Name))}", "pass table= with one of them, or none for the first table");
            int limit = Math.Clamp(file.Options.Limit ?? DefaultLimit, 1, MaxLimit);
            long offset = Math.Max(0, file.Options.Offset);
            var page = new List<Entry>();
            long? next = null;
            List<Entry>? recovered = null;
            int found = 0;
            if (table != null)
            {
                var rows = db.Rows(table, null, ct).Skip((int)Math.Min(offset, int.MaxValue)).Take(limit + 1).ToList();
                next = rows.Count > limit ? offset + limit : null;
                page = [.. rows.Take(limit).Select(r => Show(r))];
                if (asked)
                {
                    var reached = new HashSet<uint>();
                    var live = new HashSet<string>(StringComparer.Ordinal);
                    foreach (var r in db.Rows(table, reached, ct)) live.Add(Ese.Id(r));
                    var list = db.Recover(table, live, reached, MaxRecovered + 1, ct);
                    found = list.Count;
                    recovered = [.. list.Take(MaxRecovered).Select(r => Show(r))];
                }
            }
            var notes = new List<string>(db.Notes.Distinct().Take(20));
            if (next != null) notes.Add($"offset={next} lists the next records of {table!.Name}");
            if (found > MaxRecovered) notes.Add($"recovered: the first {MaxRecovered}; more remain");
            if (!asked) notes.Add("view=ese also recovers deleted and unreachable records");

            string state = db.State switch { 1 => "just created", 2 => "dirty shutdown", 3 => "clean shutdown", 4 => "being converted", 5 => "force detach", var s => $"state {s}" };
            string format = $"0x{db.Version:x} revision 0x{db.Revision:x}";
            var user = db.Tables.Where(t => !t.Name.StartsWith("MSys", StringComparison.Ordinal)).ToList();
            var highlights = new List<string>
            {
                $"ESE database: {db.PageSize:N0}-byte pages, format {format}, {state}; {user.Count} tables" +
                (user.Count > 0 ? $": {string.Join(", ", user.Take(8).Select(t => t.Name))}{(user.Count > 8 ? ", ..." : "")}" : "") + ".",
            };
            if (found > 0) highlights.Add($"Recoverable: {found:N0}{(found > MaxRecovered ? "+" : "")} deleted or unreachable records of {table!.Name}.");
            var tables = db.Tables.Select(t => new TableEntry(t.Name, t.Columns.Count, [.. t.Indexes.Select(i => i.Name)], t.Template)).ToList();
            var columns = table?.Columns.Select(c => $"{c.Name} {TypeName(c.Type)}{(c.MultiValued ? " multi-valued" : "")}{(c.Compressed ? " compressed" : "")}").ToList() ?? [];
            return new FileView(new Facts(db.PageSize, format, state, db.LastPage, tables, table?.Name ?? "", columns, offset, next, page, recovered, notes), highlights);
        }
    }

    private static Entry Show(Ese.Row r)
    {
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var f in r.Fields)
        {
            if (f.Null) continue;
            string text = f.Values.Count switch
            {
                0 => "",
                1 => Value(f.Column, f.Values[0]),
                _ => "[" + string.Join(", ", f.Values.Select(v => Value(f.Column, v))) + "]",
            };
            if (f.Problem != null) text = text.Length == 0 ? $"({f.Problem})" : $"{text} ({f.Problem})";
            fields.TryAdd(f.Column.Name, text);
        }
        return new Entry(fields, r.Source);
    }

    private static string Value(Ese.Column c, byte[] b) => (c.Type, b.Length) switch
    {
        (1, 1) => b[0] != 0 ? "true" : "false",
        (2, 1) => b[0].ToString(),
        (3, 2) => BinaryPrimitives.ReadInt16LittleEndian(b).ToString(),
        (17, 2) => BinaryPrimitives.ReadUInt16LittleEndian(b).ToString(),
        (4, 4) => BinaryPrimitives.ReadInt32LittleEndian(b).ToString(),
        (14, 4) => BinaryPrimitives.ReadUInt32LittleEndian(b).ToString(),
        (5 or 15, 8) => BinaryPrimitives.ReadInt64LittleEndian(b).ToString(),
        (6, 4) => BinaryPrimitives.ReadSingleLittleEndian(b).ToString("R"),
        (7, 8) => BinaryPrimitives.ReadDoubleLittleEndian(b).ToString("R"),
        (8, 8) => Date(BinaryPrimitives.ReadDoubleLittleEndian(b)),
        (16, 16) => new Guid(b).ToString(),
        (10 or 12, _) => Text(Ese.Text(c, b)),
        _ => LevelDbFileView.Text(b),
    };

    // JET_coltypDateTime is an OLE Automation date: days since 1899-12-30 as a double.
    private static string Date(double days) =>
        days is >= -657435 and <= 2958465 ? DateTime.FromOADate(days).ToString("yyyy-MM-dd HH:mm:ss") : days.ToString("R");

    private static string Text(string s) => s.Length > MaxText ? $"{s[..MaxText]}... ({s.Length:N0} characters)" : s;

    private static string TypeName(int type) => type switch
    {
        1 => "bit", 2 => "unsigned byte", 3 => "short", 4 => "long", 5 => "currency", 6 => "single", 7 => "double", 8 => "date time",
        9 => "binary", 10 => "text", 11 => "long binary", 12 => "long text", 13 => "super long value", 14 => "unsigned long",
        15 => "long long", 16 => "GUID", 17 => "unsigned short", _ => $"type {type}",
    };
}
