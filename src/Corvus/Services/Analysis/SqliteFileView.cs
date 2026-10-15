using System.Globalization;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=sqlite: a SQLite 3 database read by its own B-tree reader: header facts, the schema as stored, row counts and the
/// first rows of each table (values clipped). No SQL is run; a -wal file beside it is not read.
/// </summary>
internal sealed class SqliteFileView : IFileSummaryView
{
    private const int MaxTables = 20, PreviewRows = 5, MaxValue = 80, MaxSchema = 500;

    public sealed record Table(string Name, long? Rows, bool WithoutRowId, IReadOnlyList<string> Columns, IReadOnlyList<IReadOnlyList<string>> Preview);

    public sealed record Facts(int PageSize, long Pages, string Encoding, string JournalMode, long FreelistPages, uint SchemaFormat, uint UserVersion,
        uint ApplicationId, bool AutoVacuum, string? WriterVersion, IReadOnlyList<SqliteSchemaEntry> Schema, IReadOnlyList<Table> Tables, IReadOnlyList<string> Notes);

    public string Name => "sqlite";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (!SqliteDatabase.Looks(file.Bytes) || SqliteDatabase.Open(file.Bytes, ct) is not { } db) return null;
        var tables = new List<Table>();
        var stored = db.Schema.Where(e => e.Type == "table").ToList();
        foreach (var e in stored.Take(MaxTables))
        {
            ct.ThrowIfCancellationRequested();
            var (columns, alias) = SqliteDatabase.Columns(e.Sql);
            if (e.RootPage <= 0) { tables.Add(new Table(e.Name, null, false, columns, [])); continue; }
            bool withoutRowId = db.IsIndexTree(e.RootPage) == true;
            long? rows = db.CountRows(e.RootPage, ct);
            var preview = db.Rows(e.RootPage, PreviewRows, ct)
                .Select(r => (IReadOnlyList<string>)[.. r.Values.Select((v, i) => i == alias && v == null && r.RowId is { } id ? Show(id) : Show(v))]).ToList();
            tables.Add(new Table(e.Name, rows, withoutRowId, columns, preview));
        }
        var notes = new List<string>(db.Issues.Distinct().Take(20));
        if (db.Wal) notes.Add("journal_mode=WAL: committed changes still in the -wal file are not read.");
        if (stored.Count > MaxTables) notes.Add($"tables: the first {MaxTables} of {stored.Count:N0} are counted and previewed");
        if (db.Schema.Count > MaxSchema) notes.Add($"schema: the first {MaxSchema} of {db.Schema.Count:N0} entries");
        if (tables.Any(t => t.Rows == null)) notes.Add("rows: null for a virtual table or a walk that ended early (see the issues above).");
        var facts = new Facts(db.PageSize, db.PageCount, db.TextEncoding, db.Wal ? "wal" : "rollback", db.FreelistPages, db.SchemaFormat, db.UserVersion,
            db.ApplicationId, db.AutoVacuum, db.WriterVersion, [.. db.Schema.Take(MaxSchema)], tables, notes);

        int Count(string type) => db.Schema.Count(e => e.Type == type);
        var highlights = new List<string>
        {
            $"SQLite database: {db.PageCount:N0} pages of {db.PageSize:N0} bytes, {db.TextEncoding}{(db.Wal ? ", WAL mode" : "")}; " +
            $"{Count("table")} tables, {Count("index")} indexes, {Count("view")} views, {Count("trigger")} triggers.",
        };
        if (tables.Count > 0)
            highlights.Add("Tables: " + string.Join(", ", tables.Take(8).Select(t => t.Rows is { } n ? $"{t.Name} ({n:N0} rows)" : t.Name)) +
                           (stored.Count > 8 ? $" (+{stored.Count - 8})" : "") + ".");
        if (db.Issues.Count > 0) highlights.Add($"Database structure issue: {db.Issues[0]}.");
        return new FileView(facts, highlights);
    }

    private static string Show(object? v) => v switch
    {
        null => "NULL",
        long l => l.ToString(CultureInfo.InvariantCulture),
        double d => d.ToString("R", CultureInfo.InvariantCulture),
        string s => s.Length > MaxValue ? s[..MaxValue] + $"… ({s.Length:N0} chars)" : s,
        SqliteBlob b => $"x'{Convert.ToHexString(b.Head.AsSpan(0, Math.Min(b.Head.Length, 16)))}" + (b.Length > 16 ? $"…' ({b.Length:N0} bytes)" : "'"),
        _ => v.ToString() ?? "",
    };
}
