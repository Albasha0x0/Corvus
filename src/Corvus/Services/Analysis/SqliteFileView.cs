using System.Globalization;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=sqlite: a SQLite 3 database read by its own B-tree reader, with the committed frames of a -wal file beside it
/// applied: header facts, the schema as stored, row counts and the first rows of each table (values clipped), the WAL's
/// frames per page; with table=, a page of that table's rows (columns=, offset=, limit=). No SQL is run.
/// </summary>
internal sealed class SqliteFileView : IFileSummaryView
{
    private const int MaxTables = 20, PreviewRows = 5, MaxValue = 80, PageValue = 200, MaxSchema = 500, DefaultLimit = 50, MaxLimit = 1000, MaxWalPages = 100, MaxPageFrames = 20;

    public sealed record Table(string Name, long? Rows, bool WithoutRowId, IReadOnlyList<string> Columns, IReadOnlyList<IReadOnlyList<string>> Preview);

    /// <summary>A page of a table's rows in key order (rowid, or primary key for WITHOUT ROWID); next is the offset of the following page.</summary>
    public sealed record TablePage(string Table, IReadOnlyList<string> Columns, long Offset, int Limit, long? Total, IReadOnlyList<IReadOnlyList<string>> Rows, long? Next);

    /// <summary>A page the -wal file holds, with its frames in order ("frame 3 superseded").</summary>
    public sealed record WalPage(long Page, IReadOnlyList<string> Frames);

    public sealed record WalFacts(int Frames, int Committed, int Commits, long DatabasePages, uint CheckpointSequence, IReadOnlyDictionary<string, int> States,
        IReadOnlyList<WalPage> History);

    public sealed record Facts(int PageSize, long Pages, string Encoding, string JournalMode, long FreelistPages, uint SchemaFormat, uint UserVersion,
        uint ApplicationId, bool AutoVacuum, string? WriterVersion, IReadOnlyList<SqliteSchemaEntry> Schema, IReadOnlyList<Table> Tables, IReadOnlyList<string> Notes)
    {
        public WalFacts? Wal { get; init; }
        public TablePage? Page { get; init; }
    }

    public string Name => "sqlite";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        using var open = Database.Open(file, ct);
        if (open?.Db is not { } db) return null;
        var options = file.Options;
        var notes = new List<string>();
        TablePage? page = null;
        var tables = new List<Table>();
        var stored = db.Schema.Where(e => e.Type == "table").ToList();
        if (options.Wants(Name) && options.Table != null) page = Page(db, options, ct);
        else
            foreach (var e in stored.Take(MaxTables))
            {
                ct.ThrowIfCancellationRequested();
                var (columns, alias) = SqliteDatabase.Columns(e.Sql);
                if (e.RootPage <= 0) { tables.Add(new Table(e.Name, null, false, columns, [])); continue; }
                var shape = db.Table(e.Name);
                long? rows = db.CountRows(e.RootPage, ct);
                var preview = db.Rows(e.RootPage, PreviewRows, ct)
                    .Select(r => (IReadOnlyList<string>)[.. (shape?.Shape(r) ?? [.. r.Values]).Select(v => Show(v, MaxValue))]).ToList();
                tables.Add(new Table(e.Name, rows, shape?.WithoutRowId ?? false, columns, preview));
            }
        notes.AddRange(db.Issues.Distinct().Take(20));
        var wal = Wal(db, open.WalPath, notes);
        if (page == null)
        {
            if (stored.Count > MaxTables) notes.Add($"tables: the first {MaxTables} of {stored.Count:N0} are counted and previewed; table= pages any table");
            if (db.Schema.Count > MaxSchema) notes.Add($"schema: the first {MaxSchema} of {db.Schema.Count:N0} entries");
            if (tables.Any(t => t.Rows == null)) notes.Add("rows: null for a virtual table or a walk that ended early (see the issues above).");
        }
        var facts = new Facts(db.PageSize, db.PageCount, db.TextEncoding, db.Wal ? "wal" : "rollback", db.FreelistPages, db.SchemaFormat, db.UserVersion,
            db.ApplicationId, db.AutoVacuum, db.WriterVersion, page != null ? [] : [.. db.Schema.Take(MaxSchema)], tables, notes) { Wal = wal, Page = page };

        int Count(string type) => db.Schema.Count(e => e.Type == type);
        var highlights = new List<string>
        {
            $"SQLite database: {db.PageCount:N0} pages of {db.PageSize:N0} bytes, {db.TextEncoding}{(db.Wal ? ", WAL mode" : "")}; " +
            $"{Count("table")} tables, {Count("index")} indexes, {Count("view")} views, {Count("trigger")} triggers.",
        };
        if (tables.Count > 0)
            highlights.Add("Tables: " + string.Join(", ", tables.Take(8).Select(t => t.Rows is { } n ? $"{t.Name} ({n:N0} rows)" : t.Name)) +
                           (stored.Count > 8 ? $" (+{stored.Count - 8})" : "") + ".");
        if (wal != null) highlights.Add($"Write-ahead log: {wal.Committed:N0} committed frames applied ({wal.Commits:N0} commits), {wal.Frames - wal.Committed:N0} frames past the last commit.");
        if (db.Issues.Count > 0) highlights.Add($"Database structure issue: {db.Issues[0]}.");
        return new FileView(facts, highlights);
    }

    /// <summary>The page of rows table=, columns=, offset=, limit= ask for.</summary>
    private static TablePage Page(SqliteDatabase db, FileViewOptions options, CancellationToken ct)
    {
        var t = db.Table(options.Table!) ?? throw new ToolError(ErrorCode.NotFound, $"no stored table '{options.Table}' in the database.",
            $"pass table as one of {string.Join(", ", db.Tables().Select(x => x.Name).Take(50))}");
        var columns = Selected(t, options.Columns);
        int limit = Math.Clamp(options.Limit ?? DefaultLimit, 1, MaxLimit);
        long offset = Math.Max(0, options.Offset);
        long? total = db.CountRows(t.RootPage, ct);
        var rows = db.Rows(t.RootPage, offset, limit, ct).Select(r =>
        {
            var values = t.Shape(r);
            return (IReadOnlyList<string>)[.. columns.Select(c => Show(c < 0 ? r.RowId : c < values.Length ? values[c] : null, PageValue))];
        }).ToList();
        long next = offset + rows.Count;
        return new TablePage(t.Name, [.. columns.Select(c => c < 0 ? "rowid" : t.Columns[c])], offset, limit, total, rows,
            rows.Count == limit && (total == null || next < total) ? next : null);
    }

    /// <summary>Column indexes for columns= (declaration order when absent; -1 is the rowid of a rowid table).</summary>
    private static List<int> Selected(SqliteTable t, IReadOnlyList<string>? names)
    {
        if (names is not { Count: > 0 }) return [.. Enumerable.Range(0, t.Columns.Count)];
        var picked = new List<int>();
        foreach (var name in names.SelectMany(n => n.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)))
        {
            int i = Enumerable.Range(0, t.Columns.Count).FirstOrDefault(c => t.Columns[c].Equals(name, StringComparison.OrdinalIgnoreCase), -2);
            if (i == -2 && !t.WithoutRowId && name.ToLowerInvariant() is "rowid" or "_rowid_" or "oid") i = -1;
            if (i == -2)
                throw new ToolError(ErrorCode.InvalidArgument, $"table {t.Name} has no column '{name}'.", $"pass columns from {string.Join(", ", t.Columns)}{(t.WithoutRowId ? "" : ", rowid")}");
            picked.Add(i);
        }
        return picked;
    }

    private static WalFacts? Wal(SqliteDatabase db, string? walPath, List<string> notes)
    {
        if (db.WalLog is not { } log)
        {
            if (db.Wal) notes.Add(walPath == null
                ? "journal_mode=WAL and no -wal file beside it: changes not yet checkpointed (if any) are not in this file."
                : new FileInfo(walPath).Length == 0 ? "journal_mode=WAL; the -wal file beside it is empty (fully checkpointed)."
                : "journal_mode=WAL; the -wal file beside it is not a write-ahead log.");
            return null;
        }
        notes.AddRange(log.Issues);
        if (log.Committed > 0 && log.PageSize == db.PageSize) notes.Add($"the -wal file's {log.Committed:N0} committed frames are applied (the latest copy of each page).");
        var history = log.Frames.GroupBy(f => f.Page).Take(MaxWalPages)
            .Select(g => new WalPage(g.Key, [.. g.Take(MaxPageFrames).Select(f => $"frame {f.Index} {f.State}{(f.CommitPages > 0 ? " (commit)" : "")}")])).ToList();
        if (log.Frames.Select(f => f.Page).Distinct().Count() > MaxWalPages) notes.Add($"WAL history: the first {MaxWalPages} pages");
        return new WalFacts(log.Frames.Count, log.Committed, log.Commits, log.DatabasePages, log.CheckpointSequence,
            log.Frames.GroupBy(f => f.State).ToDictionary(g => g.Key, g => g.Count()), history);
    }

    internal static string Show(object? v, int max) => v switch
    {
        null => "NULL",
        long l => l.ToString(CultureInfo.InvariantCulture),
        double d => d.ToString("R", CultureInfo.InvariantCulture),
        string s => s.Length > max ? s[..max] + $"… ({s.Length:N0} chars)" : s,
        SqliteBlob b => $"x'{Convert.ToHexString(b.Head.AsSpan(0, Math.Min(b.Head.Length, 16)))}" + (b.Length > 16 ? $"…' ({b.Length:N0} bytes)" : "'"),
        _ => v.ToString() ?? "",
    };

    /// <summary>
    /// A summarize_file input opened as a database: from its bytes, or mapped read-only when it was streamed, with the
    /// -wal file beside it (mapped) when there is one.
    /// </summary>
    internal sealed class Database : IDisposable
    {
        private SqliteSource? _source, _wal;

        public SqliteDatabase? Db { get; private set; }
        public string? WalPath { get; private set; }

        public static Database? Open(FileInput file, CancellationToken ct)
        {
            if (!SqliteDatabase.Looks(file.Head)) return null;
            var open = new Database();
            try
            {
                open._source = file.Streamed ? SqliteSource.Map(file.Path) : SqliteSource.Of(file.Bytes);
                if (open._source == null) return null;
                var walPath = file.Path + "-wal";
                if (Path.IsPathRooted(file.Path) && File.Exists(walPath))
                {
                    open.WalPath = walPath;
                    open._wal = SqliteSource.Map(walPath);
                }
                open.Db = SqliteDatabase.Open(open._source, open._wal, ct);
                return open;
            }
            catch
            {
                open.Dispose();
                throw;
            }
        }

        public void Dispose()
        {
            _source?.Dispose();
            _wal?.Dispose();
        }
    }
}
