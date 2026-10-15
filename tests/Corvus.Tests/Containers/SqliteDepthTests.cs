using Corvus.Core;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// SQLite rows by position (checked against the e_sqlite3 library as the oracle), -wal frames applied with their history,
/// and deleted rows carved from free space (summarize_file view=sqlite table=, view=sqlite-recover).
/// </summary>
public sealed class SqliteDepthTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private static readonly string[] Mixed =
    [
        "PRAGMA page_size=512;", "PRAGMA encoding='UTF-16le';",
        "CREATE TABLE t(id INTEGER PRIMARY KEY, a TEXT, b REAL, c BLOB, d);",
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 6000) INSERT INTO t(a, b, c, d) SELECT " +
        "CASE WHEN i % 7 = 0 THEN NULL ELSE 'név ' || i || substr('ééééééééééééééééééééé', 1, i % 20) END, i * -1.25, CASE WHEN i % 3 = 0 THEN randomblob(i % 90) END, " +
        "CASE i % 4 WHEN 0 THEN i * 4294967296 WHEN 1 THEN -i WHEN 2 THEN 0.5 ELSE 'x' END FROM n;",
        "CREATE TABLE w(x TEXT, y INTEGER, z, PRIMARY KEY(y, x)) WITHOUT ROWID;",
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 3000) INSERT INTO w SELECT 'k' || (i % 13), 3000 - i, i FROM n;",
    ];

    /// <summary>Our rows of every table, paged, against the library's SELECT * in the same key order.</summary>
    private static void AssertTablesMatch(SqliteDatabase db, string oraclePath)
    {
        foreach (var t in db.Tables())
        {
            var expected = NativeSqlite.Query(oraclePath, $"SELECT * FROM \"{t.Name}\"");
            Assert.Equal(expected.Count, db.CountRows(t.RootPage));
            var ours = new List<object?[]>();
            for (long offset = 0; ; offset += 333)
            {
                var page = db.Rows(t.RootPage, offset, 333);
                ours.AddRange(page.Select(t.Shape));
                if (page.Count < 333) break;
            }
            Assert.Equal(expected.Count, ours.Count);
            for (int i = 0; i < expected.Count; i++)
                for (int c = 0; c < expected[i].Length; c++)
                    if (t.Generated.GetValueOrDefault(c) == 'V') Assert.Null(ours[i][c]); // computed, not stored
                    else Assert.True(Same(expected[i][c], ours[i][c]), $"{t.Name} row {i} column {t.Columns[c]}: {expected[i][c]} vs {ours[i][c]}");
        }
        Assert.Empty(db.Issues);
    }

    private static bool Same(object? oracle, object? ours) => (oracle, ours) switch
    {
        (null, null) => true,
        (byte[] b, SqliteBlob blob) => blob.Length == b.Length && blob.Head.AsSpan().SequenceEqual(b.AsSpan(0, Math.Min(b.Length, blob.Head.Length))),
        (double x, double y) => BitConverter.DoubleToInt64Bits(x) == BitConverter.DoubleToInt64Bits(y),
        _ => Equals(oracle, ours),
    };

    private string Database(string name, params string[] statements)
    {
        var path = _dir.File(name);
        NativeSqlite.Write(path, statements);
        return path;
    }

    /// <summary>Copies a database and its -wal file while the writer holds them open (closing would checkpoint the log).</summary>
    private static void CopyOpen(string from, string to)
    {
        foreach (var suffix in new[] { "", "-wal" })
        {
            if (!File.Exists(from + suffix)) continue;
            using var source = new FileStream(from + suffix, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var target = File.Create(to + suffix);
            source.CopyTo(target);
        }
    }

    private static SqliteDatabase OpenFile(string path, out IDisposable sources)
    {
        var db = SqliteSource.Map(path)!;
        var wal = SqliteSource.Map(path + "-wal");
        sources = new Sources(db, wal);
        return SqliteDatabase.Open(db, wal)!;
    }

    private sealed class Sources(SqliteSource a, SqliteSource? b) : IDisposable
    {
        public void Dispose() { a.Dispose(); b?.Dispose(); }
    }

    [Fact]
    public void Paged_rows_equal_the_library_on_three_databases()
    {
        var fixture = _dir.File("fixture.db");
        File.WriteAllBytes(fixture, SqliteTests.FixtureBytes);
        var mixed = Database("mixed.db", Mixed);
        var walPath = WalDatabase();
        foreach (var path in new[] { fixture, mixed, walPath })
        {
            var oracle = _dir.File("oracle-" + Path.GetFileName(path));
            CopyOpen(path, oracle);
            var db = OpenFile(path, out var sources);
            using (sources) AssertTablesMatch(db, oracle);
        }
    }

    /// <summary>A WAL database copied while open: 5,000 rows checkpointed, the log restarted, then 120 deleted and 50 updated in it.</summary>
    private string WalDatabase()
    {
        var live = _dir.File("live-wal.db");
        var copy = _dir.File("wal.db");
        NativeSqlite.Write(live,
        [
            "PRAGMA journal_mode=WAL;", "PRAGMA wal_autocheckpoint=0;", "PRAGMA secure_delete=OFF;",
            "CREATE TABLE log(id INTEGER PRIMARY KEY, msg TEXT NOT NULL, level INTEGER);",
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 5000) INSERT INTO log(msg, level) SELECT 'event ' || i || ' ' || hex(randomblob(8)), i % 4 FROM n;",
            "PRAGMA wal_checkpoint(RESTART);",
            "DELETE FROM log WHERE id % 4 = 1 AND id < 480;",
            "UPDATE log SET level = 9 WHERE id % 10 = 0 AND id < 480;",
        ], whileOpen: () => CopyOpen(live, copy));
        return copy;
    }

    [Fact]
    public void Added_columns_read_their_defaults_and_generated_columns_their_stored_values()
    {
        var path = Database("altered.db",
            "CREATE TABLE p(id INTEGER PRIMARY KEY, name TEXT, qty INTEGER, price REAL, total REAL GENERATED ALWAYS AS (qty * price) STORED, " +
            "label TEXT AS (upper(name)) VIRTUAL, note TEXT DEFAULT 'none');",
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 400) INSERT INTO p(name, qty, price) SELECT 'item ' || i, i % 9, i * 0.25 FROM n;",
            "ALTER TABLE p ADD COLUMN flag INTEGER DEFAULT 7;",
            "ALTER TABLE p ADD COLUMN tag TEXT DEFAULT 'it''s';",
            "ALTER TABLE p ADD COLUMN ratio REAL DEFAULT -2;",
            "ALTER TABLE p ADD COLUMN raw BLOB DEFAULT x'00ff';",
            "ALTER TABLE p ADD COLUMN num NUMERIC DEFAULT '12';",
            "ALTER TABLE p ADD COLUMN twice INTEGER AS (id * 2) VIRTUAL;",
            "ALTER TABLE p ADD COLUMN plain;",
            "INSERT INTO p(name, qty, price, flag, tag, plain) VALUES ('late', 3, 1.5, 0, 'new', 'x');",
            "CREATE TABLE w(k TEXT, v INTEGER, PRIMARY KEY(k)) WITHOUT ROWID;",
            "INSERT INTO w VALUES ('a', 1), ('b', 2);",
            "ALTER TABLE w ADD COLUMN z DEFAULT 3.5;",
            "INSERT INTO w VALUES ('c', 3, 'zz');");
        var db = OpenFile(path, out var sources);
        using (sources) AssertTablesMatch(db, path);
        var p = db.Table("p")!;
        Assert.Equal(["label", "twice"], p.Generated.Where(g => g.Value == 'V').Select(g => p.Columns[g.Key]).Order());
        Assert.Equal('S', p.Generated[p.Columns.ToList().IndexOf("total")]);
    }

    [Fact]
    public void Wal_frames_are_applied_and_listed_per_page()
    {
        var path = WalDatabase();
        var oracle = _dir.File("wal-oracle.db");
        CopyOpen(path, oracle);
        var view = View(path, new FileViewOptions("sqlite"));
        Assert.Equal("wal", view.JournalMode);
        var wal = view.Wal!;
        Assert.True(wal.Committed > 0 && wal.Commits >= 2, $"{wal.Committed} committed, {wal.Commits} commits");
        Assert.True(wal.States.GetValueOrDefault("applied") > 0);
        Assert.True(wal.States.GetValueOrDefault("stale") > 0, string.Join(", ", wal.States)); // frames left from before the restart
        Assert.Contains(wal.History, p => p.Frames.Any(f => f.EndsWith("applied (commit)", StringComparison.Ordinal) || f.Contains("applied", StringComparison.Ordinal)));
        Assert.Equal(NativeSqlite.Query(oracle, "SELECT count(*) FROM log")[0][0], view.Tables.Single(t => t.Name == "log").Rows);
        Assert.Contains(view.Notes, n => n.Contains("committed frames are applied", StringComparison.Ordinal));
    }

    private static SqliteFileView.Facts View(string path, FileViewOptions options)
    {
        var bytes = File.ReadAllBytes(path);
        return (SqliteFileView.Facts)new SqliteFileView().Inspect(new FileInput(path, bytes, Blob.Identify(bytes)) { Options = options }, default)!.Detail;
    }

    [Fact]
    public void Table_page_selects_columns_from_an_offset()
    {
        var path = _dir.File("fixture.db");
        File.WriteAllBytes(path, SqliteTests.FixtureBytes);
        var page = View(path, new FileViewOptions("sqlite", "USERS", ["name", "rowid", "score"], 1995, 10)).Page!;
        Assert.Equal(["name", "rowid", "score"], page.Columns);
        Assert.Equal(2000, page.Total);
        Assert.Equal([["user1996", "1996", "998"], ["user1997", "1997", "998.5"]], page.Rows.Take(2));
        Assert.Equal(5, page.Rows.Count);
        Assert.Null(page.Next);
        Assert.Equal(20, View(path, new FileViewOptions("sqlite", "kv", null, 0, 20)).Page!.Next);
        var error = Assert.Throws<ToolError>(() => View(path, new FileViewOptions("sqlite", "users", ["nope"])));
        Assert.Contains("id, name, score, avatar, rowid", error.Remediation);
        Assert.Throws<ToolError>(() => View(path, new FileViewOptions("sqlite", "missing")));
    }

    /// <summary>3,000 messages; every tenth deleted (freed cells in live pages), then a run of 400 (pages freed to the freelist).</summary>
    private static readonly string[] Messages =
    [
        "PRAGMA secure_delete=OFF;",
        "CREATE TABLE msg(id INTEGER PRIMARY KEY, sender TEXT, body TEXT, sent REAL, flags INTEGER);",
        "CREATE TABLE contact(name TEXT, phone TEXT);",
        "INSERT INTO contact VALUES ('Ann', '555-0100'), ('Bob', '555-0101');",
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 3000) INSERT INTO msg(sender, body, sent, flags) SELECT " +
        "'user' || (i % 37), 'message ' || i || ' ' || substr('the quick brown fox jumps over the lazy dog again and again', 1, i % 60), 1700000000 + i * 1.5, i % 5 FROM n;",
    ];

    [Fact]
    public void Deleted_rows_are_carved_from_free_space()
    {
        var path = Database("msg.db", Messages);
        var gone = NativeSqlite.Query(path, "SELECT sender, body, sent, flags FROM msg WHERE id % 10 = 3 OR id BETWEEN 2001 AND 2400").Select(Key).ToHashSet();
        NativeSqlite.Write(path, ["PRAGMA secure_delete=OFF;", "DELETE FROM msg WHERE id % 10 = 3;", "DELETE FROM msg WHERE id BETWEEN 2001 AND 2400;"]);
        var live = NativeSqlite.Query(path, "SELECT sender, body, sent, flags FROM msg").Select(Key).ToHashSet();
        var bytes = File.ReadAllBytes(path);
        var db = SqliteDatabase.Open(bytes)!;
        var notes = new List<string>();
        var rows = db.Recover(notes);
        var carved = rows.Where(r => r.Table == "msg").Select(r => Key([.. r.Values.Skip(1)])).ToList();
        int found = gone.Count(carved.Contains);
        output.WriteLine($"{found} of {gone.Count} deleted rows recovered; {rows.Count} candidates; {string.Join("; ", notes)}");
        foreach (var g in rows.GroupBy(r => r.Method)) output.WriteLine($"  {g.Key}: {g.Count()}");
        Assert.True(found >= gone.Count * 0.9, $"{found} of {gone.Count} recovered");
        Assert.DoesNotContain(carved, live.Contains);
        Assert.True(carved.Count(gone.Contains) >= carved.Count * 0.95, $"{carved.Count(gone.Contains)} of {carved.Count} candidates are deleted rows");
        Assert.Contains(rows, r => r.Method == "cell" && r.RowId is > 2000 and <= 2400);

        var facts = (SqliteRecoverFileView.Facts)new SqliteRecoverFileView().Inspect(new FileInput("msg.db", bytes, "data") { Options = new FileViewOptions("sqlite-recover", "msg", null, 10, 5) }, default)!.Detail;
        Assert.Equal(5, facts.Rows.Count);
        Assert.Equal(15, facts.Next);
        Assert.All(facts.Rows, r => Assert.Equal("msg", r.Table));
    }

    [Fact]
    public void Deleted_rows_are_carved_from_without_rowid_tables_overflow_pages_and_rows_before_added_columns()
    {
        string[] build =
        [
            "PRAGMA secure_delete=OFF;",
            "CREATE TABLE kv(k TEXT, n INTEGER, v TEXT, PRIMARY KEY(k, n)) WITHOUT ROWID;",
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 3000) INSERT INTO kv SELECT 'key' || (i % 50), i, 'value ' || i || substr('lorem ipsum dolor sit amet consectetur', 1, i % 30) FROM n;",
            "CREATE TABLE doc(id INTEGER PRIMARY KEY, title TEXT, body TEXT);",
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 300) INSERT INTO doc(title, body) SELECT 'doc ' || i, 'doc ' || i || ' ' || replace(hex(zeroblob(3000 + i * 7)), '00', 'ab') FROM n;",
            "CREATE TABLE note(id INTEGER PRIMARY KEY, text TEXT);",
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 1000) INSERT INTO note(text) SELECT 'note ' || i FROM n;",
            "ALTER TABLE note ADD COLUMN pinned INTEGER DEFAULT 0;",
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 200) INSERT INTO note(text, pinned) SELECT 'late note ' || i, 1 FROM n;",
        ];
        var path = Database("carve.db", build);
        var gone = new Dictionary<string, List<object?[]>>
        {
            ["kv"] = NativeSqlite.Query(path, "SELECT k, n, v FROM kv WHERE n % 10 = 3"),
            ["doc"] = NativeSqlite.Query(path, "SELECT title, body FROM doc WHERE id % 5 = 0"),
            ["note"] = NativeSqlite.Query(path, "SELECT text, pinned FROM note WHERE id % 10 = 7"),
        };
        NativeSqlite.Write(path, ["PRAGMA secure_delete=OFF;", "DELETE FROM kv WHERE n % 10 = 3;", "DELETE FROM doc WHERE id % 5 = 0;", "DELETE FROM note WHERE id % 10 = 7;"]);
        var bytes = File.ReadAllBytes(path);
        var db = SqliteDatabase.Open(bytes)!;
        var notes = new List<string>();
        var rows = db.Recover(notes);
        output.WriteLine(string.Join("; ", notes));
        var skip = new Dictionary<string, int> { ["kv"] = 0, ["doc"] = 1, ["note"] = 1 }; // the rowid alias
        foreach (var (table, deleted) in gone)
        {
            // a row can come back only while its bytes are in the file: B-tree rebalancing rewrites pages and drops freed cells
            var expected = deleted.Select(Key).ToHashSet();
            var present = deleted.Where(r => bytes.AsSpan().IndexOf(System.Text.Encoding.UTF8.GetBytes(((string)r[table == "kv" ? 2 : table == "doc" ? 1 : 0]!)[..Math.Min(24, ((string)r[table == "kv" ? 2 : table == "doc" ? 1 : 0]!).Length)])) >= 0)
                .Select(Key).ToHashSet();
            var carved = rows.Where(r => r.Table == table).Select(r => Key([.. r.Values.Skip(skip[table])])).ToList();
            int found = expected.Count(carved.Contains);
            output.WriteLine($"{table}: {found} of {expected.Count} deleted rows recovered ({present.Count} still in the file); {carved.Count} candidates; " +
                             string.Join(", ", rows.Where(r => r.Table == table).GroupBy(r => r.Method).Select(g => $"{g.Key} {g.Count()}")));
            Assert.True(found >= present.Count * 0.9, $"{table}: {found} of {present.Count}");
            Assert.True(carved.Count(expected.Contains) >= carved.Count * 0.95, $"{table}: {carved.Count(expected.Contains)} of {carved.Count} candidates are deleted rows");
        }
        Assert.Contains(rows, r => r.Method == "record, overflow pages");
    }

    private static string Key(object?[] row) => string.Join("|", row.Select(v => v is double d ? d.ToString("R", System.Globalization.CultureInfo.InvariantCulture) : v?.ToString() ?? "NULL"));

    [Fact]
    public void Recover_view_only_points_at_free_space_unless_asked()
    {
        var path = Database("small.db", [.. Messages, "DELETE FROM msg WHERE id <= 600;"]);
        var bytes = File.ReadAllBytes(path);
        var view = new SqliteRecoverFileView().Inspect(new FileInput("small.db", bytes, "data"), default)!;
        Assert.Empty(((SqliteRecoverFileView.Facts)view.Detail).Rows);
        Assert.Contains("freelist pages", Assert.Single(view.Highlights));
    }

    [Fact]
    [FuzzEntry(typeof(SqliteDatabase))]
    public void Fuzzed_wal_and_carving_never_throw()
    {
        WalDatabase();
        var db = File.ReadAllBytes(_dir.File("wal.db"));
        var wal = File.ReadAllBytes(_dir.File("wal.db-wal"));
        var failures = FormatFuzz.Run(wal, b =>
        {
            var d = SqliteDatabase.Open(SqliteSource.Of(db), SqliteSource.Of(b));
            d?.Recover([]);
            if (d?.Table("log") is { } t) d.Rows(t.RootPage, 100, 50);
        }, 300);
        var seed = NativeSqlite.Build([.. Messages[..^1], Messages[^1].Replace("3000", "300"), "DELETE FROM msg WHERE id % 3 = 0;"]);
        failures.AddRange(FormatFuzz.Run(seed, b =>
        {
            var d = SqliteDatabase.Open(b);
            d?.Recover([]);
            if (d?.Table("msg") is { } t) d.Rows(t.RootPage, 150, 20);
        }, 1000));
        var spilled = NativeSqlite.Build("PRAGMA page_size=512;", "PRAGMA secure_delete=OFF;", "CREATE TABLE kv(k TEXT, n INTEGER, v TEXT, PRIMARY KEY(k, n)) WITHOUT ROWID;",
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 60) INSERT INTO kv SELECT 'k' || (i % 7), i, 'v' || i FROM n;",
            "CREATE TABLE doc(id INTEGER PRIMARY KEY, body TEXT);", "INSERT INTO doc(body) VALUES (hex(zeroblob(700))), (hex(zeroblob(900))), ('short');",
            "ALTER TABLE doc ADD COLUMN pinned INTEGER DEFAULT 0;", "DELETE FROM kv WHERE n % 4 = 1;", "DELETE FROM doc WHERE id < 3;");
        failures.AddRange(FormatFuzz.Run(spilled, b => SqliteDatabase.Open(b)?.Recover([]), 500));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(5)));
    }
}

/// <summary>Paging time on a database over 100 MB, measured without other tests running.</summary>
[Collection(nameof(SerialTimingTests))]
public sealed class SqlitePagingTimingTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    [Fact]
    [Trait("Speed", "Slow")]
    public void Hundred_megabyte_database_pages_quickly()
    {
        var path = _dir.File("big.db");
        NativeSqlite.Write(path, ["PRAGMA journal_mode=OFF;", "PRAGMA synchronous=OFF;", "CREATE TABLE big(id INTEGER PRIMARY KEY, a TEXT, b INTEGER);",
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 800000) INSERT INTO big(a, b) SELECT printf('%.120c', 'x') || i, i * 7 FROM n;"]);
        long length = new FileInfo(path).Length;
        Assert.True(length > 100L << 20, $"{length:N0} bytes");
        SqliteFileView.Facts Page(long offset)
        {
            var input = FileInput.Open(path);
            input.Options = new FileViewOptions("sqlite", "big", ["id", "b"], offset, 50);
            return (SqliteFileView.Facts)new SqliteFileView().Inspect(input, default)!.Detail;
        }
        Page(0); // the file in the OS cache
        var times = new List<double>();
        foreach (var offset in new long[] { 0, 400_000, 799_950 })
        {
            var clock = System.Diagnostics.Stopwatch.StartNew();
            var page = Page(offset).Page!;
            times.Add(clock.Elapsed.TotalMilliseconds);
            Assert.Equal((offset + 1).ToString(System.Globalization.CultureInfo.InvariantCulture), page.Rows[0][0]);
            Assert.Equal(800_000, page.Total);
        }
        output.WriteLine($"{length:N0} bytes; pages at offsets 0, 400,000, 799,950 in {string.Join(", ", times.Select(t => $"{t:F0} ms"))}");
        Assert.True(times.Max() < 250, string.Join(", ", times)); // about 50 ms on a desktop; the margin is for loaded machines
    }
}
