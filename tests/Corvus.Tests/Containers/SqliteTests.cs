using System.Runtime.InteropServices;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>The SQLite B-tree reader and summarize_file view=sqlite on databases written by the real library (e_sqlite3 from its package).</summary>
public sealed class SqliteTests
{
    private const string Users = "CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, score REAL, avatar BLOB)";
    private const string Kv = "CREATE TABLE kv(k TEXT PRIMARY KEY, v INTEGER) WITHOUT ROWID";

    private static readonly Lazy<byte[]> Fixture = new(() => NativeSqlite.Build(
        "PRAGMA page_size=1024;",
        Users + ";",
        "CREATE INDEX users_name ON users(name);",
        Kv + ";",
        "CREATE TABLE notes(body TEXT);",
        "CREATE VIEW names AS SELECT name FROM users;",
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 2000) INSERT INTO users(name, score, avatar) SELECT 'user' || i, i * 0.5, x'00112233445566778899AABBCCDDEEFF0011' FROM n;",
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 500) INSERT INTO kv SELECT printf('key%04d', 501 - i), i FROM n;",
        "INSERT INTO notes VALUES (replace(hex(zeroblob(2500)), '0', 'x'));"));

    internal static byte[] FixtureBytes => Fixture.Value;

    private static SqliteFileView.Facts View(byte[] bytes) =>
        (SqliteFileView.Facts)new SqliteFileView().Inspect(new FileInput("app.db", bytes, Blob.Identify(bytes)), default)!.Detail;

    [Fact]
    public void Header_schema_and_row_counts_match_the_writer()
    {
        var f = View(Fixture.Value);
        Assert.Equal(1024, f.PageSize);
        Assert.Equal("UTF-8", f.Encoding);
        Assert.Equal("rollback", f.JournalMode);
        Assert.Equal(Users, f.Schema.Single(e => e.Name == "users").Sql);
        Assert.Equal(Kv, f.Schema.Single(e => e.Name == "kv").Sql);
        Assert.Equal(["table users", "index users_name", "table kv", "table notes", "view names"], f.Schema.Select(e => $"{e.Type} {e.Name}"));
        Assert.Equal(2000, f.Tables.Single(t => t.Name == "users").Rows);
        Assert.Equal(500, f.Tables.Single(t => t.Name == "kv").Rows);
        Assert.Equal(1, f.Tables.Single(t => t.Name == "notes").Rows);
        Assert.Empty(f.Notes);
    }

    [Theory]
    [InlineData(3_045_001u, "3.45.1")]
    [InlineData(3_000_000u, "3.0.0")]
    [InlineData(3_999_999u, "3.999.999")]
    [InlineData(2_999_999u, null)]
    [InlineData(4_000_000u, null)]
    public void The_writer_version_is_read_from_the_header_only_for_sqlite_3(uint version, string? expected)
    {
        var bytes = (byte[])Fixture.Value.Clone();
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(96), version); // SQLITE_VERSION_NUMBER of the last writer
        Assert.Equal(expected, SqliteDatabase.Open(bytes)!.WriterVersion);
    }

    [Fact]
    public void Preview_shows_rowid_alias_clipped_overflow_text_and_without_rowid_key_order()
    {
        var f = View(Fixture.Value);
        var users = f.Tables.Single(t => t.Name == "users");
        Assert.Equal(["id", "name", "score", "avatar"], users.Columns);
        Assert.Equal(["1", "user1", "0.5", "x'00112233445566778899AABBCCDDEEFF…' (18 bytes)"], users.Preview[0]);
        Assert.Equal(5, users.Preview.Count);
        Assert.Equal(new string('x', 80) + "… (5,000 chars)", f.Tables.Single(t => t.Name == "notes").Preview[0][0]);
        var kv = f.Tables.Single(t => t.Name == "kv");
        Assert.True(kv.WithoutRowId);
        Assert.Equal(["key0001", "500"], kv.Preview[0]);
        Assert.Equal(["key0002", "499"], kv.Preview[1]);
    }

    [Fact]
    public void Utf16_text_is_decoded()
    {
        var bytes = NativeSqlite.Build("PRAGMA encoding='UTF-16le';", "CREATE TABLE t(a TEXT);", "INSERT INTO t VALUES ('héllo');");
        var f = View(bytes);
        Assert.Equal("UTF-16le", f.Encoding);
        Assert.Equal("héllo", f.Tables.Single().Preview[0][0]);
    }

    [Fact]
    public void A_page_cycle_ends_the_walk_with_an_issue()
    {
        var bytes = (byte[])Fixture.Value.Clone();
        var db = SqliteDatabase.Open(bytes)!;
        long root = db.Schema.Single(e => e.Name == "users").RootPage;
        int header = (int)(root - 1) * db.PageSize;
        Assert.Equal(5, bytes[header]);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(header + 8), (uint)root);
        var f = View(bytes);
        Assert.Null(f.Tables.Single(t => t.Name == "users").Rows);
        Assert.Contains(f.Notes, n => n.Contains("a cycle"));
    }

    [Fact]
    public void Wal_mode_is_noted()
    {
        var bytes = (byte[])Fixture.Value.Clone();
        bytes[18] = bytes[19] = 2;
        var f = View(bytes);
        Assert.Equal("wal", f.JournalMode);
        Assert.Contains(f.Notes, n => n.Contains("-wal file"));
    }

    [Fact]
    public void Other_files_do_not_apply() =>
        Assert.Null(new SqliteFileView().Inspect(new FileInput("x.bin", new byte[200], "data"), default));

    [Fact]
    [FuzzEntry(typeof(SqliteFileView), typeof(SqliteDatabase))]
    public void Fuzzed_database_never_throws()
    {
        var failures = FormatFuzz.Run(Fixture.Value, b => new SqliteFileView().Inspect(new FileInput("app.db", b, "data"), default), 1500);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(5)));
    }
}

/// <summary>Writes and queries databases with the e_sqlite3 library of the SQLitePCLRaw package for this platform (the oracle).</summary>
internal static class NativeSqlite
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int Open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, out IntPtr db);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int Exec(IntPtr db, [MarshalAs(UnmanagedType.LPUTF8Str)] string sql, IntPtr callback, IntPtr arg, out IntPtr error);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int Close(IntPtr db);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int Prepare(IntPtr db, [MarshalAs(UnmanagedType.LPUTF8Str)] string sql, int bytes, out IntPtr stmt, IntPtr tail);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int Stmt(IntPtr stmt);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int Column(IntPtr stmt, int i);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate long ColumnInt64(IntPtr stmt, int i);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate double ColumnDouble(IntPtr stmt, int i);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr ColumnPointer(IntPtr stmt, int i);

    private static readonly Lazy<IntPtr> Library = new(() => NativeLibrary.Load(LibraryPath()));

    private static string LibraryPath()
    {
        string arch = RuntimeInformation.ProcessArchitecture switch { Architecture.Arm64 => "arm64", Architecture.X86 => "x86", _ => "x64" };
        var (os, file) = OperatingSystem.IsWindows() ? ("win", "e_sqlite3.dll") : OperatingSystem.IsMacOS() ? ("osx", "libe_sqlite3.dylib") : ("linux", "libe_sqlite3.so");
        return RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "runtimes", $"{os}-{arch}", "native", file);
    }

    private static T Fn<T>(string name) where T : Delegate => Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(Library.Value, name));

    public static byte[] Build(params string[] statements)
    {
        var path = Path.Combine(Path.GetTempPath(), "corvus-sqlite-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            Write(path, statements);
            return File.ReadAllBytes(path);
        }
        finally { File.Delete(path); }
    }

    /// <summary>Runs the statements on the database at <paramref name="path"/>; <paramref name="whileOpen"/> runs before it is closed.</summary>
    public static void Write(string path, string[] statements, Action? whileOpen = null)
    {
        Assert.Equal(0, Fn<Open>("sqlite3_open")(path, out var db));
        try
        {
            foreach (var sql in statements)
                Assert.True(Fn<Exec>("sqlite3_exec")(db, sql, IntPtr.Zero, IntPtr.Zero, out _) == 0, sql);
            whileOpen?.Invoke();
        }
        finally { Fn<Close>("sqlite3_close")(db); }
    }

    /// <summary>The rows of a query: long, double, string, byte[] or null per column, as the library returns them.</summary>
    public static List<object?[]> Query(string path, string sql)
    {
        Assert.Equal(0, Fn<Open>("sqlite3_open")(path, out var db));
        var rows = new List<object?[]>();
        try
        {
            Assert.Equal(0, Fn<Prepare>("sqlite3_prepare_v2")(db, sql, -1, out var stmt, IntPtr.Zero));
            try
            {
                int columns = Fn<Stmt>("sqlite3_column_count")(stmt);
                while (Fn<Stmt>("sqlite3_step")(stmt) == 100)
                {
                    var row = new object?[columns];
                    for (int i = 0; i < columns; i++)
                        row[i] = Fn<Column>("sqlite3_column_type")(stmt, i) switch
                        {
                            1 => Fn<ColumnInt64>("sqlite3_column_int64")(stmt, i),
                            2 => Fn<ColumnDouble>("sqlite3_column_double")(stmt, i),
                            3 => Marshal.PtrToStringUTF8(Fn<ColumnPointer>("sqlite3_column_text")(stmt, i), Fn<Column>("sqlite3_column_bytes")(stmt, i)),
                            4 => Blob(Fn<ColumnPointer>("sqlite3_column_blob")(stmt, i), Fn<Column>("sqlite3_column_bytes")(stmt, i)),
                            _ => null,
                        };
                    rows.Add(row);
                }
            }
            finally { Fn<Stmt>("sqlite3_finalize")(stmt); }
        }
        finally { Fn<Close>("sqlite3_close")(db); }
        return rows;

        static byte[] Blob(IntPtr p, int n)
        {
            var b = new byte[n];
            if (n > 0) Marshal.Copy(p, b, 0, n);
            return b;
        }
    }
}
