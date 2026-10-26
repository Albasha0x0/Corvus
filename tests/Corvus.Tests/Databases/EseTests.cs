using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Databases;
using Corvus.Native.Providers;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// ledger-8k.edb and ledger-32k.edb (stored gzip-compressed) built by build.cs with esent.dll: table accounts (200 rows, 20 updated, rows 191 to
/// 200 deleted) and table journal (300 rows), one file per page size.
/// </summary>
public sealed class EseTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    // A database fixture is unpacked into the test's folder; other files are read in place.
    private string Fixture(string name)
    {
        string source = Path.Combine(AppContext.BaseDirectory, "Databases", "EseFixtures", name);
        if (!name.EndsWith(".edb", StringComparison.Ordinal)) return source;
        string path = Path.Combine(_dir.Path, name);
        if (!File.Exists(path))
        {
            using var z = new GZipStream(File.OpenRead(source + ".gz"), CompressionMode.Decompress);
            using var o = File.Create(path);
            z.CopyTo(o);
        }
        return path;
    }

    private EseFileView.Facts View(string file, string? table = null, long offset = 0, int? limit = null, string view = "ese")
    {
        var f = FileInput.Open(Fixture(file));
        f.Options = new FileViewOptions(view, table, Offset: offset, Limit: limit);
        return (EseFileView.Facts)new EseFileView().Inspect(f, default)!.Detail;
    }

    private List<Ese.Row> Rows(string file, string table)
    {
        using var db = new Ese(File.OpenRead(Fixture(file)));
        return [.. db.Rows(db.Tables.Single(t => t.Name == table), null, default)];
    }

    [Fact]
    public void The_catalog_names_the_tables_and_a_page_of_records_reads()
    {
        var v = View("ledger-8k.edb", limit: 2);
        Assert.Equal((8192, "0x620 revision 0x12c", "clean shutdown"), (v.PageSize, v.Format, v.State));
        Assert.Equal(["MSysObjects", "MSysObjectsShadow", "MSysObjids", "MSysLocales", "accounts", "journal"], v.Tables.Select(t => t.Name));
        Assert.Equal(["primary", "by_name"], v.Tables.Single(t => t.Name == "accounts").Indexes);
        Assert.Equal("accounts", v.Table);
        Assert.Equal(["Id long", "Balance currency", "Opened date time", "Active bit", "Name text", "Tags text multi-valued", "Statement long binary", "Memo long text compressed"], v.Columns);
        Assert.Equal(new Dictionary<string, string> { ["Id"] = "1", ["Balance"] = "0", ["Opened"] = "2026-01-02 00:00:00", ["Active"] = "false", ["Name"] = "holder1", ["Tags"] = "region-1", ["Memo"] = "memo 1: balance reviewed, statement sent, account in good standing" },
            v.Records[0].Fields);
        Assert.Equal(2, v.Next);
        var journal = View("ledger-32k.edb", "journal", offset: 298);
        Assert.Equal(["299", "300"], journal.Records.Select(r => r.Fields["Entry"]));
        Assert.Equal($"transfer {300 * 13 % 500}.00 from holder{300 % 200 + 1}", journal.Records[^1].Fields["Text"]);
        Assert.Null(journal.Next);
    }

    [Theory]
    [InlineData("ledger-8k.edb")]
    [InlineData("ledger-32k.edb")]
    public void Every_column_form_reads_on_both_page_sizes(string file)
    {
        var rows = Rows(file, "accounts");
        Assert.Equal(190, rows.Count);
        Ese.Field F(int id, string column) => rows[id - 1].Fields.Single(f => f.Column.Name == column);
        string Text(Ese.Field f) => Encoding.Unicode.GetString(f.Values[0]);
        // Fixed columns: a null one by its bitmap bit although its bytes are filler, the others by value.
        Assert.True(F(7, "Opened").Null);
        Assert.Equal(BitConverter.GetBytes(new DateTime(2026, 1, 9).ToOADate()), F(8, "Opened").Values[0]);
        Assert.Equal(BitConverter.GetBytes((long)(25 * 37 % 1000) * 10000 + 25 * 100), F(25, "Balance").Values[0]);
        Assert.Equal("holder190", Text(F(190, "Name")));
        // Tagged multi-values: one value, two (the two-value form) and three (the offset form), ASCII.
        Assert.Equal(["region-3"], F(3, "Tags").Values.Select(Encoding.ASCII.GetString));
        Assert.Equal(["retail", "region-2"], F(2, "Tags").Values.Select(Encoding.ASCII.GetString));
        Assert.Equal(["retail", "region-0", "audited"], F(10, "Tags").Values.Select(Encoding.ASCII.GetString));
        // Long values: 12,000 bytes over several chunks; compressed text: 7-bit inline and LZ4 in the long-value tree.
        var statement = F(50, "Statement");
        Assert.Equal(Encoding.ASCII.GetBytes(string.Concat(Enumerable.Range(0, 800).Select(n => $"line {n:D5}: ok\n")))[..12000], statement.Values[0]);
        Assert.True(statement.Separated);
        Assert.Null(statement.Problem);
        Assert.Equal("memo 1: balance reviewed, statement sent, account in good standing", Text(F(1, "Memo")));
        Assert.Equal(0x10, F(1, "Memo").Stored[0][0] & 0xF8);
        var memo = F(25, "Memo");
        Assert.Equal(string.Concat(Enumerable.Repeat("memo for holder25; ", 4000))[..4000], Text(memo));
        Assert.Equal(0x38, memo.Stored[0][0]);
        // 60,000 bytes span several long-value chunks, each compressed on its own.
        var large = F(100, "Memo");
        Assert.Equal(string.Concat(Enumerable.Repeat("memo for holder100; ", 4000))[..30000], Text(large));
        Assert.True(large.Separated);
        Assert.Null(large.Problem);
    }

    [Fact]
    public void Deleted_records_are_recovered_from_free_space()
    {
        var large = View("ledger-32k.edb").Recovered!;
        Assert.Equal(Enumerable.Range(191, 10).Select(i => i.ToString()), large.Select(r => r.Fields["Id"]));
        Assert.All(large, r => Assert.StartsWith("free space, page 31", r.Source));
        Assert.Equal(new Dictionary<string, string> { ["Id"] = "196", ["Balance"] = "2529600", ["Active"] = "true", ["Name"] = "holder196", ["Tags"] = "[retail, region-1]", ["Memo"] = "memo 196: balance reviewed, statement sent, account in good standing" },
            large[5].Fields);
        // The deleted row's long value went with it.
        Assert.EndsWith("is not in the long-value tree)", large[^1].Fields["Statement"]);
        var small = View("ledger-8k.edb").Recovered!;
        Assert.Equal(Enumerable.Range(191, 10).Select(i => i.ToString()), small.Select(r => r.Fields["Id"]));
        Assert.Equal(large.SkipLast(1).Select(r => r.Fields), small.SkipLast(1).Select(r => r.Fields));
        // Only a gap's last node can lack a recorded end.
        Assert.All(small.SkipLast(1).Concat(large.SkipLast(1)), r => Assert.DoesNotContain("end unknown", r.Source));
        Assert.Null(View("ledger-8k.edb", view: "overview").Recovered);
    }

    [Fact]
    public void Compression_schemes_decode_or_name_what_is_not_read()
    {
        // MS-XCA 3.1 plain LZ77 example: "abc" 100 times, behind ESE's Xpress header (scheme 3, uncompressed size).
        byte[] xpress = [0x18, 0x2C, 0x01, 0xFF, 0xFF, 0xFF, 0x1F, 0x61, 0x62, 0x63, 0x17, 0x00, 0x0F, 0xFF, 0x26, 0x01];
        Assert.Equal(string.Concat(Enumerable.Repeat("abc", 100)), Encoding.ASCII.GetString(Ese.Decompress(xpress).Data!));
        Assert.Equal((null, "Xpress9-compressed; not read"), Ese.Decompress([0x28, 0, 0, 0, 0]));
        Assert.Equal((null, "Xpress10-compressed; not read"), Ese.Decompress([0x30, 0, 0]));
        Assert.Equal("Xpress data ends after 3 of 300 bytes", Ese.Decompress(xpress.AsSpan(0, 10)).Problem);
    }

    [Fact]
    public void An_unknown_table_name_is_refused_with_the_names()
    {
        var e = Assert.Throws<ToolError>(() => View("ledger-8k.edb", "ledger"));
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
        Assert.Contains("accounts, journal", e.Message);
    }

    [Fact]
    [FuzzEntry(typeof(EseFileView), typeof(Ese))]
    public void Fuzzed_databases_never_throw_past_a_tool_error()
    {
        var path = _dir.File("ledger.edb");
        // The fixture cut after its last used page keeps the mutations on pages the reader visits.
        var seed = File.ReadAllBytes(Fixture("ledger-8k.edb"))[..(8192 * 72)];
        var failures = FormatFuzz.Run(seed, b =>
        {
            File.WriteAllBytes(path, b);
            foreach (var table in new string?[] { null, "journal" })
                try { new EseFileView().Inspect(new FileInput(path, b, Blob.Identify(b)) { Options = new FileViewOptions("ese", table) }, default); }
                catch (ToolError) { }
        }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    // The fixtures and each *.edb file under CORVUS_ESE_FILES are read by libesedb's pyesedb through reference.py, run by
    // CORVUS_FS_REFERENCE (python3 on Linux, wsl.exe on Windows). Compared: the tables, their columns and every record.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_FS_REFERENCE")]
    public void Tables_and_records_equal_what_libesedb_reads()
    {
        string runner = RealData.Path("CORVUS_FS_REFERENCE");
        var files = new List<string> { Fixture("ledger-8k.edb"), Fixture("ledger-32k.edb") };
        if (Environment.GetEnvironmentVariable("CORVUS_ESE_FILES") is { Length: > 0 } dir)
            files.AddRange(Directory.EnumerateFiles(dir, "*.edb", SearchOption.AllDirectories).Order(StringComparer.Ordinal));
        bool wsl = Path.GetFileNameWithoutExtension(runner).Equals("wsl", StringComparison.OrdinalIgnoreCase);
        var problems = new List<string>();
        int databases = 0, records = 0, filler = 0, unread = 0, lz4 = 0;
        foreach (var file in files)
        {
            List<string> args = wsl ? ["-e", "python3", "-I", LinuxPath(Fixture("reference.py")), LinuxPath(file)] : ["-I", Fixture("reference.py"), file];
            var run = ExternalTools.Run(runner, args, TimeSpan.FromMinutes(20), 1 << 30, default);
            string name = Path.GetFileName(file);
            if (run.ExitCode != 0) { problems.Add($"{name}: reference exit {run.ExitCode}: {run.Stderr}"); continue; }
            var expected = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            var expectedTables = new List<string>();
            foreach (var line in run.Text.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var f = line.Split('\t');
                if (f[0] == "T") { expectedTables.Add($"{f[1]}({f[2]})"); expected[f[1]] = []; }
                else if (f[0] == "R") expected[f[1]].Add(f[2]);
            }
            using var db = new Ese(File.OpenRead(file));
            var actualTables = db.Tables.Select(t => $"{t.Name}({string.Join(",", t.Columns.Select(c => c.Name))})").ToList();
            if (!expectedTables.SequenceEqual(actualTables))
                problems.Add($"{name}: tables libesedb [{string.Join(" ", expectedTables)}], Corvus [{string.Join(" ", actualTables)}]");
            foreach (var t in db.Tables)
            {
                if (!expected.TryGetValue(t.Name, out var want)) continue;
                var got = db.Rows(t, null, default).ToList();
                if (got.Count != want.Count) { problems.Add($"{name}/{t.Name}: libesedb {want.Count} records, Corvus {got.Count}"); continue; }
                for (int i = 0; i < got.Count; i++)
                {
                    var theirs = want[i].Split('\x1f');
                    for (int k = 0; k < got[i].Fields.Count && k < theirs.Length; k++)
                    {
                        var field = got[i].Fields[k];
                        // pyesedb returns a null fixed column's filler bytes, an empty value as none, and cannot read some
                        // compressed values.
                        if (field.Null && field.Column.Id < 128 && theirs[k].Length > 0) { filler++; continue; }
                        if (!field.Null && field.Values.Count == 1 && field.Values[0].Length == 0 && theirs[k].Length == 0) continue;
                        if (theirs[k].StartsWith("err:", StringComparison.Ordinal)) { if (unread++ < 3) output.WriteLine($"{name}/{t.Name} {field.Column.Name}: {theirs[k]}"); continue; }
                        string mine = Reference(field);
                        // libesedb has no LZ4 decoder and stops at a long value's first LZ4 chunk; the value Corvus decodes
                        // must then fill the size its root states.
                        if (field.Separated && field.Values[0].Length != field.Stored[0].Length && mine != theirs[k] && mine.StartsWith(theirs[k], StringComparison.Ordinal))
                        {
                            lz4++;
                            if (field.Problem != null) problems.Add($"{name}/{t.Name} record {i + 1} {field.Column.Name}: {field.Problem}");
                            continue;
                        }
                        if (mine != theirs[k] && problems.Count < 40) problems.Add($"{name}/{t.Name} record {i + 1} {field.Column.Name}: {Difference(theirs[k], mine)}");
                    }
                }
                records += got.Count;
            }
            // The fixtures are shut down clean; a database copied from a running system may carry a state note.
            if (db.Notes.Count > 0 && file.StartsWith(_dir.Path, StringComparison.Ordinal)) problems.Add($"{name}: notes on an intact file: {db.Notes[0]}");
            databases++;
        }
        output.WriteLine($"{databases} databases: {records} records equal to libesedb; skipped: {filler} null fixed fields, {unread} values libesedb does not read, {lz4} LZ4 long values it reads in part");
        foreach (var p in problems.Take(40)) output.WriteLine(p);
        Assert.Empty(problems);
    }

    // The field as reference.py prints it.
    private static string Reference(Ese.Field f)
    {
        if (f.Null) return "";
        if (f.Stored.Count > 1) return "mv:" + string.Join(",", f.Stored.Select(Convert.ToHexStringLower));
        if (f.Separated) return "lv:" + Convert.ToHexStringLower(f.Stored[0]);
        if (f.Column.Type is 10 or 12)
            return "s:" + Escape(Ese.Text(f.Column, f.Values[0]));
        return Convert.ToHexStringLower(f.Stored[0]);
    }

    // As reference.py escapes text.
    private static string Escape(string s) =>
        s.Replace("\\", "\\\\").Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t").Replace("\x1f", "\\x1f");

    private static string Difference(string theirs, string mine)
    {
        int at = 0;
        while (at < theirs.Length && at < mine.Length && theirs[at] == mine[at]) at++;
        int from = Math.Max(0, at - 16);
        return $"from character {at:N0} of {theirs.Length:N0} (libesedb) and {mine.Length:N0} (Corvus): libesedb {Clip(theirs[from..])}, Corvus {Clip(mine[from..])}";
    }

    private static string Clip(string s) => s.Length > 80 ? s[..80] + "..." : s;

    /// <summary>A Windows path as WSL mounts it (/mnt/d/...).</summary>
    private static string LinuxPath(string path) =>
        path.Length > 2 && path[1] == ':' ? $"/mnt/{char.ToLowerInvariant(path[0])}{path[2..].Replace('\\', '/')}" : path;
}
