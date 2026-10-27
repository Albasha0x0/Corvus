using System.Text;
using Corvus.Core;
using Corvus.Core.Databases;
using Corvus.Native.Providers;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Berkeley DB files built by build.py with libdb 5.3.28: every access method, both byte orders.</summary>
public sealed class BerkeleyDbTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Databases", "BerkeleyDbFixtures", name);

    private static BerkeleyDbFileView.Facts View(string file, string? table = null, long offset = 0, int? limit = null, string view = "berkeleydb")
    {
        var f = FileInput.Open(Fixture(file));
        f.Options = new FileViewOptions(view, table, Offset: offset, Limit: limit);
        return (BerkeleyDbFileView.Facts)new BerkeleyDbFileView().Inspect(f, default)!.Detail;
    }

    private static List<BerkeleyDb.Record> Records(string file, string name)
    {
        using var bdb = new BerkeleyDb(File.OpenRead(Fixture(file)));
        return [.. bdb.Records(bdb.Databases.Single(d => d.Name == name), null, default)];
    }

    private static string S(byte[]? b) => b == null ? "" : Encoding.ASCII.GetString(b);

    [Fact]
    public void The_named_databases_and_a_page_of_records_read()
    {
        var v = View("ledger.db", limit: 2);
        Assert.Equal(("btree version 9", 4096, "little-endian"), (v.Format, v.PageSize, v.ByteOrder));
        Assert.Equal(["accounts btree", "index hash", "journal recno", "tags btree sorted duplicates"], v.Databases.Select(d => $"{d.Name} {d.Kind} {d.Flags}".TrimEnd()));
        Assert.Equal("accounts", v.Database);
        Assert.Equal([("account/0001", "owner=holder1; balance=0.00; closed"), ("account/0002", "owner=holder2; balance=0.00; closed")], v.Records.Select(r => (r.Key!, r.Value)));
        Assert.Equal(2, v.Next);
        var journal = View("ledger.db", "journal", offset: 293);
        Assert.Equal([(294L, "transfer 322.00 from holder95"), (295L, "transfer 335.00 from holder96")], journal.Records.Select(r => (r.Number!.Value, r.Value)));
        Assert.All(journal.Records, r => Assert.Null(r.Key));
        Assert.Null(journal.Next);
    }

    [Fact]
    public void Each_access_method_reads_in_both_byte_orders()
    {
        var accounts = Records("ledger.db", "accounts");
        Assert.Equal(191, accounts.Count);
        Assert.Equal("owner=holder190; balance=30.90", S(accounts.Single(r => S(r.Key) == "account/0190").Value));
        // A 10,000-byte value on overflow pages.
        Assert.Equal(string.Concat(Enumerable.Range(0, 500).Select(i => $"line {i:D5}: settled\n"))[..10000], S(accounts.Single(r => S(r.Key) == "statement/2026").Value));
        // Sorted duplicates: three on the leaf page, 400 in an off-page duplicate tree.
        var tags = Records("ledger.db", "tags");
        Assert.Equal(Enumerable.Range(0, 400).Select(i => $"large value-{i:D4}").Concat(["small blue", "small green", "small red"]), tags.Select(r => $"{S(r.Key)} {S(r.Value)}"));
        var index = Records("ledger.db", "index");
        Assert.Equal(290, index.Count);
        Assert.Equal("account/0002", S(index.Single(r => S(r.Key) == "holder1").Value));
        Assert.DoesNotContain(index, r => S(r.Key) == "holder300");
        var queue = Records("queue.db", "");
        Assert.Equal(Enumerable.Range(6, 95).Select(i => (long)i), queue.Select(r => r.Number!.Value));
        Assert.Equal("job 100: export ledger".PadRight(32), S(queue[^1].Value));
        var big = View("ledger-be.db", limit: 1000);
        Assert.Equal(("big-endian", 512, 44L), (big.ByteOrder, big.PageSize, big.Pages));
        Assert.Equal(Enumerable.Range(1, 300).Select(i => $"entry/{i:D4}"), big.Records.Select(r => r.Key!));
        Assert.Equal("transfer 400.00 from holder101", big.Records[^1].Value);
    }

    [Fact]
    public void Overwritten_values_deleted_items_and_consumed_records_are_recovered()
    {
        var recovered = View("ledger.db").Recovered!;
        // The accounts root page still holds the leaf items it had before it split: values later overwritten.
        var previous = recovered.Where(r => r.Source == "free space, page 3").ToList();
        Assert.Contains(previous, r => r.Key == "account/0005" && r.Value == "owner=holder5; balance=185.05" && r.Database == "accounts");
        Assert.All(previous, r => Assert.Equal($"owner=holder{int.Parse(r.Key![^4..])}; balance={int.Parse(r.Key[^4..]) * 37 % 1000}.{int.Parse(r.Key[^4..]) % 100:D2}", r.Value));
        // Recno deletes leave an empty placeholder under the record number.
        Assert.Equal(Enumerable.Range(296, 5).Select(i => (long)i), recovered.Where(r => r.Database == "journal").Select(r => r.Number!.Value));
        Assert.All(recovered.Where(r => r.Database == "journal"), r => Assert.Equal("deleted item; value not kept", r.Source));
        Assert.Equal(previous.Count + 5, recovered.Count);
        var consumed = View("queue.db").Recovered!;
        Assert.Equal(Enumerable.Range(1, 5).Select(i => $"job {i:D3}: export ledger".PadRight(32)), consumed.Select(r => r.Value));
        Assert.All(consumed, r => Assert.Equal("consumed record, page 1", r.Source));
        Assert.Null(View("ledger.db", view: "overview").Recovered);
    }

    [Fact]
    public void An_unknown_database_name_is_refused_with_the_names()
    {
        var e = Assert.Throws<ToolError>(() => View("ledger.db", "ledger"));
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
        Assert.Contains("accounts, index, journal, tags", e.Message);
    }

    [Fact]
    [FuzzEntry(typeof(BerkeleyDbFileView), typeof(BerkeleyDb))]
    public void Fuzzed_files_never_throw_past_a_tool_error()
    {
        var path = _dir.File("ledger.db");
        var seeds = new[] { "ledger.db", "queue.db", "ledger-be.db" }.Select(f => File.ReadAllBytes(Fixture(f))).ToArray();
        var failures = new List<string>();
        foreach (var seed in seeds)
            failures.AddRange(FormatFuzz.Run(seed, b =>
            {
                File.WriteAllBytes(path, b);
                foreach (var table in new string?[] { null, "tags", "index" })
                    try { new BerkeleyDbFileView().Inspect(new FileInput(path, b, Blob.Identify(b)) { Options = new FileViewOptions("berkeleydb", table) }, default); }
                    catch (ToolError) { }
            }, 150));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    // The fixtures and each file under CORVUS_BDB_FILES that opens as Berkeley DB are read by libdb through reference.py,
    // run by CORVUS_FS_REFERENCE (python3 on Linux, wsl.exe on Windows). Compared: the databases, their kinds and every record in order.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_FS_REFERENCE")]
    public void Databases_and_records_equal_what_libdb_reads()
    {
        string runner = RealData.Path("CORVUS_FS_REFERENCE");
        var files = new List<string> { Fixture("ledger.db"), Fixture("queue.db"), Fixture("ledger-be.db") };
        if (Environment.GetEnvironmentVariable("CORVUS_BDB_FILES") is { Length: > 0 } dir)
            files.AddRange(Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).Where(f => BerkeleyDb.Looks(Head(f))).Order(StringComparer.Ordinal));
        bool wsl = Path.GetFileNameWithoutExtension(runner).Equals("wsl", StringComparison.OrdinalIgnoreCase);
        var problems = new List<string>();
        int checkedFiles = 0, records = 0;
        foreach (var file in files)
        {
            List<string> args = wsl ? ["-e", "python3", "-I", LinuxPath(Fixture("reference.py")), LinuxPath(file)] : ["-I", Fixture("reference.py"), file];
            var run = ExternalTools.Run(runner, args, TimeSpan.FromMinutes(10), 1 << 30, default);
            string name = Path.GetFileName(file);
            if (run.ExitCode != 0) { problems.Add($"{name}: reference exit {run.ExitCode}: {run.Stderr}"); continue; }
            var expected = new List<string>();
            foreach (var line in run.Text.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries)) expected.Add(line);
            var actual = new List<string>();
            using (var bdb = new BerkeleyDb(File.OpenRead(file)))
                foreach (var d in bdb.Databases)
                {
                    actual.Add($"D\t{d.Name}\t{d.Kind}");
                    foreach (var r in bdb.Records(d, null, default))
                        actual.Add($"R\t{d.Name}\t{(r.Key == null ? "#" + r.Number : Convert.ToHexStringLower(r.Key))}\t{Convert.ToHexStringLower(r.Value)}");
                }
            int at = 0;
            while (at < expected.Count && at < actual.Count && expected[at] == actual[at]) at++;
            if (at < expected.Count || at < actual.Count)
                problems.Add($"{name}: line {at + 1} of {expected.Count} (libdb) and {actual.Count} (Corvus): libdb {Clip(at < expected.Count ? expected[at] : "(end)")}, Corvus {Clip(at < actual.Count ? actual[at] : "(end)")}");
            records += actual.Count(l => l[0] == 'R');
            checkedFiles++;
        }
        output.WriteLine($"{checkedFiles} files: {records} records equal to libdb");
        foreach (var p in problems.Take(40)) output.WriteLine(p);
        Assert.Empty(problems);
    }

    private static byte[] Head(string path)
    {
        using var s = File.OpenRead(path);
        var b = new byte[Math.Min(512, s.Length)];
        s.ReadExactly(b);
        return b;
    }

    private static string Clip(string s) => s.Length > 120 ? s[..120] + "..." : s;

    /// <summary>A Windows path as WSL mounts it (/mnt/d/...).</summary>
    private static string LinuxPath(string path) =>
        path.Length > 2 && path[1] == ':' ? $"/mnt/{char.ToLowerInvariant(path[0])}{path[2..].Replace('\\', '/')}" : path;
}
