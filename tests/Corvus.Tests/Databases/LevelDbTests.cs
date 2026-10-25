using System.Security.Cryptography;
using Corvus.Core;
using Corvus.Core.Databases;
using Corvus.Native.Providers;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>LevelDB databases built by build.py with libleveldb 1.23: tables at two levels and a live log over them.</summary>
public sealed class LevelDbTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Databases", "LevelDbFixtures", name);

    private static LevelDbFileView.Facts View(string path, long offset = 0, int? limit = null) =>
        (LevelDbFileView.Facts)new LevelDbFileView().Inspect(FileInput.Open(path) is var f ? WithOptions(f, offset, limit) : null!, default)!.Detail;

    private static FileInput WithOptions(FileInput f, long offset, int? limit)
    {
        f.Options = new FileViewOptions("leveldb", Offset: offset, Limit: limit);
        return f;
    }

    [Theory]
    [InlineData("ledger-snappy")]
    [InlineData("ledger-none")]
    public void Live_records_merge_two_levels_and_the_log_by_sequence(string db)
    {
        var v = View(Fixture(Path.Combine(db, "CURRENT")));
        Assert.Equal("leveldb.BytewiseComparator", v.Comparator);
        Assert.Equal((1187, 15, 35, 0), (v.LiveKeys, v.DeletedKeys, v.OlderVersions, v.UnlistedRecords));
        Assert.Equal(["MANIFEST-000002 MANIFEST", "000005.ldb table, level 2", "000006.log log, live", "000007.ldb table, level 1"],
            v.Files.Select(f => $"{f.Name} {f.Role}"));
        Assert.Equal(new LevelDbFileView.Entry("_https://ledger.test\\x00\\x01title", "\\x01Ledger", 1237, "live", "000006.log"), v.Records[0]);
        Assert.Equal(new LevelDbFileView.Entry("account/0001", "owner=holder1; balance=0.00; closed", 201, "live", "000007.ldb"), v.Records[1]);
        Assert.Contains(v.Recovered, e => e == new LevelDbFileView.Entry("account/0001", "owner=holder1; balance=37.01", 1, "older version", "000005.ldb"));
        Assert.Contains(v.Recovered, e => e == new LevelDbFileView.Entry("account/0181", null, 221, "deleted", "000007.ldb"));
        Assert.Contains(v.Recovered, e => e == new LevelDbFileView.Entry("account/0200", null, 1235, "deleted", "000006.log"));
    }

    [Fact]
    public void Records_page_with_offset_and_limit_and_binary_bytes_show_escaped_or_as_hex()
    {
        var v = View(Fixture(Path.Combine("ledger-snappy", "000007.ldb")), offset: 1185, limit: 10);
        Assert.Null(v.Next);
        Assert.Equal(["journal/1000", "meta/\\x00\\x01\\xff"], v.Records.Select(e => e.Key));
        Assert.Equal("hex:000102030405060708090a0b0c0d0e0f", v.Records[1].Value);
        Assert.Equal(500, View(Fixture(Path.Combine("ledger-snappy", "000006.log")), limit: 500).Next);
    }

    [Fact]
    public void A_table_the_MANIFEST_does_not_list_is_read_as_no_longer_live()
    {
        var folder = Directory.CreateDirectory(_dir.File("unlisted")).FullName;
        foreach (var f in Directory.GetFiles(Fixture("ledger-snappy"))) File.Copy(f, Path.Combine(folder, Path.GetFileName(f)));
        File.Copy(Path.Combine(folder, "000005.ldb"), Path.Combine(folder, "000003.ldb"));
        var v = View(Path.Combine(folder, "CURRENT"));
        Assert.Equal((1187, 200), (v.LiveKeys, v.UnlistedRecords));
        Assert.Contains(v.Files, f => f is { Name: "000003.ldb", Role: "table, not in the MANIFEST", Live: false });
    }

    [Fact]
    public void A_folder_without_a_MANIFEST_reads_the_file_given_and_names_the_live_state_partial()
    {
        var folder = Directory.CreateDirectory(_dir.File("alone")).FullName;
        File.Copy(Fixture(Path.Combine("ledger-snappy", "000005.ldb")), Path.Combine(folder, "000005.ldb"));
        var v = View(Path.Combine(folder, "000005.ldb"));
        Assert.Equal(200, v.LiveKeys);
        Assert.Contains("no MANIFEST was read: the live state is that of the files read, which may be partial", v.Notes);
    }

    [Fact]
    public void A_file_outside_a_LevelDB_folder_is_not_viewed()
    {
        var path = _dir.File("notes.log");
        File.WriteAllText(path, "plain text");
        Assert.Null(new LevelDbFileView().Inspect(FileInput.Open(path), default));
    }

    [Fact]
    [FuzzEntry(typeof(LevelDbFileView), typeof(LevelDb), typeof(Snappy))]
    public void Fuzzed_tables_logs_and_manifests_never_throw_past_a_tool_error()
    {
        var folder = Directory.CreateDirectory(_dir.File("fuzz")).FullName;
        foreach (var f in Directory.GetFiles(Fixture("ledger-snappy"))) File.Copy(f, Path.Combine(folder, Path.GetFileName(f)));
        var failures = new List<string>();
        foreach (var name in new[] { "000006.log", "000007.ldb", "MANIFEST-000002" })
        {
            var path = Path.Combine(folder, name);
            var seed = File.ReadAllBytes(path);
            failures.AddRange(FormatFuzz.Run(seed, b =>
            {
                File.WriteAllBytes(path, b);
                try { new LevelDbFileView().Inspect(new FileInput(path, b, Blob.Identify(b)) { Options = new FileViewOptions("leveldb") }, default); }
                catch (ToolError) { }
            }, 200));
            File.WriteAllBytes(path, seed);
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    // The fixtures and each database folder under CORVUS_LEVELDB_DIRS are read by libleveldb through reference.py, run by
    // CORVUS_FS_REFERENCE (python3 on Linux, wsl.exe on Windows) with leveldbutil at CORVUS_LEVELDB_DUMP. Compared: the
    // live records (plyvel) and every record of every table and log (leveldbutil dump) with its sequence and value.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_FS_REFERENCE", "CORVUS_LEVELDB_DUMP")]
    public void Live_and_file_records_equal_what_libleveldb_reads()
    {
        string runner = RealData.Path("CORVUS_FS_REFERENCE"), dump = RealData.Path("CORVUS_LEVELDB_DUMP");
        var folders = new List<string> { Fixture("ledger-snappy"), Fixture("ledger-none") };
        if (Environment.GetEnvironmentVariable("CORVUS_LEVELDB_DIRS") is { Length: > 0 } dir)
            folders.AddRange(Directory.EnumerateFiles(dir, "CURRENT", SearchOption.AllDirectories).Select(Path.GetDirectoryName).Order(StringComparer.Ordinal)!);
        bool wsl = Path.GetFileNameWithoutExtension(runner).Equals("wsl", StringComparison.OrdinalIgnoreCase);
        var problems = new List<string>();
        int databases = 0, live = 0, records = 0;
        foreach (var folder in folders)
        {
            List<string> args = wsl ? ["-e", "python3", LinuxPath(Fixture("reference.py")), LinuxPath(folder), LinuxPath(dump)] : [Fixture("reference.py"), folder, dump];
            var run = ExternalTools.Run(runner, args, TimeSpan.FromMinutes(10), 1 << 28, default);
            string name = Path.GetFileName(folder);
            if (run.ExitCode != 0) { problems.Add($"{name}: reference exit {run.ExitCode}: {run.Stderr}"); continue; }
            var db = LevelDb.Read(folder, null, 1L << 32, default);
            static string Hash(byte[] b) => Convert.ToHexStringLower(SHA256.HashData(b));
            var expectedLive = new List<string>();
            var expectedRecords = new List<string>();
            foreach (var line in run.Text.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var f = line.Split('\t');
                if (f[0] == "L") expectedLive.Add($"{f[1]} {f[2]}");
                else if (f[0] == "R") expectedRecords.Add($"{f[1]} {f[2]} {f[3]} {f[4]} {f[5]}");
            }
            var actualLive = db.Live.Where(r => !r.Deleted).Select(r => $"{Convert.ToHexStringLower(r.Key)} {Hash(r.Value)}").ToList();
            var actualRecords = db.Records.Select(r => $"{r.File} {Convert.ToHexStringLower(r.Key)} {r.Sequence} {(r.Deleted ? "del" : "put")} {(r.Deleted ? "" : Hash(r.Value))}").ToList();
            if (!expectedLive.Order().SequenceEqual(actualLive.Order()))
                problems.Add($"{name}: live records differ: libleveldb {expectedLive.Count}, Corvus {actualLive.Count}; first: {expectedLive.Except(actualLive).Concat(actualLive.Except(expectedLive)).FirstOrDefault()}");
            if (!expectedRecords.Order().SequenceEqual(actualRecords.Order()))
                problems.Add($"{name}: file records differ: leveldbutil {expectedRecords.Count}, Corvus {actualRecords.Count}; first: {expectedRecords.Except(actualRecords).Concat(actualRecords.Except(expectedRecords)).FirstOrDefault()}");
            databases++;
            live += expectedLive.Count;
            records += expectedRecords.Count;
        }
        output.WriteLine($"{databases} databases: {live} live records and {records} file records equal to libleveldb");
        foreach (var p in problems.Take(40)) output.WriteLine(p);
        Assert.Empty(problems);
    }

    /// <summary>A Windows path as WSL mounts it (/mnt/d/...).</summary>
    private static string LinuxPath(string path) =>
        path.Length > 2 && path[1] == ':' ? $"/mnt/{char.ToLowerInvariant(path[0])}{path[2..].Replace('\\', '/')}" : path;
}
