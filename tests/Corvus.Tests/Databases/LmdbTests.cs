using Corvus.Core;
using Corvus.Core.Databases;
using Corvus.Native.Providers;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>ledger.mdb built by build.py with liblmdb 0.9.24: a main database, three named ones and a last transaction over them.</summary>
public sealed class LmdbTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Databases", "LmdbFixtures", name);

    private static LmdbFileView.Facts View(string? table = null, long offset = 0, int? limit = null, string view = "lmdb")
    {
        var f = FileInput.Open(Fixture("ledger.mdb"));
        f.Options = new FileViewOptions(view, table, Offset: offset, Limit: limit);
        return (LmdbFileView.Facts)new LmdbFileView().Inspect(f, default)!.Detail;
    }

    [Fact]
    public void The_live_commit_names_its_databases_and_pages_the_main_one()
    {
        var v = View(limit: 3);
        Assert.Equal((4096, 6L, (long?)5), (v.PageSize, v.Transaction, v.PreviousTransaction));
        Assert.Equal(["(main)  194", "fixed duplicate values, fixed-size duplicates 50", "journal  301", "tags duplicate values 403"], v.Databases.Select(d => $"{d.Name} {d.Flags} {d.Entries}"));
        Assert.Equal(new LmdbFileView.Entry("account/0001", "owner=holder1; balance=0.00; closed"), v.Records[0]);
        Assert.Equal(3, v.Next);
        var statement = View(offset: 190, limit: 5).Records;
        Assert.Equal("statement/2026", statement.Single().Key);
        Assert.EndsWith("... (10,000 bytes)", statement[0].Value);
    }

    [Fact]
    public void Duplicate_values_read_from_sub_pages_sub_databases_and_fixed_size_pages()
    {
        var tags = View("tags", limit: 1000).Records;
        Assert.Equal(403, tags.Count);
        Assert.Equal(["blue", "green", "red"], tags.Where(e => e.Key == "small").Select(e => e.Value));
        Assert.Equal("value-0399", tags.Last(e => e.Key == "large").Value);
        var ids = View("fixed", limit: 100).Records;
        Assert.Equal(50, ids.Count);
        Assert.Equal("hex:0000000000000031", ids[^1].Value);
    }

    [Fact]
    public void Records_of_freed_pages_no_commit_reaches_are_recovered()
    {
        var recovered = View().Recovered!;
        Assert.Contains(new LmdbFileView.Entry("account/0001", "owner=holder1; balance=37.01", "(unknown)", "unreachable page 2"), recovered);
        Assert.Contains(recovered, e => e is { Key: "account/0200", Value: "owner=holder200; balance=400.00", Database: "(unknown)" } && e.Source!.StartsWith("unreachable page ", StringComparison.Ordinal));
        // The previous commit differs from the live one by a journal record it lacks, so it adds nothing.
        Assert.DoesNotContain(recovered, e => e.Source!.StartsWith("previous", StringComparison.Ordinal));
        Assert.DoesNotContain(recovered, e => e.Key == "account/0021");
        Assert.Null(View(view: "overview").Recovered);
    }

    [Fact]
    public void An_unknown_database_name_is_refused_with_the_names()
    {
        var e = Assert.Throws<ToolError>(() => View("ledger"));
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
        Assert.Contains("fixed, journal, tags", e.Message);
    }

    [Fact]
    [FuzzEntry(typeof(LmdbFileView), typeof(Lmdb))]
    public void Fuzzed_environments_never_throw_past_a_tool_error()
    {
        var path = _dir.File("data.mdb");
        var failures = FormatFuzz.Run(File.ReadAllBytes(Fixture("ledger.mdb")), b =>
        {
            File.WriteAllBytes(path, b);
            foreach (var table in new string?[] { null, "tags", "fixed" })
                try { new LmdbFileView().Inspect(new FileInput(path, b, Blob.Identify(b)) { Options = new FileViewOptions("lmdb", table) }, default); }
                catch (ToolError) { }
        }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    // The fixture and each *.mdb file under CORVUS_LMDB_FILES are read by mdb_dump through reference.py, run by
    // CORVUS_FS_REFERENCE (python3 on Linux, wsl.exe on Windows). Compared: the named databases and every record.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_FS_REFERENCE")]
    public void Databases_and_records_equal_what_mdb_dump_reads()
    {
        string runner = RealData.Path("CORVUS_FS_REFERENCE");
        var files = new List<string> { Fixture("ledger.mdb") };
        if (Environment.GetEnvironmentVariable("CORVUS_LMDB_FILES") is { Length: > 0 } dir)
            files.AddRange(Directory.EnumerateFiles(dir, "*.mdb", SearchOption.AllDirectories).Where(f => !f.EndsWith("lock.mdb", StringComparison.Ordinal)).Order(StringComparer.Ordinal));
        bool wsl = Path.GetFileNameWithoutExtension(runner).Equals("wsl", StringComparison.OrdinalIgnoreCase);
        var problems = new List<string>();
        int environments = 0, records = 0;
        foreach (var file in files)
        {
            List<string> args = wsl ? ["-e", "python3", LinuxPath(Fixture("reference.py")), LinuxPath(file)] : [Fixture("reference.py"), file];
            var run = ExternalTools.Run(runner, args, TimeSpan.FromMinutes(10), 1 << 30, default);
            string name = Path.GetFileName(Path.GetDirectoryName(file)) + "/" + Path.GetFileName(file);
            if (run.ExitCode != 0) { problems.Add($"{name}: reference exit {run.ExitCode}: {run.Stderr}"); continue; }
            var expected = new List<string>();
            var expectedNames = new List<string>();
            foreach (var line in run.Text.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var f = line.Split('\t');
                if (f[0] == "D") expectedNames.Add(f[1]);
                else if (f[0] == "R") expected.Add($"{f[1]} {f[2]} {f[3]}");
            }
            using var env = new Lmdb(File.OpenRead(file));
            var named = env.Named(env.Current, null, default);
            var actual = new List<string>();
            foreach (var db in named.Prepend(env.Current.Main))
                actual.AddRange(env.Records(db, null, default).Select(r => $"{r.Database} {Convert.ToHexStringLower(r.Key)} {Convert.ToHexStringLower(r.Value)}"));
            if (!expectedNames.Order(StringComparer.Ordinal).SequenceEqual(named.Select(d => d.Name).Order(StringComparer.Ordinal)))
                problems.Add($"{name}: databases mdb_dump [{string.Join(", ", expectedNames)}], Corvus [{string.Join(", ", named.Select(d => d.Name))}]");
            if (!expected.Order(StringComparer.Ordinal).SequenceEqual(actual.Order(StringComparer.Ordinal)))
                problems.Add($"{name}: records differ: mdb_dump {expected.Count}, Corvus {actual.Count}; first: {expected.Except(actual).Concat(actual.Except(expected)).FirstOrDefault()}");
            if (env.Notes.Count > 0) problems.Add($"{name}: notes on an intact file: {env.Notes[0]}");
            var reached = new HashSet<long>();
            var live = new HashSet<string>(StringComparer.Ordinal);
            env.Named(env.Current, reached, default);
            foreach (var db in named.Prepend(env.Current.Main)) foreach (var r in env.Records(db, reached, default)) live.Add(Lmdb.Id(r));
            var recovered = env.Recover(live, reached, int.MaxValue, default);
            output.WriteLine($"{name}: recovered " + string.Join(", ", recovered.GroupBy(r => r.Source.Split(' ')[0]).Select(g => $"{g.Count()} from {g.Key}")));
            environments++;
            records += expected.Count;
        }
        output.WriteLine($"{environments} environments: {records} records equal to mdb_dump");
        foreach (var p in problems.Take(40)) output.WriteLine(p);
        Assert.Empty(problems);
    }

    /// <summary>A Windows path as WSL mounts it (/mnt/d/...).</summary>
    private static string LinuxPath(string path) =>
        path.Length > 2 && path[1] == ':' ? $"/mnt/{char.ToLowerInvariant(path[0])}{path[2..].Replace('\\', '/')}" : path;
}
