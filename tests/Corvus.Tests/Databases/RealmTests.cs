using System.Globalization;
using System.Text;
using Corvus.Core;
using Corvus.Core.Databases;
using Corvus.Native.Providers;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// ledger.realm, built by build.js with the realm package 12.14.2 (Realm Core 14, file format 24): Holder, Account (every
/// column type) and Journal classes in two commits; the second changes accounts 1 to 20 and deletes 191 to 200.
/// </summary>
public sealed class RealmTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Databases", "RealmFixtures", name);

    private static RealmFileView.Facts View(string? table = null, long offset = 0, int? limit = null, string view = "realm")
    {
        var f = FileInput.Open(Fixture("ledger.realm"));
        f.Options = new FileViewOptions(view, table, Offset: offset, Limit: limit);
        return (RealmFileView.Facts)new RealmFileView().Inspect(f, default)!.Detail;
    }

    private static List<Realm.Obj> Objects(string table)
    {
        using var realm = new Realm(File.OpenRead(Fixture("ledger.realm")));
        return [.. realm.Objects(realm.Tables.Single(t => t.Name == "class_" + table), default)];
    }

    [Fact]
    public void The_tables_columns_and_a_page_of_objects_read()
    {
        var v = View(limit: 2);
        Assert.Equal(24, v.FileFormat);
        Assert.Equal(["metadata 1", "Account 190", "Holder 50", "Journal 300"], v.Tables.Select(t => $"{t.Name} {t.Objects}"));
        Assert.Equal(["id int", "owner Holder?", "balance double", "opened date?", "active bool", "tags string[]", "note string?", "photo data?", "code uuid", "ref objectId", "total decimal128"],
            v.Tables[1].Columns.Select(c => $"{c.Name} {c.Type}"));
        Assert.Equal("Account", v.Table);
        Assert.Equal(["0 1, Holder#1, 0, 2026-01-02T00:00:00Z, false, [region-1], note 1, null, 00000001-0000-4000-8000-00000000001f, 000000000000000000000001, 1.25",
            "1 2, Holder#2, 0, 2026-01-03T00:00:00Z, false, [retail, region-2], note 2, null, 00000002-0000-4000-8000-00000000003e, 000000000000000000000002, 2.25"],
            v.Objects.Select(o => $"{o.Key} {string.Join(", ", o.Values)}"));
        Assert.Equal(2, v.Next);
        var journal = View("Journal", offset: 298);
        Assert.Equal(["65578 299, transfer 387.00 from holder50, 74.75", "65579 300, transfer 400.00 from holder1, 75"], journal.Objects.Select(o => $"{o.Key} {string.Join(", ", o.Values)}"));
        Assert.Null(journal.Next);
    }

    [Fact]
    public void Each_column_type_reads_its_values()
    {
        var accounts = Objects("Account");
        Assert.Equal(Enumerable.Range(1, 190).Select(i => (long)i), accounts.Select(o => (long)o.Values[0]!));
        var a = accounts.Single(o => (long)o.Values[0]! == 50).Values;
        Assert.Equal(new Realm.Link("class_Holder", 0), a[1]);
        Assert.Equal(850.5, a[2]);
        Assert.Equal(new Realm.Timestamp(1767225600 + 50 * 86400, 0), a[3]);
        Assert.Equal(true, a[4]);
        Assert.Equal(["retail", "region-0", "audited"], ((Realm.Collection)a[5]!).Items.Cast<string>());
        // A 4,000-character string and a 3,000-byte value are stored in blobs of their own.
        Assert.Equal(string.Concat(Enumerable.Repeat("note for account 50; ", 300))[..4000], a[6]);
        Assert.Equal(Enumerable.Range(0, 3000).Select(k => (byte)((k * 7 + 50) % 256)), (byte[])a[7]!);
        Assert.Equal("00000032-0000-4000-8000-00000000060e", Realm.Text(a[8]));
        Assert.Equal("000000000000000000000032", Realm.Text(a[9]));
        Assert.Equal(new Realm.Decimal("50.25"), a[10]);
        Assert.Null(accounts.Single(o => (long)o.Values[0]! == 49).Values[3]);
        Assert.Null(accounts.Single(o => (long)o.Values[0]! == 48).Values[6]);
        var holders = Objects("Holder");
        Assert.Equal(["holder1", "holder50"], new[] { holders[0], holders[^1] }.Select(o => (string)o.Values[0]!));
        // 300 objects span two cluster leaves under an inner node; the second leaf's keys start at 65536.
        var journal = Objects("Journal");
        Assert.Equal(Enumerable.Range(0, 256).Concat(Enumerable.Range(65536, 44)).Select(i => (long?)i), journal.Select(o => o.Key));
        Assert.Equal(0.25f, journal[0].Values[2]);
    }

    [Fact]
    public void Deleted_and_changed_objects_are_recovered_from_the_previous_commit()
    {
        var recovered = View().Recovered!;
        var deleted = recovered.Where(r => r.Source == "previous commit: deleted since").ToList();
        Assert.Equal(Enumerable.Range(191, 10).Select(i => i.ToString(CultureInfo.InvariantCulture)), deleted.Select(r => r.Values[0]));
        Assert.All(deleted, r => Assert.Equal("Account", r.Table));
        var changed = recovered.Where(r => r.Source == "previous commit: changed since").ToList();
        Assert.Equal(Enumerable.Range(1, 20).Select(i => i.ToString(CultureInfo.InvariantCulture)), changed.Select(r => r.Values[0]));
        // The previous commit keeps the balances and flags the second one overwrote.
        Assert.All(changed, r =>
        {
            int i = int.Parse(r.Values[0], CultureInfo.InvariantCulture);
            Assert.Equal(((i * 37 % 1000) + i % 100 / 100.0).ToString("R", CultureInfo.InvariantCulture), r.Values[2]);
            Assert.Equal(i % 3 != 0 ? "true" : "false", r.Values[4]);
        });
        Assert.Equal(30, recovered.Count);
        Assert.Null(View(view: "overview").Recovered);
    }

    [Fact]
    public void An_unknown_table_name_is_refused_with_the_names()
    {
        var e = Assert.Throws<ToolError>(() => View("Ledger"));
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
        Assert.Contains("metadata, Account, Holder, Journal", e.Message);
    }

    [Fact]
    [FuzzEntry(typeof(RealmFileView), typeof(Realm))]
    public void Fuzzed_files_never_throw_past_a_tool_error()
    {
        var path = _dir.File("ledger.realm");
        var seed = File.ReadAllBytes(Fixture("ledger.realm"));
        var failures = FormatFuzz.Run(seed, b =>
        {
            File.WriteAllBytes(path, b);
            foreach (var table in new string?[] { null, "Journal" })
                try { new RealmFileView().Inspect(new FileInput(path, b, Blob.Identify(b)) { Options = new FileViewOptions("realm", table) }, default); }
                catch (ToolError) { }
        }, 150);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    // The fixture and each Realm file under CORVUS_REALM_FILES are read by the realm package through reference.js, run
    // by node from PATH with CORVUS_REALM_REFERENCE (the folder holding node_modules/realm) as NODE_PATH, each on a copy. Compared:
    // the classes, their object counts, and every object's key and values.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_REALM_REFERENCE")]
    public void Classes_and_objects_equal_what_the_realm_package_reads()
    {
        string modules = Path.Combine(RealData.Path("CORVUS_REALM_REFERENCE"), "node_modules");
        string node = Environment.GetEnvironmentVariable("PATH")!.Split(Path.PathSeparator)
            .Select(d => Path.Combine(d, OperatingSystem.IsWindows() ? "node.exe" : "node")).FirstOrDefault(File.Exists) ?? throw new InvalidOperationException("node is not on PATH");
        var files = new List<string> { Fixture("ledger.realm") };
        if (Environment.GetEnvironmentVariable("CORVUS_REALM_FILES") is { Length: > 0 } dir)
            files.AddRange(Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).Where(f => Realm.Looks(Head(f))).Order(StringComparer.Ordinal));
        var problems = new List<string>();
        int checkedFiles = 0, objects = 0;
        foreach (var file in files)
        {
            string name = Path.GetFileName(file), copy = Path.Combine(_dir.Path, $"{checkedFiles}-{name}");
            File.Copy(file, copy);
            var run = ExternalTools.Run(node, [Fixture("reference.js"), copy], TimeSpan.FromMinutes(10), 1 << 30, default, new Dictionary<string, string?> { ["NODE_PATH"] = modules });
            if (run.ExitCode != 0) { problems.Add($"{name}: reference exit {run.ExitCode}: {run.Stderr}"); continue; }
            var expected = run.Text.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
            var actual = new List<string>();
            using (var realm = new Realm(File.OpenRead(file)))
                foreach (var t in realm.Tables.Where(t => t.Name.StartsWith("class_", StringComparison.Ordinal)).OrderBy(t => t.Name, StringComparer.Ordinal))
                {
                    string cls = t.Name[6..];
                    if (t.Embedded) { actual.Add($"T\t{cls}\tembedded"); continue; }
                    var all = realm.Objects(t, default).ToList();
                    actual.Add($"T\t{cls}\t{all.Count}");
                    var columns = t.Columns.Where(c => c.Type != 14).Select((c, i) => (c, i)).OrderBy(p => p.c.Name, StringComparer.Ordinal).ToList();
                    foreach (var o in all)
                        actual.Add($"R\t{cls}\t{o.Key}\t" + string.Join("\t", columns.Select(p => p.c.Name + "=" + Canonical(o.Values[p.i], p.c.Type == 6))));
                }
            int at = 0;
            while (at < expected.Count && at < actual.Count && expected[at] == actual[at]) at++;
            if (at < expected.Count || at < actual.Count)
                problems.Add($"{name}: line {at + 1} of {expected.Count} (realm) and {actual.Count} (Corvus): realm {Clip(at < expected.Count ? expected[at] : "(end)")}, Corvus {Clip(at < actual.Count ? actual[at] : "(end)")}");
            objects += actual.Count(l => l[0] == 'R');
            checkedFiles++;
        }
        output.WriteLine($"{checkedFiles} files: {objects} objects equal to the realm package");
        foreach (var p in problems.Take(40)) output.WriteLine(p);
        Assert.Empty(problems);
    }

    // A value in reference.js form; integers in a mixed column print as doubles, as JavaScript reads them.
    private static string Canonical(object? v, bool mixed) => v switch
    {
        null => "null",
        bool b => b ? "true" : "false",
        long l when mixed => Canonical((double)l, false),
        long l => l.ToString(CultureInfo.InvariantCulture),
        string s => "s:" + Convert.ToHexStringLower(Encoding.UTF8.GetBytes(s)),
        byte[] bytes => "b:" + Convert.ToHexStringLower(bytes),
        float f => "f:" + BitConverter.DoubleToUInt64Bits(f).ToString("x", CultureInfo.InvariantCulture),
        double d => "f:" + BitConverter.DoubleToUInt64Bits(d).ToString("x", CultureInfo.InvariantCulture),
        Realm.Timestamp t => "d:" + (t.Seconds * 1000 + t.Nanoseconds / 1_000_000).ToString(CultureInfo.InvariantCulture),
        Realm.Id id => (id.Uuid ? "u:" : "o:") + Convert.ToHexStringLower(id.Bytes),
        Realm.Decimal m => "m:" + m.Text,
        Realm.Link k => $"k:{(k.Table is { } t && t.StartsWith("class_", StringComparison.Ordinal) ? t[6..] : k.Table)}#{k.Key}",
        Realm.Collection c => "[" + string.Join(",", c.Items.Select(i => Canonical(i, mixed))) + "]",
        Realm.Map m => "{" + string.Join(",", m.Entries.OrderBy(e => e.Key, StringComparer.Ordinal).Select(e => e.Key + "=" + Canonical(e.Value, mixed))) + "}",
        _ => "?",
    };

    private static byte[] Head(string path)
    {
        using var s = File.OpenRead(path);
        var b = new byte[Math.Min(64, s.Length)];
        s.ReadExactly(b);
        return b;
    }

    private static string Clip(string s) => s.Length > 160 ? s[..160] + "..." : s;
}
