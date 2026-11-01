using System.IO.Compression;
using System.Text;
using Corvus.Services.Analysis.Dependencies;

namespace Corvus.Tests;

/// <summary>The advisory check of view=dependencies, matched in process against a folder of OSV records built by each test.</summary>
[Collection(ProcessEnvironmentCollection.Name)]
public sealed class OsvAdvisoriesTests
{
    private static DependencyComponent Nuget(string name, string? version) =>
        new($"pkg:nuget/{name}@{version}", name, version, "nuget", "library", version == null ? null : $"pkg:nuget/{name}@{version}", 1.0, "manifest-analysis", "deps.json");

    private static DependencyComponent Pypi(string name, string version) =>
        new($"pkg:pypi/{name}@{version}", name, version, "pypi", "library", $"pkg:pypi/{name}@{version}", 1.0, "manifest-analysis", "frozen requirements");

    private static string Record(string id, string ecosystem, string name, string events, string aliases = "", string extra = "") =>
        $$"""{"id":"{{id}}","aliases":[{{aliases}}],"summary":"summary of {{id}}",{{extra}}"affected":[{"package":{"ecosystem":"{{ecosystem}}","name":"{{name}}"},"ranges":[{"type":"ECOSYSTEM","events":[{{events}}]}]}]}""";

    private const string Range = """{"introduced":"0"},{"fixed":"13.0.1"}""";

    private const string HighVector = "\"severity\":[{\"type\":\"CVSS_V3\",\"score\":\"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H\"}],";

    private static void WriteZip(string root, string ecosystem, params string[] records)
    {
        Directory.CreateDirectory(Path.Combine(root, ecosystem));
        File.Delete(Path.Combine(root, ecosystem, "all.zip"));
        using var archive = ZipFile.Open(Path.Combine(root, ecosystem, "all.zip"), ZipArchiveMode.Create);
        for (int i = 0; i < records.Length; i++)
        {
            using var w = archive.CreateEntry($"record-{i}.json").Open();
            w.Write(Encoding.UTF8.GetBytes(records[i]));
        }
    }

    [Fact]
    public void Advisories_are_not_checked_when_no_database_folder_is_named()
    {
        using var env = new EnvironmentScope().Set(OsvAdvisories.DatabaseVariable, null);
        var a = OsvAdvisories.Check([Nuget("Newtonsoft.Json", "12.0.2")], default);
        Assert.Equal(("not checked", 0, 1), (a.State, a.Checked, a.NotChecked));
        Assert.Contains(OsvAdvisories.DatabaseVariable, a.Note);
    }

    [Fact]
    public void An_advisory_names_its_component_aliases_severity_and_fix()
    {
        using var dir = new TempDir();
        WriteZip(dir.Path, "NuGet", Record("GHSA-5crp-9r3c-p9vr", "NuGet", "Newtonsoft.Json", Range, "\"CVE-2024-21907\"", HighVector));
        using var env = new EnvironmentScope().Set(OsvAdvisories.DatabaseVariable, dir.Path);
        var a = OsvAdvisories.Check([Nuget("newtonsoft.json", "12.0.2"), Nuget("NLog", "6.1.4"), Nuget("Helper", null)], default);
        Assert.Equal(("partial", 2, 1), (a.State, a.Checked, a.NotChecked));
        var f = Assert.Single(a.Findings);
        Assert.Equal(("pkg:nuget/newtonsoft.json@12.0.2", "GHSA-5crp-9r3c-p9vr", "7.5"), (f.Component, f.Id, f.Severity));
        Assert.Equal(["CVE-2024-21907"], f.Aliases);
        Assert.Equal(["13.0.1"], f.Fixed);
        Assert.Equal("1 components without a package URL or a version, or in an ecosystem OSV does not cover, were not checked", a.Note);
    }

    [Fact]
    public void A_version_at_or_past_the_fix_is_checked_with_no_findings()
    {
        using var dir = new TempDir();
        WriteZip(dir.Path, "NuGet", Record("GHSA-a", "NuGet", "Newtonsoft.Json", Range));
        using var env = new EnvironmentScope().Set(OsvAdvisories.DatabaseVariable, dir.Path);
        var a = OsvAdvisories.Check([Nuget("Newtonsoft.Json", "13.0.1"), Nuget("Newtonsoft.Json", "13.0.3-beta1")], default);
        Assert.Equal(("checked", 2), (a.State, a.Checked));
        Assert.Empty(a.Findings);
    }

    [Fact]
    public void One_advisory_published_under_two_ids_is_reported_once()
    {
        using var dir = new TempDir();
        WriteZip(dir.Path, "NuGet", Record("GHSA-a", "NuGet", "Pkg", Range, "\"CVE-1\""), Record("CVE-1", "NuGet", "Pkg", Range, "\"GHSA-a\""));
        using var env = new EnvironmentScope().Set(OsvAdvisories.DatabaseVariable, dir.Path);
        var a = OsvAdvisories.Check([Nuget("Pkg", "1.0.0")], default);
        Assert.Equal("GHSA-a", Assert.Single(a.Findings).Id);
    }

    [Fact]
    public void A_withdrawn_record_is_not_reported()
    {
        using var dir = new TempDir();
        WriteZip(dir.Path, "NuGet", Record("GHSA-w", "NuGet", "Pkg", Range, extra: "\"withdrawn\":\"2024-01-01T00:00:00Z\","));
        using var env = new EnvironmentScope().Set(OsvAdvisories.DatabaseVariable, dir.Path);
        Assert.Empty(OsvAdvisories.Check([Nuget("Pkg", "1.0.0")], default).Findings);
    }

    [Fact]
    public void A_database_laid_out_as_record_files_is_read_like_an_archive()
    {
        using var dir = new TempDir();
        Directory.CreateDirectory(Path.Combine(dir.Path, "PyPI"));
        File.WriteAllText(Path.Combine(dir.Path, "PyPI", "PYSEC-1.json"), Record("PYSEC-1", "PyPI", "Foo.Bar", """{"introduced":"1.0"},{"fixed":"1.4.0rc1"}"""));
        using var env = new EnvironmentScope().Set(OsvAdvisories.DatabaseVariable, dir.Path);
        Assert.Equal("PYSEC-1", Assert.Single(OsvAdvisories.Check([Pypi("foo-bar", "1.3.9")], default).Findings).Id);
        Assert.Empty(OsvAdvisories.Check([Pypi("foo-bar", "1.4.0")], default).Findings);
    }

    [Fact]
    public void A_missing_ecosystem_database_leaves_its_components_partial_and_named()
    {
        using var dir = new TempDir();
        WriteZip(dir.Path, "NuGet", Record("GHSA-a", "NuGet", "Pkg", Range));
        using var env = new EnvironmentScope().Set(OsvAdvisories.DatabaseVariable, dir.Path);
        var a = OsvAdvisories.Check([Nuget("Pkg", "1.0.0"), Pypi("foo", "1.0")], default);
        Assert.Equal(("partial", 1, 1), (a.State, a.Checked, a.NotChecked));
        Assert.Contains("1 PyPI components not checked: no PyPI database", a.Note);
        Assert.Single(a.Findings);
    }

    [Fact]
    public void A_version_that_cannot_be_ordered_is_reported_unknown_not_absent()
    {
        using var dir = new TempDir();
        WriteZip(dir.Path, "NuGet", Record("GHSA-a", "NuGet", "Pkg", Range));
        using var env = new EnvironmentScope().Set(OsvAdvisories.DatabaseVariable, dir.Path);
        var a = OsvAdvisories.Check([Nuget("Pkg", "not-a-version")], default);
        Assert.Equal("not checked", a.State);
        Assert.Contains("1 NuGet components not checked: a version could not be ordered", a.Note);
    }

    [Fact]
    public void An_unreadable_archive_and_an_unreadable_record_are_counted()
    {
        using var dir = new TempDir();
        Directory.CreateDirectory(Path.Combine(dir.Path, "NuGet"));
        File.WriteAllText(Path.Combine(dir.Path, "NuGet", "all.zip"), "not a zip");
        using var env = new EnvironmentScope().Set(OsvAdvisories.DatabaseVariable, dir.Path);
        Assert.Contains("the NuGet database could not be read", OsvAdvisories.Check([Nuget("Pkg", "1.0.0")], default).Note);

        WriteZip(dir.Path, "NuGet", "{broken", Record("GHSA-a", "NuGet", "Pkg", Range));
        var a = OsvAdvisories.Check([Nuget("Pkg", "1.0.0")], default);
        Assert.Equal(("partial", 1), (a.State, a.Findings.Count));
        Assert.Contains("1 of 2 NuGet records not read", a.Note);
    }

    [Fact]
    public void Only_the_fixes_above_the_installed_version_are_named()
    {
        using var dir = new TempDir();
        const string json = """{"id":"GHSA-r","affected":[{"package":{"ecosystem":"NuGet","name":"Pkg"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"fixed":"1.5"},{"introduced":"2.0"},{"fixed":"2.5"}]}]}]}""";
        WriteZip(dir.Path, "NuGet", json);
        using var env = new EnvironmentScope().Set(OsvAdvisories.DatabaseVariable, dir.Path);
        var a = OsvAdvisories.Check([Nuget("Pkg", "2.2.0")], default);
        Assert.Equal(["2.5"], Assert.Single(a.Findings).Fixed);
    }

    [Fact]
    public void An_unorderable_listed_version_is_reported_unknown()
    {
        using var dir = new TempDir();
        const string json = """{"id":"GHSA-v","affected":[{"package":{"ecosystem":"NuGet","name":"Pkg"},"versions":["1.0.0"]}]}""";
        WriteZip(dir.Path, "NuGet", json);
        using var env = new EnvironmentScope().Set(OsvAdvisories.DatabaseVariable, dir.Path);
        var a = OsvAdvisories.Check([Nuget("Pkg", "not-a-version")], default);
        Assert.Contains("a version could not be ordered", a.Note);
    }

    [Fact]
    public void A_corrupt_archive_entry_is_counted_and_the_others_are_kept()
    {
        using var dir = new TempDir();
        WriteZip(dir.Path, "NuGet", Record("GHSA-a", "NuGet", "Pkg", Range), "{\"id\":\"GHSA-b\"}");
        var zip = Path.Combine(dir.Path, "NuGet", "all.zip");
        var bytes = File.ReadAllBytes(zip);
        // Flips the last data byte of the second entry, before the central directory.
        var central = Encoding.Latin1.GetString(bytes).IndexOf("PK", StringComparison.Ordinal);
        bytes[central - 1] ^= 0xFF;
        File.WriteAllBytes(zip, bytes);
        using var env = new EnvironmentScope().Set(OsvAdvisories.DatabaseVariable, dir.Path);
        var a = OsvAdvisories.Check([Nuget("Pkg", "1.0.0")], default);
        Assert.Equal("GHSA-a", Assert.Single(a.Findings).Id);
        Assert.Equal("partial", a.State);
    }

    [Fact]
    public void A_cancelled_check_stops()
    {
        using var dir = new TempDir();
        WriteZip(dir.Path, "NuGet", Record("GHSA-a", "NuGet", "Pkg", Range));
        using var env = new EnvironmentScope().Set(OsvAdvisories.DatabaseVariable, dir.Path);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.Throws<OperationCanceledException>(() => OsvAdvisories.Check([Nuget("Pkg", "1.0.0")], cts.Token));
    }

    [Fact]
    public void A_database_folder_that_does_not_exist_is_named_and_nothing_is_checked()
    {
        using var dir = new TempDir();
        using var env = new EnvironmentScope().Set(OsvAdvisories.DatabaseVariable, Path.Combine(dir.Path, "absent"));
        var a = OsvAdvisories.Check([Nuget("Pkg", "1.0.0")], default);
        Assert.Equal(("not checked", 0, 1), (a.State, a.Checked, a.NotChecked));
        Assert.Contains("names a folder that does not exist", a.Note);
    }

    [Fact]
    public void An_archive_with_no_records_checks_the_component_with_no_findings()
    {
        using var dir = new TempDir();
        WriteZip(dir.Path, "NuGet");
        using var env = new EnvironmentScope().Set(OsvAdvisories.DatabaseVariable, dir.Path);
        var a = OsvAdvisories.Check([Nuget("Pkg", "1.0.0")], default);
        Assert.Equal(("checked", 1), (a.State, a.Checked));
        Assert.Empty(a.Findings);
    }

    [Fact]
    public void A_rewritten_archive_is_read_again()
    {
        using var dir = new TempDir();
        WriteZip(dir.Path, "NuGet", Record("GHSA-a", "NuGet", "Pkg", Range));
        using var env = new EnvironmentScope().Set(OsvAdvisories.DatabaseVariable, dir.Path);
        Assert.Single(OsvAdvisories.Check([Nuget("Pkg", "1.0.0")], default).Findings);
        WriteZip(dir.Path, "NuGet", Record("GHSA-a", "NuGet", "Pkg", """{"introduced":"0"},{"fixed":"0.5"}"""));
        Assert.Empty(OsvAdvisories.Check([Nuget("Pkg", "1.0.0")], default).Findings);
    }

    [Theory]
    [InlineData("NuGet", "1.0", "1.0.0.0", 0)]
    [InlineData("NuGet", "1.0.0-BETA", "1.0.0-beta", 0)]
    [InlineData("NuGet", "1.0.0-beta.2", "1.0.0-beta.11", -1)]
    [InlineData("NuGet", "1.0.0-rc1", "1.0.0", -1)]
    [InlineData("NuGet", "1.2.3.4", "1.2.3.5", -1)]
    [InlineData("crates.io", "1.0.0-alpha.1", "1.0.0-alpha.beta", -1)]
    [InlineData("crates.io", "1.0.0+build5", "1.0.0", 0)]
    [InlineData("Go", "v1.10.0", "v1.9.9", 1)]
    [InlineData("Go", "go1.22.3", "1.22.3", 0)]
    [InlineData("PyPI", "1.0", "1.0.0", 0)]
    [InlineData("PyPI", "1.0rc1", "1.0", -1)]
    [InlineData("PyPI", "1.0.dev1", "1.0a1", -1)]
    [InlineData("PyPI", "1.0.post1", "1.0", 1)]
    [InlineData("PyPI", "1!0.5", "2.0", 1)]
    [InlineData("PyPI", "1.0+local", "1.0", 1)]
    [InlineData("Maven", "1.0", "1", 0)]
    [InlineData("Maven", "1.0-alpha-1", "1.0-beta-1", -1)]
    [InlineData("Maven", "1.0-rc1", "1.0", -1)]
    [InlineData("Maven", "1.0-sp1", "1.0", 1)]
    [InlineData("Maven", "1.10", "1.9", 1)]
    [InlineData("Maven", "1.0-SNAPSHOT", "1.0", -1)]
    [InlineData("NuGet", "1.0.99999999999999999999999", "1.0.100000000000000000000000", -1)]
    [InlineData("PyPI", "1.0a1", "1.0alpha1", 0)]
    [InlineData("PyPI", "1.0.0.0.0", "1", 0)]
    [InlineData("Go", "v1.0.0-rc.1", "v1.0.0", -1)]
    [InlineData("Go", "v1.0.0+incompatible", "v1.0.0", 0)]
    public void Versions_order_as_their_ecosystem_orders_them(string ecosystem, string a, string b, int expected)
    {
        Assert.Equal(expected, VersionOrder.Compare(ecosystem, a, b));
        Assert.Equal(-expected, VersionOrder.Compare(ecosystem, b, a));
    }

    [Theory]
    [InlineData("NuGet", "1.2.3.4.5")]
    [InlineData("crates.io", "1.x")]
    [InlineData("PyPI", "not a version")]
    [InlineData("Maven", "")]
    public void A_string_outside_the_grammar_has_no_order(string ecosystem, string version) =>
        Assert.Null(VersionOrder.Compare(ecosystem, version, "1.0"));

    [Fact]
    public void An_ecosystem_without_an_ordering_has_none()
    {
        Assert.Null(VersionOrder.Compare("Debian", "1", "2"));
        Assert.Null(VersionOrder.Osv("npm"));
    }

    [Fact]
    public void A_record_matches_explicit_versions_and_each_introduced_range_and_ignores_git_ranges()
    {
        var record = OsvRecord.Parse(Encoding.UTF8.GetBytes("""
            {"id":"X-1","affected":[{"package":{"ecosystem":"Go","name":"example.org/m"},"versions":["1.2.3"],
              "ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"2.5.0"},{"introduced":"3.0.0"},{"last_affected":"3.1.0"}]},
                        {"type":"GIT","events":[{"introduced":"0"}]}]}]}
            """))!;
        bool? At(string v) => record.Affects("Go", "example.org/m", v, out _);
        Assert.Equal([true, false, true, false, true, false], new[] { At("1.2.3"), At("1.9.0"), At("2.4.9"), At("2.5.0"), At("3.1.0"), At("3.1.1") });
        Assert.False(record.Affects("Go", "other", "2.4.9", out _));
        Assert.Null(At("junk"));
    }

    [Fact]
    public void A_cvss_3_vector_scores_as_the_specification_does()
    {
        Assert.Equal(9.8, OsvRecord.Cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"));
        Assert.Equal(10.0, OsvRecord.Cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"));
        Assert.Equal(6.1, OsvRecord.Cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"));
        Assert.Null(OsvRecord.Cvss3("CVSS:3.1/AV:N"));
        Assert.Null(OsvRecord.Cvss3("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"));
    }

    [Fact]
    [FuzzEntry(typeof(OsvRecord))]
    public void Fuzzed_osv_records_never_throw_unexpectedly()
    {
        var seed = Encoding.UTF8.GetBytes(Record("GHSA-a", "NuGet", "Pkg", Range, "\"CVE-1\"", HighVector));
        var failures = FormatFuzz.Run(seed, b => OsvRecord.Parse(b)?.Affects("NuGet", "Pkg", "1.0.0", out _), 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
