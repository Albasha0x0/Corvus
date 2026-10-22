using System.Text.Json;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Dependencies;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>The advisory check of view=dependencies, run through a scripted osv-scanner.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class OsvAdvisoriesTests(ITestOutputHelper output)
{
    private static readonly DependencyComponent[] Components =
    [
        new("pkg:nuget/Newtonsoft.Json@12.0.2", "Newtonsoft.Json", "12.0.2", "nuget", "library", "pkg:nuget/Newtonsoft.Json@12.0.2", 1.0, "manifest-analysis", "deps.json"),
        new("pkg:nuget/NLog@6.1.4", "NLog", "6.1.4", "nuget", "library", "pkg:nuget/NLog@6.1.4", 1.0, "manifest-analysis", "deps.json"),
        new("nuget:Helper", "Helper", null, "nuget", "library", null, 0.5, "binary-analysis", "assembly metadata") { AssemblyVersion = "1.0.0.0" },
    ];

    // The shape of osv-scanner 2.7.0's JSON report for an SBOM: one advisory published as a GHSA and a CVE.
    private const string Report = """
        {"results":[{"source":{"path":"components.cdx.json","type":"sbom"},"packages":[{
          "package":{"name":"Newtonsoft.Json","version":"12.0.2","ecosystem":"NuGet","purl":"pkg:nuget/Newtonsoft.Json@12.0.2"},
          "vulnerabilities":[{"id":"GHSA-5crp-9r3c-p9vr","summary":"Improper Handling of Exceptional Conditions in Newtonsoft.Json","aliases":["CVE-2024-21907"],
            "affected":[{"package":{"ecosystem":"NuGet","name":"Newtonsoft.Json"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"13.0.1"}]}]}]}],
          "groups":[{"ids":["GHSA-5crp-9r3c-p9vr"],"aliases":["CVE-2024-21907","GHSA-5crp-9r3c-p9vr"],"max_severity":"7.5"}]}]}]}
        """;

    private static FakeTool Scanner()
    {
        var fake = new FakeTool();
        fake.On("^--version$", stdout: "osv-scanner version: 2.7.0\nosv-scalibr version: 0.5.3\n");
        return fake;
    }

    [Fact]
    public void Advisories_are_reported_not_checked_when_osv_scanner_is_not_found()
    {
        using var env = new EnvironmentScope().Set("CORVUS_OSV_SCANNER", Path.Combine(Path.GetTempPath(), "no-osv-scanner", "osv-scanner.exe"));
        var a = OsvAdvisories.Check(Components, default);
        Assert.Equal(("not checked", 0, 3), (a.State, a.Checked, a.NotChecked));
        Assert.Empty(a.Findings);
        Assert.Contains("CORVUS_OSV_SCANNER", a.Note);
    }

    [Fact]
    public void An_advisory_osv_scanner_reports_names_its_component_aliases_severity_and_fix()
    {
        using var fake = Scanner();
        fake.On(@"^scan source --offline --format json -L .+components\.cdx\.json$", stdout: Report, exit: 1);
        using var env = new EnvironmentScope().Set("CORVUS_OSV_SCANNER", fake.CopyAs("osv-scanner")).Set(FakeTool.ScriptVariable, fake.ScriptPath);
        var a = OsvAdvisories.Check(Components, default);
        Assert.Equal(("checked", "osv-scanner 2.7.0, offline", 2, 1), (a.State, a.Checker, a.Checked, a.NotChecked));
        var f = Assert.Single(a.Findings);
        Assert.Equal(("pkg:nuget/Newtonsoft.Json@12.0.2", "GHSA-5crp-9r3c-p9vr", "7.5"), (f.Component, f.Id, f.Severity));
        Assert.Equal(["CVE-2024-21907"], f.Aliases);
        Assert.Equal(["13.0.1"], f.Fixed);
        Assert.Equal("1 components without a package URL were not checked", a.Note);
    }

    [Fact]
    public void A_scan_with_no_advisory_is_checked_with_no_findings()
    {
        using var fake = Scanner();
        fake.On("^scan ", stdout: """{"results":[]}""");
        using var env = new EnvironmentScope().Set("CORVUS_OSV_SCANNER", fake.CopyAs("osv-scanner")).Set(FakeTool.ScriptVariable, fake.ScriptPath);
        var a = OsvAdvisories.Check(Components, default);
        Assert.Equal(("checked", 2), (a.State, a.Checked));
        Assert.Empty(a.Findings);
    }

    [Fact]
    public void A_missing_offline_database_leaves_advisories_not_checked_with_the_scanner_message()
    {
        using var fake = Scanner();
        fake.On("^scan ", stdout: """{"results":[]}""", stderr: "could not load db for NuGet ecosystem: unable to fetch OSV database: no offline version of the OSV database is available", exit: 127);
        using var env = new EnvironmentScope().Set("CORVUS_OSV_SCANNER", fake.CopyAs("osv-scanner")).Set(FakeTool.ScriptVariable, fake.ScriptPath);
        var a = OsvAdvisories.Check(Components, default);
        Assert.Equal(("not checked", 0, 3), (a.State, a.Checked, a.NotChecked));
        Assert.Empty(a.Findings);
        Assert.Contains("exit 127: could not load db for NuGet ecosystem", a.Note);
    }

    /// <summary>
    /// A real osv-scanner named by CORVUS_OSV_SCANNER, with its offline databases downloaded: the advisories of a published
    /// app's dependencies view equal the ones osv-scanner reports for the app's own packages.lock.json.
    /// </summary>
    [Fact]
    [Trait("Speed", "Slow")]
    public void A_published_apps_advisories_equal_osv_scanners_for_its_lock_file()
    {
        if (Environment.GetEnvironmentVariable(ExternalTools.OsvScanner.Variable) is not { Length: > 0 }) return;
        using var dir = new TempDir();
        var project = dir.File("App");
        Directory.CreateDirectory(project);
        // Empty build props stop MSBuild from picking up a Directory.Build.props above the temp folder.
        File.WriteAllText(Path.Combine(project, "Directory.Build.props"), "<Project />");
        File.WriteAllText(Path.Combine(project, "Directory.Packages.props"), "<Project />");
        File.WriteAllText(Path.Combine(project, "App.csproj"), """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile></PropertyGroup>
              <ItemGroup>
                <PackageReference Include="NLog" Version="6.1.4" />
                <PackageReference Include="Newtonsoft.Json" Version="12.0.2" />
              </ItemGroup>
            </Project>
            """);
        File.WriteAllText(Path.Combine(project, "Program.cs"),
            """System.Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(NLog.LogManager.GetCurrentClassLogger().Name));""");
        var folder = dir.File("out");
        var (exitCode, log) = Tools.Dotnet(project, ["publish", "-c", "Release", "-r", ContainerFixtures.Rid, "--self-contained", "false", "-o", folder]);
        Assert.True(exitCode == 0, $"dotnet publish failed:\n{log}");

        var probe = ExternalTools.Probe(ExternalTools.OsvScanner);
        Assert.True(probe.Usable, probe.Problem);
        var run = ExternalTools.Run(probe.Path!, ExternalTools.Arguments(ExternalTools.OsvScanner, "scan", ("file", Path.Combine(project, "packages.lock.json"))),
            TimeSpan.FromMinutes(5), 64L << 20, default,
            Environment.GetEnvironmentVariable("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY") is { Length: > 0 } db ? new Dictionary<string, string?> { ["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = db } : null);
        Assert.True(run.ExitCode is 0 or 1, $"osv-scanner on the lock file: exit {run.ExitCode} {run.StartError ?? run.Stderr}");
        using var doc = JsonDocument.Parse(run.Output);
        var theirs = doc.RootElement.GetProperty("results").EnumerateArray().SelectMany(r => r.GetProperty("packages").EnumerateArray())
            .SelectMany(p => p.GetProperty("groups").EnumerateArray().Select(g => $"{p.GetProperty("package").GetProperty("name").GetString()} {g.GetProperty("ids")[0].GetString()}"))
            .Order(StringComparer.Ordinal).ToList();

        using var workspace = new AssemblyWorkspace(new ServerOptions());
        var app = Path.Combine(folder, OperatingSystem.IsWindows() ? "App.exe" : "App");
        var summary = new InspectionService(workspace).Summarize(null, app, default, new FileViewOptions("dependencies"));
        var advisories = Assert.IsType<DependencyFacts>(summary.Views["dependencies"].Detail).Advisories!;
        Assert.True(advisories.State == "checked", advisories.Note);
        var ours = advisories.Findings.Select(f => $"{f.Name} {f.Id}").Order(StringComparer.Ordinal).ToList();
        output.WriteLine($"ours: {string.Join(", ", ours)}; osv-scanner on the lock file: {string.Join(", ", theirs)}");
        Assert.NotEmpty(theirs);
        Assert.Equal(theirs, ours);
    }
}
