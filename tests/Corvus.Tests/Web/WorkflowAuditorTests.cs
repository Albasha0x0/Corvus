using Corvus.Services.Web.Packages;

namespace Corvus.Tests;

/// <summary>The workflow auditor set in CORVUS_ZIZMOR adds its findings to workflow review; a fake program answers.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class WorkflowAuditorTests : IDisposable
{
    private const string Workflow = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        """;

    private const string Report = """[{"ident":"unpinned-uses","desc":"action is not pinned","determinations":{"severity":"Medium"},"locations":[{"concrete":{"location":{"start_point":{"row":6,"column":8}}}}]}]""";

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private PackageReport Review()
    {
        var root = _dir.File("repo");
        var full = Path.Combine(root, ".github", "workflows", "ci.yml");
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllText(full, Workflow);
        return PackageReview.Review(root, default)!;
    }

    [Fact]
    public void A_configured_auditor_adds_its_findings_with_their_lines()
    {
        using var fake = new FakeTool();
        fake.On("--format json", stdout: Report);
        using var scope = new EnvironmentScope().Set(FakeTool.ScriptVariable, fake.ScriptPath).Set("CORVUS_ZIZMOR", fake.CopyAs("zizmor"));
        var finding = Assert.Single(Review().Findings!, f => f.Rule == "package/workflow-auditor");
        Assert.Equal(7, finding.Line);
        Assert.Equal(".github/workflows/ci.yml", finding.Path);
        Assert.Contains("unpinned-uses", finding.Detail);
    }

    [Fact]
    public void An_auditor_that_exits_non_zero_is_reported_as_a_note()
    {
        using var fake = new FakeTool();
        fake.On("--format json", stderr: "bad", exit: 3);
        using var scope = new EnvironmentScope().Set(FakeTool.ScriptVariable, fake.ScriptPath).Set("CORVUS_ZIZMOR", fake.CopyAs("zizmor"));
        var report = Review();
        Assert.DoesNotContain(report.Findings!, f => f.Rule == "package/workflow-auditor");
        Assert.Contains(report.Notes!, n => n.Contains("workflow auditor") && n.Contains("exit 3"));
    }

    [Fact]
    public void Review_without_the_variable_runs_no_program()
    {
        using var fake = new FakeTool();
        fake.On("--format json", stdout: Report);
        using var scope = new EnvironmentScope().Set(FakeTool.ScriptVariable, fake.ScriptPath).Set("CORVUS_ZIZMOR", null);
        var report = Review();
        Assert.Empty(fake.Calls);
        Assert.DoesNotContain(report.Findings!, f => f.Rule == "package/workflow-auditor");
    }

    [Fact]
    public void The_private_copy_is_deleted_after_the_run()
    {
        using var fake = new FakeTool();
        fake.On("--format json", stdout: Report);
        using var scope = new EnvironmentScope().Set(FakeTool.ScriptVariable, fake.ScriptPath).Set("CORVUS_ZIZMOR", fake.CopyAs("zizmor"));
        Review();
        var args = Assert.Single(fake.Calls).AsArray();
        var copy = (string)args[^1]!;
        Assert.Contains("workflow-audit", copy);
        Assert.False(File.Exists(copy));
    }
}
