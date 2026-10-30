using Corvus.Core;
using Corvus.Services.Analysis;
using Corvus.Services.Web.Packages;

namespace Corvus.Tests;

/// <summary>Workflow files as agent entries and their three rules, on models built from documented workflow syntax.</summary>
public sealed class WorkflowReviewTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private string Repository(string name, params (string Path, string Text)[] files)
    {
        var root = _dir.File(name);
        foreach (var (p, text) in files)
        {
            var full = Path.Combine(root, p);
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllText(full, text);
        }
        return root;
    }

    private PackageReport Review(string name, string workflow) =>
        PackageReview.Review(Repository(name, (".github/workflows/ci.yml", workflow)), default)!;

    private const string Harmless = """
        name: ci
        on:
          push:
            branches: [main]
          pull_request:
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - name: Test
                env:
                  TITLE: ${{ github.event.pull_request.title }}
                run: |
                  echo "$TITLE"
                  echo "${{ github.sha }} ${{ github.event.pull_request.number }} ${{ secrets.TOKEN }}"
                  dotnet test
        """;

    [Fact]
    public void A_workflow_job_is_listed_with_its_trigger_and_what_it_runs()
    {
        var r = Review("listed", Harmless);
        var e = Assert.Single(r.Agents!);
        Assert.Equal(new AgentEntry("workflow job", "ci.yml: build", "on push, pull_request; actions/checkout@v4; run: echo \"$TITLE\"", ".github/workflows/ci.yml", 8), e);
    }

    [Fact]
    public void Harmless_workflows_report_nothing_noteworthy()
    {
        var r = Review("harmless", Harmless);
        Assert.Empty(r.Findings);
        var safe = Review("safe-target", """
            on: [pull_request_target]
            jobs:
              label:
                steps:
                  - uses: actions/checkout@v4
                    with:
                      ref: ${{ github.event.pull_request.base.sha }}
                  - uses: actions/checkout@v4
                  - run: echo ${{ github.event.pull_request.number }}
            """);
        Assert.Empty(safe.Findings);
        var lookalike = Review("lookalike", """
            on: issues
            jobs:
              triage:
                steps:
                  # ALL: ${{ toJSON(secrets) }}
                  - run: echo ${{ github.event.issue.title2 }}
            """);
        Assert.Empty(lookalike.Findings);
        var plain = Review("plain-pr", """
            on: pull_request
            jobs:
              test:
                steps:
                  - uses: actions/checkout@v4
                    with:
                      ref: ${{ github.event.pull_request.head.sha }}
                  - uses: some/action@main
            """);
        Assert.Empty(plain.Findings);
    }

    [Fact]
    public void A_privileged_trigger_that_checks_out_the_change_is_noteworthy_at_the_ref_line()
    {
        var r = Review("checkout", """
            on:
              pull_request_target:
                types: [opened]
            jobs:
              test:
                steps:
                  - uses: actions/checkout@v4
                    with:
                      ref: ${{ github.event.pull_request.head.sha }}
            """);
        var f = Assert.Single(r.Findings);
        Assert.Equal(("package/workflow-pr-checkout", "noteworthy", ".github/workflows/ci.yml", (int?)9), (f.Rule, f.Level, f.Path, f.Line));
        Assert.Equal("noteworthy", r.Review);
    }

    [Fact]
    public void A_workflow_run_trigger_that_checks_out_the_triggering_head_is_noteworthy()
    {
        var r = Review("workflow-run", """
            on:
              workflow_run:
                workflows: [ci]
            jobs:
              deploy:
                steps:
                  - uses: actions/checkout@v4
                    with: { path: x }
                  - uses: actions/checkout@v4
                    with:
                      repository: ${{ github.event.workflow_run.head_repository.full_name }}
                      ref: ${{ github.event.workflow_run.head_branch }}
            """);
        Assert.Contains(r.Findings, f => f is { Rule: "package/workflow-pr-checkout", Level: "noteworthy", Line: 12 });
    }

    [Fact]
    public void Reading_every_secret_as_one_value_is_noteworthy_at_its_line()
    {
        var r = Review("secrets", """
            on: push
            jobs:
              build:
                steps:
                  - run: echo ok
                  - name: Collect
                    env:
                      ALL: ${{ toJSON(secrets) }}
                    run: ./collect.sh
            """);
        var f = Assert.Single(r.Findings);
        Assert.Equal(("package/workflow-secrets-dump", "noteworthy", (int?)8), (f.Rule, f.Level, f.Line));
    }

    [Fact]
    public void An_event_field_an_author_controls_inside_a_run_command_is_noteworthy_at_its_line()
    {
        var r = Review("expression", """
            on: issues
            jobs:
              triage:
                steps:
                  - run: |
                      echo start
                      echo "${{ github.event.issue.title }}"
                  - run: echo ${{ github.head_ref }}
                  - run: echo ${{ github.event.commits[0].message }}
                  - uses: actions/github-script@v7
            """);
        Assert.Equal([7, 8, 9], r.Findings.Where(f => f.Rule == "package/workflow-run-expression").Select(f => f.Line!.Value).Order());
        Assert.All(r.Findings, f => Assert.Equal("noteworthy", f.Level));
    }

    [Fact]
    public void An_added_workflow_between_two_trees_is_listed_in_the_policy_facts()
    {
        const string manifest = """{"name":"sample","version":"1.0.0"}""";
        var old = PackageReview.Review(Repository("old", ("package.json", manifest)), default)!;
        var @new = PackageReview.Review(Repository("new", ("package.json", manifest), (".github/workflows/release.yml", Harmless)), default)!;
        var (rows, _) = CapabilityChanges.Policy(old, @new, CapabilityChanges.Of(old, @new));
        var row = Assert.Single(rows);
        Assert.Equal(("added", "runs: workflow job release.yml: build: on push, pull_request; actions/checkout@v4; run: echo \"$TITLE\""), (row.Kind, row.Key));
    }

    [Fact]
    public void An_unreadable_workflow_is_noted_as_unknown()
    {
        var r = Review("empty", "just text\n");
        Assert.Contains(r.Notes, n => n.Contains("workflow unknown", StringComparison.Ordinal));
    }

    [Fact]
    [FuzzEntry(typeof(WorkflowFile))]
    public void Fuzzed_workflows_never_throw()
    {
        var seed = System.Text.Encoding.UTF8.GetBytes(Harmless);
        var failures = FormatFuzz.Run(seed, b => WorkflowFile.Parse(System.Text.Encoding.UTF8.GetString(b)), 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
