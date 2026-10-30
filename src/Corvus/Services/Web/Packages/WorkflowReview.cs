using System.Text.RegularExpressions;

namespace Corvus.Services.Web.Packages;

public static partial class PackageReview
{
    // Triggers that run with the base repository's secrets on an outside change.
    private static readonly string[] PrivilegedTriggers = ["pull_request_target", "workflow_run"];

    // Values a pull request, issue or commit author controls.
    private static readonly string[] AuthorControlled =
    [
        "github.head_ref", "github.event.issue.title", "github.event.issue.body", "github.event.pull_request.title", "github.event.pull_request.body",
        "github.event.pull_request.head.ref", "github.event.pull_request.head.label", "github.event.comment.body", "github.event.review.body",
        "github.event.review_comment.body", "github.event.discussion.title", "github.event.discussion.body", "github.event.head_commit.message",
        "github.event.head_commit.author.name", "github.event.head_commit.author.email", "github.event.workflow_run.head_branch",
        "github.event.workflow_run.head_commit.message", "github.event.workflow_run.head_commit.author.name", "github.event.workflow_run.head_commit.author.email",
    ];

    private static readonly Regex Expression = new(@"\$\{\{(.*?)\}\}", RegexOptions.Singleline | RegexOptions.NonBacktracking);
    private static readonly Regex SecretsDump = new(@"toJSON\(\s*secrets\s*\)", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking);
    private static readonly Regex CommitList = new(@"github\.event\.commits\[[^\]]*\]\.(?:message|author\.(?:name|email))", RegexOptions.NonBacktracking);
    private static readonly Regex PullRequestRef = new(@"github\.(?:head_ref|event\.pull_request\.head\.|event\.workflow_run\.head_|event\.workflow_run\.pull_requests)|refs/pull/", RegexOptions.NonBacktracking);

    /// <summary>A workflow's jobs as entries (trigger, job, what runs), and its privileged-trigger checkout, secret dump and run-expression findings.</summary>
    private static void Workflow(string text, string path, AgentReview review, CancellationToken ct)
    {
        var root = WorkflowFile.Parse(text);
        if (root?["jobs"]?.Map is not { } jobs)
        {
            review.Notes.Add($"{path}: no jobs read; workflow unknown");
            return;
        }
        var on = root["on"] ?? root["true"];
        var triggers = on?.Map?.Select(e => e.Key).ToList()
            ?? on?.Seq?.Select(i => i.Text ?? "").ToList()
            ?? [.. WorkflowFile.Flow(on?.Text ?? "")];
        var privileged = triggers.Where(t => PrivilegedTriggers.Contains(t, StringComparer.Ordinal)).ToList();
        var file = path[(path.LastIndexOf('/') + 1)..];
        var when = triggers.Count > 0 ? "on " + string.Join(", ", triggers) : "no trigger";
        foreach (var (id, job) in jobs)
        {
            ct.ThrowIfCancellationRequested();
            var runs = new List<string>();
            if (job["uses"]?.Text is { } reusable) runs.Add(reusable);
            foreach (var step in job["steps"]?.Seq ?? [])
            {
                if (step["uses"]?.Text is { } action) runs.Add(action);
                if (step["run"]?.Text is { } script)
                {
                    runs.Add("run: " + script.Split('\n')[0]);
                    foreach (var (expr, offset) in Expressions(script))
                        if (Injected(expr))
                            review.Findings.Add(new PackageFinding("package/workflow-run-expression", "noteworthy", "agent configuration",
                                $"workflow job {id} puts {Clip(expr.Trim(), 100)} in a run command, which the shell reads as code", path, step["run"]!.Line + offset));
                }
                if (step["uses"]?.Text is { } u && u.StartsWith("actions/checkout", StringComparison.Ordinal) && privileged.Count > 0)
                    foreach (var key in new[] { "ref", "repository" })
                        if (step["with"]?[key] is { Text: { } value } node && PullRequestRef.IsMatch(value))
                            review.Findings.Add(new PackageFinding("package/workflow-pr-checkout", "noteworthy", "agent configuration",
                                $"workflow job {id} on {string.Join(", ", privileged)} checks out the change's own code ({key}: {Clip(value, 100)}) with the base repository's secrets", path, node.Line));
            }
            review.Entries.Add(new AgentEntry("workflow job", $"{file}: {id}", Clip($"{when}; {string.Join("; ", runs.Distinct())}"), path, job.Line));
        }
        var lines = text.Split('\n');
        for (int i = 0; i < lines.Length; i++)
            if (!lines[i].TrimStart().StartsWith('#') && SecretsDump.IsMatch(lines[i]))
                review.Findings.Add(new PackageFinding("package/workflow-secrets-dump", "noteworthy", "agent configuration",
                    "workflow reads every secret as one value with toJSON(secrets)", path, i + 1));
    }

    private static IEnumerable<(string Expr, int Line)> Expressions(string script)
    {
        var lines = script.Split('\n');
        for (int i = 0; i < lines.Length; i++)
            foreach (Match m in Expression.Matches(lines[i]))
                yield return (m.Groups[1].Value, i);
    }

    private static bool Injected(string expr) =>
        CommitList.IsMatch(expr) || AuthorControlled.Any(c => Names(expr, c));

    // A longer name such as 'github.event.issue.title2' is another field.
    private static bool Names(string expr, string name)
    {
        for (int at = expr.IndexOf(name, StringComparison.Ordinal); at >= 0; at = expr.IndexOf(name, at + 1, StringComparison.Ordinal))
        {
            int end = at + name.Length;
            if (end >= expr.Length || !(char.IsLetterOrDigit(expr[end]) || expr[end] == '_')) return true;
        }
        return false;
    }
}
