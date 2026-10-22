using System.Diagnostics;

namespace Corvus.Tests;

/// <summary>.githooks/commit-msg.ps1: the commit message form it rejects, and the messages it lets through.</summary>
public class CommitMessageCheckTests
{
    private const string Trailer = "Co-Authored-By: A Person <person@example.com>";
    private static readonly string Long = string.Join(' ', Enumerable.Repeat("word", 15));

    private static readonly Dictionary<string, string> Messages = new()
    {
        ["good"] = $"fix(live): keep deferred stop points\n\nBefore, a point was lost.\nSee https://example.com/{new string('a', 80)}\n" +
                   $"- {new string('A', 80)}\n\n# a comment git strips: {Long}\nUpstream: frida/frida-gum#1190 {Long}\n{Trailer}\n",
        ["merge"] = "Merge branch 'x' into main\n",
        ["long-subject"] = $"fix(live): {new string('a', 70)}\n\n{Trailer}\n",
        ["form"] = $"live: keep points\n\n{Trailer}\n",
        ["type"] = $"build(live): keep points\n\n{Trailer}\n",
        ["scope"] = $"feat(ci): keep points\n\n{Trailer}\n",
        ["capital"] = $"fix(live): Keep points\n\n{Trailer}\n",
        ["period"] = $"fix(live): keep points.\n\n{Trailer}\n",
        ["issue"] = $"fix(live): keep points, Fixes #12\n\n{Trailer}\n",
        ["body"] = $"fix(live): keep points\n\n{Long}\n\n{Trailer}\n",
        ["no-trailer"] = "fix(live): keep points\n\nBefore, a point was lost.\n",
        ["scissors"] = $"fix(live): keep points\n\n{Trailer}\n# ------------------------ >8 ------------------------\n{Long}\n",
    };

    [Fact]
    [Trait("Speed", "Slow")]
    public void Each_rule_names_its_problem_and_a_conforming_message_passes()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"corvus-commit-msg-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            foreach (var (name, text) in Messages)
                File.WriteAllText(Path.Combine(dir, name), text);
            ProcessStartInfo start = new("pwsh") { RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var arg in new[] { "-NoProfile", "-File", Path.Combine(DocsTests.RepoRoot(), ".githooks", "commit-msg.ps1") })
                start.ArgumentList.Add(arg);
            foreach (var name in Messages.Keys)
                start.ArgumentList.Add(Path.Combine(dir, name));
            Process? process;
            try { process = Process.Start(start); }
            catch (System.ComponentModel.Win32Exception) { return; } // no pwsh on this machine
            string output;
            using (process)
            {
                output = process!.StandardOutput.ReadToEnd();
                process.WaitForExit();
                Assert.Equal(1, process.ExitCode);
            }
            var problems = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(l => l.Substring(dir.Length + 1).Split(": ", 2))
                .ToLookup(p => p[0], p => p[1]);

            Assert.Empty(problems["good"]);
            Assert.Empty(problems["no-trailer"]);
            Assert.Empty(problems["merge"]);
            Assert.Empty(problems["scissors"]);
            Assert.Equal(["subject is 81 characters; at most 72"], problems["long-subject"]);
            Assert.Equal(["subject is not 'type(scope): summary'"], problems["form"]);
            Assert.StartsWith("type 'build' is not one of", Assert.Single(problems["type"]));
            Assert.StartsWith("scope 'ci' is not one of", Assert.Single(problems["scope"]));
            Assert.Equal(["summary starts with a capital letter; write it in lower case"], problems["capital"]);
            Assert.Equal(["subject ends with a period"], problems["period"]);
            Assert.Equal(["subject names an issue; put it in a Fixes, Refs or Upstream trailer"], problems["issue"]);
            Assert.Equal(["line 3 is 74 columns; wrap the body at 72"], problems["body"]);
        }
        finally { Directory.Delete(dir, true); }
    }
}
