using System.Text.RegularExpressions;

namespace Corvus.Tests;

/// <summary>SECURITY.md, CONTRIBUTING.md and the GitHub forms exist, and the source files they name exist.</summary>
public partial class CommunityFilesTests
{
    private static readonly string Root = FindRoot();

    [Fact]
    public void PathsNamedInContributingExist()
    {
        var text = File.ReadAllText(Path.Combine(Root, "CONTRIBUTING.md"));
        var paths = RepoPath().Matches(text).Select(m => m.Groups[1].Value).Distinct().ToList();
        Assert.NotEmpty(paths);
        Assert.All(paths, p => Assert.True(File.Exists(Path.Combine(Root, p)) || Directory.Exists(Path.Combine(Root, p)), $"CONTRIBUTING.md names {p}, which does not exist"));
        Assert.Contains("SECURITY.md", File.ReadAllText(Path.Combine(Root, "README.md")));
        Assert.Contains("CONTRIBUTING.md", File.ReadAllText(Path.Combine(Root, "README.md")));
    }

    [Fact]
    public void IssueFormsHaveTheRequiredKeys()
    {
        var forms = Directory.GetFiles(Path.Combine(Root, ".github", "ISSUE_TEMPLATE"), "*.yml").Where(f => Path.GetFileName(f) != "config.yml").ToList();
        Assert.Equal(3, forms.Count);
        foreach (var form in forms)
        {
            var lines = File.ReadAllLines(form);
            foreach (var key in new[] { "name:", "description:", "body:" })
                Assert.True(lines.Any(l => l.StartsWith(key, StringComparison.Ordinal)), $"{Path.GetFileName(form)}: no top-level {key}");
            Assert.DoesNotContain(lines, l => l.Contains('\t'));
        }
        Assert.Contains("blank_issues_enabled: false", File.ReadAllText(Path.Combine(Root, ".github", "ISSUE_TEMPLATE", "config.yml")));
        Assert.True(File.Exists(Path.Combine(Root, ".github", "PULL_REQUEST_TEMPLATE.md")));
    }

    [Fact]
    public void SolutionProjectNamesAreUniquePerFolder()
    {
        // The SDK's solution parser refuses two projects of one name in a folder; local runs build the test project and never parse it.
        var solution = System.Xml.Linq.XDocument.Load(Path.Combine(Root, "Corvus.slnx"));
        foreach (var folder in solution.Descendants("Folder"))
        {
            var names = folder.Elements("Project").Select(p => Path.GetFileNameWithoutExtension((string)p.Attribute("Path")!)).ToList();
            Assert.True(names.Count == names.Distinct(StringComparer.OrdinalIgnoreCase).Count(), $"Corvus.slnx folder {(string?)folder.Attribute("Name")} repeats a project name: {string.Join(", ", names)}");
            Assert.All(folder.Elements("Project"), p => Assert.True(File.Exists(Path.Combine(Root, (string)p.Attribute("Path")!)), $"Corvus.slnx names {(string?)p.Attribute("Path")}, which does not exist"));
        }
    }

    [Fact]
    public void SecurityNamesEveryCallThatReachesOutside()
    {
        var text = File.ReadAllText(Path.Combine(Root, "SECURITY.md"));
        var missing = ContractSweep.OpenWorldParameters.Concat(ContractSweep.AlwaysOpenWorld).Where(name => !text.Contains($"`{name}", StringComparison.Ordinal)).ToList();
        Assert.True(missing.Count == 0, "SECURITY.md does not name these open-world parameters or tools: " + string.Join(", ", missing));
    }

    [Fact]
    public void TrackedFilesNameNoMachinePath()
    {
        // The checkout's own location and the current account's home folder are what leak from a machine into a commit.
        var user = Environment.UserName;
        bool personal = user.Length > 2 && !new[] { "user", "runner", "root", "vsts", "admin" }.Contains(user, StringComparer.OrdinalIgnoreCase);
        var needles = new List<string>();
        // A checkout straight in a shared account's home (/root/corvus) or in the temp folder (test.ps1 -Background's
        // worktree, /tmp/corvus-bg-*) has a parent that names no machine.
        if (Path.GetDirectoryName(Root.TrimEnd(Path.DirectorySeparatorChar)) is { } parent && Path.GetPathRoot(parent) != parent
            && (personal || parent != Environment.GetFolderPath(Environment.SpecialFolder.UserProfile))
            && !string.Equals(parent, Path.TrimEndingDirectorySeparator(LeakGuard.SharedTemp), StringComparison.OrdinalIgnoreCase)) needles.Add(parent);
        if (personal)
            needles.AddRange([$@"\Users\{user}", $"/Users/{user}", $"/home/{user}", $@"\\Users\\{user}"]);
        var git = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("git", "ls-files -z") { WorkingDirectory = Root, RedirectStandardOutput = true })!;
        var files = git.StandardOutput.ReadToEnd().Split('\0', StringSplitOptions.RemoveEmptyEntries);
        git.WaitForExit();
        Assert.NotEmpty(files);
        var found = new List<string>();
        foreach (var file in files)
        {
            var path = Path.Combine(Root, file);
            if (!File.Exists(path) || new FileInfo(path).Length > 4 << 20) continue;
            var bytes = File.ReadAllBytes(path);
            if (bytes.AsSpan(0, Math.Min(bytes.Length, 8000)).Contains((byte)0)) continue;
            var text = System.Text.Encoding.UTF8.GetString(bytes);
            found.AddRange(needles.Where(n => text.Contains(n, StringComparison.OrdinalIgnoreCase)).Select(n => $"{file}: {n}"));
        }
        Assert.True(found.Count == 0, "machine-specific paths in tracked files:\n" + string.Join("\n", found));
    }

    private static string FindRoot()
    {
        var root = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(root, "Corvus.slnx"))) root = Path.GetDirectoryName(root) ?? throw new InvalidOperationException("repository root not found");
        return root;
    }

    [GeneratedRegex(@"`((?:src|tests|docs)/[^`\s]+)`")]
    private static partial Regex RepoPath();
}
