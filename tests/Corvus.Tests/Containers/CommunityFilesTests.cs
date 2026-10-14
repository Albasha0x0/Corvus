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

    private static string FindRoot()
    {
        var root = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(root, "Corvus.slnx"))) root = Path.GetDirectoryName(root) ?? throw new InvalidOperationException("repository root not found");
        return root;
    }

    [GeneratedRegex(@"`((?:src|tests|docs)/[^`\s]+)`")]
    private static partial Regex RepoPath();
}
