using System.Text.RegularExpressions;

namespace Corvus.Tests;

/// <summary>The maintainer skills under .agents/skills: valid front matter, and every path, test class and variable they name exists.</summary>
public sealed partial class MaintainerSkillTests
{
    private static readonly string Root = DocsTests.RepoRoot();

    public static TheoryData<string> Skills()
    {
        var data = new TheoryData<string>();
        foreach (var dir in Directory.GetDirectories(Path.Combine(Root, ".agents", "skills")).Order(StringComparer.Ordinal)) data.Add(Path.GetFileName(dir));
        return data;
    }

    [Theory, MemberData(nameof(Skills))]
    public void A_skill_has_its_folder_name_and_a_description_clients_accept(string name)
    {
        var text = File.ReadAllText(Path.Combine(Root, ".agents", "skills", name, "SKILL.md")).ReplaceLineEndings("\n");
        var front = FrontMatter().Match(text);
        Assert.True(front.Success, "SKILL.md starts with name and description front matter");
        Assert.Equal(name, front.Groups[1].Value);
        Assert.InRange(front.Groups[2].Value.Length, 1, 1024);
    }

    [Theory, MemberData(nameof(Skills))]
    public void A_skill_names_only_paths_tests_and_variables_that_exist(string name)
    {
        var text = File.ReadAllText(Path.Combine(Root, ".agents", "skills", name, "SKILL.md"));
        var sources = string.Concat(Directory.GetFiles(Path.Combine(Root, "src"), "*.cs", SearchOption.AllDirectories)
            .Concat(Directory.GetFiles(Path.Combine(Root, "tests", "Corvus.Tests"), "*.cs", SearchOption.AllDirectories)).Select(File.ReadAllText));
        foreach (Match m in RepoPath().Matches(text))
        {
            var path = m.Groups[1].Value.Split('<')[0].TrimEnd('/');
            Assert.True(File.Exists(Path.Combine(Root, path)) || Directory.Exists(Path.Combine(Root, path)), $"{name} names {m.Groups[1].Value}, which does not exist");
        }
        var types = typeof(MaintainerSkillTests).Assembly.GetTypes().Select(t => t.Name).ToHashSet(StringComparer.Ordinal);
        foreach (Match m in TestClass().Matches(text)) Assert.True(types.Contains(m.Value), $"{name} names {m.Value}, which is not a test class");
        foreach (Match m in Variable().Matches(text)) Assert.True(sources.Contains($"\"{m.Value}\"", StringComparison.Ordinal), $"{name} names {m.Value}, which no code reads");
    }

    [GeneratedRegex(@"^---\nname: ([a-z0-9-]+)\ndescription: ""([^""\n]*)""\n---\n")]
    private static partial Regex FrontMatter();

    [GeneratedRegex(@"`((?:src|tests|docs|skills)/[^`\s]*|[A-Za-z.]+\.(?:md|ps1))`")]
    private static partial Regex RepoPath();

    [GeneratedRegex(@"\b[A-Z][A-Za-z]+Tests\b")]
    private static partial Regex TestClass();

    [GeneratedRegex(@"\bCORVUS_[A-Z0-9_]+\b")]
    private static partial Regex Variable();
}
