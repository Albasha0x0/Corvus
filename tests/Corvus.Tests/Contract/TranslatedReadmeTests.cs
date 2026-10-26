using System.Text.RegularExpressions;

namespace Corvus.Tests;

/// <summary>
/// Each README.*.md translation keeps the English README's code blocks, links, numbers, headings and table rows, so a
/// changed command, count or link in README.md fails here until every translation carries it.
/// </summary>
public sealed partial class TranslatedReadmeTests
{
    private static readonly string Root = DocsTests.RepoRoot();

    public static TheoryData<string> Translations()
    {
        var data = new TheoryData<string>();
        foreach (var path in Directory.GetFiles(Root, "README.*.md").Order(StringComparer.Ordinal)) data.Add(Path.GetFileName(path));
        return data;
    }

    private static string Read(string name) => File.ReadAllText(Path.Combine(Root, name)).ReplaceLineEndings("\n");

    [Fact]
    public void The_english_readme_links_every_translation()
    {
        var english = Read("README.md");
        Assert.NotEmpty(Translations());
        foreach (var name in Translations()) Assert.Contains($"]({name})", english);
    }

    [Theory, MemberData(nameof(Translations))]
    public void A_translation_keeps_the_code_links_numbers_and_structure_of_the_english_readme(string name)
    {
        string english = Read("README.md"), translated = Read(name);
        Assert.Contains("](README.md)", translated);
        Assert.Equal(Code().Matches(english).Select(m => m.Value), Code().Matches(translated).Select(m => m.Value));
        Assert.Equal(Links(english), Links(translated));
        Assert.Equal(Numbers(english), Numbers(translated));
        Assert.Equal(Heading().Matches(english).Select(m => m.Groups[1].Length), Heading().Matches(translated).Select(m => m.Groups[1].Length));
        Assert.Equal(Row().Count(english), Row().Count(translated));
    }

    [Theory, MemberData(nameof(Translations))]
    public void A_translation_links_only_to_its_own_headings(string name)
    {
        var translated = Read(name);
        var headings = Heading().Matches(translated).Select(m => Slug(m.Groups[2].Value)).ToHashSet(StringComparer.Ordinal);
        Assert.All(Fragment().Matches(translated).Select(m => m.Groups[1].Value), a => Assert.Contains(a, headings));
    }

    /// <summary>Link targets other than in-page anchors and the README pages themselves, sorted.</summary>
    private static List<string> Links(string text) =>
        [.. Link().Matches(text).Select(m => m.Groups[1].Value).Where(t => !t.StartsWith('#') && !ReadmePage().IsMatch(t)).Order(StringComparer.Ordinal)];

    /// <summary>Every number outside in-page anchors, sorted: versions, counts, architectures and paths.</summary>
    private static List<string> Numbers(string text) =>
        [.. Number().Matches(Fragment().Replace(text, "")).Select(m => m.Value).Order(StringComparer.Ordinal)];

    /// <summary>GitHub's heading anchor: lower case, punctuation removed, spaces as hyphens.</summary>
    private static string Slug(string heading) => SlugDrop().Replace(heading.Trim().ToLowerInvariant(), "").Replace(' ', '-');

    [GeneratedRegex(@"```.*?```", RegexOptions.Singleline)]
    private static partial Regex Code();

    [GeneratedRegex(@"\]\(([^)\s]+)\)")]
    private static partial Regex Link();

    [GeneratedRegex(@"\]\(#([^)]*)\)")]
    private static partial Regex Fragment();

    [GeneratedRegex(@"^README(\.[\w-]+)?\.md$")]
    private static partial Regex ReadmePage();

    [GeneratedRegex(@"\d+(?:\.\d+)*")]
    private static partial Regex Number();

    [GeneratedRegex(@"^(#+) (.*)$", RegexOptions.Multiline)]
    private static partial Regex Heading();

    [GeneratedRegex(@"^\|", RegexOptions.Multiline)]
    private static partial Regex Row();

    [GeneratedRegex(@"[^\w\- ]")]
    private static partial Regex SlugDrop();
}
