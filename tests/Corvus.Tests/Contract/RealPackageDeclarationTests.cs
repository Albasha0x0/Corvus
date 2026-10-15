using System.Text.RegularExpressions;

namespace Corvus.Tests;

/// <summary>Every package a test reads through RealPackages is declared in the test project, so a clean restore (CI) has it.</summary>
public partial class RealPackageDeclarationTests
{
    // Restored as dependencies of a PackageReference rather than downloaded on their own.
    private static readonly HashSet<string> Transitive = ["microsoft.codecoverage"];

    [Fact]
    public void EveryPackageReadIsDeclared()
    {
        var tests = Path.Combine(DocsTests.RepoRoot(), "tests", "Corvus.Tests");
        var project = File.ReadAllText(Path.Combine(tests, "Corvus.Tests.csproj"));
        var declared = Download().Matches(project)
            .SelectMany(m => Versions().Matches(m.Groups[2].Value).Select(v => $"{m.Groups[1].Value.ToLowerInvariant()}/{v.Groups[1].Value}"))
            .ToHashSet();
        var missing = Directory.EnumerateFiles(tests, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}") && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"))
            .SelectMany(f => Use().Matches(File.ReadAllText(f)).Select(m => (File: Path.GetFileName(f), Id: m.Groups[1].Value.ToLowerInvariant(), Version: m.Groups[2].Value)))
            .Where(u => !Transitive.Contains(u.Id) && !declared.Contains($"{u.Id}/{u.Version}"))
            .Select(u => $"{u.Id} {u.Version} ({u.File})")
            .Distinct()
            .ToList();
        Assert.True(missing.Count == 0, "add a <PackageDownload> for: " + string.Join(", ", missing));
    }

    [GeneratedRegex(@"<PackageDownload Include=""([^""]+)"" Version=""([^""]+)""")]
    private static partial Regex Download();

    [GeneratedRegex(@"\[([^\]]+)\]")]
    private static partial Regex Versions();

    [GeneratedRegex(@"RealPackages\.\w+\(""([^""]+)"",\s*""([^""]+)""")]
    private static partial Regex Use();
}
