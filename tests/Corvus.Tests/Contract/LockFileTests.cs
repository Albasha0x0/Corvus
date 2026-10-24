using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Corvus.Tests;

/// <summary>The shipped projects restore from committed lock files that cover every release target; CI restores them locked.</summary>
public partial class LockFileTests
{
    private static readonly string Root = DocsTests.RepoRoot();
    internal static readonly string[] Shipped = ["src/Corvus/Corvus.csproj", "src/Corvus.Clr32/Corvus.Clr32.csproj"];

    [GeneratedRegex(@"<PackageReference Include=""([^""]+)"" Version=""([^""]+)""")]
    private static partial Regex PackageReference();

    internal static JsonObject LockTargets(string project) =>
        JsonNode.Parse(File.ReadAllText(Path.Combine(Root, Path.GetDirectoryName(project)!, "packages.lock.json")))!["dependencies"]!.AsObject();

    private static string[] ReleaseRids() =>
        [.. Regex.Matches(File.ReadAllText(Path.Combine(Root, ".github", "workflows", "release.yml")), @"rid: ([a-z0-9-]+)")
            .Select(m => m.Groups[1].Value).Distinct().Order(StringComparer.Ordinal)];

    [Fact]
    public void Each_package_reference_is_locked_at_its_version()
    {
        foreach (var project in Shipped)
        {
            var targets = LockTargets(project);
            foreach (Match reference in PackageReference().Matches(File.ReadAllText(Path.Combine(Root, project))))
            {
                var (name, version) = (reference.Groups[1].Value, reference.Groups[2].Value);
                // RID targets list only the packages with RID-specific assets; the framework target lists every one.
                foreach (var (target, packages) in targets.Where(t => !t.Key.Contains('/', StringComparison.Ordinal)))
                {
                    var entry = packages![name];
                    Assert.True(entry != null, $"{project}: {target} lacks {name}");
                    Assert.Equal("Direct", (string?)entry["type"]);
                    Assert.Equal($"[{version}, )", (string?)entry["requested"]);
                    Assert.Equal(version, (string?)entry["resolved"]);
                }
            }
        }
    }

    [Fact]
    public void The_lock_file_covers_every_release_target()
    {
        // A RID-specific restore of Corvus applies the RID to Corvus.Clr32 too, so both lock files cover each target.
        foreach (var (project, framework, own) in new[] { (Shipped[0], "net10.0", ""), (Shipped[1], ".NETFramework,Version=v4.8", "win-x86") })
        {
            var csproj = File.ReadAllText(Path.Combine(Root, project));
            var listed = Regex.Match(csproj, "<RuntimeIdentifiers[^>]*>([^<]+)</RuntimeIdentifiers>").Groups[1].Value.Split(';').Where(r => r != own).Order(StringComparer.Ordinal);
            Assert.Equal(ReleaseRids(), listed);
            var targets = LockTargets(project).Select(t => t.Key).ToHashSet(StringComparer.Ordinal);
            foreach (var rid in ReleaseRids()) Assert.Contains($"{framework}/{rid}", targets);
        }
    }

    [Fact]
    public void Ci_restores_the_shipped_projects_locked()
    {
        var props = File.ReadAllText(Path.Combine(Root, "Directory.Build.props"));
        Assert.Contains("'$(MSBuildProjectName)' == 'Corvus' or '$(MSBuildProjectName)' == 'Corvus.Clr32'", props, StringComparison.Ordinal);
        Assert.Contains("<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>", props, StringComparison.Ordinal);
        Assert.Contains("<RestoreLockedMode Condition=\"'$(CI)' == 'true'\">true</RestoreLockedMode>", props, StringComparison.Ordinal);
    }
}
