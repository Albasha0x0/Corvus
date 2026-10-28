using System.Diagnostics;
using System.Reflection.Metadata;

namespace Corvus.Tests;

/// <summary>
/// A GitHub Actions build maps source paths to /_/, so a rebuild on another
/// machine writes the same PDB paths.
/// </summary>
public class ReproducibleBuildTests
{
    [Fact]
    public void A_GitHub_Actions_build_writes_PDB_paths_under_the_mapped_root()
    {
        using var dir = new TempDir();
        var project = Directory.CreateDirectory(dir.File("Probe")).FullName;
        var props = Path.Combine(DocsTests.RepoRoot(), "Directory.Build.props");
        File.WriteAllText(Path.Combine(project, "Directory.Build.props"), $"""<Project><Import Project="{props}" /></Project>""");
        File.WriteAllText(Path.Combine(project, "Directory.Packages.props"), "<Project />");
        File.WriteAllText(Path.Combine(project, "Probe.csproj"),
            """<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>""");
        File.WriteAllText(Path.Combine(project, "Probe.cs"), "namespace Probe;\n\npublic static class P\n{\n    public static int F() => 1;\n}\n");
        // Source Link maps the git work tree's root, which needs a commit.
        Git(project, "init", "-q");
        Git(project, "add", "-A");
        Git(project, "-c", "user.name=probe", "-c", "user.email=probe@example.invalid", "commit", "-q", "-m", "probe");

        // A global property stands in for the variable GitHub Actions sets; the
        // condition reads both alike.
        var (exitCode, log) = Tools.Dotnet(project, "build", "-c", "Release", "-p:GITHUB_ACTIONS=true", "--nologo");
        Assert.True(exitCode == 0, $"dotnet build failed:\n{log}");
        using var pdb = File.OpenRead(Path.Combine(project, "bin", "Release", "net10.0", "Probe.pdb"));
        using var provider = MetadataReaderProvider.FromPortablePdbStream(pdb);
        var reader = provider.GetMetadataReader();
        var documents = reader.Documents.Select(d => reader.GetString(reader.GetDocument(d).Name)).ToList();
        Assert.Contains("/_/Probe.cs", documents);
        Assert.All(documents, d => Assert.StartsWith("/_/", d, StringComparison.Ordinal));
    }

    private static void Git(string dir, params string[] args)
    {
        ProcessStartInfo start = new("git") { RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = dir };
        foreach (var arg in args) start.ArgumentList.Add(arg);
        using var p = Process.Start(start)!;
        var error = p.StandardError.ReadToEnd();
        p.WaitForExit();
        Assert.True(p.ExitCode == 0, $"git {string.Join(' ', args)}: {error}");
    }
}
