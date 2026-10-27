using System.Text.Json;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Dependencies;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>view=dependencies compared with a reference SBOM tool (CORVUS_DEPENDENCY_LISTER) on a published app and an APK.</summary>
[Trait("Speed", "Slow")]
public sealed class DependencyListerComparisonTests(ITestOutputHelper output) : IDisposable
{
    /// <summary>The reference tool's variable and native arguments ({input}: the file or folder); it prints CycloneDX JSON.</summary>
    private static readonly (string Variable, string[] Arguments) Reference = ("CORVUS_DEPENDENCY_LISTER", ["scan", "{input}", "-o", "cyclonedx-json", "-q"]);

    private static readonly string[] Packages = ["pkg:nuget/NLog@6.1.4", "pkg:nuget/Newtonsoft.Json@13.0.4"];

    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    [Fact]
    public void A_published_app_lists_every_package_the_reference_tool_lists()
    {
        if (Environment.GetEnvironmentVariable(Reference.Variable) is not { Length: > 0 } tool) return;
        var project = _dir.File("App");
        Directory.CreateDirectory(project);
        // Empty build props stop MSBuild from picking up a Directory.Build.props above the temp folder.
        File.WriteAllText(Path.Combine(project, "Directory.Build.props"), "<Project />");
        File.WriteAllText(Path.Combine(project, "Directory.Packages.props"), "<Project />");
        File.WriteAllText(Path.Combine(project, "App.csproj"), """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework></PropertyGroup>
              <ItemGroup>
                <PackageReference Include="NLog" Version="6.1.4" />
                <PackageReference Include="Newtonsoft.Json" Version="13.0.4" />
              </ItemGroup>
            </Project>
            """);
        File.WriteAllText(Path.Combine(project, "Program.cs"),
            """System.Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(NLog.LogManager.GetCurrentClassLogger().Name));""");
        var app = OperatingSystem.IsWindows() ? "App.exe" : "App";
        var bundle = Path.Combine(Publish(project, "bundle", "-p:PublishSingleFile=true"), app);
        var folder = Publish(project, "folder");

        var failures = new List<string>();
        foreach (var (label, input, ours) in new[] { ("bundle", bundle, bundle), ("folder", folder, Path.Combine(folder, app)) })
        {
            var theirs = ReferencePurls(tool, input);
            var mine = OurPurls(ours);
            output.WriteLine($"{label}: ours {mine.Count} ({string.Join(", ", mine)}); reference {theirs.Count} ({string.Join(", ", theirs)})");
            if (theirs.Except(mine).ToList() is { Count: > 0 } missing) failures.Add($"{label}: missing {string.Join(", ", missing)}");
            if (Packages.Except(mine).ToList() is { Count: > 0 } absent) failures.Add($"{label}: not listed {string.Join(", ", absent)}");
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    private string Publish(string project, string name, params string[] args)
    {
        var output = _dir.File(name);
        var (exitCode, log) = Tools.Dotnet(project, ["publish", "-c", "Release", "-r", ContainerFixtures.Rid, "--self-contained", "false", "-o", output, .. args]);
        Assert.True(exitCode == 0, $"dotnet publish {name} failed:\n{log}");
        return output;
    }

    private HashSet<string> OurPurls(string path) =>
        new InspectionService(_workspace).Summarize(null, path, default).Views.GetValueOrDefault("dependencies")?.Detail is DependencyFacts facts
            ? [.. facts.All.Where(c => c.Purl?.StartsWith("pkg:nuget/", StringComparison.Ordinal) == true).Select(c => c.Purl!)]
            : [];

    [Fact]
    public void An_android_package_lists_every_package_the_reference_tool_lists()
    {
        if (Environment.GetEnvironmentVariable(Reference.Variable) is not { Length: > 0 } tool) return;
        var bytes = AndroidDependencyTests.JavaApp();
        var apk = _dir.File("app.apk");
        File.WriteAllBytes(apk, bytes);
        // The reference tool reads Maven properties in Java archives only; the same bytes as a .jar give it the
        // libraries to compare with.
        var jar = _dir.File("app.jar");
        File.WriteAllBytes(jar, bytes);
        var ours = new InspectionService(_workspace).Summarize(null, apk, default, new FileViewOptions("dependencies")).Views["dependencies"].Detail is DependencyFacts facts
            ? facts.All.Where(c => c.Purl != null).Select(c => c.Purl!).ToHashSet(StringComparer.Ordinal) : [];
        var asApk = ReferencePurls(tool, apk, "pkg:");
        var asJar = ReferencePurls(tool, jar, "pkg:maven/");
        output.WriteLine($"ours {ours.Count} ({string.Join(", ", ours)}); reference on the .apk {asApk.Count}, on the .jar {asJar.Count} ({string.Join(", ", asJar)})");
        Assert.Empty(asApk.Except(ours));
        Assert.NotEmpty(asJar);
        Assert.Empty(asJar.Except(ours));
    }

    private static HashSet<string> ReferencePurls(string tool, string input) => ReferencePurls(tool, input, "pkg:nuget/");

    private static HashSet<string> ReferencePurls(string tool, string input, string prefix)
    {
        var run = ExternalTools.Run(tool, [.. Reference.Arguments.Select(a => a.Replace("{input}", input))], TimeSpan.FromMinutes(5), 64L << 20, default);
        Assert.True(run.StartError == null && !run.TimedOut && !run.Truncated, $"{Reference.Variable}: {run.StartError ?? run.Stderr}");
        using var doc = JsonDocument.Parse(run.Text);
        var purls = new HashSet<string>(StringComparer.Ordinal);
        if (doc.RootElement.TryGetProperty("components", out var components))
            foreach (var c in components.EnumerateArray())
                if (c.TryGetProperty("purl", out var p) && p.GetString() is { } purl && purl.StartsWith(prefix, StringComparison.Ordinal)
                    && !purl.StartsWith("pkg:nuget/App@", StringComparison.Ordinal) && purl.Contains('@'))
                    purls.Add(purl);
        return purls;
    }
}
