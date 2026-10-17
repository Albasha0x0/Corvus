using System.Diagnostics;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>The NuGet .NET tool CorvusRE: its metadata, the update advice per install kind, and (slow) a real pack and install from a local feed.</summary>
public partial class ToolPackageTests
{
    private static readonly string Root = DocsTests.RepoRoot();
    private static string Project => File.ReadAllText(Path.Combine(Root, "src", "Corvus", "Corvus.csproj"));
    private static string Property(string name) => Regex.Match(Project, $"<{name}>([^<]+)</{name}>").Groups[1].Value;

    [Fact]
    public void PackageAndRegistryEntryAgreeWithTheProject()
    {
        Assert.Equal(Installation.PackageId, Property("PackageId"));
        Assert.Equal("corvus", Property("ToolCommandName"));
        Assert.Equal("true", Property("PackAsTool"));
        var server = JsonNode.Parse(File.ReadAllText(Path.Combine(Root, "src", "Corvus", ".mcp", "server.json")))!;
        var version = Property("Version");
        Assert.Equal(version, (string?)server["version"]);
        var package = Assert.Single(server["packages"]!.AsArray())!;
        Assert.Equal("nuget", (string?)package["registryType"]);
        Assert.Equal("https://api.nuget.org/v3/index.json", (string?)package["registryBaseUrl"]); // the registry's RegistryURLNuGet
        Assert.Equal(Installation.PackageId, (string?)package["identifier"]);
        Assert.Equal(version, (string?)package["version"]);
        Assert.Equal("stdio", (string?)package["transport"]!["type"]);
        Assert.True(((string?)server["description"])!.Length <= 100, "the registry limits description to 100 characters");
        Assert.Equal("README.md", Property("PackageReadmeFile"));
        var readme = File.ReadAllText(Path.Combine(Root, "src", "Corvus", "PACKAGE.md"));
        Assert.Contains($"<!-- mcp-name: {(string?)server["name"]} -->", readme, StringComparison.Ordinal); // the registry's ownership check
    }

    [Fact]
    public void UpdateNamesTheCommandOfEachInstallKind()
    {
        Assert.Equal("corvus update", Installation.UpdateCommand("script"));
        Assert.Equal("dotnet tool update -g CorvusRE --version 1.3.0", Installation.UpdateCommand("dotnet-tool", "v1.3.0"));
        Assert.Equal("dnx CorvusRE --yes", Installation.UpdateCommand("dnx"));
        Assert.Equal("dnx CorvusRE@1.3.0 --yes", Installation.UpdateCommand("dnx", "1.3.0"));
        Assert.Null(Installation.UpdateCommand("source"));

        // The test host is no script install, so update explains instead of downloading.
        foreach (var (kind, expected) in new[] { ("dotnet-tool", "dotnet tool update -g CorvusRE"), ("dnx", "dnx CorvusRE --yes"), ("source", "not installed by the install script") })
        {
            using var output = new StringWriter();
            Assert.Equal(1, Installation.Update(output, installKind: kind));
            Assert.Contains(expected, output.ToString(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public void UpdateWarnsOnADowngrade()
    {
        Assert.Contains("a downgrade", Installation.DowngradeWarning("2.0.0", "v1.3.0"));
        Assert.Null(Installation.DowngradeWarning("1.3.0", "v2.0.0"));
        Assert.Null(Installation.DowngradeWarning("1.3.0", "1.3.0"));
        Assert.Null(Installation.DowngradeWarning("1.3.0", "next"));
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public async Task PacksInstallsAndRunsFromALocalFeed()
    {
        using var dir = new TempDir();
        var feed = Path.Combine(dir.Path, "feed");
        var config = Path.Combine(dir.Path, "nuget.config");
        File.WriteAllText(config, $"""
            <?xml version="1.0" encoding="utf-8"?>
            <configuration><packageSources><clear /><add key="local" value="{System.Security.SecurityElement.Escape(feed)}" /></packageSources></configuration>
            """);
        var env = new Dictionary<string, string>
        {
            ["DOTNET_CLI_HOME"] = Path.Combine(dir.Path, "home"),
            ["NUGET_PACKAGES"] = Path.Combine(dir.Path, "packages"),
            ["DOTNET_NOLOGO"] = "1",
            ["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1",
            // else the first run under this home appends its tools folder to the user's PATH (the registry, on Windows)
            ["DOTNET_ADD_GLOBAL_TOOLS_TO_PATH"] = "false",
        };
        // the CLI stages tool installs and restores in random folders of the temporary folder and leaves them: one of its own, deleted with dir
        var temp = Directory.CreateDirectory(Path.Combine(dir.Path, "tmp")).FullName;
        foreach (var name in new[] { "TMP", "TEMP", "TMPDIR" }) env[name] = temp;
        var version = Property("Version");

        // Packed with the repository's sources and package cache; installed and run in isolation from the feed alone.
        var pack = await RunAsync("dotnet", ["pack", Path.Combine(Root, "src", "Corvus", "Corvus.csproj"), "-c", "Release", "-o", feed, "--nologo"], Root,
            new() { ["TMP"] = temp, ["TEMP"] = temp, ["TMPDIR"] = temp });
        Assert.True(pack.Code == 0, pack.Output);
        var nupkg = Path.Combine(feed, $"{Installation.PackageId}.{version}.nupkg");
        using (var zip = System.IO.Compression.ZipFile.OpenRead(nupkg))
        {
            var entries = zip.Entries.Select(e => e.FullName).ToHashSet();
            Assert.Contains(".mcp/server.json", entries);
            Assert.Contains("README.md", entries);
            Assert.Contains("tools/net10.0/any/corvus.dll", entries);
            Assert.Contains("tools/net10.0/any/DotnetToolSettings.xml", entries);
            using var reader = new StreamReader(zip.GetEntry($"{Installation.PackageId}.nuspec")!.Open());
            var nuspec = await reader.ReadToEndAsync();
            Assert.Contains("<packageType name=\"DotnetTool\" />", nuspec, StringComparison.Ordinal);
            Assert.Contains("<packageType name=\"McpServer\" />", nuspec, StringComparison.Ordinal);
            Assert.Contains("<readme>README.md</readme>", nuspec, StringComparison.Ordinal);
        }

        var install = await RunAsync("dotnet", ["tool", "install", "-g", Installation.PackageId, "--configfile", config], dir.Path, env);
        Assert.True(install.Code == 0, install.Output);
        var shim = Path.Combine(env["DOTNET_CLI_HOME"], ".dotnet", "tools", OperatingSystem.IsWindows() ? "corvus.exe" : "corvus");
        Assert.Equal(version, (await RunAsync(shim, ["version"], dir.Path, env)).Output.Trim());
        Assert.Equal("dotnet-tool", (string?)Status(await RunAsync(shim, ["status", "--json", "--engine", "ida"], dir.Path, env))["installKind"]);
        var update = await RunAsync(shim, ["update"], dir.Path, env);
        Assert.Equal(1, update.Code);
        Assert.Contains("dotnet tool update -g CorvusRE", update.Output, StringComparison.Ordinal);

        var exec = await RunAsync("dotnet", ["tool", "exec", Installation.PackageId, "--configfile", config, "--yes", "status", "--json", "--engine", "ida"], dir.Path, env);
        Assert.Equal("dnx", (string?)Status(exec)["installKind"]);
    }

    private static JsonNode Status((int Code, string Output) run)
    {
        var start = run.Output.IndexOf('{');
        Assert.True(start >= 0, run.Output);
        return JsonNode.Parse(run.Output[start..])!;
    }

    private static async Task<(int Code, string Output)> RunAsync(string exe, string[] args, string cwd, Dictionary<string, string> env)
    {
        var psi = new ProcessStartInfo(exe) { WorkingDirectory = cwd, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var a in args) psi.ArgumentList.Add(a);
        foreach (var (k, v) in env) psi.Environment[k] = v;
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(10));
        await p.WaitForExitAsync(timeout.Token);
        return (p.ExitCode, await stdout + await stderr);
    }
}
