using System.Diagnostics;
using System.Formats.Tar;
using System.IO.Compression;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Corvus.Tests;

/// <summary>The MCP bundles (.mcpb) release.ps1 makes from the release archives and release.yml attaches.</summary>
public partial class BundleTests
{
    private static readonly string Root = DocsTests.RepoRoot();
    private static string Read(string relative) => File.ReadAllText(Path.Combine(Root, relative));
    private static readonly string[] Platforms = ["win32", "darwin", "linux"];

    /// <summary>The fields an MCP bundle manifest requires, and the shape of a binary server entry.</summary>
    internal static void AssertManifest(JsonNode manifest, string version)
    {
        Assert.Matches(@"^0\.[23]$", (string?)manifest["manifest_version"]);
        Assert.Matches("^[a-z0-9-]+$", (string?)manifest["name"]);
        Assert.Equal(version, (string?)manifest["version"]);
        Assert.False(string.IsNullOrWhiteSpace((string?)manifest["description"]));
        Assert.False(string.IsNullOrWhiteSpace((string?)manifest["author"]?["name"]));
        var server = manifest["server"]!;
        Assert.Equal("binary", (string?)server["type"]);
        var entry = (string)server["entry_point"]!;
        Assert.Equal("${__dirname}/" + entry, (string?)server["mcp_config"]!["command"]);
        Assert.NotNull(server["mcp_config"]!["args"]!.AsArray());
        var platforms = manifest["compatibility"]!["platforms"]!.AsArray().Select(p => (string)p!).ToList();
        Assert.NotEmpty(platforms);
        Assert.All(platforms, p => Assert.Contains(p, Platforms));
    }

    [Fact]
    public void ManifestTemplateAndReleaseWiring()
    {
        var version = Regex.Match(Read("src/Corvus/Corvus.csproj"), "<Version>([^<]+)</Version>").Groups[1].Value;
        AssertManifest(JsonNode.Parse(Read("mcpb/manifest.json"))!, version);

        var workflow = Read(".github/workflows/release.yml");
        var rids = Regex.Matches(workflow, "rid: ([a-z0-9-]+)").Select(m => m.Groups[1].Value).ToHashSet();
        Assert.Equal(["linux-arm64", "linux-x64", "osx-arm64", "osx-x64", "win-arm64", "win-x64"], Bundled().Order(StringComparer.Ordinal));
        Assert.Equal(rids.Count, Regex.Count(workflow, @"rid: [a-z0-9-]+[^}\n]*bundle: (?:true|false)"));
        Assert.Contains(@"'rid: ([a-z0-9-]+)[^}\n]*bundle: true'", Read("release.ps1"), StringComparison.Ordinal);
        Assert.Contains("./release.ps1 -Version $env:GITHUB_REF_NAME -Bundle .", workflow, StringComparison.Ordinal);
        // The bundles are made before the checksums, which cover every corvus-* asset.
        Assert.True(workflow.IndexOf("-Bundle .", StringComparison.Ordinal) < workflow.IndexOf("sha256sum corvus-*", StringComparison.Ordinal));
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public async Task ReleaseScriptBundlesEachDesktopArchive()
    {
        if (FindOnPath(OperatingSystem.IsWindows() ? "pwsh.exe" : "pwsh") is not { } pwsh) return;
        using var dir = new TempDir();
        var bundled = Bundled();
        foreach (var rid in bundled)
        {
            var content = Path.Combine(dir.Path, "content-" + rid);
            Directory.CreateDirectory(content);
            var exe = rid.StartsWith("win-", StringComparison.Ordinal) ? "corvus.exe" : "corvus";
            File.WriteAllText(Path.Combine(content, exe), "program");
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(Path.Combine(content, exe), UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
            File.WriteAllText(Path.Combine(content, "corvus.dll"), "library");
            if (rid.StartsWith("win-", StringComparison.Ordinal)) ZipFile.CreateFromDirectory(content, Path.Combine(dir.Path, $"corvus-{rid}.zip"));
            else
            {
                await using var file = File.Create(Path.Combine(dir.Path, $"corvus-{rid}.tar.gz"));
                await using var gzip = new GZipStream(file, CompressionLevel.Fastest);
                await TarFile.CreateFromDirectoryAsync(content, gzip, includeBaseDirectory: false);
            }
        }

        var psi = new ProcessStartInfo(pwsh) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var a in new[] { "-NoProfile", "-File", Path.Combine(Root, "release.ps1"), "-Version", "v9.8.7", "-Bundle", dir.Path }) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var output = await p.StandardOutput.ReadToEndAsync() + await p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync();
        Assert.True(p.ExitCode == 0, output);

        foreach (var rid in bundled)
        {
            using var zip = ZipFile.OpenRead(Path.Combine(dir.Path, $"corvus-{rid}.mcpb"));
            using var reader = new StreamReader(zip.GetEntry("manifest.json")!.Open());
            var manifest = JsonNode.Parse(await reader.ReadToEndAsync())!;
            AssertManifest(manifest, "9.8.7");
            var platform = rid.Split('-')[0] switch { "win" => "win32", "osx" => "darwin", _ => "linux" };
            Assert.Equal([platform], manifest["compatibility"]!["platforms"]!.AsArray().Select(n => (string)n!));
            var entry = zip.GetEntry((string)manifest["server"]!["entry_point"]!);
            Assert.NotNull(entry);
            Assert.NotNull(zip.GetEntry("server/corvus.dll"));
            if (platform != "win32") Assert.True(((entry.ExternalAttributes >> 16) & 0x40) != 0, $"{rid}: the launcher is not executable");
        }
    }

    /// <summary>The release targets marked bundle: true, as release.ps1 reads them.</summary>
    private static List<string> Bundled() =>
        [.. Regex.Matches(Read(".github/workflows/release.yml"), @"rid: ([a-z0-9-]+)[^}\n]*bundle: true").Select(m => m.Groups[1].Value)];

    private static string? FindOnPath(string name) =>
        (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Select(d => Path.Combine(d, name)).FirstOrDefault(File.Exists);
}
