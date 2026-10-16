using System.Diagnostics;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>The Claude Code and Codex plugins: one marketplace, both manifests on this release, each server entry running this release's .NET tool under its own client profile.</summary>
public class PluginManifestTests
{
    private static readonly string Root = DocsTests.RepoRoot();
    private static JsonNode Read(string relative) => JsonNode.Parse(File.ReadAllText(Path.Combine(Root, relative)))!;
    private static string Version => Regex.Match(File.ReadAllText(Path.Combine(Root, "src", "Corvus", "Corvus.csproj")), "<Version>([^<]+)</Version>").Groups[1].Value;

    private static void AssertPlugin(JsonNode plugin, string client)
    {
        Assert.Equal("corvus", (string?)plugin["name"]);
        Assert.Equal(Version, (string?)plugin["version"]);
        Assert.False(string.IsNullOrWhiteSpace((string?)plugin["description"]));
        // Paths are relative to the plugin root (the repository root) and stay inside it.
        Assert.Equal("./skills/", (string?)plugin["skills"]);
        Assert.True(File.Exists(Path.Combine(Root, "skills", "corvus", "SKILL.md")));
        var servers = plugin["mcpServers"]!.AsObject();
        Assert.Equal(["corvus"], servers.Select(s => s.Key));
        var server = servers["corvus"]!;
        Assert.Equal("dotnet", (string?)server["command"]);
        var args = server["args"]!.AsArray().Select(a => (string)a!).ToList();
        Assert.Equal(["tool", "exec", $"{Corvus.Setup.Installation.PackageId}@{Version}", "--yes", "--", "--client", client], args);
        Assert.NotNull(ClientProfiles.Find(client));
        ServerOptions.Parse([.. args.SkipWhile(a => a != "--").Skip(1)]);
    }

    [Fact]
    public void ClaudeCodePlugin() => AssertPlugin(Read(".claude-plugin/plugin.json"), "claude-code");

    [Fact]
    public void CodexPlugin()
    {
        var plugin = Read(".codex-plugin/plugin.json");
        AssertPlugin(plugin, "codex");
        Assert.Equal("Corvus", (string?)plugin["interface"]!["displayName"]);
        Assert.False(string.IsNullOrWhiteSpace((string?)plugin["interface"]!["shortDescription"]));
    }

    [Fact]
    public void MarketplaceListsThePluginAtTheRoot()
    {
        // Claude Code and Codex both read .claude-plugin/marketplace.json.
        var marketplace = Read(".claude-plugin/marketplace.json");
        Assert.Matches("^[a-z0-9-]+$", (string?)marketplace["name"]);
        Assert.False(string.IsNullOrWhiteSpace((string?)marketplace["owner"]!["name"]));
        var entry = Assert.Single(marketplace["plugins"]!.AsArray())!;
        Assert.Equal("corvus", (string?)entry["name"]);
        Assert.Equal("./", (string?)entry["source"]);
        Assert.Equal(Version, (string?)entry["version"]);
        foreach (var file in new[] { ".claude-plugin/plugin.json", ".claude-plugin/marketplace.json", ".codex-plugin/plugin.json" })
            Assert.Contains($"'{file}'", File.ReadAllText(Path.Combine(Root, "release.ps1")), StringComparison.Ordinal);
    }

    /// <summary>Claude Code's own validator, when the claude CLI is on PATH (CORVUS_CLAUDE names another).</summary>
    [Fact]
    [Trait("Speed", "Slow")]
    public async Task ClaudeCodeValidatesTheManifests()
    {
        var claude = Environment.GetEnvironmentVariable("CORVUS_CLAUDE") ?? BundleTests.FindOnPath(OperatingSystem.IsWindows() ? "claude.exe" : "claude");
        if (claude is null) return; // no claude CLI on this machine
        foreach (var target in new[] { ".claude-plugin/plugin.json", ".claude-plugin/marketplace.json" })
        {
            ProcessStartInfo start = new(claude) { RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = Root };
            foreach (var arg in new[] { "plugin", "validate", "--strict", target }) start.ArgumentList.Add(arg);
            using var process = Process.Start(start)!;
            var output = process.StandardOutput.ReadToEndAsync();
            var error = await process.StandardError.ReadToEndAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            await process.WaitForExitAsync(timeout.Token);
            Assert.True(process.ExitCode == 0, $"claude plugin validate --strict {target}:\n{await output}\n{error}");
        }
    }
}
