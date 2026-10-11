using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary>server_status identity, the unavailable-tools table and the client _meta keys.</summary>
[Collection(InProcessCatalogCollection.Name)]
public class ServerIdentityTests
{
    private static readonly List<System.Text.Json.Nodes.JsonNode> AllTools = Catalog.OfThisBuild().Tools;

    [Fact]
    public void InstallKindFollowsThePath()
    {
        using var dir = new TempDir();
        var versioned = Path.Combine(dir.Path, "versions", "1.2.0");
        Directory.CreateDirectory(versioned);
        Directory.CreateDirectory(Path.Combine(dir.Path, "current"));
        Assert.Equal("script", ServerIdentity.ClassifyInstall(Path.Combine(versioned, "corvus.exe")));
        Assert.Equal("script", ServerIdentity.ClassifyInstall(Path.Combine(dir.Path, "current", "corvus.exe")));
        var home = Path.Combine(dir.Path, "home");
        Assert.Equal("dotnet-tool", ServerIdentity.ClassifyInstall(Path.Combine(home, ".dotnet", "tools", ".store", "corvusre", "1.2.0", "x.exe")));
        Assert.Equal("dnx", ServerIdentity.ClassifyInstall(Path.Combine(home, ".nuget", "packages", "corvusre", "1.2.0", "tools", "x.exe")));
        Assert.Equal("winget", ServerIdentity.ClassifyInstall(Path.Combine(home, "AppData", "Local", "Microsoft", "WinGet", "Packages", "P", "x.exe")));
        Assert.Equal("scoop", ServerIdentity.ClassifyInstall(Path.Combine(home, "scoop", "apps", "corvus", "current", "x.exe")));
        Assert.Equal("homebrew", ServerIdentity.ClassifyInstall(Path.Combine(dir.Path, "opt", "homebrew", "Caskroom", "corvus", "1.2.0", "x")));
        Assert.Equal("source", ServerIdentity.ClassifyInstall(Path.Combine(dir.Path, "bin", "Debug", "net10.0", "corvus.dll")));
    }

    [Fact]
    public void IdentityOfThisProcess()
    {
        Assert.StartsWith(typeof(ServerOptions).Assembly.GetName().Version!.ToString(3), ServerIdentity.InformationalVersion);
        if (ServerIdentity.Commit is { } commit) Assert.Matches("^[0-9a-f]{7,40}$", commit);
        Assert.True(ServerIdentity.StartedAt <= DateTimeOffset.UtcNow);
        Assert.True(File.Exists(ServerIdentity.Executable), ServerIdentity.Executable);
    }

    [Fact]
    public void SamePathNormalizesAndFollowsLinks()
    {
        using var dir = new TempDir();
        var real = Directory.CreateDirectory(Path.Combine(dir.Path, "versions", "1.0")).FullName;
        File.WriteAllText(Path.Combine(real, "a.exe"), "");
        Assert.True(ServerIdentity.SamePath(Path.Combine(dir.Path, "versions", ".", "1.0", "a.exe"), Path.Combine(real, "a.exe")));
        Assert.False(ServerIdentity.SamePath(Path.Combine(dir.Path, "other", "a.exe"), Path.Combine(real, "a.exe")));
        var link = Path.Combine(dir.Path, "current");
        try { Directory.CreateSymbolicLink(link, real); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return; } // no symlink privilege here
        Assert.True(ServerIdentity.SamePath(Path.Combine(link, "a.exe"), Path.Combine(real, "a.exe")));
    }

    [Fact]
    public void AvailabilityTableNamesOnlyTools()
    {
        var names = AllTools.Select(t => (string)t["name"]!).ToHashSet(StringComparer.Ordinal);
        Assert.All(ToolAvailability.NamedTools, t => Assert.Contains(t, names));
    }

    [Fact]
    public void UnavailableToolsFollowTheEngines()
    {
        var all = AllTools.Select(t => (string)t["name"]!).ToHashSet(StringComparer.Ordinal);
        var noIda = new ProviderAvailability("ida", false, "IDA not found", "set IDADIR", new Dictionary<string, string>());
        var noGhidra = new ProviderAvailability("ghidra", false, "Ghidra not found", "set CORVUS_GHIDRA_DIR", new Dictionary<string, string>());
        var rows = ToolAvailability.Of(all, [noIda, noGhidra], idaScripting: false, isWindows: false);
        Assert.Contains(rows, r => r is { Tool: "decompile_native", Mode: null, Reason: "ida: IDA not found; ghidra: Ghidra not found", Remediation: "set IDADIR; or set CORVUS_GHIDRA_DIR" });
        Assert.Contains(rows, r => r is { Tool: "ida_python", Mode: null, Reason: "IDA not found", Remediation: "set IDADIR" });
        Assert.Contains(rows, r => r is { Tool: "set_native_type", Mode: null, Reason: "ida: IDA not found; ghidra: Ghidra not found" });
        Assert.Contains(rows, r => r is { Tool: "disassemble", Mode: "engine=ida" });
        Assert.Contains(rows, r => r is { Tool: "disassemble", Mode: "engine=ghidra", Reason: "Ghidra not found" });
        Assert.Contains(rows, r => r is { Tool: "find_virtual_calls", Mode: "crossCheck=true" });
        Assert.Contains(rows, r => r is { Tool: "inspect_process", Mode: null });
        Assert.DoesNotContain(rows, r => r.Tool == "decompile_native" && r.Mode != null);

        var ida = noIda with { IsAvailable = true, Reason = null };
        var ghidra = noGhidra with { IsAvailable = true, Reason = null };
        var withIda = ToolAvailability.Of(all, [ida, ghidra], idaScripting: false, isWindows: true);
        Assert.Equal(["ida_python", "ghidra_script"], withIda.Where(r => !ToolAvailability.ExternalProgramTools.Contains(r.Tool)).Select(r => r.Tool));
        Assert.DoesNotContain(ToolAvailability.Of(all, [ida, ghidra], idaScripting: true, isWindows: true), r => r.Tool == "ida_python");
        // Ghidra alone serves decompile_native and the engine=ghidra modes
        var ghidraOnly = ToolAvailability.Of(all, [noIda, ghidra], idaScripting: false, isWindows: true);
        Assert.DoesNotContain(ghidraOnly, r => r.Tool == "decompile_native" || r.Mode == "engine=ghidra");
        Assert.Contains(ghidraOnly, r => r is { Tool: "find_xrefs", Mode: "engine=ida" });
        // Only registered tools are reported.
        Assert.Empty(ToolAvailability.Of(Toolsets.Families.Single(f => f.Name == "dotnet").Tools.ToHashSet(), [noIda], false, false));
    }

    [Fact]
    public void ClientMetaKeys()
    {
        Assert.True(ToolEffects.MaxResultSizeChars >= new ServerOptions().MaxOutputChars + ResponseBudget.Slack);
        foreach (var tool in AllTools)
        {
            var name = (string)tool["name"]!;
            Assert.Equal(ToolEffects.MaxResultSizeChars, (int)tool["_meta"]![ToolEffects.MaxResultSizeMetaKey]!);
            Assert.Equal(ToolEffects.AlwaysLoad.Contains(name), tool["_meta"]![ToolEffects.AlwaysLoadMetaKey] is { } v && (bool)v);
        }
    }
}
