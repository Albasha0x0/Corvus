using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>Client folders moved by environment variables, and XDG_CONFIG_HOME.</summary>
public sealed class ClientHomeTests : IDisposable
{
    private readonly SetupHome _home = new();
    public void Dispose() => _home.Dispose();

    private McpClient Client(string id, Dictionary<string, string>? variables = null, HostOs? os = null) =>
        ClientCatalog.All(_home.Env(variables: variables, os: os)).Single(c => c.Id == id);

    [Fact]
    public void ClaudeConfigDir_HoldsTheConfigFile_AndMarksDetection()
    {
        var dir = _home.Path("claude-profile");
        var vars = new Dictionary<string, string> { ["CLAUDE_CONFIG_DIR"] = dir };
        Assert.False(Client("claude-code", vars).Present);
        Directory.CreateDirectory(dir);
        var client = Client("claude-code", vars);
        Assert.True(client.Present);
        Assert.Equal(Path.Combine(dir, ".claude.json"), client.Target.Path);
        var (code, output) = _home.Run(_home.Env(variables: vars), "install", "--no-check", "--yes");
        Assert.True(code == 0, output);
        Assert.True(File.Exists(Path.Combine(dir, ".claude.json")));
        Assert.False(File.Exists(_home.Path(".claude.json")));
    }

    [Fact]
    public void GeminiQwenAndCopilotHomes()
    {
        var vars = new Dictionary<string, string>
        {
            ["GEMINI_CLI_HOME"] = _home.Path("g"),
            ["QWEN_HOME"] = "~/qwen-home",
            ["COPILOT_HOME"] = _home.Path("cp"),
        };
        Assert.Equal(_home.Path("g", ".gemini", "settings.json"), Client("gemini-cli", vars).Target.Path);
        Assert.Equal(_home.Path("qwen-home", "settings.json"), Client("qwen-code", vars).Target.Path);
        Assert.Equal(_home.Path("cp", "mcp-config.json"), Client("copilot-cli", vars).Target.Path);
        Assert.Equal(Path.GetFullPath(Path.Combine("rel", "settings.json")), Client("qwen-code", new() { ["QWEN_HOME"] = "rel" }).Target.Path);
        Assert.Equal(_home.Path("settings.json"), Client("qwen-code", new() { ["QWEN_HOME"] = "~" }).Target.Path);
        // Empty means unset.
        Assert.Equal(_home.Path(".copilot", "mcp-config.json"), Client("copilot-cli", new() { ["COPILOT_HOME"] = "" }).Target.Path);
    }

    [Fact]
    public void OpenCode_FollowsItsOverridePrecedence()
    {
        var xdg = _home.Path("xdg");
        Assert.Equal(Path.Combine(xdg, "opencode", "opencode.json"), Client("opencode", new() { ["XDG_CONFIG_HOME"] = xdg }).Target.Path);
        _home.Write("{}", "xdg", "opencode", "opencode.jsonc");
        Assert.Equal(Path.Combine(xdg, "opencode", "opencode.jsonc"), Client("opencode", new() { ["XDG_CONFIG_HOME"] = xdg }).Target.Path);

        var file = _home.Path("custom", "oc.json");
        Assert.Equal(file, Client("opencode", new() { ["XDG_CONFIG_HOME"] = xdg, ["OPENCODE_CONFIG"] = file }).Target.Path);
        var dir = _home.Path("oc-dir");
        var both = Client("opencode", new() { ["OPENCODE_CONFIG"] = file, ["OPENCODE_CONFIG_DIR"] = dir });
        Assert.Equal(Path.Combine(dir, "opencode.json"), both.Target.Path);
        Assert.False(both.Present);
        Directory.CreateDirectory(dir);
        Assert.True(Client("opencode", new() { ["OPENCODE_CONFIG_DIR"] = dir }).Present);
    }

    [Fact]
    public void XdgConfigHome_MovesCrushZedAndClaudeDesktopOnLinux()
    {
        var xdg = _home.Path("xdg");
        var vars = new Dictionary<string, string> { ["XDG_CONFIG_HOME"] = xdg };
        Assert.Equal(Path.Combine(xdg, "crush", "crush.json"), Client("crush", vars, HostOs.Linux).Target.Path);
        Assert.Equal(Path.Combine(xdg, "crush", "crush.json"), Client("crush", vars, HostOs.Windows).Target.Path);
        Assert.Equal(_home.Path(".config", "crush", "crush.json"), Client("crush", null, HostOs.MacOs).Target.Path);
        Assert.Equal(Path.Combine(xdg, "zed", "settings.json"), Client("zed", vars, HostOs.Linux).Target.Path);
        Assert.Equal(_home.Path(".config", "zed", "settings.json"), Client("zed", vars, HostOs.MacOs).Target.Path);

        var desktop = Client("claude-desktop", vars, HostOs.Linux);
        Assert.Equal(Path.Combine(xdg, "Claude", "claude_desktop_config.json"), desktop.Target.Path);
        Assert.False(desktop.Present);
        Directory.CreateDirectory(Path.Combine(xdg, "Claude"));
        Assert.True(Client("claude-desktop", vars, HostOs.Linux).Present);
    }
}
