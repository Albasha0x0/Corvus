using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>Entry shapes of the newer clients, OMP and Pi folders, disabled entries and the README client list.</summary>
public sealed class ClientCatalogTests : IDisposable
{
    private readonly SetupHome _home = new();
    public void Dispose() => _home.Dispose();

    private static readonly JsonDocumentOptions Lenient = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };
    private static JsonNode ReadJson(string path) => JsonNode.Parse(File.ReadAllText(path), documentOptions: Lenient)!;

    private McpClient Client(string id, Dictionary<string, string>? variables = null) =>
        ClientCatalog.All(_home.Env(variables: variables)).Single(c => c.Id == id);

    [Fact]
    public void NewClients_GetTheirOwnEntryShapes()
    {
        var (code, output) = _home.Run("install", "--no-check", "--client", "devin,command-code,grok-build,omp,pi");
        Assert.True(code == 0, output);
        JsonNode Entry(string id) => ReadJson(Client(id).Target.Path)["mcpServers"]!["net-decompiler"]!;

        var devin = Entry("devin");
        Assert.Equal(SetupHome.Launch.Command, devin["command"]!.GetValue<string>());
        Assert.Null(devin["type"]);
        var commandCode = Entry("command-code");
        Assert.Equal("stdio", commandCode["transport"]!.GetValue<string>());
        Assert.True(commandCode["enabled"]!.GetValue<bool>());
        Assert.Equal(_home.Path(".commandcode", "mcp.json"), Client("command-code").Target.Path);
        Assert.Equal("stdio", Entry("omp")["type"]!.GetValue<string>());
        Assert.Equal(_home.Path(".omp", "agent", "mcp.json"), Client("omp").Target.Path);
        Assert.Equal("stdio", Entry("pi")["type"]!.GetValue<string>());
        Assert.Equal(_home.Path(".pi", "agent", "mcp.json"), Client("pi").Target.Path);
        var grok = File.ReadAllText(_home.Path(".grok", "config.toml"));
        Assert.Contains("[mcp_servers.net-decompiler]\ncommand = " + JsonSerializer.Serialize(SetupHome.Launch.Command), grok);
        Assert.Equal(_home.Path("gh", "config.toml"), Client("grok-build", new() { ["GROK_HOME"] = _home.Path("gh") }).Target.Path);
    }

    [Fact]
    public void OmpAndPi_FollowProfilesAndAgentFolders()
    {
        Assert.Equal(_home.Path(".omp", "profiles", "work", "agent", "mcp.json"), Client("omp", new() { ["OMP_PROFILE"] = "work" }).Target.Path);
        Assert.Equal(_home.Path(".omp", "agent", "mcp.json"), Client("omp", new() { ["OMP_PROFILE"] = "default" }).Target.Path);
        Assert.Equal(_home.Path("alt", "profiles", "p1", "agent", "mcp.json"), Client("omp", new() { ["PI_CONFIG_DIR"] = "alt", ["PI_PROFILE"] = "p1" }).Target.Path);
        // A named profile ignores PI_CODING_AGENT_DIR; without one it applies.
        var agent = _home.Path("agent-dir");
        Assert.Equal(Path.Combine(agent, "mcp.json"), Client("omp", new() { ["PI_CODING_AGENT_DIR"] = agent }).Target.Path);
        Assert.Equal(_home.Path(".omp", "profiles", "w", "agent", "mcp.json"), Client("omp", new() { ["PI_CODING_AGENT_DIR"] = agent, ["OMP_PROFILE"] = "w" }).Target.Path);

        var bad = _home.Env(variables: new Dictionary<string, string> { ["OMP_PROFILE"] = "Bad!" });
        var (code, output) = _home.Run(bad, "install", "--no-check", "--client", "omp");
        Assert.Equal(1, code);
        Assert.Contains("invalid OMP profile", output);
        Assert.IsType<InvalidTarget>(Client("omp", new() { ["OMP_PROFILE"] = "nul" }).Target);
        Assert.IsType<InvalidTarget>(Client("omp", new() { ["OMP_PROFILE"] = "a." }).Target);

        Assert.Equal(_home.Path("pa", "mcp.json"), Client("pi", new() { ["PI_CODING_AGENT_DIR"] = "~/pa" }).Target.Path);
    }

    [Fact]
    public void DisabledEntries_AreDetected_AndKeptDisabledOnRefresh()
    {
        _home.Write("""{ "mcpServers": { "net-decompiler": { "command": "old", "disabled": true } } }""", ".cursor", "mcp.json");
        _home.Write("""{ "mcpServers": { "net-decompiler": { "transport": "stdio", "command": "old", "enabled": false } } }""", ".commandcode", "mcp.json");
        _home.Write("""{ "disabledServers": ["net-decompiler"], "mcpServers": { "net-decompiler": { "command": "old" } } }""", ".omp", "agent", "mcp.json");
        _home.Write("disabled_mcp_servers = [\"other\", 'net-decompiler']\n\n[mcp_servers.net-decompiler]\ncommand = \"old\"\n", ".grok", "config.toml");
        _home.Write("[mcp_servers.net-decompiler]\ncommand = \"old\"\nenabled = false\n", ".codex", "config.toml");
        foreach (var id in new[] { "cursor", "command-code", "omp", "grok-build", "codex" })
            Assert.True(Client(id).Target.Current("net-decompiler")!.Disabled, id);

        // An allowlist turns an OMP entry back on; the denylist wins over it.
        _home.Write("""{ "enabledServers": ["net-decompiler"], "mcpServers": { "net-decompiler": { "command": "old", "enabled": false } } }""", ".omp", "agent", "mcp.json");
        Assert.False(Client("omp").Target.Current("net-decompiler")!.Disabled);
        _home.Write("""{ "mcpServers": { "net-decompiler": { "command": "old", "disabled": true } } }""", ".omp", "agent", "mcp.json");

        var (code, output) = _home.Run("install", "--no-check");
        Assert.True(code == 0, output);
        Assert.Contains("kept disabled", output);
        Assert.True(ReadJson(_home.Path(".cursor", "mcp.json"))["mcpServers"]!["net-decompiler"]!["disabled"]!.GetValue<bool>());
        Assert.False(ReadJson(_home.Path(".commandcode", "mcp.json"))["mcpServers"]!["net-decompiler"]!["enabled"]!.GetValue<bool>());
        Assert.Contains("enabled = false", File.ReadAllText(_home.Path(".codex", "config.toml")));
        Assert.All(new[] { "cursor", "command-code", "grok-build", "codex" }, id =>
            Assert.Equal(SetupHome.Launch.Command, Client(id).Target.Current("net-decompiler")!.Command));
    }

    [Fact]
    public void ReadmeClientList_MatchesTheCatalog()
    {
        var readme = File.ReadAllText(Path.Combine(RepoRoot(), "README.md")).Replace("\r\n", "\n");
        var sentence = Regex.Match(readme, @"Supported clients: (?<list>[^.]+)\.").Groups["list"].Value.Replace("\n", " ");
        var listed = Regex.Split(sentence, @",\s*|\s+and\s+").Select(s => s.Trim()).Where(s => s.Length > 0).Order(StringComparer.Ordinal);
        var catalog = ClientCatalog.All(_home.Env(os: HostOs.Windows)).Select(c => c.Name).Order(StringComparer.Ordinal);
        Assert.Equal(catalog, listed);
        var help = _home.Run("help").Output;
        foreach (var client in ClientCatalog.All(_home.Env())) Assert.Contains(client.Id, help);
    }

    private static string RepoRoot()
    {
        var root = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(root, "Corvus.slnx"))) root = Path.GetDirectoryName(root) ?? throw new InvalidOperationException("repository root not found");
        return root;
    }
}
