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
        JsonNode Entry(string id) => ReadJson(Client(id).Target.Path)["mcpServers"]!["corvus"]!;

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
        Assert.Contains("[mcp_servers.corvus]\ncommand = " + JsonSerializer.Serialize(SetupHome.Launch.Command), grok);
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
        _home.Write("""{ "mcpServers": { "corvus": { "command": "old", "disabled": true } } }""", ".cursor", "mcp.json");
        _home.Write("""{ "mcpServers": { "corvus": { "transport": "stdio", "command": "old", "enabled": false } } }""", ".commandcode", "mcp.json");
        _home.Write("""{ "disabledServers": ["corvus"], "mcpServers": { "corvus": { "command": "old" } } }""", ".omp", "agent", "mcp.json");
        _home.Write("disabled_mcp_servers = [\"other\", 'corvus']\n\n[mcp_servers.corvus]\ncommand = \"old\"\n", ".grok", "config.toml");
        _home.Write("[mcp_servers.corvus]\ncommand = \"old\"\nenabled = false\n", ".codex", "config.toml");
        foreach (var id in new[] { "cursor", "command-code", "omp", "grok-build", "codex" })
            Assert.True(Client(id).Target.Current("corvus")!.Disabled, id);

        // An allowlist turns an OMP entry back on; the denylist wins over it.
        _home.Write("""{ "enabledServers": ["corvus"], "mcpServers": { "corvus": { "command": "old", "enabled": false } } }""", ".omp", "agent", "mcp.json");
        Assert.False(Client("omp").Target.Current("corvus")!.Disabled);
        _home.Write("""{ "mcpServers": { "corvus": { "command": "old", "disabled": true } } }""", ".omp", "agent", "mcp.json");

        var (code, output) = _home.Run("install", "--no-check");
        Assert.True(code == 0, output);
        Assert.Contains("kept disabled", output);
        Assert.True(ReadJson(_home.Path(".cursor", "mcp.json"))["mcpServers"]!["corvus"]!["disabled"]!.GetValue<bool>());
        Assert.False(ReadJson(_home.Path(".commandcode", "mcp.json"))["mcpServers"]!["corvus"]!["enabled"]!.GetValue<bool>());
        Assert.Contains("enabled = false", File.ReadAllText(_home.Path(".codex", "config.toml")));
        Assert.All(new[] { "cursor", "command-code", "grok-build", "codex" }, id =>
            Assert.Equal(SetupHome.Launch.Command, Client(id).Target.Current("corvus")!.Command));
    }

    [Fact]
    public void Enable_TurnsDisabledEntriesOn_IncludingDisableListsAndClaudeCodeProjects()
    {
        _home.Write("""{ "mcpServers": { "corvus": { "command": "old", "disabled": true } } }""", ".cursor", "mcp.json");
        _home.Write("""{ "mcpServers": { "corvus": { "transport": "stdio", "command": "old", "enabled": false } } }""", ".commandcode", "mcp.json");
        _home.Write("""{ "disabledServers": ["x", "corvus"], "mcpServers": { "corvus": { "command": "old" } } }""", ".omp", "agent", "mcp.json");
        _home.Write("disabled_mcp_servers = [\"other\", 'corvus']\n\n[mcp_servers.corvus]\ncommand = \"old\"\n", ".grok", "config.toml");
        _home.Write("[mcp_servers.corvus]\ncommand = \"old\"\nenabled = false\n", ".codex", "config.toml");
        _home.Write("""{ "mcpServers": { "corvus": { "command": "old" } }, "projects": { "D:/a": { "disabledMcpServers": ["corvus"] }, "D:/b": { "disabledMcpServers": ["y"] } } }""", ".claude.json");
        Assert.Equal(["D:/a"], Client("claude-code").Target.DisabledInProjects("corvus"));

        // Without --enable they stay off, and the output says how to turn them on.
        var (code, output) = _home.Run("install", "--no-check");
        Assert.True(code == 0, output);
        Assert.Contains("off in projects D:/a (--enable turns it on)", output);
        Assert.True(Client("cursor").Target.Current("corvus")!.Disabled);

        (code, output) = _home.Run("install", "--no-check", "--enable");
        Assert.True(code == 0, output);
        foreach (var id in new[] { "cursor", "command-code", "omp", "grok-build", "codex", "claude-code" })
            Assert.False(Client(id).Target.Current("corvus")!.Disabled, id);
        Assert.Empty(Client("claude-code").Target.DisabledInProjects("corvus"));
        Assert.Equal(["y"], ReadJson(_home.Path(".claude.json"))["projects"]!["D:/b"]!["disabledMcpServers"]!.AsArray().Select(n => (string)n!));
        Assert.Contains("disabled_mcp_servers = [\"other\"]", File.ReadAllText(_home.Path(".grok", "config.toml")));
        Assert.DoesNotContain("enabled = false", File.ReadAllText(_home.Path(".codex", "config.toml")));
        Assert.Equal(["x"], ReadJson(_home.Path(".omp", "agent", "mcp.json"))["disabledServers"]!.AsArray().Select(n => (string)n!));
        Assert.DoesNotContain("enabled", _home.Run("install", "--no-check", "--enable").Output.Replace("--enable", ""));
    }

    [Fact]
    public void ASlowStart_GetsALongerStartupTimeout_OnlyWhenNeeded()
    {
        Assert.False(CodexTomlTarget.NeedsStartupTimeout(1.2, null));
        Assert.True(CodexTomlTarget.NeedsStartupTimeout(6, null));
        Assert.True(CodexTomlTarget.NeedsStartupTimeout(6, 10));
        Assert.False(CodexTomlTarget.NeedsStartupTimeout(6, 30));

        _home.Write("[mcp_servers.corvus]\ncommand = \"c\"\nargs = []\n\n[mcp_servers.corvus.env]\nA = \"1\"\n\n[profiles.x]\nm = 1\n", ".codex", "config.toml");
        var target = (CodexTomlTarget)Client("codex").Target;
        Assert.True(target.SetStartupTimeout("corvus", 30).Changed);
        Assert.Equal("[mcp_servers.corvus]\ncommand = \"c\"\nargs = []\nstartup_timeout_sec = 30\n\n[mcp_servers.corvus.env]\nA = \"1\"\n\n[profiles.x]\nm = 1\n",
            File.ReadAllText(_home.Path(".codex", "config.toml")));
        Assert.Equal(30, target.Current("corvus")!.StartupTimeout);
        Assert.False(target.SetStartupTimeout("corvus", 30).Changed);
        Assert.False(target.SetStartupTimeout("other", 30).Changed);
    }

    [Fact]
    public void EveryClientEntry_CarriesItsClientId()
    {
        var env = _home.Env(os: HostOs.Windows);
        var all = ClientCatalog.All(env);
        Assert.Equal(27, all.Count);
        var output = new StringWriter();
        Assert.Equal(0, SetupCli.TryRun(["install", "--no-check", "--client", string.Join(",", all.Select(c => c.Id))], output, env, SetupHome.Launch));
        foreach (var client in ClientCatalog.All(env))
        {
            var args = client.Target.Current("corvus")?.Args ?? throw new Xunit.Sdk.XunitException($"{client.Id}: not registered\n{output}");
            Assert.True(args.Count >= 2 && args[0] == "--client" && args[1] == client.Id, $"{client.Id}: {string.Join(" ", args)}");
            bool lean = Corvus.Core.ClientProfiles.Find(client.Id)!.DefaultProfile == "lean";
            Assert.Equal(lean, args.SequenceEqual(["--client", client.Id, "--toolsets", "lean"]));
            if (!lean) Assert.Equal(["--client", client.Id], args);
        }
        // A second install changes nothing.
        output = new StringWriter();
        Assert.Equal(0, SetupCli.TryRun(["install", "--no-check"], output, env, SetupHome.Launch));
        Assert.DoesNotContain("registered ", output.ToString().Replace("already registered", ""));
    }

    [Fact]
    public void ClientOptions_ReplaceStaleOnes_AndAUsersToolsetsWins()
    {
        _home.Write("""{ "servers": { "corvus": { "type": "stdio", "command": "old", "args": ["--client", "cursor", "--toolsets", "core", "--load", "x"] } } }""",
            "AppData", "Roaming", "Code", "User", "mcp.json");
        var (code, output) = _home.Run(_home.Env(os: HostOs.Windows), "install", "--no-check", "--client", "vscode");
        Assert.True(code == 0, output);
        Assert.Equal(["--client", "vscode", "--toolsets", "core", "--load", "x"], Client("vscode").Target.Current("corvus")!.Args);
    }

    [Fact]
    public void ARaisedCodexToolTimeout_IsPassedOn_ButNeverWritten()
    {
        var before = "[mcp_servers.corvus]\ncommand = \"old\"\nargs = [\"--client\", \"codex\", \"--client-timeout\", \"90\"]\ntool_timeout_sec = 300\n";
        _home.Write(before, ".codex", "config.toml");
        var (code, output) = _home.Run("install", "--no-check", "--client", "codex");
        Assert.True(code == 0, output);
        var toml = File.ReadAllText(_home.Path(".codex", "config.toml"));
        Assert.Contains("args = [\"--client\", \"codex\", \"--client-timeout\", \"300\"]\ntool_timeout_sec = 300\n", toml);
        // Back at the default: no option.
        _home.Write(toml.Replace("tool_timeout_sec = 300", "tool_timeout_sec = 60"), ".codex", "config.toml");
        Assert.Equal(0, _home.Run("install", "--no-check", "--client", "codex").Code);
        Assert.Contains("args = [\"--client\", \"codex\"]\ntool_timeout_sec = 60\n", File.ReadAllText(_home.Path(".codex", "config.toml")));
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
