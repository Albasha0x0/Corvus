using System.Text.Json.Nodes;
using NetDecompilerMcp.Setup;

namespace NetDecompilerMcp.Tests;

/// <summary>Client registration against a throwaway home folder.</summary>
public sealed class SetupTests : IDisposable
{
    private readonly TempDir _home = new();
    private readonly SetupEnvironment _env;
    private static readonly ServerLaunch Launch = new(
        OperatingSystem.IsWindows() ? @"C:\Tools\NetDecompilerMcp\current\NetDecompilerMcp.exe" : "/opt/ndm/current/NetDecompilerMcp", []);

    public SetupTests()
    {
        var os = OperatingSystem.IsWindows() ? HostOs.Windows : OperatingSystem.IsMacOS() ? HostOs.MacOs : HostOs.Linux;
        _env = new SetupEnvironment
        {
            Os = os,
            Home = _home.Path,
            AppData = Path.Combine(_home.Path, "AppData", "Roaming"),
            LocalAppData = Path.Combine(_home.Path, "AppData", "Local"),
            XdgConfig = Path.Combine(_home.Path, ".config"),
            Variable = _ => null,
        };
    }

    public void Dispose() => _home.Dispose();

    private string Home(params string[] parts) => Path.Combine([_home.Path, .. parts]);

    private (int Code, string Output) Run(params string[] args)
    {
        var output = new StringWriter();
        var code = SetupCli.TryRun(args, output, _env, Launch);
        Assert.NotNull(code);
        return (code!.Value, output.ToString());
    }

    private static JsonNode ReadJson(string path) => JsonNode.Parse(File.ReadAllText(path))!;

    [Fact]
    public void Install_RegistersWithDetectedClients_AndKeepsTheirOtherSettings()
    {
        Directory.CreateDirectory(Home(".cursor"));
        File.WriteAllText(Home(".cursor", "mcp.json"), """{ "mcpServers": { "other": { "command": "x" } }, "theme": "dark" }""");
        Directory.CreateDirectory(Home(".codex"));
        File.WriteAllText(Home(".codex", "config.toml"), "model = \"o4\"\n\n[mcp_servers.other]\ncommand = \"y\"\n\n[profiles.fast]\nmodel = \"mini\"\n");
        File.WriteAllText(Home(".claude.json"), """{ "numStartups": 3, "projects": {} }""");
        var zed = _env.Os == HostOs.Windows ? Path.Combine(_env.AppData, "Zed") : Home(".config", "zed");
        Directory.CreateDirectory(zed);
        File.WriteAllText(Path.Combine(zed, "settings.json"), "// Zed settings\n{\n  \"ui_font_size\": 16, // trailing comment\n}\n");

        var (code, output) = Run("install", "--no-check");
        Assert.True(code == 0, output);

        var cursor = ReadJson(Home(".cursor", "mcp.json"));
        Assert.Equal(Launch.Command, cursor["mcpServers"]!["net-decompiler"]!["command"]!.GetValue<string>());
        Assert.Equal("x", cursor["mcpServers"]!["other"]!["command"]!.GetValue<string>());
        Assert.Equal("dark", cursor["theme"]!.GetValue<string>());

        var toml = File.ReadAllText(Home(".codex", "config.toml"));
        Assert.Contains("[mcp_servers.other]\ncommand = \"y\"", toml);
        Assert.Contains("[profiles.fast]\nmodel = \"mini\"", toml);
        Assert.Contains("[mcp_servers.net-decompiler]\ncommand = " + System.Text.Json.JsonSerializer.Serialize(Launch.Command), toml);

        var claude = ReadJson(Home(".claude.json"));
        Assert.Equal("stdio", claude["mcpServers"]!["net-decompiler"]!["type"]!.GetValue<string>());
        Assert.Equal(3, claude["numStartups"]!.GetValue<int>());

        var zedSettings = ReadJson(Path.Combine(zed, "settings.json"));
        Assert.Equal(16, zedSettings["ui_font_size"]!.GetValue<int>());
        Assert.Equal(Launch.Command, zedSettings["context_servers"]!["net-decompiler"]!["command"]!.GetValue<string>());
        Assert.Contains("comments were not kept", output);
        Assert.True(File.Exists(Path.Combine(zed, "settings.json.netdecompiler.bak")));

        // Clients that are not installed get no files.
        Assert.False(Directory.Exists(Home(".kiro")));
        Assert.DoesNotContain("Kiro", output);
    }

    [Fact]
    public void Install_IsIdempotent_AndUninstallRemovesOnlyItsEntry()
    {
        Directory.CreateDirectory(Home(".cursor"));
        File.WriteAllText(Home(".cursor", "mcp.json"), """{ "mcpServers": { "other": { "command": "x" } } }""");
        Directory.CreateDirectory(Home(".codex"));
        File.WriteAllText(Home(".codex", "config.toml"), "[mcp_servers.other]\ncommand = \"y\"\n");

        Assert.Equal(0, Run("install", "--no-check").Code);
        var cursorAfterFirst = File.ReadAllText(Home(".cursor", "mcp.json"));
        var tomlAfterFirst = File.ReadAllText(Home(".codex", "config.toml"));
        var (code, output) = Run("install", "--no-check");
        Assert.Equal(0, code);
        Assert.Contains("already registered", output);
        Assert.DoesNotContain("Restart", output);
        Assert.Equal(cursorAfterFirst, File.ReadAllText(Home(".cursor", "mcp.json")));
        Assert.Equal(tomlAfterFirst, File.ReadAllText(Home(".codex", "config.toml")));

        (code, output) = Run("uninstall", "--keep-files");
        Assert.Equal(0, code);
        Assert.Contains("removed", output);
        var cursor = ReadJson(Home(".cursor", "mcp.json"));
        Assert.Null(cursor["mcpServers"]!["net-decompiler"]);
        Assert.NotNull(cursor["mcpServers"]!["other"]);
        Assert.Equal("[mcp_servers.other]\ncommand = \"y\"\n", File.ReadAllText(Home(".codex", "config.toml")));
    }

    [Fact]
    public void Install_NeverOverwritesAFileItCannotParse()
    {
        Directory.CreateDirectory(Home(".cursor"));
        File.WriteAllText(Home(".cursor", "mcp.json"), "{ this is not json");
        var (code, output) = Run("install", "--no-check");
        Assert.Equal(1, code);
        Assert.Contains("left unchanged", output);
        Assert.Equal("{ this is not json", File.ReadAllText(Home(".cursor", "mcp.json")));
    }

    [Fact]
    public void NamedClients_AreRegisteredEvenWhenNotDetected_AndUnknownNamesAreRejected()
    {
        var (code, output) = Run("install", "--no-check", "kiro", "VS Code");
        Assert.True(code == 0, output);
        Assert.Equal(Launch.Command, ReadJson(Home(".kiro", "settings", "mcp.json"))["mcpServers"]!["net-decompiler"]!["command"]!.GetValue<string>());
        var vscode = Path.Combine(_env.AppSupport("Code"), "User", "mcp.json");
        Assert.Equal("stdio", ReadJson(vscode)["servers"]!["net-decompiler"]!["type"]!.GetValue<string>());

        (code, output) = Run("install", "--no-check", "notepad");
        Assert.Equal(2, code);
        Assert.Contains("Unknown client 'notepad'", output);
    }

    [Fact]
    public void ClientFormats_FollowEachClientsSchema()
    {
        Run("install", "--no-check", "opencode", "copilot", "roo-code", "crush");
        var opencode = ReadJson(Home(".config", "opencode", "opencode.json"))["mcp"]!["net-decompiler"]!;
        Assert.Equal("local", opencode["type"]!.GetValue<string>());
        Assert.Equal(Launch.Command, opencode["command"]![0]!.GetValue<string>());
        var copilot = ReadJson(Home(".copilot", "mcp-config.json"))["mcpServers"]!["net-decompiler"]!;
        Assert.Equal("*", copilot["tools"]![0]!.GetValue<string>());
        var roo = ClientCatalog.All(_env).Single(c => c.Id == "roo-code").Target.Path;
        Assert.False(ReadJson(roo)["mcpServers"]!["net-decompiler"]!["disabled"]!.GetValue<bool>());
        var crush = ClientCatalog.All(_env).Single(c => c.Id == "crush").Target.Path;
        Assert.Equal("stdio", ReadJson(crush)["mcp"]!["net-decompiler"]!["type"]!.GetValue<string>());
    }

    [Fact]
    public void Codex_PathsWithQuotesAndBackslashesRoundTrip()
    {
        var launch = new ServerLaunch(@"C:\Users\O""Brien\ndm\NetDecompilerMcp.exe", ["--load", @"D:\App\Managed"]);
        var target = new CodexTomlTarget(Home("config.toml"));
        Assert.True(target.Install("net-decompiler", launch).Changed);
        Assert.Equal(launch.Command, target.Registered("net-decompiler"));
        Assert.Contains("args = [\"--load\", \"D:\\\\App\\\\Managed\"]", File.ReadAllText(Home("config.toml")));
        Assert.False(target.Install("net-decompiler", launch).Changed);
    }

    [Fact]
    public void Status_ReportsRegistrations_AndSelfTestStartsTheRealServer()
    {
        Directory.CreateDirectory(Home(".cursor"));
        File.WriteAllText(Home(".cursor", "mcp.json"), """{ "mcpServers": { "net-decompiler": { "command": "C:/gone/NetDecompilerMcp.exe" } } }""");
        var output = new StringWriter();
        var server = new ServerLaunch("dotnet", [typeof(NetDecompilerMcp.Core.AssemblyWorkspace).Assembly.Location]);
        var code = SetupCli.TryRun(["status"], output, _env, server);
        Assert.True(code == 0, output.ToString());
        Assert.Contains("registered with a missing program: C:/gone/NetDecompilerMcp.exe", output.ToString());
        Assert.Matches(@"Server check: OK \(version [0-9.]+, 54 tools", output.ToString());
    }

    [Fact]
    public void ClaudeCode_FallsBackToTheFile_WhenItsCliFails()
    {
        var env = new SetupEnvironment
        {
            Os = _env.Os, Home = _env.Home, AppData = _env.AppData, LocalAppData = _env.LocalAppData, XdgConfig = _env.XdgConfig,
            Variable = _ => null,
            FindTool = t => t == "claude" ? Home("missing", OperatingSystem.IsWindows() ? "claude.exe" : "claude") : null,
        };
        var client = ClientCatalog.All(env).Single(c => c.Id == "claude-code");
        Assert.IsType<ClaudeCliTarget>(client.Target);
        Assert.True(client.Present);
        Assert.Equal("registered", client.Target.Install("net-decompiler", Launch).Message);
        Assert.Equal(Launch.Command, client.Target.Registered("net-decompiler"));
        Assert.Equal("already registered", client.Target.Install("net-decompiler", Launch).Message);
        Assert.Equal("removed", client.Target.Uninstall("net-decompiler").Message);
    }

    [Fact]
    public void ServerArguments_AreNotTreatedAsCommands()
    {
        Assert.Null(SetupCli.TryRun(["--load", "x.dll"], new StringWriter(), _env, Launch));
        Assert.Null(SetupCli.TryRun([], new StringWriter(), _env, Launch));
    }
}
