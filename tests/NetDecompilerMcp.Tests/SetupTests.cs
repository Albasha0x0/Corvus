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

    private static JsonNode ReadJson(string path) =>
        JsonNode.Parse(File.ReadAllText(path), documentOptions: new System.Text.Json.JsonDocumentOptions { CommentHandling = System.Text.Json.JsonCommentHandling.Skip, AllowTrailingCommas = true })!;

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

        var (code, output) = Run("install", "--no-check", "--yes");
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
        Assert.DoesNotContain("comments were not kept", output);
        Assert.StartsWith("// Zed settings\n{\n  \"ui_font_size\": 16, // trailing comment\n", File.ReadAllText(Path.Combine(zed, "settings.json")));
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

        Assert.Equal(0, Run("install", "--no-check", "--yes").Code);
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

    [Trait("Speed", "Slow")]
    [Fact]
    public void Status_StartsEachRegistrationWithItsOwnArgsAndEnv_AndTheRealServer()
    {
        using var home = new SetupHome();
        var dll = typeof(NetDecompilerMcp.Core.AssemblyWorkspace).Assembly.Location;
        var server = new ServerLaunch("dotnet", [dll]);
        var q = System.Text.Json.JsonSerializer.Serialize(dll);
        home.Write($$"""{ "mcpServers": { "net-decompiler": { "command": "dotnet", "args": [{{q}}] } } }""", ".cursor", "mcp.json");
        // The entry's env reaches the server: an invalid engine makes it exit.
        home.Write($$"""{ "mcpServers": { "net-decompiler": { "command": "dotnet", "args": [{{q}}], "env": { "NDM_ENGINE": "nonsense" } } } }""", ".kiro", "settings", "mcp.json");
        home.Write("""{ "mcpServers": { "net-decompiler": { "command": "C:/gone/NetDecompilerMcp.exe" } } }""", ".lmstudio", "mcp.json");
        var output = new StringWriter();
        var code = SetupCli.TryRun(["status"], output, home.Env(), server);
        var text = output.ToString();
        Assert.True(code == 1, text);
        Assert.Contains("registered with a missing program: C:/gone/NetDecompilerMcp.exe", text);
        Assert.Contains("must be auto, ours or ida", text);
        var tools = SelfTest.DeclaredTools().Count;
        Assert.True(tools > 50, $"{tools} declared tools");
        Assert.Matches($@"Cursor\s+registered \(version [0-9.]+, {tools} tools", text);
        Assert.Matches($@"Server check: OK \(version [0-9.]+, {tools} tools", text);
        Assert.Matches($@"Tool catalog: matches this build \({tools} tools\); digest t{tools}-[0-9a-f]{{12}}\.p\d+-[0-9a-f]{{8}}", text);

        output = new StringWriter();
        Assert.Equal(0, SetupCli.TryRun(["status", "--client", "cursor"], output, home.Env(), server));
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

        File.WriteAllText(Home(".claude.json"), """{ "mcpServers": { "net-decompiler": { "command": "C:/old/x.exe", "args": ["--load", "x"], "env": { "A": "1" } } } }""");
        Assert.Equal("registered", client.Target.Install("net-decompiler", Launch).Message);
        var entry = ReadJson(Home(".claude.json"))["mcpServers"]!["net-decompiler"]!;
        Assert.Equal(Launch.Command, entry["command"]!.GetValue<string>());
        Assert.Equal("x", entry["args"]![1]!.GetValue<string>());
        Assert.Equal("1", entry["env"]!["A"]!.GetValue<string>());
    }

    private static readonly ServerLaunch DotnetLaunch = new("dotnet", [Path.Combine(Path.GetTempPath(), "build", "NetDecompilerMcp.dll")]);

    [Fact]
    public void Install_DevReload_RegistersTheRelayFromAStagedCopy_AndBack()
    {
        var program = Home("src", "bin", "NetDecompilerMcp.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(program)!);
        File.WriteAllText(program, "apphost");
        File.WriteAllText(Home("src", "bin", "NetDecompilerMcp.dll"), "server");
        var publish = Home("publish");
        Directory.CreateDirectory(publish);
        var state = Home("relay-state");
        var env = new SetupEnvironment
        {
            Os = _env.Os, Home = _env.Home, AppData = _env.AppData, LocalAppData = _env.LocalAppData, XdgConfig = _env.XdgConfig,
            Variable = name => name == "NDM_RELAY_DIR" ? state : null,
        };
        Directory.CreateDirectory(Home(".cursor"));
        File.WriteAllText(Home(".cursor", "mcp.json"), """{ "mcpServers": { "net-decompiler": { "command": "old", "args": ["--load", "x"] } } }""");
        JsonNode Entry() => ReadJson(Home(".cursor", "mcp.json"))["mcpServers"]!["net-decompiler"]!;
        string[] Args() => [.. Entry()["args"]!.AsArray().Select(a => a!.GetValue<string>())];

        var output = new StringWriter();
        Assert.Equal(0, SetupCli.TryRun(["install", "--no-check", "--dev-reload", publish], output, env, new ServerLaunch(program, [])));
        var staged = Entry()["command"]!.GetValue<string>();
        Assert.StartsWith(Path.Combine(state, "host"), staged);
        Assert.Equal("apphost", File.ReadAllText(staged));
        Assert.Equal(["relay", "--target", publish, "--load", "x"], Args());
        // Again: unchanged; another folder replaces the relay's options instead of stacking them.
        Assert.Contains("already registered", Run2("install", "--no-check", "--dev-reload", publish));
        Assert.Equal(0, SetupCli.TryRun(["install", "--no-check", "--dev-reload", Home(".cursor")], new StringWriter(), env, new ServerLaunch(program, [])));
        Assert.Equal(["relay", "--target", Home(".cursor"), "--load", "x"], Args());
        // A plain install switches back to the server.
        Assert.Equal(0, SetupCli.TryRun(["install", "--no-check"], new StringWriter(), env, Launch));
        Assert.Equal(Launch.Command, Entry()["command"]!.GetValue<string>());
        Assert.Equal(["--load", "x"], Args());

        Assert.Equal(2, SetupCli.TryRun(["install", "--no-check", "--dev-reload", Home("missing")], new StringWriter(), env, Launch));
        var config = new StringWriter();
        Assert.Equal(0, SetupCli.TryRun(["config", "--dev-reload", publish], config, env, new ServerLaunch(program, [])));
        Assert.Contains("\"relay\"", config.ToString());

        string Run2(params string[] args)
        {
            var o = new StringWriter();
            Assert.Equal(0, SetupCli.TryRun(args, o, env, new ServerLaunch(program, [])));
            return o.ToString();
        }
    }

    [Fact]
    public void Install_KeepsTheUsersArgumentsEnvAndKeys_OnJsonEntries()
    {
        Directory.CreateDirectory(Home(".cursor"));
        File.WriteAllText(Home(".cursor", "mcp.json"), """
            { "mcpServers": { "net-decompiler": { "command": "C:/old/NetDecompilerMcp.exe", "args": ["--load", "x"],
              "env": { "NDM_IDA_DIR": "C:/ida" }, "timeout": 30 } } }
            """);
        JsonNode Entry() => ReadJson(Home(".cursor", "mcp.json"))["mcpServers"]!["net-decompiler"]!;
        void AssertKept(params string[] args)
        {
            var e = Entry();
            Assert.Equal(args, e["args"]!.AsArray().Select(a => a!.GetValue<string>()));
            Assert.Equal("C:/ida", e["env"]!["NDM_IDA_DIR"]!.GetValue<string>());
            Assert.Equal(30, e["timeout"]!.GetValue<int>());
        }

        Assert.Equal(0, Run("install", "--no-check").Code);
        Assert.Equal(Launch.Command, Entry()["command"]!.GetValue<string>());
        AssertKept("--load", "x");
        var (code, output) = Run("install", "--no-check");
        Assert.Equal(0, code);
        Assert.Contains("already registered", output);

        // A launcher switch, as after an update or a run from source: our own arguments follow the launcher.
        Assert.Equal(0, SetupCli.TryRun(["install", "--no-check"], new StringWriter(), _env, DotnetLaunch));
        Assert.Equal("dotnet", Entry()["command"]!.GetValue<string>());
        AssertKept(DotnetLaunch.Args[0], "--load", "x");
        Assert.Equal(0, Run("install", "--no-check").Code);
        AssertKept("--load", "x");

        // Our keys are added only where absent.
        var target = new JsonTarget(Home("cline.json"), ["mcpServers"], l => new JsonObject { ["command"] = l.Command, ["args"] = new JsonArray(), ["disabled"] = false });
        File.WriteAllText(target.Path, """{ "mcpServers": { "net-decompiler": { "command": "a", "disabled": true } } }""");
        Assert.True(target.Install("net-decompiler", Launch).Changed);
        var cline = ReadJson(target.Path)["mcpServers"]!["net-decompiler"]!;
        Assert.True(cline["disabled"]!.GetValue<bool>());
        Assert.Empty(cline["args"]!.AsArray());
    }

    [Fact]
    public void Install_KeepsTheUsersArguments_InCommandArrays()
    {
        Directory.CreateDirectory(Home(".config", "opencode"));
        File.WriteAllText(Home(".config", "opencode", "opencode.json"), """
            { "mcp": { "net-decompiler": { "type": "local", "command": ["C:/old/NetDecompilerMcp.exe", "--load", "x"], "enabled": false,
              "environment": { "A": "1" } } } }
            """);
        Assert.Equal(0, Run("install", "--no-check", "opencode").Code);
        Assert.Equal(0, Run("install", "--no-check", "opencode").Code);
        var entry = ReadJson(Home(".config", "opencode", "opencode.json"))["mcp"]!["net-decompiler"]!;
        Assert.Equal([Launch.Command, "--load", "x"], entry["command"]!.AsArray().Select(a => a!.GetValue<string>()));
        Assert.False(entry["enabled"]!.GetValue<bool>());
        Assert.Equal("1", entry["environment"]!["A"]!.GetValue<string>());
    }

    [Fact]
    public void Install_KeepsTheUsersArgumentsEnvAndKeys_InTheCodexTable()
    {
        Directory.CreateDirectory(Home(".codex"));
        var before = """
            model = "o4"

            [mcp_servers.net-decompiler]
            command = 'C:\old\NetDecompilerMcp.exe'
            args = ["--load", "x"]  # my build
            startup_timeout_sec = 30

            [mcp_servers.net-decompiler.env]
            NDM_IDA_DIR = "C:/ida"

            [profiles.fast]
            model = "mini"

            """.Replace("\r\n", "\n");
        File.WriteAllText(Home(".codex", "config.toml"), before);
        Assert.Equal(0, Run("install", "--no-check", "codex").Code);
        var expected = before.Replace(@"command = 'C:\old\NetDecompilerMcp.exe'", "command = " + System.Text.Json.JsonSerializer.Serialize(Launch.Command));
        Assert.Equal(expected, File.ReadAllText(Home(".codex", "config.toml")));
        var (_, output) = Run("install", "--no-check", "codex");
        Assert.Contains("already registered", output);
        Assert.Equal(expected, File.ReadAllText(Home(".codex", "config.toml")));

        Assert.Equal(0, SetupCli.TryRun(["install", "--no-check", "codex"], new StringWriter(), _env, DotnetLaunch));
        var toml = File.ReadAllText(Home(".codex", "config.toml"));
        Assert.Contains("command = \"dotnet\"\nargs = [" + System.Text.Json.JsonSerializer.Serialize(DotnetLaunch.Args[0]) + ", \"--load\", \"x\"]\nstartup_timeout_sec = 30", toml);
        Assert.Contains("[mcp_servers.net-decompiler.env]\nNDM_IDA_DIR = \"C:/ida\"", toml);
        Assert.Equal(0, Run("install", "--no-check", "codex").Code);
        Assert.Contains("args = [\"--load\", \"x\"]\nstartup_timeout_sec = 30", File.ReadAllText(Home(".codex", "config.toml")));

        // A table without command or args gets both.
        File.WriteAllText(Home(".codex", "config.toml"), "[mcp_servers.net-decompiler]\nstartup_timeout_sec = 30\n");
        Assert.Equal(0, Run("install", "--no-check", "codex").Code);
        Assert.Equal("[mcp_servers.net-decompiler]\ncommand = " + System.Text.Json.JsonSerializer.Serialize(Launch.Command) + "\nargs = []\nstartup_timeout_sec = 30\n",
            File.ReadAllText(Home(".codex", "config.toml")));
    }

    /// <summary>A fake install root with two versions, a "current" link and data folders.</summary>
    private string FakeInstall(string root, string dataRoot)
    {
        foreach (var v in new[] { "1.0.0", "1.1.0" })
        {
            Directory.CreateDirectory(Path.Combine(root, "versions", v));
            File.WriteAllText(Path.Combine(root, "versions", v, "NetDecompilerMcp.dll"), "x");
        }
        Installation.PointCurrent(root, Path.Combine(root, "versions", "1.1.0"));
        foreach (var data in new[] { "annotations", "analysis", "code-index" }) Directory.CreateDirectory(Path.Combine(dataRoot, data));
        File.WriteAllText(Path.Combine(dataRoot, "annotations", "a.json"), "{}");
        return root;
    }

    [Fact]
    public void Uninstall_RemovesProgramFiles_AndKeepsDataInASharedRoot()
    {
        var root = FakeInstall(Home("Local", "NetDecompilerMcp"), Home("Local", "NetDecompilerMcp"));
        var plan = Installation.PlanRemoval(root, root, purgeData: false);
        Assert.Equal(["analysis", "annotations", "code-index"], plan.Kept);
        var output = new StringWriter();
        Installation.Report(plan, root, output);
        Assert.Contains("Kept your data in", output.ToString());
        Assert.Contains("--purge-data", output.ToString());
        Installation.Apply(plan);
        Assert.False(Directory.Exists(Path.Combine(root, "versions")));
        Assert.False(Directory.Exists(Path.Combine(root, "current")) || File.Exists(Path.Combine(root, "current")));
        Assert.True(File.Exists(Path.Combine(root, "annotations", "a.json")));
        Assert.True(Directory.Exists(Path.Combine(root, "code-index")));

        Installation.Apply(Installation.PlanRemoval(root, root, purgeData: true));
        Assert.False(Directory.Exists(root));
    }

    [Fact]
    public void Uninstall_RemovesAnEmptiedInstallRoot_AndPurgeRemovesASeparateDataRoot()
    {
        var root = FakeInstall(Home("share", "net-decompiler-mcp"), Home("share", "NetDecompilerMcp"));
        var dataRoot = Home("share", "NetDecompilerMcp");
        Installation.Apply(Installation.PlanRemoval(root, dataRoot, purgeData: false));
        Assert.False(Directory.Exists(root));
        Assert.True(File.Exists(Path.Combine(dataRoot, "annotations", "a.json")));

        FakeInstall(root, dataRoot);
        var purge = Installation.PlanRemoval(root, dataRoot, purgeData: true);
        Assert.Empty(purge.Kept);
        Installation.Apply(purge);
        Assert.False(Directory.Exists(root));
        Assert.False(Directory.Exists(dataRoot));
    }

    [Fact]
    public void Uninstall_DeferredWindowsCommand_RemovesTheJunctionWithoutFollowingIt()
    {
        if (!OperatingSystem.IsWindows()) return;
        var root = @"C:\Users\u\AppData\Local\NetDecompilerMcp";
        var command = Installation.DeferredWindowsCommand(Installation.PlanRemoval(root, root, purgeData: false));
        Assert.Equal($"ping -n 3 127.0.0.1 >nul & rmdir \"{root}\\current\" 2>nul & rmdir /s /q \"{root}\\versions\" 2>nul & rmdir \"{root}\" 2>nul", command);
        command = Installation.DeferredWindowsCommand(Installation.PlanRemoval(root, root, purgeData: true));
        Assert.EndsWith($"rmdir \"{root}\\current\" 2>nul & rmdir /s /q \"{root}\" 2>nul", command);
    }

    [Fact]
    public void Uninstall_PurgeData_DeletesTheDataRoot_AndRejectsKeepFiles()
    {
        var dataRoot = Path.Combine(_env.LocalAppData, "NetDecompilerMcp");
        Directory.CreateDirectory(Path.Combine(dataRoot, "analysis"));
        var (code, output) = Run("uninstall", "--purge-data", "--keep-files");
        Assert.Equal(2, code);
        Assert.True(Directory.Exists(dataRoot), output);
        (code, output) = Run("uninstall");
        Assert.Equal(0, code);
        Assert.True(Directory.Exists(dataRoot), output);
        (code, output) = Run("uninstall", "--purge-data");
        Assert.Equal(0, code);
        Assert.False(Directory.Exists(dataRoot), output);
    }

    [Fact]
    public void ReleaseChecksum_MatchesMismatchesAndMissingEntries()
    {
        var data = "release archive"u8.ToArray();
        var hash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(data));
        var manifest = $"{new string('0', 64)}  NetDecompilerMcp-linux-x64.tar.gz\r\n{hash}  NetDecompilerMcp-win-x64.zip\n{hash.ToUpperInvariant()} *NetDecompilerMcp-osx-arm64.tar.gz\n";
        Assert.Null(Installation.VerifyChecksum(manifest, "NetDecompilerMcp-win-x64.zip", data));
        Assert.Null(Installation.VerifyChecksum(manifest, "NetDecompilerMcp-osx-arm64.tar.gz", data));
        Assert.Contains("Checksum mismatch for NetDecompilerMcp-linux-x64.tar.gz", Installation.VerifyChecksum(manifest, "NetDecompilerMcp-linux-x64.tar.gz", data));
        Assert.Contains("lists no NetDecompilerMcp-win-arm64.zip", Installation.VerifyChecksum(manifest, "NetDecompilerMcp-win-arm64.zip", data));
        Assert.Contains("lists no NetDecompilerMcp-win-x64.zip", Installation.VerifyChecksum("", "NetDecompilerMcp-win-x64.zip", data));
        Assert.NotNull(Installation.VerifyChecksum(manifest, "NetDecompilerMcp-win-x64.zip", "altered"u8));
    }

    [Fact]
    public void ServerArguments_AreNotTreatedAsCommands()
    {
        Assert.Null(SetupCli.TryRun(["--load", "x.dll"], new StringWriter(), _env, Launch));
        Assert.Null(SetupCli.TryRun([], new StringWriter(), _env, Launch));
    }
}
