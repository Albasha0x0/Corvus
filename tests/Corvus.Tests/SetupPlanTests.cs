using System.Text.Json.Nodes;
using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>A throwaway home folder and the setup environment that points at it; nothing reaches the real user folders.</summary>
internal sealed class SetupHome : IDisposable
{
    private readonly TempDir _dir = new();
    public static readonly ServerLaunch Launch = new(
        OperatingSystem.IsWindows() ? @"C:\Tools\Corvus\current\corvus.exe" : "/opt/corvus/current/corvus", []);

    public string Root => _dir.Path;
    public string Path(params string[] parts) => System.IO.Path.Combine([_dir.Path, .. parts]);

    public SetupEnvironment Env(bool interactive = false, Func<string, bool>? confirm = null, IReadOnlyDictionary<string, string>? variables = null,
        HostOs? os = null, Func<string, string?>? findTool = null, bool idaAvailable = false) => new()
    {
        Ida = deep => idaAvailable
            ? Corvus.Native.Providers.ProviderAvailability.Ok("ida", new Dictionary<string, string> { ["install_dir"] = "fake", ["deep"] = deep.ToString() })
            : Corvus.Native.Providers.ProviderAvailability.Missing("ida", "IDA not found (test)", "Install IDA."),
        Python = () => (null, ["test: no interpreter"]),
        Os = os ?? (OperatingSystem.IsWindows() ? HostOs.Windows : OperatingSystem.IsMacOS() ? HostOs.MacOs : HostOs.Linux),
        Home = _dir.Path,
        AppData = Path("AppData", "Roaming"),
        LocalAppData = Path("AppData", "Local"),
        XdgConfig = variables?.GetValueOrDefault("XDG_CONFIG_HOME") ?? Path(".config"),
        // ProgramFiles too: Visual Studio is detected there, and a runner with it installed would add a client.
        Variable = name => variables?.GetValueOrDefault(name) ?? (name == "ProgramFiles" ? Path("Program Files") : null),
        FindTool = findTool ?? (_ => null),
        Interactive = interactive,
        Confirm = confirm ?? (_ => throw new InvalidOperationException("asked without a terminal")),
    };

    public (int Code, string Output) Run(SetupEnvironment env, params string[] args)
    {
        var output = new StringWriter();
        var code = SetupCli.TryRun(args, output, env, Launch);
        Assert.NotNull(code);
        return (code!.Value, output.ToString());
    }

    public (int Code, string Output) Run(params string[] args) => Run(Env(), args);

    public void Write(string text, params string[] parts)
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path(parts))!);
        File.WriteAllText(Path(parts), text);
    }

    /// <summary>Every file under the home folder with its content, to prove a run wrote nothing.</summary>
    public SortedDictionary<string, string> Snapshot() =>
        new(Directory.EnumerateFiles(_dir.Path, "*", SearchOption.AllDirectories).ToDictionary(f => f, File.ReadAllText), StringComparer.Ordinal);

    public void Dispose() => _dir.Dispose();
}

/// <summary>Install consent: the plan, dry run, JSON, selection, confirmation and refresh-only update.</summary>
public sealed class SetupPlanTests : IDisposable
{
    private readonly SetupHome _home = new();
    public void Dispose() => _home.Dispose();

    private static JsonNode ReadJson(string path) => JsonNode.Parse(File.ReadAllText(path))!;
    private static readonly string Old = OperatingSystem.IsWindows() ? @"C:\Old\corvus.exe" : "/old/corvus";

    /// <summary>Cursor registered with an old copy; Codex and Kiro detected and not registered.</summary>
    private void ExistingAndNew()
    {
        _home.Write($$"""{ "mcpServers": { "corvus": { "command": {{System.Text.Json.JsonSerializer.Serialize(Old)}}, "args": ["--load", "x"] } } }""", ".cursor", "mcp.json");
        Directory.CreateDirectory(_home.Path(".codex"));
        Directory.CreateDirectory(_home.Path(".kiro"));
    }

    [Fact]
    public void WithoutATerminalOrYes_ExistingRegistrationsAreRefreshed_AndNewClientsOnlyNamed()
    {
        ExistingAndNew();
        var (code, output) = _home.Run("install", "--no-check");
        Assert.True(code == 0, output);
        var cursor = ReadJson(_home.Path(".cursor", "mcp.json"))["mcpServers"]!["corvus"]!;
        Assert.Equal(SetupHome.Launch.Command, cursor["command"]!.GetValue<string>());
        Assert.Equal(["--load", "x"], cursor["args"]!.AsArray().Select(a => a!.GetValue<string>()));
        Assert.False(File.Exists(_home.Path(".codex", "config.toml")));
        Assert.False(File.Exists(_home.Path(".kiro", "settings", "mcp.json")));
        Assert.Contains("install --all-detected", output);
        Assert.Contains("codex, kiro", output);

        (code, output) = _home.Run("install", "--no-check", "--all-detected");
        Assert.True(code == 0, output);
        Assert.True(File.Exists(_home.Path(".codex", "config.toml")));
        Assert.True(File.Exists(_home.Path(".kiro", "settings", "mcp.json")));
    }

    [Fact]
    public void CorvusYes_AddsNewClientsUnattended()
    {
        ExistingAndNew();
        var (code, output) = _home.Run(_home.Env(variables: new Dictionary<string, string> { ["CORVUS_YES"] = "1" }), "install", "--no-check");
        Assert.True(code == 0, output);
        Assert.True(File.Exists(_home.Path(".codex", "config.toml")));
    }

    [Fact]
    public void DryRun_WritesNothing_AndJsonDescribesEachClient()
    {
        ExistingAndNew();
        var before = _home.Snapshot();
        var (code, output) = _home.Run("install", "--dry-run", "--json");
        Assert.Equal(0, code);
        Assert.Equal(before, _home.Snapshot());

        var report = JsonNode.Parse(output)!;
        Assert.Equal("install", report["command"]!.GetValue<string>());
        Assert.True(report["dryRun"]!.GetValue<bool>());
        Assert.False(report["applied"]!.GetValue<bool>());
        Assert.Null(report["server"]);
        JsonNode Client(string id) => report["clients"]!.AsArray().Single(c => c!["id"]!.GetValue<string>() == id)!;
        var cursor = Client("cursor");
        Assert.Equal("refresh", cursor["action"]!.GetValue<string>());
        Assert.Equal(Old, cursor["registered"]!["command"]!.GetValue<string>());
        Assert.Equal(Old, cursor["before"]!["command"]!.GetValue<string>());
        Assert.Equal(SetupHome.Launch.Command, cursor["after"]!["command"]!.GetValue<string>());
        Assert.EndsWith("mcp.json.corvus.bak", cursor["backupPath"]!.GetValue<string>());
        var codex = Client("codex");
        Assert.Equal("add", codex["action"]!.GetValue<string>());
        Assert.True(codex["needsConsent"]!.GetValue<bool>());
        Assert.Null(codex["backupPath"]);
        Assert.Equal("skip", Client("zed")["action"]!.GetValue<string>());
        Assert.False(Client("zed")["detected"]!.GetValue<bool>());

        (code, output) = _home.Run("install", "--dry-run");
        Assert.Equal(0, code);
        Assert.Matches(@"refresh\s+Cursor", output);
        Assert.Matches(@"add \(new\)\s+Codex", output);
        Assert.Contains("Dry run: nothing was written.", output);
        Assert.DoesNotContain("Zed", output);
        Assert.Equal(before, _home.Snapshot());
    }

    [Fact]
    public void Interactive_ShowsThePlanAndAsksOnce_YesRegisters_NoSkips()
    {
        ExistingAndNew();
        var questions = new List<string>();
        var (code, output) = _home.Run(_home.Env(interactive: true, confirm: q => { questions.Add(q); return false; }), "install", "--no-check");
        Assert.True(code == 0, output);
        Assert.Equal(["Register with these 2 new clients?"], questions);
        Assert.Matches(@"add \(new\)\s+Kiro", output);
        Assert.False(File.Exists(_home.Path(".codex", "config.toml")));
        Assert.Equal(SetupHome.Launch.Command, ReadJson(_home.Path(".cursor", "mcp.json"))["mcpServers"]!["corvus"]!["command"]!.GetValue<string>());

        (code, output) = _home.Run(_home.Env(interactive: true, confirm: q => { questions.Add(q); return true; }), "install", "--no-check");
        Assert.True(code == 0, output);
        Assert.True(File.Exists(_home.Path(".codex", "config.toml")));
        Assert.True(File.Exists(_home.Path(".kiro", "settings", "mcp.json")));

        // Nothing new: no question.
        (code, _) = _home.Run(_home.Env(interactive: true), "install", "--no-check");
        Assert.Equal(0, code);
        Assert.Equal(2, questions.Count);
    }

    [Fact]
    public void Json_IsNonInteractive_AndReportsTheResult()
    {
        ExistingAndNew();
        var (code, output) = _home.Run(_home.Env(interactive: true), "install", "--no-check", "--json", "--yes");
        Assert.Equal(0, code);
        var report = JsonNode.Parse(output)!;
        Assert.True(report["applied"]!.GetValue<bool>());
        Assert.True(report["healthy"]!.GetValue<bool>());
        Assert.All(report["clients"]!.AsArray().Where(c => c!["detected"]!.GetValue<bool>()),
            c => Assert.Equal("registered", c!["message"]!.GetValue<string>()));
    }

    [Fact]
    public void RefreshOnly_NeverAddsClients()
    {
        ExistingAndNew();
        var (code, output) = _home.Run("install", "--no-check", "--refresh-only", "--yes");
        Assert.True(code == 0, output);
        Assert.Contains("update adds no clients", output);
        Assert.False(File.Exists(_home.Path(".codex", "config.toml")));
        Assert.Equal(SetupHome.Launch.Command, ReadJson(_home.Path(".cursor", "mcp.json"))["mcpServers"]!["corvus"]!["command"]!.GetValue<string>());
    }

    [Fact]
    public void Strict_WritesNothingWhenAFileIsBlocked()
    {
        ExistingAndNew();
        _home.Write("{ not json", ".kiro", "settings", "mcp.json");
        var before = _home.Snapshot();
        var (code, output) = _home.Run("install", "--no-check", "--yes", "--strict");
        Assert.Equal(1, code);
        Assert.Matches(@"blocked\s+Kiro", output);
        Assert.Equal(before, _home.Snapshot());

        (code, output) = _home.Run("install", "--no-check", "--yes");
        Assert.Equal(1, code);
        Assert.True(File.Exists(_home.Path(".codex", "config.toml")), output);
        Assert.Equal("{ not json", File.ReadAllText(_home.Path(".kiro", "settings", "mcp.json")));
    }

    [Fact]
    public void UnknownOptions_AreUsageErrors_AndWriteNothing()
    {
        ExistingAndNew();
        var before = _home.Snapshot();
        Assert.Equal(2, _home.Run("install", "--dryrun").Code);
        Assert.Equal(2, _home.Run("install", "--client").Code);
        Assert.Equal(2, _home.Run("install", "--yes=1").Code);
        Assert.Equal(before, _home.Snapshot());

        var (code, output) = _home.Run("install", "--no-check", "--client", "codex,zed");
        Assert.True(code == 0, output);
        Assert.True(File.Exists(_home.Path(".codex", "config.toml")));
        Assert.False(File.Exists(_home.Path(".kiro", "settings", "mcp.json")));
        Assert.Equal(Old, ReadJson(_home.Path(".cursor", "mcp.json"))["mcpServers"]!["corvus"]!["command"]!.GetValue<string>());
    }

    [Fact]
    public void InstallCommand_PlansForTheProgramTheScriptsPutInPlace()
    {
        ExistingAndNew();
        var final = _home.Path("root", "current", OperatingSystem.IsWindows() ? "corvus.exe" : "corvus");
        var (code, output) = _home.Run("install", "--dry-run", "--json", "--yes", "--command", final);
        Assert.Equal(0, code);
        var report = JsonNode.Parse(output)!;
        Assert.Equal(final, report["launch"]!["command"]!.GetValue<string>());
        var codex = report["clients"]!.AsArray().Single(c => c!["id"]!.GetValue<string>() == "codex")!;
        Assert.Equal("add", codex["action"]!.GetValue<string>());
        Assert.False(codex["needsConsent"]!.GetValue<bool>());
        Assert.Equal(final, codex["after"]!["command"]!.GetValue<string>());
    }

    [Fact]
    public void Update_TakesAVersionOrDryRun_AndNoClientNames()
    {
        Assert.Equal("https://api.github.com/repos/o/r/releases/latest", Installation.ReleaseApi("o/r", null));
        Assert.Equal("https://api.github.com/repos/o/r/releases/tags/v1.2.0", Installation.ReleaseApi("o/r", "1.2.0"));
        Assert.Equal("https://api.github.com/repos/o/r/releases/tags/v1.2.0", Installation.ReleaseApi("o/r", "v1.2.0"));
        Assert.Equal(2, _home.Run("update", "cursor").Code);
        Assert.Equal(2, _home.Run("update", "--version").Code);
        Assert.Equal(2, _home.Run("update", "--yes").Code);
        // The test host is not an installed copy: nothing is downloaded.
        var (code, output) = _home.Run("update", "--version", "1.2.0", "--dry-run");
        Assert.Equal(1, code);
        Assert.Contains("cannot update itself", output);
    }

    [Fact]
    public void UninstallDryRun_ListsRemovals_AndChangesNothing()
    {
        ExistingAndNew();
        var before = _home.Snapshot();
        var (code, output) = _home.Run("uninstall", "--dry-run", "--json");
        Assert.Equal(0, code);
        Assert.Equal(before, _home.Snapshot());
        var report = JsonNode.Parse(output)!;
        var removed = Assert.Single(report["clients"]!.AsArray());
        Assert.Equal("cursor", removed!["id"]!.GetValue<string>());
        Assert.Equal("remove", removed["action"]!.GetValue<string>());
    }
}
