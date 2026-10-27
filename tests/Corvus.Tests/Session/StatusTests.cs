using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>status / doctor: scopes, classifications, engines, targets, JSON and exit codes; read-only.</summary>
public sealed class StatusTests : IDisposable
{
    private readonly SetupHome _home = new();
    public void Dispose() => _home.Dispose();

    private static string Q(string s) => JsonSerializer.Serialize(s);
    private static readonly string Gone = OperatingSystem.IsWindows() ? @"C:\gone\corvus.exe" : "/gone/corvus";

    private void Registrations()
    {
        _home.Write($$"""{ "mcpServers": { "corvus": { "command": {{Q(Gone)}} } } }""", ".cursor", "mcp.json");
        _home.Write("""{ "mcpServers": { "corvus": { "command": "corvus-test-test-no-such-tool", "args": ["x"] } } }""", ".kiro", "settings", "mcp.json");
        Directory.CreateDirectory(_home.Path(".lmstudio"));
    }

    private static JsonNode Json(string output) => JsonNode.Parse(output)!;
    private static JsonNode Client(JsonNode report, string id) => report["clients"]!.AsArray().Single(c => c!["id"]!.GetValue<string>() == id)!;

    [Fact]
    public void A_relay_whose_publish_folder_is_gone_is_a_missing_program()
    {
        var gone = _home.Path("publish-gone");
        _home.Write($$"""{ "mcpServers": { "corvus": { "command": "corvus-host", "args": ["relay", "--target", {{Q(gone)}}] } } }""", ".cursor", "mcp.json");
        var (code, output) = _home.Run("status", "--client", "cursor", "--json");
        Assert.Equal(1, code);
        var cursor = Client(Json(output), "cursor");
        Assert.Equal("missing_program", cursor["state"]!.GetValue<string>());
        Assert.Contains("development relay for " + gone, cursor["message"]!.GetValue<string>());
    }

    [Fact]
    public void Install_removes_staged_relay_copies_no_configuration_names()
    {
        var hosts = _home.Path("AppData", "Local", "Corvus", "relay", "host");
        foreach (var name in new[] { "1.2.0-aaaaaaaaaaaa", "1.3.0-bbbbbbbbbbbb", "1.3.0-cccccccccccc.tmp-42" })
            _home.Write("x", "AppData", "Local", "Corvus", "relay", "host", name, "corvus.exe");
        // A project-level entry still names one copy.
        _home.Write($$"""{ "projects": { "D:/w": { "mcpServers": { "corvus": { "command": {{Q(Path.Combine(hosts, "1.3.0-bbbbbbbbbbbb", "corvus.exe"))}} } } } } }""", ".claude.json");
        var (code, output) = _home.Run(_home.Env(variables: new Dictionary<string, string> { ["CORVUS_RELAY_DIR"] = Path.GetDirectoryName(hosts)! }), "install", "--no-check");
        Assert.True(code == 0, output);
        Assert.Equal(["1.3.0-bbbbbbbbbbbb"], Directory.EnumerateDirectories(hosts).Select(Path.GetFileName));
        Assert.Contains("removed the unused staged copy", output);
    }

    [Fact]
    public void Client_scope_checks_only_those_clients_and_fails_only_for_them()
    {
        Registrations();
        var before = _home.Snapshot();
        var (code, output) = _home.Run("status", "--client", "cursor", "--json");
        Assert.Equal(1, code);
        var report = Json(output);
        var cursor = Assert.Single(report["clients"]!.AsArray())!;
        Assert.Equal("missing_program", cursor["state"]!.GetValue<string>());
        Assert.Equal(Gone, cursor["registered"]!["command"]!.GetValue<string>());
        Assert.Null(cursor["action"]);
        Assert.Null(report["server"]);
        Assert.Empty(report["engines"]!.AsArray());
        Assert.False(report["healthy"]!.GetValue<bool>());

        (code, output) = _home.Run("status", "--client", "kiro");
        Assert.Equal(1, code);
        Assert.Contains("registered, but the server does not start", output);

        (code, output) = _home.Run("status", "--client", "lm-studio", "--json");
        Assert.Equal(1, code);
        Assert.Equal("not_registered", Client(Json(output), "lm-studio")["state"]!.GetValue<string>());
        Assert.Equal(before, _home.Snapshot());
    }

    [Fact]
    public void Audit_reports_every_detected_client_the_server_and_the_engines()
    {
        Registrations();
        var (code, output) = _home.Run("status", "--json");
        Assert.Equal(1, code);
        var report = Json(output);
        Assert.Equal("missing_program", Client(report, "cursor")["state"]!.GetValue<string>());
        Assert.Equal("start_failed", Client(report, "kiro")["state"]!.GetValue<string>());
        Assert.Equal("not_registered", Client(report, "lm-studio")["state"]!.GetValue<string>());
        Assert.DoesNotContain(report["clients"]!.AsArray(), c => c!["id"]!.GetValue<string>() == "zed");
        Assert.False(report["server"]!["ok"]!.GetValue<bool>());
        Assert.Equal(["ida", "python", "ghidra"], report["engines"]!.AsArray().Select(e => e!["name"]!.GetValue<string>()));
        Assert.All(report["engines"]!.AsArray(), e => Assert.Equal("missing_engine", e!["classification"]!.GetValue<string>()));
    }

    [Fact]
    public void Engine_scope_checks_IDA_Python_and_Ghidra()
    {
        Assert.Equal(1, _home.Run("status", "--engine", "ida").Code);
        var (code, output) = _home.Run(_home.Env(idaAvailable: true), "status", "--engine", "ida", "--deep", "--json");
        Assert.Equal(0, code);
        var ida = Assert.Single(Json(output)["engines"]!.AsArray())!;
        Assert.Equal("healthy", ida["classification"]!.GetValue<string>());
        Assert.Contains("deep True", ida["detail"]!.GetValue<string>());

        (code, output) = _home.Run("status", "--engine", "python");
        Assert.Equal(1, code);
        Assert.Contains("test: no interpreter", output);

        (code, output) = _home.Run("status", "--engine", "ghidra");
        Assert.Equal(1, code);
        Assert.Contains("CORVUS_GHIDRA_DIR is not set", output);
        var ghidra = _home.Path("ghidra");
        var vars = new Dictionary<string, string> { ["CORVUS_GHIDRA_DIR"] = ghidra, ["JAVA_HOME"] = _home.Path("jdk") };
        (code, output) = _home.Run(_home.Env(variables: vars), "status", "--engine", "ghidra");
        Assert.Equal(1, code);
        Assert.Contains("is not a Ghidra install", output);
        _home.Write("", "ghidra", "support", OperatingSystem.IsWindows() ? "analyzeHeadless.bat" : "analyzeHeadless");
        (code, output) = _home.Run(_home.Env(variables: vars), "status", "--engine", "ghidra");
        Assert.Equal(1, code);
        Assert.Contains("no Java runtime", output);
        _home.Write("", "jdk", "bin", OperatingSystem.IsWindows() ? "java.exe" : "java");
        (code, output) = _home.Run(_home.Env(variables: vars), "status", "--engine", "ghidra");
        Assert.True(code == 0, output);

        (code, output) = _home.Run("status", "--engine", "all", "--json");
        Assert.Equal(3, Json(output)["engines"]!.AsArray().Count);
        Assert.Equal(2, _home.Run("status", "--engine", "hopper").Code);
        Assert.Equal(2, _home.Run("status", "--deeper").Code);
    }

    [Fact]
    public void Target_scope_classifies_the_file_without_loading_it()
    {
        var (code, output) = _home.Run("status", "--target", Env.FixturePath, "--json");
        Assert.Equal(0, code);
        Assert.Contains(".NET assembly", Json(output)["target"]!["detail"]!.GetValue<string>());

        _home.Write("hello", "note.txt");
        (code, output) = _home.Run("status", "--target", _home.Path("note.txt"), "--json");
        Assert.Equal(1, code);
        Assert.Equal("unsupported_target", Json(output)["target"]!["classification"]!.GetValue<string>());
        Assert.Equal(1, _home.Run("status", "--target", _home.Path("missing.dll")).Code);
        Assert.Equal(0, _home.Run("status", "--target", _home.Root).Code);

        File.WriteAllBytes(_home.Path("app.apk"), [(byte)'P', (byte)'K', 3, 4, 0, 0]);
        Assert.Contains("ZIP container", _home.Run("status", "--target", _home.Path("app.apk")).Output);
        File.WriteAllBytes(_home.Path("global-metadata.dat"), [0xAF, 0x1B, 0xB1, 0xFA, 29, 0, 0, 0]);
        Assert.Contains("AOT metadata", _home.Run("status", "--target", _home.Path("global-metadata.dat")).Output);

        if (OperatingSystem.IsWindows())
        {
            var native = Path.Combine(Environment.SystemDirectory, "kernel32.dll");
            (code, output) = _home.Run("status", "--target", native);
            Assert.True(code == 0, output);
            Assert.Contains("native PE image", output);
        }
    }
}
