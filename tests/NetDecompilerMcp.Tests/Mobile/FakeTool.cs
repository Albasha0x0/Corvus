using System.Text.Json;
using System.Text.Json.Nodes;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// The TestFixture.FakeTools program standing in for adb, java and the JADX server, and its JSON script
/// (ADB_FAKE_SCRIPT; ADB_ variables pass the external tools' minimal environment).
/// </summary>
internal sealed class FakeTool : IDisposable
{
    public const string ScriptVariable = "ADB_FAKE_SCRIPT";
    private const string Program = "TestFixture.FakeTools";

    public static string Executable => Path.Combine(AppContext.BaseDirectory, Program + (OperatingSystem.IsWindows() ? ".exe" : ""));

    private readonly TempDir _dir = new();
    private readonly JsonObject _script = new() { ["rules"] = new JsonArray() };

    public string ScriptPath => _dir.File("script.json");
    public string LogPath => _dir.File("log.jsonl");
    public string Directory => _dir.Path;

    public FakeTool()
    {
        _script["log"] = LogPath;
        Save();
    }

    /// <summary>The environment a child needs to read this script.</summary>
    public IReadOnlyDictionary<string, string?> Environment => new Dictionary<string, string?> { [ScriptVariable] = ScriptPath };

    /// <summary>Adds a rule: the first whose regex finds the joined arguments answers.</summary>
    public FakeTool On(string match, string? stdout = null, string? stderr = null, int exit = 0, byte[]? file = null, int? repeat = null, int? sleepMs = null, string? printEnv = null)
    {
        var rule = new JsonObject { ["match"] = match, ["exit"] = exit };
        if (stdout != null) rule["stdout"] = stdout;
        if (stderr != null) rule["stderr"] = stderr;
        if (file != null) rule["file"] = Convert.ToBase64String(file);
        if (repeat != null) rule["repeat"] = repeat;
        if (sleepMs != null) rule["sleepMs"] = sleepMs;
        if (printEnv != null) rule["printEnv"] = printEnv;
        _script["rules"]!.AsArray().Add(rule);
        Save();
        return this;
    }

    public FakeTool Set(string key, JsonNode value)
    {
        _script[key] = value;
        Save();
        return this;
    }

    private void Save() => File.WriteAllText(ScriptPath, _script.ToJsonString());

    /// <summary>Each invocation's arguments, in order (JADX tool calls are logged as objects).</summary>
    public List<JsonNode> Calls => File.Exists(LogPath)
        ? File.ReadAllLines(LogPath).Where(l => l.Length > 0).Select(l => JsonNode.Parse(l)!).ToList()
        : [];

    public List<string[]> ArgumentLists => Calls.OfType<JsonArray>().Select(a => a.Select(x => (string)x!).ToArray()).ToList();

    /// <summary>A copy of the program under another name (with its .dll beside it), e.g. "adb" or "java".</summary>
    public string CopyAs(string name)
    {
        var dir = _dir.File("bin-" + name);
        System.IO.Directory.CreateDirectory(dir);
        foreach (var ext in new[] { ".dll", ".runtimeconfig.json", ".deps.json" })
            File.Copy(Path.Combine(AppContext.BaseDirectory, Program + ext), Path.Combine(dir, Program + ext), true);
        var exe = Path.Combine(dir, name + (OperatingSystem.IsWindows() ? ".exe" : ""));
        File.Copy(Executable, exe, true);
        return exe;
    }

    public static string Json(object value) => JsonSerializer.Serialize(value);

    public void Dispose() => _dir.Dispose();
}

/// <summary>Tests that set the external tools' environment variables (NDM_ADB, NDM_JAVA, ...) run one at a time.</summary>
[CollectionDefinition(Name)]
public sealed class ExternalToolEnvironmentCollection
{
    public const string Name = "external tool environment";
}

/// <summary>Sets environment variables for one test and restores them.</summary>
internal sealed class EnvironmentScope : IDisposable
{
    private readonly Dictionary<string, string?> _saved = [];

    public EnvironmentScope Set(string name, string? value)
    {
        if (!_saved.ContainsKey(name)) _saved[name] = System.Environment.GetEnvironmentVariable(name);
        System.Environment.SetEnvironmentVariable(name, value);
        return this;
    }

    public void Dispose()
    {
        foreach (var (k, v) in _saved) System.Environment.SetEnvironmentVariable(k, v);
    }
}
