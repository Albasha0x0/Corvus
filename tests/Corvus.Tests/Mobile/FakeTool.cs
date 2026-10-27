using System.Text.Json;
using System.Text.Json.Nodes;

namespace Corvus.Tests;

/// <summary>The TestFixture.FakeTools program standing in for adb, java and the JADX server, scripted by ADB_FAKE_SCRIPT.</summary>
internal sealed class FakeTool : IDisposable
{
    public const string ScriptVariable = "ADB_FAKE_SCRIPT";
    private const string Program = "TestFixture.FakeTools";

    public static string Executable => Native ?? (OperatingSystem.IsWindows() ? Path.Combine(AppContext.BaseDirectory, Program + ".exe") : UnixLauncher.Value);

    /// <summary>The native build Corvus.Tests.csproj publishes beside the tests, or null where the host could not build it.</summary>
    public static string? Native { get; } = Path.Combine(AppContext.BaseDirectory, "fake-tools-native", Program + (OperatingSystem.IsWindows() ? ".exe" : "")) is var path && File.Exists(path) ? path : null;

    // Off Windows the apphost finds a runtime outside the default locations (CI, ~/.dotnet) only through DOTNET_ROOT, which
    // the minimal environment drops: a script runs the program with this runtime's dotnet host instead.
    private static readonly Lazy<string> UnixLauncher = new(() => WriteLauncher(Path.Combine(AppContext.BaseDirectory, "fake-tool-bin", Program)));

    private static string WriteLauncher(string path)
    {
        static string Quote(string s) => "'" + s.Replace("'", "'\\''") + "'";
        var host = Path.GetFullPath(Path.Combine(System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory(), "..", "..", "..", "dotnet"));
        System.IO.Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, $"#!/bin/sh\nexec {Quote(host)} {Quote(Path.Combine(AppContext.BaseDirectory, Program + ".dll"))} \"$@\"\n");
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return path;
    }

    private readonly TempDir _dir = new();
    private readonly JsonObject _script = new() { ["rules"] = new JsonArray() };

    public string ScriptPath => _dir.File("script.json");
    /// <summary>The folder each call writes its arguments to, one file per call.</summary>
    public string LogPath => _dir.File("log");
    public string Directory => _dir.Path;

    /// <summary>A fake with no rules; without <paramref name="log"/> its calls are not recorded and <see cref="Calls"/> stays empty.</summary>
    public FakeTool(bool log = true)
    {
        if (log) _script["log"] = LogPath;
        Save();
    }

    /// <summary>The environment a child needs to read this script.</summary>
    public IReadOnlyDictionary<string, string?> Environment => new Dictionary<string, string?> { [ScriptVariable] = ScriptPath };

    /// <summary>Adds a rule: the first whose regex finds the joined arguments answers.</summary>
    public FakeTool On(string match, string? stdout = null, string? stderr = null, int exit = 0, byte[]? file = null, int? repeat = null, int? sleepMs = null, string? printEnv = null,
        byte[]? bytes = null)
    {
        var rule = new JsonObject { ["match"] = match, ["exit"] = exit };
        if (stdout != null) rule["stdout"] = stdout;
        if (bytes != null) rule["bytes"] = Convert.ToBase64String(bytes);
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
    public List<JsonNode> Calls => System.IO.Directory.Exists(LogPath)
        ? System.IO.Directory.GetFiles(LogPath, "*.json").Order(StringComparer.Ordinal).Select(f => JsonNode.Parse(File.ReadAllText(f))!).ToList()
        : [];

    public List<string[]> ArgumentLists => Calls.OfType<JsonArray>().Select(a => a.Select(x => (string)x!).ToArray()).ToList();

    /// <summary>The program under another name, e.g. "adb" or "java": a copy of the native build, else of the managed one with its .dll beside it (off Windows a launcher).</summary>
    public string CopyAs(string name)
    {
        var dir = _dir.File("bin-" + name);
        if (Native == null && !OperatingSystem.IsWindows()) return WriteLauncher(Path.Combine(dir, name));
        System.IO.Directory.CreateDirectory(dir);
        foreach (var ext in Native == null ? new[] { ".dll", ".runtimeconfig.json", ".deps.json" } : [])
            File.Copy(Path.Combine(AppContext.BaseDirectory, Program + ext), Path.Combine(dir, Program + ext), true);
        var exe = Path.Combine(dir, name + (OperatingSystem.IsWindows() ? ".exe" : ""));
        File.Copy(Executable, exe, true);
        return exe;
    }

    public static string Json(object value) => JsonSerializer.Serialize(value);

    public void Dispose() => _dir.Dispose();
}

/// <summary>Tests that set the external tools' environment variables (CORVUS_ADB, CORVUS_JAVA, ...) run one at a time.</summary>
[CollectionDefinition(Name)]
public sealed class ExternalToolEnvironmentCollection
{
    public const string Name = "external tool environment";
}

/// <summary>Sets environment variables for one test's flow and restores them; other flows see the run's values.</summary>
internal sealed class EnvironmentScope : IDisposable
{
    private static readonly StringComparer Names = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    /// <summary>The process environment as the run started, before any test set a variable.</summary>
    internal static readonly IReadOnlyDictionary<string, string> AtStart = System.Environment.GetEnvironmentVariables()
        .Cast<System.Collections.DictionaryEntry>().ToDictionary(e => (string)e.Key, e => (string)e.Value!, Names);

    private static readonly AsyncLocal<Dictionary<string, string?>?> InFlow = new();

    private readonly Dictionary<string, string?> _saved = [];
    private readonly Dictionary<string, string?>? _flowBefore = InFlow.Value;

    [System.Runtime.CompilerServices.ModuleInitializer]
    internal static void PinToolLookups()
    {
        Corvus.Native.Providers.ExternalTools.ReadVariable = Read;
        Corvus.Native.Providers.ExternalTools.ChildVariables = () => InFlow.Value ?? [];
    }

    /// <summary>A variable as this flow's scopes set it, else as the run started; null when unset.</summary>
    internal static string? Read(string name) =>
        InFlow.Value is { } set && set.TryGetValue(name, out var value) ? value : AtStart.GetValueOrDefault(name);

    /// <summary>Sets <paramref name="name"/> in this flow only; the process environment is not changed.</summary>
    public EnvironmentScope Set(string name, string? value)
    {
        // Copied on write: a flow started before this call keeps the values it started with.
        InFlow.Value = new Dictionary<string, string?>(InFlow.Value ?? [], Names) { [name] = value };
        return this;
    }

    /// <summary>Sets <paramref name="name"/> in this flow and the process environment, which every test running sees.</summary>
    public EnvironmentScope SetProcessWide(string name, string? value)
    {
        if (!_saved.ContainsKey(name)) _saved[name] = System.Environment.GetEnvironmentVariable(name);
        System.Environment.SetEnvironmentVariable(name, value);
        return Set(name, value);
    }

    public void Dispose()
    {
        foreach (var (k, v) in _saved) System.Environment.SetEnvironmentVariable(k, v);
        InFlow.Value = _flowBefore;
    }
}
