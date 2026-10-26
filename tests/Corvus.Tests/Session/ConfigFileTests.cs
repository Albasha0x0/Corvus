using Corvus.Core;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>corvus.json: the variables it sets, the ones the environment or the client entry keeps, and its status field.</summary>
public sealed class ConfigFileTests
{
    private static (ConfigFile.Report Report, Dictionary<string, string> Env) Apply(string json, Dictionary<string, string>? env = null)
    {
        using var dir = new TempDir();
        File.WriteAllText(dir.File(ConfigFile.FileName), json);
        env ??= [];
        var report = ConfigFile.Apply(dir.File(ConfigFile.FileName), "default", n => env.GetValueOrDefault(n), (n, v) => env[n] = v);
        return (report, env);
    }

    [Fact]
    public void A_value_in_the_file_applies_unless_the_environment_already_sets_it()
    {
        var (report, env) = Apply("""
            {
              "$schema": "ignored",
              // Comments and trailing commas are read.
              "CORVUS_OFFLINE": true,
              "CORVUS_RESULT_CACHE_MB": 64,
              "CORVUS_ENGINE": "ghidra",
            }
            """, new() { ["CORVUS_ENGINE"] = "ida" });
        Assert.Null(report.Problem);
        Assert.Equal(["CORVUS_OFFLINE", "CORVUS_RESULT_CACHE_MB"], report.Applied);
        Assert.Equal(["CORVUS_ENGINE"], report.Overridden);
        Assert.Equal(new Dictionary<string, string> { ["CORVUS_ENGINE"] = "ida", ["CORVUS_OFFLINE"] = "1", ["CORVUS_RESULT_CACHE_MB"] = "64" }, env);
    }

    [Fact]
    public void Security_switches_the_locating_variables_and_other_names_are_refused()
    {
        var (report, env) = Apply("""
            { "CORVUS_ALLOW_LIVE_ATTACH": "1", "CORVUS_IDA_SCRIPTING": true, "CORVUS_DATA_DIR": "x", "CORVUS_CONFIG": "y",
              "PATH": "z", "CORVUS_LOAD": ["a"], "CORVUS_LOG_LEVEL": "debug" }
            """);
        Assert.Equal(["CORVUS_ALLOW_LIVE_ATTACH", "CORVUS_IDA_SCRIPTING", "CORVUS_DATA_DIR", "CORVUS_CONFIG", "PATH", "CORVUS_LOAD"], report.Refused);
        Assert.Equal(new Dictionary<string, string> { ["CORVUS_LOG_LEVEL"] = "debug" }, env);
        Assert.Equal("<dataDir>/x.json: 1 set (CORVUS_LOG_LEVEL); refused CORVUS_ALLOW_LIVE_ATTACH, CORVUS_IDA_SCRIPTING, CORVUS_DATA_DIR, CORVUS_CONFIG, PATH, CORVUS_LOAD",
            RunStatus.Config(report with { Path = Path.Combine(Native.Providers.DataFolder.Root, "x.json") })!.Value.Replace('\\', '/'));
    }

    [Fact]
    public void A_malformed_file_applies_nothing_and_says_why_and_no_file_shows_no_field()
    {
        var (report, env) = Apply("""{ "CORVUS_OFFLINE": "1", """);
        Assert.True(report.Found);
        Assert.StartsWith("not valid JSON", report.Problem, StringComparison.Ordinal);
        Assert.Empty(env);
        Assert.Contains("not applied: not valid JSON", RunStatus.Config(report)!.Value, StringComparison.Ordinal);
        Assert.Null(RunStatus.Config(ConfigFile.Apply(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), ConfigFile.FileName),
            ConfigFile.Variable, _ => null, (_, _) => { })));
    }
}
