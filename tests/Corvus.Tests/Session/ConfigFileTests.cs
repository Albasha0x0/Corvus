using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>corvus.json: the variables it sets, the ones the environment or the client entry keeps, and its status field.</summary>
public sealed class ConfigFileTests
{
    private static (ConfigFile.Report Report, Dictionary<string, string> Env) Apply(string json, Dictionary<string, string>? env = null,
        Action<string>? share = null)
    {
        // Under the per-user data folder, which carries the default access list; TEMP may be shared.
        using var dir = new TempDir(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create),
            "corvus-test-" + Guid.NewGuid().ToString("N")));
        File.WriteAllText(dir.File(ConfigFile.FileName), json);
        share?.Invoke(dir.File(ConfigFile.FileName));
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
              "PATH": "z", "CORVUS_LOAD": ["a"], "CORVUS_REPO": "a/b", "CORVUS_LOG_LEVEL": "debug" }
            """);
        Assert.Equal(["CORVUS_ALLOW_LIVE_ATTACH", "CORVUS_IDA_SCRIPTING", "CORVUS_DATA_DIR", "CORVUS_CONFIG", "PATH", "CORVUS_LOAD", "CORVUS_REPO"], report.Refused);
        Assert.Equal(new Dictionary<string, string> { ["CORVUS_LOG_LEVEL"] = "debug" }, env);
        Assert.Equal("<dataDir>/x.json: 1 set (CORVUS_LOG_LEVEL); refused CORVUS_ALLOW_LIVE_ATTACH, CORVUS_IDA_SCRIPTING, CORVUS_DATA_DIR, CORVUS_CONFIG, PATH, CORVUS_LOAD, CORVUS_REPO",
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

    [Fact]
    public void Locators_apply_from_a_file_with_the_default_access_list()
    {
        var (report, env) = Apply("""{ "CORVUS_CAPA": "capa", "CORVUS_DEBUGINFOD_URLS": "https://debuginfod.example", "CORVUS_LOG_LEVEL": "debug" }""");
        Assert.Null(report.Writers);
        Assert.Empty(report.Refused);
        Assert.Equal(["CORVUS_CAPA", "CORVUS_DEBUGINFOD_URLS", "CORVUS_LOG_LEVEL"], report.Applied);
        Assert.Equal("capa", env["CORVUS_CAPA"]);
    }

    [Fact]
    public void Locators_in_a_file_another_account_can_write_are_refused_and_named()
    {
        var (report, env) = Apply("""{ "CORVUS_CAPA": "capa", "CORVUS_GHIDRA_DIR": "g", "CORVUS_LOG_LEVEL": "debug" }""", share: Share);
        Assert.Equal(["CORVUS_CAPA", "CORVUS_GHIDRA_DIR"], report.Refused);
        Assert.Equal(new Dictionary<string, string> { ["CORVUS_LOG_LEVEL"] = "debug" }, env);
        Assert.NotNull(report.Writers);
        var value = RunStatus.Config(report)!.Value;
        Assert.Contains("refused CORVUS_CAPA, CORVUS_GHIDRA_DIR; locators refused: the file ", value, StringComparison.Ordinal);
        Assert.Contains(OperatingSystem.IsWindows() ? "is writable by " : "is writable by its group or others", value, StringComparison.Ordinal);
    }

    // Grants Users write on the Windows test file; adds group write on POSIX.
    private static void Share(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            var info = new FileInfo(path);
            var acl = info.GetAccessControl();
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.Write,
                AccessControlType.Allow));
            info.SetAccessControl(acl);
        }
        else File.SetUnixFileMode(path, File.GetUnixFileMode(path) | UnixFileMode.GroupWrite);
    }

    // Variables that set a size, switch, mode or data folder: nothing the server starts or loads code from.
    private static readonly string[] PlainSettings =
    [
        "CORVUS_ALLOW_DEVICE_CHANGES", "CORVUS_ANALYSIS_CACHE", "CORVUS_ANALYSIS_CACHE_DAYS", "CORVUS_ANALYSIS_CACHE_MB", "CORVUS_ANNOTATIONS_DIR",
        "CORVUS_AOT_CACHE", "CORVUS_AUTO_APPLE_NAMES", "CORVUS_AUTO_DART_NAMES", "CORVUS_AUTO_NATIVEAOT", "CORVUS_AUTO_PDB", "CORVUS_CHILD_DATA_KB",
        "CORVUS_CLEANUP_LOG", "CORVUS_CLIENT", "CORVUS_CLIENT_TIMEOUT", "CORVUS_CODE_INDEX_CACHE", "CORVUS_CODE_INDEX_CACHE_DAYS",
        "CORVUS_CODE_INDEX_CACHE_MB", "CORVUS_DEBUG_DIRS", "CORVUS_DUMP_BUCKET_CACHE", "CORVUS_ENGINE", "CORVUS_ENGINE_ANALYSIS",
        "CORVUS_ENGINE_MEMORY_MB", "CORVUS_ENGINE_OPEN_TIMEOUT", "CORVUS_ENGINE_OUTPUT_MB", "CORVUS_ENGINE_REQUEST_TIMEOUT", "CORVUS_GHIDRA_ANALYSIS",
        "CORVUS_GHIDRA_COMPLETION", "CORVUS_GHIDRA_DECOMPILE_PAYLOAD_MB", "CORVUS_GHIDRA_DECOMPILE_TIMEOUT", "CORVUS_GHIDRA_MAXMEM",
        "CORVUS_GHIDRA_OPTIONS", "CORVUS_GHIDRA_SPARE_WORKER", "CORVUS_IDA_CONNECT", "CORVUS_IDA_PREWARM", "CORVUS_JAVA_CACHE", "CORVUS_LOAD",
        "CORVUS_LOCK_CHECK", "CORVUS_LOG_FORMAT", "CORVUS_LOG_LEVEL", "CORVUS_MAX_LEFTOVER_CALLS", "CORVUS_MAX_OUTPUT_TOKENS", "CORVUS_OFFLINE",
        "CORVUS_PREWARM", "CORVUS_RELAY_DIR", "CORVUS_REQUIRE_ATTESTATION", "CORVUS_RESULT_CACHE", "CORVUS_RESULT_CACHE_DAYS",
        "CORVUS_RESULT_CACHE_MB", "CORVUS_RESULT_MODE", "CORVUS_STALL_DIR", "CORVUS_SYMBOL_CACHE", "CORVUS_TOOLSETS", "CORVUS_TOOLS_FILE",
        "CORVUS_TRACE", "CORVUS_WORKER_FIXTURE_OPS", "CORVUS_WORKER_HOST", "CORVUS_WORKER_MEMORY_MB", "CORVUS_YES",
    ];

    [Fact]
    public void Every_variable_in_the_source_is_a_locator_a_plain_setting_or_refused()
    {
        var src = Path.Combine(DocsTests.RepoRoot(), "src");
        var named = Directory.EnumerateFiles(src, "*.cs", SearchOption.AllDirectories)
            .SelectMany(f => Regex.Matches(File.ReadAllText(f), "\"(CORVUS_[A-Z0-9_]+)\"").Select(m => m.Groups[1].Value))
            .ToHashSet(StringComparer.Ordinal);
        Assert.Empty(PlainSettings.Intersect(ConfigFile.Locators, StringComparer.OrdinalIgnoreCase));
        Assert.Empty(named.Where(n => !ConfigFile.Locators.Contains(n) && !ConfigFile.Refused.Contains(n) && !PlainSettings.Contains(n)).Order());
        Assert.Empty(PlainSettings.Except(named));
    }
}
