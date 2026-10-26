using Corvus.Native.Providers;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>The external tool table: location by variable, folder and PATH, version probes, minimal environment, output and time budgets.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public class ExternalToolsTests : IDisposable
{
    private readonly TimeSpan _versionTimeout = ExternalTools.VersionTimeout;
    private readonly ITestOutputHelper output;

    public ExternalToolsTests(ITestOutputHelper output)
    {
        this.output = output;
        // A fake tool is a .NET program: on a loaded machine its start alone can
        // pass the 15 s version check limit, and these tests read versions.
        ExternalTools.VersionTimeout = TimeSpan.FromMinutes(2);
    }

    public void Dispose() => ExternalTools.VersionTimeout = _versionTimeout;

    [Fact]
    public void Locate_TakesTheVariableAsFileOrFolder_AndNeverFallsBackFromABadOne()
    {
        using var fake = new FakeTool();
        var adb = fake.CopyAs("adb");
        using var env = new EnvironmentScope().Set("CORVUS_ADB", adb);
        Assert.Equal((adb, "CORVUS_ADB"), ExternalTools.Locate(ExternalTools.Adb));
        env.Set("CORVUS_ADB", Path.GetDirectoryName(adb));
        Assert.Equal((adb, "CORVUS_ADB"), ExternalTools.Locate(ExternalTools.Adb));

        env.Set("CORVUS_ADB", Path.Combine(fake.Directory, "missing"));
        Assert.Null(ExternalTools.Locate(ExternalTools.Adb));
        var probe = ExternalTools.Probe(ExternalTools.Adb);
        Assert.False(probe.Usable);
        Assert.Contains("CORVUS_ADB is set to", probe.Problem);
        Assert.Contains("CORVUS_ADB", probe.Remediation);
    }

    [Fact]
    public void Locate_FindsAJarByPattern_AndOnPath()
    {
        using var dir = new TempDir();
        File.WriteAllBytes(dir.File("jadx-headless-mcp-0.7.1-all.jar"), [0x50, 0x4B]);
        using var env = new EnvironmentScope().Set("CORVUS_JAVA_DECOMPILER", dir.Path);
        Assert.Equal(dir.File("jadx-headless-mcp-0.7.1-all.jar"), ExternalTools.Locate(ExternalTools.JavaDecompiler)?.Path);
        Assert.Equal("0.7.1", ExternalTools.Probe(ExternalTools.JavaDecompiler).Version); // from the file name; nothing is run

        using var fake = new FakeTool();
        var adb = fake.CopyAs("adb");
        env.Set("CORVUS_ADB", null).Set("PATH", Path.GetDirectoryName(adb) + Path.PathSeparator + Environment.GetEnvironmentVariable("PATH"));
        Assert.Equal((adb, "PATH"), ExternalTools.Locate(ExternalTools.Adb));
    }

    // Regression: c1cbd3ef push run, the jars reported "check running" when the 300 ms status wait passed on a loaded machine.
    [Fact]
    public void A_tool_without_a_version_check_is_never_reported_as_running_one()
    {
        using var dir = new TempDir();
        File.WriteAllBytes(dir.File("vineflower-1.11.1.jar"), [0x50, 0x4B]);
        using var env = new EnvironmentScope().Set("CORVUS_JAVA_DECOMPILER2", dir.Path);
        // A zero wait ends before any thread can finish: the old bounded probe always reported the check as running.
        var probe = ExternalTools.Probe(ExternalTools.JavaDecompiler2, TimeSpan.Zero);
        Assert.Equal(("1.11.1", null), (probe.Version, probe.VersionUnknown));
    }

    [Fact]
    public void Callers_probing_one_file_at_once_share_one_version_check()
    {
        using var fake = new FakeTool();
        // The version check sleeps so the callers overlap it.
        fake.On("--version", stdout: "TShark (Wireshark) 4.6.9 (v4.6.9-0)\n", sleepMs: 500);
        using var env = new EnvironmentScope().Set("CORVUS_TSHARK", fake.CopyAs("tshark")).Set(FakeTool.ScriptVariable, fake.ScriptPath);
        var probes = Enumerable.Range(0, 4).AsParallel().WithDegreeOfParallelism(4).Select(_ => ExternalTools.Probe(ExternalTools.TShark)).ToList();
        Assert.All(probes, p => Assert.Equal("4.6.9", p.Version));
        Assert.Single(fake.ArgumentLists);
    }

    [Fact]
    public void Probe_ReadsVersions_AndChecksTheMinimum()
    {
        using var fake = new FakeTool();
        using var env = new EnvironmentScope().Set("CORVUS_ADB", fake.CopyAs("adb")).Set("CORVUS_JAVA", fake.CopyAs("java"));
        var adb = ExternalTools.Probe(ExternalTools.Adb);
        Assert.True(adb.Usable, adb.Problem);
        Assert.Equal("1.0.41", adb.Version);
        Assert.Equal("CORVUS_ADB", adb.Source);
        Assert.Equal("21.0.2", ExternalTools.Probe(ExternalTools.Java).Version);

        // A JDK 8 is found but refused (the probe reads the script through the inherited variable).
        using var old = new FakeTool();
        old.Set("javaVersion", "java version \"1.8.0_202\"");
        env.Set("CORVUS_JAVA", old.CopyAs("java8")).Set(FakeTool.ScriptVariable, old.ScriptPath);
        var java = ExternalTools.Probe(ExternalTools.Java);
        Assert.True(java.Found);
        Assert.False(java.Usable);
        Assert.Contains("17 or newer is required", java.Problem);
    }

    [Fact]
    public async Task A_scoped_variable_reaches_the_tools_this_flow_starts_and_no_other_flow()
    {
        using var fake = new FakeTool();
        fake.On("script", printEnv: FakeTool.ScriptVariable);
        var before = Environment.GetEnvironmentVariable(FakeTool.ScriptVariable);
        using var env = new EnvironmentScope().Set(FakeTool.ScriptVariable, fake.ScriptPath);
        Assert.Equal(fake.ScriptPath, ExternalTools.Run(FakeTool.Executable, ["script"], TimeSpan.FromSeconds(30), 1000, default).Text);
        Assert.Equal(before, Environment.GetEnvironmentVariable(FakeTool.ScriptVariable));
        Task<string> other;
        // A flow started without this one's context, as a worker another test starts.
        using (ExecutionContext.SuppressFlow())
            other = Task.Run(() => ExternalTools.Run(FakeTool.Executable, ["script"], TimeSpan.FromSeconds(30), 1000, default).Text);
        Assert.DoesNotContain(fake.ScriptPath, await other);
    }

    [Fact]
    public void Run_GivesTheChildAMinimalEnvironment()
    {
        using var fake = new FakeTool();
        fake.On("secret", printEnv: "CORVUS_TEST_SECRET").On("script", printEnv: FakeTool.ScriptVariable);
        // Process-wide: the check is that the minimal environment strips the server's own variables.
        using var env = new EnvironmentScope().SetProcessWide("CORVUS_TEST_SECRET", "s3cret");
        Assert.Equal("<unset>", ExternalTools.Run(FakeTool.Executable, ["secret"], TimeSpan.FromSeconds(30), 1000, default, fake.Environment).Text);
        Assert.Equal(fake.ScriptPath, ExternalTools.Run(FakeTool.Executable, ["script"], TimeSpan.FromSeconds(30), 1000, default, fake.Environment).Text);
        Assert.Contains("CORVUS_TEST_SECRET", ExternalTools.MinimalEnvironment().Keys);
        Assert.Null(ExternalTools.MinimalEnvironment()["CORVUS_TEST_SECRET"]);
    }

    [Fact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public void Run_StopsAtTheOutputBudget_AndAtTheTimeout()
    {
        using var fake = new FakeTool();
        fake.On("flood", stdout: new string('x', 1000) + "\n", repeat: 10_000).On("slow", sleepMs: 20_000, stdout: "late");
        var flood = ExternalTools.Run(FakeTool.Executable, ["flood"], TimeSpan.FromSeconds(30), 50_000, default, fake.Environment);
        Assert.True(flood.Truncated);
        Assert.Equal(50_000, flood.Output.Length);

        var watch = System.Diagnostics.Stopwatch.StartNew();
        var slow = ExternalTools.Run(FakeTool.Executable, ["slow"], TimeSpan.FromMilliseconds(500), 1000, default, fake.Environment);
        Assert.True(slow.TimedOut);
        // The child prints only after its 20 s sleep, so no output means it was ended at the timeout.
        Assert.DoesNotContain("late", slow.Text);
        PerfBudget.Time("mobile/external-tool-timeout", watch.Elapsed, TimeSpan.FromSeconds(10), output);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        Assert.ThrowsAny<OperationCanceledException>(() => ExternalTools.Run(FakeTool.Executable, ["slow"], TimeSpan.FromSeconds(30), 1000, cts.Token, fake.Environment));
        Assert.Equal("not a program", ExternalTools.Run(Path.Combine(fake.Directory, "none.exe"), [], TimeSpan.FromSeconds(5), 10, default).StartError is { } e && e.Length > 0 ? "not a program" : "started");
    }

    [Fact]
    public void Arguments_FillPlaceholders_FromTheOneOptionTable()
    {
        Assert.Equal(["-s", "emulator-5554", "shell", "pm", "path", "com.example"],
            ExternalTools.Arguments(ExternalTools.Adb, "path", ("serial", "emulator-5554"), ("package", "com.example")));
        Assert.Equal(["-Xss16m", "-jar", "a.jar"], ExternalTools.Arguments(ExternalTools.Java, "jar", ("jar", "a.jar")));
        foreach (var tool in ExternalTools.Table)
        {
            Assert.StartsWith("CORVUS_", tool.Variable);
            Assert.NotEmpty(tool.Options);
        }
        Assert.Equal(ExternalTools.Table.Count, ExternalTools.Table.Select(t => t.Variable).Distinct().Count());
    }

    [Fact]
    public void Fake_tool_calls_started_side_by_side_each_answer_and_log()
    {
        // Regression: CI run 39774585910, a probe of the fake crashed on the shared log while another call held it.
        using var fake = new FakeTool();
        fake.On("^--version$", stdout: "osv-scanner version: 2.7.0");
        var runs = Enumerable.Range(0, 16).AsParallel().WithDegreeOfParallelism(16)
            .Select(_ => ExternalTools.Run(FakeTool.Executable, ["--version"], TimeSpan.FromSeconds(60), 1000, default, fake.Environment)).ToList();
        Assert.All(runs, r => Assert.Equal((0, "osv-scanner version: 2.7.0"), (r.ExitCode ?? -1, r.Text)));
        Assert.Equal(16, fake.ArgumentLists.Count);
    }

    [Fact]
    public void A_version_check_that_times_out_leaves_the_tool_usable_with_its_version_unknown()
    {
        using var fake = new FakeTool();
        fake.On("^--version$", stdout: "osv-scanner version: 2.7.0", sleepMs: 3000);
        using var env = new EnvironmentScope().Set("CORVUS_OSV_SCANNER", fake.CopyAs("osv-scanner")).Set(FakeTool.ScriptVariable, fake.ScriptPath);
        var saved = ExternalTools.VersionTimeout;
        ExternalTools.VersionTimeout = TimeSpan.FromMilliseconds(300);
        try
        {
            var probe = ExternalTools.Probe(ExternalTools.OsvScanner);
            Assert.Equal((true, null, "check timed out after 300 ms"), (probe.Usable, probe.Version, probe.VersionUnknown));
            var status = Assert.Single(Corvus.Tools.SessionTools.ExternalToolCapabilities(), c => c.Name.StartsWith("osv-scanner", StringComparison.Ordinal));
            Assert.True(status.Available);
            Assert.EndsWith("version unknown (check timed out after 300 ms)", status.Detail);
        }
        finally { ExternalTools.VersionTimeout = saved; }
    }

    [Fact]
    public async Task A_version_check_still_running_when_status_stops_waiting_is_an_unknown_version_read_by_the_next_call()
    {
        using var fake = new FakeTool();
        fake.On("^--version$", stdout: "osv-scanner version: 2.7.0");
        // The check runs until the test releases it: the first answer cannot have waited for it, however loaded the
        // runner (a 2.5 s bound on that answer failed in a push run at 2.8 s).
        var release = Path.Combine(fake.Directory, "check.release");
        fake.Set("barriers", new System.Text.Json.Nodes.JsonObject
        {
            ["--version"] = new System.Text.Json.Nodes.JsonObject { ["touch"] = Path.Combine(fake.Directory, "check.started"), ["waitFor"] = release, ["seconds"] = 100 },
        });
        using var env = new EnvironmentScope().Set("CORVUS_OSV_SCANNER", fake.CopyAs("osv-scanner")).Set(FakeTool.ScriptVariable, fake.ScriptPath);
        try
        {
            var answer = Task.Run(() => Corvus.Tools.SessionTools.ExternalToolCapabilities(TimeSpan.FromMilliseconds(300)).ToList());
            // A status that waits for the check fails here, not after the barrier's own 100 s.
            Assert.True(await Task.WhenAny(answer, Task.Delay(TimeSpan.FromSeconds(60))) == answer, "status waited for the version check");
            var first = Assert.Single(await answer, c => c.Name.StartsWith("osv-scanner", StringComparison.Ordinal));
            Assert.True(first.Available);
            Assert.EndsWith("version unknown (check running; call server_status again)", first.Detail);
        }
        finally { File.WriteAllText(release, ""); }
        var next = Assert.Single(Corvus.Tools.SessionTools.ExternalToolCapabilities(), c => c.Name.StartsWith("osv-scanner", StringComparison.Ordinal));
        Assert.Contains("version 2.7.0", next.Detail);
    }

    [Fact]
    public void Tool_availability_checks_the_programs_side_by_side()
    {
        using var fake = new FakeTool();
        // Each version check waits for the other to start: checked one after another, the first holds the call for the
        // whole wait and its version stays unknown.
        fake.Set("barriers", new System.Text.Json.Nodes.JsonObject
        {
            ["-version"] = new System.Text.Json.Nodes.JsonObject { ["touch"] = Path.Combine(fake.Directory, "java.started"), ["waitFor"] = Path.Combine(fake.Directory, "adb.started"), ["seconds"] = 100 },
            ["version"] = new System.Text.Json.Nodes.JsonObject { ["touch"] = Path.Combine(fake.Directory, "adb.started"), ["waitFor"] = Path.Combine(fake.Directory, "java.started"), ["seconds"] = 100 },
        });
        using var env = new EnvironmentScope().Set("CORVUS_JAVA", fake.CopyAs("java")).Set("CORVUS_ADB", fake.CopyAs("adb"))
            .Set("CORVUS_JAVA_DECOMPILER", Path.Combine(fake.Directory, "none.jar")).Set(FakeTool.ScriptVariable, fake.ScriptPath);
        var wait = TimeSpan.FromSeconds(60);
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var unavailable = Corvus.Mcp.ToolAvailability.Of(new HashSet<string>(["decompile_java", "list_android_devices"], StringComparer.Ordinal), [],
            idaScripting: false, isWindows: OperatingSystem.IsWindows(), wait: wait);
        Assert.True(watch.Elapsed < wait, $"{watch.Elapsed}");
        Assert.DoesNotContain(unavailable, u => u.Tool == "list_android_devices");
        Assert.Equal("21.0.2", ExternalTools.Probe(ExternalTools.Java).Version);
        Assert.Equal("1.0.41", ExternalTools.Probe(ExternalTools.Adb).Version);
    }

    [Fact]
    public async Task A_barrier_call_ends_when_its_script_is_deleted()
    {
        using var fake = new FakeTool();
        // The mark this call waits for never comes: only the deleted script ends its wait before 100 s.
        var started = Path.Combine(fake.Directory, "version.started");
        fake.Set("barriers", new System.Text.Json.Nodes.JsonObject
        {
            ["version"] = new System.Text.Json.Nodes.JsonObject { ["touch"] = started, ["waitFor"] = Path.Combine(fake.Directory, "never"), ["seconds"] = 100 },
        });
        var call = Task.Run(() => ExternalTools.Run(FakeTool.Executable, ["version"], TimeSpan.FromMinutes(2), 1000, default, fake.Environment));
        Assert.True(SpinWait.SpinUntil(() => File.Exists(started), TimeSpan.FromMinutes(1)), "the call did not start");
        File.Delete(fake.ScriptPath);
        Assert.Equal(1, (await call.WaitAsync(TimeSpan.FromSeconds(30))).ExitCode);
    }

    [Fact]
    public async Task A_tool_lookup_outside_a_tests_flow_sees_the_values_the_run_started_with()
    {
        using var fake = new FakeTool();
        var adb = fake.CopyAs("adb");
        // A flow started before the scope stands for a test running beside this one.
        var go = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var beside = Task.Run(async () =>
        {
            await go.Task;
            return ExternalTools.Locate(ExternalTools.Adb);
        });
        using var env = new EnvironmentScope().Set("CORVUS_ADB", adb);
        go.SetResult();
        Assert.Equal((adb, "CORVUS_ADB"), ExternalTools.Locate(ExternalTools.Adb));
        Assert.NotEqual(adb, (await beside)?.Path);
    }

    [Fact]
    public void A_test_server_gets_the_external_tool_variables_the_run_started_with()
    {
        var atStart = FakeDevice.ServerEnvironment["CORVUS_TSHARK"];
        using var env = new EnvironmentScope().Set("CORVUS_TSHARK", Path.Combine(Path.GetTempPath(), "set-by-a-test", "tshark.exe"));
        Assert.Equal(atStart, FakeDevice.ServerEnvironment["CORVUS_TSHARK"]);
    }

    [Fact]
    public void ServerStatus_ListsEachExternalTool_WithItsFix()
    {
        using var fake = new FakeTool();
        using var env = new EnvironmentScope().Set("CORVUS_ADB", fake.CopyAs("adb")).Set("CORVUS_JAVA_DECOMPILER", Path.Combine(fake.Directory, "none.jar"));
        var capabilities = Corvus.Tools.SessionTools.ExternalToolCapabilities().ToList();
        Assert.Equal(ExternalTools.Table.Count(t => !t.TestOracle), capabilities.Count);
        var adb = capabilities.Single(c => c.Name.Contains("adb", StringComparison.Ordinal));
        Assert.True(adb.Available);
        Assert.Contains("version 1.0.41", adb.Detail);
        var jadx = capabilities.Single(c => c.Name.Contains("JADX", StringComparison.Ordinal));
        Assert.False(jadx.Available);
        Assert.Contains("CORVUS_JAVA_DECOMPILER", jadx.Remediation);
        Assert.DoesNotContain(capabilities, c => c.Name.Contains("oracle", StringComparison.Ordinal));
    }

    [Fact]
    public void Status_names_the_programs_not_found_in_one_row()
    {
        // A CI runner has none of the programs; their rows put status over its report budget.
        using var empty = new TempDir();
        var env = new EnvironmentScope().Set("PATH", empty.Path).Set("JAVA_HOME", null).Set("ANDROID_HOME", null).Set("ANDROID_SDK_ROOT", null);
        using var _ = ExternalTools.Table.Aggregate(env, (scope, t) => scope.Set(t.Variable, null));
        var each = Corvus.Tools.SessionTools.ExternalToolCapabilities().ToList();
        var missing = each.Where(c => c.Detail == ExternalTools.NotFound).ToList();
        Assert.True(missing.Count >= 2, string.Join("; ", each.Select(c => $"{c.Name}: {c.Detail}")));
        var status = Corvus.Tools.SessionTools.ExternalToolStatus();
        Assert.Equal(each.Count - missing.Count + 1, status.Count);
        Assert.DoesNotContain(status, c => c.Detail == ExternalTools.NotFound);
        var merged = Assert.Single(status, c => c.Name == $"{missing.Count} programs not found");
        Assert.False(merged.Available);
        foreach (var tool in ExternalTools.Table.Where(t => missing.Any(m => m.Name == $"{t.Name}: {t.Purpose}")))
            Assert.Contains($"{tool.Name} ({tool.Variable}): {tool.Purpose}", merged.Detail);
    }

    [Fact]
    public void A_device_call_runs_adb_without_checking_its_version_first()
    {
        using var fake = new FakeTool();
        fake.On("^devices -l$", "List of devices attached\n");
        // adb version waits up to 30 s for the devices call to start: a device call that checked the version first
        // waited it out. Classes running beside this one may probe the same copy through CORVUS_ADB, so the log alone
        // cannot tell whose version call it was.
        fake.Set("barriers", new System.Text.Json.Nodes.JsonObject
        {
            ["version"] = new System.Text.Json.Nodes.JsonObject { ["touch"] = Path.Combine(fake.Directory, "version.started"), ["waitFor"] = Path.Combine(fake.Directory, "devices.started"), ["seconds"] = 30 },
            ["devices -l"] = new System.Text.Json.Nodes.JsonObject { ["touch"] = Path.Combine(fake.Directory, "devices.started"), ["waitFor"] = fake.ScriptPath },
        });
        using var env = new EnvironmentScope().Set("CORVUS_ADB", fake.CopyAs("adb")).Set(FakeTool.ScriptVariable, fake.ScriptPath);
        var watch = System.Diagnostics.Stopwatch.StartNew();
        Assert.Empty(new Corvus.Services.Mobile.DeviceService(new Corvus.Core.ServerOptions()) { Environment = fake.Environment }.Devices(default).Items);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(20), $"{watch.Elapsed}");
        Assert.Contains(["devices", "-l"], fake.ArgumentLists);
    }

    [Fact]
    public void A_status_probes_the_external_tools_side_by_side()
    {
        using var fake = new FakeTool();
        // Each version check waits for the other to start: probed one after another, the first gives up and reads unknown.
        // Launches take Process.Start's lock one at a time, behind those of every other test running, so on a loaded
        // runner the second started over 20 s after the first (CI run 39872882747); the wait stays under the class's
        // version check limit.
        fake.On("--version", stdout: "TShark (Wireshark) 4.6.9 (v4.6.9-0)\n");
        fake.Set("barriers", new System.Text.Json.Nodes.JsonObject
        {
            ["version"] = new System.Text.Json.Nodes.JsonObject { ["touch"] = Path.Combine(fake.Directory, "adb.started"), ["waitFor"] = Path.Combine(fake.Directory, "tshark.started"), ["seconds"] = 100 },
            ["--version"] = new System.Text.Json.Nodes.JsonObject { ["touch"] = Path.Combine(fake.Directory, "tshark.started"), ["waitFor"] = Path.Combine(fake.Directory, "adb.started"), ["seconds"] = 100 },
        });
        using var env = new EnvironmentScope().Set("CORVUS_ADB", fake.CopyAs("adb")).Set("CORVUS_TSHARK", fake.CopyAs("tshark"))
            .Set(FakeTool.ScriptVariable, fake.ScriptPath);
        var capabilities = Corvus.Tools.SessionTools.ExternalToolCapabilities().ToList();
        Assert.Contains("version 1.0.41", capabilities.Single(c => c.Name.StartsWith("Android Debug Bridge", StringComparison.Ordinal)).Detail);
        Assert.Contains("version 4.6.9", capabilities.Single(c => c.Name.StartsWith("TShark", StringComparison.Ordinal)).Detail);
    }
}
