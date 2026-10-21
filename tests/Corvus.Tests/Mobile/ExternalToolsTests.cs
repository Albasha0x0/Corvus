using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary>The external tool table: location by variable, folder and PATH, version probes, minimal environment, output and time budgets.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public class ExternalToolsTests
{
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
    public void Run_GivesTheChildAMinimalEnvironment()
    {
        using var fake = new FakeTool();
        fake.On("secret", printEnv: "CORVUS_TEST_SECRET").On("script", printEnv: FakeTool.ScriptVariable);
        using var env = new EnvironmentScope().Set("CORVUS_TEST_SECRET", "s3cret");
        Assert.Equal("<unset>", ExternalTools.Run(FakeTool.Executable, ["secret"], TimeSpan.FromSeconds(30), 1000, default, fake.Environment).Text);
        Assert.Equal(fake.ScriptPath, ExternalTools.Run(FakeTool.Executable, ["script"], TimeSpan.FromSeconds(30), 1000, default, fake.Environment).Text);
        Assert.Contains("CORVUS_TEST_SECRET", ExternalTools.MinimalEnvironment().Keys);
        Assert.Null(ExternalTools.MinimalEnvironment()["CORVUS_TEST_SECRET"]);
    }

    [Fact]
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
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(10));

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
}
