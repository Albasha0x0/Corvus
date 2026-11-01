using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Native.Providers.Ghidra;

namespace Corvus.Tests;

/// <summary>The embedded worker sources and their build with a JDK (the compile tests need one and run in the slow set).</summary>
public class GhidraWorkerBuildTests
{
    [Fact]
    public void Worker_sources_are_embedded_and_name_the_boot_class()
    {
        var sources = WorkerBuild.EmbeddedSources();
        Assert.Contains(sources, s => s.Name == "Boot.java");
        Assert.Contains(sources, s => s.Name == "Worker.java");
        var boot = Encoding.UTF8.GetString(sources.Single(s => s.Name == "Boot.java").Bytes);
        Assert.Contains("package " + GhidraLaunch.BootClass[..GhidraLaunch.BootClass.LastIndexOf('.')] + ";", boot);
        Assert.Contains(GhidraLaunch.WorkerJarProperty, boot);
        // Every op the session sends is dispatched by the worker.
        var worker = Encoding.UTF8.GetString(sources.Single(s => s.Name == "Worker.java").Bytes);
        foreach (var op in new[] { "hello", "open", "rebase", "functions", "decompile", "disasm", "disasm_range", "blocks", "xrefs_to", "xrefs_from",
                     "set_name", "set_comment", "apply_names", "get_stamp", "save", "close", "cancel", "sleep" })
            Assert.Contains($"\"{op}\"", worker);
    }

    [Theory]
    [InlineData(600, 600)]
    [InlineData(90, 90)]
    [InlineData(0.2, 1)]
    public void The_checkpoint_interval_sent_to_the_worker_is_the_configured_one_and_at_least_a_second(double configured, double sent)
    {
        var options = configured == 600 ? new GhidraProviderOptions() : new GhidraProviderOptions { AnalysisCheckpoint = TimeSpan.FromSeconds(configured) };
        Assert.Equal(sent, GhidraSession.CheckpointSeconds(options));
    }

    [Fact]
    public void Source_hash_depends_on_names_and_bytes_only()
    {
        (string, byte[])[] a = [("A.java", [1, 2]), ("B.java", [3])];
        var h = WorkerBuild.SourceHash(a);
        Assert.Equal(12, h.Length);
        Assert.Equal(h, WorkerBuild.SourceHash(a.Reverse()));
        Assert.NotEqual(h, WorkerBuild.SourceHash([("A.java", [1, 2]), ("B.java", [4])]));
        Assert.NotEqual(h, WorkerBuild.SourceHash([("A.java", [1, 2]), ("C.java", [3])]));
    }

    [JdkFact]
    [Trait("Speed", "Slow")]
    public async Task Sources_compile_into_a_boot_jar_and_a_worker_jar_once()
    {
        using var tmp = new TempDir();
        var java = JdkFactAttribute.Jdk!;
        (string, byte[])[] sources =
        [
            ("Boot.java", "package corvus.ghidra; public class Boot { }"u8.ToArray()),
            ("Other.java", "package corvus.ghidra; class Other { }"u8.ToArray()),
        ];
        var dir = tmp.File("worker (x)");
        var jars = await WorkerBuild.EnsureAsync(java, [], sources, dir, default);
        Assert.Equal(["META-INF/MANIFEST.MF", "corvus/ghidra/Boot.class"], Entries(jars.Boot));
        Assert.Equal(["META-INF/MANIFEST.MF", "corvus/ghidra/Other.class"], Entries(jars.Worker));
        Assert.Equal(["ghidra-boot.jar", "ghidra-worker.jar"], Directory.GetFileSystemEntries(dir).Select(Path.GetFileName).Order());

        var written = File.GetLastWriteTimeUtc(jars.Worker);
        await WorkerBuild.EnsureAsync(java, [], sources, dir, default);
        Assert.Equal(written, File.GetLastWriteTimeUtc(jars.Worker));
    }

    [JdkFact]
    [Trait("Speed", "Slow")]
    public async Task A_compile_error_makes_the_provider_unavailable_with_javac_output()
    {
        using var tmp = new TempDir();
        var e = await Assert.ThrowsAsync<ToolError>(() => WorkerBuild.EnsureAsync(JdkFactAttribute.Jdk!, [],
            [("Boot.java", "package corvus.ghidra; public class Boot { int x = missing; }"u8.ToArray())], tmp.File("w"), default));
        Assert.Equal(ErrorCode.ProviderUnavailable, e.Code);
        Assert.Contains("missing", e.Message);
        Assert.NotNull(e.Remediation);
        Assert.Empty(Directory.GetFiles(tmp.File("w"), "*.jar"));
    }

    // Regression: workers on one home shared scripts/<hash> folders.
    [JdkFact]
    public async Task Evicting_a_script_in_one_worker_keeps_the_scripts_of_another()
    {
        using var tmp = new TempDir();
        var java = JdkFactAttribute.Jdk!;
        var folder = WorkerBuild.EmbeddedSources().Single(s => s.Name == "ScriptFolder.java");
        const string probe = """
            package corvus.ghidra;
            import java.io.File;
            public class Probe {
                public static void main(String[] a) throws Exception {
                    File home = new File(a[0]);
                    ScriptFolder one = new ScriptFolder(home, "1"), two = new ScriptFolder(home, "2");
                    for (ScriptFolder f : new ScriptFolder[] { one, two }) {
                        new File(f.of("k"), "classes").mkdirs();
                        new File(f.of("k"), "UserScript_k.java").createNewFile();
                    }
                    one.evict("k");
                    System.out.println(one.of("k").exists() + " " + new File(two.of("k"), "UserScript_k.java").exists());
                }
            }
            """;
        var jars = await WorkerBuild.EnsureAsync(java, [], [folder, ("Probe.java", System.Text.Encoding.UTF8.GetBytes(probe))], tmp.File("w"), default);
        var run = Corvus.Native.Providers.PythonLocator.RunCapture(java.Java, ["-cp", jars.Boot + Path.PathSeparator + jars.Worker, "corvus.ghidra.Probe", tmp.File("home")], TimeSpan.FromSeconds(30));
        Assert.Equal(0, run.ExitCode);
        Assert.Equal("false true", run.Stdout.Trim());
        var ops = System.Text.Encoding.UTF8.GetString(WorkerBuild.EmbeddedSources().Single(s => s.Name == "ScriptOps.java").Bytes);
        Assert.DoesNotContain("\"scripts\"", ops);
        Assert.Contains("FOLDER.evict(", ops);
    }

    // A pid above any the system hands out stands for an ended worker.
    [JdkFact]
    public async Task Starting_a_worker_deletes_the_script_folders_of_ended_workers_only()
    {
        using var tmp = new TempDir();
        var java = JdkFactAttribute.Jdk!;
        var folder = WorkerBuild.EmbeddedSources().Single(s => s.Name == "ScriptFolder.java");
        const string probe = """
            package corvus.ghidra;
            import java.io.File;
            public class Probe {
                public static void main(String[] a) throws Exception {
                    File scripts = new File(a[0], "scripts");
                    String self = Long.toString(ProcessHandle.current().pid());
                    for (String w : new String[] { "4000000000", self, "notes" }) new File(new File(scripts, w), "k").mkdirs();
                    ScriptFolder.sweep(scripts);
                    System.out.println(new File(scripts, "4000000000").exists() + " " + new File(scripts, self).exists() + " " + new File(scripts, "notes").exists());
                }
            }
            """;
        var jars = await WorkerBuild.EnsureAsync(java, [], [folder, ("Probe.java", System.Text.Encoding.UTF8.GetBytes(probe))], tmp.File("w"), default);
        var run = Corvus.Native.Providers.PythonLocator.RunCapture(java.Java, ["-cp", jars.Boot + Path.PathSeparator + jars.Worker, "corvus.ghidra.Probe", tmp.File("home")], TimeSpan.FromSeconds(30));
        Assert.Equal(0, run.ExitCode);
        Assert.Equal("false true true", run.Stdout.Trim());
    }

    private static List<string> Entries(string jar)
    {
        using var zip = ZipFile.OpenRead(jar);
        return zip.Entries.Select(e => e.FullName).Order(StringComparer.Ordinal).ToList();
    }
}

/// <summary>Runs when a JDK 21+ is found the way the Ghidra provider looks for one, checked when a test runs (java -version).</summary>
[Xunit.Sdk.XunitTestCaseDiscoverer(RunTimeSkips.FactDiscoverer, RunTimeSkips.Assembly)]
public sealed class JdkFactAttribute : FactAttribute, IRunTimeSkip
{
    public static JavaRuntime? Jdk => Found.Value;
    private static readonly Lazy<JavaRuntime?> Found = new(() => JavaRuntime.Locate(null, 21, null, []));

    public string? RunTimeSkip() => Jdk == null ? $"No JDK 21+ ({GhidraOptions.JavaVariable}, JAVA_HOME or PATH)." : null;
}
