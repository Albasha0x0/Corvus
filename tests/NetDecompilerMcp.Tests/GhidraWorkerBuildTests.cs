using System.IO.Compression;
using System.Text;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Providers.Ghidra;

namespace NetDecompilerMcp.Tests;

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
            ("Boot.java", "package ndm.ghidra; public class Boot { }"u8.ToArray()),
            ("Other.java", "package ndm.ghidra; class Other { }"u8.ToArray()),
        ];
        var dir = tmp.File("worker (x)");
        var jars = await WorkerBuild.EnsureAsync(java, [], sources, dir, default);
        Assert.Equal(["META-INF/MANIFEST.MF", "ndm/ghidra/Boot.class"], Entries(jars.Boot));
        Assert.Equal(["META-INF/MANIFEST.MF", "ndm/ghidra/Other.class"], Entries(jars.Worker));
        Assert.Equal(["ndm-ghidra-boot.jar", "ndm-ghidra-worker.jar"], Directory.GetFileSystemEntries(dir).Select(Path.GetFileName).Order());

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
            [("Boot.java", "package ndm.ghidra; public class Boot { int x = missing; }"u8.ToArray())], tmp.File("w"), default));
        Assert.Equal(ErrorCode.ProviderUnavailable, e.Code);
        Assert.Contains("missing", e.Message);
        Assert.NotNull(e.Remediation);
        Assert.Empty(Directory.GetFiles(tmp.File("w"), "*.jar"));
    }

    private static List<string> Entries(string jar)
    {
        using var zip = ZipFile.OpenRead(jar);
        return zip.Entries.Select(e => e.FullName).Order(StringComparer.Ordinal).ToList();
    }
}

/// <summary>Runs when a JDK 21+ is found the way the Ghidra provider looks for one.</summary>
public sealed class JdkFactAttribute : FactAttribute
{
    public static JavaRuntime? Jdk => Found.Value;
    private static readonly Lazy<JavaRuntime?> Found = new(() => JavaRuntime.Locate(null, 21, null, []));

    public JdkFactAttribute()
    {
        if (Jdk == null) Skip = $"No JDK 21+ ({GhidraOptions.JavaVariable}, JAVA_HOME or PATH).";
    }
}
