using System.Diagnostics;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;

namespace Corvus.Tests;

/// <summary>The stall report of a Java worker, read with the JDK's jcmd from a running JVM.</summary>
[Trait("Speed", "Slow")]
public sealed class JavaThreadDumpTests
{
    private static readonly Lazy<JavaRuntime?> Found = new(() => JavaRuntime.Locate(null, 21, null, []));

    /// <summary>A JVM that sleeps for two minutes, started from source.</summary>
    private static Process StartHold(JavaRuntime java, TempDir dir, params string[] vmArgs)
    {
        var source = dir.File("Hold.java");
        File.WriteAllText(source, "class Hold { public static void main(String[] a) throws Exception { Thread.sleep(120_000); } }");
        return Process.Start(new ProcessStartInfo(java.Java, [.. vmArgs, source]) { UseShellExecute = false, CreateNoWindow = true })!;
    }

    /// <summary>Reports until <paramref name="done"/> holds or 90 s pass; each dump is read and deleted so the stall folder keeps only real stalls.</summary>
    private static (string Report, string? File, string Dump) Take(JavaRuntime java, IReadOnlyList<int> pids, TempDir dir, Func<string, string, bool> done)
    {
        (string, string?, string) last = ("", null, "");
        for (var clock = Stopwatch.StartNew(); clock.Elapsed < TimeSpan.FromSeconds(90); Thread.Sleep(1000))
        {
            var report = JavaThreadDump.Report(java.Java, pids, dir.File("stalls"));
            var at = report.IndexOf("full dump: ", StringComparison.Ordinal);
            var file = at < 0 ? null : report[(at + "full dump: ".Length)..];
            var dump = file != null && File.Exists(file) ? File.ReadAllText(file) : "";
            if (file != null) File.Delete(file);
            last = (report, file, dump);
            if (done(report, dump)) break;
        }
        return last;
    }

    // A JVM still starting refuses jcmd and is read with jhsdb instead, which reports no heap, so wait for jcmd's answer.
    private static bool Answered(string report, string dump) => report.StartsWith("heap: ", StringComparison.Ordinal);

    [Fact]
    public void A_running_jvm_reports_its_heap_and_saves_its_thread_dump()
    {
        if (Found.Value is not { } java) return;
        using var dir = new TempDir();
        using var jvm = StartHold(java, dir);
        try
        {
            var (report, file, dump) = Take(java, [jvm.Id], dir, Answered);
            Assert.StartsWith("heap: ", report);
            Assert.Contains("java.lang.Thread.State", dump);
            // Test runs keep dumps in CORVUS_STALL_DIR, outside the test's own folder.
            Assert.Equal(Environment.GetEnvironmentVariable(JavaThreadDump.FolderVariable), Path.GetDirectoryName(file));
        }
        finally { jvm.Kill(); }
    }

    [Fact]
    public void The_report_reads_the_jvm_among_the_worker_processes()
    {
        if (Found.Value is not { } java) return;
        using var dir = new TempDir();
        using var jvm = StartHold(java, dir);
        try
        {
            // The test process hosts no JVM, like the Python launcher in front of a PyGhidra worker.
            var (report, _, _) = Take(java, [Environment.ProcessId, jvm.Id], dir, Answered);
            Assert.StartsWith("heap: ", report);
            Assert.Contains($"worker-{jvm.Id}-", report);
            // Each worker process is named with its CPU time, the JVM's child processes included.
            Assert.Matches($@"processes: \S+ {Environment.ProcessId}, \d+\.\d s CPU in \d+ s; java {jvm.Id}, ", report);
        }
        finally { jvm.Kill(); }
    }

    [Fact]
    public void A_jvm_that_refuses_jcmd_is_read_with_the_debugger()
    {
        if (Found.Value is not { } java || !File.Exists(Path.Combine(java.Home, "bin", OperatingSystem.IsWindows() ? "jhsdb.exe" : "jhsdb"))) return;
        using var dir = new TempDir();
        // Without the attach mechanism jcmd gets no answer, as from a JVM that does not reach a safepoint.
        using var jvm = StartHold(java, dir, "-XX:+DisableAttachMechanism");
        try
        {
            var (report, _, dump) = Take(java, [jvm.Id], dir, (_, d) => d.Contains("java.lang.Thread.State", StringComparison.Ordinal));
            Assert.Contains($"jcmd Thread.print of {jvm.Id} failed", report);
            Assert.Contains("java.lang.Thread.State", dump);
        }
        finally { jvm.Kill(); }
    }
}
