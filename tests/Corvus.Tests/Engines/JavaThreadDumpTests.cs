using System.Diagnostics;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;

namespace Corvus.Tests;

/// <summary>The stall report of a Java worker, read with the JDK's jcmd from a running JVM.</summary>
[Trait("Speed", "Slow")]
public sealed class JavaThreadDumpTests
{
    private static readonly Lazy<JavaRuntime?> Found = new(() => JavaRuntime.Locate(null, 21, null, []));

    [Fact]
    public void A_running_jvm_reports_its_heap_and_saves_its_thread_dump()
    {
        if (Found.Value is not { } java) return;
        using var dir = new TempDir();
        var source = dir.File("Hold.java");
        File.WriteAllText(source, "class Hold { public static void main(String[] a) throws Exception { Thread.sleep(120_000); } }");
        using var jvm = Process.Start(new ProcessStartInfo(java.Java, [source]) { UseShellExecute = false, CreateNoWindow = true })!;
        try
        {
            // jcmd attaches once the JVM has started; the source launcher compiles first.
            string? report = null;
            for (var clock = Stopwatch.StartNew(); (report == null || report.StartsWith(WorkerConnection.StateUnknown, StringComparison.Ordinal)) && clock.Elapsed < TimeSpan.FromSeconds(60); Thread.Sleep(1000))
                report = JavaThreadDump.Report(java.Java, [jvm.Id], dir.File("stalls"));
            Assert.NotNull(report);
            Assert.StartsWith("heap: ", report);
            var file = report[(report.IndexOf("full dump: ", StringComparison.Ordinal) + "full dump: ".Length)..];
            Assert.Contains("java.lang.Thread.State", File.ReadAllText(file));
            // Test runs keep dumps in CORVUS_STALL_DIR, outside the test's own folder.
            Assert.Equal(Environment.GetEnvironmentVariable(JavaThreadDump.FolderVariable), Path.GetDirectoryName(file));
            File.Delete(file);
        }
        finally { jvm.Kill(); }
    }

    [Fact]
    public void The_report_reads_the_jvm_among_the_worker_processes()
    {
        if (Found.Value is not { } java) return;
        using var dir = new TempDir();
        var source = dir.File("Hold.java");
        File.WriteAllText(source, "class Hold { public static void main(String[] a) throws Exception { Thread.sleep(120_000); } }");
        using var jvm = Process.Start(new ProcessStartInfo(java.Java, [source]) { UseShellExecute = false, CreateNoWindow = true })!;
        try
        {
            // The test process hosts no JVM, like the Python launcher in front of a PyGhidra worker.
            string? report = null;
            for (var clock = Stopwatch.StartNew(); (report == null || report.StartsWith(WorkerConnection.StateUnknown, StringComparison.Ordinal)) && clock.Elapsed < TimeSpan.FromSeconds(60); Thread.Sleep(1000))
                report = JavaThreadDump.Report(java.Java, [Environment.ProcessId, jvm.Id], dir.File("stalls"));
            Assert.NotNull(report);
            Assert.StartsWith("heap: ", report);
            Assert.Contains($"worker-{jvm.Id}-", report);
        }
        finally { jvm.Kill(); }
    }

    [Fact]
    public void A_jvm_that_refuses_jcmd_is_read_with_the_debugger()
    {
        if (Found.Value is not { } java || !File.Exists(Path.Combine(java.Home, "bin", OperatingSystem.IsWindows() ? "jhsdb.exe" : "jhsdb"))) return;
        using var dir = new TempDir();
        var source = dir.File("Hold.java");
        File.WriteAllText(source, "class Hold { public static void main(String[] a) throws Exception { Thread.sleep(120_000); } }");
        // Without the attach mechanism jcmd gets no answer, as from a JVM that does not reach a safepoint.
        using var jvm = Process.Start(new ProcessStartInfo(java.Java, ["-XX:+DisableAttachMechanism", source]) { UseShellExecute = false, CreateNoWindow = true })!;
        try
        {
            string? report = null, dump = null;
            for (var clock = Stopwatch.StartNew(); dump?.Contains("java.lang.Thread.State", StringComparison.Ordinal) != true && clock.Elapsed < TimeSpan.FromSeconds(90); Thread.Sleep(1000))
            {
                report = JavaThreadDump.Report(java.Java, [jvm.Id], dir.File("stalls"));
                var file = report?[(report.IndexOf("full dump: ", StringComparison.Ordinal) + "full dump: ".Length)..];
                dump = file != null && File.Exists(file) ? File.ReadAllText(file) : null;
            }
            Assert.NotNull(report);
            Assert.Contains($"jcmd Thread.print of {jvm.Id} failed", report);
            Assert.Contains("java.lang.Thread.State", dump);
        }
        finally { jvm.Kill(); }
    }
}
