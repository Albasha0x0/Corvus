using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Xunit.Abstractions;
using Xunit.Sdk;

[assembly: TestFramework("Corvus.Tests.LeakGuardFramework", "Corvus.Tests")]

namespace Corvus.Tests;

/// <summary>Fails the run when tests leave child processes or temporary files; the run's temporary folder is private.</summary>
internal static class LeakGuard
{
    /// <summary>The machine's temporary folder, for files meant to outlive the run.</summary>
    public static readonly string SharedTemp = Path.GetTempPath();

    public static readonly string RunTemp = Path.Combine(SharedTemp, $"corvus-test-run-{Environment.ProcessId}-{Guid.NewGuid().ToString("N")[..8]}");

    /// <summary>This run's annotations folder (sidecars and edit journals), beside its temporary folder and named alike.</summary>
    public static readonly string RunAnnotations = Path.Combine(SharedTemp, $"corvus-test-annotations-{Environment.ProcessId}-{Guid.NewGuid().ToString("N")[..8]}");

    /// <summary>Files runtimes and SDKs keep in the temporary folder by design (.NET diagnostic endpoints, JVM perf data, java.exe launcher logs, dotnet workload logs, NuGet scratch).</summary>
    private static readonly string[] RuntimeFiles = ["dotnet-diagnostic-", "clr-debug-pipe-", "hsperfdata_", "JavaLauncher.log", "Microsoft.NET.Workload_", "NuGetScratch"];

    /// <summary>IDA's default symbol-server store (IdaProvider: SRV*%TEMP%\ida*...), a cache by design; matched by its exact name.</summary>
    private const string IdaSymbolStore = "ida";

    [ModuleInitializer]
    internal static void Redirect()
    {
        TestDataFolder.Isolate(); // the data folder stays in the shared temp: its caches outlive the run
        // Every process a test starts ends with this one, even when it crashes or is killed, so no program outlives the run.
        try { TestFixture.FakeTools.KillOnCloseJob.EnterCurrentProcess(); }
        catch (System.ComponentModel.Win32Exception ex) { Console.Error.WriteLine($"test processes are not tied to the run: {ex.Message}"); }
        RemoveEndedRuns();
        Directory.CreateDirectory(RunTemp);
        foreach (var name in new[] { "TMP", "TEMP", "TMPDIR" })
            Environment.SetEnvironmentVariable(name, RunTemp + (OperatingSystem.IsWindows() ? "" : "/"));
        // Ghidra workers of every test share one folder and a spare, so a test opens on a started JVM and the worker is
        // compiled once per run, not per cache root.
        Environment.SetEnvironmentVariable(Corvus.Native.Providers.Ghidra.GhidraOptions.WorkerDirectoryVariable, DeleteAtEnd(Path.Combine(RunTemp, "ghidra-workers")));
        Environment.SetEnvironmentVariable(Corvus.Native.Providers.Ghidra.GhidraOptions.SpareWorkerVariable, "on");
        // A discovery-only run never reaches the check.
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            try { Directory.Delete(RunTemp, false); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        };
    }

    /// <summary>
    /// Removes the temporary and annotations folders of earlier runs whose process has ended (a failed run leaves what it
    /// reported).
    /// </summary>
    internal static void RemoveEndedRuns()
    {
        try
        {
            foreach (var dir in Directory.EnumerateDirectories(SharedTemp, "corvus-test-run-*").Concat(Directory.EnumerateDirectories(SharedTemp, "corvus-test-annotations-*")))
            {
                if (Path.GetFileName(dir).Split('-') is not [_, _, _, var id, _] || !int.TryParse(id, out var pid)) continue;
                try
                {
                    using var p = Process.GetProcessById(pid);
                    if (!p.HasExited) continue;
                }
                catch (ArgumentException) { /* not running */ }
                EndPrograms(dir);
                try { Directory.Delete(dir, true); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>Off Windows, ends programs left from an ended run's folder; on Windows a job already ends them.</summary>
    private static void EndPrograms(string dir)
    {
        if (OperatingSystem.IsWindows()) return;
        foreach (var p in Process.GetProcesses())
            using (p)
            {
                try { if (p.MainModule?.FileName is { } file && file.StartsWith(dir + "/", StringComparison.Ordinal)) p.Kill(); }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { }
            }
    }

    /// <summary>What leaked, or null: children still running after a grace period, then entries left in the run's temporary folder.</summary>
    public static string? Check()
    {
        var problems = new List<string>();
        // The spares hold files in the shared worker folder: end them before it is deleted.
        Corvus.Native.Providers.Ghidra.GhidraSpareWorkers.EndAll(TimeSpan.FromSeconds(10));
        foreach (var path in RunScoped)
        {
            try { if (Directory.Exists(path)) Directory.Delete(path, true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { problems.Add($"{path} could not be deleted: {ex.Message}"); }
        }
        var children = Children();
        for (var clock = Stopwatch.StartNew(); children.Count > 0 && clock.Elapsed < TimeSpan.FromSeconds(10); children = Children()) Thread.Sleep(200);
        if (children.Count > 0)
            problems.Add("child processes still running: " + string.Join(", ", children.Select(c => $"{c.Name} ({c.Id})")));
        var left = new List<string>();
        for (var clock = Stopwatch.StartNew(); ; Thread.Sleep(200))
        {
            left = Leftovers(RunTemp);
            if (left.Count == 0 || clock.Elapsed > TimeSpan.FromSeconds(5)) break;
        }
        if (left.Count > 0)
            problems.Add($"left in the temporary folder: {string.Join(", ", left.Take(20).Select(Describe))}{(left.Count > 20 ? $" and {left.Count - 20} more" : "")}");
        try { Directory.Delete(RunTemp, true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return problems.Count == 0 ? null : string.Join("; ", problems);
    }

    /// <summary>Names of the entries left in <paramref name="folder"/>, sorted; empty when it is absent.</summary>
    internal static List<string> Leftovers(string folder)
    {
        if (!Directory.Exists(folder)) return [];
        // A server killed during an external tool run leaves its tool folder,
        // which the product sweeps once that process has ended: sweep it here.
        var runs = Path.Combine(folder, "corvus-run");
        Corvus.Native.Providers.ExternalTools.SweepRunFolders(runs);
        try { if (Directory.Exists(runs) && !Directory.EnumerateFileSystemEntries(runs).Any()) Directory.Delete(runs); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return Directory.EnumerateFileSystemEntries(folder).Select(Path.GetFileName)
            .Where(n => n != IdaSymbolStore && !RuntimeFiles.Any(n!.StartsWith) && !OnlyCompilerServerCache(Path.Combine(folder, n)))
            .Select(n => n!).Order().ToList();
    }

    /// <summary>A folder holding only VBCSCompiler shadow copies, kept by the compiler server after a test build.</summary>
    private static bool OnlyCompilerServerCache(string path)
    {
        try
        {
            return Directory.Exists(path) && Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories)
                .All(f => Path.GetRelativePath(path, f).Split(Path.DirectorySeparatorChar).Contains("VBCSCompiler"));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    /// <summary>A leftover with a hint at its owner: a folder's first entries, a file's size.</summary>
    private static string Describe(string name)
    {
        var path = Path.Combine(RunTemp, name);
        try
        {
            if (Directory.Exists(path))
                return $"{name}/ [{string.Join(", ", Directory.EnumerateFileSystemEntries(path).Take(3).Select(Path.GetFileName))}]";
            return $"{name} ({new FileInfo(path).Length} bytes)";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return name; }
    }

    /// <summary>Folders shared by a test class for the whole run; deleted before the check.</summary>
    private static readonly System.Collections.Concurrent.ConcurrentBag<string> RunScoped = [];

    /// <summary>Returns <paramref name="path"/>, deleted once every test has finished.</summary>
    public static string DeleteAtEnd(string path)
    {
        RunScoped.Add(path);
        return path;
    }

    private sealed record Child(int Id, string Name);

    /// <summary>Running processes whose parent is this one (and that started after it, so a reused id does not count).</summary>
    private static List<Child> Children()
    {
        var self = Environment.ProcessId;
        var started = Process.GetCurrentProcess().StartTime;
        var found = new List<Child>();
        foreach (var (pid, parent) in ParentLinks())
        {
            if (parent != self || pid == self) continue;
            try
            {
                using var p = Process.GetProcessById(pid);
                // Conhost serves this process's own console.
                if (p.HasExited || p.StartTime < started || p.ProcessName.Equals("conhost", StringComparison.OrdinalIgnoreCase)) continue;
                found.Add(new Child(pid, p.ProcessName));
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception) { }
        }
        return found;
    }

    /// <summary>
    /// Running processes descended from <paramref name="root"/> and started after it, nearest first; empty when the root
    /// has exited or the links cannot be read. The caller disposes them.
    /// </summary>
    internal static List<Process> Descendants(Process root)
    {
        var found = new List<Process>();
        DateTime started;
        try { started = root.StartTime; }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { return found; }
        var children = ParentLinks().ToLookup(l => l.Parent, l => l.Pid);
        var queue = new Queue<int>([root.Id]);
        var seen = new HashSet<int> { root.Id };
        while (queue.TryDequeue(out var parent))
            foreach (var pid in children[parent])
            {
                if (!seen.Add(pid)) continue;
                try
                {
                    var p = Process.GetProcessById(pid);
                    // A reused id keeps a stale parent link: only processes started after the root count.
                    if (p.StartTime < started) { p.Dispose(); continue; }
                    found.Add(p);
                    queue.Enqueue(pid);
                }
                catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception) { }
            }
        return found;
    }

    private static IEnumerable<(int Pid, int Parent)> ParentLinks()
    {
        if (OperatingSystem.IsWindows()) return WindowsLinks();
        if (Directory.Exists("/proc/self")) return ProcLinks();
        return PsLinks();
    }

    private static List<(int, int)> ProcLinks()
    {
        var links = new List<(int, int)>();
        foreach (var dir in Directory.EnumerateDirectories("/proc"))
        {
            if (!int.TryParse(Path.GetFileName(dir), out var pid)) continue;
            try
            {
                // Pid (comm) state ppid ...: comm may hold spaces and parentheses, so read after the last ')'.
                var stat = File.ReadAllText(Path.Combine(dir, "stat"));
                var fields = stat[(stat.LastIndexOf(')') + 2)..].Split(' ');
                if (fields[0] != "Z" && int.TryParse(fields[1], out var parent)) links.Add((pid, parent));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or IndexOutOfRangeException) { }
        }
        return links;
    }

    private static List<(int, int)> PsLinks()
    {
        var links = new List<(int, int)>();
        using var ps = Process.Start(new ProcessStartInfo("ps", ["-A", "-o", "pid=,ppid="]) { RedirectStandardOutput = true, UseShellExecute = false })!;
        foreach (var line in ps.StandardOutput.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries))
            if (line.Split(' ', StringSplitOptions.RemoveEmptyEntries) is [var a, var b] && int.TryParse(a, out var pid) && int.TryParse(b, out var parent))
                links.Add((pid, parent));
        ps.WaitForExit();
        return links;
    }

    private static List<(int, int)> WindowsLinks()
    {
        var links = new List<(int, int)>();
        var snapshot = CreateToolhelp32Snapshot(2 /* TH32CS_SNAPPROCESS */, 0);
        if (snapshot == new IntPtr(-1)) return links;
        try
        {
            var entry = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            for (var ok = Process32FirstW(snapshot, ref entry); ok; ok = Process32NextW(snapshot, ref entry))
                links.Add(((int)entry.th32ProcessID, (int)entry.th32ParentProcessID));
        }
        finally { CloseHandle(snapshot); }
        return links;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize, cntUsage, th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID, cntThreads, th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern bool Process32FirstW(IntPtr snapshot, ref PROCESSENTRY32W entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern bool Process32NextW(IntPtr snapshot, ref PROCESSENTRY32W entry);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}

/// <summary>The xUnit framework with <see cref="LeakGuard"/> run once every test has finished.</summary>
public sealed class LeakGuardFramework(IMessageSink messageSink) : XunitTestFramework(messageSink)
{
    /// <summary>Full names of the test classes this run executes (nested ones with '+'); empty before the run starts.</summary>
    public static IReadOnlySet<string> RunClasses { get; private set; } = new HashSet<string>();

    protected override ITestFrameworkExecutor CreateExecutor(AssemblyName assemblyName) =>
        new Executor(assemblyName, SourceInformationProvider, DiagnosticMessageSink);

    private sealed class Executor(AssemblyName assemblyName, ISourceInformationProvider sourceInformationProvider, IMessageSink diagnosticMessageSink)
        : XunitTestFrameworkExecutor(assemblyName, sourceInformationProvider, diagnosticMessageSink)
    {
        protected override async void RunTestCases(IEnumerable<IXunitTestCase> testCases, IMessageSink executionMessageSink, ITestFrameworkExecutionOptions executionOptions)
        {
            RunClasses = testCases.Select(t => t.TestMethod.TestClass.Class.Name).ToHashSet(StringComparer.Ordinal);
            using var runner = new Runner(TestAssembly, testCases, DiagnosticMessageSink, executionMessageSink, executionOptions);
            await runner.RunAsync();
        }
    }

    private sealed class Runner(ITestAssembly testAssembly, IEnumerable<IXunitTestCase> testCases, IMessageSink diagnosticMessageSink,
        IMessageSink executionMessageSink, ITestFrameworkExecutionOptions executionOptions)
        : XunitTestAssemblyRunner(testAssembly, testCases, diagnosticMessageSink, executionMessageSink, executionOptions)
    {
        // Permits are taken before the parallel slot, so a collection waiting for an engine holds no slot.
        protected override async Task<RunSummary> RunTestCollectionAsync(IMessageBus messageBus, ITestCollection testCollection,
            IEnumerable<IXunitTestCase> testCases, CancellationTokenSource cancellationTokenSource)
        {
            var needed = MachinePermits.Needed(testCases);
            if (needed.Count == 0) return await base.RunTestCollectionAsync(messageBus, testCollection, testCases, cancellationTokenSource);
            PermitHandle held;
            TimeSpan waited;
            try { (held, waited) = await MachinePermits.TakeAsync(needed, cancellationTokenSource.Token); }
            catch (TimeoutException e)
            {
                // Each test fails with the wait's message instead of the run hanging without output.
                var failed = new ExceptionAggregator(Aggregator);
                failed.Add(e);
                return await new XunitTestCollectionRunner(testCollection, testCases, DiagnosticMessageSink, messageBus, TestCaseOrderer, failed, cancellationTokenSource).RunAsync();
            }
            using (held)
            {
                MachinePermits.Record(needed, waited, testCollection.DisplayName);
                return await base.RunTestCollectionAsync(new ProgressBus(messageBus, held), testCollection, testCases, cancellationTokenSource);
            }
        }

        // Each finished test is the holder's progress, which keeps a waiter's limit from running out.
        private sealed class ProgressBus(IMessageBus inner, PermitHandle held) : IMessageBus
        {
            public bool QueueMessage(IMessageSinkMessage message)
            {
                if (message is ITestFinished) held.Progress();
                return inner.QueueMessage(message);
            }

            // The runner owns the inner bus.
            public void Dispose() { }
        }

        protected override async Task BeforeTestAssemblyFinishedAsync()
        {
            if (LeakGuard.Check() is { } leaks)
            {
                // The runner prints only the exception's type for a cleanup failure.
                DiagnosticMessageSink.OnMessage(new DiagnosticMessage("Tests leaked resources: " + leaks));
                Aggregator.Add(new LeakException(leaks));
            }
            await base.BeforeTestAssemblyFinishedAsync();
        }
    }
}

public sealed class LeakException(string message) : Exception("Tests leaked resources: " + message);
