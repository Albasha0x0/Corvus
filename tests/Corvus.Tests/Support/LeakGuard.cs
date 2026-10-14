using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Xunit.Abstractions;
using Xunit.Sdk;

[assembly: TestFramework("Corvus.Tests.LeakGuardFramework", "Corvus.Tests")]

namespace Corvus.Tests;

/// <summary>
/// Fails the run when tests leave child processes running or files in the temporary folder. The folder is private to the
/// run (TMP, TEMP and TMPDIR point into it, for the servers the tests start too), so other runs on the machine do not count.
/// </summary>
internal static class LeakGuard
{
    /// <summary>The machine's temporary folder, for files meant to outlive the run.</summary>
    public static readonly string SharedTemp = Path.GetTempPath();

    public static readonly string RunTemp = Path.Combine(SharedTemp, $"corvus-test-run-{Environment.ProcessId}-{Guid.NewGuid().ToString("N")[..8]}");

    /// <summary>
    /// Files runtimes and SDKs keep in the temporary folder by design: .NET's diagnostic endpoints (left by a killed child),
    /// the JVM's performance data, the log of Oracle's java.exe launcher stub on Windows, the dotnet CLI's workload logs and
    /// NuGet's scratch folder.
    /// </summary>
    private static readonly string[] RuntimeFiles = ["dotnet-diagnostic-", "clr-debug-pipe-", "hsperfdata_", "JavaLauncher.log", "Microsoft.NET.Workload_", "NuGetScratch"];

    /// <summary>IDA's default symbol-server store (IdaProvider: SRV*%TEMP%\ida*...), a cache by design; matched by its exact name.</summary>
    private const string IdaSymbolStore = "ida";

    [ModuleInitializer]
    internal static void Redirect()
    {
        TestDataFolder.Isolate(); // the data folder stays in the shared temp: its caches outlive the run
        RemoveEndedRuns();
        Directory.CreateDirectory(RunTemp);
        foreach (var name in new[] { "TMP", "TEMP", "TMPDIR" })
            Environment.SetEnvironmentVariable(name, RunTemp + (OperatingSystem.IsWindows() ? "" : "/"));
        // A discovery-only run never reaches the check.
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            try { Directory.Delete(RunTemp, false); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        };
    }

    /// <summary>Folders of earlier runs whose process has ended (a failed run leaves what it reported).</summary>
    private static void RemoveEndedRuns()
    {
        try
        {
            foreach (var dir in Directory.EnumerateDirectories(SharedTemp, "corvus-test-run-*"))
            {
                if (Path.GetFileName(dir).Split('-') is not [_, _, _, var id, _] || !int.TryParse(id, out var pid)) continue;
                try
                {
                    using var p = Process.GetProcessById(pid);
                    if (!p.HasExited) continue;
                }
                catch (ArgumentException) { /* not running */ }
                try { Directory.Delete(dir, true); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>What leaked, or null: children still running after a grace period, then entries left in the run's temporary folder.</summary>
    public static string? Check()
    {
        var problems = new List<string>();
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
            left = Directory.Exists(RunTemp)
                ? Directory.EnumerateFileSystemEntries(RunTemp).Select(Path.GetFileName).Where(n => n != IdaSymbolStore && !RuntimeFiles.Any(n!.StartsWith) && !OnlyCompilerServerCache(Path.Combine(RunTemp, n))).Select(n => n!).Order().ToList()
                : [];
            if (left.Count == 0 || clock.Elapsed > TimeSpan.FromSeconds(5)) break;
        }
        if (left.Count > 0)
            problems.Add($"left in the temporary folder: {string.Join(", ", left.Take(20).Select(Describe))}{(left.Count > 20 ? $" and {left.Count - 20} more" : "")}");
        try { Directory.Delete(RunTemp, true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return problems.Count == 0 ? null : string.Join("; ", problems);
    }

    /// <summary>
    /// A folder whose files all lie in VBCSCompiler folders: the shadow copies of the C# compiler server, which a test build
    /// starts with that build's temporary folder and which stays running (and holding them) after the build.
    /// </summary>
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
                // conhost serves this process's own console.
                if (p.HasExited || p.StartTime < started || p.ProcessName.Equals("conhost", StringComparison.OrdinalIgnoreCase)) continue;
                found.Add(new Child(pid, p.ProcessName));
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
                // pid (comm) state ppid ...: comm may hold spaces and parentheses, so read after the last ')'.
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
    protected override ITestFrameworkExecutor CreateExecutor(AssemblyName assemblyName) =>
        new Executor(assemblyName, SourceInformationProvider, DiagnosticMessageSink);

    private sealed class Executor(AssemblyName assemblyName, ISourceInformationProvider sourceInformationProvider, IMessageSink diagnosticMessageSink)
        : XunitTestFrameworkExecutor(assemblyName, sourceInformationProvider, diagnosticMessageSink)
    {
        protected override async void RunTestCases(IEnumerable<IXunitTestCase> testCases, IMessageSink executionMessageSink, ITestFrameworkExecutionOptions executionOptions)
        {
            using var runner = new Runner(TestAssembly, testCases, DiagnosticMessageSink, executionMessageSink, executionOptions);
            await runner.RunAsync();
        }
    }

    private sealed class Runner(ITestAssembly testAssembly, IEnumerable<IXunitTestCase> testCases, IMessageSink diagnosticMessageSink,
        IMessageSink executionMessageSink, ITestFrameworkExecutionOptions executionOptions)
        : XunitTestAssemblyRunner(testAssembly, testCases, diagnosticMessageSink, executionMessageSink, executionOptions)
    {
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
