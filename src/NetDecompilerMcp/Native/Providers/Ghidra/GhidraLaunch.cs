using System.Collections.Concurrent;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native.Providers.Ghidra;

/// <summary>
/// Private directories of the Ghidra workers under the analysis cache. Ghidra writes its settings, logs, export
/// symbol files and packed-database cache to the user's application data unless all four are redirected.
/// </summary>
public sealed record GhidraDirectories(string Root)
{
    public string Home => Path.Combine(Root, "home");
    public string Settings => Path.Combine(Root, "settings");
    public string Cache => Path.Combine(Root, "cache");
    public string Temp => Path.Combine(Root, "tmp");
    public string Workers => Path.Combine(Root, "worker");

    public void Create()
    {
        foreach (var d in new[] { Home, Settings, Cache, Temp, Workers }) Directory.CreateDirectory(d);
    }
}

/// <summary>The JVM command of a worker: Ghidra's own VM arguments, heap, private directories and the two worker jars.</summary>
public static class GhidraLaunch
{
    public const string BootClass = "ndm.ghidra.Boot";
    public const string WorkerJarProperty = "ndm.worker.jar";

    private static readonly ConcurrentDictionary<(string, DateTime), IReadOnlyList<string>> VmArgsCache = new();

    /// <summary>The VM arguments of support/launch.properties for this OS, via LaunchSupport; cached per install and file time.</summary>
    public static IReadOnlyList<string> VmArgs(GhidraInstallation ghidra, JavaRuntime java)
    {
        var properties = Path.Combine(ghidra.Directory, "support", "launch.properties");
        var key = (ghidra.Directory, File.Exists(properties) ? File.GetLastWriteTimeUtc(properties) : default);
        if (VmArgsCache.TryGetValue(key, out var cached)) return cached;
        var run = PythonLocator.RunCapture(java.Java, ["-cp", ghidra.LaunchSupportJar, "LaunchSupport", ghidra.Directory, "-vmargs"], TimeSpan.FromSeconds(30));
        if (run.StartError != null || run.TimedOut || run.ExitCode != 0)
            throw new ToolError(ErrorCode.ProviderUnavailable,
                $"Ghidra's LaunchSupport failed with {java.Java}: {run.StartError ?? (run.TimedOut ? "timed out" : $"exit code {run.ExitCode}")} {run.Stderr.Trim()}".TrimEnd(),
                $"Check the JDK ({GhidraOptions.JavaVariable}) and the Ghidra install ({GhidraOptions.DirectoryVariable}).");
        var args = run.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Where(l => l.StartsWith('-')).ToList();
        if (!args.Any(a => a.Contains("GhidraClassLoader", StringComparison.Ordinal)))
            throw new ToolError(ErrorCode.ProviderUnavailable, $"Ghidra's LaunchSupport returned no class loader argument for {ghidra.Directory}.",
                "Unpack the Ghidra release archive again.");
        VmArgsCache[key] = args;
        return args;
    }

    /// <summary>Arguments after the java executable: <paramref name="vmArgs"/>, heap, private directories, then ghidra.Ghidra starting the boot class.</summary>
    public static IReadOnlyList<string> Arguments(GhidraInstallation ghidra, IReadOnlyList<string> vmArgs, string maxMemory, GhidraDirectories dirs,
        string bootJar, string workerJar)
    {
        var args = new List<string>(vmArgs)
        {
            "-Xmx" + maxMemory,
            "-XX:ParallelGCThreads=" + Math.Clamp(Environment.ProcessorCount / 2, 1, 4),
            "-Djava.awt.headless=true",
            "-Duser.home=" + dirs.Home,
            "-Dapplication.settingsdir=" + dirs.Settings,
            "-Dapplication.cachedir=" + dirs.Cache,
            "-Dapplication.tempdir=" + dirs.Temp,
            "-Djava.io.tmpdir=" + dirs.Temp,
            $"-D{WorkerJarProperty}={workerJar}",
            "-cp",
            ghidra.UtilityJar + Path.PathSeparator + bootJar,
            "ghidra.Ghidra",
            BootClass,
        };
        return args;
    }
}
