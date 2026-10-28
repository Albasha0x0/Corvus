using System.Text;

namespace Corvus.Native.Providers;

/// <summary>A Python interpreter that passed the checks, with its reported version and pointer size.</summary>
public sealed record PythonInterpreter(string Executable, Version Version, int Bits, string Source);

/// <summary>Finds a worker's Python (preferred candidates, <c>py -3</c>, then PATH), each run once in isolated mode and resolved to the real interpreter, so no launcher process sits in between.</summary>
public static class PythonLocator
{
    public static readonly Version MinimumVersion = new(3, 9);
    internal const string ProbeScript = "import sys,struct;print(sys.version_info[0],sys.version_info[1],struct.calcsize('P')*8);print(sys.executable)";

    /// <summary>How long a candidate may stay idle before it counts as not answering, unless the caller gives more.</summary>
    public static readonly TimeSpan DefaultProbeTimeout = TimeSpan.FromSeconds(15);

    // The probe limit counts idle time only, as a busy machine stretches a start; this many limits bound the whole probe.
    private const int ProbeCapLimits = 3;

    /// <summary>Returns the first working 64-bit interpreter, or null; <paramref name="log"/> lists every candidate and why it was rejected.</summary>
    public static PythonInterpreter? Find(IEnumerable<(string Path, string Source)> preferred, List<string> log, TimeSpan? probeTimeout = null) =>
        Search(preferred, log, probeTimeout ?? DefaultProbeTimeout).Python;

    /// <summary><see cref="Find"/>, and whether a candidate timed out, making a null result unknown rather than absent.</summary>
    public static (PythonInterpreter? Python, bool Unanswered) Search(IEnumerable<(string Path, string Source)> preferred, List<string> log, TimeSpan probeTimeout) =>
        Search(preferred, log, probeTimeout, defaults: true);

    /// <summary><see cref="Search(IEnumerable{ValueTuple{string, string}}, List{string}, TimeSpan)"/>; without <paramref name="defaults"/>, only <paramref name="preferred"/>.</summary>
    internal static (PythonInterpreter? Python, bool Unanswered) Search(IEnumerable<(string Path, string Source)> preferred, List<string> log, TimeSpan probeTimeout, bool defaults)
    {
        bool unanswered = false;
        var seen = new HashSet<string>(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        foreach (var (exe, args, source) in Candidates(preferred, defaults))
        {
            if (!seen.Add(exe + "|" + string.Join(" ", args))) continue;
            if (!File.Exists(exe)) { log.Add($"{source}: {exe} does not exist"); continue; }
            var result = Probe(exe, args, probeTimeout, out var error, out var timedOut);
            unanswered |= timedOut;
            if (result == null) { log.Add($"{source}: {exe}: {error}"); continue; }
            if (result.Bits != 64) { log.Add($"{source}: {result.Executable} is {result.Bits}-bit; a 64-bit Python is required"); continue; }
            if (result.Version < MinimumVersion) { log.Add($"{source}: {result.Executable} is Python {result.Version}; {MinimumVersion}+ is required"); continue; }
            return (result with { Source = source }, false);
        }
        return (null, unanswered);
    }

    private static IEnumerable<(string Exe, string[] Args, string Source)> Candidates(IEnumerable<(string Path, string Source)> preferred, bool defaults)
    {
        foreach (var (path, source) in preferred)
        {
            if (string.IsNullOrWhiteSpace(path)) continue;
            var p = Directory.Exists(path) ? System.IO.Path.Combine(path, OperatingSystem.IsWindows() ? "python.exe" : "python3") : path;
            yield return (p, [], source);
        }
        if (!defaults) yield break;
        if (OperatingSystem.IsWindows())
        {
            var launcher = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "py.exe");
            var localLauncher = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Python", "Launcher", "py.exe");
            foreach (var l in new[] { launcher, localLauncher, OnPath("py.exe") })
                if (l != null && File.Exists(l)) { yield return (l, ["-3"], "py -3"); break; }
        }
        foreach (var name in OperatingSystem.IsWindows() ? new[] { "python.exe", "python3.exe" } : ["python3", "python"])
            if (OnPath(name) is { } p) yield return (p, [], "PATH");
    }

    private static string? OnPath(string name)
    {
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(System.IO.Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            // The Microsoft Store alias opens the Store instead of running Python when none is installed.
            if (dir.Contains(@"\Microsoft\WindowsApps", StringComparison.OrdinalIgnoreCase)) continue;
            try
            {
                var p = System.IO.Path.Combine(dir.Trim('"'), name);
                if (File.Exists(p)) return p;
            }
            catch (ArgumentException) { }
        }
        return null;
    }

    /// <summary>Runs the probe script; returns null with <paramref name="error"/> set when the interpreter does not work.</summary>
    public static PythonInterpreter? Probe(string exe, string[] launcherArgs, TimeSpan timeout, out string error) =>
        Probe(exe, launcherArgs, timeout, out error, out _);

    private static PythonInterpreter? Probe(string exe, string[] launcherArgs, TimeSpan timeout, out string error, out bool timedOut)
    {
        var run = RunCapture(exe, [.. launcherArgs, "-I", "-c", ProbeScript], timeout, cap: timeout * ProbeCapLimits);
        timedOut = run.TimedOut;
        if (run.TimedOut) { error = run.Stopped ?? $"did not answer within {timeout.TotalSeconds:0} s"; return null; }
        if (run.StartError != null) { error = run.StartError; return null; }
        var lines = run.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (run.ExitCode != 0 || lines.Length < 2)
        {
            error = $"exit code {run.ExitCode}: {Last(run.Stderr.Length > 0 ? run.Stderr : run.Stdout)}";
            return null;
        }
        var parts = lines[0].Split(' ');
        if (parts.Length != 3 || !int.TryParse(parts[0], out var major) || !int.TryParse(parts[1], out var minor) || !int.TryParse(parts[2], out var bits))
        {
            error = "unexpected probe output: " + lines[0];
            return null;
        }
        error = "";
        return new PythonInterpreter(lines[1], new Version(major, minor), bits, "");
    }

    private static string Last(string text) =>
        text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).LastOrDefault() ?? "(no output)";

    /// <summary>A finished run; <paramref name="Stopped"/> names the limit that stopped a timed-out run, null when it is the plain timeout.</summary>
    public sealed record CaptureResult(int? ExitCode, string Stdout, string Stderr, bool TimedOut, string? StartError, string? Stopped = null);

    /// <summary>Runs a short process in its own job, capturing output; with <paramref name="cap"/>, <paramref name="timeout"/> counts idle time only.</summary>
    /// <remarks>The tree is killed on timeout; the cap bounds the whole run.</remarks>
    public static CaptureResult RunCapture(string exe, IReadOnlyList<string> args, TimeSpan timeout, IReadOnlyDictionary<string, string?>? environment = null,
        TimeSpan? cap = null)
    {
        ChildProcess child;
        try
        {
            child = ChildProcess.Start(new ChildProcessStart(exe, args) { Environment = environment ?? new Dictionary<string, string?>() });
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException)
        {
            return new CaptureResult(null, "", "", false, ex.Message);
        }
        using (child)
        {
            child.StandardInput.Dispose();
            var watch = System.Diagnostics.Stopwatch.StartNew();
            string stdout = "", stderr = "";
            Thread[] readers = [ChildProcess.StartReader(() => stdout = ReadAll(child.StandardOutput)), ChildProcess.StartReader(() => stderr = ReadAll(child.StandardError))];
            var bound = cap is { } c && c > timeout ? c : timeout;
            string? stopped = null;
            var exited = bound > timeout ? WaitWhileBusy(child, timeout, bound, out stopped) : child.Exited.Wait(timeout);
            // A tree still holding the output at the deadline is stopped, which ends it.
            if (!exited || !ChildProcess.JoinReaders(readers, watch, bound))
            {
                child.Kill();
                // A killed POSIX child's exit is reaped after the kill returns; until then it has no exit code.
                child.Exited.Wait(TimeSpan.FromSeconds(2));
            }
            ChildProcess.JoinReaders(readers, System.Diagnostics.Stopwatch.StartNew(), TimeSpan.FromSeconds(2));
            return new CaptureResult(child.ExitCode, stdout, stderr, !exited, null, exited ? null : stopped);
        }
    }

    private static bool WaitWhileBusy(ChildProcess child, TimeSpan idle, TimeSpan cap, out string? stopped)
    {
        var watch = System.Diagnostics.Stopwatch.StartNew();
        return WaitWhileBusy(wait => child.Exited.Wait(wait), child.TreeCpuTime, () => watch.Elapsed, idle, cap, out stopped);
    }

    /// <summary>True once the tree exits; false after <paramref name="idle"/> under 0.1% CPU (or unreadable CPU) or at <paramref name="cap"/>, naming the limit.</summary>
    internal static bool WaitWhileBusy(Func<TimeSpan, bool> waitExit, Func<TimeSpan?> cpuTime, Func<TimeSpan> elapsed, TimeSpan idle, TimeSpan cap,
        out string? stopped)
    {
        var step = idle / 8;
        var samples = new Queue<(TimeSpan At, TimeSpan Cpu)>();
        while (true)
        {
            var now = elapsed();
            if (cpuTime() is not { } cpu)
            {
                stopped = $"did not answer within {idle.TotalSeconds:0.#} s";
                return waitExit(idle - now > TimeSpan.Zero ? idle - now : TimeSpan.Zero);
            }
            samples.Enqueue((now, cpu));
            while (samples.Count > 1 && now - samples.ElementAt(1).At >= idle) samples.Dequeue();
            var (first, used) = samples.Peek();
            // An interpreter's whole start uses about 50 ms of CPU, under 1% of a 15 s limit, so idle is under 0.1%.
            if (now - first >= idle && cpu - used < idle / 1000)
            {
                stopped = $"did not answer within {idle.TotalSeconds:0.#} s spent under 0.1% of a core";
                return false;
            }
            var left = cap - now;
            if (left <= TimeSpan.Zero)
            {
                stopped = $"did not answer within its overall limit of {cap.TotalSeconds:0.#} s";
                return false;
            }
            if (waitExit(left < step ? left : step)) { stopped = null; return true; }
        }
    }

    private static string ReadAll(Stream s)
    {
        try
        {
            using var r = new StreamReader(s, new UTF8Encoding(false), false, 4096, leaveOpen: true);
            return r.ReadToEnd();
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException) { return ""; }
    }
}
