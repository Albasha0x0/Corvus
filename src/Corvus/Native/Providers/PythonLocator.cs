using System.Text;

namespace Corvus.Native.Providers;

/// <summary>A Python interpreter that passed the checks, with its reported version and pointer size.</summary>
public sealed record PythonInterpreter(string Executable, Version Version, int Bits, string Source);

/// <summary>
/// Finds a Python interpreter for a worker: explicit candidates first (an override, an engine's configured
/// interpreter), then the Windows launcher (<c>py -3</c>), then PATH. Each candidate is run once in isolated mode
/// to read its version, pointer size and real executable (the launcher and PATH shims are resolved to the
/// interpreter itself so the worker is not started through a launcher process).
/// </summary>
public static class PythonLocator
{
    public static readonly Version MinimumVersion = new(3, 9);
    private const string ProbeScript = "import sys,struct;print(sys.version_info[0],sys.version_info[1],struct.calcsize('P')*8);print(sys.executable)";

    /// <summary>How long a candidate may take to answer unless the caller gives more.</summary>
    public static readonly TimeSpan DefaultProbeTimeout = TimeSpan.FromSeconds(15);

    /// <summary>Returns the first working 64-bit interpreter, or null; <paramref name="log"/> lists every candidate and why it was rejected.</summary>
    public static PythonInterpreter? Find(IEnumerable<(string Path, string Source)> preferred, List<string> log, TimeSpan? probeTimeout = null) =>
        Search(preferred, log, probeTimeout ?? DefaultProbeTimeout).Python;

    /// <summary>
    /// <see cref="Find"/>, and whether a candidate gave no answer within <paramref name="probeTimeout"/>: a null
    /// interpreter is then unknown rather than absent, and a search with more time may find one.
    /// </summary>
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
        var run = RunCapture(exe, [.. launcherArgs, "-I", "-c", ProbeScript], timeout);
        timedOut = run.TimedOut;
        if (run.TimedOut) { error = $"did not answer within {timeout.TotalSeconds:0} s"; return null; }
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

    public sealed record CaptureResult(int? ExitCode, string Stdout, string Stderr, bool TimedOut, string? StartError);

    /// <summary>Runs a short-lived process in its own job, capturing output; the tree is killed on timeout.</summary>
    public static CaptureResult RunCapture(string exe, IReadOnlyList<string> args, TimeSpan timeout, IReadOnlyDictionary<string, string?>? environment = null)
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
            var exited = child.Exited.Wait(timeout);
            // A tree still holding the output at the deadline is stopped, which ends it.
            if (!exited || !ChildProcess.JoinReaders(readers, watch, timeout)) child.Kill();
            ChildProcess.JoinReaders(readers, System.Diagnostics.Stopwatch.StartNew(), TimeSpan.FromSeconds(2));
            return new CaptureResult(child.ExitCode, stdout, stderr, !exited, null);
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
