using System.Runtime.InteropServices;

namespace Corvus.Native.Providers.Live;

/// <summary>The --live-install-frida venv holding Frida <see cref="FridaVersions.Pinned"/>, installed from hash-checked wheels only.</summary>
public sealed class FridaEnvironment(string folder)
{
    public const string Source = "private environment";
    private const string CompleteMarker = "corvus-complete";
    private static readonly TimeSpan VenvTimeout = TimeSpan.FromMinutes(2), PipTimeout = TimeSpan.FromMinutes(10), PipProbeTimeout = TimeSpan.FromSeconds(30);
    private static readonly object Gate = new();

    public static FridaEnvironment Default => new(DataFolder.Combine("frida", "python-" + FridaVersions.Pinned));

    public string Folder { get; } = Path.GetFullPath(folder);

    /// <summary>Runs a process to completion; tests substitute a scripted one.</summary>
    public Func<string, IReadOnlyList<string>, TimeSpan, PythonLocator.CaptureResult> Run { get; init; } =
        (exe, args, timeout) => PythonLocator.RunCapture(exe, args, timeout);

    public bool Offline { get; init; } = Core.ReferencePacks.Offline;

    public string Platform { get; init; } =
        FridaVersions.Platform(OperatingSystem.IsWindows(), OperatingSystem.IsLinux(), RuntimeInformation.OSArchitecture);

    public string Python => OperatingSystem.IsWindows() ? Path.Combine(Folder, "Scripts", "python.exe") : Path.Combine(Folder, "bin", "python3");

    /// <summary>Whether a finished install is there (the marker is written last).</summary>
    public bool Complete => File.Exists(Path.Combine(Folder, CompleteMarker)) && File.Exists(Python);

    /// <summary>Creates the environment from <paramref name="basePython"/> unless complete; returns its python, or null with <paramref name="problem"/>.</summary>
    public string? Create(PythonInterpreter? basePython, out string? problem)
    {
        problem = null;
        if (Complete) return Python;
        if (Offline) { problem = $"CORVUS_OFFLINE is set: the private Frida environment ({Folder}) is not created, as it needs a download of Frida {FridaVersions.Pinned}."; return null; }
        if (FridaVersions.Requirements(Platform) is not { } requirements) { problem = $"No Frida {FridaVersions.Pinned} wheel is pinned for {Platform}."; return null; }
        if (basePython == null) { problem = "No 64-bit Python 3 was found to create the private Frida environment with."; return null; }
        lock (Gate)
        {
            try
            {
                using var held = Hold();
                // Another server made it meanwhile.
                if (Complete) return Python;
                // An unfinished environment (no marker) is made again from scratch.
                if (Directory.Exists(Folder)) Directory.Delete(Folder, recursive: true);
                Directory.CreateDirectory(Folder);
                // ensurepip overran the 2 min bound on a loaded machine: a base pip with --python installs instead.
                bool basePip = PipTargetsOtherPython(basePython.Executable);
                if (Step(basePython.Executable, basePip ? ["-I", "-m", "venv", "--without-pip", Folder] : ["-I", "-m", "venv", Folder], VenvTimeout, "python -m venv", out problem))
                    return null;
                var list = Path.Combine(Folder, "requirements.txt");
                File.WriteAllText(list, requirements);
                string[] install = ["install", "--disable-pip-version-check", "--no-input", "--only-binary", ":all:", "--require-hashes", "-r", list];
                if (Step(basePip ? basePython.Executable : Python, basePip ? ["-I", "-m", "pip", "--python", Python, .. install] : ["-I", "-m", "pip", .. install],
                        PipTimeout, "pip install", out problem)) return null;
                File.WriteAllText(Path.Combine(Folder, CompleteMarker), FridaVersions.Pinned + "\n");
                return Python;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                problem = $"The private Frida environment ({Folder}) could not be created: {ex.Message}";
                return null;
            }
        }
    }

    /// <summary>The lock file beside the folder, held by one server process at a time while it makes the environment.</summary>
    private FileStream Hold()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Folder)!);
        var deadline = DateTime.UtcNow + PipProbeTimeout + PipTimeout + VenvTimeout;
        while (true)
        {
            try { return new FileStream(Folder + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException) when (DateTime.UtcNow < deadline) { Thread.Sleep(1000); }
        }
    }

    /// <summary>Whether <paramref name="python"/> has pip 22.3 or later, which takes --python; false when pip is missing or older.</summary>
    private bool PipTargetsOtherPython(string python)
    {
        var run = Run(python, ["-I", "-m", "pip", "--version"], PipProbeTimeout);
        var m = System.Text.RegularExpressions.Regex.Match(run.ExitCode == 0 ? run.Stdout : "", @"^pip (\d+)\.(\d+)");
        return m.Success && new Version(int.Parse(m.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture),
            int.Parse(m.Groups[2].Value, System.Globalization.CultureInfo.InvariantCulture)) >= new Version(22, 3);
    }

    /// <summary>Runs one step; true (with <paramref name="problem"/>) when it failed.</summary>
    private bool Step(string exe, IReadOnlyList<string> args, TimeSpan timeout, string what, out string? problem)
    {
        var run = Run(exe, args, timeout);
        problem = run.StartError != null ? $"{what} could not start: {run.StartError}"
            : run.TimedOut ? $"{what} did not finish within {timeout.TotalMinutes:0} min"
            : run.ExitCode != 0 ? $"{what} failed (exit code {run.ExitCode}): {Last(run.Stderr.Length > 0 ? run.Stderr : run.Stdout)}"
            : null;
        if (problem != null) problem = $"The private Frida environment ({Folder}) could not be created: {problem}.";
        return problem != null;
    }

    private static string Last(string text) =>
        text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).LastOrDefault() ?? "(no output)";
}
