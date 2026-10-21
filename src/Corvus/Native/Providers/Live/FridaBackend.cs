using System.Security.AccessControl;
using System.Security.Principal;
using Corvus.Core;

namespace Corvus.Native.Providers.Live;

/// <summary>Starts the worker that holds one session; tests substitute a scripted one.</summary>
public interface ILiveBackend
{
    string Name { get; }
    /// <summary>Null when sessions can start, else why not and the next step.</summary>
    (string Reason, string Remediation)? Unavailable();
    WorkerConnection Start();
}

/// <summary>
/// Sessions through Frida's Python bindings: the first 64-bit Python that imports frida (CORVUS_FRIDA_PYTHON, then
/// the launcher and PATH) runs live_worker.py with the session script beside it.
/// </summary>
public sealed class FridaBackend : ILiveBackend
{
    public const string PythonVariable = "CORVUS_FRIDA_PYTHON";
    private const string WorkerResource = "Corvus.Native.Providers.Live.live_worker.py";
    private const string AgentResource = "Corvus.Native.Providers.Live.live_agent.js";
    private readonly Lazy<(PythonInterpreter? Python, string? Frida, string? Problem)> _python = new(Locate);

    public string Name => "frida";

    public (string Reason, string Remediation)? Unavailable() => PlatformProblem(OperatingSystem.IsMacOS())
        ?? (_python.Value.Problem is { } problem
            ? (problem, $"Install Frida's Python bindings (python -m pip install frida) in a 64-bit Python 3, or set {PythonVariable} to that python.")
            : FridaVersions.Refusal(_python.Value.Frida) is { } old ? (old, Upgrade) : null);

    /// <summary>The pip command that installs a Frida in the tested range.</summary>
    public static string Upgrade =>
        $"Install a tested Frida (python -m pip install \"frida>={FridaVersions.TestedFrom},<{FridaVersions.TestedMajor + 1}\"), or set {PythonVariable} to a python that has one.";

    /// <summary>The session script is written and tested for Windows and Linux only.</summary>
    internal static (string Reason, string Remediation)? PlatformProblem(bool macOS) => macOS
        ? ("Live sessions run on Windows and Linux; macOS is not supported yet.",
            "Run the server on Windows or Linux for live sessions; the static tools and open_minidump work on macOS.")
        : null;

    /// <summary>The interpreter sessions use, for server_status; null when none imports frida.</summary>
    public PythonInterpreter? Python => _python.Value.Python;

    /// <summary>frida.__version__ in that interpreter.</summary>
    public string? FridaVersion => _python.Value.Frida;

    private static (PythonInterpreter?, string?, string?) Locate()
    {
        var log = new List<string>();
        var seen = new HashSet<string>(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        // Each interpreter is asked for frida in turn, so one without it does not hide a later one that has it.
        foreach (var (path, source) in Candidates(log))
        {
            var exe = Directory.Exists(path) ? Path.Combine(path, OperatingSystem.IsWindows() ? "python.exe" : "python3") : path;
            if (!seen.Add(exe)) continue;
            if (!File.Exists(exe)) { log.Add($"{source}: {exe} does not exist"); continue; }
            var python = PythonLocator.Probe(exe, [], TimeSpan.FromSeconds(15), out var error);
            if (python == null) { log.Add($"{source}: {exe}: {error}"); continue; }
            if (python.Bits != 64 || python.Version < PythonLocator.MinimumVersion)
            {
                log.Add($"{source}: {python.Executable} is {python.Bits}-bit Python {python.Version}; 64-bit {PythonLocator.MinimumVersion}+ is required");
                continue;
            }
            python = python with { Source = source };
            var run = PythonLocator.RunCapture(python.Executable, ["-I", "-c", "import frida; print(frida.__version__)"], TimeSpan.FromSeconds(30));
            if (run.ExitCode == 0) return (python, run.Stdout.Trim(), null);
            log.Add($"{source}: {python.Executable} has no frida package");
        }
        return (null, null, "No 64-bit Python with Frida's bindings was found (" + (log.Count == 0 ? "no Python found" : string.Join("; ", log.Distinct())) + ").");
    }

    /// <summary>CORVUS_FRIDA_PYTHON, the interpreter the usual search finds first, then every python on PATH.</summary>
    private static IEnumerable<(string Path, string Source)> Candidates(List<string> log)
    {
        if (Environment.GetEnvironmentVariable(PythonVariable) is { Length: > 0 } env) yield return (env, PythonVariable);
        if (PythonLocator.Find([], log) is { } first) yield return (first.Executable, first.Source);
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            string candidate;
            try { candidate = Path.Combine(dir.Trim('"'), OperatingSystem.IsWindows() ? "python.exe" : "python3"); }
            catch (ArgumentException) { continue; }
            if (File.Exists(candidate)) yield return (candidate, "PATH");
        }
    }

    public WorkerConnection Start()
    {
        var python = _python.Value.Python ?? throw new ToolError(ErrorCode.ProviderUnavailable, Unavailable()!.Value.Reason, Unavailable()!.Value.Remediation);
        var dir = Path.Combine(AnalysisCache.DefaultRoot, "workers");
        var worker = EmbeddedScript.Extract(WorkerResource, dir, "live_worker", ".py");
        var agent = EmbeddedScript.Extract(AgentResource, dir, "live_agent", ".js");
        // Frida unpacks its helper DLLs into TEMP and leaves them: each worker gets a folder of its own, removed when it ends.
        var temp = Path.Combine(dir, "live-temp", Guid.NewGuid().ToString("N")[..12]);
        Directory.CreateDirectory(temp);
        if (OperatingSystem.IsWindows()) AllowSandboxedReads(temp);
        var start = new ChildProcessStart(python.Executable, ["-I", "-u", worker, agent])
        {
            WorkingDirectory = dir,
            Environment = ExternalTools.MinimalEnvironment(new Dictionary<string, string?> { ["TEMP"] = temp, ["TMP"] = temp }),
        };
        try
        {
            var connection = WorkerConnection.Start("session worker", start, Remediation);
            _ = connection.Closed.ContinueWith(_ => RemoveLater(temp), TaskScheduler.Default);
            return connection;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException)
        {
            _ = RemoveLater(temp);
            throw new ToolError(ErrorCode.ProviderUnavailable, $"The session worker could not be started with {python.Executable}: {ex.Message}",
                $"Check the Python install or set {PythonVariable}.");
        }
    }

    /// <summary>The next step for a worker failure the default wording does not fit: an open that timed out waits on the program, not on its size.</summary>
    internal static string? Remediation(ErrorCode code, string op) => code == ErrorCode.Timeout && op == "open"
        ? "the program did not load the session's agent in time (starting up, exiting, or blocked): try again once it runs"
        : null;

    /// <summary>
    /// Grants read and execute on <paramref name="folder"/> to RESTRICTED and ALL APPLICATION PACKAGES: a child that
    /// runs with a restricted token or in an AppContainer (a Chromium sandbox) loads the agent DLL from here.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    internal static void AllowSandboxedReads(string folder)
    {
        var info = new DirectoryInfo(folder);
        var acl = info.GetAccessControl();
        foreach (var sid in new[] { new SecurityIdentifier(WellKnownSidType.RestrictedCodeSid, null), new SecurityIdentifier("S-1-15-2-1") })
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.ReadAndExecute,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        info.SetAccessControl(acl);
    }

    /// <summary>Deletes a worker's temp folder once its files are no longer held (a few tries over about 10 s).</summary>
    private static async Task RemoveLater(string folder)
    {
        for (int i = 0; i < 20 && Directory.Exists(folder); i++)
        {
            try { Directory.Delete(folder, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { await Task.Delay(500).ConfigureAwait(false); }
        }
    }
}
