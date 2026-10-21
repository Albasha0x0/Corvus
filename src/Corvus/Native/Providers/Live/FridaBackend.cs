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
/// Sessions through Frida's Python bindings, run by live_worker.py with the session script beside it. The interpreter, in
/// order: CORVUS_FRIDA_PYTHON; with <see cref="InstallPinned"/>, the private environment once made; the first user
/// Python (the launcher, then PATH) with a tested Frida; with <see cref="InstallPinned"/>, a new private environment;
/// else the first user Python with any Frida.
/// </summary>
public sealed class FridaBackend : ILiveBackend
{
    public const string PythonVariable = "CORVUS_FRIDA_PYTHON";
    private const string WorkerResource = "Corvus.Native.Providers.Live.live_worker.py";
    private const string AgentResource = "Corvus.Native.Providers.Live.live_agent.js";
    private readonly Lazy<Located> _found, _ready;

    public FridaBackend()
    {
        _found = new(() => Locate(create: false));
        _ready = new(() => _found.Value.Python == null && _found.Value.Pending ? Locate(create: true) : _found.Value);
    }

    /// <summary>The interpreter chosen, its frida.__version__, why none was, and whether the private environment is still to be made.</summary>
    private sealed record Located(PythonInterpreter? Python, string? Frida, string? Problem, bool Pending = false);

    /// <summary>--live-install-frida: make and use the private environment (<see cref="FridaEnvironment"/>) when no tested Frida is found.</summary>
    public bool InstallPinned { get; init; }

    public FridaEnvironment PrivateEnvironment { get; init; } = FridaEnvironment.Default;

    /// <summary>Whether CORVUS_FRIDA_PYTHON is read; a test of the private environment turns it off, since the variable wins.</summary>
    internal bool ReadsPythonVariable { get; init; } = true;

    public string Name => "frida";

    public (string Reason, string Remediation)? Unavailable() => _ready.Value.Problem is { } problem
        ? (problem, InstallPinned && _ready.Value.Pending
            ? "Unset CORVUS_OFFLINE, or install a tested Frida yourself (python -m pip install frida) and restart the server."
            : $"Install Frida's Python bindings (python -m pip install frida) in a 64-bit Python 3, or set {PythonVariable} to that python, or start the server with {Core.ServerOptions.LiveInstallFridaOption}.")
        : FridaVersions.Refusal(_ready.Value.Frida) is { } old ? (old, Upgrade) : null;

    /// <summary>The pip command that installs a Frida in the tested range.</summary>
    public static string Upgrade =>
        $"Install a tested Frida (python -m pip install \"frida>={FridaVersions.TestedFrom},<{FridaVersions.TestedMajor + 1}\"), or set {PythonVariable} to a python that has one.";

    private Located Current => _ready.IsValueCreated ? _ready.Value : _found.Value;

    /// <summary>The interpreter sessions use, for server_status (Source: CORVUS_FRIDA_PYTHON, py -3, PATH or private environment); null when none imports frida.</summary>
    public PythonInterpreter? Python => Current.Python;

    /// <summary>frida.__version__ in that interpreter.</summary>
    public string? FridaVersion => Current.Frida;

    /// <summary>True when the private environment is to be made by the next session (it is not made for server_status).</summary>
    public bool PrivatePending => Current.Pending && Current.Python == null;

    /// <summary>The order of choice over the interpreters found (lazily, in search order) and the private environment.</summary>
    internal static (PythonInterpreter? Python, string? Frida, bool CreatePrivate) Choose(IEnumerable<(PythonInterpreter Python, string? Frida)> found,
        bool install, (PythonInterpreter Python, string Frida)? privateEnvironment)
    {
        (PythonInterpreter, string)? any = null;
        bool first = true;
        foreach (var (python, frida) in found)
        {
            bool variable = first && python.Source == PythonVariable;
            first = false;
            if (variable && frida != null) return (python, frida, false);
            if (install && privateEnvironment is { } p) return (p.Python, p.Frida, false);
            if (frida == null) continue;
            if (FridaVersions.Parse(frida) is { } v && FridaVersions.Tested(v)) return (python, frida, false);
            any ??= (python, frida);
        }
        if (install && privateEnvironment is { } made) return (made.Python, made.Frida, false);
        if (install) return (null, null, true);
        return any is var (u, f) ? (u, f, false) : (null, null, false);
    }

    private Located Locate(bool create)
    {
        var log = new List<string>();
        PythonInterpreter? basePython = null;
        (PythonInterpreter, string)? privateEnvironment = null;
        if (InstallPinned && PrivateEnvironment.Complete && Ask(PrivateEnvironment.Python, FridaEnvironment.Source, log) is { Frida: { } pinned } p)
            privateEnvironment = (p.Python, pinned);
        var (python, frida, createPrivate) = Choose(Found(log, ReadsPythonVariable, found => basePython ??= found), InstallPinned, privateEnvironment);
        if (python != null) return new(python, frida, null);
        if (createPrivate)
        {
            if (!create) return new(null, null, null, Pending: true);
            var made = PrivateEnvironment.Create(basePython, out var problem);
            if (made != null && Ask(made, FridaEnvironment.Source, log) is { Frida: not null } ready) return new(ready.Python, ready.Frida, null);
            return new(null, null, problem ?? $"The private Frida environment ({PrivateEnvironment.Folder}) has no working frida ({string.Join("; ", log)}).", Pending: true);
        }
        return new(null, null, "No 64-bit Python with Frida's bindings was found (" + (log.Count == 0 ? "no Python found" : string.Join("; ", log.Distinct())) + ").");
    }

    /// <summary>Each usable interpreter in search order with its frida version (null without one); <paramref name="usable"/> sees each first.</summary>
    private static IEnumerable<(PythonInterpreter Python, string? Frida)> Found(List<string> log, bool variable, Action<PythonInterpreter> usable)
    {
        var seen = new HashSet<string>(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        foreach (var (path, source) in Candidates(log, variable))
        {
            var exe = Directory.Exists(path) ? Path.Combine(path, OperatingSystem.IsWindows() ? "python.exe" : "python3") : path;
            if (!seen.Add(exe)) continue;
            if (Ask(exe, source, log) is not { } found) continue;
            usable(found.Python);
            yield return found;
        }
    }

    /// <summary>A 64-bit Python 3.9+ at <paramref name="exe"/> and its frida version (null without one); null when it is not usable.</summary>
    private static (PythonInterpreter Python, string? Frida)? Ask(string exe, string source, List<string> log)
    {
        if (!File.Exists(exe)) { log.Add($"{source}: {exe} does not exist"); return null; }
        var python = PythonLocator.Probe(exe, [], TimeSpan.FromSeconds(15), out var error);
        if (python == null) { log.Add($"{source}: {exe}: {error}"); return null; }
        if (python.Bits != 64 || python.Version < PythonLocator.MinimumVersion)
        {
            log.Add($"{source}: {python.Executable} is {python.Bits}-bit Python {python.Version}; 64-bit {PythonLocator.MinimumVersion}+ is required");
            return null;
        }
        python = python with { Source = source };
        var run = PythonLocator.RunCapture(python.Executable, ["-I", "-c", "import frida; print(frida.__version__)"], TimeSpan.FromSeconds(30));
        if (run.ExitCode == 0) return (python, run.Stdout.Trim());
        log.Add($"{source}: {python.Executable} has no frida package");
        return (python, null);
    }

    /// <summary>CORVUS_FRIDA_PYTHON, the interpreter the usual search finds first, then every python on PATH.</summary>
    private static IEnumerable<(string Path, string Source)> Candidates(List<string> log, bool variable)
    {
        if (variable && Environment.GetEnvironmentVariable(PythonVariable) is { Length: > 0 } env) yield return (env, PythonVariable);
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
        var python = _ready.Value.Python ?? throw new ToolError(ErrorCode.ProviderUnavailable, Unavailable()!.Value.Reason, Unavailable()!.Value.Remediation);
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
