using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native.Providers.Ida;

public sealed record IdaProviderOptions
{
    /// <summary>IDA install directory; null: NDM_IDA_DIR, then ida-config.json.</summary>
    public string? InstallDirectory { get; init; }
    /// <summary>Python executable or directory; null: NDM_IDA_PYTHON, IDA's configured Python, py -3, PATH.</summary>
    public string? PythonPath { get; init; }
    /// <summary>Root of the private input copies and databases; null: <see cref="AnalysisCache.DefaultRoot"/>.</summary>
    public string? CacheRoot { get; init; }
    /// <summary>
    /// Run with the user's IDA directory (IDAUSR) and therefore the user's plugins. Off by default: the worker gets a
    /// private IDAUSR, so third-party plugins neither slow down nor destabilize headless analysis.
    /// </summary>
    public bool UseUserPlugins { get; init; }
    /// <summary>Time the worker gets to save and exit on close before it is killed.</summary>
    public TimeSpan ShutdownGrace { get; init; } = TimeSpan.FromSeconds(30);
    /// <summary>Time for the Python process to start and report ready (before idalib loads).</summary>
    public TimeSpan StartTimeout { get; init; } = TimeSpan.FromSeconds(60);
    /// <summary>Consecutive worker failures a session survives by restarting from the saved database.</summary>
    public int MaxRestarts { get; init; } = 3;
}

/// <summary>
/// IDA Pro through idalib, driven by a Python worker process (Native/Providers/Ida/ida_worker.py) per session. The
/// worker runs inside a kill-on-close Job Object on Windows, works on a private copy of the input and keeps its
/// .i64 database per SHA-256 in the analysis cache.
/// </summary>
public sealed class IdaProvider(IdaProviderOptions? options = null) : INativeDecompilerProvider
{
    public const string ProviderId = "ida";
    public const string PythonVariable = "NDM_IDA_PYTHON";
    internal const string WorkerResource = "NetDecompilerMcp.Native.Providers.Ida.ida_worker.py";

    private readonly IdaProviderOptions _options = options ?? new IdaProviderOptions();
    private readonly ConcurrentDictionary<IdaSession, byte> _sessions = new();
    private readonly object _availabilityLock = new();
    private (ProviderAvailability Result, IdaInstallation? Ida, PythonInterpreter? Python)? _static;
    private int _disposed;

    public string Id => ProviderId;
    public string DisplayName => "IDA Pro (idalib)";
    internal IdaProviderOptions Options => _options;
    internal AnalysisCache Cache { get; } = new((options ?? new IdaProviderOptions()).CacheRoot ?? AnalysisCache.DefaultRoot);

    public ProviderAvailability CheckAvailability() => Static().Result;

    private (ProviderAvailability Result, IdaInstallation? Ida, PythonInterpreter? Python) Static()
    {
        lock (_availabilityLock)
            return _static ??= ComputeStatic();
    }

    private (ProviderAvailability, IdaInstallation?, PythonInterpreter?) ComputeStatic()
    {
        var ida = IdaInstallation.Locate(_options.InstallDirectory, out var reason, out var remediation);
        if (ida == null) return (ProviderAvailability.Missing(Id, reason, remediation), null, null);

        var preferred = new List<(string, string)>();
        if (_options.PythonPath != null) preferred.Add((_options.PythonPath, "configured"));
        if (Environment.GetEnvironmentVariable(PythonVariable) is { Length: > 0 } env) preferred.Add((env, PythonVariable));
        if (IdaInstallation.ConfiguredPythonDirectory() is { } idaPython) preferred.Add((idaPython, "IDA Python3TargetDLL"));
        var log = new List<string>();
        var python = PythonLocator.Find(preferred, log);
        var details = new Dictionary<string, string> { ["install_dir"] = ida.Directory, ["install_source"] = ida.Source };
        if (python == null)
        {
            details["python_candidates"] = log.Count == 0 ? "none found" : string.Join("; ", log);
            return (ProviderAvailability.Missing(Id,
                $"No usable 64-bit Python {PythonLocator.MinimumVersion}+ was found for idalib ({details["python_candidates"]}).",
                $"Install 64-bit Python 3 from python.org, select it for IDA with idapyswitch, or set {PythonVariable} to python.exe.", details), ida, null);
        }
        details["python"] = $"{python.Executable} ({python.Version}, {python.Source})";
        return (ProviderAvailability.Ok(Id, details), ida, python);
    }

    public async Task<ProviderAvailability> ProbeAsync(CancellationToken cancellationToken = default)
    {
        var (result, ida, python) = Static();
        if (!result.IsAvailable) return result;
        var details = new Dictionary<string, string>(result.Details);
        try
        {
            using var worker = StartWorker(ida!, python!);
            await worker.WaitReadyAsync(_options.StartTimeout, cancellationToken).ConfigureAwait(false);
            var hello = await worker.RequestAsync("hello", null, TimeSpan.FromMinutes(2), cancellationToken).ConfigureAwait(false);
            if (hello.TryGetProperty("version", out var v) && v.GetString() is { } version) details["version"] = version;
            await worker.ShutdownAsync("close", null, TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            return ProviderAvailability.Ok(Id, details);
        }
        catch (ToolError e)
        {
            return ProviderAvailability.Missing(Id, e.Message, e.Remediation ?? "Check the IDA install and the Python it uses.", details);
        }
    }

    public async Task<INativeDecompilerSession> OpenAsync(string imagePath, string? sha256 = null, NativeOpenOptions? options = null, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        var (result, ida, python) = Static();
        if (!result.IsAvailable)
            throw new ToolError(ErrorCode.ProviderUnavailable, result.Reason!, result.Remediation);
        var session = new IdaSession(this, ida!, python!, options ?? new NativeOpenOptions());
        _sessions[session] = 0;
        try
        {
            await session.OpenAsync(imagePath, sha256, cancellationToken).ConfigureAwait(false);
            return session;
        }
        catch
        {
            session.Dispose();
            throw;
        }
    }

    internal void Forget(IdaSession session) => _sessions.TryRemove(session, out _);

    /// <summary>Starts a worker process (inside a job on Windows) and returns its connection; idalib is loaded on the first request.</summary>
    internal WorkerConnection StartWorker(IdaInstallation ida, PythonInterpreter python)
    {
        var workerDir = Path.Combine(Cache.Root, "workers");
        var script = EmbeddedScript.Extract(WorkerResource, workerDir, "ida_worker", ".py");
        var env = new Dictionary<string, string?>
        {
            ["IDADIR"] = ida.Directory,
            ["IDA_IS_INTERACTIVE"] = null,
            ["TVHEADLESS"] = "1",
        };
        if (!_options.UseUserPlugins) env["IDAUSR"] = PrivateUserDirectory();
        var start = new ChildProcessStart(python.Executable, ["-I", "-u", script])
        {
            WorkingDirectory = workerDir,
            Environment = env,
        };
        try
        {
            return WorkerConnection.Start("IDA worker", start, Remediation);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.ProviderUnavailable, $"The IDA worker could not be started with {python.Executable}: {ex.Message}",
                $"Check the Python install or set {PythonVariable}.");
        }
    }

    /// <summary>
    /// IDAUSR for the worker: an empty per-user directory with the user's license files copied in, so IDA finds its
    /// license but none of the user's plugins or scripts.
    /// </summary>
    private string PrivateUserDirectory()
    {
        var dir = Path.Combine(Cache.Root, ProviderId, "idausr");
        Directory.CreateDirectory(dir);
        foreach (var userDir in IdaInstallation.UserDirectories())
        {
            if (Path.GetFullPath(userDir).Equals(Path.GetFullPath(dir), StringComparison.OrdinalIgnoreCase) || !Directory.Exists(userDir)) continue;
            try
            {
                foreach (var license in Directory.EnumerateFiles(userDir, "*.hexlic"))
                {
                    var target = Path.Combine(dir, Path.GetFileName(license));
                    if (!File.Exists(target) || !File.ReadAllBytes(target).AsSpan().SequenceEqual(File.ReadAllBytes(license)))
                        File.Copy(license, target, overwrite: true);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* IDA reports a missing license itself */ }
        }
        return dir;
    }

    internal static string? Remediation(ErrorCode code, string message)
    {
        if (message.Contains("licen", StringComparison.OrdinalIgnoreCase))
            return "Start IDA once interactively to accept the license terms, and check that the license is valid on this machine.";
        return code switch
        {
            ErrorCode.Timeout => "Retry; the next request restarts IDA from the saved database. Raise the time limit for large images.",
            ErrorCode.ProviderUnavailable => "Retry once (the session restarts IDA from the saved database); if it persists, run the provider probe and check the IDA install, its license and the Python it uses.",
            ErrorCode.Unsupported => "Use the built-in disassembly for this architecture.",
            ErrorCode.NotFound => "List the functions to find a valid address.",
            _ => null,
        };
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        foreach (var s in _sessions.Keys) s.Dispose();
        _sessions.Clear();
    }

    internal static JsonObject Args(params (string Key, JsonNode? Value)[] values)
    {
        var o = new JsonObject();
        foreach (var (k, v) in values) o[k] = v;
        return o;
    }
}
