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
    /// <summary>Memory cap of each worker in bytes (0: none); null: <see cref="EngineMemoryLimit.Variable"/>, else three quarters of the memory available.</summary>
    public long? MemoryLimitBytes { get; init; }
    /// <summary>Unsaved edits after which the database is saved, so a restart replays a bounded journal.</summary>
    public int JournalSaveThreshold { get; init; } = 100;
    /// <summary>Time a request that timed out or was cancelled gets to stop after the worker is asked to; then the worker is killed.</summary>
    public TimeSpan CancelGrace { get; init; } = TimeSpan.FromSeconds(10);
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

    /// <summary>The idalib version a worker reported (probe or session start), or null before one ran.</summary>
    public string? Version { get; private set; }

    /// <summary>The static checks, plus the version once a worker reported it.</summary>
    public ProviderAvailability CheckAvailability()
    {
        var result = Static().Result;
        if (!result.IsAvailable) return result;
        var details = new Dictionary<string, string>(result.Details)
        {
            ["version"] = Version ?? "not probed yet (reported by the first IDA session, or NetDecompilerMcp status --deep)",
        };
        return ProviderAvailability.Ok(Id, details);
    }

    /// <summary>Records the version a worker's hello reported; IDA before 9.0 has no usable idalib and is refused.</summary>
    internal void CheckVersion(System.Text.Json.JsonElement hello)
    {
        if (!hello.TryGetProperty("version", out var v) || v.GetString() is not { Length: > 0 } version) return;
        Version = version;
        if (int.TryParse(version.Split('.')[0], out var major) && major < 9)
            throw new ToolError(ErrorCode.Unsupported, $"IDA {version} is too old: idalib from IDA Pro 9.0 or newer is required.",
                "Install IDA Pro 9 or newer, or set NDM_IDA_DIR to such an install.");
    }

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
            CheckVersion(hello);
            if (Version != null) details["version"] = Version;
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

    public IReadOnlyList<EngineSessionState> SessionStates() => _sessions.Keys.Select(s => s.State()).ToList();

    /// <summary>The database file of a symbol profile (default, nopdb): keyed by the IDA build, so another IDA never reuses it.</summary>
    internal static string DatabaseFileName(IdaInstallation ida, string profile) => $"ida-{profile}-{ida.EngineDigest()}.i64";

    /// <summary>Where this IDA build keeps the saved analysis of <paramref name="sha256"/>, or null when IDA is not available.</summary>
    public string? SavedDatabasePath(string sha256, string profile = "default") =>
        Static().Ida is { } ida ? Path.Combine(Cache.Root, ProviderId, sha256.ToLowerInvariant(), DatabaseFileName(ida, profile)) : null;

    /// <summary>
    /// The symbol path for a worker: the directory of the PDB the server located first (IDA analyzes a copy of the image,
    /// so it cannot look next to the original), then the configured path (_NT_SYMBOL_PATH, else pdb.cfg, else IDA's
    /// default). Null leaves IDA's configuration alone.
    /// </summary>
    internal static string? SymbolPathWith(string? pdbPath, string? idaDirectory = null)
    {
        if (string.IsNullOrEmpty(pdbPath) || Path.GetDirectoryName(pdbPath) is not { Length: > 0 } dir) return null;
        var configured = Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH") is { Length: > 0 } env ? env
            : ConfiguredSymbolPath(idaDirectory) ?? $"SRV*{Path.Combine(Path.GetTempPath(), "ida")}*https://msdl.microsoft.com/download/symbols";
        return dir + ";" + configured;
    }

    /// <summary>The _NT_SYMBOL_PATH setting of IDA's cfg/pdb.cfg, when one is not commented out.</summary>
    private static string? ConfiguredSymbolPath(string? idaDirectory)
    {
        if (idaDirectory == null) return null;
        try
        {
            var cfg = Path.Combine(idaDirectory, "cfg", "pdb.cfg");
            if (!File.Exists(cfg)) return null;
            foreach (var line in File.ReadLines(cfg))
            {
                var t = line.Trim();
                if (!t.StartsWith("_NT_SYMBOL_PATH", StringComparison.Ordinal)) continue;
                int q1 = t.IndexOf('"'), q2 = t.LastIndexOf('"');
                if (q1 >= 0 && q2 > q1) return t[(q1 + 1)..q2].Replace(@"\\", @"\");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return null;
    }

    /// <summary>Starts a worker process (inside a job on Windows) and returns its connection; idalib is loaded on the first request.</summary>
    internal WorkerConnection StartWorker(IdaInstallation ida, PythonInterpreter python, string? pdbPath = null)
    {
        var workerDir = Path.Combine(Cache.Root, "workers");
        var script = EmbeddedScript.Extract(WorkerResource, workerDir, "ida_worker", ".py");
        var env = new Dictionary<string, string?>
        {
            ["IDADIR"] = ida.Directory,
            ["IDA_IS_INTERACTIVE"] = null,
            ["TVHEADLESS"] = "1",
        };
        if (SymbolPathWith(pdbPath, ida.Directory) is { } symbolPath) env["_NT_SYMBOL_PATH"] = symbolPath;
        if (!_options.UseUserPlugins) env["IDAUSR"] = PrivateUserDirectory();
        var start = new ChildProcessStart(python.Executable, ["-I", "-u", script])
        {
            WorkingDirectory = workerDir,
            Environment = env,
            MemoryLimitBytes = EngineMemoryLimit.Resolve(_options.MemoryLimitBytes),
        };
        try
        {
            return WorkerConnection.Start("IDA worker", start, Remediation, new WorkerConnectionOptions { CancelGrace = _options.CancelGrace });
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
        if (message.Contains(EngineMemoryLimit.Variable, StringComparison.Ordinal))
            return $"Raise {EngineMemoryLimit.Variable} (MB; 0 turns the limit off) and retry.";
        return code switch
        {
            ErrorCode.Timeout => "The request was stopped and IDA keeps running; retry with a larger time limit (timeoutSeconds where the tool takes it, or NDM_ENGINE_REQUEST_TIMEOUT).",
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
