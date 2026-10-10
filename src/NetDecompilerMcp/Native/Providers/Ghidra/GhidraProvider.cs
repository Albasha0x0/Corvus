using System.Collections.Concurrent;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native.Providers.Ghidra;

public sealed record GhidraProviderOptions
{
    /// <summary>Ghidra install directory; null: NDM_GHIDRA_DIR, then GHIDRA_INSTALL_DIR.</summary>
    public string? InstallDirectory { get; init; }
    /// <summary>JDK home, its bin directory or its java; null: NDM_GHIDRA_JAVA, JAVA_HOME, PATH.</summary>
    public string? JavaHome { get; init; }
    /// <summary>Root of the private input copies, projects and Ghidra directories; null: <see cref="AnalysisCache.DefaultRoot"/>.</summary>
    public string? CacheRoot { get; init; }
    /// <summary>Analysis profile; null: NDM_GHIDRA_ANALYSIS, else standard.</summary>
    public GhidraAnalysisProfile? Profile { get; init; }
    /// <summary>JVM heap such as 6G; null: NDM_GHIDRA_MAXMEM, else by image size.</summary>
    public string? MaxMemory { get; init; }
    /// <summary>Extra analyzer options "Name=value;..."; null: NDM_GHIDRA_OPTIONS.</summary>
    public string? ExtraOptions { get; init; }
    /// <summary>Time the worker gets to save and exit on close before it is killed.</summary>
    public TimeSpan ShutdownGrace { get; init; } = TimeSpan.FromSeconds(30);
    /// <summary>Time for the JVM to start and initialize Ghidra.</summary>
    public TimeSpan StartTimeout { get; init; } = TimeSpan.FromMinutes(2);
    /// <summary>Time a cancelled request gets to stop before the worker is killed.</summary>
    public TimeSpan CancelGrace { get; init; } = TimeSpan.FromSeconds(10);
    /// <summary>Consecutive worker failures a session survives by restarting from the saved project.</summary>
    public int MaxRestarts { get; init; } = 3;
    /// <summary>Decompiler processes per session.</summary>
    public int Decompilers { get; init; } = Math.Clamp(Environment.ProcessorCount / 2, 1, 4);
}

/// <summary>
/// Ghidra through a Java worker per session (Native/Providers/Ghidra/worker), built on first use with the user's JDK.
/// The JVM runs inside a kill-on-close Job Object on Windows; Ghidra's settings, caches and temporary files are kept
/// under the analysis cache, and each image's project is kept per SHA-256 and analysis profile.
/// </summary>
public sealed class GhidraProvider(GhidraProviderOptions? options = null) : INativeDecompilerProvider
{
    public const string ProviderId = "ghidra";

    private readonly GhidraProviderOptions _options = options ?? new GhidraProviderOptions();
    private readonly ConcurrentDictionary<GhidraSession, byte> _sessions = new();
    private readonly object _availabilityLock = new();
    private (ProviderAvailability Result, GhidraInstallation? Ghidra, JavaRuntime? Java)? _static;
    private int _disposed;

    public string Id => ProviderId;
    public string DisplayName => "Ghidra";
    internal GhidraProviderOptions Options => _options;
    internal AnalysisCache Cache { get; } = new((options ?? new GhidraProviderOptions()).CacheRoot ?? AnalysisCache.DefaultRoot);
    internal GhidraDirectories Directories => new(Path.Combine(Cache.Root, ProviderId));
    /// <summary>One first analysis at a time: a cold analysis of a large image takes several GB.</summary>
    internal SemaphoreSlim ColdAnalysis { get; } = new(1, 1);

    internal GhidraAnalysisProfile Profile => _options.Profile ?? GhidraOptions.Profile(Environment.GetEnvironmentVariable(GhidraOptions.ProfileVariable));
    internal string? ExtraOptions => _options.ExtraOptions ?? Environment.GetEnvironmentVariable(GhidraOptions.OptionsVariable);

    public ProviderAvailability CheckAvailability() => Static().Result;

    private (ProviderAvailability Result, GhidraInstallation? Ghidra, JavaRuntime? Java) Static()
    {
        lock (_availabilityLock)
            return _static ??= ComputeStatic();
    }

    private (ProviderAvailability, GhidraInstallation?, JavaRuntime?) ComputeStatic()
    {
        var ghidra = GhidraInstallation.Locate(_options.InstallDirectory, out var reason, out var remediation);
        if (ghidra == null) return (ProviderAvailability.Missing(Id, reason, remediation), null, null);
        var details = new Dictionary<string, string>
        {
            ["install_dir"] = ghidra.Directory,
            ["install_source"] = ghidra.Source,
            ["version"] = ghidra.Version,
            ["decompiler"] = ghidra.DecompilerPath ?? "missing: " + ghidra.DecompilerRemediation,
        };
        var log = new List<string>();
        var java = JavaRuntime.Locate(_options.JavaHome, ghidra.JavaMin, ghidra.JavaMax, log);
        if (java == null)
        {
            details["java_candidates"] = log.Count == 0 ? "none found" : string.Join("; ", log);
            return (ProviderAvailability.Missing(Id, $"No JDK {ghidra.JavaMin}+ was found for Ghidra {ghidra.Version} ({details["java_candidates"]}).",
                $"Install a 64-bit JDK {ghidra.JavaMin} or newer (a JRE is not enough: the worker is compiled on first use) and set {GhidraOptions.JavaVariable} to its directory.",
                details), ghidra, null);
        }
        details["java"] = $"{java.Home} (Java {java.Major}, {java.Source})";
        try
        {
            details["profile"] = Profile.ToString().ToLowerInvariant();
            GhidraOptions.ParseExtra(ExtraOptions);
        }
        catch (ToolError e)
        {
            return (ProviderAvailability.Missing(Id, e.Message, e.Remediation ?? "", details), ghidra, java);
        }
        return (ProviderAvailability.Ok(Id, details), ghidra, java);
    }

    public async Task<ProviderAvailability> ProbeAsync(CancellationToken cancellationToken = default)
    {
        var (result, ghidra, java) = Static();
        if (!result.IsAvailable) return result;
        var details = new Dictionary<string, string>(result.Details);
        try
        {
            using var worker = await StartWorkerAsync(ghidra!, java!, 0, cancellationToken).ConfigureAwait(false);
            await worker.WaitReadyAsync(_options.StartTimeout, cancellationToken).ConfigureAwait(false);
            var hello = await worker.RequestAsync("hello", null, TimeSpan.FromMinutes(1), cancellationToken).ConfigureAwait(false);
            if (hello.TryGetProperty("version", out var v) && v.GetString() is { } version) details["version"] = version;
            await worker.ShutdownAsync("close", null, TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            return ProviderAvailability.Ok(Id, details);
        }
        catch (ToolError e)
        {
            return ProviderAvailability.Missing(Id, e.Message, e.Remediation ?? "Check the Ghidra install and the JDK.", details);
        }
    }

    public async Task<INativeDecompilerSession> OpenAsync(string imagePath, string? sha256 = null, NativeOpenOptions? options = null, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        var (result, ghidra, java) = Static();
        if (!result.IsAvailable)
            throw new ToolError(ErrorCode.ProviderUnavailable, result.Reason!, result.Remediation);
        var session = new GhidraSession(this, ghidra!, java!, options ?? new NativeOpenOptions());
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

    internal void Forget(GhidraSession session) => _sessions.TryRemove(session, out _);

    /// <summary>Builds the worker when needed and starts a JVM (inside a job on Windows); Ghidra initializes before the ready event.</summary>
    internal async Task<WorkerConnection> StartWorkerAsync(GhidraInstallation ghidra, JavaRuntime java, long imageBytes, CancellationToken cancellationToken)
    {
        var dirs = Directories;
        try { dirs.Create(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.IoError, $"Creating {dirs.Root} failed: {ex.Message}", $"Check that the analysis cache is writable ({AnalysisCache.RootVariable} selects another).");
        }
        var jars = await WorkerBuild.EnsureAsync(ghidra, java, dirs.Workers, cancellationToken).ConfigureAwait(false);
        var vmArgs = await Task.Run(() => GhidraLaunch.VmArgs(ghidra, java), cancellationToken).ConfigureAwait(false);
        var memory = GhidraOptions.MaxMemory(_options.MaxMemory ?? Environment.GetEnvironmentVariable(GhidraOptions.MaxMemoryVariable), imageBytes);
        var start = new ChildProcessStart(java.Java, GhidraLaunch.Arguments(ghidra, vmArgs, memory, dirs, jars.Boot, jars.Worker))
        {
            WorkingDirectory = dirs.Temp,
            // Options a user set for their own Java programs must not reach the worker (a second -Xmx, an agent, a debugger).
            Environment = new Dictionary<string, string?> { ["JAVA_TOOL_OPTIONS"] = null, ["_JAVA_OPTIONS"] = null, ["JDK_JAVA_OPTIONS"] = null },
        };
        try
        {
            return WorkerConnection.Start("Ghidra worker", start, Remediation,
                new WorkerConnectionOptions { Concurrent = true, CancelGrace = _options.CancelGrace });
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.ProviderUnavailable, $"The Ghidra worker could not be started with {java.Java}: {ex.Message}",
                $"Check the JDK or set {GhidraOptions.JavaVariable}.");
        }
    }

    internal static string? Remediation(ErrorCode code, string message) => code switch
    {
        ErrorCode.Timeout => "Retry; a cancelled request leaves the session running. Raise the time limit for large functions or images.",
        ErrorCode.ProviderUnavailable => "Retry once (the session restarts Ghidra from the saved project); if it persists, run the provider probe and check the Ghidra install and the JDK.",
        ErrorCode.Unsupported => "Use the built-in disassembly, or build Ghidra's native decompiler for this platform.",
        ErrorCode.NotFound => "List the functions to find a valid address.",
        ErrorCode.LimitExceeded => "Ask for a smaller range.",
        _ => null,
    };

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        foreach (var s in _sessions.Keys) s.Dispose();
        _sessions.Clear();
    }
}
