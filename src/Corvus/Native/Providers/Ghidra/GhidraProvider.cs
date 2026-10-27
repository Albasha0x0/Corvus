using System.Collections.Concurrent;
using Corvus.Core;

namespace Corvus.Native.Providers.Ghidra;

public sealed record GhidraProviderOptions
{
    /// <summary>Ghidra install directory; null: CORVUS_GHIDRA_DIR, then GHIDRA_INSTALL_DIR.</summary>
    public string? InstallDirectory { get; init; }
    /// <summary>JDK home, its bin directory or its java; null: CORVUS_GHIDRA_JAVA, JAVA_HOME, PATH.</summary>
    public string? JavaHome { get; init; }
    /// <summary>Root of the private input copies, projects and Ghidra directories; null: <see cref="AnalysisCache.DefaultRoot"/>.</summary>
    public string? CacheRoot { get; init; }
    /// <summary>Analysis profile; null: CORVUS_GHIDRA_ANALYSIS, else standard.</summary>
    public GhidraAnalysisProfile? Profile { get; init; }
    /// <summary>Null: <see cref="GhidraOptions.CompletionVariable"/> decides (default on).</summary>
    public bool? CompletionPass { get; init; }
    /// <summary>JVM heap such as 6G; null: CORVUS_GHIDRA_MAXMEM, else by image size.</summary>
    public string? MaxMemory { get; init; }
    /// <summary>Extra analyzer options "Name=value;..."; null: CORVUS_GHIDRA_OPTIONS.</summary>
    public string? ExtraOptions { get; init; }
    /// <summary>Directory of Ghidra extensions to install for the workers; null: CORVUS_GHIDRA_EXTENSIONS.</summary>
    public string? ExtensionsDirectory { get; init; }
    /// <summary>A Python with PyGhidra that hosts the workers (else <see cref="GhidraOptions.PythonVariable"/>); Python scripts need it.</summary>
    public string? Python { get; init; }
    /// <summary>Per-function decompiler limit; null: CORVUS_GHIDRA_DECOMPILE_TIMEOUT, else 60 s.</summary>
    public TimeSpan? DecompileTimeout { get; init; }
    /// <summary>Decompiler response limit in MB; null: CORVUS_GHIDRA_DECOMPILE_PAYLOAD_MB, else 200.</summary>
    public int? DecompilePayloadMb { get; init; }
    /// <summary>Time the worker gets to save and exit on close before it is killed.</summary>
    public TimeSpan ShutdownGrace { get; init; } = TimeSpan.FromSeconds(30);
    /// <summary>Time the JVM may spend idle (under 1% of a core) while it starts and initializes Ghidra.</summary>
    public TimeSpan StartTimeout { get; init; } = TimeSpan.FromMinutes(2);
    /// <summary>Time a cancelled request gets to stop before the worker is killed.</summary>
    public TimeSpan CancelGrace { get; init; } = TimeSpan.FromSeconds(10);
    /// <summary>Consecutive worker failures a session survives by restarting from the saved project.</summary>
    public int MaxRestarts { get; init; } = 3;
    /// <summary>Unsaved edits after which the project is saved, so a restart replays a bounded journal.</summary>
    public int JournalSaveThreshold { get; init; } = 50;
    /// <summary>Memory cap of each worker tree in bytes (0: none); null: <see cref="EngineMemoryLimit.Variable"/>, else three quarters of the memory available.</summary>
    public long? MemoryLimitBytes { get; init; }
    /// <summary>Root of the workers' settings, home, temporary files and built jars; null: <see cref="GhidraOptions.WorkerDirectoryVariable"/>, else the ghidra folder of the cache root.</summary>
    public string? WorkerRoot { get; init; }
    /// <summary>Keep one started worker ready for the next open; null: <see cref="GhidraOptions.SpareWorkerVariable"/>, else off.</summary>
    public bool? SpareWorker { get; init; }
    /// <summary>Decompiler processes per session.</summary>
    public int Decompilers { get; init; } = Math.Clamp(Environment.ProcessorCount / 2, 1, 4);
}

/// <summary>Ghidra through one Java worker per session, built on first use, in a kill-on-close job on Windows; Ghidra's settings and caches stay under the analysis cache, projects per SHA-256 and profile.</summary>
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
    /// <summary>The worker directories: under <see cref="GhidraProviderOptions.WorkerRoot"/>, one folder per extension set, else the cache folder.</summary>
    internal GhidraDirectories Directories => new((_options.WorkerRoot ?? Environment.GetEnvironmentVariable(GhidraOptions.WorkerDirectoryVariable)) is { Length: > 0 } root
        ? Path.Combine(Path.GetFullPath(root), ExtensionSet())
        : CacheDirectory);
    /// <summary>This provider's folder of the analysis cache: projects and unpacked archives, per input.</summary>
    internal string CacheDirectory => Path.Combine(Cache.Root, ProviderId);
    internal bool KeepsSpareWorker => _options.SpareWorker ?? GhidraOptions.SpareWorker(Environment.GetEnvironmentVariable(GhidraOptions.SpareWorkerVariable));
    private readonly HashSet<string> _spareCommands = [];
    /// <summary>One first analysis at a time: a cold analysis of a large image takes several GB.</summary>
    internal SemaphoreSlim ColdAnalysis { get; } = new(1, 1);

    internal bool CompletionPass => _options.CompletionPass ?? GhidraOptions.Completion(Environment.GetEnvironmentVariable(GhidraOptions.CompletionVariable));

    internal GhidraAnalysisProfile Profile => _options.Profile ?? GhidraOptions.Profile(Environment.GetEnvironmentVariable(GhidraOptions.ProfileVariable));
    internal string? ExtraOptions => _options.ExtraOptions ?? Environment.GetEnvironmentVariable(GhidraOptions.OptionsVariable);
    internal TimeSpan DecompileTimeout => _options.DecompileTimeout ?? GhidraOptions.DecompileTimeout(Environment.GetEnvironmentVariable(GhidraOptions.DecompileTimeoutVariable));
    internal int DecompilePayloadMb => _options.DecompilePayloadMb ?? GhidraOptions.DecompilePayloadMb(Environment.GetEnvironmentVariable(GhidraOptions.DecompilePayloadVariable));

    /// <summary>The extensions the workers load (read with the static checks).</summary>
    internal IReadOnlyList<GhidraExtension> Extensions { get; private set; } = [];

    /// <summary>The Python that hosts the workers under PyGhidra (read with the static checks); null runs a plain JVM, Java scripts only.</summary>
    internal string? PythonHost { get; private set; }

    /// <summary>Why the configured Python cannot host the workers, or null.</summary>
    internal string? PythonProblem { get; private set; }

    public ProviderAvailability CheckAvailability() => Static().Result;

    /// <summary>The project directory an open of <paramref name="imagePath"/> would use, when its cache entry exists; null otherwise. Opens nothing.</summary>
    internal string? ProjectFor(string imagePath, string sha256, EngineAnalysis analysis)
    {
        if (Static().Ghidra is not { } ghidra || Cache.Find(ProviderId, sha256) is not { } entry) return null;
        try { return GhidraSession.Project(this, ghidra, entry, GhidraSession.ReadHeader(imagePath, imagePath), SymbolMode.Default, analysis).Directory; }
        catch (ToolError) { return null; }
    }

    /// <summary>The install directory, or null when Ghidra is not available.</summary>
    internal string? InstallDirectory => Static().Ghidra?.Directory;

    /// <summary>The installed version, or null when Ghidra is not available.</summary>
    internal string? Version => Static().Ghidra?.Version;

    /// <summary>What decides Ghidra's output besides the project: release, revision, profile, extra options, extensions, decompiler limits.</summary>
    internal string? EngineBuild => Static().Ghidra is { } g
        ? $"{g.Version} {g.Revision} {Profile} {ExtraOptions} {string.Join(",", Extensions.Select(e => e.Name))} {DecompileTimeout.TotalSeconds} {DecompilePayloadMb}"
        : null;

    private (ProviderAvailability Result, GhidraInstallation? Ghidra, JavaRuntime? Java) Static()
    {
        // Locating Java runs processes: a call waiting here stops when it is cancelled.
        using (AssemblyWorkspace.Lock(_availabilityLock))
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
                $"Install a 64-bit JDK {ghidra.JavaMin} or newer, not a JRE (the worker is compiled on first use), and set {GhidraOptions.JavaVariable} to its directory.",
                details), ghidra, null);
        }
        details["java"] = $"{java.Home} (Java {java.Major}, {java.Source})";
        try
        {
            details["profile"] = Profile.ToString().ToLowerInvariant();
            GhidraOptions.ParseExtra(ExtraOptions);
            details["decompile"] = $"{DecompileTimeout.TotalSeconds:0} s, {DecompilePayloadMb} MB";
            Extensions = GhidraExtensions.Configured(_options.ExtensionsDirectory ?? Environment.GetEnvironmentVariable(GhidraOptions.ExtensionsVariable));
            if (Extensions.Count > 0) details["extensions"] = string.Join(", ", Extensions.Select(e => e.Name));
            (PythonHost, PythonProblem) = PyGhidraPython(_options.Python ?? Environment.GetEnvironmentVariable(GhidraOptions.PythonVariable));
            if (PythonHost != null) details["python"] = PythonHost + " (PyGhidra)";
            else if (PythonProblem != null) details["python"] = PythonProblem;
        }
        catch (ToolError e)
        {
            return (ProviderAvailability.Missing(Id, e.Message, e.Remediation ?? "", details), ghidra, java);
        }
        return (ProviderAvailability.Ok(Id, details), ghidra, java);
    }

    /// <summary>Waits for a new worker's ready event; the start limit counts idle time only, <paramref name="cap"/> bounds the whole start.</summary>
    internal Task WaitStartedAsync(WorkerConnection worker, TimeSpan cap, CancellationToken cancellationToken) =>
        worker.WaitReadyAsync(cap > _options.StartTimeout ? cap : _options.StartTimeout, cancellationToken, idle: _options.StartTimeout);

    public async Task<ProviderAvailability> ProbeAsync(CancellationToken cancellationToken = default)
    {
        var (result, ghidra, java) = Static();
        if (!result.IsAvailable) return result;
        var details = new Dictionary<string, string>(result.Details);
        try
        {
            using var worker = await StartWorkerAsync(ghidra!, java!, 0, cancellationToken).ConfigureAwait(false);
            await WaitStartedAsync(worker, _options.StartTimeout * 5, cancellationToken).ConfigureAwait(false);
            var hello = await worker.RequestAsync("hello", null, TimeSpan.FromMinutes(1), cancellationToken).ConfigureAwait(false);
            if (hello.TryGetProperty("version", out var v) && v.GetString() is { } version) details["version"] = version;
            if (hello.TryGetProperty("extensions", out var x) && x.GetArrayLength() > 0)
                details["extensions_loaded"] = string.Join(", ", x.EnumerateArray().Select(n => n.GetString()));
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
        if (IsWasm(imagePath) && !HasWasmLanguage(ghidra!))
            throw new ToolError(ErrorCode.Unsupported,
                $"Ghidra {ghidra!.Version} has no WebAssembly language in its processors or in {GhidraOptions.ExtensionsVariable}.",
                $"omit engine for the built-in WebAssembly reader, or put a WebAssembly extension zip built for Ghidra {ghidra.Version} in {GhidraOptions.ExtensionsVariable}");
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

    // Offline install: python -m pip install --no-index -f Ghidra/Features/PyGhidra/pypkg/dist pyghidra.
    /// <summary>The configured Python when it imports PyGhidra and JPype, else the problem.</summary>
    private static (string? Python, string? Problem) PyGhidraPython(string? configured)
    {
        if (string.IsNullOrWhiteSpace(configured)) return (null, null);
        var python = configured.Trim().Trim('"');
        if (!File.Exists(python)) return (null, $"{GhidraOptions.PythonVariable}: {python} does not exist");
        var run = PythonLocator.RunCapture(python, ["-I", "-c", "import pyghidra, jpype; print(pyghidra.__version__)"], TimeSpan.FromSeconds(30));
        if (run.StartError != null || run.TimedOut || run.ExitCode != 0)
            return (null, $"{GhidraOptions.PythonVariable}: {python} cannot import pyghidra ({run.StartError ?? (run.TimedOut ? "timed out" : run.Stderr.Trim().Split('\n').LastOrDefault())})");
        return (python, null);
    }

    private static bool IsWasm(string path)
    {
        try
        {
            using var f = File.OpenRead(path);
            Span<byte> head = stackalloc byte[4];
            return f.ReadAtLeast(head, 4, throwOnEndOfStream: false) == 4 && head.SequenceEqual("\0asm"u8);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return false; }
    }

    private bool? _wasmLanguage;

    /// <summary>Whether an .ldefs of the install or a configured extension names a WebAssembly processor; user-installed extensions do not count.</summary>
    private bool HasWasmLanguage(GhidraInstallation ghidra) => _wasmLanguage ??= ComputeWasmLanguage(ghidra);

    private bool ComputeWasmLanguage(GhidraInstallation ghidra)
    {
        static bool Names(string text) => text.Contains("processor=\"Webassembly\"", StringComparison.OrdinalIgnoreCase)
                                          || text.Contains("processor=\"Wasm\"", StringComparison.OrdinalIgnoreCase);
        try
        {
            var processors = Path.Combine(ghidra.Directory, "Ghidra", "Processors");
            if (Directory.Exists(processors) && Directory.EnumerateFiles(processors, "*.ldefs", SearchOption.AllDirectories).Any(f => Names(File.ReadAllText(f))))
                return true;
            foreach (var e in Extensions)
            {
                if (Directory.Exists(e.Source))
                {
                    if (Directory.EnumerateFiles(e.Source, "*.ldefs", SearchOption.AllDirectories).Any(f => Names(File.ReadAllText(f)))) return true;
                    continue;
                }
                using var zip = System.IO.Compression.ZipFile.OpenRead(e.Source);
                foreach (var entry in zip.Entries.Where(x => x.FullName.EndsWith(".ldefs", StringComparison.OrdinalIgnoreCase)))
                {
                    using var r = new StreamReader(entry.Open());
                    if (Names(r.ReadToEnd())) return true;
                }
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException) { }
        return false;
    }

    /// <summary>What a Ghidra archive records of the file it was made from; <see cref="Path"/>: its bytes, when the archive keeps them.</summary>
    internal sealed record ArchiveOriginal(string Name, string? Sha256, string? Format, string? Path);

    /// <summary>Unpacks <paramref name="gzf"/> on a short-lived worker and writes its original file under <paramref name="outDirectory"/>.</summary>
    internal async Task<ArchiveOriginal> OriginalOfAsync(string gzf, string outDirectory, CancellationToken cancellationToken)
    {
        var (result, ghidra, java) = Static();
        if (!result.IsAvailable)
            throw new ToolError(ErrorCode.ProviderUnavailable, $"Reading a Ghidra archive (.gzf) needs Ghidra: {result.Reason}", result.Remediation);
        using var worker = await StartWorkerAsync(ghidra!, java!, new FileInfo(gzf).Length, cancellationToken).ConfigureAwait(false);
        await WaitStartedAsync(worker, _options.StartTimeout * 5, cancellationToken).ConfigureAwait(false);
        var r = await worker.RequestAsync("gzf_original", WorkerRows.Args(("gzf", gzf), ("out_dir", outDirectory),
            ("scratch", System.IO.Path.Combine(outDirectory, "scratch"))), TimeSpan.FromMinutes(10), cancellationToken).ConfigureAwait(false);
        await worker.ShutdownAsync("close", null, TimeSpan.FromSeconds(10)).ConfigureAwait(false);
        string? S(string name) => r.TryGetProperty(name, out var v) && v.ValueKind == System.Text.Json.JsonValueKind.String && v.GetString() is { Length: > 0 } s ? s : null;
        return new(S("name") ?? System.IO.Path.GetFileNameWithoutExtension(gzf), S("sha256"), S("format"), S("path"));
    }

    /// <summary>Packs the program at <paramref name="program"/> (null: the only one) of the project copy in <paramref name="projectDirectory"/> into <paramref name="gzf"/>; returns its path in the project.</summary>
    internal async Task<string> PackProjectAsync(string projectDirectory, string name, string? program, string gzf, CancellationToken cancellationToken)
    {
        var (result, ghidra, java) = Static();
        if (!result.IsAvailable)
            throw new ToolError(ErrorCode.ProviderUnavailable, $"Reading a Ghidra project (.gpr) needs Ghidra: {result.Reason}", result.Remediation);
        using var worker = await StartWorkerAsync(ghidra!, java!, 0, cancellationToken).ConfigureAwait(false);
        await WaitStartedAsync(worker, _options.StartTimeout * 5, cancellationToken).ConfigureAwait(false);
        var r = await worker.RequestAsync("gpr_pack", WorkerRows.Args(("project_dir", projectDirectory), ("name", name), ("program", program), ("out", gzf)),
            TimeSpan.FromMinutes(10), cancellationToken).ConfigureAwait(false);
        await worker.ShutdownAsync("close", null, TimeSpan.FromSeconds(10)).ConfigureAwait(false);
        return r.GetProperty("program").GetString()!;
    }

    internal void Forget(GhidraSession session) => _sessions.TryRemove(session, out _);

    public IReadOnlyList<EngineSessionState> SessionStates() => _sessions.Keys.Select(s => s.State()).ToList();

    /// <summary>Whether the cache holds a saved project of these bytes under any profile (file checks only).</summary>
    public bool HasSavedProject(string sha256, string? overrides = null)
    {
        var dir = Path.Combine(Cache.Root, ProviderId, sha256.ToLowerInvariant());
        return Directory.Exists(dir) && Directory.EnumerateDirectories(dir, "p-*").Where(p => GhidraSession.OfOverrides(p, overrides)).Any(GhidraSession.HasProject);
    }

    /// <summary>Builds the worker if needed and starts a JVM or takes a matching spare; <paramref name="refill"/> starts the next spare when spares are on.</summary>
    internal async Task<WorkerConnection> StartWorkerAsync(GhidraInstallation ghidra, JavaRuntime java, long imageBytes, CancellationToken cancellationToken, bool refill = false)
    {
        var dirs = Directories;
        try { dirs.Create(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.IoError, $"Creating {dirs.Root} failed: {ex.Message}", $"Check that the analysis cache is writable ({AnalysisCache.RootVariable} selects another).");
        }
        var jars = await WorkerBuild.EnsureAsync(ghidra, java, dirs.Workers, cancellationToken).ConfigureAwait(false);
        try
        {
            lock (ExtensionInstall) GhidraExtensions.Install(Extensions, GhidraExtensions.InstallDirectory(dirs, ghidra));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            throw new ToolError(ErrorCode.IoError, $"Installing the Ghidra extensions into {dirs.Settings} failed: {ex.Message}",
                $"Check the extensions in {GhidraOptions.ExtensionsVariable} and that the analysis cache is writable.");
        }
        var memory = GhidraOptions.MaxMemory(_options.MaxMemory ?? Environment.GetEnvironmentVariable(GhidraOptions.MaxMemoryVariable), imageBytes);
        ChildProcessStart start;
        if (PythonHost is { } python)
            start = new ChildProcessStart(python, ["-I", .. GhidraLaunch.PyGhidraArguments(ghidra, java, memory, dirs, jars.Boot, jars.Worker)]);
        else
        {
            var vmArgs = await Task.Run(() => GhidraLaunch.VmArgs(ghidra, java), cancellationToken).ConfigureAwait(false);
            start = new ChildProcessStart(java.Java, GhidraLaunch.Arguments(ghidra, vmArgs, memory, dirs, jars.Boot, jars.Worker));
        }
        start = start with
        {
            WorkingDirectory = dirs.Temp,
            Environment = WorkerEnvironment(dirs),
            MemoryLimitBytes = EngineMemoryLimit.Resolve(_options.MemoryLimitBytes),
        };
        Interlocked.Increment(ref _workersStarted);
        WorkerConnection Launch()
        {
            try
            {
                return WorkerConnection.Start("Ghidra worker", start, Remediation,
                    new WorkerConnectionOptions
                    {
                        Concurrent = true,
                        CancelGrace = _options.CancelGrace,
                        StallReport = pids => JavaThreadDump.Report(java.Java, pids, Path.Combine(dirs.Root, "stalls")),
                    });
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException)
            {
                throw new ToolError(ErrorCode.ProviderUnavailable, $"The Ghidra worker could not be started with {java.Java}: {ex.Message}",
                    $"Check the JDK or set {GhidraOptions.JavaVariable}.");
            }
        }
        if (!KeepsSpareWorker) return Launch();
        var command = GhidraSpareWorkers.Command(start, _options.CancelGrace);
        lock (_spareCommands)
            if (_disposed == 0 && _spareCommands.Add(command)) GhidraSpareWorkers.Use(command);
        var worker = GhidraSpareWorkers.Take(command) ?? Launch();
        if (refill) GhidraSpareWorkers.Refill(command, Launch, worker, _options.StartTimeout);
        return worker;
    }

    /// <summary>Worker environment: the user's Java options removed (a second -Xmx, an agent, a debugger), the temporary folder of <paramref name="dirs"/>.</summary>
    internal static Dictionary<string, string?> WorkerEnvironment(GhidraDirectories dirs) => new()
    {
        ["JAVA_TOOL_OPTIONS"] = null,
        ["_JAVA_OPTIONS"] = null,
        ["JDK_JAVA_OPTIONS"] = null,
        // Workaround for NationalSecurityAgency/ghidra#9988 (tested PyGhidra 3.1.0, no fix yet): a private TEMP keeps
        // PyGhidra's start lock per worker directory instead of one per machine. The lock guards the extensions in the
        // settings folder, which these directories own.
        ["TEMP"] = dirs.Temp,
        ["TMP"] = dirs.Temp,
        ["TMPDIR"] = dirs.Temp,
    };

    /// <summary>Worker processes this provider has started.</summary>
    internal int WorkersStarted => Volatile.Read(ref _workersStarted);

    private int _workersStarted;

    private static readonly object ExtensionInstall = new();

    internal static string? Remediation(ErrorCode code, string message) => message.Contains(EngineMemoryLimit.Variable, StringComparison.Ordinal)
        ? $"Raise {EngineMemoryLimit.Variable} (MB; 0 turns the limit off) or lower {GhidraOptions.MaxMemoryVariable}, and retry."
        // Ghidra's native decompiler crashes on some functions every time; the next request starts a new one.
        : message.Contains("Decompiler process died", StringComparison.Ordinal)
        ? "Ghidra's decompiler fails on this function each time: decompile it with engine=ida, or read it with disassemble."
        : code switch
    {
        ErrorCode.Timeout => WorkerConnection.TimeoutNext(message),
        ErrorCode.ProviderUnavailable => "Retry once; the session restarts Ghidra from the saved project. If it persists, run the provider probe and check the Ghidra install and JDK.",
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
        lock (_spareCommands)
        {
            foreach (var command in _spareCommands) GhidraSpareWorkers.Release(command);
            _spareCommands.Clear();
        }
    }

    /// <summary>The extension set's folder name under a worker root: its own settings, so sets do not replace each other's extensions.</summary>
    private string ExtensionSet() => Extensions.Count == 0 ? "base"
        : "x-" + Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(
            string.Join('\n', Extensions.OrderBy(e => e.Name, StringComparer.Ordinal).Select(e => e.Name + "=" + e.Hash)))))[..12];
}
