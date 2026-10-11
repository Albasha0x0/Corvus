using Microsoft.Extensions.Logging;

namespace NetDecompilerMcp.Core;

/// <summary>
/// Startup options. Command line:
///   --load &lt;path&gt;        assembly file or directory to load at startup (repeatable)
///   --search-dir &lt;dir&gt;   extra directory for resolving references (repeatable)
///   --max-output &lt;n&gt;     max characters per tool response page (default 60000)
///   --timeout &lt;seconds&gt;  per-call decompilation timeout (default 180)
///   --no-index            do not index method bodies / build the call graph in the background
///   --no-watch            do not reload assemblies when their files change on disk
///   --binding-style &lt;s&gt;  default generate_cpp_binding style when none is requested or detected: mono, il2cpp or hostapi
///   --binding-project &lt;d&gt; default project directory scanned for a host table by generate_cpp_binding
///   --prewarm &lt;e&gt;        start an engine's analysis of each native image in the background right after it loads (one at a time):
///                         ida, ghidra or auto (the preferred engine installed); --ida-prewarm is --prewarm ida
///   --ida-scripting       allow ida_python (arbitrary Python in the IDA worker; NDM_IDA_SCRIPTING=1)
///   --ghidra-scripting    allow ghidra_script (arbitrary Java in the Ghidra worker; NDM_GHIDRA_SCRIPTING=1)
///   --engine &lt;e&gt;         where native functions, xrefs and CFGs come from by default: auto (an engine's analysis when it is complete, else ours), ours, ida or ghidra
///   --index-cache &lt;dir|off&gt;  directory of saved native code indexes (default &lt;LocalAppData&gt;/NetDecompilerMcp/code-index), or off
///   --index-cache-mb &lt;n&gt;  size limit of the code index cache in MB (default 8192)
///   --index-cache-days &lt;n&gt; entries unused for this many days are deleted (default 30)
///   --log-level &lt;l&gt;     stderr log level: trace, debug (adds one line per tool call), information (default), warning, error or none
///   --toolsets &lt;list&gt;   register only these tool families (see <see cref="Core.Toolsets"/>; default all): core, or names such as core,dumps
///   --tools-file &lt;path|readonly|triage&gt;  register only the tools a whitelist names, after --toolsets (NDM_TOOLS_FILE)
///   --trace &lt;file&gt;      append one JSON line per tool call (tool, arguments, ms, error, size) to this file (NDM_TRACE)
///   --allow-device-changes  allow the Android device tools that install or uninstall apps (NDM_ALLOW_DEVICE_CHANGES=1)
/// The NETDECOMP_LOAD environment variable (';'-separated paths) is also honored; NDM_PREWARM sets --prewarm (NDM_IDA_PREWARM=1: ida); NDM_ENGINE sets --engine;
/// NDM_CODE_INDEX_CACHE, NDM_CODE_INDEX_CACHE_MB and NDM_CODE_INDEX_CACHE_DAYS set the code index cache defaults; NDM_LOG_LEVEL sets --log-level;
/// NDM_TOOLSETS sets --toolsets; NDM_ENGINE_REQUEST_TIMEOUT and NDM_ENGINE_OPEN_TIMEOUT (seconds) bound IDA and Ghidra requests and opens;
/// NDM_ENGINE_ANALYSIS=none opens images in IDA without auto-analysis.
/// </summary>
public sealed class ServerOptions
{
    public List<string> Preload { get; } = new();
    public List<string> SearchDirectories { get; } = new();
    public int MaxOutputChars { get; set; } = 60_000;
    public int TimeoutSeconds { get; set; } = 180;

    /// <summary>Warm method bodies and build the call graph in the background after loading (default on).</summary>
    public bool BackgroundIndexing { get; set; } = true;

    /// <summary>Reload assemblies that change on disk (default on).</summary>
    public bool WatchFiles { get; set; } = true;

    /// <summary>generate_cpp_binding style used when none is requested and no host table is detected (null: "mono").</summary>
    public string? BindingStyle { get; set; }

    /// <summary>Project directory generate_cpp_binding scans for a host table when the call gives none.</summary>
    public string? BindingProject { get; set; }

    /// <summary>
    /// The engine whose session opens for each native image in the background right after it loads (one image at a time,
    /// cancelled on unload), so the first engine call does not wait for auto-analysis: Ida, Ghidra or Auto (the preferred
    /// engine installed); null: off (default).
    /// </summary>
    public EngineMode? Prewarm { get; set; }

    public const string PrewarmVariable = "NDM_PREWARM";
    /// <summary>Older switch: 1 means --prewarm ida.</summary>
    public const string IdaPrewarmVariable = "NDM_IDA_PREWARM";

    /// <summary>Allow ida_python: arbitrary Python in the IDA worker, with the server's rights (default off).</summary>
    public bool IdaScripting { get; set; }

    public const string IdaScriptingVariable = "NDM_IDA_SCRIPTING";

    /// <summary>Allow ghidra_script: arbitrary Java in the Ghidra worker, with the server's rights (default off).</summary>
    public bool GhidraScripting { get; set; }

    public const string GhidraScriptingOption = "--ghidra-scripting";
    public const string GhidraScriptingVariable = "NDM_GHIDRA_SCRIPTING";

    /// <summary>Allow the device tools that change a connected Android device (install, uninstall); default off.</summary>
    public bool AllowDeviceChanges { get; set; }

    public const string AllowDeviceChangesOption = "--allow-device-changes";
    public const string AllowDeviceChangesVariable = "NDM_ALLOW_DEVICE_CHANGES";

    /// <summary>Default engine of the native code tools when a call names none (see <see cref="EngineMode"/>).</summary>
    public EngineMode Engine { get; set; } = EngineMode.Auto;

    public const string EngineVariable = "NDM_ENGINE";

    /// <summary>Seconds each IDA or Ghidra request may take before it is cancelled (the worker answers with what it has); default 120.</summary>
    public int EngineRequestTimeoutSeconds { get; set; } = 120;

    public const string EngineRequestTimeoutVariable = "NDM_ENGINE_REQUEST_TIMEOUT";

    /// <summary>Seconds an engine gets to start and load or auto-analyze an image; default 1200.</summary>
    public int EngineOpenTimeoutSeconds { get; set; } = 1200;

    public const string EngineOpenTimeoutVariable = "NDM_ENGINE_OPEN_TIMEOUT";

    /// <summary>IDA's first open of an image: full auto-analysis (default) or none (load only; functions made on demand, kept under a separate database).</summary>
    public Native.Providers.EngineAnalysis EngineAnalysis { get; set; } = Native.Providers.EngineAnalysis.Full;

    public const string EngineAnalysisVariable = "NDM_ENGINE_ANALYSIS";

    /// <summary>Minimum level of the stderr log; Debug adds a line per tool call (tool, outcome, milliseconds).</summary>
    public LogLevel LogLevel { get; set; } = LogLevel.Information;

    public const string LogLevelVariable = "NDM_LOG_LEVEL";

    /// <summary>Tool families registered (<see cref="Core.Toolsets"/>); session is always among them.</summary>
    public IReadOnlySet<string> Toolsets { get; set; } = Core.Toolsets.Default;

    /// <summary>
    /// Saved native code indexes, so reopening an image loads its index instead of building it again; null = off
    /// (the default for options not parsed from a command line, so embedded and test servers write nothing).
    /// </summary>
    public Native.Code.CodeIndexCacheOptions? CodeIndexCache { get; set; }

    /// <summary>The options <see cref="Parse"/> reads a value after (the tool CLI tells them from tool arguments).</summary>
    public static readonly IReadOnlySet<string> ValueOptions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "--load", "--search-dir", "--max-output", "--timeout", "--binding-style", "--binding-project", "--prewarm", "--engine",
        "--index-cache", "--index-cache-mb", "--index-cache-days", "--log-level", Core.Toolsets.Option, Core.Toolsets.ToolsFileOption, TraceOption,
    };

    public static ServerOptions Parse(string[] args)
    {
        var o = new ServerOptions { CodeIndexCache = Native.Code.CodeIndexCacheOptions.FromEnvironment() };
        string? cacheRoot = null;
        long? cacheMb = null;
        int? cacheDays = null;
        string? engine = Environment.GetEnvironmentVariable(EngineVariable) is { Length: > 0 } fromEnv ? fromEnv : null;
        string? prewarm = Environment.GetEnvironmentVariable(PrewarmVariable) is { Length: > 0 } prewarmFromEnv ? prewarmFromEnv
            : Environment.GetEnvironmentVariable(IdaPrewarmVariable)?.Trim() is "1" or "true" or "on" ? "ida" : null;
        string? logLevel = Environment.GetEnvironmentVariable(LogLevelVariable) is { Length: > 0 } levelFromEnv ? levelFromEnv : null;
        string? toolsets = Environment.GetEnvironmentVariable(Core.Toolsets.Variable) is { Length: > 0 } setsFromEnv ? setsFromEnv : null;
        string? toolsFile = null, trace = null;
        for (int i = 0; i < args.Length; i++)
        {
            string Next() => i + 1 < args.Length ? args[++i] : throw new ArgumentException($"Missing value after {args[i]}");
            switch (args[i].ToLowerInvariant())
            {
                case "--load": o.Preload.Add(Next()); break;
                case "--search-dir": o.SearchDirectories.Add(Next()); break;
                case "--max-output": o.MaxOutputChars = Math.Max(2_000, int.Parse(Next())); break;
                case "--timeout": o.TimeoutSeconds = Math.Max(5, int.Parse(Next())); break;
                case "--no-index": o.BackgroundIndexing = false; break;
                case "--no-watch": o.WatchFiles = false; break;
                case "--binding-style":
                    var style = Next().Trim().ToLowerInvariant();
                    o.BindingStyle = style is "mono" or "hostapi" or "il2cpp" ? style : throw new ArgumentException($"--binding-style must be mono, il2cpp or hostapi, not '{style}'");
                    break;
                case "--binding-project": o.BindingProject = Next(); break;
                case "--ida-prewarm": prewarm = "ida"; break;
                case "--prewarm": prewarm = Next(); break;
                case "--ida-scripting": o.IdaScripting = true; break;
                case GhidraScriptingOption: o.GhidraScripting = true; break;
                case AllowDeviceChangesOption: o.AllowDeviceChanges = true; break;
                case "--engine": engine = Next(); break;
                case "--index-cache": cacheRoot = Next(); break;
                case "--index-cache-mb": cacheMb = long.TryParse(Next(), out var mb) && mb > 0 ? mb : throw new ArgumentException("--index-cache-mb must be a positive number"); break;
                case "--log-level": logLevel = Next(); break;
                case Core.Toolsets.Option: toolsets = Next(); break;
                case Core.Toolsets.ToolsFileOption: toolsFile = Next(); break;
                case TraceOption: trace = Next(); break;
                case "--index-cache-days": cacheDays = int.TryParse(Next(), out var days) && days > 0 ? days : throw new ArgumentException("--index-cache-days must be a positive number"); break;
                default: throw new ArgumentException($"Unknown argument '{args[i]}'");
            }
        }

        if (cacheRoot?.Trim().ToLowerInvariant() is "off" or "none" or "0") o.CodeIndexCache = null;
        else
        {
            var c = o.CodeIndexCache ?? Native.Code.CodeIndexCacheOptions.Default;
            if (cacheRoot != null) c = c with { Root = cacheRoot };
            if (cacheMb is { } m) c = c with { MaxBytes = m << 20 };
            if (cacheDays is { } d) c = c with { MaxAge = TimeSpan.FromDays(d) };
            // an explicit option turns the cache on even when the environment turned it off
            if (o.CodeIndexCache != null || cacheRoot != null || cacheMb != null || cacheDays != null) o.CodeIndexCache = c;
        }
        if (logLevel != null)
            o.LogLevel = ParseLogLevel(logLevel) ?? throw new ArgumentException($"--log-level (or {LogLevelVariable}) must be trace, debug, information, warning, error or none, not '{logLevel.Trim()}'");
        if (toolsets != null) o.Toolsets = Core.Toolsets.Parse(toolsets);
        o.ParseProductOptions(toolsFile, trace);
        if (prewarm != null)
            o.Prewarm = EngineModes.TryParse(prewarm) is { } p && p != EngineMode.Ours ? p
                : prewarm.Trim().ToLowerInvariant() is "off" or "0" or "none" ? null
                : throw new ArgumentException($"--prewarm (or {PrewarmVariable}) must be ida, ghidra, auto or off, not '{prewarm.Trim()}'");
        if (Environment.GetEnvironmentVariable(IdaScriptingVariable)?.Trim() is "1" or "true" or "on") o.IdaScripting = true;
        if (Environment.GetEnvironmentVariable(GhidraScriptingVariable)?.Trim() is "1" or "true" or "on") o.GhidraScripting = true;
        if (Environment.GetEnvironmentVariable(AllowDeviceChangesVariable)?.Trim() is "1" or "true" or "on") o.AllowDeviceChanges = true;
        o.EngineRequestTimeoutSeconds = Seconds(EngineRequestTimeoutVariable, o.EngineRequestTimeoutSeconds);
        o.EngineOpenTimeoutSeconds = Seconds(EngineOpenTimeoutVariable, o.EngineOpenTimeoutSeconds);
        o.EngineAnalysis = Environment.GetEnvironmentVariable(EngineAnalysisVariable)?.Trim().ToLowerInvariant() switch
        {
            null or "" or "full" => Native.Providers.EngineAnalysis.Full,
            "none" => Native.Providers.EngineAnalysis.None,
            var other => throw new ArgumentException($"{EngineAnalysisVariable} must be full or none, not '{other}'"),
        };
        if (engine != null)
            o.Engine = EngineModes.TryParse(engine) ?? throw new ArgumentException($"--engine (or {EngineVariable}) must be auto, ours, ida or ghidra, not '{engine.Trim()}'");
        var env = Environment.GetEnvironmentVariable("NETDECOMP_LOAD");
        if (!string.IsNullOrWhiteSpace(env))
            o.Preload.AddRange(env.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        return o;
    }

    // ---- Catalog whitelist and call trace ----

    /// <summary>Tools a --tools-file whitelist names (null: no whitelist); applied after <see cref="Toolsets"/>, session tools always kept.</summary>
    public IReadOnlySet<string>? ToolAllowList { get; set; }

    /// <summary>The --tools-file value the whitelist came from (a list name or a path); null without one.</summary>
    public string? ToolAllowListSource { get; set; }

    /// <summary>JSONL file that gets one line per tools/call (tool, arguments, ms, error, size); null: off.</summary>
    public string? TracePath { get; set; }

    public const string TraceOption = "--trace";
    public const string TraceVariable = "NDM_TRACE";

    /// <summary>Engine database files a trace must never be written into.</summary>
    private static readonly string[] DatabaseExtensions = [".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til", ".gpr", ".gzf", ".rep"];

    /// <summary>The full path of a trace file; an engine database path is an <see cref="ArgumentException"/>.</summary>
    public static string TraceFile(string path)
    {
        var full = Path.GetFullPath(path.Trim());
        if (DatabaseExtensions.Contains(Path.GetExtension(full), StringComparer.OrdinalIgnoreCase))
            throw new ArgumentException($"{TraceOption} (or {TraceVariable}): the trace goes to a file of its own, not an engine database ('{full}')");
        return full;
    }

    /// <summary>The command line value wins over the environment.</summary>
    private void ParseProductOptions(string? toolsFile, string? trace)
    {
        toolsFile ??= Environment.GetEnvironmentVariable(Core.Toolsets.ToolsFileVariable) is { Length: > 0 } fileFromEnv ? fileFromEnv : null;
        if (toolsFile != null)
        {
            ToolAllowList = Core.Toolsets.LoadToolList(toolsFile);
            ToolAllowListSource = Core.Toolsets.ToolLists.ContainsKey(toolsFile.Trim().ToLowerInvariant()) ? toolsFile.Trim().ToLowerInvariant() : Path.GetFullPath(toolsFile.Trim());
        }
        trace ??= Environment.GetEnvironmentVariable(TraceVariable) is { Length: > 0 } traceFromEnv ? traceFromEnv : null;
        if (trace != null) TracePath = TraceFile(trace);
    }

    /// <summary>A positive number of seconds from <paramref name="variable"/>, or <paramref name="fallback"/> when it is unset.</summary>
    private static int Seconds(string variable, int fallback)
    {
        var text = Environment.GetEnvironmentVariable(variable)?.Trim();
        if (string.IsNullOrEmpty(text)) return fallback;
        return int.TryParse(text, out var s) && s > 0 ? s : throw new ArgumentException($"{variable} must be a positive number of seconds, not '{text}'");
    }

    private static LogLevel? ParseLogLevel(string text) => text.Trim().ToLowerInvariant() switch
    {
        "trace" => LogLevel.Trace,
        "debug" => LogLevel.Debug,
        "information" or "info" => LogLevel.Information,
        "warning" or "warn" => LogLevel.Warning,
        "error" => LogLevel.Error,
        "none" or "off" => LogLevel.None,
        _ => null,
    };
}

/// <summary>
/// Where the native code tools take functions, cross-references and control-flow graphs from: Auto (an engine's
/// analysis when one of the image is complete in this session, IDA's before Ghidra's, else the built-in index; never
/// starts an engine), Ours (the built-in index only; no engine is asked), Ida or Ghidra (that engine's analysis,
/// started and waited for when needed).
/// </summary>
public enum EngineMode { Auto, Ours, Ida, Ghidra }

public static class EngineModes
{
    /// <summary>auto, ours, ida or ghidra (case-insensitive; "built-in" and "builtin" mean ours); null for anything else.</summary>
    public static EngineMode? TryParse(string? text) => text?.Trim().ToLowerInvariant() switch
    {
        "auto" => EngineMode.Auto,
        "ours" or "built-in" or "builtin" => EngineMode.Ours,
        "ida" => EngineMode.Ida,
        "ghidra" => EngineMode.Ghidra,
        _ => null,
    };

    /// <summary>The mode a call asks for, or <paramref name="fallback"/> when it names none; an unknown name is an invalid_argument error.</summary>
    public static EngineMode Resolve(string? text, EngineMode fallback) =>
        string.IsNullOrWhiteSpace(text) ? fallback
        : TryParse(text) ?? throw new ToolError(ErrorCode.InvalidArgument, $"Unknown engine '{text.Trim()}'.", "use auto, ours, ida or ghidra");

    public static string Name(EngineMode mode) => mode switch { EngineMode.Ours => "ours", EngineMode.Ida => "ida", EngineMode.Ghidra => "ghidra", _ => "auto" };

    /// <summary>The provider id of an engine mode (ida, ghidra), or null for auto and ours.</summary>
    public static string? ProviderId(EngineMode mode) => mode switch { EngineMode.Ida => "ida", EngineMode.Ghidra => "ghidra", _ => null };
}
