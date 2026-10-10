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
///   --ida-prewarm         start IDA's analysis of each native image in the background right after it loads (one at a time)
///   --index-cache &lt;dir|off&gt;  directory of saved native code indexes (default &lt;LocalAppData&gt;/NetDecompilerMcp/code-index), or off
///   --index-cache-mb &lt;n&gt;  size limit of the code index cache in MB (default 8192)
///   --index-cache-days &lt;n&gt; entries unused for this many days are deleted (default 30)
/// The NETDECOMP_LOAD environment variable (';'-separated paths) is also honored; NDM_IDA_PREWARM=1 turns on --ida-prewarm;
/// NDM_CODE_INDEX_CACHE, NDM_CODE_INDEX_CACHE_MB and NDM_CODE_INDEX_CACHE_DAYS set the code index cache defaults.
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
    /// Open an IDA session for each native image in the background right after it loads (one image at a time, cancelled
    /// on unload), so the first decompile_native does not wait for auto-analysis (default off).
    /// </summary>
    public bool IdaPrewarm { get; set; }

    public const string IdaPrewarmVariable = "NDM_IDA_PREWARM";

    /// <summary>
    /// Saved native code indexes, so reopening an image loads its index instead of building it again; null = off
    /// (the default for options not parsed from a command line, so embedded and test servers write nothing).
    /// </summary>
    public Native.Code.CodeIndexCacheOptions? CodeIndexCache { get; set; }

    public static ServerOptions Parse(string[] args)
    {
        var o = new ServerOptions { CodeIndexCache = Native.Code.CodeIndexCacheOptions.FromEnvironment() };
        string? cacheRoot = null;
        long? cacheMb = null;
        int? cacheDays = null;
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
                case "--ida-prewarm": o.IdaPrewarm = true; break;
                case "--index-cache": cacheRoot = Next(); break;
                case "--index-cache-mb": cacheMb = long.TryParse(Next(), out var mb) && mb > 0 ? mb : throw new ArgumentException("--index-cache-mb must be a positive number"); break;
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
        if (Environment.GetEnvironmentVariable(IdaPrewarmVariable)?.Trim() is "1" or "true" or "on") o.IdaPrewarm = true;
        var env = Environment.GetEnvironmentVariable("NETDECOMP_LOAD");
        if (!string.IsNullOrWhiteSpace(env))
            o.Preload.AddRange(env.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        return o;
    }
}
