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
/// The NETDECOMP_LOAD environment variable (';'-separated paths) is also honored; NDM_IDA_PREWARM=1 turns on --ida-prewarm.
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

    public static ServerOptions Parse(string[] args)
    {
        var o = new ServerOptions();
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
                default: throw new ArgumentException($"Unknown argument '{args[i]}'");
            }
        }

        if (Environment.GetEnvironmentVariable(IdaPrewarmVariable)?.Trim() is "1" or "true" or "on") o.IdaPrewarm = true;
        var env = Environment.GetEnvironmentVariable("NETDECOMP_LOAD");
        if (!string.IsNullOrWhiteSpace(env))
            o.Preload.AddRange(env.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        return o;
    }
}
