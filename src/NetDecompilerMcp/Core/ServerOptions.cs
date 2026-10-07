namespace NetDecompilerMcp.Core;

/// <summary>
/// Startup options. Command line:
///   --load &lt;path&gt;        assembly file or directory to load at startup (repeatable)
///   --search-dir &lt;dir&gt;   extra directory for resolving references (repeatable)
///   --max-output &lt;n&gt;     max characters per tool response page (default 60000)
///   --timeout &lt;seconds&gt;  per-call decompilation timeout (default 180)
/// The NETDECOMP_LOAD environment variable (';'-separated paths) is also honored.
/// </summary>
public sealed class ServerOptions
{
    public List<string> Preload { get; } = new();
    public List<string> SearchDirectories { get; } = new();
    public int MaxOutputChars { get; set; } = 60_000;
    public int TimeoutSeconds { get; set; } = 180;

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
                default: throw new ArgumentException($"Unknown argument '{args[i]}'");
            }
        }

        var env = Environment.GetEnvironmentVariable("NETDECOMP_LOAD");
        if (!string.IsNullOrWhiteSpace(env))
            o.Preload.AddRange(env.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        return o;
    }
}
