using System.Globalization;

namespace Corvus.Relay;

/// <summary>
/// "NetDecompilerMcp relay --target &lt;publishDir&gt; [--state &lt;dir&gt;] [--poll-ms &lt;n&gt;] [--] [server args]": the development
/// reload relay. Arguments it does not know go to the server.
/// </summary>
public static class RelayCli
{
    public const string Command = "relay";
    private static readonly string[] ValueOptions = ["--target", "--state", "--poll-ms"];

    public static int? TryRun(string[] args)
    {
        if (args.Length == 0 || args[0] != Command) return null;
        RelayOptions options;
        try { options = Parse(args.Skip(1).ToList()); }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine($"net-decompiler relay: {ex.Message}");
            return 2;
        }
        if (RelayBuilds.IsInside(AppContext.BaseDirectory, options.Target))
            Console.Error.WriteLine($"net-decompiler relay: running from inside {options.Target}; publish.ps1 renames these files aside while they run, " +
                                    "other publish tools may fail on them. A staged copy avoids that: NetDecompilerMcp install --dev-reload <publishDir>.");
        var relay = new DevRelay(options, Console.OpenStandardInput(), Console.OpenStandardOutput(), Console.Error);
        return relay.RunAsync().GetAwaiter().GetResult();
    }

    public static RelayOptions Parse(IReadOnlyList<string> args)
    {
        string? target = null, state = null;
        int pollMs = 1000;
        var server = new List<string>();
        for (int i = 0; i < args.Count; i++)
        {
            var arg = args[i];
            if (arg == "--")
            {
                server.AddRange(args.Skip(i + 1));
                break;
            }
            if (!ValueOptions.Contains(arg))
            {
                server.Add(arg);
                continue;
            }
            var value = i + 1 < args.Count ? args[++i] : throw new ArgumentException($"{arg} needs a value.");
            switch (arg)
            {
                case "--target": target = value; break;
                case "--state": state = value; break;
                default:
                    if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out pollMs) || pollMs < 10)
                        throw new ArgumentException("--poll-ms takes milliseconds (10 or more).");
                    break;
            }
        }
        if (target == null) throw new ArgumentException("--target <publishDir> is required.");
        target = Path.GetFullPath(target);
        if (!Directory.Exists(target)) throw new ArgumentException($"{target} does not exist.");
        return new RelayOptions
        {
            Target = target,
            StateDirectory = Path.GetFullPath(state ?? DefaultState()),
            ServerArgs = server,
            Poll = TimeSpan.FromMilliseconds(pollMs),
        };
    }

    /// <summary><c>CORVUS_RELAY_DIR</c>, else the data folder's relay/.</summary>
    public static string DefaultState() =>
        Environment.GetEnvironmentVariable("CORVUS_RELAY_DIR") is { Length: > 0 } dir
            ? dir
            : Native.Providers.DataFolder.Combine("relay");

    /// <summary>
    /// A registration's arguments without the relay command and its own options (what remains is the server's); the
    /// command may follow the corvus.dll of a dotnet launch.
    /// </summary>
    public static List<string> WithoutRelayPrefix(IEnumerable<string> args)
    {
        var list = args.ToList();
        int start = list.Count > 1 && Path.GetFileName(list[0]).Equals("corvus.dll", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        if (list.Count <= start || list[start] != Command) return list;
        int i = start + 1;
        while (i < list.Count && ValueOptions.Contains(list[i])) i += 2;
        if (i < list.Count && list[i] == "--") i++;
        return [.. list.Take(start), .. list.Skip(Math.Min(i, list.Count))];
    }
}
