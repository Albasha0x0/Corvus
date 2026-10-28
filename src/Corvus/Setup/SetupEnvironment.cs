using System.Runtime.InteropServices;

namespace Corvus.Setup;

internal enum HostOs { Windows, MacOs, Linux }

/// <summary>User folders and tool lookup used to locate MCP client configurations; replaceable for tests.</summary>
internal sealed class SetupEnvironment
{
    public required HostOs Os { get; init; }
    public required string Home { get; init; }
    /// <summary>Windows: %APPDATA%. Unused elsewhere.</summary>
    public string AppData { get; init; } = "";
    /// <summary>The local application data folder (%LOCALAPPDATA% on Windows); holds the per-user data root.</summary>
    public string LocalAppData { get; init; } = "";
    /// <summary>Linux: $XDG_CONFIG_HOME or ~/.config.</summary>
    public string XdgConfig { get; init; } = "";
    public Func<string, string?> Variable { get; init; } = Environment.GetEnvironmentVariable;
    /// <summary>Full path of a command on PATH, else null.</summary>
    public Func<string, string?> FindTool { get; init; } = _ => null;
    public bool HasTool(string tool) => FindTool(tool) != null;
    public Func<string, bool> DirectoryExists { get; init; } = Directory.Exists;
    /// <summary>Input and output are terminals, so install may ask before registering new clients.</summary>
    public bool Interactive { get; init; }
    /// <summary>Asks a yes/no question whose default is yes.</summary>
    public Func<string, bool> Confirm { get; init; } = _ => false;
    /// <summary>IDA's availability; with true, a started idalib worker. Machine-dependent, so tests replace it.</summary>
    public Func<bool, Corvus.Native.Providers.ProviderAvailability> Ida { get; init; } = Doctor.ProbeIda;
    /// <summary>The Python interpreter IDA would use and why each candidate was rejected.</summary>
    public Func<(string? Python, List<string> Log)> Python { get; init; } = Doctor.FindPython;

    public static SetupEnvironment Current()
    {
        var os = OperatingSystem.IsWindows() ? HostOs.Windows : OperatingSystem.IsMacOS() ? HostOs.MacOs : HostOs.Linux;
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var xdg = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME");
        return new SetupEnvironment
        {
            Os = os,
            Home = home,
            AppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            LocalAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            XdgConfig = string.IsNullOrEmpty(xdg) ? Path.Combine(home, ".config") : xdg,
            FindTool = OnPath(),
            Interactive = !Console.IsInputRedirected && !Console.IsOutputRedirected,
            Confirm = AskConsole,
        };
    }

    /// <summary>One keypress: Enter or y is yes, anything else is no.</summary>
    private static bool AskConsole(string question)
    {
        Console.Write(question + " [Y/n] ");
        try
        {
            var key = Console.ReadKey(intercept: true);
            bool yes = key.Key == ConsoleKey.Enter || key.KeyChar is 'y' or 'Y';
            Console.WriteLine(yes ? "y" : "n");
            return yes;
        }
        catch (InvalidOperationException)
        {
            var line = Console.ReadLine()?.Trim();
            return line is "" or "y" or "Y" or "yes";
        }
    }

    /// <summary>Per-application settings folder: %APPDATA%\name, ~/Library/Application Support/name, ~/.config/name.</summary>
    public string AppSupport(string name) => Os switch
    {
        HostOs.Windows => Path.Combine(AppData, name),
        HostOs.MacOs => Path.Combine(Home, "Library", "Application Support", name),
        _ => Path.Combine(XdgConfig, name),
    };

    public string InHome(params string[] parts) => Path.Combine([Home, .. parts]);

    /// <summary>A non-empty environment variable, else null.</summary>
    public string? Set(string name) => Variable(name) is { Length: > 0 } value ? value : null;

    /// <summary>A path from an override variable: "~" and "~/x" are under the home folder, relative paths under the working directory.</summary>
    public string ExpandPath(string path)
    {
        if (path == "~") return Home;
        if (path.StartsWith("~/", StringComparison.Ordinal) || path.StartsWith("~\\", StringComparison.Ordinal))
            return Path.Combine([Home, .. path[2..].Split(['/', '\\'], StringSplitOptions.RemoveEmptyEntries)]);
        return Path.GetFullPath(path);
    }

    // One listing per PATH folder for all the tools a probe looks up, not one
    // File.Exists per folder, extension and tool.
    private static Func<string, string?> OnPath() =>
        new PathSearch(Environment.GetEnvironmentVariable("PATH"),
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? Environment.GetEnvironmentVariable("PATHEXT") ?? ".EXE;.CMD;.BAT" : null).Find;
}

/// <summary>
/// Finds a command in <c>path</c>'s folders, in order, with each of <c>extensions</c> (';'-separated; null: the name
/// alone), as File.Exists would; each folder is listed once, on first use. A folder that cannot be listed holds nothing.
/// </summary>
internal sealed class PathSearch(string? path, string? extensions, Func<string, IEnumerable<string>>? list = null)
{
    private readonly string[] _dirs = (path ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries).Select(d => d.Trim('"')).ToArray();
    private readonly string[] _extensions = extensions?.Split(';', StringSplitOptions.RemoveEmptyEntries) ?? [""];
    private readonly Func<string, IEnumerable<string>> _list = list ?? (d => Directory.EnumerateFiles(d).Select(Path.GetFileName)!);
    private readonly Dictionary<string, HashSet<string>> _names = [];

    /// <summary>The full path of <paramref name="tool"/>, or null when no folder holds it.</summary>
    public string? Find(string tool)
    {
        foreach (var dir in _dirs)
            foreach (var ext in _extensions)
                if (Names(dir).Contains(tool + ext)) return Path.Combine(dir, tool + ext);
        return null;
    }

    private HashSet<string> Names(string dir)
    {
        lock (_names)
        {
            if (_names.TryGetValue(dir, out var names)) return names;
            var comparer = OperatingSystem.IsLinux() ? StringComparer.Ordinal : StringComparer.OrdinalIgnoreCase;
            try { names = new HashSet<string>(_list(dir), comparer); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or System.Security.SecurityException) { names = new(comparer); }
            return _names[dir] = names;
        }
    }
}
