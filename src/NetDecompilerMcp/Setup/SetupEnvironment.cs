using System.Runtime.InteropServices;

namespace NetDecompilerMcp.Setup;

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
            FindTool = OnPath,
        };
    }

    /// <summary>Per-application settings folder: %APPDATA%\name, ~/Library/Application Support/name, ~/.config/name.</summary>
    public string AppSupport(string name) => Os switch
    {
        HostOs.Windows => Path.Combine(AppData, name),
        HostOs.MacOs => Path.Combine(Home, "Library", "Application Support", name),
        _ => Path.Combine(XdgConfig, name),
    };

    public string InHome(params string[] parts) => Path.Combine([Home, .. parts]);

    private static string? OnPath(string tool)
    {
        var dirs = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);
        string[] extensions = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? (Environment.GetEnvironmentVariable("PATHEXT") ?? ".EXE;.CMD;.BAT").Split(';', StringSplitOptions.RemoveEmptyEntries)
            : [""];
        foreach (var dir in dirs)
            foreach (var ext in extensions)
            {
                try
                {
                    var candidate = Path.Combine(dir.Trim('"'), tool + ext);
                    if (File.Exists(candidate)) return candidate;
                }
                catch (ArgumentException) { }
            }
        return null;
    }
}
