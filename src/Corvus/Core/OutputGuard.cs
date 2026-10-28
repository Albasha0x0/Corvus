namespace Corvus.Core;

/// <summary>Places no output path may reach: the server's own state and install, PATH, start files, repository, SSH and agent configuration.</summary>
public static class OutputGuard
{
    /// <summary>How much of the file system a place covers: the path itself, everything under it, only the entries directly in it,
    /// or the code and host configuration files the runtime loads from it.</summary>
    public enum Reach { Exact, Tree, Children, Code }

    /// <summary>One refused place; <paramref name="Except"/> is a folder under a tree that takes outputs.</summary>
    public sealed record Place(string Path, Reach Reach, string Reason, string? Except = null);

    /// <summary>The details of a refusal: the path as given, its final path and why.</summary>
    public sealed record Refused(string Path, string Final, string Reason);

    /// <summary>Where a host keeps the places: its variables, its special folders and the install root (null outside the install layout).</summary>
    public sealed record Host(Func<string, string?> Variable, Func<Environment.SpecialFolder, string> Folder, string? InstallRoot, string? ProgramFolder = null);

    /// <summary>The folder of the data folder that takes outputs.</summary>
    public const string ExportsFolder = "exports";

    /// <summary>Programs and folders sessions may open (--live-allow), set when the options are parsed.</summary>
    public static IReadOnlyList<string> LiveAllow { get; set; } = [];

    /// <summary>The configuration files of the MCP clients setup registers; read once, on the first output.</summary>
    public static Func<IEnumerable<string>>? ClientConfigs
    {
        get => _clientConfigs;
        set
        {
            _clientConfigs = value;
            _clients = null;
        }
    }

    private static Func<IEnumerable<string>>? _clientConfigs;
    private static IReadOnlyList<string>? _clients;
    private static Cached? _cache;
    private static readonly Lock Gate = new();

    private sealed record Cached(string Key, IReadOnlyList<Place> Places);

    /// <summary>The install root when this process runs from &lt;root&gt;/versions/&lt;version&gt;/ or &lt;root&gt;/current/; null otherwise.</summary>
    public static string? InstallRoot()
    {
        var dir = Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory);
        var parent = Path.GetDirectoryName(dir);
        if (parent == null) return null;
        if (Path.GetFileName(parent) == "versions") return Path.GetDirectoryName(parent);
        if (Path.GetFileName(dir) == "current" && Directory.Exists(Path.Combine(parent, "versions"))) return parent;
        return null;
    }

    /// <summary>This process's host.</summary>
    public static Host ThisHost() => new(Environment.GetEnvironmentVariable, f => Environment.GetFolderPath(f), InstallRoot(), AppContext.BaseDirectory);

    /// <summary>This host's refused places as final paths, built again when an input changes.</summary>
    public static IReadOnlyList<Place> Current()
    {
        IReadOnlyList<string> clients;
        lock (Gate) clients = _clients ??= Clients();
        var key = string.Join('\n', Environment.GetEnvironmentVariable("PATH"), Environment.GetEnvironmentVariable(Native.Providers.DataFolder.RootVariable),
            Environment.GetEnvironmentVariable(ConfigFile.Variable), Environment.GetEnvironmentVariable(Relay.RelayBuilds.TargetVariable),
            Environment.GetEnvironmentVariable("XDG_CONFIG_HOME"), string.Join(';', LiveAllow), clients.Count);
        if (_cache is { } cached && cached.Key == key) return cached.Places;
        var places = Final(Defaults(ThisHost(), LiveAllow, clients));
        _cache = new(key, places);
        return places;
    }

    private static IReadOnlyList<string> Clients()
    {
        try { return [.. _clientConfigs?.Invoke() ?? []]; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { return []; }
    }

    /// <summary>The places of <paramref name="host"/>, paths as configured, not yet final.</summary>
    public static List<Place> Defaults(Host host, IReadOnlyList<string> liveAllow, IReadOnlyList<string> clients)
    {
        var data = host.Variable(Native.Providers.DataFolder.RootVariable) is { Length: > 0 } custom ? custom
            : Path.Combine(host.Folder(Environment.SpecialFolder.LocalApplicationData), Native.Providers.DataFolder.Name);
        var list = new List<Place>
        {
            new(data, Reach.Tree, "in the server's data folder", Path.Combine(data, ExportsFolder)),
            new(host.Variable(ConfigFile.Variable) is { Length: > 0 } named ? named : Path.Combine(data, ConfigFile.FileName), Reach.Exact,
                "the server's configuration file"),
        };
        if (host.InstallRoot is { } root) list.Add(new(root, Reach.Tree, "in the server's install folder"));
        // Any layout (tool install, copied folder): the files the server loads, and new code it could load.
        if (host.ProgramFolder is { Length: > 0 } program) list.Add(new(program, Reach.Code, "a program file in the server's folder"));
        foreach (var dir in (host.Variable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            list.Add(new(dir, Reach.Children, "in a folder on PATH"));
        foreach (var entry in liveAllow) list.Add(new(entry, Reach.Tree, "a program sessions may open (--live-allow)"));
        if (host.Variable(Relay.RelayBuilds.TargetVariable) is { Length: > 0 } relay) list.Add(new(relay, Reach.Tree, "in the relay's publish folder"));
        foreach (var file in clients) list.Add(new(file, Reach.Exact, "an MCP client's configuration file"));
        if (OperatingSystem.IsWindows())
        {
            foreach (var folder in new[] { Environment.SpecialFolder.Startup, Environment.SpecialFolder.CommonStartup })
                if (host.Folder(folder) is { Length: > 0 } startup) list.Add(new(startup, Reach.Tree, "in a Startup folder"));
            if (host.Folder(Environment.SpecialFolder.MyDocuments) is { Length: > 0 } documents)
                foreach (var shell in new[] { "PowerShell", "WindowsPowerShell" })
                    list.Add(new(Path.Combine(documents, shell), Reach.Tree, "in a shell profile folder"));
        }
        var home = host.Folder(Environment.SpecialFolder.UserProfile);
        if (home.Length == 0) return list;
        // Git for Windows reads the POSIX shell files too.
        foreach (var name in StartFiles) list.Add(new(Path.Combine(home, name), Reach.Exact, "a shell start file"));
        var config = host.Variable("XDG_CONFIG_HOME") is { Length: > 0 } xdg ? xdg : Path.Combine(home, ".config");
        foreach (var folder in StartFolders) list.Add(new(Path.Combine(config, folder), Reach.Tree, "in an autostart or shell start folder"));
        list.Add(new(Path.Combine(home, "Library", "LaunchAgents"), Reach.Tree, "in an autostart or shell start folder"));
        list.Add(new(Path.Combine(home, ".gitconfig"), Reach.Exact, "the git configuration file"));
        list.Add(new(Path.Combine(config, "git"), Reach.Tree, "in the git configuration folder"));
        list.Add(new(Path.Combine(home, ".ssh"), Reach.Tree, "in the SSH folder"));
        return list;
    }

    private static readonly HashSet<string> CodeExtensions = new(StringComparer.OrdinalIgnoreCase) { ".dll", ".exe", ".so", ".dylib" };

    // The host loads code and its configuration from the folder itself and from runtimes/; other files there are outputs.
    private static bool IsProgramFile(string final, string folder)
    {
        if (!(Path.GetDirectoryName(final) is { } parent && InputFiles.SamePath(parent, folder) || Under(final, Path.Combine(folder, "runtimes")))) return false;
        var name = Path.GetFileName(final);
        return CodeExtensions.Contains(Path.GetExtension(name))
               || name.EndsWith(".deps.json", InputFiles.PathComparison) || name.EndsWith(".runtimeconfig.json", InputFiles.PathComparison);
    }

    private static readonly string[] StartFiles =
    [
        ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout",
        ".cshrc", ".tcshrc", ".login", ".kshrc", ".mkshrc", ".xprofile", ".xsessionrc", ".xinitrc", ".pam_environment",
    ];

    private static readonly string[] StartFolders = ["autostart", "fish", Path.Combine("systemd", "user"), "environment.d", "powershell"];

    /// <summary>Each place with its path made final; a relative path, or one the host cannot name, is left out.</summary>
    public static IReadOnlyList<Place> Final(IEnumerable<Place> places)
    {
        var list = new List<Place>();
        foreach (var p in places)
        {
            try
            {
                if (!Path.IsPathFullyQualified(p.Path)) continue;
                list.Add(p with
                {
                    Path = InputFiles.FinalPathOfNew(Path.GetFullPath(p.Path)),
                    Except = p.Except == null ? null : InputFiles.FinalPathOfNew(Path.GetFullPath(p.Except)),
                });
            }
            catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException) { }
        }
        return list;
    }

    /// <summary>Why <paramref name="final"/>, a final path, takes no output; null when it may be written.</summary>
    public static string? Refusal(string final, IReadOnlyList<Place> places)
    {
        foreach (var p in places)
        {
            bool hit = p.Reach switch
            {
                Reach.Exact => InputFiles.SamePath(final, p.Path),
                Reach.Tree => Under(final, p.Path) && (p.Except == null || !Under(final, p.Except)),
                Reach.Code => IsProgramFile(final, p.Path),
                _ => InputFiles.SamePath(final, p.Path) || Path.GetDirectoryName(final) is { } parent && InputFiles.SamePath(parent, p.Path),
            };
            if (hit) return p.Reason;
        }
        var segments = final.Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries);
        if (segments.Any(s => s.Equals(".git", InputFiles.PathComparison))) return "in a repository's .git folder";
        if (segments.Any(s => s.Equals(".claude", InputFiles.PathComparison))) return "in a .claude folder";
        if (AgentFiles.Kind(string.Join('/', segments), InputFiles.PathComparison == StringComparison.OrdinalIgnoreCase) is { } kind)
            return $"an agent {kind} file";
        return null;
    }

    /// <summary>Throws invalid_argument naming <paramref name="shown"/> when <paramref name="final"/> takes no output.</summary>
    public static void Check(string final, string shown, IReadOnlyList<Place> places)
    {
        if (Refusal(final, places) is not { } reason) return;
        throw new ToolError(ErrorCode.InvalidArgument, $"{shown} is {reason}; outputs are not written there.", "pick a path outside it")
        {
            Details = new Refused(shown, final, reason),
        };
    }

    /// <summary>Whether <paramref name="error"/> is a refusal of <see cref="Check"/>.</summary>
    public static bool IsRefusal(ToolError error) => error.Details is Refused;

    private static bool Under(string path, string root) =>
        InputFiles.SamePath(path, root) || path.StartsWith(Path.EndsInDirectorySeparator(root) ? root : root + Path.DirectorySeparatorChar, InputFiles.PathComparison);
}
