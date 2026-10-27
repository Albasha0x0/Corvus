using System.Runtime.InteropServices;

namespace Corvus.Native.Providers.Ghidra;

/// <summary>A Ghidra install with its version, Java range and native decompiler (shipped for win_x86_64 and linux_x86_64 only), located from the option, <see cref="GhidraOptions.DirectoryVariable"/> or GHIDRA_INSTALL_DIR.</summary>
public sealed record GhidraInstallation(string Directory, string Version, string Revision, int JavaMin, int? JavaMax, string? DecompilerPath, string Source)
{
    public const string StandardDirectoryVariable = "GHIDRA_INSTALL_DIR";

    public string UtilityJar => Path.Combine(Directory, "Ghidra", "Framework", "Utility", "lib", "Utility.jar");
    public string LaunchSupportJar => Path.Combine(Directory, "support", "LaunchSupport.jar");
    public string PropertiesPath => Path.Combine(Directory, "Ghidra", "application.properties");

    /// <summary>Ghidra's directory name for this OS and CPU (Ghidra/Features/Decompiler/os/&lt;name&gt;).</summary>
    public static string PlatformName =>
        (OperatingSystem.IsWindows() ? "win" : OperatingSystem.IsMacOS() ? "mac" : "linux") + "_" +
        (RuntimeInformation.OSArchitecture == Architecture.Arm64 ? "arm_64" : "x86_64");

    /// <summary>Jars the worker compiles against: the framework and feature modules.</summary>
    public IReadOnlyList<string> CompileClasspath()
    {
        var jars = new List<string>();
        foreach (var group in new[] { "Framework", "Features" })
        {
            var root = Path.Combine(Directory, "Ghidra", group);
            if (!System.IO.Directory.Exists(root)) continue;
            foreach (var module in System.IO.Directory.EnumerateDirectories(root).Order(StringComparer.Ordinal))
            {
                var lib = Path.Combine(module, "lib");
                if (System.IO.Directory.Exists(lib)) jars.AddRange(System.IO.Directory.EnumerateFiles(lib, "*.jar").Order(StringComparer.Ordinal));
            }
        }
        return jars;
    }

    /// <summary>The validated install (<paramref name="explicitDirectory"/> first), or null with <paramref name="reason"/> and <paramref name="remediation"/> set.</summary>
    public static GhidraInstallation? Locate(string? explicitDirectory, out string reason, out string remediation)
    {
        string? dir = null, source = null;
        if (!string.IsNullOrWhiteSpace(explicitDirectory)) (dir, source) = (explicitDirectory, "configured");
        else if (Environment.GetEnvironmentVariable(GhidraOptions.DirectoryVariable) is { Length: > 0 } env) (dir, source) = (env, GhidraOptions.DirectoryVariable);
        else if (Environment.GetEnvironmentVariable(StandardDirectoryVariable) is { Length: > 0 } std) (dir, source) = (std, StandardDirectoryVariable);
        var fix = $"set {GhidraOptions.DirectoryVariable} to a Ghidra 12 or newer folder (the one holding ghidraRun)";
        if (dir == null)
        {
            reason = $"Ghidra was not found: neither {GhidraOptions.DirectoryVariable} nor {StandardDirectoryVariable} is set.";
            remediation = fix;
            return null;
        }
        dir = dir.Trim().Trim('"');
        if (!System.IO.Directory.Exists(dir))
        {
            reason = $"The Ghidra directory {dir} (from {source}) does not exist.";
            remediation = fix;
            return null;
        }
        dir = Path.GetFullPath(dir);
        var properties = ReadProperties(Path.Combine(dir, "Ghidra", "application.properties"));
        if (properties == null || !properties.TryGetValue("application.version", out var version) || version.Length == 0)
        {
            reason = $"{dir} (from {source}) is not a Ghidra install: Ghidra/application.properties is missing or names no version.";
            remediation = fix;
            return null;
        }
        var install = new GhidraInstallation(dir, version, properties.GetValueOrDefault("application.revision.ghidra", ""),
            int.TryParse(properties.GetValueOrDefault("application.java.min"), out var min) ? min : 21,
            int.TryParse(properties.GetValueOrDefault("application.java.max"), out var max) ? max : null,
            DecompilerFor(dir), source!);
        foreach (var required in new[] { install.UtilityJar, install.LaunchSupportJar })
        {
            if (File.Exists(required)) continue;
            reason = $"{dir} (from {source}) is incomplete: {Path.GetRelativePath(dir, required)} is missing.";
            remediation = "Unpack the Ghidra release archive again.";
            return null;
        }
        if (!System.Version.TryParse(version, out var v) || v.Major < 12)
        {
            reason = $"Ghidra {version} at {dir} is too old; version 12.0 or newer is required.";
            remediation = fix;
            return null;
        }
        reason = remediation = "";
        return install;
    }

    private static string? DecompilerFor(string dir)
    {
        var path = Path.Combine(dir, "Ghidra", "Features", "Decompiler", "os", PlatformName, OperatingSystem.IsWindows() ? "decompile.exe" : "decompile");
        return File.Exists(path) ? path : null;
    }

    /// <summary>Remediation for a missing native decompiler on this platform.</summary>
    public string DecompilerRemediation =>
        $"Ghidra ships its decompiler for win_x86_64 and linux_x86_64 only; build it for {PlatformName} with 'gradle buildNatives' in {Directory} (see Ghidra's DevGuide).";

    /// <summary>Java-style properties: key=value lines, '#' and '!' comments, no continuations (Ghidra's files use none).</summary>
    internal static Dictionary<string, string>? ReadProperties(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            var map = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var raw in File.ReadLines(path))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line[0] is '#' or '!') continue;
                int eq = line.IndexOf('=');
                if (eq > 0) map[line[..eq].Trim()] = line[(eq + 1)..].Trim();
            }
            return map;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}

/// <summary>A JDK: java and javac, and its feature version (24 for 24.0.1).</summary>
public sealed record JavaRuntime(string Home, string Java, string Javac, int Major, string Source)
{
    private static string Exe(string name) => OperatingSystem.IsWindows() ? name + ".exe" : name;

    /// <summary>The first JDK of <see cref="GhidraOptions.JavaVariable"/>, JAVA_HOME and PATH within [<paramref name="min"/>, <paramref name="max"/>]; tries go to <paramref name="log"/>.</summary>
    public static JavaRuntime? Locate(string? explicitHome, int min, int? max, List<string> log)
    {
        var candidates = new List<(string Path, string Source)>();
        if (!string.IsNullOrWhiteSpace(explicitHome)) candidates.Add((explicitHome, "configured"));
        if (Environment.GetEnvironmentVariable(GhidraOptions.JavaVariable) is { Length: > 0 } env) candidates.Add((env, GhidraOptions.JavaVariable));
        if (Environment.GetEnvironmentVariable("JAVA_HOME") is { Length: > 0 } home) candidates.Add((home, "JAVA_HOME"));
        if (OnPath(Exe("java")) is { } onPath) candidates.Add((onPath, "PATH"));
        foreach (var (path, source) in candidates)
        {
            var jdk = Probe(path.Trim().Trim('"'), source, out var problem);
            if (jdk == null) { log.Add($"{source} {path}: {problem}"); continue; }
            if (jdk.Major < min || (max is { } m && jdk.Major > m))
            {
                log.Add($"{source} {jdk.Home}: Java {jdk.Major} is outside Ghidra's range {min}..{(max?.ToString() ?? "")}");
                continue;
            }
            return jdk;
        }
        return null;
    }

    /// <summary>A JDK from its home, its bin directory, or its java executable.</summary>
    internal static JavaRuntime? Probe(string path, string source, out string problem)
    {
        var home = path;
        if (File.Exists(path)) home = Path.GetDirectoryName(Path.GetDirectoryName(Path.GetFullPath(path))!)!;
        else if (string.Equals(Path.GetFileName(Path.TrimEndingDirectorySeparator(path)), "bin", StringComparison.OrdinalIgnoreCase))
            home = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(path))!;
        if (!System.IO.Directory.Exists(home)) { problem = "does not exist"; return null; }
        home = Path.GetFullPath(home);
        var java = Path.Combine(home, "bin", Exe("java"));
        var javac = Path.Combine(home, "bin", Exe("javac"));
        if (!File.Exists(java)) { problem = "has no bin/java"; return null; }
        if (!File.Exists(javac)) { problem = "is a JRE, not a JDK (no bin/javac)"; return null; }
        var version = ReleaseVersion(Path.Combine(home, "release")) ?? RunVersion(java);
        if (version is not { } major) { problem = "its version could not be read"; return null; }
        problem = "";
        return new JavaRuntime(home, java, javac, major, source);
    }

    /// <summary>JAVA_VERSION from the JDK's release file: "24.0.1" is 24, "1.8.0_x" is 8.</summary>
    internal static int? ReleaseVersion(string releaseFile)
    {
        var props = GhidraInstallation.ReadProperties(releaseFile);
        return props != null && props.TryGetValue("JAVA_VERSION", out var v) ? FeatureVersion(v.Trim('"')) : null;
    }

    internal static int? FeatureVersion(string version)
    {
        var parts = version.Split('.', '_', '-', '+');
        if (!int.TryParse(parts[0], out var first)) return null;
        return first == 1 && parts.Length > 1 && int.TryParse(parts[1], out var second) ? second : first;
    }

    private static int? RunVersion(string java)
    {
        var run = PythonLocator.RunCapture(java, ["-version"], TimeSpan.FromSeconds(15));
        var text = run.Stderr + run.Stdout;
        int q = text.IndexOf('"');
        int q2 = q >= 0 ? text.IndexOf('"', q + 1) : -1;
        return q2 > q ? FeatureVersion(text[(q + 1)..q2]) : null;
    }

    private static string? OnPath(string exe)
    {
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var candidate = Path.Combine(dir.Trim('"'), exe);
                if (File.Exists(candidate)) return candidate;
            }
            catch (ArgumentException) { }
        }
        return null;
    }
}
