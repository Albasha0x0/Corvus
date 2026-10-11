using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;

namespace NetDecompilerMcp.Native.Providers;

/// <summary>How an external tool is started: an executable, or a jar run by the configured Java.</summary>
public enum ExternalToolKind { Executable, Jar }

/// <summary>
/// One external program: the environment variable that names it (a file or its folder), the file names looked for there
/// and on PATH, extra folders probed, the version arguments, and its option strings by operation (placeholders in braces).
/// </summary>
public sealed record ExternalTool(string Id, string Name, string Variable, ExternalToolKind Kind, string[] Files, string[] VersionArguments,
    int MinimumMajorVersion, string Purpose, bool TestOracle, IReadOnlyDictionary<string, string[]> Options)
{
    /// <summary>Folders searched after the variable: before PATH when <see cref="KnownDirectoriesFirst"/>, else after it.</summary>
    public Func<IEnumerable<(string Directory, string Source)>> KnownDirectories { get; init; } = () => [];
    public bool KnownDirectoriesFirst { get; init; }
}

/// <summary>Where a tool was found and how it ran its version probe.</summary>
public sealed record ExternalToolProbe(string Id, string Name, string Purpose, bool Found, string? Path, string? Source, string? Version,
    string? Problem, string Remediation)
{
    public bool Usable => Found && Problem == null;
}

/// <summary>
/// The one table of external programs (engines, device bridge, test oracles), how each is found and run. Children get a
/// minimal environment (<see cref="MinimalEnvironment"/>), never the whole server environment.
/// </summary>
public static partial class ExternalTools
{
    private static Dictionary<string, string[]> Ops(params (string Op, string[] Args)[] ops) => ops.ToDictionary(o => o.Op, o => o.Args, StringComparer.Ordinal);

    private static readonly string Exe = OperatingSystem.IsWindows() ? ".exe" : "";

    public static readonly ExternalTool Java = new("java", "Java (JDK 17+)", "NDM_JAVA", ExternalToolKind.Executable, ["java" + Exe], ["-version"], 17,
        "runs the Java decompiler (decompile_java)", false,
        Ops(("jar", ["-Xss16m", "-jar", "{jar}"])))
    {
        KnownDirectories = () => Environment.GetEnvironmentVariable("JAVA_HOME") is { Length: > 0 } home ? [(System.IO.Path.Combine(home, "bin"), "JAVA_HOME")] : [],
        KnownDirectoriesFirst = true,
    };

    public static readonly ExternalTool JavaDecompiler = new("jadx", "JADX headless server (jadx-headless-mcp fat jar)", "NDM_JAVA_DECOMPILER", ExternalToolKind.Jar,
        ["jadx-headless-mcp*.jar"], [], 0, "Java / Kotlin source for decompile_java", false,
        Ops(("server", ["--threads", "{threads}", "--decompile-timeout-ms", "{timeoutMs}", "--max-source-bytes", "{maxBytes}", "--resources", "none"])));

    public static readonly ExternalTool Adb = new("adb", "Android Debug Bridge (adb)", "NDM_ADB", ExternalToolKind.Executable, ["adb" + Exe], ["version"], 0,
        "the Android device tools", false,
        Ops(("devices", ["devices", "-l"]),
            ("getprop", ["-s", "{serial}", "shell", "getprop"]),
            ("packages", ["-s", "{serial}", "shell", "pm", "list", "packages", "-f", "-U", "-i"]),
            ("user", ["--user", "{user}"]),
            ("dumpsys", ["-s", "{serial}", "shell", "dumpsys", "package", "{package}"]),
            ("path", ["-s", "{serial}", "shell", "pm", "path", "{package}"]),
            ("stat", ["-s", "{serial}", "shell", "stat", "-c", "%F", "{remote}"]),
            ("pull", ["-s", "{serial}", "pull", "{remote}", "{local}"]),
            ("logcat", ["-s", "{serial}", "logcat", "-d", "-v", "threadtime"]),
            ("install", ["-s", "{serial}", "install-multiple"]),
            ("uninstall", ["-s", "{serial}", "uninstall"])))
    {
        KnownDirectories = AndroidSdkDirectories,
    };

    public static readonly ExternalTool Aapt2 = new("aapt2", "aapt2 (test oracle)", "NDM_AAPT2", ExternalToolKind.Executable, ["aapt2" + Exe], ["version"], 0,
        "oracle for the manifest and resource readers in tests", true,
        Ops(("xmltree", ["dump", "xmltree", "--file", "{file}", "{apk}"]), ("resources", ["dump", "resources", "{apk}"])));

    public static readonly ExternalTool ApkSigner = new("apksigner", "apksigner (test oracle)", "NDM_APKSIGNER", ExternalToolKind.Jar, ["apksigner*.jar"], ["--version"], 0,
        "oracle for APK signature verification in tests", true,
        Ops(("verify", ["verify", "--print-certs", "-v", "{apk}"])));

    public static readonly ExternalTool DexDisassembler = new("baksmali", "baksmali (test oracle)", "NDM_DEX_DISASSEMBLER", ExternalToolKind.Jar, ["baksmali*.jar"], ["--version"], 0,
        "oracle for the Dalvik disassembler in tests", true,
        Ops(("disassemble", ["disassemble", "-o", "{out}", "{dex}"])));

    /// <summary>Every external program, in display order.</summary>
    public static readonly IReadOnlyList<ExternalTool> Table = [Java, JavaDecompiler, Adb, Aapt2, ApkSigner, DexDisassembler];

    public static ExternalTool Get(string id) => Table.Single(t => t.Id == id);

    /// <summary>The option strings of <paramref name="op"/> with placeholders filled; an unknown placeholder stays as written.</summary>
    public static List<string> Arguments(ExternalTool tool, string op, params (string Name, string Value)[] values)
    {
        var map = values.ToDictionary(v => "{" + v.Name + "}", v => v.Value, StringComparer.Ordinal);
        return [.. tool.Options[op].Select(a => map.GetValueOrDefault(a, a))];
    }

    private static IEnumerable<(string, string)> AndroidSdkDirectories()
    {
        foreach (var variable in new[] { "ANDROID_HOME", "ANDROID_SDK_ROOT" })
            if (Environment.GetEnvironmentVariable(variable) is { Length: > 0 } sdk) yield return (System.IO.Path.Combine(sdk, "platform-tools"), variable);
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (OperatingSystem.IsWindows() && local.Length > 0) yield return (System.IO.Path.Combine(local, "Android", "Sdk", "platform-tools"), "default SDK location");
        else if (OperatingSystem.IsMacOS() && home.Length > 0) yield return (System.IO.Path.Combine(home, "Library", "Android", "sdk", "platform-tools"), "default SDK location");
        else if (home.Length > 0) yield return (System.IO.Path.Combine(home, "Android", "Sdk", "platform-tools"), "default SDK location");
    }

    /// <summary>The tool's file: the variable (a file, or a folder holding one of <see cref="ExternalTool.Files"/>), known folders, then PATH.</summary>
    public static (string Path, string Source)? Locate(ExternalTool tool)
    {
        if (Environment.GetEnvironmentVariable(tool.Variable) is { Length: > 0 } configured)
        {
            configured = configured.Trim().Trim('"');
            if (File.Exists(configured)) return (System.IO.Path.GetFullPath(configured), tool.Variable);
            if (Directory.Exists(configured) && InDirectory(tool, configured) is { } inside) return (inside, tool.Variable);
            return null; // a variable that names nothing usable is not silently replaced by another copy
        }
        var path = tool.Kind == ExternalToolKind.Executable
            ? (Environment.GetEnvironmentVariable("PATH") ?? "").Split(System.IO.Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries).Select(d => (d.Trim('"'), "PATH"))
            : [];
        var known = tool.KnownDirectories();
        foreach (var (dir, source) in tool.KnownDirectoriesFirst ? known.Concat(path) : path.Concat(known))
            if (InDirectory(tool, dir) is { } found) return (found, source);
        return null;
    }

    private static string? InDirectory(ExternalTool tool, string dir)
    {
        try
        {
            if (!Directory.Exists(dir)) return null;
            foreach (var pattern in tool.Files)
                if (pattern.Contains('*', StringComparison.Ordinal))
                {
                    if (Directory.EnumerateFiles(dir, pattern).Order(StringComparer.Ordinal).LastOrDefault() is { } match) return System.IO.Path.GetFullPath(match);
                }
                else if (File.Exists(System.IO.Path.Combine(dir, pattern))) return System.IO.Path.GetFullPath(System.IO.Path.Combine(dir, pattern));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { }
        return null;
    }

    public static string Remediation(ExternalTool tool) => tool.Kind == ExternalToolKind.Jar
        ? $"set {tool.Variable} to the {tool.Name} jar (or its folder); it runs with {Java.Variable} / JAVA_HOME / PATH java"
        : $"set {tool.Variable} to the {tool.Name} executable (or its folder), or put it on PATH";

    private static readonly ConcurrentDictionary<string, ExternalToolProbe> Probes = new(StringComparer.Ordinal);

    /// <summary>Where the tool is and its version, probed once per file per server process.</summary>
    public static ExternalToolProbe Probe(ExternalTool tool)
    {
        var located = Locate(tool);
        if (located is not { } at)
        {
            var configured = Environment.GetEnvironmentVariable(tool.Variable);
            var why = configured is { Length: > 0 }
                ? $"{tool.Variable} is set to '{configured.Trim()}', which is not {(tool.Kind == ExternalToolKind.Jar ? "a jar or a folder with one" : "the program or a folder with it")}"
                : $"not found ({tool.Variable} is not set{(tool.Kind == ExternalToolKind.Executable ? " and it is not on PATH" : "")})";
            return new(tool.Id, tool.Name, tool.Purpose, false, null, null, null, why, Remediation(tool));
        }
        return Probes.GetOrAdd(tool.Id + "|" + at.Path + "|" + Stamp(at.Path), _ => VersionProbe(tool, at.Path, at.Source));
    }

    private static string Stamp(string path)
    {
        try { return File.GetLastWriteTimeUtc(path).Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return "?"; }
    }

    private static ExternalToolProbe VersionProbe(ExternalTool tool, string path, string source)
    {
        if (tool.VersionArguments.Length == 0) return new(tool.Id, tool.Name, tool.Purpose, true, path, source, VersionFromName(path), null, Remediation(tool));
        var (exe, args) = tool.Kind == ExternalToolKind.Jar
            ? Probe(Java) is { Usable: true, Path: { } java } ? (java, Arguments(Java, "jar", ("jar", path)).Concat(tool.VersionArguments).ToList()) : ((string?)null, (List<string>)[])
            : (path, tool.VersionArguments.ToList());
        if (exe == null) return new(tool.Id, tool.Name, tool.Purpose, true, path, source, null, "no usable Java to run it", $"set {Java.Variable} or JAVA_HOME to a JDK 17+");
        var run = Run(exe, args, TimeSpan.FromSeconds(15), 64 * 1024, CancellationToken.None);
        if (run.StartError != null) return new(tool.Id, tool.Name, tool.Purpose, true, path, source, null, $"cannot be started: {run.StartError}", Remediation(tool));
        if (run.TimedOut) return new(tool.Id, tool.Name, tool.Purpose, true, path, source, null, "its version check did not answer within 15 s", Remediation(tool));
        var version = VersionPattern().Match(run.Text + "\n" + run.Stderr) is { Success: true } m ? m.Value : null;
        string? problem = null;
        if (tool.MinimumMajorVersion > 0)
        {
            var major = version == null ? 0 : int.Parse(version.Split('.')[0], System.Globalization.CultureInfo.InvariantCulture);
            if (major == 1 && version!.Split('.') is [_, var legacy, ..]) major = int.Parse(legacy, System.Globalization.CultureInfo.InvariantCulture); // 1.8 means 8
            if (major < tool.MinimumMajorVersion) problem = $"version {version ?? "unknown"}; {tool.MinimumMajorVersion} or newer is required";
        }
        return new(tool.Id, tool.Name, tool.Purpose, true, path, source, version, problem, Remediation(tool));
    }

    private static string? VersionFromName(string path) => VersionPattern().Match(System.IO.Path.GetFileNameWithoutExtension(path)) is { Success: true } m ? m.Value : null;

    [GeneratedRegex(@"\d+(\.\d+)+")]
    private static partial Regex VersionPattern();

    /// <summary>Variables a child keeps; everything else is removed (credentials and tokens in the server's environment stay out).</summary>
    private static readonly string[] KeptVariables =
    [
        "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "SYSTEMDRIVE", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "LOCALAPPDATA",
        "APPDATA", "LANG", "LC_ALL", "JAVA_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT", "ANDROID_SERIAL", "ANDROID_ADB_SERVER_PORT",
        "ANDROID_ADB_SERVER_ADDRESS",
    ];

    /// <summary>The overrides that reduce the server's environment to <see cref="KeptVariables"/> and ADB_* (null removes), plus <paramref name="extra"/>.</summary>
    public static Dictionary<string, string?> MinimalEnvironment(IReadOnlyDictionary<string, string?>? extra = null)
    {
        var result = new Dictionary<string, string?>(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        foreach (System.Collections.DictionaryEntry e in Environment.GetEnvironmentVariables())
        {
            var name = (string)e.Key;
            bool keep = KeptVariables.Contains(name, StringComparer.OrdinalIgnoreCase) || name.StartsWith("ADB_", StringComparison.OrdinalIgnoreCase);
            if (!keep) result[name] = null;
        }
        foreach (var (k, v) in extra ?? new Dictionary<string, string?>()) result[k] = v;
        return result;
    }

    public sealed record RunResult(int? ExitCode, byte[] Output, string Stderr, bool TimedOut, bool Truncated, string? StartError)
    {
        public string Text => Encoding.UTF8.GetString(Output);
    }

    /// <summary>
    /// Runs a program to completion in its own job with a minimal environment. Stdout is kept up to <paramref name="maxOutputBytes"/>;
    /// past that the tree is stopped and <see cref="RunResult.Truncated"/> set. Cancellation and the timeout stop the tree too.
    /// </summary>
    public static RunResult Run(string exe, IReadOnlyList<string> args, TimeSpan timeout, long maxOutputBytes, CancellationToken ct,
        IReadOnlyDictionary<string, string?>? environment = null, string? workingDirectory = null)
    {
        ChildProcess child;
        try
        {
            child = ChildProcess.Start(new ChildProcessStart(exe, args) { Environment = MinimalEnvironment(environment), WorkingDirectory = workingDirectory });
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return new RunResult(null, [], "", false, false, ex.Message);
        }
        using (child)
        {
            child.StandardInput.Dispose();
            bool truncated = false;
            var stdout = Task.Run(() =>
            {
                var buffer = new MemoryStream();
                var chunk = new byte[64 * 1024];
                try
                {
                    int n;
                    while ((n = child.StandardOutput.Read(chunk, 0, chunk.Length)) > 0)
                    {
                        int keep = (int)Math.Min(n, Math.Max(0, maxOutputBytes - buffer.Length));
                        buffer.Write(chunk, 0, keep);
                        if (keep < n) { truncated = true; child.Kill(); break; }
                    }
                }
                catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
                return buffer.ToArray();
            }, CancellationToken.None);
            var stderr = Task.Run(() =>
            {
                try
                {
                    using var r = new StreamReader(child.StandardError, new UTF8Encoding(false), false, 4096, leaveOpen: true);
                    var text = new StringBuilder();
                    var block = new char[4096];
                    int n;
                    while ((n = r.Read(block, 0, block.Length)) > 0)
                        if (text.Length < 256 * 1024) text.Append(block, 0, n);
                    return text.ToString();
                }
                catch (Exception ex) when (ex is IOException or ObjectDisposedException) { return ""; }
            }, CancellationToken.None);
            int index = Task.WaitAny([child.Exited, Task.Delay(timeout, CancellationToken.None), Task.Delay(Timeout.Infinite, ct)]);
            bool timedOut = index == 1;
            if (index != 0) child.Kill();
            Task.WaitAll([stdout, stderr], TimeSpan.FromSeconds(5));
            ct.ThrowIfCancellationRequested();
            return new RunResult(child.ExitCode, stdout.IsCompletedSuccessfully ? stdout.Result : [], stderr.IsCompletedSuccessfully ? stderr.Result : "",
                timedOut, truncated, null);
        }
    }

    /// <summary>The program and arguments that start <paramref name="path"/>: a jar through Java, else the program itself; null without a usable Java.</summary>
    public static (string Exe, List<string> Args)? Command(ExternalTool tool, string path, IEnumerable<string> args) =>
        tool.Kind == ExternalToolKind.Jar || path.EndsWith(".jar", StringComparison.OrdinalIgnoreCase)
            ? Probe(Java) is { Usable: true, Path: { } java } ? (java, [.. Arguments(Java, "jar", ("jar", path)), .. args]) : null
            : (path, [.. args]);
}
