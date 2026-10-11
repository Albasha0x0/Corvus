using System.Text.Json;

namespace Corvus.Native.Providers.Ida;

/// <summary>
/// An IDA install usable as a library: the directory, the idalib binary and the <c>idapro</c> Python package
/// shipped under idalib/python. Located from CORVUS_IDA_DIR, else from Paths.ida-install-dir in ida-config.json
/// (in IDAUSR or the per-user IDA directory), which IDA writes on first start.
/// </summary>
public sealed record IdaInstallation(string Directory, string LibraryPath, string PythonPackageDirectory, string Source)
{
    public const string DirectoryVariable = "CORVUS_IDA_DIR";

    public static string LibraryFileName =>
        OperatingSystem.IsWindows() ? "idalib.dll" : OperatingSystem.IsMacOS() ? "libidalib.dylib" : "libidalib.so";

    /// <summary>The IDA kernel idalib loads; its bytes decide the database format and the analysis.</summary>
    public static string KernelFileName =>
        OperatingSystem.IsWindows() ? "ida.dll" : OperatingSystem.IsMacOS() ? "libida.dylib" : "libida.so";

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> Digests = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Identity of this IDA build for cache keys: the idalib file version and a SHA-256 prefix over idalib and the kernel,
    /// e.g. "9.3.26.0213-1a2b3c4d5e6f". Computed once per install directory.
    /// </summary>
    public string EngineDigest() => Digests.GetOrAdd(Directory, _ =>
    {
        using var hash = System.Security.Cryptography.IncrementalHash.CreateHash(System.Security.Cryptography.HashAlgorithmName.SHA256);
        foreach (var file in new[] { LibraryPath, Path.Combine(Directory, KernelFileName) })
        {
            try
            {
                using var s = File.OpenRead(file);
                var buffer = new byte[1 << 16];
                for (int n; (n = s.Read(buffer)) > 0;) hash.AppendData(buffer, 0, n);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { hash.AppendData(System.Text.Encoding.UTF8.GetBytes(file)); }
        }
        var version = System.Diagnostics.FileVersionInfo.GetVersionInfo(LibraryPath).FileVersion is { Length: > 0 } v
            ? new string(v.Where(c => char.IsAsciiLetterOrDigit(c) || c == '.').ToArray()) + "-" : "";
        return version + Convert.ToHexStringLower(hash.GetHashAndReset())[..12];
    });

    /// <summary>Per-user IDA directories, in IDA's search order: IDAUSR entries, then the default.</summary>
    public static IReadOnlyList<string> UserDirectories()
    {
        var dirs = new List<string>();
        if (Environment.GetEnvironmentVariable("IDAUSR") is { Length: > 0 } usr)
            dirs.AddRange(usr.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        dirs.Add(OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Hex-Rays", "IDA Pro")
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".idapro"));
        return dirs;
    }

    /// <summary>
    /// Finds and validates the install. <paramref name="explicitDirectory"/> wins over the environment and IDA's config.
    /// Returns null with <paramref name="reason"/> and <paramref name="remediation"/> set when unusable.
    /// </summary>
    public static IdaInstallation? Locate(string? explicitDirectory, out string reason, out string remediation)
    {
        string? dir = null, source = null;
        if (!string.IsNullOrWhiteSpace(explicitDirectory)) (dir, source) = (explicitDirectory, "configured");
        else if (Environment.GetEnvironmentVariable(DirectoryVariable) is { Length: > 0 } env) (dir, source) = (env, DirectoryVariable);
        else
        {
            foreach (var userDir in UserDirectories())
            {
                var config = Path.Combine(userDir, "ida-config.json");
                if (ReadInstallDir(config) is { } fromConfig) { (dir, source) = (fromConfig, config); break; }
            }
        }
        if (dir == null)
        {
            reason = "IDA Pro was not found: CORVUS_IDA_DIR is not set and no ida-config.json names an install directory.";
            remediation = "Install IDA Pro 9 or newer and start it once (it records its directory in ida-config.json), or set CORVUS_IDA_DIR to the IDA install directory.";
            return null;
        }
        dir = dir.Trim().Trim('"');
        if (!System.IO.Directory.Exists(dir))
        {
            reason = $"The IDA directory {dir} (from {source}) does not exist.";
            remediation = "Set CORVUS_IDA_DIR to the IDA install directory, or start the installed IDA once so it updates ida-config.json.";
            return null;
        }
        var lib = Path.Combine(dir, LibraryFileName);
        var package = Path.Combine(dir, "idalib", "python");
        if (!File.Exists(lib) || !File.Exists(Path.Combine(package, "idapro", "__init__.py")))
        {
            reason = $"{dir} (from {source}) has no idalib ({LibraryFileName} and idalib/python/idapro); IDA Pro 9 or newer is required.";
            remediation = "Point CORVUS_IDA_DIR at an IDA Pro 9+ install; IDA Home/Free editions do not ship idalib.";
            return null;
        }
        reason = remediation = "";
        return new IdaInstallation(Path.GetFullPath(dir), lib, package, source!);
    }

    private static string? ReadInstallDir(string configPath)
    {
        try
        {
            if (!File.Exists(configPath)) return null;
            using var doc = JsonDocument.Parse(File.ReadAllBytes(configPath), new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
            return doc.RootElement.ValueKind == JsonValueKind.Object
                && doc.RootElement.TryGetProperty("Paths", out var paths) && paths.ValueKind == JsonValueKind.Object
                && paths.TryGetProperty("ida-install-dir", out var d) && d.ValueKind == JsonValueKind.String
                && d.GetString() is { Length: > 0 } s ? s : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    /// <summary>The interpreter IDA itself is configured to use (idapyswitch writes Python3TargetDLL), as a directory.</summary>
    public static string? ConfiguredPythonDirectory()
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Hex-Rays\IDA");
            return key?.GetValue("Python3TargetDLL") is string dll && dll.Length > 0 ? Path.GetDirectoryName(dll) : null;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
