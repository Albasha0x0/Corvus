using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Corvus.Core;

namespace Corvus.Native.Providers.Ghidra;

/// <summary>The two worker jars: the boot jar on the JVM class path and the worker jar added to Ghidra's class loader.</summary>
public sealed record WorkerJars(string Boot, string Worker);

/// <summary>
/// Builds the Ghidra worker from its embedded Java sources with the user's JDK, against the user's Ghidra, on first
/// use. The jars are kept per Ghidra version and source hash, so no binary ships with the server and any Ghidra whose
/// API compiles is accepted; a compile error makes the provider unavailable with javac's message.
/// </summary>
public static class WorkerBuild
{
    public const string ResourcePrefix = "Corvus.Native.Providers.Ghidra.worker.";
    private const string BootClassFile = "ndm/ghidra/Boot.class";
    private static readonly SemaphoreSlim Gate = new(1, 1);

    public static IReadOnlyList<(string Name, byte[] Bytes)> EmbeddedSources() =>
        EmbeddedScript.Names(ResourcePrefix).Select(n => (n[ResourcePrefix.Length..], EmbeddedScript.Read(n))).ToList();

    /// <summary>First 12 hex digits of the SHA-256 over the sources' names and bytes.</summary>
    public static string SourceHash(IEnumerable<(string Name, byte[] Bytes)> sources)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var (name, bytes) in sources.OrderBy(s => s.Name, StringComparer.Ordinal))
        {
            hash.AppendData(Encoding.UTF8.GetBytes(name + "\n" + bytes.Length + "\n"));
            hash.AppendData(bytes);
        }
        return Convert.ToHexStringLower(hash.GetHashAndReset())[..12];
    }

    /// <summary>The jars for this Ghidra under <paramref name="workersRoot"/>, compiled when missing.</summary>
    public static Task<WorkerJars> EnsureAsync(GhidraInstallation ghidra, JavaRuntime java, string workersRoot, CancellationToken cancellationToken) =>
        EnsureAsync(java, ghidra.CompileClasspath(), EmbeddedSources(), Path.Combine(workersRoot, $"{ghidra.Version}-{SourceHash(EmbeddedSources())}"), cancellationToken);

    internal static async Task<WorkerJars> EnsureAsync(JavaRuntime java, IReadOnlyList<string> classpath, IReadOnlyList<(string Name, byte[] Bytes)> sources,
        string directory, CancellationToken cancellationToken)
    {
        var jars = new WorkerJars(Path.Combine(directory, "ndm-ghidra-boot.jar"), Path.Combine(directory, "ndm-ghidra-worker.jar"));
        if (File.Exists(jars.Boot) && File.Exists(jars.Worker)) return jars;
        await Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(directory);
            using var processLock = await LockAsync(Path.Combine(directory, ".build.lock"), cancellationToken).ConfigureAwait(false);
            if (File.Exists(jars.Boot) && File.Exists(jars.Worker)) return jars;
            await Task.Run(() => Build(java, classpath, sources, directory, jars), cancellationToken).ConfigureAwait(false);
            return jars;
        }
        finally { Gate.Release(); }
    }

    /// <summary>Another server process may be building the same directory.</summary>
    private static async Task<FileStream> LockAsync(string path, CancellationToken cancellationToken)
    {
        var until = DateTime.UtcNow + TimeSpan.FromMinutes(5);
        while (true)
        {
            try
            {
                return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose);
            }
            catch (IOException) when (DateTime.UtcNow < until)
            {
                await Task.Delay(250, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static void Build(JavaRuntime java, IReadOnlyList<string> classpath, IReadOnlyList<(string Name, byte[] Bytes)> sources, string directory, WorkerJars jars)
    {
        var work = Path.Combine(directory, "build-" + Guid.NewGuid().ToString("N")[..8]);
        try
        {
            var src = Path.Combine(work, "src");
            var classes = Path.Combine(work, "classes");
            Directory.CreateDirectory(src);
            Directory.CreateDirectory(classes);
            var files = new List<string>();
            foreach (var (name, bytes) in sources)
            {
                var file = Path.Combine(src, name);
                File.WriteAllBytes(file, bytes);
                files.Add(file);
            }
            // An argument file: the class path of a Ghidra install is far longer than a command line allows.
            var argFile = Path.Combine(work, "javac.args");
            var lines = new List<string> { "--release 21", "-nowarn", "-encoding UTF-8", "-d " + Quote(classes) };
            if (classpath.Count > 0) lines.Add("-cp " + Quote(string.Join(Path.PathSeparator, classpath)));
            lines.AddRange(files.Select(Quote));
            File.WriteAllLines(argFile, lines);
            var run = PythonLocator.RunCapture(java.Javac, ["@" + argFile], TimeSpan.FromMinutes(5));
            if (run.StartError != null || run.TimedOut || run.ExitCode != 0)
            {
                var detail = run.StartError ?? (run.TimedOut ? "javac timed out" : string.Join("\n", (run.Stderr + run.Stdout).Split('\n', StringSplitOptions.RemoveEmptyEntries).Take(15)));
                throw new ToolError(ErrorCode.ProviderUnavailable, $"The Ghidra worker did not compile with {java.Javac} against {directory}: {detail}",
                    $"Use a Ghidra release this server supports (12.0 or newer) and a JDK {java.Major}+; set {GhidraOptions.DirectoryVariable} and {GhidraOptions.JavaVariable}.");
            }
            WriteJar(jars.Boot + ".tmp", classes, f => f == BootClassFile);
            WriteJar(jars.Worker + ".tmp", classes, f => f != BootClassFile);
            File.Move(jars.Worker + ".tmp", jars.Worker, overwrite: true);
            File.Move(jars.Boot + ".tmp", jars.Boot, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.IoError, $"Building the Ghidra worker in {directory} failed: {ex.Message}",
                $"Check that the analysis cache is writable ({AnalysisCache.RootVariable} selects another).");
        }
        finally
        {
            try { Directory.Delete(work, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    /// <summary>javac argument files take double-quoted strings with backslash escapes; forward slashes avoid them.</summary>
    private static string Quote(string path) => "\"" + path.Replace('\\', '/') + "\"";

    private static void WriteJar(string path, string classes, Func<string, bool> include)
    {
        File.Delete(path); // left by an interrupted build
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        var manifest = zip.CreateEntry("META-INF/MANIFEST.MF");
        using (var w = new StreamWriter(manifest.Open(), new UTF8Encoding(false)))
            w.Write("Manifest-Version: 1.0\r\nCreated-By: NetDecompilerMcp\r\n\r\n");
        foreach (var file in Directory.EnumerateFiles(classes, "*.class", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            var name = Path.GetRelativePath(classes, file).Replace('\\', '/');
            if (include(name)) zip.CreateEntryFromFile(file, name, CompressionLevel.Fastest);
        }
    }
}
