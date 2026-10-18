using System.Collections.Concurrent;
using System.Security.Cryptography;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>
/// Engine analyses shared between tests: an input is analysed once per engine, engine install and test build, and a test
/// starts from a copy of that cache entry in its own cache root. Tests about cold opens keep an empty cache.
/// </summary>
internal static class EngineSeed
{
    private static readonly string Folder = Path.Combine(LeakGuard.SharedTemp, "corvus-test-data", "engine-seed");
    private static readonly Lazy<string> Build = new(BuildKey);
    private static readonly ConcurrentDictionary<string, Lazy<string>> Seeds = new();

    /// <summary>How the seed is opened: as the tools open it (a server's engine service), or by the provider with symbols off.</summary>
    public enum Recipe { Tools, SymbolsOff }

    /// <summary>
    /// Copies the analysis of <paramref name="input"/> into <paramref name="cacheRoot"/> for each of <paramref name="engines"/>
    /// ("ida", "ghidra"; all when none) that is available and has no entry there yet: a reopened cache keeps its edits.
    /// </summary>
    public static void Copy(string cacheRoot, string input, params string[] engines) => Copy(cacheRoot, input, Recipe.Tools, engines);

    public static void Copy(string cacheRoot, string input, Recipe recipe, params string[] engines)
    {
        string? sha = null;
        foreach (var engine in engines.Length > 0 ? engines : ["ida", "ghidra"])
        {
            if (Directory.Exists(Path.Combine(cacheRoot, engine)) || !Available(engine)) continue;
            sha ??= Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(input)));
            var key = $"{engine}-{(recipe == Recipe.Tools ? "" : "nosym-")}{Build.Value}-{sha[..16]}";
            string seed;
            // a seed that cannot be made leaves the test its cold open
            try { seed = Seeds.GetOrAdd(key, k => new(() => Make(k, input, engine, recipe))).Value; }
            catch (Exception) { continue; }
            foreach (var file in Directory.EnumerateFiles(seed, "*", SearchOption.AllDirectories))
            {
                var name = Path.GetFileName(file);
                if (name == ".owner" || name.EndsWith(".lock", StringComparison.OrdinalIgnoreCase)) continue;
                var target = Path.Combine(cacheRoot, Path.GetRelativePath(seed, file));
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                File.Copy(file, target); // keeps the write time the saved state is checked against
            }
        }
    }

    private static bool Available(string engine) => (engine == "ida" ? new IdaFactAttribute().Skip : new GhidraFactAttribute().Skip) == null;

    /// <summary>The seed's cache root: made in a folder of this process, then moved in place (another process may win).</summary>
    private static string Make(string key, string input, string engine, Recipe recipe)
    {
        var dir = Path.Combine(Folder, key);
        if (Directory.Exists(dir)) return dir;
        RemoveOtherBuilds();
        var work = dir + "-" + Environment.ProcessId;
        if (Directory.Exists(work)) Directory.Delete(work, true);
        // off the test's synchronization context, which the open's continuations would otherwise wait on
        Task.Run(() => Analyse(Path.Combine(work, "cache"), input, engine, recipe)).GetAwaiter().GetResult();
        try { Directory.Move(Path.Combine(work, "cache"), dir); }
        catch (IOException) when (Directory.Exists(dir)) { }
        Directory.Delete(work, true);
        return dir;
    }

    private static async Task Analyse(string cacheRoot, string input, string engine, Recipe recipe)
    {
        if (recipe == Recipe.SymbolsOff)
        {
            using INativeDecompilerProvider provider = engine == "ida"
                ? new IdaProvider(new IdaProviderOptions { CacheRoot = cacheRoot })
                : new Native.Providers.Ghidra.GhidraProvider(new Native.Providers.Ghidra.GhidraProviderOptions { CacheRoot = cacheRoot });
            await using var session = await provider.OpenAsync(input, null, new NativeOpenOptions { Symbols = SymbolMode.Off });
            return;
        }
        var options = new ServerOptions { TimeoutSeconds = 600, BackgroundIndexing = false };
        using var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(Path.Combine(Path.GetDirectoryName(cacheRoot)!, "annotations")));
        using var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = cacheRoot }, code, workspace, options);
        workspace.LoadAny(input);
        await engines.Session(workspace.Read(() => workspace.Natives[0]), engine, null, default);
    }

    /// <summary>The test build and the engine installs, so a rebuilt worker or another engine never reuses a seed.</summary>
    private static string BuildKey()
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(File.ReadAllBytes(typeof(AnalysisCache).Assembly.Location));
        foreach (var variable in new[] { "CORVUS_GHIDRA_DIR", IdaInstallation.DirectoryVariable })
            hash.AppendData(System.Text.Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable(variable) + "\n"));
        return Convert.ToHexStringLower(hash.GetHashAndReset())[..12];
    }

    /// <summary>Seeds of other builds unused for a day.</summary>
    private static void RemoveOtherBuilds()
    {
        if (!Directory.Exists(Folder)) return;
        foreach (var dir in Directory.EnumerateDirectories(Folder))
        {
            if (dir.Contains(Build.Value, StringComparison.Ordinal) || Directory.GetLastWriteTimeUtc(dir) > DateTime.UtcNow.AddDays(-1)) continue;
            try { Directory.Delete(dir, true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }
}
