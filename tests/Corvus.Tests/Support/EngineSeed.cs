using System.Collections.Concurrent;
using System.Security.Cryptography;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>
/// Engine analyses shared between tests: an input is analysed once per engine build, worker scripts and recipe, and a
/// test starts from a copy of that cache entry in its own cache root. Tests about cold opens keep an empty cache.
/// </summary>
internal static class EngineSeed
{
    private static readonly string Folder = Path.Combine(LeakGuard.SharedTemp, "corvus-test-data", "engine-seed");
    // Raise when the seed layout or the way a seed is made changes, so older seeds are not reused.
    private const int Format = 3;
    // The seed's own record in its cache root: engine, recipe, input path and fingerprint; never copied.
    private const string RecordFile = ".seed";
    private static readonly ConcurrentDictionary<string, string> Builds = new();
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
            var key = $"{engine}-{(recipe == Recipe.Tools ? "" : "nosym-")}{Builds.GetOrAdd(engine, BuildKey)}-{sha[..16]}";
            string seed;
            // a seed that cannot be made leaves the test its cold open
            try { seed = Seeds.GetOrAdd(key, k => new(() => Make(k, input, engine, recipe))).Value; }
            catch (Exception) { continue; }
            foreach (var file in Directory.EnumerateFiles(seed, "*", SearchOption.AllDirectories))
            {
                var name = Path.GetFileName(file);
                if (name is ".owner" or RecordFile || name.EndsWith(".lock", StringComparison.OrdinalIgnoreCase)) continue;
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
        var fingerprint = Task.Run(() => Analyse(Path.Combine(work, "cache"), input, engine, recipe)).GetAwaiter().GetResult();
        // A partial analysis (the open's time ran out) would give every copy a short function list.
        if (Directory.EnumerateFiles(Path.Combine(work, "cache"), "*.partial", SearchOption.AllDirectories).Any())
        {
            Directory.Delete(work, true);
            throw new InvalidOperationException($"the {engine} analysis of {Path.GetFileName(input)} is partial");
        }
        File.WriteAllLines(Path.Combine(work, "cache", RecordFile), [engine, recipe.ToString(), Path.GetFullPath(input), fingerprint]);
        try { Directory.Move(Path.Combine(work, "cache"), dir); }
        catch (IOException) when (Directory.Exists(dir)) { }
        Directory.Delete(work, true);
        return dir;
    }

    /// <summary>Analyses <paramref name="input"/> into <paramref name="cacheRoot"/> and returns its fingerprint.</summary>
    private static async Task<string> Analyse(string cacheRoot, string input, string engine, Recipe recipe)
    {
        if (recipe == Recipe.SymbolsOff)
        {
            using INativeDecompilerProvider provider = engine == "ida"
                ? new IdaProvider(new IdaProviderOptions { CacheRoot = cacheRoot })
                : new Native.Providers.Ghidra.GhidraProvider(new Native.Providers.Ghidra.GhidraProviderOptions { CacheRoot = cacheRoot });
            await using var session = await provider.OpenAsync(input, null, new NativeOpenOptions { Symbols = SymbolMode.Off });
            return Fingerprint(await session.ListFunctionsAsync());
        }
        var options = new ServerOptions { TimeoutSeconds = 600, BackgroundIndexing = false };
        using var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(Path.Combine(Path.GetDirectoryName(cacheRoot)!, "annotations")));
        using var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = cacheRoot }, code, workspace, options);
        workspace.LoadAny(input);
        var opened = await engines.Session(workspace.Read(() => workspace.Natives[0]), engine, null, default);
        return Fingerprint(await opened.ListFunctionsAsync());
    }

    /// <summary>The function count and a hash of the sorted function starts and names.</summary>
    private static string Fingerprint(IReadOnlyList<NativeFunctionInfo> functions)
    {
        var lines = functions.Select(f => $"{f.StartRva:X} {f.Name}").Order(StringComparer.Ordinal);
        var hash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(string.Join('\n', lines)));
        return $"{functions.Count} {Convert.ToHexStringLower(hash)[..16]}";
    }

    /// <summary>
    /// Analyses the inputs of <paramref name="count"/> seeds of this build cold, a different set each day, and compares
    /// their fingerprints; a seed that differs is removed. Returns one line per difference; empty when all matched.
    /// </summary>
    public static IReadOnlyList<string> Validate(int count)
    {
        var day = DateTime.UtcNow.DayOfYear;
        var builds = new[] { "ida", "ghidra" }.Where(Available).Select(e => Builds.GetOrAdd(e, BuildKey)).ToList();
        var seeds = Directory.Exists(Folder)
            ? Directory.EnumerateDirectories(Folder).Where(d => builds.Any(b => d.Contains(b, StringComparison.Ordinal)) && File.Exists(Path.Combine(d, RecordFile)))
                .OrderBy(d => Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes($"{day} {Path.GetFileName(d)}"))), StringComparer.Ordinal)
                .Take(count).ToList()
            : [];
        var differences = new List<string>();
        foreach (var seed in seeds)
        {
            var record = File.ReadAllLines(Path.Combine(seed, RecordFile));
            if (record.Length < 4 || !File.Exists(record[2])) continue;
            var work = Path.Combine(Folder, "validate-" + Environment.ProcessId);
            if (Directory.Exists(work)) Directory.Delete(work, true);
            try
            {
                var cold = Task.Run(() => Analyse(Path.Combine(work, "cache"), record[2], record[0], Enum.Parse<Recipe>(record[1]))).GetAwaiter().GetResult();
                if (cold == record[3]) continue;
                differences.Add($"{Path.GetFileName(seed)} ({Path.GetFileName(record[2])}): seed {record[3]}, cold analysis {cold}");
                Directory.Delete(seed, true);
            }
            finally { if (Directory.Exists(work)) Directory.Delete(work, true); }
        }
        return differences;
    }

    /// <summary>
    /// What changes an engine's analysis: the engine build, the worker scripts embedded in Corvus and the seed format.
    /// Corvus's own code is left out, so a change to it reuses the seeds.
    /// </summary>
    private static string BuildKey(string engine)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(System.Text.Encoding.UTF8.GetBytes($"{Format}\n{EngineBuild(engine)}\n"));
        var corvus = typeof(AnalysisCache).Assembly;
        var prefix = engine == "ida" ? "Corvus.Native.Providers.Ida." : "Corvus.Native.Providers.Ghidra.";
        foreach (var name in corvus.GetManifestResourceNames().Where(n => n.StartsWith(prefix, StringComparison.Ordinal)).Order(StringComparer.Ordinal))
        {
            using var stream = corvus.GetManifestResourceStream(name)!;
            hash.AppendData(System.Text.Encoding.UTF8.GetBytes(name + "\n"));
            hash.AppendData(SHA256.HashData(stream));
        }
        return Convert.ToHexStringLower(hash.GetHashAndReset())[..12];
    }

    /// <summary>The engine install's build: IDA's library digest, or Ghidra's version and revision; its directory when unknown.</summary>
    internal static string EngineBuild(string engine) => engine == "ida"
        ? IdaInstallation.Locate(null, out _, out _)?.EngineDigest() ?? "ida:" + Environment.GetEnvironmentVariable(IdaInstallation.DirectoryVariable)
        : Native.Providers.Ghidra.GhidraInstallation.Locate(null, out _, out _) is { } g ? $"ghidra:{g.Version}:{g.Revision}" : "ghidra:" + Environment.GetEnvironmentVariable(Native.Providers.Ghidra.GhidraOptions.DirectoryVariable);

    /// <summary>Seeds of other builds unused for a day.</summary>
    private static void RemoveOtherBuilds()
    {
        if (!Directory.Exists(Folder)) return;
        foreach (var dir in Directory.EnumerateDirectories(Folder))
        {
            if (Builds.Values.Any(b => dir.Contains(b, StringComparison.Ordinal)) || Directory.GetLastWriteTimeUtc(dir) > DateTime.UtcNow.AddDays(-1)) continue;
            try { Directory.Delete(dir, true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }
}
