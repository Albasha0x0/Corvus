using dnlib.DotNet;
using Microsoft.Extensions.Logging;
using DecompilerMetadata = ICSharpCode.Decompiler.Metadata;

namespace NetDecompilerMcp.Core;

/// <summary>
/// The set of loaded assemblies plus reference-resolution state. All access goes through
/// <see cref="Read{T}"/> (shared) or <see cref="Write{T}"/> (exclusive: load/unload/edit),
/// so concurrent tool calls never observe a half-edited module.
/// </summary>
public sealed class AssemblyWorkspace : IDisposable
{
    private readonly ReaderWriterLockSlim _lock = new(LockRecursionPolicy.SupportsRecursion);
    private readonly List<LoadedAssembly> _assemblies = new();
    private readonly List<string> _searchDirectories = new();
    private readonly Dictionary<string, ModuleDefMD?> _referenceModules = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DecompilerMetadata.MetadataFile?> _externalDecompilerRefs = new(StringComparer.OrdinalIgnoreCase);
    private readonly ILogger<AssemblyWorkspace>? _logger;

    public AssemblyWorkspace(ServerOptions? options = null, ILogger<AssemblyWorkspace>? logger = null)
    {
        _logger = logger;
        var resolver = new DnlibResolver(this);
        DnlibContext = new ModuleContext(resolver, new Resolver(resolver));
        foreach (var dir in options?.SearchDirectories ?? [])
            AddSearchDirectory(dir);
    }

    /// <summary>Raised (outside the lock) after assemblies were loaded or reloaded.</summary>
    public event Action<IReadOnlyList<LoadedAssembly>>? AssembliesLoaded;

    /// <summary>Raised (outside the lock) after an assembly was unloaded.</summary>
    public event Action<LoadedAssembly>? AssemblyUnloaded;

    private readonly System.Collections.Concurrent.ConcurrentQueue<string> _notices = new();

    /// <summary>Queues a message for the client (e.g. "reloaded from disk"); shown with the next tool result.</summary>
    public void Notify(string message) => _notices.Enqueue(message);

    /// <summary>Takes all pending notices.</summary>
    public List<string> DrainNotices()
    {
        var list = new List<string>();
        while (_notices.TryDequeue(out var n)) list.Add(n);
        return list;
    }

    /// <summary>Bumped on any change (load, unload, edit, search path) to invalidate caches.</summary>
    public int Generation { get; private set; }

    internal ModuleContext DnlibContext { get; }

    public T Read<T>(Func<T> action)
    {
        _lock.EnterReadLock();
        try { return action(); }
        finally { _lock.ExitReadLock(); }
    }

    public T Write<T>(Func<T> action)
    {
        _lock.EnterWriteLock();
        try { return action(); }
        finally
        {
            Generation++;
            lock (_referenceModules) _referenceModules.Clear();
            lock (_externalDecompilerRefs) _externalDecompilerRefs.Clear();
            _lock.ExitWriteLock();
        }
    }

    /// <summary>Snapshot of loaded assemblies. Call inside Read/Write for consistency.</summary>
    public IReadOnlyList<LoadedAssembly> Assemblies => _assemblies.ToArray();

    public IReadOnlyList<string> SearchDirectories => _searchDirectories.ToArray();

    public void AddSearchDirectory(string directory)
    {
        var full = Path.GetFullPath(directory);
        if (!Directory.Exists(full))
            throw new ToolError($"Directory not found: {full}");
        Write(() =>
        {
            if (!_searchDirectories.Contains(full, StringComparer.OrdinalIgnoreCase))
                _searchDirectories.Add(full);
            return 0;
        });
    }

    /// <summary>Loads a single assembly file. Returns the existing entry if the same path is already loaded.</summary>
    public LoadedAssembly Load(string path)
    {
        int before = _assemblies.Count;
        var asm = Write(() => LoadCore(path));
        if (_assemblies.Count != before) AssembliesLoaded?.Invoke([asm]);
        return asm;
    }

    private LoadedAssembly LoadCore(string path)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full))
            throw new ToolError($"File not found: {full}");

        var existing = _assemblies.FirstOrDefault(a => string.Equals(a.FilePath, full, StringComparison.OrdinalIgnoreCase));
        if (existing != null)
            return existing;

        byte[] bytes = File.ReadAllBytes(full);
        ModuleDefMD module;
        try
        {
            module = ModuleDefMD.Load(bytes, DnlibContext);
            // dnlib resolves type names constantly; without this every lookup is a linear scan.
            // It reads the NestedClass table, so corrupt metadata fails here rather than in ModuleDefMD.Load.
            module.EnableTypeDefFindCache = true;
        }
        catch (Exception ex)
        {
            throw new ToolError($"Not a loadable .NET assembly: {full} ({ex.Message})");
        }
        module.Location = full;

        var asm = new LoadedAssembly(MakeUniqueId(module, full), full, bytes, module);
        _assemblies.Add(asm);

        var dir = Path.GetDirectoryName(full)!;
        if (!_searchDirectories.Contains(dir, StringComparer.OrdinalIgnoreCase))
            _searchDirectories.Add(dir);
        _logger?.LogInformation("Loaded {Id} from {Path}", asm.Id, full);
        return asm;
    }

    public sealed record LoadReport(List<LoadedAssembly> Loaded, List<(string Path, string Error)> Skipped);

    /// <summary>Loads every .dll/.exe in a directory. Non-.NET files are skipped, not fatal.</summary>
    public LoadReport LoadDirectory(string directory, bool recursive, Action<int, int, string>? onProgress = null)
    {
        var full = Path.GetFullPath(directory);
        if (!Directory.Exists(full))
            throw new ToolError($"Directory not found: {full}");

        var files = Directory.EnumerateFiles(full, "*.*", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly)
            .Where(f => f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var result = Write(() =>
        {
            var report = new LoadReport(new(), new());
            for (int i = 0; i < files.Count; i++)
            {
                var f = files[i];
                onProgress?.Invoke(i, files.Count, f);
                try { report.Loaded.Add(LoadCore(f)); }
                catch (Exception ex) { report.Skipped.Add((f, ex.Message)); }
            }
            return report;
        });
        if (result.Loaded.Count > 0) AssembliesLoaded?.Invoke(result.Loaded);
        return result;
    }

    public void Unload(LoadedAssembly asm)
    {
        Write(() =>
        {
            _assemblies.Remove(asm);
            asm.Dispose();
            return 0;
        });
        AssemblyUnloaded?.Invoke(asm);
    }

    /// <summary>Re-reads the file from disk, discarding in-memory edits.</summary>
    public LoadedAssembly Reload(LoadedAssembly asm)
    {
        var fresh = ReloadCore(asm);
        AssemblyUnloaded?.Invoke(asm);
        AssembliesLoaded?.Invoke([fresh]);
        return fresh;
    }

    private LoadedAssembly ReloadCore(LoadedAssembly asm) => Write(() =>
    {
        int index = _assemblies.IndexOf(asm);
        _assemblies.Remove(asm);
        asm.Dispose();
        var fresh = LoadCore(asm.FilePath);
        // Keep the original position (and therefore a stable listing order).
        _assemblies.Remove(fresh);
        _assemblies.Insert(Math.Max(0, Math.Min(index, _assemblies.Count)), fresh);
        return fresh;
    });

    /// <summary>
    /// Finds an assembly by id, simple name, file name or full path (case-insensitive).
    /// </summary>
    public LoadedAssembly Get(string identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier))
            throw new ToolError("Assembly identifier is empty.");
        var all = _assemblies;
        if (all.Count == 0)
            throw new ToolError("No assemblies are loaded. Call load_assembly first.");

        var id = identifier.Trim();
        var matches = all.Where(a => a.Id.Equals(id, StringComparison.OrdinalIgnoreCase)).ToList();
        if (matches.Count == 0)
            matches = all.Where(a => Path.GetFileName(a.FilePath).Equals(id, StringComparison.OrdinalIgnoreCase)
                                     || a.FilePath.Equals(SafeFullPath(id), StringComparison.OrdinalIgnoreCase)).ToList();
        if (matches.Count == 0)
            matches = all.Where(a => a.AssemblyName.Equals(id, StringComparison.OrdinalIgnoreCase)).ToList();

        if (matches.Count == 1)
            return matches[0];
        if (matches.Count > 1)
            throw new ToolError($"'{identifier}' matches several loaded assemblies: {string.Join(", ", matches.Select(m => $"{m.Id} ({m.FilePath})"))}. Use the id.");
        throw new ToolError($"No loaded assembly matches '{identifier}'. Loaded: {string.Join(", ", all.Select(a => a.Id))}");
    }

    /// <summary>Resolves the optional assembly parameter: null/empty means "all loaded assemblies".</summary>
    public IReadOnlyList<LoadedAssembly> Scope(string? identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier))
        {
            if (_assemblies.Count == 0)
                throw new ToolError("No assemblies are loaded. Call load_assembly first.");
            return _assemblies.ToArray();
        }
        return [Get(identifier)];
    }

    /// <summary>
    /// The loaded assembly a reference binds to, when several builds or runtime families are loaded side by side.
    /// Candidates have the referenced simple name. One from another folder than the referencing assembly must also
    /// carry the requested public key token (when one is requested): an Il2Cpp dummy "mscorlib" never stands in for
    /// the real one. Among the rest: the requester's own folder first, then the exact version, then the exact token,
    /// then load order. Null when nothing qualifies (the caller then resolves from files).
    /// </summary>
    public LoadedAssembly? FindReference(string name, Version? version, byte[]? publicKeyToken, string? requesterPath, bool sameMajor = false,
        bool netFramework = false)
    {
        var requesterDir = requesterPath == null ? null : SafeDirectory(requesterPath);
        bool tokenRequested = publicKeyToken is { Length: > 0 };
        LoadedAssembly? best = null;
        int bestScore = -1;
        foreach (var a in _assemblies)
        {
            if (!a.AssemblyName.Equals(name, StringComparison.OrdinalIgnoreCase)) continue;
            bool sameDir = requesterDir != null && string.Equals(SafeDirectory(a.FilePath), requesterDir, StringComparison.OrdinalIgnoreCase);
            var token = a.Module.Assembly?.PublicKeyToken?.Data;
            bool tokenMatches = tokenRequested && token is { Length: > 0 } && token.AsSpan().SequenceEqual(publicKeyToken);
            if (!sameDir && tokenRequested && !tokenMatches) continue;
            // another folder's build of another major version (System.Runtime 10.0 for a 6.0 reference): only as a last resort
            if (sameMajor && !sameDir && version != null && !Frameworks.IsWildcard(version)
                && a.Module.Assembly?.Version is { } have && !Frameworks.IsWildcard(have) && have.Major != version.Major)
                continue;
            // a .NET Framework app is not read against a modern .NET facade of the same name (mscorlib 4.0 of .NET 10)
            if (sameMajor && netFramework && !sameDir && Frameworks.IsModernNet(a.Module))
                continue;
            int score = (sameDir ? 4 : 0) + (version != null && a.Module.Assembly?.Version == version ? 2 : 0) + (tokenMatches ? 1 : 0);
            if (score > bestScore) { best = a; bestScore = score; }
        }
        return best;
    }

    private static string? SafeDirectory(string path)
    {
        try { return Path.GetDirectoryName(Path.GetFullPath(path)); }
        catch { return null; }
    }

    public LoadedAssembly? FindByPath(string path) =>
        _assemblies.FirstOrDefault(a => string.Equals(a.FilePath, path, StringComparison.OrdinalIgnoreCase));

    public LoadedAssembly? FindByModule(ModuleDef? module) =>
        module == null ? null : _assemblies.FirstOrDefault(a => ReferenceEquals(a.Module, module));

    /// <summary>Creates a reference resolver for decompiling <paramref name="main"/>.</summary>
    internal DecompilerMetadata.IAssemblyResolver CreateDecompilerResolver(LoadedAssembly main) => new DecompilerResolver(this, main);

    private string MakeUniqueId(ModuleDefMD module, string path)
    {
        var baseId = module.Assembly?.Name?.String;
        if (string.IsNullOrWhiteSpace(baseId))
            baseId = Path.GetFileNameWithoutExtension(path);
        var id = baseId;
        for (int n = 2; _assemblies.Any(a => a.Id.Equals(id, StringComparison.OrdinalIgnoreCase)); n++)
            id = $"{baseId}#{n}";
        return id;
    }

    private static string SafeFullPath(string p)
    {
        try { return Path.GetFullPath(p); }
        catch { return p; }
    }

    /// <summary>
    /// Looks in the search directories, then in the installed .NET framework directories as a last resort
    /// (resolves System.Runtime / System.Private.CoreLib for modern .NET targets).
    /// </summary>
    public string? FindAssemblyFile(string simpleName, string? requesterPath = null, byte[]? publicKeyToken = null, Version? version = null,
        bool netFramework = false)
    {
        var first = requesterPath == null ? null : SafeDirectory(requesterPath); // the referencing assembly's own folder first
        var dirs = (first != null ? [first] : Array.Empty<string>()).Concat(_searchDirectories).Concat(Frameworks.DirectoriesFor(version, netFramework))
            .Distinct(StringComparer.OrdinalIgnoreCase);
        string? otherMajor = null; // a file of another major version, used when nothing better exists
        foreach (var dir in dirs)
            foreach (var ext in new[] { ".dll", ".exe", ".winmd" })
            {
                var candidate = Path.Combine(dir, simpleName + ext);
                if (!File.Exists(candidate)) continue;
                bool sameDir = string.Equals(dir, first, StringComparison.OrdinalIgnoreCase);
                // outside the requester's folder, a requested public key token must match (as for loaded assemblies)
                if (publicKeyToken is { Length: > 0 } && !sameDir && !TokenMatches(candidate, publicKeyToken))
                    continue;
                if (!sameDir && ((version != null && !Frameworks.IsWildcard(version) && FileVersion(candidate) is { } have
                                  && !Frameworks.IsWildcard(have) && have.Major != version.Major)
                                 // a .NET Framework app is not read against a modern .NET runtime folder's facades
                                 || (netFramework && File.Exists(Path.Combine(dir, "System.Private.CoreLib.dll")))))
                {
                    otherMajor ??= candidate;
                    continue;
                }
                return candidate;
            }
        return otherMajor;
    }

    private static Version? FileVersion(string file)
    {
        try { return System.Reflection.AssemblyName.GetAssemblyName(file).Version; }
        catch { return null; }
    }

    /// <summary>Where a reference comes from: a loaded assembly, a file, or an assembly embedded in a loaded one (Costura).</summary>
    public sealed record ReferenceTarget(LoadedAssembly? Loaded, string? File, byte[]? Bytes, string? EmbeddedIn)
    {
        public string Describe() => Loaded != null ? $"loaded as {Loaded.Id}" : EmbeddedIn != null ? $"embedded in {EmbeddedIn}" : "resolvable from search path";
    }

    /// <summary>
    /// Resolves a reference: a loaded assembly (same folder, or the same major version elsewhere); else a file (the
    /// requester's folder, the search directories, then the installed framework of the requested version —
    /// <paramref name="netFramework"/> for .NET Framework apps); else an assembly embedded in a loaded one (Costura);
    /// else any loaded assembly of that name. Null when nothing matches.
    /// </summary>
    public ReferenceTarget? LocateReference(string name, Version? version, byte[]? token, string? requesterPath, bool netFramework)
    {
        // a .NET Framework app reads framework assemblies from .NET Framework itself, never from a loaded modern .NET
        // facade of the same name and version (mscorlib 4.0, System.ServiceModel 4.0 of a .NET 10 app folder)
        if (netFramework && Frameworks.NetFrameworkFile(name) is { } netfx && (token is not { Length: > 0 } || TokenMatches(netfx, token)))
        {
            var requesterDir = requesterPath == null ? null : SafeDirectory(requesterPath);
            var local = FindReference(name, version, token, requesterPath, sameMajor: true, netFramework);
            if (local == null || !string.Equals(SafeDirectory(local.FilePath), requesterDir, StringComparison.OrdinalIgnoreCase))
                return new(null, netfx, null, null); // only the app's own folder overrides it
        }
        if (FindReference(name, version, token, requesterPath, sameMajor: true, netFramework) is { } loaded) return new(loaded, null, null, null);
        if (FindAssemblyFile(name, requesterPath, token, version, netFramework) is { } file)
        {
            // a file of another major version loses to an assembly embedded next to the app
            bool exact = version == null || Frameworks.IsWildcard(version) || FileVersion(file) is not { } v || Frameworks.IsWildcard(v) || v.Major == version.Major;
            if (exact || FindEmbedded(name, token) is not { } embeddedFirst) return new(null, file, null, null);
            return embeddedFirst;
        }
        if (FindEmbedded(name, token) is { } embedded) return embedded;
        return FindReference(name, version, token, requesterPath) is { } any ? new(any, null, null, null) : null;
    }

    private readonly System.Runtime.CompilerServices.ConditionalWeakTable<LoadedAssembly, EmbeddedIndex> _embedded = new();

    private sealed record EmbeddedIndex(int Version, Dictionary<string, byte[]> Assemblies);

    /// <summary>An assembly of this name embedded (Costura) in a loaded assembly, decompressed in memory.</summary>
    private ReferenceTarget? FindEmbedded(string name, byte[]? token)
    {
        foreach (var host in _assemblies)
        {
            if (!HasCostura(host)) continue;
            if (!_embedded.TryGetValue(host, out var index) || index.Version != host.Version)
            {
                var map = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
                try
                {
                    var contents = Services.Analysis.Containers.Open(host.OriginalBytes, host.FilePath, Services.Analysis.AnalysisLimits.Default, default);
                    foreach (var item in contents.Items)
                        if (Services.Analysis.Blob.Identify(item.Bytes) == ".NET assembly")
                            map[Path.GetFileNameWithoutExtension(item.Name)] = item.Bytes;
                }
                catch (Exception) { /* unreadable resources: nothing embedded */ }
                index = new EmbeddedIndex(host.Version, map);
                _embedded.AddOrUpdate(host, index);
            }
            if (!index.Assemblies.TryGetValue(name, out var bytes)) continue;
            if (token is { Length: > 0 })
            {
                try
                {
                    using var m = ModuleDefMD.Load(bytes);
                    if (m.Assembly?.PublicKeyToken?.Data is not { } t || !t.AsSpan().SequenceEqual(token)) continue;
                }
                catch (Exception) { continue; }
            }
            return new ReferenceTarget(null, null, bytes, host.Id);
        }
        return null;
    }

    private static bool HasCostura(LoadedAssembly a)
    {
        try { return a.Module.Resources.Any(r => r.Name.String.StartsWith("costura.", StringComparison.OrdinalIgnoreCase)); }
        catch (Exception) { return false; }
    }

    private static bool TokenMatches(string file, byte[] token)
    {
        try { return System.Reflection.AssemblyName.GetAssemblyName(file).GetPublicKeyToken() is { } t && t.AsSpan().SequenceEqual(token); }
        catch { return false; } // not an assembly / unreadable: not a match for a token-qualified reference
    }

    /// <summary>dnlib resolution: loaded assemblies first, then reference-only modules from the search directories.</summary>
    private sealed class DnlibResolver(AssemblyWorkspace ws) : dnlib.DotNet.IAssemblyResolver
    {
        public AssemblyDef? Resolve(IAssembly assembly, ModuleDef sourceModule)
        {
            var name = assembly.Name?.String;
            if (string.IsNullOrEmpty(name))
                return null;
            var requester = sourceModule?.Location;
            var target = ws.LocateReference(name, assembly.Version, assembly.PublicKeyOrToken?.Token?.Data, requester,
                sourceModule != null && Frameworks.TargetsNetFramework(sourceModule));
            if (target == null) return null;
            if (target.Loaded != null)
                return target.Loaded.Module.Assembly;

            // reference-only modules from files or embedded images, keyed by where they came from
            var key = target.File ?? $"{target.EmbeddedIn}!{name}";
            lock (ws._referenceModules)
            {
                if (!ws._referenceModules.TryGetValue(key, out var module))
                {
                    try
                    {
                        module = ModuleDefMD.Load(target.Bytes ?? File.ReadAllBytes(target.File!), ws.DnlibContext);
                        // its own references then resolve from its folder too (an embedded one: from its host's)
                        module.Location = target.File ?? (requester != null ? Path.Combine(SafeDirectory(requester) ?? "", name + ".dll") : name + ".dll");
                        module.EnableTypeDefFindCache = true;
                    }
                    catch { module = null; }
                    ws._referenceModules[key] = module;
                }
                return module?.Assembly;
            }
        }
    }

    /// <summary>ICSharpCode resolution: loaded assemblies first, then the standard resolver (search dirs, GAC, runtime packs).</summary>
    private sealed class DecompilerResolver : DecompilerMetadata.IAssemblyResolver
    {
        private readonly AssemblyWorkspace _ws;
        private readonly LoadedAssembly _main;
        private DecompilerMetadata.UniversalAssemblyResolver? _fallback;

        public DecompilerResolver(AssemblyWorkspace ws, LoadedAssembly main)
        {
            _ws = ws;
            _main = main;
        }

        private DecompilerMetadata.UniversalAssemblyResolver Fallback
        {
            get
            {
                if (_fallback == null)
                {
                    string? tfm = null;
                    try { tfm = DecompilerMetadata.DotNetCorePathFinderExtensions.DetectTargetFrameworkId(_main.GetPEFile()); }
                    catch { /* unknown framework is fine */ }
                    var r = new DecompilerMetadata.UniversalAssemblyResolver(_main.FilePath, false, tfm, null,
                        System.Reflection.PortableExecutable.PEStreamOptions.PrefetchEntireImage,
                        System.Reflection.Metadata.MetadataReaderOptions.None);
                    foreach (var dir in _ws._searchDirectories)
                        r.AddSearchDirectory(dir);
                    _fallback = r;
                }
                return _fallback;
            }
        }

        public DecompilerMetadata.MetadataFile? Resolve(DecompilerMetadata.IAssemblyReference reference)
        {
            var target = _ws.LocateReference(reference.Name, reference.Version, reference.PublicKeyToken, _main.FilePath,
                Frameworks.TargetsNetFramework(_main.Module));
            if (target?.Loaded != null)
                return target.Loaded.GetPEFile();

            var cacheKey = SafeDirectory(_main.FilePath) + "|" + reference.FullName; // per requester folder
            lock (_ws._externalDecompilerRefs)
            {
                if (_ws._externalDecompilerRefs.TryGetValue(cacheKey, out var cached))
                    return cached;
            }
            DecompilerMetadata.MetadataFile? file = null;
            // our folder-, version- and token-aware lookup first (the standard resolver matches by name only)
            if (target is { File: not null } or { Bytes: not null })
            {
                try
                {
                    var bytes = target.Bytes ?? File.ReadAllBytes(target.File!);
                    file = new DecompilerMetadata.PEFile(target.File ?? $"{target.EmbeddedIn}!{reference.Name}.dll", new MemoryStream(bytes, writable: false),
                        System.Reflection.PortableExecutable.PEStreamOptions.PrefetchEntireImage);
                }
                catch { file = null; }
            }
            if (file == null)
            {
                try { file = Fallback.Resolve(reference); }
                catch { file = null; }
            }
            lock (_ws._externalDecompilerRefs)
                _ws._externalDecompilerRefs[cacheKey] = file;
            return file;
        }

        public DecompilerMetadata.MetadataFile? ResolveModule(DecompilerMetadata.MetadataFile mainModule, string moduleName)
        {
            try { return Fallback.ResolveModule(mainModule, moduleName); }
            catch { return null; }
        }

        public Task<DecompilerMetadata.MetadataFile?> ResolveAsync(DecompilerMetadata.IAssemblyReference reference) =>
            Task.FromResult(Resolve(reference));

        public Task<DecompilerMetadata.MetadataFile?> ResolveModuleAsync(DecompilerMetadata.MetadataFile mainModule, string moduleName) =>
            Task.FromResult(ResolveModule(mainModule, moduleName));

        public IDisposable BeginSnapshot() => NoopDisposable.Instance;
    }

    private sealed class NoopDisposable : IDisposable
    {
        public static readonly NoopDisposable Instance = new();
        public void Dispose() { }
    }

    public void Dispose()
    {
        foreach (var a in _assemblies)
            a.Dispose();
        _assemblies.Clear();
        _lock.Dispose();
    }
}
