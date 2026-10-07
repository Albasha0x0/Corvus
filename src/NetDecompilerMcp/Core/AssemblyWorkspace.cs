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
        }
        catch (Exception ex)
        {
            throw new ToolError($"Not a loadable .NET assembly: {full} ({ex.Message})");
        }
        module.Location = full;
        module.EnableTypeDefFindCache = true; // dnlib resolves type names constantly; without this every lookup is a linear scan

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

    public LoadedAssembly? FindByAssemblyName(string simpleName) =>
        _assemblies.FirstOrDefault(a => a.AssemblyName.Equals(simpleName, StringComparison.OrdinalIgnoreCase));

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
    public string? FindAssemblyFile(string simpleName)
    {
        foreach (var dir in _searchDirectories.Concat(FrameworkDirectories.Value))
            foreach (var ext in new[] { ".dll", ".exe", ".winmd" })
            {
                var candidate = Path.Combine(dir, simpleName + ext);
                if (File.Exists(candidate))
                    return candidate;
            }
        return null;
    }

    /// <summary>
    /// Framework assembly directories: this process's runtime directory when its assemblies are on disk, otherwise
    /// (self-contained single-file builds bundle them inside the exe) the newest installed shared frameworks.
    /// </summary>
    private static readonly Lazy<IReadOnlyList<string>> FrameworkDirectories = new(() =>
    {
        var dirs = new List<string>();
        var runtimeDir = System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory();
        if (!string.IsNullOrEmpty(runtimeDir) && File.Exists(Path.Combine(runtimeDir, "System.Runtime.dll")))
            dirs.Add(runtimeDir);

        var roots = new[]
        {
            Environment.GetEnvironmentVariable("DOTNET_ROOT"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".dotnet"),
            "/usr/share/dotnet", "/usr/lib/dotnet", "/usr/local/share/dotnet", "/opt/homebrew/opt/dotnet/libexec",
        };
        foreach (var framework in new[] { "Microsoft.NETCore.App", "Microsoft.WindowsDesktop.App", "Microsoft.AspNetCore.App" })
            foreach (var root in roots.Where(r => !string.IsNullOrEmpty(r)).Distinct())
            {
                var shared = Path.Combine(root!, "shared", framework);
                if (!Directory.Exists(shared)) continue;
                var newest = Directory.EnumerateDirectories(shared)
                    .Select(d => (Dir: d, Version: Version.TryParse(Path.GetFileName(d).Split('-')[0], out var v) ? v : null))
                    .Where(x => x.Version != null)
                    .OrderByDescending(x => x.Version)
                    .FirstOrDefault();
                if (newest.Dir != null && !dirs.Contains(newest.Dir, StringComparer.OrdinalIgnoreCase))
                    dirs.Add(newest.Dir);
                break;
            }
        return dirs;
    });

    /// <summary>dnlib resolution: loaded assemblies first, then reference-only modules from the search directories.</summary>
    private sealed class DnlibResolver(AssemblyWorkspace ws) : dnlib.DotNet.IAssemblyResolver
    {
        public AssemblyDef? Resolve(IAssembly assembly, ModuleDef sourceModule)
        {
            var name = assembly.Name?.String;
            if (string.IsNullOrEmpty(name))
                return null;
            var loaded = ws.FindByAssemblyName(name);
            if (loaded != null)
                return loaded.Module.Assembly;

            lock (ws._referenceModules)
            {
                if (!ws._referenceModules.TryGetValue(name, out var module))
                {
                    module = null;
                    var path = ws.FindAssemblyFile(name);
                    if (path != null)
                    {
                        try
                        {
                            module = ModuleDefMD.Load(File.ReadAllBytes(path), ws.DnlibContext);
                            module.EnableTypeDefFindCache = true;
                        }
                        catch { module = null; }
                    }
                    ws._referenceModules[name] = module;
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
            var loaded = _ws.FindByAssemblyName(reference.Name);
            if (loaded != null)
                return loaded.GetPEFile();

            lock (_ws._externalDecompilerRefs)
            {
                if (_ws._externalDecompilerRefs.TryGetValue(reference.FullName, out var cached))
                    return cached;
            }
            DecompilerMetadata.MetadataFile? file;
            try { file = Fallback.Resolve(reference); }
            catch { file = null; }
            lock (_ws._externalDecompilerRefs)
                _ws._externalDecompilerRefs[reference.FullName] = file;
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
