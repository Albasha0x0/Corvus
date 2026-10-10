using dnlib.DotNet;
using Microsoft.Extensions.Logging;
using DecompilerMetadata = ICSharpCode.Decompiler.Metadata;

namespace NetDecompilerMcp.Core;

/// <summary>
/// Loaded assemblies and reference-resolution state. Access goes through <see cref="Read{T}"/> (shared) or
/// <see cref="Write{T}"/> (exclusive) so concurrent tool calls never observe a half-edited module.
/// </summary>
public sealed class AssemblyWorkspace : IDisposable
{
    private readonly ReaderWriterLockSlim _lock = new(LockRecursionPolicy.SupportsRecursion);
    private readonly List<LoadedAssembly> _assemblies = new();
    private readonly List<LoadedNative> _natives = new();
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

    /// <summary>Raised outside the lock after assemblies are loaded or reloaded.</summary>
    public event Action<IReadOnlyList<LoadedAssembly>>? AssembliesLoaded;

    /// <summary>Raised outside the lock after a native image is loaded or reloaded.</summary>
    public event Action<LoadedNative>? NativeLoaded;

    /// <summary>Raised outside the lock after an assembly is unloaded.</summary>
    public event Action<LoadedAssembly>? AssemblyUnloaded;

    private readonly System.Collections.Concurrent.ConcurrentQueue<string> _notices = new();

    /// <summary>Queues a client notice, prepended to the next tool result.</summary>
    public void Notify(string message) => _notices.Enqueue(message);

    public List<string> DrainNotices()
    {
        var list = new List<string>();
        while (_notices.TryDequeue(out var n)) list.Add(n);
        return list;
    }

    /// <summary>Incremented on every write (load, unload, edit, search path); used to invalidate caches.</summary>
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

    /// <summary>Snapshot of loaded assemblies; consistent only inside Read/Write.</summary>
    public IReadOnlyList<LoadedAssembly> Assemblies => _assemblies.ToArray();

    /// <summary>Snapshot of loaded native images; consistent only inside Read/Write.</summary>
    public IReadOnlyList<LoadedNative> Natives => _natives.ToArray();

    public IReadOnlyList<string> SearchDirectories => _searchDirectories.ToArray();

    public void AddSearchDirectory(string directory)
    {
        var full = Path.GetFullPath(directory);
        if (!Directory.Exists(full))
            throw new ToolError(ErrorCode.NotFound, $"Directory not found: {full}");
        Write(() =>
        {
            if (!_searchDirectories.Contains(full, StringComparer.OrdinalIgnoreCase))
                _searchDirectories.Add(full);
            return 0;
        });
    }

    /// <summary>Returns the existing entry if the same path is already loaded.</summary>
    public LoadedAssembly Load(string path)
    {
        int before = _assemblies.Count;
        var asm = Write(() => LoadCore(path));
        if (_assemblies.Count != before) AssembliesLoaded?.Invoke([asm]);
        RaiseNativeViews();
        return asm;
    }

    /// <summary>
    /// Loads a .NET assembly, or a native PE image when the file has no .NET metadata. Returns the existing entry when
    /// the path is already loaded.
    /// </summary>
    public (LoadedAssembly? Assembly, LoadedNative? Native) LoadAny(string path)
    {
        var full = Path.GetFullPath(path);
        if (Read(() => _natives.FirstOrDefault(n => string.Equals(n.FilePath, full, StringComparison.OrdinalIgnoreCase))) is { } existing)
            return (existing.ManagedView, existing);
        try
        {
            // A mixed-mode (C++/CLI) assembly also gets its native view.
            var asm = Load(full);
            return (asm, Read(() => NativeViewOf(asm)));
        }
        catch (ToolError ex) when (ex.Code == ErrorCode.Unsupported)
        {
            var image = Native.Pe.PeFile.Open(full);
            if (image.IsDotNet) throw;
            int before = _natives.Count;
            var native = Write(() => LoadNativeCore(full, image));
            if (_natives.Count != before) NativeLoaded?.Invoke(native);
            return (null, native);
        }
    }

    private LoadedNative LoadNativeCore(string full, Native.Pe.PeFile image)
    {
        var existing = _natives.FirstOrDefault(n => string.Equals(n.FilePath, full, StringComparison.OrdinalIgnoreCase));
        if (existing != null) return existing;
        var baseId = Path.GetFileName(full);
        var id = baseId;
        for (int n = 2; IdTaken(id); n++) id = $"{baseId}#{n}";
        var native = new LoadedNative(id, full, image);
        _natives.Add(native);
        _logger?.LogInformation("Loaded native image {Id} from {Path}", id, full);
        return native;
    }

    /// <summary>The native view of a mixed-mode assembly (see <see cref="LoadedNative.ManagedView"/>), or null.</summary>
    public LoadedNative? NativeViewOf(LoadedAssembly asm) => _natives.FirstOrDefault(n => n.ManagedView == asm);

    private readonly List<LoadedNative> _newViews = new();

    /// <summary>
    /// A mixed-mode (C++/CLI) assembly is also a native image: its native code gets a view in the native list, id
    /// the file name (the assembly's own id is its assembly name), unloaded and reloaded with the assembly.
    /// </summary>
    private void AttachNativeView(LoadedAssembly asm, byte[] bytes)
    {
        if (!Native.Linking.MixedModeMap.IsMixedMode(asm.Module)) return;
        Native.Pe.PeFile image;
        try { image = Native.Pe.PeFile.FromBytes(bytes, asm.FilePath); }
        catch (ToolError) { return; }
        var baseId = Path.GetFileName(asm.FilePath);
        var id = baseId;
        for (int n = 2; IdTaken(id); n++) id = $"{baseId}#{n}";
        var view = new LoadedNative(id, asm.FilePath, image) { ManagedView = asm };
        _natives.Add(view);
        lock (_newViews) _newViews.Add(view);
    }

    private void RemoveNativeViews(LoadedAssembly asm)
    {
        foreach (var view in _natives.Where(n => n.ManagedView == asm).ToList())
        {
            _natives.Remove(view);
            view.Release();
        }
    }

    /// <summary>Raises <see cref="NativeLoaded"/> for native views attached since the last call (outside the lock).</summary>
    private void RaiseNativeViews()
    {
        List<LoadedNative> views;
        lock (_newViews)
        {
            views = [.. _newViews];
            _newViews.Clear();
        }
        foreach (var view in views) NativeLoaded?.Invoke(view);
    }

    private bool IdTaken(string id) =>
        _assemblies.Any(a => a.Id.Equals(id, StringComparison.OrdinalIgnoreCase)) || _natives.Any(n => n.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    /// <summary>The loaded native image matching an id, file name or full path; null when none matches.</summary>
    public LoadedNative? FindNative(string identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier)) return null;
        var id = identifier.Trim();
        return _natives.FirstOrDefault(n => n.Id.Equals(id, StringComparison.OrdinalIgnoreCase))
               ?? _natives.FirstOrDefault(n => Path.GetFileName(n.FilePath).Equals(id, StringComparison.OrdinalIgnoreCase)
                                               || n.FilePath.Equals(SafeFullPath(id), StringComparison.OrdinalIgnoreCase))
               // A mixed-mode assembly's id names its native view too.
               ?? _natives.FirstOrDefault(n => n.ManagedView?.Id.Equals(id, StringComparison.OrdinalIgnoreCase) == true);
    }

    /// <summary><see cref="FindNative"/>, with a typed error when nothing matches.</summary>
    public LoadedNative GetNative(string identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier))
            throw new ToolError(ErrorCode.InvalidArgument, "Image identifier is empty.");
        if (FindNative(identifier) is { } native) return native;
        if (_assemblies.Any(a => a.Id.Equals(identifier.Trim(), StringComparison.OrdinalIgnoreCase)))
            throw new ToolError(ErrorCode.Unsupported, $"'{identifier}' is a .NET assembly, not a native image.",
                "use the .NET tools (decompile_member, get_il, find_references) for it");
        if (_natives.Count == 0)
            throw new ToolError(ErrorCode.NotLoaded, "No native images are loaded.", "load_assembly with the path of a native .exe or .dll");
        throw new ToolError(ErrorCode.NotFound, $"No loaded native image matches '{identifier}'. Loaded: {string.Join(", ", _natives.Select(n => n.Id))}");
    }

    public void UnloadNative(LoadedNative native) => Write(() =>
    {
        if (!_natives.Remove(native)) throw Gone(native.Id);
        native.Release();
        return 0;
    });

    private static ToolError Gone(string id) =>
        new(ErrorCode.Conflict, $"{id} was unloaded or reloaded by another call in the meantime.", "list_assemblies shows what is loaded now; repeat the call");

    /// <summary>Re-reads a native image from disk, discarding its analysis state.</summary>
    public LoadedNative ReloadNative(LoadedNative native)
    {
        var image = Native.Pe.PeFile.Open(native.FilePath);
        var fresh = Write(() =>
        {
            int index = _natives.IndexOf(native);
            if (index < 0) throw Gone(native.Id);
            _natives.RemoveAt(index);
            native.Release();
            var reloaded = new LoadedNative(native.Id, native.FilePath, image) { ManagedView = native.ManagedView };
            _natives.Insert(index, reloaded);
            return reloaded;
        });
        NativeLoaded?.Invoke(fresh);
        return fresh;
    }

    /// <summary>The longest file or directory name Windows, Linux and macOS file systems accept.</summary>
    private const int MaxFileNameLength = 255;

    private LoadedAssembly LoadCore(string path)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full))
        {
            // Windows raises PathTooLongException for these; Linux and macOS only report the file missing.
            if (full.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(part => part.Length > MaxFileNameLength))
                throw new ToolError(ErrorCode.InvalidArgument, "a path is too long.", "Pass a shorter path.");
            throw new ToolError(ErrorCode.NotFound, $"File not found: {full}");
        }

        var existing = _assemblies.FirstOrDefault(a => string.Equals(a.FilePath, full, StringComparison.OrdinalIgnoreCase));
        if (existing != null)
            return existing;

        byte[] bytes = File.ReadAllBytes(full);
        ModuleDefMD module;
        try
        {
            module = ModuleDefMD.Load(bytes, DnlibContext);
            // Avoids linear type lookups. Reads the NestedClass table, so corrupt metadata fails here.
            module.EnableTypeDefFindCache = true;
        }
        catch (Exception ex)
        {
            // Malformed metadata: say where (the survey reads the structures directly, without dnlib).
            var issues = MetadataSurvey.Survey(bytes);
            if (issues.Count > 0)
                throw new ToolError(ErrorCode.MalformedInput, $"Not a loadable .NET assembly: {full} ({ex.Message}). Metadata issues: " +
                    string.Join("; ", issues.Take(8).Select(i => $"{i.Code} at {i.Location}{(i.FileOffset != null ? $", file offset {i.FileOffset}" : "")}: {i.Detail}")),
                    "the metadata is damaged beyond what can be read leniently; repair the named structures or load another copy");
            throw new ToolError(ErrorCode.Unsupported, $"Not a loadable .NET assembly: {full} ({ex.Message})");
        }
        module.Location = full;

        var asm = new LoadedAssembly(MakeUniqueId(module, full), full, bytes, module);
        _assemblies.Add(asm);
        AttachNativeView(asm, bytes);

        var dir = Path.GetDirectoryName(full)!;
        if (!_searchDirectories.Contains(dir, StringComparer.OrdinalIgnoreCase))
            _searchDirectories.Add(dir);
        _logger?.LogInformation("Loaded {Id} from {Path}", asm.Id, full);
        return asm;
    }

    public sealed record LoadReport(List<LoadedAssembly> Loaded, List<(string Path, string Error)> Skipped);

    /// <summary>Loads every .dll/.exe in a directory; files that fail to load are reported as skipped.</summary>
    public LoadReport LoadDirectory(string directory, bool recursive, Action<int, int, string>? onProgress = null)
    {
        var full = Path.GetFullPath(directory);
        if (!Directory.Exists(full))
            throw new ToolError(ErrorCode.NotFound, $"Directory not found: {full}");

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
        RaiseNativeViews();
        return result;
    }

    public void Unload(LoadedAssembly asm)
    {
        Write(() =>
        {
            // A concurrent unload or reload already replaced it.
            if (!_assemblies.Remove(asm)) throw Gone(asm.Id);
            RemoveNativeViews(asm);
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
        RaiseNativeViews();
        return fresh;
    }

    private LoadedAssembly ReloadCore(LoadedAssembly asm) => Write(() =>
    {
        int index = _assemblies.IndexOf(asm);
        if (index < 0) throw Gone(asm.Id);
        _assemblies.Remove(asm);
        RemoveNativeViews(asm);
        asm.Dispose();
        var fresh = LoadCore(asm.FilePath);
        // Keep the original position for a stable listing order.
        _assemblies.Remove(fresh);
        _assemblies.Insert(Math.Max(0, Math.Min(index, _assemblies.Count)), fresh);
        return fresh;
    });

    /// <summary>Finds an assembly by id, file name, full path or simple name (case-insensitive).</summary>
    public LoadedAssembly Get(string identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier))
            throw new ToolError(ErrorCode.InvalidArgument, "Assembly identifier is empty.");
        var all = _assemblies;
        var id = identifier.Trim();
        if (all.Count == 0)
            throw FindNative(id) is { } only
                ? new ToolError(ErrorCode.Unsupported, $"'{identifier}' is a native image ({only.Image.MachineName}), not a .NET assembly.",
                    "use the native tools: get_pe_info, list_imports, list_exports, list_functions, disassemble")
                : new ToolError(ErrorCode.NotLoaded, "No assemblies are loaded. Call load_assembly first.");

        var matches = all.Where(a => a.Id.Equals(id, StringComparison.OrdinalIgnoreCase)).ToList();
        if (matches.Count == 0)
            matches = all.Where(a => Path.GetFileName(a.FilePath).Equals(id, StringComparison.OrdinalIgnoreCase)
                                     || a.FilePath.Equals(SafeFullPath(id), StringComparison.OrdinalIgnoreCase)).ToList();
        if (matches.Count == 0)
            matches = all.Where(a => a.AssemblyName.Equals(id, StringComparison.OrdinalIgnoreCase)).ToList();

        if (matches.Count == 1)
            return matches[0];
        if (matches.Count == 0 && FindNative(id) is { } native)
            throw new ToolError(ErrorCode.Unsupported, $"'{identifier}' is a native image ({native.Image.MachineName}), not a .NET assembly.",
                "use the native tools: get_pe_info, list_imports, list_exports, list_functions, disassemble");
        if (matches.Count > 1)
            throw new ToolError(ErrorCode.Ambiguous, $"'{identifier}' matches several loaded assemblies: {string.Join(", ", matches.Select(m => $"{m.Id} ({m.FilePath})"))}. Use the id.");
        throw new ToolError(ErrorCode.NotFound, $"No loaded assembly matches '{identifier}'. Loaded: {string.Join(", ", all.Select(a => a.Id))}");
    }

    /// <summary>Resolves an optional assembly parameter; null or empty means all loaded assemblies.</summary>
    public IReadOnlyList<LoadedAssembly> Scope(string? identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier))
        {
            if (_assemblies.Count == 0)
                throw new ToolError(ErrorCode.NotLoaded, "No assemblies are loaded. Call load_assembly first.");
            return _assemblies.ToArray();
        }
        return [Get(identifier)];
    }

    /// <summary>
    /// The loaded assembly a reference binds to. Candidates outside the requester's folder must match a requested
    /// public key token (so an Il2Cpp dummy mscorlib never replaces the real one). Ranked by same folder, exact
    /// version, exact token, then load order. Null when nothing qualifies.
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
            // A different major version from another folder is left to the caller's last-resort lookup.
            if (sameMajor && !sameDir && version != null && !Frameworks.IsWildcard(version)
                && a.Module.Assembly?.Version is { } have && !Frameworks.IsWildcard(have) && have.Major != version.Major)
                continue;
            // A .NET Framework requester never binds to a modern .NET facade of the same name.
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

    internal DecompilerMetadata.IAssemblyResolver CreateDecompilerResolver(LoadedAssembly main) => new DecompilerResolver(this, main);

    private string MakeUniqueId(ModuleDefMD module, string path)
    {
        var baseId = module.Assembly?.Name?.String;
        if (string.IsNullOrWhiteSpace(baseId))
            baseId = Path.GetFileNameWithoutExtension(path);
        var id = baseId;
        for (int n = 2; IdTaken(id); n++)
            id = $"{baseId}#{n}";
        return id;
    }

    private static string SafeFullPath(string p)
    {
        try { return Path.GetFullPath(p); }
        catch { return p; }
    }

    /// <summary>
    /// Searches the requester's folder, the search directories, then installed framework directories. A file of
    /// another major version is returned only when nothing else matches.
    /// </summary>
    public string? FindAssemblyFile(string simpleName, string? requesterPath = null, byte[]? publicKeyToken = null, Version? version = null,
        bool netFramework = false)
    {
        var first = requesterPath == null ? null : SafeDirectory(requesterPath);
        var dirs = (first != null ? [first] : Array.Empty<string>()).Concat(_searchDirectories).Concat(Frameworks.DirectoriesFor(version, netFramework))
            .Distinct(StringComparer.OrdinalIgnoreCase);
        string? otherMajor = null;
        foreach (var dir in dirs)
            foreach (var ext in new[] { ".dll", ".exe", ".winmd" })
            {
                var candidate = Path.Combine(dir, simpleName + ext);
                if (!File.Exists(candidate)) continue;
                bool sameDir = string.Equals(dir, first, StringComparison.OrdinalIgnoreCase);
                // Outside the requester's folder a requested public key token must match.
                if (publicKeyToken is { Length: > 0 } && !sameDir && !TokenMatches(candidate, publicKeyToken))
                    continue;
                if (!sameDir && ((version != null && !Frameworks.IsWildcard(version) && FileVersion(candidate) is { } have
                                  && !Frameworks.IsWildcard(have) && have.Major != version.Major)
                                 // Modern .NET runtime folders only hold facades for .NET Framework requesters.
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

    /// <summary>Resolved reference source: a loaded assembly, a file, an embedded (Costura) image, or a generated stub.</summary>
    public sealed record ReferenceTarget(LoadedAssembly? Loaded, string? File, byte[]? Bytes, string? EmbeddedIn, string? Stub = null)
    {
        public string Describe() => Loaded != null ? $"loaded as {Loaded.Id}"
            : Stub != null ? $"not found; {Stub}"
            : EmbeddedIn != null ? $"embedded in {EmbeddedIn}" : "resolvable from search path";
    }

    private readonly Dictionary<string, ReferenceTarget?> _stubs = new(StringComparer.OrdinalIgnoreCase);
    private int _stubGeneration = -1;

    /// <summary>
    /// Stub for an unresolvable reference, synthesized from its usage in loaded assemblies. Cached per name until
    /// the workspace generation changes.
    /// </summary>
    private ReferenceTarget? StubFor(string name, Version? version)
    {
        if (!ReferenceStubs.CanStub(name)) return null;
        // One builder at a time: building one stub can require another, and two threads building each other's
        // dependency would wait forever. The lock is re-entrant for the building thread.
        lock (_stubs)
        {
            if (_stubGeneration != Generation)
            {
                _stubs.Clear();
                _stubGeneration = Generation;
            }
            // Re-entrant resolution of the stub being built (e.g. via generic constraints) returns null.
            _building ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (_building.Contains(name)) return null;
            _building.Add(name);
            try
            {
                if (!_stubs.TryGetValue(name, out var target))
                {
                    target = ReferenceStubs.Build(name, version, Assemblies) is { } stub
                        ? new ReferenceTarget(null, null, stub.Image, null, $"stub built from what the loaded code uses ({stub.Types} types, {stub.Members} members)")
                        : null;
                    _stubs[name] = target;
                }
                return target;
            }
            finally { _building.Remove(name); }
        }
    }

    [ThreadStatic] private static HashSet<string>? _building;

    private readonly System.Runtime.CompilerServices.ConditionalWeakTable<ModuleDef, LoadedAssembly> _referenceViews = new();

    /// <summary>
    /// Wraps a reference-only module as a <see cref="LoadedAssembly"/> so tools can name its members.
    /// Not added to the workspace.
    /// </summary>
    internal LoadedAssembly ReferenceView(ModuleDefMD module) => _referenceViews.GetValue(module, m =>
    {
        byte[] bytes = [];
        try { if (File.Exists(m.Location)) bytes = File.ReadAllBytes(m.Location); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return new LoadedAssembly($"{m.Assembly?.Name ?? m.Name} (reference)", string.IsNullOrEmpty(m.Location) ? m.Name : m.Location, bytes, (ModuleDefMD)m);
    });

    /// <summary>
    /// Resolves a reference in order: framework files, loaded assemblies, files on disk, Costura-embedded images,
    /// NuGet packages, installed app packages, any loaded assembly of that name, then a generated stub.
    /// </summary>
    public ReferenceTarget? LocateReference(string name, Version? version, byte[]? token, string? requesterPath, bool netFramework, string? requesterFramework = null)
    {
        // .NET Framework requesters bind framework assemblies to .NET Framework itself, not to modern .NET facades.
        if (netFramework && Frameworks.NetFrameworkFile(name) is { } netfx && (token is not { Length: > 0 } || TokenMatches(netfx, token))
            && FrameworkUnlessLocal(netfx) is { } fx)
            return fx;
        // netstandard binds to the .NET Standard reference assembly, not a runtime facade.
        if (string.Equals(name, "netstandard", StringComparison.OrdinalIgnoreCase) && Frameworks.NetStandardFile(version) is { } ns
            && FrameworkUnlessLocal(ns) is { } standard)
            return standard;
        // Windows Runtime contracts resolve from Windows SDK metadata.
        if (Frameworks.WindowsMetadataFile(name, version) is { } winmd && FindReference(name, version, token, requesterPath, sameMajor: true) == null)
            return new(null, winmd, null, null);
        if (FindReference(name, version, token, requesterPath, sameMajor: true, netFramework) is { } loaded) return new(loaded, null, null, null);
        if (FindAssemblyFile(name, requesterPath, token, version, netFramework) is { } file)
        {
            // Prefer the NuGet package for the requester's TFM over a newer shared-framework copy.
            if (Frameworks.NetCoreMajor(requesterFramework) is { } targetMajor && Frameworks.SharedFrameworkMajor(file) is { } fileMajor
                && fileMajor > targetMajor && Frameworks.SharedFrameworkOf(name, targetMajor) != "Microsoft.NETCore.App"
                && Frameworks.NuGetFile(name, version, netFramework, requesterFramework) is { } fitting)
                return new(null, fitting, null, null);
            // A major-version mismatch, or a modern runtime copy for a .NET Framework requester, ranks below
            // embedded images and matching NuGet packages.
            bool exact = (version == null || Frameworks.IsWildcard(version) || FileVersion(file) is not { } v || Frameworks.IsWildcard(v) || v.Major == version.Major)
                         && !(netFramework && Frameworks.SharedFrameworkMajor(file) != null);
            if (exact) return new(null, file, null, null);
            if (FindEmbedded(name, token) is { } embeddedFirst) return embeddedFirst;
            if (Frameworks.NuGetFile(name, version, netFramework, requesterFramework) is { } packageFirst
                && (token is not { Length: > 0 } || TokenMatches(packageFirst, token)))
                return new(null, packageFirst, null, null);
            return new(null, file, null, null);
        }
        if (FindEmbedded(name, token) is { } embedded) return embedded;
        if (Frameworks.NuGetFile(name, version, netFramework, requesterFramework) is { } package && (token is not { Length: > 0 } || TokenMatches(package, token)))
            return new(null, package, null, null);
        // Windows Runtime component from an installed app package.
        if (Frameworks.InstalledPackageMetadata(name) is { } packaged)
            return new(null, packaged, null, null);
        if (FindReference(name, version, token, requesterPath) is { } any) return new(any, null, null, null);
        return StubFor(name, version);

        // A copy shipped in the requester's folder takes precedence over the framework file.
        ReferenceTarget? FrameworkUnlessLocal(string frameworkFile)
        {
            var requesterDir = requesterPath == null ? null : SafeDirectory(requesterPath);
            var local = FindReference(name, version, token, requesterPath, sameMajor: true, netFramework);
            return local == null || !string.Equals(SafeDirectory(local.FilePath), requesterDir, StringComparison.OrdinalIgnoreCase)
                ? new(null, frameworkFile, null, null)
                : null;
        }
    }

    private readonly System.Runtime.CompilerServices.ConditionalWeakTable<LoadedAssembly, EmbeddedIndex> _embedded = new();

    private sealed record EmbeddedIndex(int Version, Dictionary<string, byte[]> Assemblies);

    /// <summary>Finds a Costura-embedded assembly in a loaded assembly; decompressed in memory and indexed per edit version.</summary>
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
                catch (Exception) { }
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
        catch { return false; }
    }

    /// <summary>dnlib resolver backed by <see cref="LocateReference"/>; non-loaded targets are cached as reference-only modules.</summary>
    private sealed class DnlibResolver(AssemblyWorkspace ws) : dnlib.DotNet.IAssemblyResolver
    {
        // Resolution probes the file system; a scan over every call site asks for the same few references over and
        // over, unresolvable ones included. Results are kept for one workspace generation (loads, unloads, searches).
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, AssemblyDef?> _cache = new();
        private int _cacheGeneration = -1;

        public AssemblyDef? Resolve(IAssembly assembly, ModuleDef sourceModule)
        {
            var name = assembly.Name?.String;
            if (string.IsNullOrEmpty(name))
                return null;
            int generation = ws.Generation;
            if (_cacheGeneration != generation)
            {
                _cache.Clear();
                _cacheGeneration = generation;
            }
            var key = string.Join("|", name, assembly.Version, Convert.ToHexString(assembly.PublicKeyOrToken?.Token?.Data ?? []),
                sourceModule?.Location is { } location ? SafeDirectory(location) : "", sourceModule == null ? "" : Frameworks.TargetFrameworkOf(sourceModule));
            return _cache.GetOrAdd(key, _ => ResolveUncached(name, assembly, sourceModule));
        }

        private AssemblyDef? ResolveUncached(string name, IAssembly assembly, ModuleDef? sourceModule)
        {
            var requester = sourceModule?.Location;
            var target = ws.LocateReference(name, assembly.Version, assembly.PublicKeyOrToken?.Token?.Data, requester,
                sourceModule != null && Frameworks.TargetsNetFramework(sourceModule), sourceModule == null ? null : Frameworks.TargetFrameworkOf(sourceModule));
            if (target == null) return null;
            if (target.Loaded != null)
                return target.Loaded.Module.Assembly;

            // Keyed by source: file path, or host!name for embedded images and stubs.
            var key = target.File ?? $"{target.EmbeddedIn ?? "stub"}!{name}";
            lock (ws._referenceModules)
            {
                if (!ws._referenceModules.TryGetValue(key, out var module))
                {
                    try
                    {
                        module = ModuleDefMD.Load(target.Bytes ?? File.ReadAllBytes(target.File!), ws.DnlibContext);
                        Services.MetadataUtil.MarkReferenceOnly(module);
                        // Location drives where this module's own references resolve; embedded images use the requester's folder.
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

    /// <summary>ICSharpCode resolver backed by <see cref="LocateReference"/>, falling back to UniversalAssemblyResolver.</summary>
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
                    catch { }
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
                Frameworks.TargetsNetFramework(_main.Module), Frameworks.TargetFrameworkOf(_main.Module));
            if (target?.Loaded != null)
                return target.Loaded.GetPEFile();

            var cacheKey = SafeDirectory(_main.FilePath) + "|" + reference.FullName; // resolution depends on the requester's folder
            lock (_ws._externalDecompilerRefs)
            {
                if (_ws._externalDecompilerRefs.TryGetValue(cacheKey, out var cached))
                    return cached;
            }
            DecompilerMetadata.MetadataFile? file = null;
            // The fallback resolver matches by name only, so the folder/version/token-aware target goes first.
            if (target is { File: not null } or { Bytes: not null })
            {
                try
                {
                    var bytes = target.Bytes ?? File.ReadAllBytes(target.File!);
                    file = new DecompilerMetadata.PEFile(target.File ?? $"{target.EmbeddedIn ?? "stub"}!{reference.Name}.dll", new MemoryStream(bytes, writable: false),
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
        // Cancels background code index builds and closes engine sessions.
        foreach (var n in _natives)
            n.Release();
        _natives.Clear();
        _lock.Dispose();
    }
}
