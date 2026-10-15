using dnlib.DotNet;
using Microsoft.Extensions.Logging;
using DecompilerMetadata = ICSharpCode.Decompiler.Metadata;

namespace Corvus.Core;

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

    /// <summary>One tool call's flow: what its lock waits stop on, and its name and start for lock diagnostics.</summary>
    public sealed class CallScope(CancellationToken token, string? tool) : IDisposable
    {
        public CancellationToken Token => _ended ? default : token;
        public string? Tool { get; } = tool;
        public long Started { get; } = System.Diagnostics.Stopwatch.GetTimestamp();

        /// <summary>The lock holders a wait of this call gave up on (the call was cancelled or reached its deadline), else null.</summary>
        public string? BlockedBy { get; internal set; }

        private volatile bool _ended;
        public void Dispose() => _ended = true;
    }

    private static readonly AsyncLocal<CallScope?> Call = new();

    /// <summary>
    /// Until the scope is disposed, lock waits on this async flow (one tool call) end when <paramref name="cancellationToken"/>
    /// is cancelled. Background work the call started inherits the flow; after the call it waits uncancellably again.
    /// <paramref name="tool"/> names the call to calls waiting for a lock it holds.
    /// </summary>
    public static CallScope CancelWaitsWith(CancellationToken cancellationToken, string? tool = null) =>
        Call.Value = new CallScope(cancellationToken, tool);

    internal static CancellationToken CallToken => Call.Value?.Token ?? default;

    /// <summary>
    /// <c>lock</c> for a monitor whose holder can run long: a call waiting for it stops when the call is cancelled (see
    /// <see cref="CancelWaitsWith"/>). Use as <c>using (AssemblyWorkspace.Lock(gate)) ...</c>; re-entrant like <c>lock</c>.
    /// </summary>
    public static MonitorExit Lock(object gate)
    {
        var ct = CallToken;
        if (!ct.CanBeCanceled) Monitor.Enter(gate);
        else
            while (!Monitor.TryEnter(gate, WaitSliceMs))
                ct.ThrowIfCancellationRequested();
        return new MonitorExit(gate);
    }

    public readonly struct MonitorExit(object gate) : IDisposable
    {
        public void Dispose() => Monitor.Exit(gate);
    }

    /// <summary>Threads queued for the exclusive and the shared lock (tests order lock waits with these).</summary>
    internal (int Writers, int Readers) Waiting => (_lock.WaitingWriteCount, _lock.WaitingReadCount);

    /// <summary>The calling thread holds the shared or the exclusive lock.</summary>
    internal bool LockHeld => _lock.IsReadLockHeld || _lock.IsWriteLockHeld;

    /// <summary>Waits in slices of this length when the wait can be cancelled.</summary>
    private const int WaitSliceMs = 50;

    /// <summary>A thread holding or waiting for the lock, for diagnostics; Depth counts recursive holds.</summary>
    private sealed class LockUser(string? tool, long since, bool write)
    {
        public readonly string? Tool = tool;
        public readonly long Since = since;
        public readonly bool Write = write;
        public int Depth;
    }

    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, LockUser> _holders = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, LockUser> _waiters = new();

    /// <summary>A lock holder or waiter: the tool (null: background work), exclusive or shared, and seconds since its call started.</summary>
    public sealed record LockEntry(string? Tool, bool Write, double Seconds, bool Waiting)
    {
        public override string ToString() =>
            $"{Tool ?? "background work"} ({(Write ? "exclusive" : "shared")}, {(Waiting ? "waiting" : "running")} {Seconds:0} s)";
    }

    /// <summary>Who holds the workspace lock and who waits for it.</summary>
    public IReadOnlyList<LockEntry> LockUsers()
    {
        static LockEntry Entry(LockUser u, bool waiting) =>
            new(u.Tool, u.Write, System.Diagnostics.Stopwatch.GetElapsedTime(u.Since).TotalSeconds, waiting);
        return [.. _holders.Values.Select(u => Entry(u, false)), .. _waiters.Values.Select(u => Entry(u, true)).OrderByDescending(e => e.Seconds)];
    }

    private static LockUser Me(bool write) =>
        Call.Value is { } scope ? new LockUser(scope.Tool, scope.Started, write) : new LockUser(null, System.Diagnostics.Stopwatch.GetTimestamp(), write);

    private void Held(bool write)
    {
        var user = _holders.GetOrAdd(Environment.CurrentManagedThreadId, _ => Me(write));
        user.Depth++;
    }

    private void Released()
    {
        int id = Environment.CurrentManagedThreadId;
        if (_holders.TryGetValue(id, out var user) && --user.Depth == 0) _holders.TryRemove(id, out _);
    }

    /// <summary>Workspace locks held by this flow (tasks started under a lock inherit it).</summary>
    private static readonly AsyncLocal<int> LockDepth = new();

    /// <summary>
    /// Tests: a tool call that reads a loaded assembly's module or decompiler reader without holding the workspace lock throws
    /// (an edit, reload or unload meanwhile disposes them). Also on with CORVUS_LOCK_CHECK=1.
    /// </summary>
    public static bool CheckLockScope { get; set; } = Environment.GetEnvironmentVariable("CORVUS_LOCK_CHECK") == "1";

    /// <summary>Throws when <see cref="CheckLockScope"/> is on, a tool call is running and it holds no workspace lock.</summary>
    internal static void RequireLock(LoadedAssembly asm, string what)
    {
        if (CheckLockScope && Call.Value != null && LockDepth.Value == 0)
            throw new InvalidOperationException($"{asm.Id}: {what} used outside the workspace lock; an edit, reload or unload can replace or dispose it meanwhile.");
    }

    private static T Locked<T>(Func<T> action)
    {
        int depth = LockDepth.Value;
        LockDepth.Value = depth + 1;
        try { return action(); }
        finally { LockDepth.Value = depth; }
    }

    public T Read<T>(Func<T> action) => Read(action, CallToken);

    /// <summary>Runs <paramref name="action"/> under the shared lock; a cancelled wait throws <see cref="OperationCanceledException"/>.</summary>
    public T Read<T>(Func<T> action, CancellationToken cancellationToken)
    {
        Enter(write: false, cancellationToken);
        try { return Locked(action); }
        finally
        {
            Released();
            _lock.ExitReadLock();
        }
    }

    public T Write<T>(Func<T> action) => Write(action, CallToken);

    /// <summary>Runs <paramref name="action"/> under the exclusive lock; a cancelled wait throws <see cref="OperationCanceledException"/>.</summary>
    public T Write<T>(Func<T> action, CancellationToken cancellationToken)
    {
        Enter(write: true, cancellationToken);
        try { return Locked(action); }
        finally
        {
            Generation++;
            lock (_referenceModules) _referenceModules.Clear();
            lock (_externalDecompilerRefs) _externalDecompilerRefs.Clear();
            Released();
            _lock.ExitWriteLock();
        }
    }

    private void Enter(bool write, CancellationToken cancellationToken)
    {
        if (write ? _lock.TryEnterWriteLock(0) : _lock.TryEnterReadLock(0))
        {
            Held(write);
            return;
        }
        int id = Environment.CurrentManagedThreadId;
        _waiters[id] = Me(write);
        try
        {
            if (!cancellationToken.CanBeCanceled)
            {
                if (write) _lock.EnterWriteLock();
                else _lock.EnterReadLock();
            }
            else
            {
                // ReaderWriterLockSlim waits take no token: a queued call checks it between slices.
                while (!(write ? _lock.TryEnterWriteLock(WaitSliceMs) : _lock.TryEnterReadLock(WaitSliceMs)))
                {
                    if (!cancellationToken.IsCancellationRequested) continue;
                    if (Call.Value is { } scope)
                        scope.BlockedBy = string.Join(", ", LockUsers().Where(u => !u.Waiting).Select(u => u.ToString())) is { Length: > 0 } holders
                            ? holders : "a writer queued before it";
                    cancellationToken.ThrowIfCancellationRequested();
                }
            }
        }
        finally { _waiters.TryRemove(id, out _); }
        Held(write);
    }

    /// <summary>Longest shared-lock section of <see cref="ReadEach{T}"/>, so a queued writer waits about this long.</summary>
    internal const int ReadSectionMs = 100;

    /// <summary>
    /// Visits <paramref name="items"/> under the shared lock in sections of about <see cref="ReadSectionMs"/>, so whole-assembly
    /// work never holds the lock for long; stops when <paramref name="visit"/> returns false. A load or unload of
    /// <paramref name="owner"/> between sections ends the visit with a conflict error.
    /// </summary>
    public void ReadEach<T>(LoadedAssembly? owner, IReadOnlyList<T> items, Func<T, bool> visit, CancellationToken cancellationToken)
    {
        var ct = cancellationToken.CanBeCanceled ? cancellationToken : CallToken;
        int next = 0;
        bool more = true;
        while (more && next < items.Count)
            Read(() =>
            {
                if (owner != null && !_assemblies.Contains(owner)) throw Gone(owner.Id);
                long start = System.Diagnostics.Stopwatch.GetTimestamp();
                do
                {
                    ct.ThrowIfCancellationRequested();
                    more = visit(items[next++]);
                }
                while (more && next < items.Count && System.Diagnostics.Stopwatch.GetElapsedTime(start).TotalMilliseconds < ReadSectionMs);
                return 0;
            }, ct);
    }

    /// <summary>Snapshot of loaded assemblies; consistent only inside Read/Write.</summary>
    public IReadOnlyList<LoadedAssembly> Assemblies => _assemblies.ToArray();

    /// <summary>Snapshot of loaded native images; consistent only inside Read/Write.</summary>
    public IReadOnlyList<LoadedNative> Natives => _natives.ToArray();

    public IReadOnlyList<string> SearchDirectories => _searchDirectories.ToArray();

    /// <summary>Loaded assemblies and native images, read without the lock (may be one load behind).</summary>
    public int LoadedCount => _assemblies.Count + _natives.Count;

    public void AddSearchDirectory(string directory)
    {
        var full = Path.GetFullPath(directory);
        if (!Directory.Exists(full))
            throw Targets.DirectoryNotFound(directory);
        Write(() =>
        {
            if (!_searchDirectories.Contains(full, InputFiles.PathComparer))
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
    /// Loads a .NET assembly, or a native image when the file has no .NET metadata (PE, ELF, Mach-O; for a universal
    /// Mach-O the <paramref name="slice"/>). Returns the existing entry when the path (and slice) is already loaded.
    /// </summary>
    public (LoadedAssembly? Assembly, LoadedNative? Native) LoadAny(string path, string? slice = null, Func<Native.INativeImage, Native.EngineOverrides?>? overrides = null)
    {
        var full = InputFiles.RequireRegularFile(path);
        Webcil.ThrowIfWebcil(full);
        var kind = Native.NativeImageLoader.DetectFile(full);
        if (kind is Native.NativeFileKind.Elf or Native.NativeFileKind.MachO or Native.NativeFileKind.MachOFat)
            return (null, LoadNativeFile(full, slice, overrides));
        if (slice != null) Native.NativeImageLoader.Open(full, slice); // the slice error
        if (Read(() => _natives.FirstOrDefault(n => InputFiles.SamePath(n.FilePath, full) && LoadedNative.KeyOf(n.Image) == null)) is { } existing)
            return (existing.ManagedView, existing);
        try
        {
            // A mixed-mode (C++/CLI) assembly also gets its native view.
            var asm = Load(full);
            return (asm, Read(() => NativeViewOf(asm)));
        }
        catch (ToolError ex) when (ex.Code == ErrorCode.Unsupported)
        {
            var image = Native.NativeImageLoader.Open(full);
            if (image is Native.Pe.PeFile { IsDotNet: true }) throw;
            int before = _natives.Count;
            var native = Write(() => LoadNativeCore(full, image, overrides));
            if (_natives.Count != before) NativeLoaded?.Invoke(native);
            return (null, native);
        }
    }

    /// <summary>An ELF or Mach-O image; each slice of a universal file is its own entry, id "name[slice]".</summary>
    private LoadedNative LoadNativeFile(string full, string? slice, Func<Native.INativeImage, Native.EngineOverrides?>? overrides)
    {
        if (slice == null && Read(() => _natives.FirstOrDefault(n => InputFiles.SamePath(n.FilePath, full) && LoadedNative.KeyOf(n.Image) == null)) is { } existing)
            return existing;
        var image = Native.NativeImageLoader.Open(full, slice);
        int before = _natives.Count;
        var native = Write(() => LoadNativeCore(full, image, overrides));
        if (_natives.Count != before) NativeLoaded?.Invoke(native);
        return native;
    }

    /// <summary>A headerless file mapped by <paramref name="layout"/>; each layout of a file is its own entry, id "name[x64@0x400000]".</summary>
    public LoadedNative LoadRaw(string path, Native.RawLayout layout, Func<Native.INativeImage, Native.EngineOverrides?>? overrides = null)
    {
        var full = InputFiles.RequireRegularFile(path);
        if (Read(() => _natives.FirstOrDefault(n => InputFiles.SamePath(n.FilePath, full) && LoadedNative.KeyOf(n.Image) == layout.Key)) is { } existing)
            return existing;
        var image = Native.RawCodeImage.Open(full, layout);
        int before = _natives.Count;
        var native = Write(() => LoadNativeCore(full, image, overrides));
        if (_natives.Count != before) NativeLoaded?.Invoke(native);
        return native;
    }

    /// <summary>A new entry gets <paramref name="overrides"/> before anything (a prewarm) can open an engine on it.</summary>
    private LoadedNative LoadNativeCore(string full, Native.INativeImage image, Func<Native.INativeImage, Native.EngineOverrides?>? overrides = null)
    {
        var key = LoadedNative.KeyOf(image);
        var existing = _natives.FirstOrDefault(n => InputFiles.SamePath(n.FilePath, full) && LoadedNative.KeyOf(n.Image) == key);
        if (existing != null) return existing;
        var baseId = Path.GetFileName(full) + (key != null ? $"[{key}]" : "");
        var id = baseId;
        for (int n = 2; IdTaken(id); n++) id = $"{baseId}#{n}";
        var native = new LoadedNative(id, full, image) { Overrides = overrides?.Invoke(image) };
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
                                               || InputFiles.SamePath(n.FilePath, SafeFullPath(id)))
               // A mixed-mode assembly's id names its native view too.
               ?? _natives.FirstOrDefault(n => n.ManagedView?.Id.Equals(id, StringComparison.OrdinalIgnoreCase) == true);
    }

    /// <summary><see cref="FindNative"/>, with a typed error when nothing matches (see <see cref="Targets"/>).</summary>
    public LoadedNative GetNative(string identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier))
            throw new ToolError(ErrorCode.InvalidArgument, "Image identifier is empty.", "pass image=<an id from list_assemblies, or a file path>");
        if (FindNative(identifier) is { } native) return native;
        var id = identifier.Trim();
        if (FindAssemblies(id).Count > 0)
            throw new ToolError(ErrorCode.Unsupported, $"'{identifier}' is a .NET assembly, not a native image.",
                "use the .NET tools (decompile_member, get_il, find_references) for it");
        if (MissingPath(id)) throw Targets.FileNotFound(id);
        if (_natives.Count == 0)
            throw Targets.NotLoaded("No native images are loaded.", id);
        throw new ToolError(ErrorCode.NotFound, $"No loaded native image matches '{identifier}'. Loaded: {string.Join(", ", _natives.Select(n => n.Id))}",
            "list_assemblies shows loaded ids; a file path loads the file");
    }

    public void UnloadNative(LoadedNative native) => Write(() =>
    {
        if (!_natives.Remove(native)) throw Gone(native.Id);
        native.Release();
        return 0;
    });

    private static ToolError Gone(string id) =>
        new(ErrorCode.Conflict, $"{id} was unloaded or reloaded by another call in the meantime.", "list_assemblies shows what is loaded now; repeat the call");

    /// <summary>Re-reads a native image from disk, discarding its analysis state; <paramref name="overrides"/> replace its import overrides.</summary>
    public LoadedNative ReloadNative(LoadedNative native, Native.EngineOverrides? overrides = null)
    {
        Native.INativeImage image = native.Image is Native.RawCodeImage raw
            ? Native.RawCodeImage.Open(native.FilePath, raw.Layout)
            : Native.NativeImageLoader.Open(native.FilePath, native.SliceName);
        var fresh = Write(() =>
        {
            int index = _natives.IndexOf(native);
            if (index < 0) throw Gone(native.Id);
            _natives.RemoveAt(index);
            native.Release();
            var reloaded = new LoadedNative(native.Id, native.FilePath, image) { ManagedView = native.ManagedView, EngineDatabase = native.EngineDatabase, Overrides = overrides ?? native.Overrides };
            _natives.Insert(index, reloaded);
            return reloaded;
        });
        NativeLoaded?.Invoke(fresh);
        return fresh;
    }

    /// <summary>The longest file or directory name Windows, Linux and macOS file systems accept.</summary>
    private const int MaxFileNameLength = 255;

    /// <summary>The .NET load cap, the same as for native images (S10.1); checked before the file is read.</summary>
    public const long MaxAssemblyBytes = Native.Pe.PeLimits.MaxFileSize;

    internal static void CheckSize(string full, long length)
    {
        if (length > MaxAssemblyBytes)
            throw new ToolError(ErrorCode.LimitExceeded, $"{full} is {length:N0} bytes; .NET assemblies up to {MaxAssemblyBytes:N0} bytes are loaded.",
                "the cap is fixed; load a smaller file") { Details = new { limit = MaxAssemblyBytes, size = length } };
    }

    private LoadedAssembly LoadCore(string path)
    {
        var full = InputFiles.RequireRegularFile(path);
        if (!File.Exists(full))
        {
            // Windows raises PathTooLongException for these; Linux and macOS only report the file missing.
            if (full.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(part => part.Length > MaxFileNameLength))
                throw new ToolError(ErrorCode.InvalidArgument, "a path is too long.", "Pass a shorter path.");
            throw Targets.FileNotFound(path);
        }

        var existing = _assemblies.FirstOrDefault(a => InputFiles.SamePath(a.FilePath, full));
        if (existing != null)
            return existing;

        CheckSize(full, new FileInfo(full).Length);
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

        var asm = new LoadedAssembly(MakeUniqueId(module, full), full, bytes, module) { Shared = true };
        _assemblies.Add(asm);
        ModuleSetChanged();
        AttachNativeView(asm, bytes);

        var dir = Path.GetDirectoryName(full)!;
        if (!_searchDirectories.Contains(dir, InputFiles.PathComparer))
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
            throw Targets.DirectoryNotFound(directory);

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
            ModuleSetChanged();
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

    /// <summary>The loaded assemblies an id, file name, full path or simple name (case-insensitive) matches, by the first rule that matches any.</summary>
    public List<LoadedAssembly> FindAssemblies(string identifier)
    {
        var id = identifier.Trim();
        var matches = _assemblies.Where(a => a.Id.Equals(id, StringComparison.OrdinalIgnoreCase)).ToList();
        if (matches.Count == 0)
            matches = _assemblies.Where(a => Path.GetFileName(a.FilePath).Equals(id, StringComparison.OrdinalIgnoreCase)
                                             || InputFiles.SamePath(a.FilePath, SafeFullPath(id))).ToList();
        if (matches.Count == 0)
            matches = _assemblies.Where(a => a.AssemblyName.Equals(id, StringComparison.OrdinalIgnoreCase)).ToList();
        return matches;
    }

    /// <summary>Finds an assembly by id, file name, full path or simple name (case-insensitive); the error follows <see cref="Targets"/>.</summary>
    public LoadedAssembly Get(string identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier))
            throw new ToolError(ErrorCode.InvalidArgument, "Assembly identifier is empty.", "pass assembly=<an id from list_assemblies, or a file path>");
        var id = identifier.Trim();
        var matches = FindAssemblies(id);
        if (matches.Count == 1)
            return matches[0];
        if (matches.Count > 1)
            throw new ToolError(ErrorCode.Ambiguous, $"'{identifier}' matches several loaded assemblies: {string.Join(", ", matches.Select(m => $"{m.Id} ({m.FilePath})"))}. Use the id.");
        if (FindNative(id) is { } native)
            throw new ToolError(ErrorCode.Unsupported, $"'{identifier}' is a native image ({native.Image.MachineName}), not a .NET assembly.",
                "use the native tools: get_pe_info, list_imports, list_exports, list_functions, disassemble");
        if (MissingPath(id)) throw Targets.FileNotFound(id);
        if (_assemblies.Count == 0) throw NoAssemblies(id);
        throw new ToolError(ErrorCode.NotFound, $"No loaded assembly matches '{identifier}'. Loaded: {string.Join(", ", _assemblies.Select(a => a.Id))}",
            "list_assemblies shows loaded ids; a file path loads the file");
    }

    /// <summary>A path-like identifier naming nothing on disk.</summary>
    private static bool MissingPath(string id) =>
        Targets.LooksLikePath(id) && Targets.FullPath(id) is { } full && !File.Exists(full) && !Directory.Exists(full);

    private ToolError NoAssemblies(string? identifier = null)
    {
        var natives = _natives.ToArray();
        var next = identifier != null ? $"load_assembly path={identifier}" : "load_assembly path=<a .NET assembly or folder>";
        return natives.Length == 0
            ? new ToolError(ErrorCode.NotLoaded, "No assemblies are loaded.", next)
            : new ToolError(ErrorCode.NotLoaded,
                $"No .NET assembly is loaded, only native images ({string.Join(", ", natives.Take(5).Select(n => n.Id))}{(natives.Length > 5 ? ", ..." : "")}).",
                (identifier != null ? next + "; " : "") + "use the native tools (list_functions, disassemble, native_call_tree, find_xrefs); find_call_paths takes native code as to=native:<image>!<function>");
    }

    /// <summary>Resolves an optional assembly parameter; null or empty means all loaded assemblies.</summary>
    public IReadOnlyList<LoadedAssembly> Scope(string? identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier))
        {
            if (_assemblies.Count == 0) throw NoAssemblies();
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
            bool sameDir = requesterDir != null && InputFiles.SamePath(SafeDirectory(a.FilePath), requesterDir);
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
        _assemblies.FirstOrDefault(a => InputFiles.SamePath(a.FilePath, path));

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
            .Distinct(InputFiles.PathComparer);
        string? otherMajor = null;
        foreach (var dir in dirs)
            foreach (var ext in new[] { ".dll", ".exe", ".winmd" })
            {
                var candidate = Path.Combine(dir, simpleName + ext);
                if (!File.Exists(candidate)) continue;
                bool sameDir = InputFiles.SamePath(dir, first);
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

    /// <summary>A stub built once per name; other threads wait for the builder.</summary>
    private sealed class StubEntry
    {
        public readonly TaskCompletionSource<ReferenceTarget?> Done = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int Claimed;
    }

    /// <summary>Replaced when a load or unload changes the loaded modules; edits keep it.</summary>
    private volatile System.Collections.Concurrent.ConcurrentDictionary<string, StubEntry> _stubs = new(StringComparer.OrdinalIgnoreCase);

    [ThreadStatic] private static int _stubsOff;

    /// <summary>
    /// Until disposed, a reference this thread cannot locate stays unresolved instead of being stubbed, and the miss is
    /// not cached. For scans that only need real definitions (a stub has no P/Invokes) and for stub builds themselves.
    /// </summary>
    public static IDisposable WithoutStubs()
    {
        _stubsOff++;
        return new StubsBack();
    }

    private sealed class StubsBack : IDisposable
    {
        private bool _done;
        public void Dispose()
        {
            if (_done) return;
            _done = true;
            _stubsOff--;
        }
    }

    private void ModuleSetChanged() => _stubs = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Stub for an unresolvable reference, synthesized from its usage in loaded assemblies. Cached per name until a
    /// load or unload changes the loaded modules.
    /// </summary>
    private ReferenceTarget? StubFor(string name, Version? version)
    {
        if (!ReferenceStubs.CanStub(name)) return null;
        // A build reads loaded modules whose dnlib lists may be locked further up this stack (LockException) and must
        // never wait for another build: any reference met while building stays unresolved.
        if (_stubsOff > 0) return null;
        var ct = CallToken;
        while (true)
        {
            var stubs = _stubs;
            var entry = stubs.GetOrAdd(name, _ => new StubEntry());
            if (Interlocked.Exchange(ref entry.Claimed, 1) == 0)
            {
                using var building = WithoutStubs();
                try
                {
                    var target = ReferenceStubs.Build(name, version, Assemblies, ct) is { } stub
                        ? new ReferenceTarget(null, null, stub.Image, null, $"stub built from what the loaded code uses ({stub.Types} types, {stub.Members} members)")
                        : null;
                    entry.Done.SetResult(target);
                    return target;
                }
                catch
                {
                    // Waiters retry and the next caller builds again.
                    stubs.TryRemove(new KeyValuePair<string, StubEntry>(name, entry));
                    entry.Done.TrySetCanceled();
                    throw;
                }
            }
            try { entry.Done.Task.Wait(ct); }
            catch (AggregateException) { continue; }
            return entry.Done.Task.Result;
        }
    }

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
        // So do its facades: a runtime facade brings System.Private.CoreLib in beside netstandard, and the engine then
        // matches types it looks up by name (ExceptionDispatchInfo, for await in catch) against the wrong copy.
        if (!netFramework && Frameworks.NetStandardFacade(name, requesterFramework) is { } facade && FrameworkUnlessLocal(facade) is { } standardFacade)
            return standardFacade;
        // Windows Runtime contracts resolve from Windows SDK metadata.
        if (Frameworks.WindowsMetadataFile(name, version) is { } winmd && FindReference(name, version, token, requesterPath, sameMajor: true) == null)
            return new(null, winmd, null, null);
        if (FindReference(name, version, token, requesterPath, sameMajor: true, netFramework) is { } loaded) return new(loaded, null, null, null);
        if (FindAssemblyFile(name, requesterPath, token, version, netFramework) is { } file)
        {
            // Prefer the NuGet package for the requester's TFM over a newer shared-framework or targeting-pack copy.
            if (Frameworks.NetCoreMajor(requesterFramework) is { } targetMajor && Frameworks.ModernFrameworkMajor(file) is { } fileMajor
                && fileMajor > targetMajor && Frameworks.SharedFrameworkOf(name, targetMajor) != "Microsoft.NETCore.App"
                && Frameworks.NuGetFile(name, version, netFramework, requesterFramework) is { } fitting)
                return new(null, fitting, null, null);
            // A major-version mismatch, or a modern runtime copy for a .NET Framework requester, ranks below
            // embedded images and matching NuGet packages.
            // Likewise a .NET Framework copy for a .NET Standard or .NET requester (System.Numerics.Vectors there lacks
            // Vector<T>), and a runtime or targeting-pack copy for a .NET Standard one (it needs that runtime's System.Runtime, CS1705).
            bool standardRequester = requesterFramework?.StartsWith(".NETStandard", StringComparison.OrdinalIgnoreCase) == true;
            bool exact = (version == null || Frameworks.IsWildcard(version) || FileVersion(file) is not { } v || Frameworks.IsWildcard(v) || v.Major == version.Major)
                         && !((netFramework || standardRequester) && Frameworks.ModernFrameworkMajor(file) != null)
                         && !(!netFramework && requesterFramework != null && Frameworks.InNetFrameworkDirectory(file));
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
            return local == null || !InputFiles.SamePath(SafeDirectory(local.FilePath), requesterDir)
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
                    var contents = Containers.Open(host.OriginalBytes, host.FilePath, AnalysisLimits.Default, default);
                    foreach (var item in contents.Items)
                        if (Blob.Identify(item.Bytes) == ".NET assembly")
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
        // Misses while stubs are off: a stub build resolves every member reference of the loaded code, missing ones again and again.
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, bool> _missesWithoutStubs = new();
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
                _missesWithoutStubs.Clear();
                _cacheGeneration = generation;
            }
            var key = string.Join("|", name, assembly.Version, Convert.ToHexString(assembly.PublicKeyOrToken?.Token?.Data ?? []),
                sourceModule?.Location is { } location ? SafeDirectory(location) : "", sourceModule == null ? "" : Frameworks.RequesterFramework(sourceModule));
            if (_cache.TryGetValue(key, out var known)) return known;
            if (_stubsOff > 0 && _missesWithoutStubs.ContainsKey(key)) return null;
            var resolved = ResolveUncached(name, assembly, sourceModule);
            // A miss while stubs are off is not the reference's answer for the rest of the generation.
            if (resolved != null || _stubsOff == 0) _cache[key] = resolved;
            else _missesWithoutStubs[key] = true;
            return resolved;
        }

        private AssemblyDef? ResolveUncached(string name, IAssembly assembly, ModuleDef? sourceModule)
        {
            var requester = sourceModule?.Location;
            var target = ws.LocateReference(name, assembly.Version, assembly.PublicKeyOrToken?.Token?.Data, requester,
                sourceModule != null && Frameworks.ResolvesAsNetFramework(sourceModule), sourceModule == null ? null : Frameworks.RequesterFramework(sourceModule));
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
                        MetadataUtil.MarkReferenceOnly(module);
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
                Frameworks.ResolvesAsNetFramework(_main.Module), Frameworks.RequesterFramework(_main.Module));
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
