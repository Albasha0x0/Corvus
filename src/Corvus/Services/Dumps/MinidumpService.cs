using System.Collections.Concurrent;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Dump;
using Corvus.Native.Pdb;
using Corvus.Native.Pe;

namespace Corvus.Services;

/// <summary>
/// Crash dump inspection: opens Windows minidumps (by path; each gets a short id), walks thread stacks and names the
/// frames. Module images come from disk when a file with the module's timestamp and size is found (its recorded path,
/// the dump's folder, or folders the caller names), else from dump memory. Names, best first: a loaded native image's
/// code index (user, PDB, Il2Cpp and discovered names), Il2Cpp dummy DLLs for GameAssembly.dll, then a matching local
/// PDB and the exports. .NET (CLR) frames are decoded through the runtime's DAC when a verified one is available. Dumps are re-read per call
/// (positional reads); module images and names are cached.
/// </summary>
public sealed partial class MinidumpService(AssemblyWorkspace? workspace = null, NativeCodeService? code = null, Il2CppNavigator? navigator = null,
    DecompilerService? decompiler = null, StackTextService? stacks = null) : IDisposable
{
    private const int MaxCachedModules = 256;
    private static readonly TimeSpan IndexWait = TimeSpan.FromSeconds(30);

    private readonly ConcurrentDictionary<string, string> _ids = new(StringComparer.OrdinalIgnoreCase);
    // imageDirectories given for a dump file, reused by later calls on it that pass none
    private readonly ConcurrentDictionary<string, string> _imageDirectories = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _cacheGate = new();
    private readonly Dictionary<string, ModuleCode> _cache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>A module's image and lightweight names, shared between calls.</summary>
    internal sealed class ModuleCode
    {
        private readonly Deferred<ModuleNames?> _names;

        public ModuleCode(PeFile? image, string source, string? localPath, string detail)
        {
            Image = image;
            Source = source;
            LocalPath = localPath;
            Detail = detail;
            _names = new Deferred<ModuleNames?>(() => image == null ? null : BuildNames(image));
        }

        public PeFile? Image { get; }
        /// <summary>disk, dump_memory, process_memory or none.</summary>
        public string Source { get; }
        public string? LocalPath { get; }
        public string Detail { get; }
        public ModuleNames? Names => _names.Value;
        public string? NamesError { get; private set; }

        private ModuleNames? BuildNames(PeFile image)
        {
            IReadOnlyList<PdbName>? pdb = null;
            string? pdbPath = null;
            try
            {
                if (image.CodeView is { Format: "RSDS" } && Environment.GetEnvironmentVariable(PdbService.AutoVariable) != "0")
                {
                    var location = PdbLocator.Locate(image);
                    if (location.Path != null)
                    {
                        var file = PdbFile.Open(location.Path, image.Sections);
                        pdb = PdbNaming.Choose(file, image.SizeOfImage);
                        pdbPath = file.Path;
                    }
                }
            }
            catch (Exception ex) when (ex is ToolError or IOException or UnauthorizedAccessException)
            {
                NamesError = $"PDB not read: {ex.Message}";
            }
            return new ModuleNames(image, pdb, pdbPath);
        }
    }

    /// <summary>One tool call's view of a dump (or of a live process): its memory and the module images it resolved.</summary>
    internal sealed class Session(MinidumpService owner, string id, IProcessMemory memory, IReadOnlyList<string> directories, IReadOnlyList<string>? loaded = null) : IDisposable
    {
        private readonly Dictionary<DumpModule, ModuleCode> _modules = [];
        private readonly Dictionary<DumpModule, Task<NativeCodeIndex?>> _indexes = [];

        public string Id { get; } = id;
        public IProcessMemory Memory { get; } = memory;
        /// <summary>The minidump of a dump session.</summary>
        public MinidumpFile Dump => Memory as MinidumpFile ?? throw new InvalidOperationException("not a dump session");
        public IReadOnlyList<string> Directories { get; } = directories;
        /// <summary>Frames left whose IL offset may be mapped to a C# statement in this call.</summary>
        public int StatementBudget { get; set; } = MaxStatements;
        /// <summary>The Mono runtime's crash reports beside the dump, once read.</summary>
        public IReadOnlyList<(string Log, StackTextService.SymbolizedStack Stack)>? MonoReports { get; set; }
        /// <summary>Files of the native images open in the workspace, matched to modules by timestamp and size under any name.</summary>
        public IReadOnlyList<string> LoadedImages { get; } = loaded ?? [];

        public ModuleCode Code(DumpModule module)
        {
            lock (_modules)
            {
                if (!_modules.TryGetValue(module, out var c)) _modules[module] = c = owner.Load(Memory, module, Directories, LoadedImages);
                return c;
            }
        }

        public Task<NativeCodeIndex?> Index(DumpModule module, CancellationToken ct)
        {
            lock (_indexes)
            {
                if (!_indexes.TryGetValue(module, out var t)) _indexes[module] = t = owner.WorkspaceIndex(module, ct);
                return t;
            }
        }

        /// <summary>A stack walker over this session's memory, with function starts from the modules' PDB and export names.</summary>
        public StackWalker Walker(IProcessMemory? view = null) => new(view ?? Memory, m => Code(m).Image,
            address => Memory.ModuleAt(address) is { } m && Code(m).Names?.Lookup((uint)(address - m.Base)).Start is { } start ? m.Base + start : null);

        public IEnumerable<(DumpModule Module, ModuleCode Code)> Loaded
        {
            get { lock (_modules) return _modules.Select(kv => (kv.Key, kv.Value)).ToList(); }
        }

        public void Dispose() => (Memory as IDisposable)?.Dispose();
    }

    /// <summary>Ids of the dumps opened so far (open_minidump, bucket_minidumps).</summary>
    public IReadOnlyCollection<string> OpenIds => [.. _ids.Keys];

    /// <summary>
    /// Opens a dump by id (from an earlier open_minidump) or path; a path is registered under its file name (#2, #3...
    /// when another dump has the name).
    /// </summary>
    internal Session Open(string dump, string? imageDirectories)
    {
        if (string.IsNullOrWhiteSpace(dump))
            throw new ToolError(ErrorCode.InvalidArgument, "dump is empty.", "pass a .dmp path or the id open_minidump returned");
        var key = dump.Trim();
        string path;
        if (_ids.TryGetValue(key, out var known)) path = known;
        else
        {
            try { path = Path.GetFullPath(key); }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                throw new ToolError(ErrorCode.InvalidArgument, $"'{dump}' is neither an open dump id nor a valid path: {ex.Message}");
            }
            if (!File.Exists(path) && _ids.IsEmpty && Targets.LooksLikePath(dump)) throw Targets.FileNotFound(dump);
            if (!File.Exists(path))
                throw new ToolError(ErrorCode.NotFound,
                    _ids.IsEmpty ? $"No dump file at '{dump}'." : $"No dump file at '{dump}', and no open dump has that id (open: {string.Join(", ", _ids.Keys.Order())}).",
                    "pass the path of a .dmp file");
        }
        var file = MinidumpFile.Open(path);
        string id = Register(path);
        if (string.IsNullOrWhiteSpace(imageDirectories)) imageDirectories = _imageDirectories.GetValueOrDefault(path);
        var dirs = Directories(imageDirectories, path);
        if (!string.IsNullOrWhiteSpace(imageDirectories)) _imageDirectories[path] = imageDirectories;
        return new Session(this, id, file, dirs, LoadedImagePaths());
    }

    private List<string> LoadedImagePaths() =>
        workspace == null ? [] : workspace.Read(() => workspace.Natives.Select(n => n.FilePath).Where(File.Exists).ToList());

    /// <summary>The file of an open dump id, or null.</summary>
    internal string? PathOf(string id) => _ids.TryGetValue(id.Trim(), out var path) ? path : null;

    /// <summary>A session over other process memory (a live process); it owns <paramref name="memory"/>.</summary>
    internal Session SessionFor(string id, IProcessMemory memory, IReadOnlyList<string> directories) => new(this, id, memory, directories);

    private string Register(string path)
    {
        foreach (var (k, v) in _ids)
            if (v.Equals(path, StringComparison.OrdinalIgnoreCase)) return k;
        string name = Path.GetFileName(path);
        lock (_ids)
        {
            for (int n = 1; ; n++)
            {
                string id = n == 1 ? name : $"{name}#{n}";
                if (_ids.TryAdd(id, path)) return id;
                if (_ids.TryGetValue(id, out var p) && p.Equals(path, StringComparison.OrdinalIgnoreCase)) return id;
            }
        }
    }

    /// <summary>Folders searched for module images: the caller's (';'-separated), then the dump's own folder.</summary>
    internal static List<string> Directories(string? list, string dumpPath)
    {
        var dirs = new List<string>();
        foreach (var raw in (list ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try
            {
                var full = Path.GetFullPath(raw);
                if (!Directory.Exists(full))
                    throw new ToolError(ErrorCode.NotFound, $"imageDirectories: '{raw}' is not a directory.", "pass existing folders separated by ';'");
                dirs.Add(full);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                throw new ToolError(ErrorCode.InvalidArgument, $"imageDirectories: '{raw}' is not a valid path: {ex.Message}");
            }
        }
        if (Path.GetDirectoryName(dumpPath) is { Length: > 0 } own && !dirs.Contains(own, StringComparer.OrdinalIgnoreCase)) dirs.Add(own);
        return dirs;
    }

    internal ModuleCode Load(IProcessMemory dump, DumpModule module, IReadOnlyList<string> directories, IReadOnlyList<string>? loaded = null)
    {
        var local = DumpImages.Find(module, directories, dump.Arch, loaded);
        string key = local.Matches ? $"disk|{local.Path}|{module.TimeDateStamp:X}|{module.Size:X}"
            : $"memory|{dump.Identity}|{module.Base:X}";
        lock (_cacheGate)
            if (_cache.TryGetValue(key, out var cached)) return cached;
        ModuleCode result;
        if (local.Matches)
        {
            try { result = new ModuleCode(PeFile.Open(local.Path!), "disk", local.Path, local.Detail); }
            catch (ToolError ex) { result = new ModuleCode(null, "none", local.Path, $"{local.Path}: {ex.Message}"); }
        }
        else
        {
            var image = DumpImages.FromMemory(dump, module, out ulong captured);
            string why = local.Exists ? $"{local.Path}: {local.Detail}" : local.Detail;
            bool isDump = dump is MinidumpFile;
            result = image != null
                ? new ModuleCode(image, isDump ? "dump_memory" : "process_memory", null,
                    $"rebuilt from {(isDump ? "dump" : "process")} memory ({captured * 100 / Math.Max(1u, module.Size)}% {(isDump ? "captured" : "readable")}); local file: {why}")
                : new ModuleCode(null, "none", local.Path, $"no image: {why}; {(isDump ? "the dump does not hold its headers" : "its headers are not readable")}");
        }
        lock (_cacheGate)
        {
            if (_cache.Count >= MaxCachedModules) _cache.Clear();
            _cache[key] = result;
        }
        return result;
    }

    /// <summary>The code index of a loaded native image that is this module's build (timestamp and size; the same file name first), else null.</summary>
    private async Task<NativeCodeIndex?> WorkspaceIndex(DumpModule module, CancellationToken ct)
    {
        if (workspace == null || code == null) return null;
        var native = workspace.Read(() =>
        {
            var same = workspace.Natives.Where(n => n.Pe?.Coff.TimeDateStamp == module.TimeDateStamp && n.Image.SizeOfImage == module.Size && module.TimeDateStamp != 0).ToList();
            return same.FirstOrDefault(n => Path.GetFileName(n.FilePath).Equals(module.FileName, StringComparison.OrdinalIgnoreCase)) ?? same.FirstOrDefault();
        });
        if (native == null) return null;
        try { return await code.Index(native, null, ct).WaitAsync(IndexWait, ct); }
        catch (TimeoutException) { return null; }
        catch (ToolError) { return null; }
    }

    /// <summary>What is at an address of the dumped process.</summary>
    internal sealed record Location(
        DumpModule? Module, uint? Rva, string? Symbol, string? Function, string? Source, ulong? FunctionAddress, string Kind, string? Note);

    internal static bool HostsClr(IProcessMemory dump, out string? runtime)
    {
        runtime = null;
        foreach (var m in dump.Modules)
        {
            var n = m.FileName.ToLowerInvariant();
            runtime = n switch
            {
                "coreclr.dll" => ".NET (CoreCLR)",
                "clr.dll" => ".NET Framework 4 (CLR)",
                "mscorwks.dll" => ".NET Framework 2.0-3.5 (CLR)",
                _ when n.StartsWith("mono", StringComparison.Ordinal) && n.EndsWith(".dll", StringComparison.Ordinal) => "Mono",
                _ => null,
            };
            if (runtime != null) return true;
        }
        return false;
    }

    internal async Task<Location> Locate(Session s, ulong address, bool returnAddress, CancellationToken ct)
    {
        ulong lookup = returnAddress && address > 0 ? address - 1 : address;
        var dump = s.Memory;
        var module = dump.ModuleAt(lookup);
        if (module == null)
        {
            var unloaded = dump.UnloadedModules.FirstOrDefault(u => lookup >= u.Base && lookup - u.Base < u.Size);
            if (unloaded != null)
                return new Location(null, null, null, null, null, null, "unloaded_module",
                    $"inside {Path.GetFileName(unloaded.Path)}, which was unloaded (base 0x{unloaded.Base:X}): a call into a DLL after it was freed");
            var region = dump.RegionAt(lookup);
            if (HostsClr(dump, out var runtime) && (region == null || region.IsExecutable))
                return new Location(null, null, null, null, null, null, "managed",
                    $"not in a module: JIT-compiled managed code ({runtime} is loaded); the runtime's DAC names it when one is available (open_minidump dacPath or downloadDac)");
            string what = region == null ? "not in a module" : region.IsExecutable ? "not in a module: generated or injected code (executable private memory)"
                : "not in a module and not executable memory";
            return new Location(null, null, null, null, null, null, "unknown", what);
        }
        uint rva = (uint)(lookup - module.Base);
        uint shownRva = (uint)(address - module.Base);
        string moduleName = ModuleLabel(module);

        // a loaded image's index: user, PDB, Il2Cpp and discovered names
        var index = await s.Index(module, ct);
        (string Name, string Source, uint Start)? found = null;
        if (index?.FunctionAt(rva) is { } f)
        {
            var sourced = index.Sourced.NameAt(f.Start);
            string source = sourced is { } sn ? sn.Source.ToString().ToLowerInvariant() : f.KnownName != null ? "export" : "discovered";
            found = (index.NameAt(f.Start) ?? f.Name, source, f.Start);
        }
        if (found is not { Source: "user" } && navigator?.FrameName(rva, module.FileName) is { } il2cpp)
            found = il2cpp;
        var mc = s.Code(module);
        if (found is null or { Source: "discovered" } && mc.Names?.Lookup(rva) is { Name: not null } light)
            found = (light.Name, light.Source, light.Start!.Value);

        string kind = "native";
        string? note = null;
        if (mc.Image is { IsDotNet: true })
        {
            kind = "managed";
            note = $"managed code in {module.FileName} (ReadyToRun or IL stub): find_r2r_method maps ReadyToRun code to its method";
        }
        if (found is { } n)
        {
            uint off = shownRva - n.Start;
            return new Location(module, shownRva, $"{moduleName}!{n.Name}" + (off != 0 ? $"+0x{off:X}" : ""), n.Name, n.Source, module.Base + n.Start, kind,
                note ?? (n.Source == "nearest_export" ? "named after the nearest export below: a guess (no PDB, no unwind data)" : null));
        }
        var start = mc.Names?.Lookup(rva).Start;
        if (start is { } st)
            return new Location(module, shownRva, $"{moduleName}+0x{shownRva:X}", null, "none", module.Base + st, kind,
                note ?? $"unnamed function at {moduleName}+0x{st:X}");
        return new Location(module, shownRva, $"{moduleName}+0x{shownRva:X}", null, "none", null, kind,
            note ?? (mc.Image == null ? mc.Detail : null));
    }

    /// <summary>The module name as debuggers print it: the file name without .dll / .exe / .sys.</summary>
    internal static string ModuleLabel(DumpModule m)
    {
        var name = m.FileName;
        foreach (var ext in new[] { ".dll", ".exe", ".sys" })
            if (name.EndsWith(ext, StringComparison.OrdinalIgnoreCase)) return name[..^ext.Length];
        return name;
    }
}
