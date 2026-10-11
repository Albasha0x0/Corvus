using System.ComponentModel;
using System.Text;
using System.Text.Json.Serialization;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Services.Analysis;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class WorkspaceTools(AssemblyWorkspace workspace, Il2CppService il2cpp, AssemblyReport report, IndexingService indexing, UnpackService unpacker,
    NativeLinkService? link = null, Il2CppRawLoader? il2cppRaw = null)
{
    public sealed record AssemblyEntry(string Id, string Name, string Version, string Path, int Types, bool Il2CppDummy, IReadOnlyList<string> UnsavedEdits,
        bool ReadyToRun, string? Merged);

    public sealed record NativeEntry(string Id, string Path, string Machine, string Kind, long Size, string Sha256)
    {
        /// <summary>Universal Mach-O: every slice of the file (load_assembly slice= loads another).</summary>
        public IReadOnlyList<string>? Slices { get; init; }
    }

    /// <summary>Workspace listing, or the container contents when list_assemblies is given a path.</summary>
    public sealed record WorkspaceState(IReadOnlyList<AssemblyEntry> Assemblies, IReadOnlyList<string> SearchDirectories, string BackgroundIndexing,
        UnpackService.ContainerListing? Container = null)
    {
        /// <summary>Count of assemblies matching the filter; Assemblies holds one page.</summary>
        public int Total { get; init; }

        /// <summary>Loaded native images matching the filter (not paged).</summary>
        public IReadOnlyList<NativeEntry> NativeImages { get; init; } = [];
    }

    [McpServerTool(Name = "load_assembly", Title = "Load assembly")]
    [Description("Load a .NET assembly (.dll/.exe) or every assembly in a directory (e.g. an application folder, a Unity *_Data/Managed folder or an Il2CppDumper DummyDll folder). " +
                 "A native PE (without .NET metadata), ELF or Mach-O file given by path loads as a native image for the native tools (get_pe_info, list_imports, list_exports, list_functions, disassemble); " +
                 "a universal Mach-O loads one slice (slice=) as name[slice]; " +
                 "folder loads take only .NET assemblies and list the native files they skipped. " +
                 "An Il2Cpp game (game folder or global-metadata.dat: Windows, Linux, macOS, extracted Android, iOS .app; an .apk/.xapk/.aab/.ipa; also a memory dump of the binary) " +
                 "is read by the built-in metadata reader (versions 24-39, no external dumper): " +
                 "dummy assemblies with method addresses, field offsets and tokens, plus string literals, generic instantiations and metadata slots for the Il2Cpp tools, cached per user (NDM_IL2CPP_CACHE); " +
                 "the binary is loaded as a native image too. Unreadable metadata is an error with a reason (encrypted_or_obfuscated, unsupported_version, binary_mismatch_or_protected, encrypted_fairplay); unreadable items are listed by reason. " +
                 "Files are read into memory and never locked. The directory joins the reference search path. Loading the same path twice is a no-op. " +
                 "loadProviders=true also loads the DLLs a file's imports bind to (one level, never their own dependencies; at most " +
                 "16 per call), so native_call_tree, find_xrefs and the .NET call tools continue into them.")]
    public Task<string> LoadAssembly(
        [Description("Absolute path to an assembly file or a directory.")] string path,
        [Description("When path is a directory, also load assemblies in subdirectories.")] bool recursive = false,
        [Description("For a file: also load the DLLs its imports bind to, one level deep (at most 16).")] bool loadProviders = false,
        [Description("Universal Mach-O slice (name or index; default arm64e, arm64, x86_64), or an Android Il2Cpp game's ABI (default arm64-v8a).")] string? slice = null,
        RequestContext<CallToolRequestParams> context = null!, // bound by the SDK
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, progress => Task.Run(() =>
    {
        var requestedSlice = string.IsNullOrWhiteSpace(slice) ? null : slice.Trim();
        if (RawIl2CppGame(path, requestedSlice) is { } game)
        {
            int step = 0;
            var result = (il2cppRaw ?? new Il2CppRawLoader(workspace)).Load(game, loadBinary: true,
                m => progress?.Report(new ProgressNotificationValue { Progress = ++step, Message = $"Il2Cpp: {m}" }), cancellationToken);
            return Il2CppRawLoader.Describe(result);
        }
        if (!Directory.Exists(path))
        {
            var (loaded, native) = workspace.LoadAny(path, requestedSlice);
            var providers = loadProviders && link != null && (native == null || native.Pe != null) ? Providers(loaded, native) : "";
            if (native != null && loaded == null)
            {
                var image = native.Image;
                return $"Loaded native image {native.Id}: {Native.NativeImageExtensions.KindText(image)}\n  {native.FilePath}\n  " +
                       $"{Plural(image.Sections.Count, "section")}, {Plural(image.Imports.Count, "import")}, {Plural(image.Exports.Count, "export")}" +
                       (image.RuntimeFunctions.Count > 0 ? $", {Plural(image.RuntimeFunctions.Count, "unwind entry")}" : "") +
                       (image.Issues.Count > 0 ? $"\n  {Plural(image.Issues.Count, "parse issue")} (get_pe_info lists them)" : "") + providers +
                       (Il2CppMetadataNear(native.FilePath) is { } metadata
                           ? $"\n  Il2Cpp game: its metadata is {metadata}; load_assembly that file (or the game folder) reads it with the built-in reader " +
                             "(dummy assemblies, addresses, field offsets, string literals), or apply_il2cpp_names on this image does it"
                           : "");
            }
            return workspace.Read(() =>
            {
                // Looked up again under the lock: a concurrent reload or unload may have replaced the loaded entry.
                var asm = workspace.FindByPath(loaded!.FilePath)
                          ?? throw new ToolError(ErrorCode.Conflict, $"{loaded.Id} was unloaded by another call right after loading.", "repeat load_assembly");
                var types = MetadataUtil.CountedTypes(asm.Module);
                return $"Loaded {asm.Id}: {asm.FullAssemblyName}\n  {asm.FilePath}\n  {types.Count} types, " +
                       $"{MetadataUtil.NamespaceCount(types)} namespaces" +
                       (il2cpp.GetIndex(asm).Count > 0 ? "\n  Il2Cpp dummy DLL: method bodies are stubs; use get_il2cpp_info / find_method_by_address." : "") +
                       (native != null ? $"\n  mixed-mode (C++/CLI): its native code is also loaded as native image {native.Id} for the native tools" : "") + providers;
            });
        }

        var report = workspace.LoadDirectory(path, recursive, (done, total, file) => Report(progress, done, total, $"Loading {Path.GetFileName(file)}"));
        return FormatLoad(workspace, path, report);
    }, cancellationToken));

    /// <summary>
    /// The Il2Cpp game a load_assembly path names: a global-metadata.dat, a game folder (Windows, Linux, macOS .app,
    /// extracted Android package, iOS .app) or both files side by side, or an .apk / .xapk / .apks / .aab / .ipa holding
    /// one (extracted to the cache). A game binary alone loads as a native image.
    /// </summary>
    internal static Il2CppGameFiles? RawIl2CppGame(string path, string? slice)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        string full;
        try { full = Path.GetFullPath(path); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
        if (Il2CppPackages.IsPackage(full))
        {
            var root = Il2CppPackages.Extract(full, slice);
            return root == null ? null : (Il2CppGameFiles.Find(root, slice) ?? throw new ToolError(ErrorCode.NotFound, $"{full} holds Il2Cpp metadata but no game binary.")) with { Package = full };
        }
        if (File.Exists(full)) return Il2CppGameFiles.IsMetadataFile(full) ? Il2CppGameFiles.Find(full, slice) : null;
        if (!Directory.Exists(full)) return null;
        try { return Il2CppGameFiles.Find(full, slice); }
        catch (ToolError e) when (e.Code == ErrorCode.NotFound) { return null; } // half a game: an ordinary folder load, with the layout hints
    }

    /// <summary>The metadata of the Il2Cpp game whose binary is at <paramref name="binary"/>, or null.</summary>
    private static string? Il2CppMetadataNear(string binary)
    {
        if (!Il2CppGameFiles.BinaryNames.Any(n => n.Equals(Path.GetFileName(binary), StringComparison.OrdinalIgnoreCase))) return null;
        try { return Il2CppGameFiles.Find(binary)?.Metadata; }
        catch (ToolError) { return null; }
    }

    /// <summary>Loads the provider DLLs of a loaded file's imports (native) or P/Invoke declarations (.NET), one level.</summary>
    private string Providers(LoadedAssembly? assembly, LoadedNative? native)
    {
        var bindings = workspace.Read(() => native != null ? link!.BindAll(native).ToList() : assembly != null ? link!.PInvokeBindings(assembly).ToList() : []);
        var (loaded, skipped) = link!.LoadProviders(bindings, NativeLinkService.MaxProvidersPerCall);
        var sb = new StringBuilder($"\n  providers: loaded {(loaded.Count > 0 ? string.Join(", ", loaded) : "none")}");
        int already = bindings.Where(b => b.Status == NativeLinkService.Bound).Select(b => b.Target!.Id).Distinct().Count();
        if (already > 0) sb.Append($"; {Plural(already, "provider")} already loaded");
        if (skipped.Count > 0) sb.Append($"; not loaded ({skipped.Count}): {string.Join(", ", skipped.Take(20))}");
        int unresolved = bindings.Count(b => b.Status == NativeLinkService.Unresolved);
        if (unresolved > 0) sb.Append($"; {Plural(unresolved, "binding")} unresolved (list_imports bind=true / verify_native_imports say why)");
        return sb.ToString();
    }

    /// <summary>Folder load summary: loaded assemblies, skipped native and damaged files, Unity layout hints.</summary>
    internal static string FormatLoad(AssemblyWorkspace workspace, string path, AssemblyWorkspace.LoadReport report)
    {
        var sb = new StringBuilder($"Loaded {Plural(report.Loaded.Count, "assembly")} from {Path.GetFullPath(path)}");
        if (report.Skipped.Count > 0) sb.Append($"; skipped {report.Skipped.Count} non-.NET/unreadable file(s)");
        sb.AppendLine(".");
        workspace.Read(() =>
        {
            foreach (var a in report.Loaded)
                sb.AppendLine($"  {a.Id}  ({MetadataUtil.CountedTypes(a.Module).Count} types)");
            return 0;
        });
        // Native files are summarized on one line; other failures are listed individually.
        var native = report.Skipped.Where(s => s.Error.Contains(".NET data directory", StringComparison.Ordinal)
                                               || s.Error.Contains("Invalid DOS signature", StringComparison.Ordinal)).ToList();
        if (native.Count > 0)
            sb.AppendLine($"  skipped {Plural(native.Count, "native or non-PE file")}: " +
                          string.Join(", ", native.Take(15).Select(s => Path.GetFileName(s.Path))) + (native.Count > 15 ? $", … {native.Count - 15} more" : ""));
        var damaged = report.Skipped.Except(native).ToList();
        foreach (var (file, error) in damaged.Take(20))
            sb.AppendLine($"  skipped {Path.GetFileName(file)}: {Format.Clip(error, 160)}");
        if (damaged.Count > 20) sb.AppendLine($"  … {damaged.Count - 20} more skipped");
        foreach (var hint in Services.Analysis.UnityLayout.FolderHints(path))
            sb.AppendLine($"Note: {hint}");
        return sb.ToString();
    }

    [McpServerTool(Name = "list_assemblies", Title = "List loaded assemblies", UseStructuredContent = true)]
    [Description("Loaded assemblies with their ids (use the id in other tools), versions, paths, whether they are Il2Cpp dummy DLLs, " +
                 "ReadyToRun (precompiled native code next to the IL), merged (ILMerge / ILRepack output, with the original module count), " +
                 "and unsaved edits (paged: filter, offset, limit — total has the full count); plus the reference search directories. Pass path instead to list the managed assemblies inside a " +
                 "container file (single-file bundle, .nupkg, .apk / .aab, Costura host, zip) without extracting or loading them " +
                 "(only the container is listed then, not the workspace, paged the same way); unpack_container extracts and loads them.")]
    public Task<WorkspaceState> ListAssemblies(
        [Description("Optional: a container file whose managed assemblies to list (a plain assembly lists itself).")] string? path = null,
        [Description("Only assemblies whose id, name or path contains this text (case-insensitive).")] string? filter = null,
        [Description("Index of the first assembly to return.")] int offset = 0,
        [Description("Max assemblies to return (default 100; total has the full count).")] int limit = 100,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        var container = path == null ? null : unpacker.List(path, AnalysisLimits.Default, cancellationToken, filter, offset, limit);
        if (container != null) // container listing only; the workspace is omitted
            return new WorkspaceState([], [], indexing.Status, container) { Total = container.Total };
        return workspace.Read(() =>
        {
            var matching = workspace.Assemblies.Where(a => filter == null || a.Id.Contains(filter, StringComparison.OrdinalIgnoreCase)
                                                           || a.FullAssemblyName.Contains(filter, StringComparison.OrdinalIgnoreCase)
                                                           || a.FilePath.Contains(filter, StringComparison.OrdinalIgnoreCase)).ToList();
            return new WorkspaceState(
                matching.Skip(Math.Max(0, offset)).Take(ClampLimit(limit, 1000)).Select(a => new AssemblyEntry(a.Id, a.FullAssemblyName,
                    a.Module.Assembly?.Version?.ToString() ?? "", a.FilePath, MetadataUtil.CountedTypes(a.Module).Count, il2cpp.GetIndex(a).Count > 0,
                    a.Edits.Select(e => e.Description).ToList(), AssemblyTraits.IsReadyToRun(a.OriginalBytes), AssemblyTraits.MergeNote(a.Module))).ToList(),
                workspace.SearchDirectories,
                indexing.Status,
                container)
            {
                Total = matching.Count,
                NativeImages = workspace.Natives.Where(n => filter == null || n.Id.Contains(filter, StringComparison.OrdinalIgnoreCase)
                                                            || n.FilePath.Contains(filter, StringComparison.OrdinalIgnoreCase))
                    .Select(n => new NativeEntry(n.Id, n.FilePath, n.Image.MachineName, (n.Image.IsDll ? "dll" : "exe") + (n.ManagedView != null ? $" (native view of mixed-mode assembly {n.ManagedView.Id})" : ""), n.Image.FileSize, n.Image.Sha256)
                    {
                        Slices = n.Image is Native.MachO.MachOFile { Slices.Count: > 0 } m ? [.. m.Slices.Select(x => x.Name)] : null,
                    }).ToList(),
            };
        });
    }, cancellationToken);

    [McpServerTool(Name = "unload_assembly", Title = "Unload assembly")]
    [Description("Remove an assembly from the workspace (unsaved edits are discarded).")]
    public Task<string> UnloadAssembly([Description(AssemblyDescription)] string assembly, CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            if (workspace.Read(() => workspace.FindNative(assembly)) is { ManagedView: null } native)
            {
                workspace.UnloadNative(native);
                return $"Unloaded {native.Id}.";
            }
            var asm = workspace.Read(() => workspace.Get(assembly));
            int edits = asm.Edits.Count;
            workspace.Unload(asm);
            return $"Unloaded {asm.Id}{(edits > 0 ? $" (discarded {Plural(edits, "unsaved edit")})" : "")}.";
        }, cancellationToken);

    [McpServerTool(Name = "reload_assembly", Title = "Reload assembly")]
    [Description("Re-read an assembly from disk (e.g. after an update or after save_assembly overwrote it), discarding unsaved in-memory edits.")]
    public Task<string> ReloadAssembly([Description(AssemblyDescription)] string assembly, CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            if (workspace.Read(() => workspace.FindNative(assembly)) is { ManagedView: null } native)
            {
                var reloaded = workspace.ReloadNative(native);
                return $"Reloaded {reloaded.Id} from {reloaded.FilePath} (sha256 {reloaded.Image.Sha256[..16]}).";
            }
            var asm = workspace.Read(() => workspace.Get(assembly));
            var fresh = workspace.Reload(asm);
            return $"Reloaded {fresh.Id} from {fresh.FilePath}.";
        }, cancellationToken);

    [McpServerTool(Name = "add_search_directory", Title = "Add reference search directory")]
    [Description("Add a directory for resolving referenced assemblies that are not loaded (an application folder, a framework directory). Improves decompilation, cross-assembly navigation and C# patching.")]
    public Task<string> AddSearchDirectory([Description("Directory path.")] string directory, CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            workspace.AddSearchDirectory(directory);
            var full = Path.GetFullPath(directory);
            var text = $"Added {full}. Search directories:\n  " + string.Join("\n  ", workspace.Read(() => workspace.SearchDirectories));
            // Search directories are not recursive; suggest subfolders when the directory itself has no assemblies.
            static bool HasAssemblies(string dir) =>
                new[] { "*.dll", "*.exe", "*.winmd" }.Any(p => { try { return Directory.EnumerateFiles(dir, p).Any(); } catch (IOException) { return false; } catch (UnauthorizedAccessException) { return false; } });
            if (Directory.Exists(full) && !HasAssemblies(full))
            {
                string[] subfolders;
                try { subfolders = Directory.GetDirectories(full).Where(HasAssemblies).OrderByDescending(d => d, StringComparer.OrdinalIgnoreCase).Take(5).ToArray(); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { subfolders = []; }
                text += $"\nNote: {full} has no assemblies itself; subfolders are not searched." +
                        (subfolders.Length > 0 ? " Add one of these instead:\n  " + string.Join("\n  ", subfolders) : "");
            }
            return text;
        }, cancellationToken);

    [McpServerTool(Name = "get_assembly_info", Title = "Assembly overview", UseStructuredContent = true, OutputSchemaType = typeof(AssemblyReport.Summary))]
    [Description("Assembly overview: identity (MVID, file SHA-256), target framework, entry point, counts, references (and whether each resolves), PE headers and sections, metadata streams, table row counts and heap sizes, metadata problems (every bad table, coded or heap index, with file offsets), assembly attributes, Il2Cpp detection, invalid IL bodies and exception clauses, unsaved edits.")]
    public Task<string> GetAssemblyInfo([Description(AssemblyDescription)] string assembly, CancellationToken cancellationToken = default) =>
        Read(workspace, () =>
        {
            var text = report.Build(workspace.Get(assembly), out var summary);
            return StructuredOutput.With(text, summary);
        }, cancellationToken);
}
