using System.ComponentModel;
using System.Text;
using System.Text.Json.Serialization;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using Corvus.Services.Analysis;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class WorkspaceTools(AssemblyWorkspace workspace, Il2CppService il2cpp, IndexingService indexing, UnpackService unpacker,
    NativeLinkService? link = null, Il2CppRawLoader? il2cppRaw = null)
{
    /// <summary>
    /// A list_assemblies row: a loaded assembly or native image, or with path an assembly or file inside the container;
    /// fields that do not apply to the kind are absent.
    /// </summary>
    public sealed record WorkspaceEntry(
        [property: Description("assembly, native, contained (an assembly inside the container) or file (an archive entry).")] string Kind,
        [property: Description("The id other tools take; absent inside a container.")] string? Id,
        string Path)
    {
        public string? Name { get; init; }
        public string? Version { get; init; }
        public int? Types { get; init; }
        public bool? Il2CppDummy { get; init; }
        public bool? ReadyToRun { get; init; }
        [Description("ILMerge / ILRepack note.")] public string? Merged { get; init; }
        public IReadOnlyList<string>? UnsavedEdits { get; init; }
        public string? Machine { get; init; }
        [Description("dll or exe, and the mixed-mode assembly a native view belongs to.")] public string? FileKind { get; init; }
        public long? Size { get; init; }
        public string? Sha256 { get; init; }
        [Description("Universal Mach-O: every slice (load_assembly slice= loads another).")] public IReadOnlyList<string>? Slices { get; init; }
        [Description("Where inside the container it was found.")] public string? Origin { get; init; }
        public string? Detail { get; init; }
    }

    /// <summary>list_assemblies' record: one page of rows; with path, the container's source, kind and notes.</summary>
    public sealed record WorkspaceList(IReadOnlyList<WorkspaceEntry> Items, int Offset, int Total, IReadOnlyList<string> SearchDirectories, string BackgroundIndexing,
        UnpackService.ContainerListing? Container = null);

    /// <summary>The record of load, unload, reload and add_search_directory: the ids the call loaded, unloaded or reloaded, and its text.</summary>
    public sealed record WorkspaceChange(IReadOnlyList<string> Ids, string Text);

    private static string Changed(IEnumerable<string> ids, string text) => ToolOutput.With(text, new WorkspaceChange([.. ids], text));

    [McpServerTool(Name = "load_assembly", Title = "Load assembly", UseStructuredContent = true, OutputSchemaType = typeof(WorkspaceChange))]
    [Description("Load a .NET assembly (.dll/.exe) or every assembly in a directory (application folder, Unity *_Data/Managed, DummyDll folder). " +
                 "A native PE, ELF or Mach-O file loads as a native image (universal Mach-O: one slice, as name[slice]); folder loads skip native files. " +
                 "An Il2Cpp game (folder or global-metadata.dat, .apk/.xapk/.aab/.ipa, iOS .app, memory dump) is read by the built-in metadata " +
                 "reader (v24-39): dummy assemblies with addresses, offsets and tokens, plus the binary as a native image. Files are read into " +
                 "memory, never locked; loading a path twice is a no-op.")]
    public Task<string> LoadAssembly(
        [Description("Absolute path to an assembly file or a directory.")] string path,
        [Description("When path is a directory, also load assemblies in subdirectories.")] bool recursive = false,
        [Description("For a file: also load the DLLs its imports bind to (one level, at most 16), so the call tools continue into them.")] bool loadProviders = false,
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
            return Changed(result.Load.Loaded.Select(a => a.Id).Concat(result.Binary != null ? [result.Binary.Id] : []), Il2CppRawLoader.Describe(result));
        }
        if (!Directory.Exists(path))
        {
            var (loaded, native) = workspace.LoadAny(path, requestedSlice);
            var providers = loadProviders && link != null && (native == null || native.Pe != null) ? Providers(loaded, native) : "";
            if (native != null && loaded == null)
            {
                var image = native.Image;
                return Changed([native.Id], $"Loaded native image {native.Id}: {Native.NativeImageExtensions.KindText(image)}\n  {native.FilePath}\n  " +
                       $"{Plural(image.Sections.Count, "section")}, {Plural(image.Imports.Count, "import")}, {Plural(image.Exports.Count, "export")}" +
                       (image.RuntimeFunctions.Count > 0 ? $", {Plural(image.RuntimeFunctions.Count, "unwind entry")}" : "") +
                       (image.Issues.Count > 0 ? $"\n  {Plural(image.Issues.Count, "parse issue")} (get_pe_info lists them)" : "") + providers +
                       (Il2CppMetadataNear(native.FilePath) is { } metadata
                           ? $"\n  Il2Cpp game: its metadata is {metadata}; load_assembly that file (or the game folder) reads it with the built-in reader " +
                             "(dummy assemblies, addresses, field offsets, string literals), or apply_il2cpp_names on this image does it"
                           : ""));
            }
            return workspace.Read(() =>
            {
                // Looked up again under the lock: a concurrent reload or unload may have replaced the loaded entry.
                var asm = workspace.FindByPath(loaded!.FilePath)
                          ?? throw new ToolError(ErrorCode.Conflict, $"{loaded.Id} was unloaded by another call right after loading.", "repeat load_assembly");
                var types = MetadataUtil.CountedTypes(asm.Module);
                return Changed(native != null ? [asm.Id, native.Id] : [asm.Id], $"Loaded {asm.Id}: {asm.FullAssemblyName}\n  {asm.FilePath}\n  {types.Count} types, " +
                       $"{MetadataUtil.NamespaceCount(types)} namespaces" +
                       (il2cpp.GetIndex(asm).Count > 0 ? "\n  Il2Cpp dummy DLL: method bodies are stubs; use get_il2cpp_info / find_method_by_address." : "") +
                       (native != null ? $"\n  mixed-mode (C++/CLI): its native code is also loaded as native image {native.Id} for the native tools" : "") + providers);
            });
        }

        var report = workspace.LoadDirectory(path, recursive, (done, total, file) => Report(progress, done, total, $"Loading {Path.GetFileName(file)}"));
        return Changed(report.Loaded.Select(a => a.Id), FormatLoad(workspace, path, report));
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
            var root = Il2CppPackages.Extract(full, slice)
                       ?? throw new ToolError(ErrorCode.NotFound, $"{full} is a package without Il2Cpp metadata (no global-metadata.dat): reason no_il2cpp_metadata.",
                           "summarize_file tells what it holds; list_assemblies with path lists the .NET assemblies a Xamarin / MAUI / Unity Mono package carries");
            return (Il2CppGameFiles.Find(root, slice) ?? throw new ToolError(ErrorCode.NotFound, $"{full} holds Il2Cpp metadata but no game binary.")) with { Package = full };
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
        if (Webcil.FolderHint(path) is { } webcil)
            sb.AppendLine($"Note: {webcil}");
        return sb.ToString();
    }

    [McpServerTool(Name = "list_assemblies", Title = "List loaded assemblies", UseStructuredContent = true, OutputSchemaType = typeof(WorkspaceList))]
    [Description("Loaded assemblies and native images with their ids (for other tools), versions, paths, Il2Cpp dummy, ReadyToRun and merged (ILMerge / ILRepack) flags and unsaved edits; " +
                 "plus the reference search directories. With path: the managed assemblies inside a container file (single-file bundle, .nupkg, .apk / .aab, " +
                 "Costura host, zip) without extracting them (unpack_container extracts and loads them); archives (Electron .asar with integrity verdicts, Unity WebGL .data, HAR / mitmproxy captures) list their files.")]
    public Task<string> ListAssemblies(
        [Description("A container file (or Blazor _framework folder) to list instead of the workspace.")] string? path = null,
        [Description("Id, name or path substring (case-insensitive).")] string? filter = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Rows per page (default 100).")] int limit = 100,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        offset = Math.Max(0, offset);
        limit = ClampLimit(limit, 1000);
        if (path != null)
        {
            var c = unpacker.List(path, AnalysisLimits.Default, cancellationToken, filter, offset, limit);
            // An archive's rows are its files; any other container's are the assemblies inside.
            var rows = c.Files is { } files
                ? files.Select(f => new WorkspaceEntry("file", null, f.Path) { Size = f.Size, Detail = f.Detail }).ToList()
                : c.Assemblies.Select(x => new WorkspaceEntry("contained", null, x.Path)
                {
                    Name = x.Name, Version = x.Version, Size = x.Size, Sha256 = x.Sha256, Origin = x.Origin, ReadyToRun = x.ReadyToRun ? true : null, Merged = x.Merged,
                }).ToList();
            int total = c.Files != null ? c.FileTotal ?? rows.Count : c.Total;
            var container = c with { Assemblies = c.Files != null ? c.Assemblies : [], Files = null, FileTotal = null };
            var header = $"{c.Container}: {c.Source}\n" + string.Concat(c.Notes.Select(n => $"Note: {n}\n")) +
                         (c.Files != null && c.Assemblies.Count > 0 ? $"Assemblies inside: {string.Join(", ", c.Assemblies.Select(x => x.Path))}\n" : "");
            return ToolOutput.List(rows, offset, limit, total, Row, page => new WorkspaceList(page, offset, total, [], indexing.Status, container),
                c.Files != null ? "file" : "assembly", header);
        }
        var (all, directories) = workspace.Read(() =>
        {
            bool Match(string id, string? name, string file) => filter == null || id.Contains(filter, StringComparison.OrdinalIgnoreCase)
                || name?.Contains(filter, StringComparison.OrdinalIgnoreCase) == true || file.Contains(filter, StringComparison.OrdinalIgnoreCase);
            var assemblies = workspace.Assemblies.Where(a => Match(a.Id, a.FullAssemblyName, a.FilePath)).ToList();
            var natives = workspace.Natives.Where(n => Match(n.Id, null, n.FilePath)).ToList();
            // Rows are built for the page only: type counts and trait probes read each module.
            var rows = new List<WorkspaceEntry>();
            int index = 0;
            foreach (var a in assemblies)
            {
                if (index++ < offset || rows.Count >= limit) continue;
                rows.Add(new WorkspaceEntry("assembly", a.Id, a.FilePath)
                {
                    Name = a.FullAssemblyName, Version = a.Module.Assembly?.Version?.ToString() ?? "", Types = MetadataUtil.CountedTypes(a.Module).Count,
                    Il2CppDummy = il2cpp.GetIndex(a).Count > 0 ? true : null, ReadyToRun = AssemblyTraits.IsReadyToRun(a.OriginalBytes) ? true : null,
                    Merged = AssemblyTraits.MergeNote(a.Module), UnsavedEdits = a.Edits.Count > 0 ? [.. a.Edits.Select(e => e.Description)] : null,
                });
            }
            foreach (var n in natives)
            {
                if (index++ < offset || rows.Count >= limit) continue;
                rows.Add(new WorkspaceEntry("native", n.Id, n.FilePath)
                {
                    Machine = n.Image.MachineName, FileKind = (n.Image.IsDll ? "dll" : "exe") + (n.ManagedView != null ? $", native view of {n.ManagedView.Id}" : ""),
                    Size = n.Image.FileSize, Sha256 = n.Image.Sha256,
                    Slices = n.Image is Native.MachO.MachOFile { Slices.Count: > 0 } m ? [.. m.Slices.Select(x => x.Name)] : null,
                });
            }
            return ((rows, assemblies.Count + natives.Count, natives.Count == 0), workspace.SearchDirectories.ToList());
        });
        var (page, count, onlyAssemblies) = all;
        var head = $"Search directories: {(directories.Count == 0 ? "none" : string.Join("; ", directories))}\nBackground indexing: {indexing.Status}\n";
        // a native image or a mix counts as images (.NET assemblies are PE images too)
        return ToolOutput.List(page, offset, limit, count, Row, rows => new WorkspaceList(rows, offset, count, directories, indexing.Status),
            onlyAssemblies ? "assembly" : "image", head);
    }, cancellationToken);

    private static string Row(WorkspaceEntry e) => e.Kind switch
    {
        "assembly" => $"{e.Id}  {e.Version}, {e.Types} types" + (e.Il2CppDummy == true ? ", Il2Cpp dummy" : "") + (e.ReadyToRun == true ? ", ReadyToRun" : "") +
                      (e.Merged != null ? ", merged" : "") + (e.UnsavedEdits is { Count: > 0 } u ? $", {Plural(u.Count, "unsaved edit")}" : "") + $"  {e.Path}",
        "native" => $"{e.Id}  native {e.Machine} {e.FileKind}, {e.Size:N0} bytes" + (e.Slices != null ? $", slices {string.Join(", ", e.Slices)}" : "") + $"  {e.Path}",
        "contained" => $"{e.Path}  {e.Name} {e.Version}, {e.Size:N0} bytes, {e.Origin}" + (e.ReadyToRun == true ? ", ReadyToRun" : "") + (e.Merged != null ? ", merged" : ""),
        _ => $"{e.Path}  {e.Size:N0} bytes" + (e.Detail != null ? $", {e.Detail}" : ""),
    };

    [McpServerTool(Name = "unload_assembly", Title = "Unload assembly", UseStructuredContent = true, OutputSchemaType = typeof(WorkspaceChange))]
    [Description("Remove an assembly from the workspace (unsaved edits are discarded).")]
    public Task<string> UnloadAssembly([Description(AssemblyDescription)] string assembly, CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            if (workspace.Read(() => workspace.FindNative(assembly)) is { ManagedView: null } native)
            {
                workspace.UnloadNative(native);
                return Changed([native.Id], $"Unloaded {native.Id}.");
            }
            var asm = workspace.Read(() => workspace.Get(assembly));
            int edits = asm.Edits.Count;
            workspace.Unload(asm);
            return Changed([asm.Id], $"Unloaded {asm.Id}{(edits > 0 ? $" (discarded {Plural(edits, "unsaved edit")})" : "")}.");
        }, cancellationToken);

    [McpServerTool(Name = "reload_assembly", Title = "Reload assembly", UseStructuredContent = true, OutputSchemaType = typeof(WorkspaceChange))]
    [Description("Re-read an assembly from disk (after an update or an overwriting save_assembly), discarding unsaved edits.")]
    public Task<string> ReloadAssembly([Description(AssemblyDescription)] string assembly, CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            if (workspace.Read(() => workspace.FindNative(assembly)) is { ManagedView: null } native)
            {
                var reloaded = workspace.ReloadNative(native);
                return Changed([reloaded.Id], $"Reloaded {reloaded.Id} from {reloaded.FilePath} (sha256 {reloaded.Image.Sha256[..16]}).");
            }
            var asm = workspace.Read(() => workspace.Get(assembly));
            var fresh = workspace.Reload(asm);
            return Changed([fresh.Id], $"Reloaded {fresh.Id} from {fresh.FilePath}.");
        }, cancellationToken);

    [McpServerTool(Name = "add_search_directory", Title = "Add reference search directory", UseStructuredContent = true, OutputSchemaType = typeof(WorkspaceChange))]
    [Description("Add a directory for resolving referenced assemblies that are not loaded (an application or framework folder), for decompilation, navigation and C# patching.")]
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
            return Changed([], text);
        }, cancellationToken);
}
