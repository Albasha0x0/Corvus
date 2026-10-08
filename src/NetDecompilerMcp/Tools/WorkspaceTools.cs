using System.ComponentModel;
using System.Text;
using System.Text.Json.Serialization;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Services.Analysis;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class WorkspaceTools(AssemblyWorkspace workspace, Il2CppService il2cpp, AssemblyReport report, IndexingService indexing, UnpackService unpacker)
{
    public sealed record AssemblyEntry(string Id, string Name, string Version, string Path, int Types, bool Il2CppDummy, IReadOnlyList<string> UnsavedEdits,
        bool ReadyToRun, string? Merged);

    /// <summary>Workspace listing, or the container contents when list_assemblies is given a path.</summary>
    public sealed record WorkspaceState(IReadOnlyList<AssemblyEntry> Assemblies, IReadOnlyList<string> SearchDirectories, string BackgroundIndexing,
        UnpackService.ContainerListing? Container = null)
    {
        /// <summary>Count of assemblies matching the filter; Assemblies holds one page.</summary>
        public int Total { get; init; }
    }

    [McpServerTool(Name = "load_assembly", Title = "Load assembly", Idempotent = true, OpenWorld = false)]
    [Description("Load a .NET assembly (.dll/.exe) or every assembly in a directory (e.g. an application folder, a Unity *_Data/Managed folder or an Il2CppDumper DummyDll folder). " +
                 "Files are read into memory and never locked. The directory joins the reference search path. Loading the same path twice is a no-op.")]
    public Task<string> LoadAssembly(
        [Description("Absolute path to an assembly file or a directory.")] string path,
        [Description("When path is a directory, also load assemblies in subdirectories.")] bool recursive = false,
        RequestContext<CallToolRequestParams> context = null!, // bound by the SDK
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, progress => Task.Run(() =>
    {
        if (!Directory.Exists(path))
        {
            var asm = workspace.Load(path);
            return workspace.Read(() =>
            {
                var types = MetadataUtil.CountedTypes(asm.Module);
                return $"Loaded {asm.Id}: {asm.FullAssemblyName}\n  {asm.FilePath}\n  {types.Count} types, " +
                       $"{MetadataUtil.NamespaceCount(types)} namespaces" +
                       (il2cpp.GetIndex(asm).Count > 0 ? "\n  Il2Cpp dummy DLL: method bodies are stubs; use get_il2cpp_info / find_method_by_address." : "");
            });
        }

        var report = workspace.LoadDirectory(path, recursive, (done, total, file) => Report(progress, done, total, $"Loading {Path.GetFileName(file)}"));
        return FormatLoad(workspace, path, report);
    }, cancellationToken));

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

    [McpServerTool(Name = "list_assemblies", Title = "List loaded assemblies", ReadOnly = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Loaded assemblies with their ids (use the id in other tools), versions, paths, whether they are Il2Cpp dummy DLLs, " +
                 "ReadyToRun (precompiled native code next to the IL), merged (ILMerge / ILRepack output, with the original module count), " +
                 "and unsaved edits (paged: filter, offset, limit — total has the full count); plus the reference search directories. Pass path instead to list the managed assemblies inside a " +
                 "container file (single-file bundle, .nupkg, .apk / .aab, Costura host, zip) without extracting or loading them " +
                 "(only the container is listed then, not the workspace); unpack_container extracts and loads them.")]
    public Task<WorkspaceState> ListAssemblies(
        [Description("Optional: a container file whose managed assemblies to list (a plain assembly lists itself).")] string? path = null,
        [Description("Only loaded assemblies whose id, name or path contains this text (case-insensitive).")] string? filter = null,
        [Description("Index of the first loaded assembly to return.")] int offset = 0,
        [Description("Max loaded assemblies to return (default 100; total has the full count).")] int limit = 100,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        var container = path == null ? null : unpacker.List(path, AnalysisLimits.Default, cancellationToken);
        if (container != null) // container listing only; the workspace is omitted
            return new WorkspaceState([], [], indexing.Status, container);
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
                container) { Total = matching.Count };
        });
    }, cancellationToken);

    [McpServerTool(Name = "unload_assembly", Title = "Unload assembly", Idempotent = true, OpenWorld = false)]
    [Description("Remove an assembly from the workspace (unsaved edits are discarded).")]
    public Task<string> UnloadAssembly([Description(AssemblyDescription)] string assembly, CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            var asm = workspace.Read(() => workspace.Get(assembly));
            int edits = asm.Edits.Count;
            workspace.Unload(asm);
            return $"Unloaded {asm.Id}{(edits > 0 ? $" (discarded {Plural(edits, "unsaved edit")})" : "")}.";
        }, cancellationToken);

    [McpServerTool(Name = "reload_assembly", Title = "Reload assembly", OpenWorld = false)]
    [Description("Re-read an assembly from disk (e.g. after an update or after save_assembly overwrote it), discarding unsaved in-memory edits.")]
    public Task<string> ReloadAssembly([Description(AssemblyDescription)] string assembly, CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            var asm = workspace.Read(() => workspace.Get(assembly));
            var fresh = workspace.Reload(asm);
            return $"Reloaded {fresh.Id} from {fresh.FilePath}.";
        }, cancellationToken);

    [McpServerTool(Name = "add_search_directory", Title = "Add reference search directory", Idempotent = true, OpenWorld = false)]
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

    [McpServerTool(Name = "get_assembly_info", Title = "Assembly overview", ReadOnly = true, OpenWorld = false)]
    [Description("Assembly overview: identity, target framework, entry point, counts, references (and whether each resolves), PE headers and sections, metadata streams, assembly attributes, Il2Cpp detection, unsaved edits.")]
    public Task<string> GetAssemblyInfo([Description(AssemblyDescription)] string assembly, CancellationToken cancellationToken = default) =>
        Read(workspace, () => report.Build(workspace.Get(assembly)), cancellationToken);
}
