using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class WorkspaceTools(AssemblyWorkspace workspace, Il2CppService il2cpp, AssemblyReport report)
{
    public sealed record AssemblyEntry(string Id, string Name, string Version, string Path, int Types, bool Il2CppDummy, IReadOnlyList<string> UnsavedEdits);

    public sealed record WorkspaceState(IReadOnlyList<AssemblyEntry> Assemblies, IReadOnlyList<string> SearchDirectories);

    [McpServerTool(Name = "load_assembly", Title = "Load assembly", Idempotent = true, OpenWorld = false)]
    [Description("Load a .NET assembly (.dll/.exe) or every assembly in a directory (e.g. a Unity game's *_Data/Managed or an Il2CppDumper DummyDll folder). " +
                 "Files are read into memory and never locked. The directory joins the reference search path. Loading the same path twice is a no-op.")]
    public Task<string> LoadAssembly(
        [Description("Absolute path to an assembly file or a directory.")] string path,
        [Description("When path is a directory, also load assemblies in subdirectories.")] bool recursive = false,
        IProgress<ProgressNotificationValue>? progress = null,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        if (!Directory.Exists(path))
        {
            var asm = workspace.Load(path);
            return workspace.Read(() =>
            {
                var types = asm.Module.GetTypes().ToList();
                return $"Loaded {asm.Id}: {asm.FullAssemblyName}\n  {asm.FilePath}\n  {types.Count} types, " +
                       $"{types.Select(t => t.Namespace.String).Distinct().Count()} namespaces" +
                       (il2cpp.GetIndex(asm).Count > 0 ? "\n  Il2Cpp dummy DLL: method bodies are stubs; use get_il2cpp_info / find_method_by_address." : "");
            });
        }

        var report = workspace.LoadDirectory(path, recursive, (done, total, file) => Report(progress, done, total, $"Loading {Path.GetFileName(file)}"));
        var sb = new StringBuilder($"Loaded {Plural(report.Loaded.Count, "assembly")} from {Path.GetFullPath(path)}");
        if (report.Skipped.Count > 0) sb.Append($"; skipped {report.Skipped.Count} non-.NET/unreadable file(s)");
        sb.AppendLine(".");
        workspace.Read(() =>
        {
            foreach (var a in report.Loaded)
                sb.AppendLine($"  {a.Id}  ({a.Module.GetTypes().Count()} types)");
            return 0;
        });
        foreach (var (file, error) in report.Skipped.Take(20))
            sb.AppendLine($"  skipped {Path.GetFileName(file)}: {Format.Clip(error, 160)}");
        if (report.Skipped.Count > 20) sb.AppendLine($"  … {report.Skipped.Count - 20} more skipped");
        return sb.ToString();
    }, cancellationToken);

    [McpServerTool(Name = "list_assemblies", Title = "List loaded assemblies", ReadOnly = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Loaded assemblies with their ids (use the id in other tools), versions, paths, whether they are Il2Cpp dummy DLLs, and unsaved edits; plus the reference search directories.")]
    public Task<WorkspaceState> ListAssemblies(CancellationToken cancellationToken = default) => Task.Run(() => workspace.Read(() =>
        new WorkspaceState(
            workspace.Assemblies.Select(a => new AssemblyEntry(a.Id, a.FullAssemblyName, a.Module.Assembly?.Version?.ToString() ?? "", a.FilePath,
                a.Module.GetTypes().Count(), il2cpp.GetIndex(a).Count > 0, a.Edits.ToList())).ToList(),
            workspace.SearchDirectories)), cancellationToken);

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
    [Description("Re-read an assembly from disk (e.g. after a game update or after save_assembly overwrote it), discarding unsaved in-memory edits.")]
    public Task<string> ReloadAssembly([Description(AssemblyDescription)] string assembly, CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            var asm = workspace.Read(() => workspace.Get(assembly));
            var fresh = workspace.Reload(asm);
            return $"Reloaded {fresh.Id} from {fresh.FilePath}.";
        }, cancellationToken);

    [McpServerTool(Name = "add_search_directory", Title = "Add reference search directory", Idempotent = true, OpenWorld = false)]
    [Description("Add a directory for resolving referenced assemblies that are not loaded (a game's Managed folder, a framework directory). Improves decompilation, cross-assembly navigation and C# patching.")]
    public Task<string> AddSearchDirectory([Description("Directory path.")] string directory, CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            workspace.AddSearchDirectory(directory);
            return $"Added {Path.GetFullPath(directory)}. Search directories:\n  " + string.Join("\n  ", workspace.Read(() => workspace.SearchDirectories));
        }, cancellationToken);

    [McpServerTool(Name = "get_assembly_info", Title = "Assembly overview", ReadOnly = true, OpenWorld = false)]
    [Description("Assembly overview: identity, target framework, entry point, counts, references (and whether each resolves), PE headers and sections, metadata streams, assembly attributes, Il2Cpp detection, unsaved edits.")]
    public Task<string> GetAssemblyInfo([Description(AssemblyDescription)] string assembly, CancellationToken cancellationToken = default) =>
        Read(workspace, () => report.Build(workspace.Get(assembly)), cancellationToken);
}
