using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class WorkspaceTools(AssemblyWorkspace workspace, Il2CppService il2cpp)
{
    [McpServerTool(Name = "load_assembly", Idempotent = true)]
    [Description("Load a .NET assembly (.dll/.exe) or every assembly in a directory. Files are read into memory, never locked. " +
                 "The file's directory is added to the reference search path. Loading the same path twice is a no-op.")]
    public Task<string> LoadAssembly(
        [Description("Absolute path to an assembly file or a directory.")] string path,
        [Description("When path is a directory, also load assemblies in subdirectories.")] bool recursive = false,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        if (Directory.Exists(path))
        {
            var report = workspace.LoadDirectory(path, recursive);
            var sb = new StringBuilder($"Loaded {Plural(report.Loaded.Count, "assembly")} from {Path.GetFullPath(path)}");
            if (report.Skipped.Count > 0) sb.Append($"; skipped {report.Skipped.Count} non-.NET/unreadable file(s)");
            sb.AppendLine(".");
            foreach (var a in report.Loaded)
                sb.AppendLine($"  {a.Id}  ({a.Module.GetTypes().Count()} types)");
            foreach (var (file, error) in report.Skipped.Take(20))
                sb.AppendLine($"  skipped {Path.GetFileName(file)}: {Format.Clip(error, 160)}");
            return sb.ToString();
        }
        var asm = workspace.Load(path);
        return workspace.Read(() => $"Loaded {asm.Id}: {asm.FullAssemblyName}\n  {asm.FilePath}\n  {asm.Module.GetTypes().Count()} types, " +
                                    $"{asm.Module.GetTypes().Select(t => t.Namespace.String).Distinct().Count()} namespaces");
    }, cancellationToken);

    [McpServerTool(Name = "list_assemblies", ReadOnly = true)]
    [Description("List loaded assemblies with their ids (use the id in other tools), versions, paths and unsaved edits.")]
    public Task<string> ListAssemblies(CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var all = workspace.Assemblies;
        if (all.Count == 0)
            return "No assemblies loaded. Use load_assembly with a file or directory path.";
        var sb = new StringBuilder($"{Plural(all.Count, "assembly")} loaded:\n");
        foreach (var a in all)
        {
            sb.Append($"  {a.Id}  v{a.Module.Assembly?.Version}  {a.FilePath}");
            if (a.IsDirty) sb.Append($"  [UNSAVED: {Plural(a.Edits.Count, "edit")}]");
            sb.AppendLine();
        }
        if (workspace.SearchDirectories.Count > 0)
            sb.AppendLine("Reference search directories:\n  " + string.Join("\n  ", workspace.SearchDirectories));
        return sb.ToString();
    }, cancellationToken);

    [McpServerTool(Name = "unload_assembly", Idempotent = true)]
    [Description("Remove an assembly from the workspace (unsaved edits are discarded).")]
    public Task<string> UnloadAssembly([Description("Assembly id, name or path.")] string assembly, CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            var asm = workspace.Read(() => workspace.Get(assembly));
            workspace.Unload(asm);
            return $"Unloaded {asm.Id}{(asm.IsDirty ? $" (discarded {Plural(asm.Edits.Count, "unsaved edit")})" : "")}.";
        }, cancellationToken);

    [McpServerTool(Name = "reload_assembly")]
    [Description("Re-read an assembly from disk (e.g. after a game update), discarding unsaved in-memory edits.")]
    public Task<string> ReloadAssembly([Description("Assembly id, name or path.")] string assembly, CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            var asm = workspace.Read(() => workspace.Get(assembly));
            var fresh = workspace.Reload(asm);
            return $"Reloaded {fresh.Id} from {fresh.FilePath}.";
        }, cancellationToken);

    [McpServerTool(Name = "add_search_directory", Idempotent = true)]
    [Description("Add a directory used to resolve referenced assemblies that are not loaded (e.g. a game's Managed folder or a framework directory). Improves decompilation of types from other assemblies.")]
    public Task<string> AddSearchDirectory([Description("Directory path.")] string directory, CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            workspace.AddSearchDirectory(directory);
            return $"Added {Path.GetFullPath(directory)}. Search directories:\n  " + string.Join("\n  ", workspace.Read(() => workspace.SearchDirectories));
        }, cancellationToken);

    [McpServerTool(Name = "get_assembly_info", ReadOnly = true)]
    [Description("Assembly overview: identity, target framework, architecture, entry point, references (and whether each resolves), resources, namespaces, assembly attributes, and whether it carries Il2Cpp address metadata.")]
    public Task<string> GetAssemblyInfo([Description("Assembly id, name or path.")] string assembly, CancellationToken cancellationToken = default) =>
        Read(workspace, () =>
        {
            var asm = workspace.Get(assembly);
            var m = asm.Module;
            var types = m.GetTypes().ToList();
            var sb = new StringBuilder();
            sb.AppendLine($"Id: {asm.Id}");
            sb.AppendLine($"Assembly: {asm.FullAssemblyName}");
            sb.AppendLine($"File: {asm.FilePath}");
            sb.AppendLine($"Module: {m.Name}  MVID {m.Mvid}");
            sb.AppendLine($"Runtime: {m.RuntimeVersion}  Kind: {m.Kind}  Machine: {m.Machine}  IL-only: {m.IsILOnly}  32-bit required: {m.Is32BitRequired}");
            var tfa = m.Assembly?.CustomAttributes.FirstOrDefault(c => c.TypeFullName == "System.Runtime.Versioning.TargetFrameworkAttribute");
            if (tfa?.ConstructorArguments.Count > 0)
                sb.AppendLine($"Target framework: {tfa.ConstructorArguments[0].Value}");
            if (m.EntryPoint != null)
                sb.AppendLine($"Entry point: {Format.MemberLabel(m.EntryPoint)}  ({Format.Token(m.EntryPoint)})");
            sb.AppendLine($"Types: {types.Count}  Namespaces: {types.Select(t => t.Namespace.String).Distinct().Count()}  Methods: {types.Sum(t => t.Methods.Count)}");
            sb.AppendLine($"Resources: {m.Resources.Count}");
            AppendPeInfo(sb, m);
            int addressed = il2cpp.GetIndex(asm).Count;
            if (addressed > 0)
                sb.AppendLine($"Il2Cpp metadata: {addressed} methods carry [Address] attributes (dummy DLL; method bodies are stubs — use get_il2cpp_info / find_method_by_address).");
            if (asm.IsDirty)
                sb.AppendLine($"Unsaved edits: {string.Join("; ", asm.Edits)}");

            sb.AppendLine("References:");
            foreach (var r in m.GetAssemblyRefs())
            {
                var loaded = workspace.FindByAssemblyName(r.Name);
                var status = loaded != null ? $"loaded as {loaded.Id}" : (TryResolve(m, r) ? "resolved from search path" : "not found");
                sb.AppendLine($"  {r.FullName}  [{status}]");
            }

            var attrs = m.Assembly?.CustomAttributes.Where(c => c != tfa).ToList() ?? [];
            if (attrs.Count > 0)
            {
                sb.AppendLine("Assembly attributes:");
                foreach (var ca in attrs.Take(40))
                    sb.AppendLine($"  [{Format.StripArity(ca.AttributeType.Name).Replace("Attribute", "")}({string.Join(", ", ca.ConstructorArguments.Select(a => Format.Literal(a.Value)))})]");
            }
            return sb.ToString();
        }, cancellationToken);

    private static void AppendPeInfo(StringBuilder sb, ModuleDefMD m)
    {
        try
        {
            var pe = m.Metadata.PEImage;
            var fh = pe.ImageNTHeaders.FileHeader;
            var oh = pe.ImageNTHeaders.OptionalHeader;
            var stamp = DateTimeOffset.FromUnixTimeSeconds(fh.TimeDateStamp);
            sb.AppendLine($"PE: {(oh.Magic == 0x20B ? "PE32+" : "PE32")}  ImageBase 0x{oh.ImageBase:X}  Subsystem {oh.Subsystem}  " +
                          $"Characteristics {fh.Characteristics}  DllCharacteristics {oh.DllCharacteristics}");
            sb.AppendLine($"Timestamp: 0x{fh.TimeDateStamp:X8}{(stamp.Year is > 1995 and < 2100 ? $" ({stamp:yyyy-MM-dd HH:mm} UTC)" : " (deterministic build hash)")}  " +
                          $"CLR header flags: {m.Metadata.ImageCor20Header.Flags}  Metadata version: {m.Metadata.VersionString}");
            sb.AppendLine("Sections:");
            foreach (var s in pe.ImageSectionHeaders)
                sb.AppendLine($"  {s.DisplayName,-8} VA 0x{(uint)s.VirtualAddress:X8}  VSize 0x{s.VirtualSize:X}  Raw 0x{s.PointerToRawData:X}+0x{s.SizeOfRawData:X}  flags 0x{s.Characteristics:X8}");
            sb.AppendLine("Metadata streams: " + string.Join(", ", m.Metadata.AllStreams.Select(st => $"{st.Name} ({st.StreamLength} bytes)")));
        }
        catch (Exception ex)
        {
            sb.AppendLine($"PE: unavailable ({ex.Message})");
        }
    }

    private static bool TryResolve(ModuleDef module, AssemblyRef r)
    {
        try { return module.Context.AssemblyResolver.Resolve(r, module) != null; }
        catch { return false; }
    }
}
