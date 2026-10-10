using System.ComponentModel;
using System.Text;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class ResourceTools(AssemblyWorkspace workspace, ResourceService resources, DecompilerService decompiler, OutputPager pager)
{
    [McpServerTool(Name = "list_resources", Title = "List manifest resources", UseStructuredContent = true, OutputSchemaType = typeof(ResourceList))]
    [Description("List manifest resources: embedded files, .resources containers (with entry counts), linked resources. For a native image, its Win32 resources as TYPE/NAME/LANGUAGE.")]
    public Task<string> ListResources(
        [Description(AssemblyDescription)] string assembly,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        static List<ResourceEntry> Win32(LoadedNative n) =>
            (n.Pe?.Resources ?? []).Take(5_000).Select(r => new ResourceEntry(NativeResourceService.Key(r), r.TypeName, r.Size, null, null)).ToList();
        // A mixed-mode assembly lists its managed resources, then the Win32 resources of its native view.
        if (workspace.FindNative(assembly) is { ManagedView: null } native)
            return StructuredOutput.With(pager.Page(NativeResourceService.List(native)),
                new ResourceList(native.Id, Win32(native), native.Pe?.Resources.Count ?? 0, native.Pe?.Resources.Count > 5_000));
        var asm = workspace.Get(assembly);
        var list = resources.List(asm);
        var nativeView = workspace.NativeViewOf(asm) is { } view && view.Pe?.Resources.Count > 0 ? view : null;
        var win32 = nativeView != null ? "\n" + NativeResourceService.List(nativeView) : "";
        var items = list.Select(r => new ResourceEntry(r.Name, r.Kind, r.Size, r.EntryCount, r.IsPublic)).Concat(nativeView != null ? Win32(nativeView) : []).ToList();
        var result = new ResourceList(asm.Id, items, list.Count + (nativeView?.Pe?.Resources.Count ?? 0), items.Count < list.Count + (nativeView?.Pe?.Resources.Count ?? 0));
        if (list.Count == 0) return StructuredOutput.With($"{asm.Id} has no managed resources." + win32, result);
        var sb = new StringBuilder($"{asm.Id}: {Plural(list.Count, "resource")}\n");
        foreach (var r in list)
            sb.AppendLine($"  {r.Name}  [{r.Kind}{(r.Size is { } s ? $", {s:N0} bytes" : "")}{(r.EntryCount is { } n ? $", {n} entries" : "")}{(r.IsPublic ? "" : ", private")}]");
        return StructuredOutput.With(sb.ToString() + win32, result);
    }, cancellationToken);

    [McpServerTool(Name = "get_resource", Title = "Read / extract resource")]
    [Description("Read a resource: text as text, binary as a hex preview, .resources containers as an entry list (pass entry to read one; WPF .baml entries come back as XAML). Pass savePath to extract the raw bytes to disk (images, asset bundles, configs). " +
                 "For a native image, name is TYPE/NAME[/LANGUAGE] from list_resources: version info and string tables are decoded, manifests shown as text.")]
    public Task<string> GetResource(
        [Description(AssemblyDescription)] string assembly,
        [Description("Resource name as shown by list_resources.")] string name,
        [Description("Entry name inside a .resources container.")] string? entry = null,
        [Description("Write the raw bytes of the resource (or entry) to this file path.")] string? savePath = null,
        [Description("Replace savePath if it exists.")] bool overwrite = false,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
        {
            if (workspace.FindNative(assembly) is { ManagedView: null } native) return pager.Page(NativeResourceService.Get(native, name, savePath, overwrite: overwrite), offset, maxChars);
            var asm = workspace.Get(assembly);
            try
            {
                return pager.Page(resources.Get(asm, name, entry, savePath, baml: bytes => decompiler.DecompileBaml(asm, bytes, cancellationToken), overwrite: overwrite), offset, maxChars);
            }
            catch (ToolError ex) when (ex.Code == ErrorCode.NotFound && name.Contains('/') && workspace.NativeViewOf(asm) is { } view)
            {
                // Mixed-mode: TYPE/NAME[/LANGUAGE] that is not a managed resource names a Win32 resource of the native view.
                return pager.Page(NativeResourceService.Get(view, name, savePath, overwrite: overwrite), offset, maxChars);
            }
        }, cancellationToken);
}
