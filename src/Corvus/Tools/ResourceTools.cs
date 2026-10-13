using System.ComponentModel;
using System.Text;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class ResourceTools(AssemblyWorkspace workspace, ResourceService resources, DecompilerService decompiler, OutputPager pager)
{
    [McpServerTool(Name = "list_resources", Title = "List manifest resources", UseStructuredContent = true, OutputSchemaType = typeof(ResourceList))]
    [Description("List manifest resources: embedded files, .resources containers (with entry counts), linked resources. For a native image, its Win32 resources as TYPE/NAME/LANGUAGE.")]
    public Task<string> ListResources(
        [Description(AssemblyDescription)] string assembly,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Max rows (default 200).")] int limit = 200,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        static List<ResourceEntry> Win32(LoadedNative n) => (n.Pe?.Resources ?? []).Select(r => new ResourceEntry(NativeResourceService.Key(r), r.TypeName, r.Size,
            null, null, $"0x{r.Rva:X}", r.CodePage != 0 ? (int)r.CodePage : null)).ToList();
        static string Row(ResourceEntry r) => r.Rva != null
            ? $"{r.Name}  {r.Size:N0} bytes at rva {r.Rva}{(r.CodePage is { } cp ? $", code page {cp}" : "")}"
            : $"{r.Name}  [{r.Kind}{(r.Size is { } s ? $", {s:N0} bytes" : "")}{(r.Entries is { } n ? $", {n} entries" : "")}{(r.Public == false ? ", private" : "")}]";
        string id;
        List<ResourceEntry> items;
        string header;
        // A mixed-mode assembly lists its managed resources, then the Win32 resources of its native view.
        if (workspace.FindNative(assembly) is { ManagedView: null } native)
        {
            (id, items) = (native.Id, Win32(native));
            header = native.Pe is null ? $"{id}: no Win32 resources ({native.Image.Format} image)\n" : $"{id}: Win32 resources (TYPE/NAME/LANGUAGE)\n";
        }
        else
        {
            var asm = workspace.Get(assembly);
            var list = resources.List(asm);
            var win32 = workspace.NativeViewOf(asm) is { } view ? Win32(view) : [];
            (id, items) = (asm.Id, list.Select(r => new ResourceEntry(r.Name, r.Kind, r.Size, r.EntryCount, r.IsPublic)).Concat(win32).ToList());
            header = $"{id}: {Plural(list.Count, "managed resource")}{(win32.Count > 0 ? $", then {win32.Count} Win32 (TYPE/NAME/LANGUAGE)" : "")}\n";
        }
        return ToolOutput.List(items, offset, ClampLimit(limit), Row, rows => new ResourceList(id, rows, Math.Max(0, offset), items.Count), "resource", header);
    }, cancellationToken);

    [McpServerTool(Name = "get_resource", Title = "Read / extract resource")]
    [Description("Read a resource: text as text, binary as hex preview, .resources as an entry list (entry reads one; .baml as XAML); savePath extracts the raw bytes. " +
                 "Native images: TYPE/NAME[/LANGUAGE], version info and string tables decoded.")]
    public Task<string> GetResource(
        [Description(AssemblyDescription)] string assembly,
        [Description("Name from list_resources.")] string name,
        [Description("Entry inside a .resources container.")] string? entry = null,
        [Description("Write the raw bytes to this file.")] string? savePath = null,
        [Description("Replace savePath if it exists.")] bool overwrite = false,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
        {
            if (workspace.FindNative(assembly) is { ManagedView: null } native) return pager.Page(NativeResourceService.Get(native, name, savePath, overwrite: overwrite), offset, maxTokens);
            var asm = workspace.Get(assembly);
            try
            {
                return pager.Page(resources.Get(asm, name, entry, savePath, baml: bytes => decompiler.DecompileBaml(asm, bytes, cancellationToken), overwrite: overwrite), offset, maxTokens);
            }
            catch (ToolError ex) when (ex.Code == ErrorCode.NotFound && name.Contains('/') && workspace.NativeViewOf(asm) is { } view)
            {
                // Mixed-mode: TYPE/NAME[/LANGUAGE] that is not a managed resource names a Win32 resource of the native view.
                return pager.Page(NativeResourceService.Get(view, name, savePath, overwrite: overwrite), offset, maxTokens);
            }
        }, cancellationToken);
}
