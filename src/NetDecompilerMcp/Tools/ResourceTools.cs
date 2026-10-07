using System.ComponentModel;
using System.Text;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class ResourceTools(AssemblyWorkspace workspace, ResourceService resources, DecompilerService decompiler, OutputPager pager)
{
    [McpServerTool(Name = "list_resources", Title = "List manifest resources", ReadOnly = true, OpenWorld = false)]
    [Description("List manifest resources: embedded files, .resources containers (with entry counts), linked resources.")]
    public Task<string> ListResources(
        [Description(AssemblyDescription)] string assembly,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var asm = workspace.Get(assembly);
        var list = resources.List(asm);
        if (list.Count == 0) return $"{asm.Id} has no resources.";
        var sb = new StringBuilder($"{asm.Id}: {Plural(list.Count, "resource")}\n");
        foreach (var r in list)
            sb.AppendLine($"  {r.Name}  [{r.Kind}{(r.Size is { } s ? $", {s:N0} bytes" : "")}{(r.EntryCount is { } n ? $", {n} entries" : "")}{(r.IsPublic ? "" : ", private")}]");
        return sb.ToString();
    }, cancellationToken);

    [McpServerTool(Name = "get_resource", Title = "Read / extract resource", ReadOnly = true, OpenWorld = false)]
    [Description("Read a resource: text as text, binary as a hex preview, .resources containers as an entry list (pass entry to read one; WPF .baml entries come back as XAML). Pass savePath to extract the raw bytes to disk (images, asset bundles, configs).")]
    public Task<string> GetResource(
        [Description(AssemblyDescription)] string assembly,
        [Description("Resource name as shown by list_resources.")] string name,
        [Description("Entry name inside a .resources container.")] string? entry = null,
        [Description("Write the raw bytes of the resource (or entry) to this file path.")] string? savePath = null,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
        {
            var asm = workspace.Get(assembly);
            return pager.Page(resources.Get(asm, name, entry, savePath, baml: bytes => decompiler.DecompileBaml(asm, bytes, cancellationToken)), offset, maxChars);
        }, cancellationToken);
}
