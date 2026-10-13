using System.ComponentModel;
using System.Security.Cryptography;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native.Pe;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed partial class ResourceTools(AssemblyWorkspace workspace, ResourceService resources, DecompilerService decompiler, OutputPager pager)
{
    [McpServerTool(Name = "list_resources", Title = "List manifest resources", UseStructuredContent = true, OutputSchemaType = typeof(ResourceList))]
    [Description("List manifest resources (embedded, .resources with entry counts, linked) with SHA-256 and file offsets; for a native image its Win32 " +
                 "resources as TYPE/NAME/LANGUAGE (icon groups name their icons).")]
    public Task<string> ListResources(
        [Description(AssemblyDescription)] string assembly,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description(LimitDescription)] int limit = 200,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        static string Row(ResourceEntry r) => r.Rva != null
            ? $"{r.Name}  {r.Size:N0} bytes at rva {r.Rva}{(r.FileOffset != null ? $", file {r.FileOffset}" : "")}{(r.CodePage is { } cp ? $", code page {cp}" : "")}" +
              $"{(r.Icons is { Count: > 0 } icons ? $", icons {string.Join(" ", icons)}" : "")}{(r.Sha256 != null ? $"  sha256 {r.Sha256}" : "")}"
            : $"{r.Name}  [{r.Kind}{(r.Size is { } s ? $", {s:N0} bytes" : "")}{(r.Entries is { } n ? $", {n} entries" : "")}{(r.Public == false ? ", private" : "")}]" +
              $"{(r.FileOffset != null ? $"  file {r.FileOffset}" : "")}{(r.Sha256 != null ? $"  sha256 {r.Sha256}" : "")}";
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
            (id, items) = (asm.Id, list.Select(r => new ResourceEntry(r.Name, r.Kind)
            {
                Size = r.Size,
                Entries = r.EntryCount,
                Public = r.IsPublic,
                FileOffset = r.FileOffset is { } o ? $"0x{o:X}" : null,
                Sha256 = r.Sha256,
            }).Concat(win32).ToList());
            header = $"{id}: {Plural(list.Count, "managed resource")}{(win32.Count > 0 ? $", then {win32.Count} Win32 (TYPE/NAME/LANGUAGE)" : "")}\n";
        }
        return ToolOutput.List(items.Skip(offset).Take(limit).ToList(), offset, limit, items.Count, Row, rows => new ResourceList(id, rows, offset, items.Count), "resource", header);
    }, cancellationToken);

    /// <summary>RT_GROUP_ICON: its directory names the RT_ICON resources it groups.</summary>
    private const uint RtGroupIcon = 14;

    private static List<ResourceEntry> Win32(LoadedNative n)
    {
        var pe = n.Pe;
        if (pe == null) return [];
        return pe.Resources.Select(r =>
        {
            var bytes = pe.ReadResource(r);
            return new ResourceEntry(NativeResourceService.Key(r), r.TypeName)
            {
                Size = r.Size,
                Rva = $"0x{r.Rva:X}",
                FileOffset = pe.TryRvaToFileOffset(r.Rva, out var at) ? $"0x{at:X}" : null,
                CodePage = r.CodePage != 0 ? (int)r.CodePage : null,
                Sha256 = bytes != null ? Convert.ToHexStringLower(SHA256.HashData(bytes)) : null,
                Icons = !r.Type.IsName && r.Type.Id == RtGroupIcon && bytes != null ? IconIds(bytes) : null,
            };
        }).ToList();
    }

    /// <summary>The RT_ICON ids of a group icon directory (GRPICONDIR: 6-byte header, 14-byte entries ending in the id).</summary>
    internal static List<int>? IconIds(byte[] group)
    {
        if (group.Length < 6) return null;
        int count = BitConverter.ToUInt16(group, 4);
        var ids = new List<int>();
        for (int i = 0; i < count && 6 + i * 14 + 14 <= group.Length; i++)
            ids.Add(BitConverter.ToUInt16(group, 6 + i * 14 + 12));
        return ids;
    }

    [McpServerTool(Name = "get_resource", Title = "Read / extract resource", UseStructuredContent = true, OutputSchemaType = typeof(ResourcePage))]
    [Description("Read a resource: text as text, binary as hex preview, .resources as an entry list (entry reads one; .baml as XAML); outputPath extracts the raw bytes. " +
                 "Native images: TYPE/NAME[/LANGUAGE], version info and string tables decoded.")]
    public Task<string> GetResource(
        [Description(AssemblyDescription)] string assembly,
        [Description("Name from list_resources.")] string name,
        [Description("Entry inside a .resources container.")] string? entry = null,
        [Description("Write the raw bytes to this file.")] string? outputPath = null,
        [Description("Replace outputPath if it exists.")] bool overwrite = false,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
        {
            string text;
            if (workspace.FindNative(assembly) is { ManagedView: null } native) text = NativeResourceService.Get(native, name, outputPath, overwrite: overwrite);
            else
            {
                var asm = workspace.Get(assembly);
                try
                {
                    text = resources.Get(asm, name, entry, outputPath, baml: bytes => decompiler.DecompileBaml(asm, bytes, cancellationToken), overwrite: overwrite);
                }
                catch (ToolError ex) when (ex.Code == ErrorCode.NotFound && name.Contains('/') && workspace.NativeViewOf(asm) is { } view)
                {
                    // Mixed-mode: TYPE/NAME[/LANGUAGE] that is not a managed resource names a Win32 resource of the native view.
                    text = NativeResourceService.Get(view, name, outputPath, overwrite: overwrite);
                }
            }
            var kind = outputPath != null ? "saved" : text.Contains(".resources container with", StringComparison.Ordinal) && entry == null ? "entries"
                : text.Contains("<!--", StringComparison.Ordinal) && text.Contains("XAML decompiled", StringComparison.Ordinal) ? "xaml"
                : HexRow().IsMatch(text) ? "hex" : "text";
            var saved = outputPath != null ? SafeFile.FullPath(outputPath) : null;
            return ToolOutput.Text(pager, text, offset, new ResourcePage(name, kind, "", 0, null, 0) { SavedTo = saved }, maxTokens);
        }, cancellationToken);

    [System.Text.RegularExpressions.GeneratedRegex(@"(?m)^[0-9A-F]{6,8}  [0-9A-F]{2} ")]
    private static partial System.Text.RegularExpressions.Regex HexRow();
}
