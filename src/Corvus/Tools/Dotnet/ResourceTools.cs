using System.Buffers.Binary;
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
                 "resources as TYPE/NAME/LANGUAGE with file ranges (icon groups paired with their icons, image headers decoded).")]
    public Task<string> ListResources(
        [Description(AssemblyDescription)] string assembly,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description(LimitDescription)] int limit = 200,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        static string Row(ResourceEntry r) => r.Rva != null
            ? $"{r.Name}  {r.Size:N0} bytes at rva {r.Rva}{(r.FileOffset != null ? $", file {r.FileOffset}-{r.FileEnd ?? "past the end"}" : "")}" +
              $"{(r.CodePage is { } cp ? $", code page {cp}" : "")}{(r.Image != null ? $", {r.Image}" : "")}" +
              $"{(r.IconEntries is { Count: > 0 } icons ? $", icons {string.Join(" ", icons.Select(IconText))}" : "")}" +
              $"{(r.IconGroups is { Count: > 0 } groups ? $", in {string.Join(" ", groups)}" : "")}{(r.Sha256 != null ? $"  sha256 {r.Sha256}" : "")}"
            : $"{r.Name}  [{r.Kind}{(r.Size is { } s ? $", {s:N0} bytes" : "")}{(r.Entries is { } n ? $", {n} entries" : "")}{(r.Public == false ? ", private" : "")}]" +
              $"{(r.FileOffset != null ? $"  file {r.FileOffset}" : "")}{(r.Sha256 != null ? $"  sha256 {r.Sha256}" : "")}";
        static string IconText(IconRef i) => $"{i.Id} ({i.Width}x{i.Height}{(i.BitCount > 0 ? $" {i.BitCount}bpp" : "")}{(i.Resource == null ? ", missing" : "")})";
        string id;
        List<ResourceEntry> items;
        string header;
        // A mixed-mode assembly lists its managed resources, then the Win32 resources of its native view.
        if (workspace.FindNative(assembly) is { ManagedView: null } native)
        {
            (id, items) = (native.Id, native.Pe is { } pe ? Win32(pe) : []);
            header = native.Pe is null ? $"{id}: no Win32 resources ({native.Image.Format} image)\n" : $"{id}: Win32 resources (TYPE/NAME/LANGUAGE)\n";
        }
        else
        {
            var asm = workspace.Get(assembly);
            var list = resources.List(asm);
            var win32 = workspace.NativeViewOf(asm)?.Pe is { } viewPe ? Win32(viewPe) : [];
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

    /// <summary>Win32 resource types; RT_GROUP_ICON's directory names the RT_ICON resources it groups.</summary>
    private const uint RtCursor = 1, RtBitmap = 2, RtIcon = 3, RtGroupIcon = 14;

    /// <summary>
    /// The Win32 resource rows: file range and SHA-256 of each; icon groups with their entries paired to the RT_ICON
    /// resources (same language first), icons with the groups naming them and their decoded image header.
    /// </summary>
    internal static List<ResourceEntry> Win32(PeFile pe)
    {
        var icons = pe.Resources.Where(r => !r.Type.IsName && r.Type.Id == RtIcon && r.Name is { IsName: false }).ToList();
        var groupsOf = new Dictionary<PeResource, List<string>>();
        var rows = new List<ResourceEntry>(pe.Resources.Count);
        foreach (var r in pe.Resources)
        {
            var bytes = pe.ReadResource(r);
            long? at = pe.TryRvaToFileOffset(r.Rva, out var o) ? o : null;
            List<IconRef>? entries = null;
            if (!r.Type.IsName && r.Type.Id == RtGroupIcon && bytes != null && GroupEntries(bytes) is { } group)
            {
                entries = [];
                foreach (var e in group)
                {
                    var icon = icons.FirstOrDefault(i => i.Name!.Id == e.Id && i.Language == r.Language) ?? icons.FirstOrDefault(i => i.Name!.Id == e.Id);
                    if (icon != null)
                    {
                        if (!groupsOf.TryGetValue(icon, out var names)) groupsOf[icon] = names = [];
                        names.Add(NativeResourceService.Key(r));
                    }
                    entries.Add(e with { Resource = icon != null ? NativeResourceService.Key(icon) : null });
                }
            }
            rows.Add(new ResourceEntry(NativeResourceService.Key(r), r.TypeName)
            {
                Size = r.Size,
                Rva = $"0x{r.Rva:X}",
                FileOffset = at is { } start ? $"0x{start:X}" : null,
                // a range that runs past the file (a truncated image) has no end
                FileEnd = at is { } s && s + r.Size <= pe.FileSize ? $"0x{s + r.Size:X}" : null,
                CodePage = r.CodePage != 0 ? (int)r.CodePage : null,
                Sha256 = bytes != null ? Convert.ToHexStringLower(SHA256.HashData(bytes)) : null,
                Icons = entries?.Select(e => e.Id).ToList(),
                IconEntries = entries,
                Image = r.Type.IsName || bytes == null ? null : r.Type.Id switch
                {
                    RtIcon => ImageHeader(bytes, mask: true),
                    RtCursor when bytes.Length > 4 => ImageHeader(bytes[4..], mask: true), // after the hotspot
                    RtBitmap => ImageHeader(bytes, mask: false),
                    _ => null,
                },
            });
        }
        for (int i = 0; i < rows.Count; i++)
            if (groupsOf.TryGetValue(pe.Resources[i], out var names)) rows[i] = rows[i] with { IconGroups = names };
        return rows;
    }

    /// <summary>The RT_ICON ids of a group icon directory.</summary>
    internal static List<int>? IconIds(byte[] group) => GroupEntries(group)?.Select(e => e.Id).ToList();

    /// <summary>GRPICONDIR: a 6-byte header (count at 4), then 14-byte entries: width, height (0 = 256), colors, reserved, planes, bit count, bytes, id.</summary>
    private static List<IconRef>? GroupEntries(byte[] group)
    {
        if (group.Length < 6) return null;
        int count = BitConverter.ToUInt16(group, 4);
        var entries = new List<IconRef>();
        for (int i = 0; i < count && 6 + i * 14 + 14 <= group.Length; i++)
        {
            int at = 6 + i * 14;
            entries.Add(new IconRef(BitConverter.ToUInt16(group, at + 12), group[at] == 0 ? 256 : group[at], group[at + 1] == 0 ? 256 : group[at + 1],
                BitConverter.ToUInt16(group, at + 6), null));
        }
        return entries;
    }

    /// <summary>"png 256x256" or "dib 32x32 32bpp"; null for other data. An icon's DIB height counts its AND mask too (<paramref name="mask"/>).</summary>
    internal static string? ImageHeader(byte[] data, bool mask)
    {
        if (data.Length >= 24 && data.AsSpan(0, 8).SequenceEqual((ReadOnlySpan<byte>)[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))
            return $"png {BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(16))}x{BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(20))}";
        if (data.Length < 16 || BitConverter.ToUInt32(data, 0) is not (12 or 40 or 108 or 124)) return null;
        bool core = BitConverter.ToUInt32(data, 0) == 12;
        int width = core ? BitConverter.ToUInt16(data, 4) : BitConverter.ToInt32(data, 4);
        int height = core ? BitConverter.ToUInt16(data, 6) : BitConverter.ToInt32(data, 8);
        int bits = core ? BitConverter.ToUInt16(data, 10) : BitConverter.ToUInt16(data, 14);
        return $"dib {width}x{Math.Abs((long)height) / (mask ? 2 : 1)} {bits}bpp";
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
