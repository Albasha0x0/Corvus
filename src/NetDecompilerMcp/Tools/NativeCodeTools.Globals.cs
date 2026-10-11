using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Pdb;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

public sealed record GlobalEntry(
    [property: Description("VA.")] string Address,
    [property: Description("The name in effect there.")] string Name,
    [property: Description("C type when a source records one (PDB, the user's types, define_native data).")] string? Type,
    [property: Description("Size in bytes when known; -1 otherwise.")] long Size,
    string? Section,
    [property: Description("Where it is named or typed: user, pdb, nativeaot, il2cpp, ida, export, symbol.")] IReadOnlyList<string> Sources);

public sealed record GlobalList(string Image, IReadOnlyList<GlobalEntry> Items, int Offset, int Total, bool Truncated);

public sealed partial class NativeCodeTools
{
    [McpServerTool(Name = "list_globals", Title = "List native globals", UseStructuredContent = true, OutputSchemaType = typeof(GlobalList))]
    [Description("Named data items of a native image, outside functions and code sections, from every name source: PDB data symbols with type " +
                 "and size, the user's names and global types (rename_native, set_native_type, define_native data), Il2Cpp, NativeAOT and " +
                 "IDA names, data exports and symbol-table objects. Filter by name or section; paged. get_native_type read=true reads one's fields.")]
    public Task<string> ListGlobals(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Only globals whose name contains this text (case-insensitive).")] string? filter = null,
        [Description("Only this section, e.g. .data.")] string? section = null,
        [Description("Index of the first row.")] int offset = 0,
        [Description("Max rows (default 300).")] int limit = 300,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, index) = await Open(image, context, progress, cancellationToken);
        var all = await Task.Run(() => Globals(native, index), cancellationToken);
        var shown = all.Where(g => (filter == null || g.Name.Contains(filter.Trim(), StringComparison.OrdinalIgnoreCase))
                                   && (string.IsNullOrWhiteSpace(section) || string.Equals(g.Section, section.Trim(), StringComparison.OrdinalIgnoreCase))).ToList();
        var rows = shown.Select(g => $"{g.Address}  {g.Name}" + (g.Type != null ? $"  {g.Type}" : "") + (g.Size >= 0 ? $"  {g.Size} bytes" : "") +
                                     $"  {g.Section ?? "-"}  ({string.Join(", ", g.Sources)})").ToList();
        var result = Paged(shown, offset, limit, (page, o, total, more) => new GlobalList(native.Id, page, o, total, more));
        return StructuredOutput.With($"{native.Id}: {Plural(all.Count, "named global")}" + (shown.Count < all.Count ? $", {shown.Count} matching" : "") + "\n" +
                                     pager.PageRows(rows, offset, limit, "global"), result);
    });

    /// <summary>Every named address outside functions and code sections, merged by address, in address order.</summary>
    private List<GlobalEntry> Globals(LoadedNative native, NativeCodeIndex index)
    {
        var image = native.Image;
        var found = new SortedDictionary<uint, (string? Name, string? Type, long Size, SortedSet<string> Sources)>();
        bool Data(uint rva) => index.FunctionAt(rva) == null && image.SectionAt(rva) is { IsExecutable: false };
        void Add(uint rva, string? name, string source, string? type = null, long size = -1)
        {
            var e = found.TryGetValue(rva, out var x) ? x : (null, null, -1, new SortedSet<string>(StringComparer.Ordinal));
            e.Sources.Add(source);
            found[rva] = (e.Name ?? name, e.Type ?? type, e.Size >= 0 ? e.Size : size, e.Sources);
        }

        if (PdbService.StateOf(native)?.Pdb is { } pdb)
        {
            var model = PdbTypeModel.Of(pdb, image.Is64Bit ? 8 : 4);
            foreach (var s in pdb.Symbols)
                if (s.Kind is PdbSymbolKind.GlobalData or PdbSymbolKind.LocalData or PdbSymbolKind.PublicData && s.Rva is { } r && Data(r))
                    Add(r, s.Name, "pdb", s.TypeIndex != 0 ? model.Spell(s.TypeIndex) : null, s.TypeIndex != 0 ? model.SizeOf(s.TypeIndex) : -1);
        }
        var annotations = code.Annotations(native);
        foreach (var (rva, name) in annotations.Names()) if (Data(rva)) Add(rva, name, "user");
        var user = annotations.UserTypes;
        foreach (var (rva, type) in user.Types) if (Data(rva)) Add(rva, null, "user", type);
        foreach (var a in user.Analysis.Where(a => a.Kind == Native.Providers.NativeAnalysisEdit.Data))
            if (Data(a.Rva)) Add(a.Rva, null, "user", a.Type);
        foreach (var layer in NativeNameLayers.Of(native).Layers)
            foreach (var (rva, name) in layer.Names) if (Data(rva)) Add(rva, name, layer.Source.Id());
        foreach (var e in image.Exports) if (e.Rva is { } r && Data(r)) Add(r, e.Name, "export");
        foreach (var s in image.Symbols) if (s.Kind == ImageSymbolKind.Object && Data(s.Rva)) Add(s.Rva, s.Name, "symbol", null, (long)s.Size);

        return found.Select(kv => new GlobalEntry(NativeAddress.Va(image, kv.Key), index.NameAt(kv.Key) ?? kv.Value.Name ?? $"data_{kv.Key:X}", kv.Value.Type,
            kv.Value.Size, image.SectionAt(kv.Key)?.Name, [.. kv.Value.Sources])).ToList();
    }
}
