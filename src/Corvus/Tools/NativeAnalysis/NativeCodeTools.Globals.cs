using System.ComponentModel;
using System.Text;
using System.Text.RegularExpressions;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Pdb;
using Corvus.Native.Providers;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

public sealed record GlobalEntry(
    [property: Description("VA.")] string Address,
    [property: Description("The name in effect there.")] string Name,
    [property: Description("C type when a source records one (PDB, the user's types, define_native data).")] string? Type,
    [property: Description("Size in bytes when known; -1 otherwise.")] long Size,
    string? Section,
    [property: Description("user, pdb, nativeaot, il2cpp, objc, swift, ida, ghidra, export or symbol.")] IReadOnlyList<string> Sources)
{
    [Description("The engine's text of the value (engine=ida or ghidra).")] public string? Value { get; init; }
}

public sealed record GlobalList(string Image, IReadOnlyList<GlobalEntry> Items, int Offset, int Total, bool Truncated)
{
    public string? Engine { get; init; }
}

public sealed partial class NativeCodeTools
{
    /// <summary>Engine data items read for list_globals at most.</summary>
    private const int MaxEngineData = 300_000;

    [McpServerTool(Name = "list_globals", Title = "List native globals", UseStructuredContent = true, OutputSchemaType = typeof(GlobalList))]
    [Description("Named data of a native image outside code, from every name source (PDB with type and size, user names and types, Il2Cpp, NativeAOT, " +
                 "exports, symbol tables); an engine adds its defined data with type and value. get_native_type read=true reads their fields.")]
    public Task<string> ListGlobals(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Name substring (case-insensitive).")] string? filter = null,
        [Description("Only this section, e.g. .data.")] string? section = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = 200,
        [Description(EngineDescription)] string? engine = null,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var mode = Mode(engine);
        var (native, index) = await Open(image, context, progress, cancellationToken);
        var choice = Choose(mode, native, index);
        EngineDataList? data = null;
        if (choice.External)
        {
            var session = await _engine!.Session(native, choice, progress, cancellationToken);
            data = await session.ListDataAsync(MaxEngineData, cancellationToken);
        }
        var all = await Task.Run(() => Globals(native, index, data, choice.Engine), cancellationToken);
        var shown = all.Where(g => (filter == null || g.Name.Contains(filter.Trim(), StringComparison.OrdinalIgnoreCase))
                                   && (string.IsNullOrWhiteSpace(section) || string.Equals(g.Section, section.Trim(), StringComparison.OrdinalIgnoreCase))).ToList();
        var rows = shown.Select(g => $"{g.Address}  {g.Name}" + (g.Type != null ? $"  {g.Type}" : "") + (g.Size >= 0 ? $"  {g.Size} bytes" : "") +
                                     $"  {g.Section ?? "-"}  ({string.Join(", ", g.Sources)})" + (g.Value != null ? $"  = {g.Value}" : "")).ToList();
        var result = Paged(shown, offset, limit, (page, o, total, more) => new GlobalList(native.Id, page, o, total, more) { Engine = choice.Engine });
        var engineNote = data == null ? "" : $" ({data.Total:N0} defined by {NativeEngineService.DisplayName(choice.Engine)}" +
                                               (data.Total > data.Items.Count ? $", the first {data.Items.Count:N0} read" : "") + ")";
        return ToolOutput.With($"{native.Id}: {Plural(all.Count, data == null ? "named global" : "global")}{engineNote}" +
                                     (shown.Count < all.Count ? $", {shown.Count} matching" : "") + $"\n{choice.Line}\n" +
                                     pager.PageRows(rows, offset, limit, "global"), result);
    });

    /// <summary>
    /// Every named address outside functions and code sections, merged by address, in address order; with <paramref name="data"/>
    /// also every item the engine defined (our names win, unnamed ones keep the engine's).
    /// </summary>
    private List<GlobalEntry> Globals(LoadedNative native, NativeCodeIndex index, EngineDataList? data = null, string? engine = null)
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
        // the engine's items wherever it defined them (also jump tables and strings in code sections)
        var values = new Dictionary<uint, string>();
        foreach (var d in data?.Items ?? [])
        {
            // alignment and int3 / nop / zero fill between functions are no globals
            if (d.Label == null && image.SectionAt(d.Rva) is { IsExecutable: true } && (d.Type == "align" || d.Value is { } v && CodePadding().IsMatch(v))) continue;
            Add(d.Rva, d.Label, engine!, d.Type, d.Size);
            if (d.Value != null) values[d.Rva] = d.Value;
        }

        return found.Select(kv => new GlobalEntry(NativeAddress.Va(image, kv.Key), index.NameAt(kv.Key) ?? kv.Value.Name ?? $"data_{kv.Key:X}", kv.Value.Type,
            kv.Value.Size, image.SectionAt(kv.Key)?.Name, [.. kv.Value.Sources]) { Value = values.GetValueOrDefault(kv.Key) }).ToList();
    }

    /// <summary>An engine's text of a fill: "db 5 dup(0CCh)", "db 3200h dup(90h)", "db 2 dup(0)".</summary>
    [GeneratedRegex(@"^db\s+[0-9A-F]+h?\s+dup\((?:0CCh|90h|0)\)$", RegexOptions.IgnoreCase)]
    private static partial Regex CodePadding();
}
