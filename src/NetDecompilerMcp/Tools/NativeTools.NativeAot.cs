using System.ComponentModel;
using System.Text;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.NativeAot;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

public sealed partial class NativeTools
{
    [McpServerTool(Name = "get_nativeaot_info", Title = "NativeAOT metadata", UseStructuredContent = true, OutputSchemaType = typeof(NativeAotInfo))]
    [Description("What a NativeAOT image's own metadata recovers, read without executing it (.NET 7-10). view=summary: runtime and ReadyToRun version, " +
                 "dehydration, module header, each recovery stage with its status (complete / partial / absent / unsupported), counts and the share of " +
                 "function starts named. view=sections: the module sections. view=types: MethodTables with name, name origin (typemap / composition / " +
                 "vtable / element / generated), kind and base. view=type: one MethodTable by name or address with flags, base chain, interfaces and " +
                 "vtable slots and dispatch-map interface implementations with their code. view=methods: named method bodies (origin stacktrace / invoke). view=strings: frozen string literals with " +
                 "their references. query filters types / methods / strings by substring. The names also apply automatically as the nativeaot name layer.")]
    public Task<string> GetNativeAotInfo(
        [Description(ImageDescription)] string image,
        [Description("summary (default), sections, types, type, methods or strings.")] string? view = null,
        [Description("view=type: a type name ('System.String', 'MT_System_String') or the MethodTable's address; other list views: substring filter.")] string? query = null,
        [Description("First row for the list views; character offset for summary and type.")] int offset = 0,
        [Description("Max rows for the list views (default 200).")] int limit = 200,
        CancellationToken cancellationToken = default) => OnImage(image, native =>
    {
        var aot = NativeAotNames.View(native, cancellationToken)
                  ?? throw new ToolError(ErrorCode.Unsupported, $"{native.Id} has no NativeAOT module header" +
                                                                (NativeAotNames.Problem(native) is { } p ? $" ({p})." : "."),
                      "summarize_file tells which runtime built a file; get_pe_info and list_functions apply to any native image");
        var index = code?.Ready(native);
        var mode = string.IsNullOrWhiteSpace(view) ? "summary" : view.Trim().ToLowerInvariant();
        return mode switch
        {
            "summary" => AotSummary(native, aot, index, offset),
            "sections" => AotSections(native, aot, offset, limit),
            "types" => AotTypes(native, aot, query, offset, limit, cancellationToken),
            "type" => AotType(native, aot, index, query, offset),
            "methods" => AotMethods(native, aot, query, offset, limit, cancellationToken),
            "strings" => AotStrings(native, aot, index, query, offset, limit, cancellationToken),
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown view '{view}'.", "use summary, sections, types, type, methods or strings"),
        };
    }, cancellationToken);

    private string AotSummary(LoadedNative native, NativeAotImage aot, NativeCodeIndex? index, int offset)
    {
        var s = aot.Summary();
        var image = native.Image;
        var sb = new StringBuilder();
        sb.AppendLine($"{native.Id}: NativeAOT, {s.Runtime}, ReadyToRun {s.ReadyToRunVersion}" + (s.DebugHeaderVersion is { } d ? $", debug header {d}" : "") +
                      (s.Dehydrated ? ", dehydrated" : "") + $"; module header at {NativeAddress.Va(image, s.HeaderRva)}" + (s.Modules > 1 ? $" ({s.Modules} modules, the first analyzed)" : ""));
        if (aot.Hydrated.Sha256 is { } sha)
            sb.AppendLine($"  rehydrated {aot.Hydrated.HydratedLength:N0} bytes at {NativeAddress.Va(image, aot.Hydrated.DestinationRva)} (derived bytes, no file offset; sha256 {sha})");
        sb.AppendLine("Stages:");
        foreach (var st in s.Stages) sb.AppendLine($"  {st.Name}: {st.Status}{(st.Detail != null ? $" ({st.Detail})" : "")}");
        sb.AppendLine("Counts: " + string.Join(", ", s.Counts.Select(c => $"{c.Key} {c.Value}")));

        var starts = image.RuntimeFunctions.Select(f => f.BeginRva).ToHashSet();
        int namedStarts = aot.Names.MethodAt.Keys.Count(starts.Contains);
        var coverage = new Dictionary<string, int> { ["functionStarts"] = starts.Count, ["functionStartsNamed"] = namedStarts };
        if (starts.Count > 0) sb.AppendLine($"Names: {namedStarts} of {starts.Count} unwind-table function starts ({100.0 * namedStarts / starts.Count:0.0} %) have a metadata name");
        if (index != null)
        {
            int functions = index.Functions.Count, named = index.Functions.Count(f => index.Sourced.NameAt(f.Start) is { Source: NativeNameSource.NativeAot });
            coverage["indexFunctions"] = functions;
            coverage["indexFunctionsNamed"] = named;
            sb.AppendLine($"  list_functions: {named} of {functions} functions carry a nativeaot name (the rest: runtime and C library code, code the index split off)");
        }
        var layer = NativeNameLayers.OfOrNull(native)?.Get(NativeNameSource.NativeAot);
        sb.AppendLine(layer != null
            ? $"  nativeaot name layer: {layer.Names.Count} names{(layer.Info is { Restored: true } ? ", restored from the saved copy" : "")}; user and PDB names rank above it"
            : Environment.GetEnvironmentVariable(NativeAotNames.AutoVariable) == "0"
                ? $"  nativeaot name layer: off ({NativeAotNames.AutoVariable}=0)"
                : "  nativeaot name layer: applied when the code index is built (any code tool builds it)");
        var text = sb.ToString();
        return StructuredOutput.With(pager.Page(text, offset), new NativeAotInfo(native.Id, "summary", s, coverage, [], 0, 0, false));
    }

    private string AotSections(LoadedNative native, NativeAotImage aot, int offset, int limit)
    {
        var rows = aot.Header.Sections.Select(x => new NativeAotRow(NativeAddress.Va(native.Image, x.StartRva), x.Name, "section",
            $"id {x.Id}, {(x.HasEnd ? $"{x.Length:N0} bytes" : "no end")}")).ToList();
        return Rows(native, "sections", rows, offset, limit, "section");
    }

    private string AotTypes(LoadedNative native, NativeAotImage aot, string? query, int offset, int limit, CancellationToken ct)
    {
        var types = aot.Types.ByRva;
        var rows = new List<NativeAotRow>();
        foreach (var mt in types.Values.OrderBy(t => t.Name, StringComparer.Ordinal).ThenBy(t => t.Rva))
        {
            ct.ThrowIfCancellationRequested();
            if (query != null && !mt.Name.Contains(query, StringComparison.OrdinalIgnoreCase)) continue;
            var parent = mt.RelatedType != 0 ? types.TryGetValue(mt.RelatedType, out var p) ? p.Name : $"MT_{mt.RelatedType:X}" : null;
            rows.Add(new NativeAotRow(NativeAddress.Va(native.Image, mt.Rva), mt.Name, mt.Kind,
                $"name from {mt.NameOrigin}" + (parent != null ? $", {(mt.Kind is "array" or "pointer" or "byref" ? "element" : "base")} {parent}" : "") +
                $", {mt.Vtable.Count} slots, {mt.Interfaces.Count} interfaces"));
        }
        return Rows(native, "types", rows, offset, limit, "MethodTable");
    }

    private string AotMethods(LoadedNative native, NativeAotImage aot, string? query, int offset, int limit, CancellationToken ct)
    {
        var rows = new List<NativeAotRow>();
        foreach (var m in aot.Names.Methods.OrderBy(m => m.Rva).ThenBy(m => m.Name.Full, StringComparer.Ordinal))
        {
            ct.ThrowIfCancellationRequested();
            if (query != null && !m.Name.Full.Contains(query, StringComparison.OrdinalIgnoreCase)) continue;
            rows.Add(new NativeAotRow(NativeAddress.Va(native.Image, m.Rva), m.Name.Full, m.Origin, m.Hidden ? "hidden from stack traces" : null));
        }
        return Rows(native, "methods", rows, offset, limit, "method");
    }

    private string AotStrings(LoadedNative native, NativeAotImage aot, NativeCodeIndex? index, string? query, int offset, int limit, CancellationToken ct)
    {
        var rows = new List<NativeAotRow>();
        foreach (var o in aot.Frozen.Objects)
        {
            ct.ThrowIfCancellationRequested();
            if (o.Text == null || query != null && !o.Text.Contains(query, StringComparison.OrdinalIgnoreCase)) continue;
            rows.Add(new NativeAotRow(NativeAddress.Va(native.Image, o.Rva), Format.Clip(o.Text, 400), "string",
                index != null ? $"{index.CountRefsTo(o.Rva)} refs" : null));
        }
        return Rows(native, "strings", rows, offset, limit, "string");
    }

    private string Rows(LoadedNative native, string view, List<NativeAotRow> rows, int offset, int limit, string noun)
    {
        var text = rows.Select(r => $"{r.Address}  {r.Name}  [{r.Kind}]{(r.Detail != null ? "  " + r.Detail : "")}").ToList();
        return StructuredOutput.With(pager.PageRows(text, offset, limit, noun),
            Paged(rows, offset, limit, (page, o, total, more) => new NativeAotInfo(native.Id, view, null, null, page, o, total, more)));
    }

    private string AotType(LoadedNative native, NativeAotImage aot, NativeCodeIndex? index, string? query, int offset)
    {
        if (string.IsNullOrWhiteSpace(query))
            throw new ToolError(ErrorCode.InvalidArgument, "view=type needs query: a type name or a MethodTable address.", "view=types lists them");
        var image = native.Image;
        var types = aot.Types;
        var q = query.Trim();
        var byName = types.ByRva.Values.Where(t => t.Name == q || "MT_" + Native.Annotations.NativeName.Identifier(t.Name) == q).ToList();
        if (byName.Count > 1)
            throw new ToolError(ErrorCode.Ambiguous, $"{byName.Count} MethodTables are named '{q}': {string.Join(", ", byName.Select(t => NativeAddress.Va(image, t.Rva)))}.",
                "pass one of the addresses");
        NativeAotMethodTable? mt = byName.FirstOrDefault();
        if (mt == null)
        {
            uint rva;
            try { rva = NativeAddress.Parse(image, q, index != null ? index.AddressesOfName : null); }
            catch (ToolError) { throw NoType(q); }
            mt = types.At(rva) ?? throw NoType(q);
        }
        string Name(uint rva) => rva == 0 ? "null" : types.At(rva)?.Name ?? $"MT_{rva:X}";
        string Code(uint rva) => rva == 0 ? "null" : $"{NativeAddress.Va(image, rva)} {index?.NameAt(rva) ?? (aot.Names.MethodAt.TryGetValue(rva, out var m) ? m.Name.Short : "")}".TrimEnd();

        var sb = new StringBuilder();
        sb.AppendLine($"{mt.Name} at {NativeAddress.Va(image, mt.Rva)}: {mt.Kind}, element type {mt.ElementType}, name from {mt.NameOrigin}" +
                      (types.ByRva.ContainsKey(mt.Rva) ? "" : " (not reached by the crawl; read on demand)"));
        sb.AppendLine($"  flags 0x{mt.Flags:X8}, base size 0x{mt.BaseSize:X}" + (mt.ComponentSize != 0 ? $", component size {mt.ComponentSize}" : "") +
                      (mt.HasFinalizer ? ", has finalizer" : "") + (mt.HasDispatchMap ? ", has dispatch map" : ""));
        var chain = new List<string>();
        for (uint at = mt.RelatedType; at != 0 && chain.Count < 32 && mt.Kind is "class" or "struct"; at = types.At(at)?.RelatedType ?? 0) chain.Add(Name(at));
        if (mt.Kind is "class" or "struct") sb.AppendLine($"  base chain: {(chain.Count > 0 ? string.Join(" -> ", chain) : "none")}");
        else if (mt.RelatedType != 0) sb.AppendLine($"  related type: {Name(mt.RelatedType)}");
        if (mt.GenericDefinition != 0)
            sb.AppendLine($"  generic definition {Name(mt.GenericDefinition)}" + (mt.GenericArguments.Count > 0 ? $", arguments {string.Join(", ", mt.GenericArguments.Select(Name))}" : ""));
        sb.AppendLine($"  interfaces ({mt.Interfaces.Count}): {(mt.Interfaces.Count > 0 ? string.Join(", ", mt.Interfaces.Select(Name)) : "none")}");
        sb.AppendLine($"  vtable ({mt.Vtable.Count} slots):");
        var parent = mt.Kind is "class" or "struct" ? types.At(mt.RelatedType) : null;
        var slots = new List<NativeAotRow>();
        for (int k = 0; k < mt.Vtable.Count; k++)
        {
            uint target = mt.Vtable[k];
            bool inherited = parent != null && k < parent.Vtable.Count && parent.Vtable[k] == target;
            sb.AppendLine($"    [{k}] {Code(target)}{(inherited ? "  (inherited)" : "")}");
            slots.Add(new NativeAotRow(target == 0 ? "null" : NativeAddress.Va(image, target), Code(target), "slot", $"slot {k}{(inherited ? ", inherited" : "")}"));
        }
        var impls = types.Implementations(mt);
        if (impls.Count > 0)
        {
            sb.AppendLine($"  interface methods implemented here ({impls.Count}, from the dispatch map):");
            foreach (var impl in impls)
            {
                sb.AppendLine($"    {Name(impl.Interface)} slot {impl.InterfaceSlot} -> [{impl.ImplSlot}{(impl.ImplSlot >= mt.Vtable.Count ? ", sealed" : "")}] {Code(impl.Code)}");
                slots.Add(new NativeAotRow(impl.Code == 0 ? "null" : NativeAddress.Va(image, impl.Code), Code(impl.Code), "interface",
                    $"{Name(impl.Interface)} slot {impl.InterfaceSlot}, vtable slot {impl.ImplSlot}"));
            }
        }
        return StructuredOutput.With(pager.Page(sb.ToString(), offset), new NativeAotInfo(native.Id, "type", null, null, slots, 0, slots.Count, false));
    }

    private static ToolError NoType(string query) =>
        new(ErrorCode.NotFound, $"No MethodTable named or at '{query}'.", "view=types with query lists MethodTables by name");
}

/// <summary>One row of a get_nativeaot_info list view.</summary>
public sealed record NativeAotRow(string Address, string Name, [property: Description("section, MethodTable kind, method origin (stacktrace / invoke), string, slot or interface.")] string Kind,
    string? Detail);

public sealed record NativeAotInfo(string Image, string View,
    [property: Description("view=summary: versions, sections, stages and counts.")] NativeAotSummary? Summary,
    [property: Description("view=summary: function starts (unwind table) and those named; with the code index, its functions and those named.")] IReadOnlyDictionary<string, int>? Coverage,
    IReadOnlyList<NativeAotRow> Items, int Offset, int Total, bool Truncated);
