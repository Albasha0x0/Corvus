using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tools;

/// <summary>Native type layouts from the PDB, RTTI, Il2Cpp and the decompiler engine's database.</summary>
[McpServerToolType]
public sealed class NativeTypeInfoTools(AssemblyWorkspace workspace, NativeCodeService? code = null, NativeEngineService? engines = null,
    NativeUserTypePush? userTypes = null)
{
    public sealed record NativeTypeReport(
        [property: Description("Image id.")] string Image,
        [property: Description("What was looked up: name, id or address.")] string Query,
        [property: Description("The type found; null when the name matched several candidates or none.")] NativeTypeView? Type,
        [property: Description("Types whose name contains the query (no exact match), one page of them.")] IReadOnlyList<NativeTypeCandidate> Candidates,
        int TotalCandidates,
        [property: Description("For address=: the typed item the address is in (a PDB global, a vftable, a metadata slot) and where it starts.")] string? Owner,
        string? OwnerAddress,
        [property: Description("The field path(s) at the address or at=.")] IReadOnlyList<NativeFieldPath> Paths,
        [property: Description("Index of the first returned field, enumerator, slot or candidate.")] int Offset,
        [property: Description("More rows exist past this page: call again with offset = offset + rows returned.")] bool Truncated,
        IReadOnlyList<string> Notes);

    [McpServerTool(Name = "get_native_type", Title = "Native type layout", UseStructuredContent = true, OutputSchemaType = typeof(NativeTypeReport))]
    [Description("A native type's layout from every source the image has: PDB type records (structs, classes, unions, enums, typedefs, pointers, " +
                 "arrays, function types; fields with offset, size and bit fields, bases, vftable pointer, explicit padding), MSVC RTTI classes " +
                 "(bases, vftables with slot targets named), Il2Cpp class layouts (after apply_il2cpp_names) and the decompiler engine's types " +
                 "(IDA local types incl. declare_native_types; source=engine opens the engine, auto reads it only when its analysis is complete " +
                 "and only for names the other sources lack). PDB and RTTI views of one class are merged. Look up by name (exact, then " +
                 "case-insensitive, then a substring candidate list; several definitions are an ambiguous error listing their ids), by id " +
                 "(from a previous result, for drill-down) or by typed address (a PDB global covering it gives the field path at the offset, " +
                 "e.g. g_Game.players[3].pos.y; also vftables, RTTI descriptors and Il2Cpp metadata slots). at=0x48 names the field at an " +
                 "offset (every member of a union; 0x48.0x10 reads through the pointer at 0x48). depth expands by-value members. " +
                 "Enumerators are sorted by value with a flags check.")]
    public Task<string> GetNativeType(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Type name (Packet, ns::Widget, Ns.Type for Il2Cpp).")] string? name = null,
        [Description("Type id from a previous result (pdb:0x1A2B, pdb:Name, rtti:0x140012000, il2cpp:Ns.Type, il2cpp:Ns.Type#statics, ida:Name).")] string? id = null,
        [Description("A typed address: " + NativeTools.AddressDescription)] string? address = null,
        [Description("The field at this offset into the type (hex): 0x48; 0x48.0x10 reads through the pointer field at 0x48.")] string? at = null,
        [Description("Levels of by-value struct, union and array members to inline (0-4, default 0); pointers are not followed.")] int depth = 0,
        [Description("auto (default: pdb, rtti, il2cpp, and the engine when its analysis is complete), pdb, rtti, il2cpp or engine.")] string? source = null,
        [Description("table (default) or c (a C declaration with offsets).")] string? format = null,
        [Description("Index of the first field, enumerator, vftable slot or candidate.")] int offset = 0,
        [Description("Max fields, enumerators, slots or candidates (default 200, max 5000).")] int limit = 200,
        [Description("Engine for source=engine: auto (default) or ida.")] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        int given = new[] { name, id, address }.Count(v => !string.IsNullOrWhiteSpace(v));
        if (given != 1) throw new ToolError(ErrorCode.InvalidArgument, given == 0 ? "Pass name, id or address." : "Pass only one of name, id and address.");
        if (!string.IsNullOrWhiteSpace(at) && !string.IsNullOrWhiteSpace(address))
            throw new ToolError(ErrorCode.InvalidArgument, "at= applies to name or id; an address already gives the offset.", "drop at, or look the type up by name");
        var src = (source ?? "").Trim().ToLowerInvariant();
        var sources = src switch
        {
            "" or "auto" => new HashSet<string> { NativeTypeCatalog.Pdb, NativeTypeCatalog.Rtti, NativeTypeCatalog.Il2Cpp },
            NativeTypeCatalog.Pdb or NativeTypeCatalog.Rtti or NativeTypeCatalog.Il2Cpp => new HashSet<string> { src },
            NativeTypeCatalog.Engine => new HashSet<string>(),
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown source '{source}'.", "use auto, pdb, rtti, il2cpp or engine"),
        };
        bool c = (format ?? "").Trim().ToLowerInvariant() switch
        {
            "" or "table" => false,
            "c" => true,
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown format '{format}'.", "use table or c"),
        };
        depth = Math.Clamp(depth, 0, 4);
        offset = Math.Max(0, offset);
        limit = Math.Clamp(limit, 1, 5000);

        var (native, rva) = await Task.Run(() => NativeAnalysisTools.Resolve(workspace, code, image, string.IsNullOrWhiteSpace(address) ? "rva:0" : address), cancellationToken);
        INativeDecompilerSession? session = null;
        if (src == NativeTypeCatalog.Engine)
        {
            if (engines == null) throw new ToolError(ErrorCode.Unsupported, "No decompiler engine is configured.");
            engines.Provider(engine);
            session = await engines.Session(native, engine, new Progress<NativeProviderProgress>(p =>
                progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
            if (userTypes != null) await userTypes.EnsureAsync(native, session, cancellationToken);
        }
        else if (src is "" or "auto" && engines?.CompletedSession(native) is { } open) session = open;

        var catalog = new NativeTypeCatalog(workspace, code);
        var ctx = await catalog.Open(native, sources, session, src == NativeTypeCatalog.Engine, cancellationToken);
        (ctx.SlotOffset, ctx.SlotLimit) = (offset, limit);
        var notes = new List<string>();

        NativeTypeView? view = null;
        string query;
        string? owner = null, ownerAddress = null;
        IReadOnlyList<NativeFieldPath> paths = [];
        IReadOnlyList<NativeTypeCandidate> candidates = [];
        int totalCandidates = 0;
        if (!string.IsNullOrWhiteSpace(address))
        {
            query = $"address {NativeAddress.Va(native.Image, rva)}";
            var typed = await Task.Run(() => catalog.AtAddress(ctx, rva, cancellationToken), cancellationToken)
                ?? throw new ToolError(ErrorCode.NotFound, $"No type source covers {NativeAddress.Va(native.Image, rva)} in {native.Id}.",
                    "typed addresses come from PDB globals (load_pdb), RTTI vftables and descriptors, and Il2Cpp metadata slots (apply_il2cpp_names); resolve_address describes any address");
            view = typed.Type;
            owner = typed.Owner;
            ownerAddress = NativeAddress.Va(native.Image, typed.Start);
            paths = typed.Paths;
            notes.Add(typed.Note);
        }
        else if (!string.IsNullOrWhiteSpace(id))
        {
            query = $"id {id.Trim()}";
            view = await catalog.Get(ctx, id.Trim(), cancellationToken);
        }
        else
        {
            query = $"name {name!.Trim()}";
            var found = await catalog.Find(ctx, name.Trim(), offset, limit, cancellationToken);
            if (found.View != null) view = await Task.Run(found.View, cancellationToken);
            else if (found.Total == 0)
                throw new ToolError(ErrorCode.NotFound, $"No type named or containing '{name.Trim()}' in {native.Id} ({string.Join(", ", Describe(ctx))}).",
                    ctx.PdbFile == null && native.Image.Format == ImageFormat.Pe ? "load_pdb adds the PDB's types; list_native_types lists the engine's" : "list_native_types lists the engine's types; source=engine reads them");
            else (candidates, totalCandidates) = (found.Candidates, found.Total);
        }
        if (view != null && !string.IsNullOrWhiteSpace(at)) paths = NativeTypeCatalog.FollowPath(ctx, view, at.Trim(), cancellationToken);
        notes.AddRange(ctx.Notes);

        bool truncated;
        if (view != null)
        {
            view = NativeTypeCatalog.WithGlobals(ctx, view);
            var viewNotes = view.Notes.ToList();
            var fields = depth > 0 ? NativeTypeCatalog.Expand(ctx, view, depth, viewNotes) : view.Fields.ToList();
            var pageFields = fields.Skip(offset).Take(limit).ToList();
            var pageEnums = view.Enumerators.Skip(offset).Take(limit).ToList();
            truncated = offset + pageFields.Count < fields.Count || offset + pageEnums.Count < view.Enumerators.Count
                        || view.Vftables.Any(v => offset + v.Entries.Count < v.Slots);
            if (c && view.Declaration == null) view = view with { Declaration = Declaration(view, fields) };
            view = view with { Fields = pageFields, TotalFields = fields.Count, Enumerators = pageEnums, Notes = viewNotes };
        }
        else truncated = offset + candidates.Count < totalCandidates;

        var report = new NativeTypeReport(native.Id, query, view, candidates, totalCandidates, owner, ownerAddress, paths, offset, truncated, notes);
        return StructuredOutput.With(Text(report, c), report);
    });

    private static IEnumerable<string> Describe(NativeTypeCatalog.Context c)
    {
        if (c.Uses(NativeTypeCatalog.Pdb)) yield return c.PdbFile != null ? "PDB loaded" : "no PDB";
        if (c.Uses(NativeTypeCatalog.Rtti)) yield return "RTTI read";
        if (c.Uses(NativeTypeCatalog.Il2Cpp)) yield return Il2CppNativeNames.Of(c.Native) != null ? "Il2Cpp names applied" : "no Il2Cpp names applied";
        yield return c.Session != null ? $"{c.Session.ProviderId} types read" : "engine not read";
    }

    private static string Text(NativeTypeReport r, bool c)
    {
        var sb = new StringBuilder();
        if (r.Type is not { } t)
        {
            sb.AppendLine($"{r.TotalCandidates} type(s) contain '{r.Query["name ".Length..]}' in {r.Image}; none is named so exactly" +
                          (r.Candidates.Count < r.TotalCandidates ? $" (showing {r.Offset + 1}-{r.Offset + r.Candidates.Count})" : "") + ":");
            foreach (var x in r.Candidates) sb.AppendLine($"  {x.Id}  {x.Kind} {x.Name}{(x.Size >= 0 ? $"  {x.Size} bytes" : "")}  [{x.Source}]");
            if (r.Truncated) sb.AppendLine($"More: offset={r.Offset + r.Candidates.Count}");
            sb.AppendLine("get_native_type id=<id> shows one.");
            foreach (var n in r.Notes) sb.AppendLine($"Note: {n}");
            return sb.ToString();
        }
        if (r.Owner != null) sb.AppendLine($"{r.Query["address ".Length..]} is in {r.Owner} (starts at {r.OwnerAddress}).");
        sb.Append($"{t.Kind} {t.Name}  [{t.Id}, {t.Source}]");
        if (t.Size >= 0) sb.Append($", {t.Size} (0x{t.Size:X}) bytes");
        if (t.Alignment is { } a) sb.Append($", align {a}");
        if (t.Packed) sb.Append(", packed");
        if (t.ArrayCount is { } n0) sb.Append($", {n0} elements");
        if (t.Referenced != null) sb.Append($", of {t.Referenced}");
        sb.AppendLine();
        foreach (var p in r.Paths) sb.AppendLine($"Field at +0x{p.Offset + p.Remainder:X}: {p.Path} ({p.Type}{(p.Remainder > 0 ? $", +0x{p.Remainder:X} into it" : "")})");
        // an engine's enum or typedef has no rows: its declaration says it all
        if (t.Declaration != null && (c || t.Fields.Count + t.Enumerators.Count == 0 && t.Function == null)) sb.AppendLine(t.Declaration);
        else
        {
            if (t.Bases.Count > 0)
                sb.AppendLine("Bases: " + string.Join(", ", t.Bases.Select(b => $"{(b.Virtual ? "virtual " : "")}{b.Name}{(b.Offset >= 0 ? $" @+0x{b.Offset:X}" : "")}{(b.Id != null ? $" [{b.Id}]" : "")}")));
            if (t.Function is { } f)
                sb.AppendLine($"Function: {f.Return} {f.Convention}({string.Join(", ", f.Parameters.Select(p => p.Type).Concat(f.Variadic ? ["..."] : []))})" +
                              (f.This != null ? $", this {f.This}" : ""));
            if (t.Fields.Count > 0)
            {
                sb.AppendLine($"Fields ({(t.Fields.Count < t.TotalFields ? $"{r.Offset + 1}-{r.Offset + t.Fields.Count} of " : "")}{t.TotalFields}; offset  size  name  type  [id]):");
                foreach (var f2 in t.Fields)
                    sb.AppendLine($"  {(f2.Offset >= 0 ? $"+0x{f2.Offset:X}" : "-")}  {(f2.Size >= 0 ? f2.Size.ToString(System.Globalization.CultureInfo.InvariantCulture) : "?")}  " +
                                  $"{f2.Name}{(f2.BitSize is { } bits ? $" : {bits} (bit {f2.BitOffset})" : "")}  {f2.Type}" +
                                  (f2.Kind is "member" ? "" : $"  ({f2.Kind})") + (f2.TypeId != null ? $"  [{f2.TypeId}]" : "") + (f2.Note != null ? $"  // {f2.Note}" : ""));
            }
            if (t.Enumerators.Count > 0)
            {
                sb.AppendLine($"Enumerators by value{(t.FlagsLike ? " (flags)" : "")}:");
                foreach (var e in t.Enumerators) sb.AppendLine($"  {e.Hex}  {e.Value}  {e.Name}");
            }
            foreach (var v in t.Vftables)
            {
                sb.AppendLine($"vftable {v.Address} for subobject +0x{v.SubobjectOffset:X}: {v.Slots} slot(s)");
                foreach (var s in v.Entries) sb.AppendLine($"  [{s.Index}] +0x{s.Offset:X}  {s.Address}{(s.Name != null ? "  " + s.Name : "")}");
            }
            if (t.GlobalsOfType > 0) sb.AppendLine($"Globals of this type ({t.GlobalsOfType}): {string.Join(", ", t.Globals)}");
        }
        if (r.Truncated) sb.AppendLine($"More rows: offset={r.Offset + Math.Max(t.Fields.Count, Math.Max(t.Enumerators.Count, t.Vftables.Select(v => v.Entries.Count).DefaultIfEmpty(0).Max()))}");
        foreach (var n in t.Notes.Concat(r.Notes)) sb.AppendLine($"Note: {n}");
        return sb.ToString();
    }

    /// <summary>A C declaration of a view with each member's offset as a comment.</summary>
    private static string Declaration(NativeTypeView t, IReadOnlyList<NativeTypeField> fields)
    {
        var sb = new StringBuilder();
        switch (t.Kind)
        {
            case "enum":
                sb.Append($"enum {t.Name}\n{{\n");
                foreach (var e in t.Enumerators) sb.Append($"  {e.Name} = {e.Hex},\n");
                return sb.Append("};").ToString();
            case "struct" or "class" or "union" or "interface" or "statics":
                sb.Append($"{(t.Kind is "union" ? "union" : "struct")} {t.Name}{(t.Bases.Count > 0 ? " : " + string.Join(", ", t.Bases.Select(b => b.Name)) : "")}" +
                          $"{(t.Size >= 0 ? $" // 0x{t.Size:X} bytes" : "")}\n{{\n");
                foreach (var f in fields.Where(f => f.Kind is not "base" and not "vbase"))
                {
                    var decl = f.Type.EndsWith(']') && f.Type.IndexOf('[', StringComparison.Ordinal) is > 0 and var bracket
                        ? $"{f.Type[..bracket]} {f.Name}{f.Type[bracket..]}" : $"{f.Type} {f.Name}";
                    sb.Append($"  /* {(f.Offset >= 0 ? $"+0x{f.Offset:X}" : "static")} */ {(f.Kind == "static" ? "static " : "")}{decl}{(f.BitSize is { } b ? $" : {b}" : "")};\n");
                }
                return sb.Append("};").ToString();
            case "function" when t.Function is { } fn:
                return $"{fn.Return} {fn.Convention}({string.Join(", ", fn.Parameters.Select(p => p.Type).Concat(fn.Variadic ? ["..."] : []))});";
            default:
                return $"/* {t.Kind} */ {t.Name};";
        }
    }
}
