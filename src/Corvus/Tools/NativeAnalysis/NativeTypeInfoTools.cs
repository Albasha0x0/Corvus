using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>Native type layouts from the PDB, RTTI, metadata and the decompiler engine's database.</summary>
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
        [property: Description("address=: the typed item containing it (PDB global, vftable, metadata slot).")] string? Owner,
        string? OwnerAddress,
        [property: Description("The field path(s) at the address or at=.")] IReadOnlyList<NativeFieldPath> Paths,
        [property: Description("Index of the first returned field, enumerator, slot or candidate.")] int Offset,
        [property: Description("More rows exist past this page: call again with offset = offset + rows returned.")] bool Truncated,
        IReadOnlyList<string> Notes)
    {
        [Description("read=true: where the values were read (VA).")]
        public string? ReadAddress { get; init; }
        [Description("read=true on a type without fields (scalar, enum, pointer, array): its value.")]
        public string? Value { get; init; }
    }

    [McpServerTool(Name = "get_native_type", Title = "Native type layout", UseStructuredContent = true, OutputSchemaType = typeof(NativeTypeReport))]
    [Description("Layout of a native type (fields, bases, enum values) from PDB, RTTI, metadata, ObjC, Swift or an engine. Look up by " +
                 "name, id or typed address; read=true adds the values at address.")]
    public Task<string> GetNativeType(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Type name (ns::Widget, Ns.Type), case-insensitive; a glob (*Widget*) lists matches.")] string? name = null,
        [Description("Type id from a result (pdb:0x1A2B, rtti:0x140012000, metadata:Ns.Type).")] string? id = null,
        [Description("A typed address: " + NativeTools.AddressDescription)] string? address = null,
        [Description("Hex field offset to name (all union members); 0x48.0x10 goes through the pointer at 0x48.")] string? at = null,
        [Description("Levels of by-value members inlined (0-4).")] int depth = 0,
        [Description("Type source (default auto).")] string? source = null,
        [Description("c: a C declaration (default table).")] string? format = null,
        [Description("First row (field, enumerator, slot, candidate).")] int offset = 0,
        [Description("Max rows (max 5000).")] int limit = 200,
        [Description(NativeCodeTools.EngineDescription)] string? engine = null,
        [Description("Add the field values at address (with name or id: that type read there).")] bool read = false,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        // read=true with name or id: address says where the type is read; it is not looked up.
        bool readAt = read && !string.IsNullOrWhiteSpace(address) && (!string.IsNullOrWhiteSpace(name) || !string.IsNullOrWhiteSpace(id));
        var lookup = readAt ? null : address;
        int given = new[] { name, id, lookup }.Count(v => !string.IsNullOrWhiteSpace(v));
        if (given != 1) throw new ToolError(ErrorCode.InvalidArgument, given == 0 ? "Pass name, id or address." : "Pass only one of name, id and address.",
            "read=true takes name or id together with address");
        if (read && string.IsNullOrWhiteSpace(address))
            throw new ToolError(ErrorCode.InvalidArgument, "read=true needs an address.", "pass address: a typed one, or where the named type is");
        if (!string.IsNullOrWhiteSpace(at) && !string.IsNullOrWhiteSpace(lookup))
            throw new ToolError(ErrorCode.InvalidArgument, "at= applies to name or id; an address already gives the offset.", "drop at, or look the type up by name");
        var src = (source ?? "").Trim().ToLowerInvariant();
        var sources = src switch
        {
            "" or "auto" => new HashSet<string> { NativeTypeCatalog.Pdb, NativeTypeCatalog.Rtti, NativeTypeCatalog.Metadata, NativeTypeCatalog.ObjC, NativeTypeCatalog.Swift },
            NativeTypeCatalog.Pdb or NativeTypeCatalog.Rtti or NativeTypeCatalog.Metadata or NativeTypeCatalog.ObjC or NativeTypeCatalog.Swift => new HashSet<string> { src },
            NativeTypeCatalog.Engine => new HashSet<string>(),
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown source '{source}'.", "use auto, pdb, rtti, metadata, objc, swift or engine"),
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
        // source=engine reads only the engine; auto takes the engine the shared rule picks, else none.
        EngineChoice? choice = null;
        if (src == NativeTypeCatalog.Engine)
        {
            if (engines == null) throw new ToolError(ErrorCode.Unsupported, "No decompiler engine is configured.", "use source=auto, pdb or rtti");
            choice = EngineChoice.EngineOnly(engine, engines, native);
        }
        else if (src is "" or "auto")
        {
            var (mode, named) = EngineChoice.Mode(engine, engines);
            if (EngineChoice.Of(mode, named, engines, native, null) is { External: true } picked) choice = picked;
        }
        if (choice != null)
        {
            session = await engines!.Session(native, choice.Engine, new Progress<NativeProviderProgress>(p =>
                progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
            if (userTypes != null) await userTypes.EnsureAsync(native, session, cancellationToken);
        }

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
        uint? readBase = readAt ? rva : null;
        if (!string.IsNullOrWhiteSpace(lookup))
        {
            query = $"address {NativeAddress.Va(native.Image, rva)}";
            var typed = await Task.Run(() => catalog.AtAddress(ctx, rva, cancellationToken), cancellationToken)
                ?? throw new ToolError(ErrorCode.NotFound, $"No type source covers {NativeAddress.Va(native.Image, rva)} in {native.Id}.",
                    "typed addresses come from load_pdb, RTTI and apply_metadata_names; resolve_address describes any address" +
                    (read ? "; or pass the type's name with read=true" : ""));
            view = typed.Type;
            owner = typed.Owner;
            ownerAddress = NativeAddress.Va(native.Image, typed.Start);
            paths = typed.Paths;
            notes.Add(typed.Note);
            if (read) readBase = typed.Start;
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
                throw new ToolError(ErrorCode.NotFound, $"No type {(Wildcard.IsPattern(name) ? "matching" : "named or containing")} '{name.Trim()}' in {native.Id} ({string.Join(", ", Describe(ctx))}).",
                    ctx.PdbFile == null && native.Image.Format == ImageFormat.Pe ? "load_pdb adds the PDB's types; list_native_types lists the engine's" : "list_native_types lists the engine's types; source=engine reads them");
            else (candidates, totalCandidates) = (found.Candidates, found.Total);
        }
        if (view != null && !string.IsNullOrWhiteSpace(at)) paths = NativeTypeCatalog.FollowPath(ctx, view, at.Trim(), cancellationToken);
        notes.AddRange(ctx.Notes);

        bool truncated;
        string? rootValue = null;
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
            if (readBase is { } at0)
            {
                var values = new ValueReader(catalog, ctx, code?.Ready(native));
                pageFields = await values.Fields(at0, pageFields, cancellationToken);
                if (view.Fields.Count == 0) rootValue = await values.Value(at0, view.Size, view.Name, view.Kind == "enum" ? view.Enumerators : null, null, cancellationToken);
                notes.Add($"values read at {NativeAddress.Va(native.Image, at0)} from the image's mapped bytes (patches included)");
            }
            view = view with { Fields = pageFields, TotalFields = fields.Count, Enumerators = pageEnums, Notes = viewNotes };
        }
        else truncated = offset + candidates.Count < totalCandidates;

        var report = new NativeTypeReport(native.Id, query, view, candidates, totalCandidates, owner, ownerAddress, paths, offset, truncated, notes)
        {
            ReadAddress = readBase is { } b ? NativeAddress.Va(native.Image, b) : null, Value = rootValue,
        };
        return ToolOutput.With(Text(report, c), report);
    });

    /// <summary>Field values at an address, enums named through the catalog.</summary>
    private sealed class ValueReader(NativeTypeCatalog catalog, NativeTypeCatalog.Context ctx, Native.Code.NativeCodeIndex? index)
    {
        private readonly Dictionary<string, IReadOnlyList<NativeTypeEnumerator>?> _enums = new(StringComparer.Ordinal);

        private string? NameAt(uint rva) => index?.NameAt(rva) ?? (index?.FunctionAt(rva) is { } f ? Format.Within(f.Name, f.Start, rva) : null);

        public async Task<List<NativeTypeField>> Fields(uint at, List<NativeTypeField> fields, CancellationToken ct)
        {
            var result = new List<NativeTypeField>(fields.Count);
            foreach (var f in fields)
            {
                if (f.Offset < 0 || f.Size <= 0 || f.Kind is "padding" or "base" or "vbase" or "static" || f.Offset > uint.MaxValue - at) { result.Add(f); continue; }
                result.Add(f with { Value = await Value(at + (uint)f.Offset, f.Size, f.Type, await Enumerators(f, ct), f, ct) });
            }
            return result;
        }

        public Task<string?> Value(uint rva, long size, string type, IReadOnlyList<NativeTypeEnumerator>? enumerators, NativeTypeField? field, CancellationToken ct) =>
            Task.FromResult(NativeValues.Read(ctx.Native.Image, rva, size, type, NameAt, enumerators, field?.BitOffset, field?.BitSize));

        /// <summary>The enumerators of a field whose type is an enum (looked up by its id once).</summary>
        private async Task<IReadOnlyList<NativeTypeEnumerator>?> Enumerators(NativeTypeField f, CancellationToken ct)
        {
            if (f.TypeId is not { } id || NativeValues.Classify(f.Type, ctx.Native.Image.Is64Bit ? 8 : 4) != null || NativeValues.ArrayOf(f.Type) != null) return null;
            if (!_enums.TryGetValue(id, out var list))
            {
                try { list = await catalog.Get(ctx, id, ct) is { Kind: "enum" } e ? e.Enumerators : null; }
                catch (ToolError) { list = null; }
                _enums[id] = list;
            }
            return list;
        }
    }

    private static IEnumerable<string> Describe(NativeTypeCatalog.Context c)
    {
        if (c.Uses(NativeTypeCatalog.Pdb)) yield return c.PdbFile != null ? "PDB loaded" : "no PDB";
        if (c.Uses(NativeTypeCatalog.Rtti)) yield return "RTTI read";
        if (c.Uses(NativeTypeCatalog.Metadata)) yield return AotNativeNames.Of(c.Native) != null ? "metadata names applied" : "no metadata names applied";
        yield return c.Session != null ? $"{c.Session.ProviderId} types read" : "engine not read";
    }

    private static string Text(NativeTypeReport r, bool c)
    {
        var sb = new StringBuilder();
        if (r.Type is not { } t)
        {
            var pattern = r.Query["name ".Length..];
            sb.AppendLine((Wildcard.IsPattern(pattern) ? $"{r.TotalCandidates} type(s) match '{pattern}' in {r.Image}"
                              : $"{r.TotalCandidates} type(s) contain '{pattern}' in {r.Image}; none is named so exactly") +
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
        if (r.Value != null) sb.AppendLine($"Value at {r.ReadAddress}: {r.Value}");
        // An engine's enum or typedef has no rows: its declaration says it all.
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
                                  (f2.Kind is "member" ? "" : $"  ({f2.Kind})") + (f2.TypeId != null ? $"  [{f2.TypeId}]" : "") + (f2.Value != null ? $"  = {f2.Value}" : "") +
                                  (f2.Note != null ? $"  // {f2.Note}" : ""));
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
