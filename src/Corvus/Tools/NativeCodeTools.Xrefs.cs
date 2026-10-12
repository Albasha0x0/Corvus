using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

public sealed partial class NativeCodeTools
{
    /// <summary>One direction of a find_xrefs answer: its title lines, rows in the tool's row format, the target as shown and an import's binding.</summary>
    private sealed record XrefPart(string Title, List<string> Rows, string Target, string? BoundTo);

    /// <summary>Row kinds that transfer control (built-in, engine and import-site kinds); every other kind is a data reference.</summary>
    private static readonly HashSet<string> CodeKinds = new(StringComparer.OrdinalIgnoreCase)
    {
        "Call", "Jump", "ConditionalJump", "TailCall", "SwitchCase", "ImportCall", "ImportJump", "VirtualExact", "VirtualPossible", "CallReg", "DynCall", "Code",
    };

    [McpServerTool(Name = "find_xrefs", Title = "Native cross-references", UseStructuredContent = true, OutputSchemaType = typeof(XrefList))]
    [Description("What references a native address: calls (also via import slots and thunks), jumps, data reads/writes, address-taken uses, " +
                 "switch tables, relocated pointers, each with its function and, for calls, recovered arguments; for a virtual method, RTTI " +
                 "virtual call sites. An import (module!name): call sites and binding; an export: also callers in other loaded images; a " +
                 "GetProcAddress import: where it is resolved. direction=from: what the address (or function) references. A struct member " +
                 "(Type::member, Type+0x18): its uses in the pseudocode of functions whose prototype names the type, via IDA or Ghidra. " + IndexNote)]
    public Task<string> FindXrefs(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription + " Or a struct member: Type::member, Type.member, Type+0xOFFSET.")] string? address = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Max rows.")] int limit = 500,
        [Description("Instead of address: up to 100 targets.")] string[]? addresses = null,
        [Description(EngineDescription + " Adds the RTTI virtual calls an engine lacks.")]
        string? engine = null,
        [Description("to (default), from or both.")] string? direction = null,
        [Description("any (default); code: calls, jumps; data: reads, writes, pointers, address-taken.")] string? kind = null,
        [Description("Struct member: typed (default) or all (every function; call again to continue).")] string? scope = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var dir = direction?.Trim().ToLowerInvariant() switch
        {
            null or "" or "to" => "to",
            "from" => "from",
            "both" => "both",
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown direction '{direction}'.", "use to, from or both"),
        };
        bool? code = kind?.Trim().ToLowerInvariant() switch
        {
            null or "" or "any" => null,
            "code" => true,
            "data" => false,
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown kind '{kind}'.", "use any, code or data"),
        };
        var mode = Mode(engine);
        if ((addresses is { Length: > 0 }) == !string.IsNullOrWhiteSpace(address))
            throw new ToolError(ErrorCode.InvalidArgument, "Pass address or addresses (one of them).", "address=<one target>, or addresses=[...] for several");
        if (addresses?.Length > MaxXrefTargets)
            throw new ToolError(ErrorCode.InvalidArgument, $"{addresses.Length} addresses; at most {MaxXrefTargets} per call.", "split the addresses");
        var (native, index) = await Open(image, context, progress, cancellationToken);
        if (addresses is { Length: > 0 })
            return await XrefsBatch(native, index, addresses, dir, code, Choose(mode, native, index), offset, limit, progress, cancellationToken);
        if (FieldTarget(address!) is { } field && !IsAddress(index, address!))
        {
            if (dir != "to") throw new ToolError(ErrorCode.InvalidArgument, "A struct member has references to it only.", "use direction=to for Type::member");
            return await FieldXrefs(native, field, mode.Mode, offset, limit, progress, cancellationToken, FieldScope(scope));
        }
        var choice = Choose(mode, native, index);
        var parts = new List<XrefPart>();
        // call arguments only for the page: a kind filter moves rows, so it analyzes every row
        if (dir != "from") parts.Add(await XrefsTo(native, index, address!, choice, progress, cancellationToken, code == null ? (offset, limit) : (0, int.MaxValue)));
        if (dir != "to") parts.Add(await XrefsFrom(native, index, address!, choice, progress, cancellationToken));
        var filtered = Filter(parts, code);
        var rows = filtered.SelectMany(p => p.Rows).ToList();
        var titles = string.Concat(filtered.Select(p => p.Title + (filtered.Count > 1 || code != null ? $"  {Plural(p.Rows.Count, "row")}" +
                                                                                                      (code is { } c ? $", {(c ? "code" : "data")} only" : "") + "\n" : "")));
        var external = choice.External ? "" : Coverage(index);
        var boundTo = filtered.Select(p => p.BoundTo).FirstOrDefault(b => b != null);
        return ToolOutput.With(titles + choice.Line + "\n" + external + pager.PageRows(rows, offset, limit, "reference"),
            Xrefs(native.Id, filtered[0].Target, rows, offset, limit, boundTo, choice));
    });

    private const int MaxXrefTargets = 100;

    private static List<XrefPart> Filter(List<XrefPart> parts, bool? code) =>
        parts.Select(p => p with { Rows = code is { } c ? p.Rows.Where(r => KindOf(r) is { } k && CodeKinds.Contains(k) == c).ToList() : p.Rows }).ToList();

    /// <summary>
    /// find_xrefs addresses=[...]: a section per target, in order; a target that fails is its section's error. With an engine the
    /// references to every target come from one request.
    /// </summary>
    private async Task<string> XrefsBatch(LoadedNative native, NativeCodeIndex index, string[] inputs, string dir, bool? code, EngineChoice choice,
        int offset, int limit, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        offset = Math.Max(0, offset);
        limit = Math.Clamp(limit, 1, 5_000);
        var rvas = new uint?[inputs.Length];
        for (int i = 0; i < inputs.Length; i++)
            try { rvas[i] = Address(index, inputs[i]); }
            catch (ToolError) { }
        var engineTo = new Dictionary<uint, XrefPart>();
        if (choice.External && dir != "from" && rvas.OfType<uint>().Distinct().ToList() is { Count: > 0 } known)
            foreach (var (rva, via) in known.Zip(await _engine!.XrefsMany(native, index, known, choice, progress, ct)))
                engineTo[rva] = new XrefPart(via.Title, via.Rows, via.Target, null);
        var sb = new System.Text.StringBuilder(choice.Line + "\n");
        var items = new List<XrefEntry>();
        int total = 0;
        for (int i = 0; i < inputs.Length; i++)
        {
            sb.Append($"[{i + 1}/{inputs.Length}] {inputs[i]}: ");
            try
            {
                var parts = new List<XrefPart>();
                if (dir != "from")
                    parts.Add(rvas[i] is { } r && engineTo.TryGetValue(r, out var fetched) ? fetched
                        : await XrefsTo(native, index, inputs[i], choice, progress, ct, code == null ? (offset, limit) : (0, int.MaxValue)));
                if (dir != "to") parts.Add(await XrefsFrom(native, index, inputs[i], choice, progress, ct));
                var filtered = Filter(parts, code);
                var rows = filtered.SelectMany(p => p.Rows).ToList();
                var page = rows.Skip(offset).Take(limit).ToList();
                sb.Append(string.Concat(filtered.Select(p => p.Title))).AppendLine($"  {Plural(rows.Count, "row")}" +
                    (page.Count < rows.Count ? $" (showing {(page.Count == 0 ? 0 : offset + 1)}-{offset + page.Count})" : ""));
                foreach (var row in page) sb.Append("  ").AppendLine(row);
                total += rows.Count;
                if (page.Count > 0) items.AddRange(Xrefs(native.Id, filtered[0].Target, page, 0, page.Count, null, choice).Items.Select(e => e with { Of = inputs[i] }));
            }
            catch (ToolError e)
            {
                sb.AppendLine($"error {ToolError.CodeName(e.Code)}: {e.Message}");
                items.Add(new XrefEntry(null, null, "error", null, e.Message) { Of = inputs[i] });
            }
        }
        return ToolOutput.With(pager.Page(sb.ToString()), new XrefList(native.Id, $"{inputs.Length} targets", items, offset, total, items.Count < total, null, choice.Engine, choice.Note));
    }

    /// <summary>The kind column of a row in the tool's format, or null for a row of another form.</summary>
    private static string? KindOf(string row) => XrefRow().Match(row) is { Success: true } m ? m.Groups["kind"].Value : null;

    /// <summary>References to the address: the engine's, or the built-in index's (imports, late-bound imports, virtual calls, switch cases, other images).</summary>
    private async Task<XrefPart> XrefsTo(LoadedNative native, NativeCodeIndex index, string address, EngineChoice choice,
        IProgress<ProgressNotificationValue> progress, CancellationToken ct, (int First, int Count) page)
    {
        if (choice.External)
        {
            var via = await _engine!.Xrefs(native, index, Address(index, address), choice, progress, ct);
            return new XrefPart(via.Title, via.Rows, via.Target, null);
        }
        // a late-bound import (GetProcAddress) by name: its resolution and the calls through its pointer
        var dynamicRows = NativeCallTools.DynamicXrefRows(index, address, ct);
        uint rva;
        try { rva = Address(index, address); }
        catch (ToolError) when (dynamicRows != null)
        {
            return new XrefPart($"References to {address.Trim()} (late-bound import):\n", dynamicRows, $"{address.Trim()} (late-bound import)", null);
        }
        string Va(uint r) => NativeAddress.Va(index.Image, r);
        var rows = new List<string>();
        var import = index.Image.Imports.FirstOrDefault(i => i.SlotRva == rva);
        if (import != null)
            rows.AddRange(NativeCallTools.ImportRows(index, import, from => Where(index, from), ct));
        else
        {
            // virtual call sites that may reach the address (RTTI resolution) among the instruction references, by source
            var refs = index.RefsTo(rva).Concat(index.VirtualEdgesTo(rva)).OrderBy(x => x.From).ToList();
            var refRows = NativeCallTools.WithArguments(index, refs.Select(x => (x.From, x.Kind.ToString(), x.Kind is XrefKind.Call or XrefKind.TailCall || x.IsVirtualCall)),
                from => Where(index, from), ct, page.First, page.Count);
            var graphs = new Dictionary<uint, FunctionGraph?>();
            for (int i = 0; i < refs.Count && i < refRows.Count; i++)
                if (refs[i].Kind == XrefKind.SwitchCase && CaseText(index, refs[i].From, rva, graphs, ct) is { } values)
                    refRows[i] += "  " + values;
                else if (refs[i].Kind == XrefKind.Pointer && index.PointersUnconfirmed)
                    refRows[i] += "  " + UnconfirmedPointer;
            rows.AddRange(refRows);
        }
        if (dynamicRows != null) rows.AddRange(dynamicRows);
        var target = $"{Va(rva)}{(Target(index, rva, ct) is { } t ? $" ({t})" : "")}";
        var title = $"References to {target}:\n";
        string? boundTo = null;
        if (link != null)
        {
            // Other loaded images reach this address through their imports; an import slot shows what it is bound to.
            await link.WarmUp(null, ct);
            if (import != null) title += $"Bound to: {boundTo = NativeLinkService.Describe(link.BindImport(native, import))}\n";
            rows.AddRange(workspace.Read(() => link.ImportCallSites(native, rva, ct)));
        }
        return new XrefPart(title, rows, target, boundTo);
    }

    /// <summary>
    /// References made by the item at the address (an instruction, or a data pointer) or, at a function start, by the whole
    /// function, with the RTTI-resolved virtual calls; rows end "-> target (name)".
    /// </summary>
    private async Task<XrefPart> XrefsFrom(LoadedNative native, NativeCodeIndex index, string address, EngineChoice choice,
        IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var rva = Address(index, address);
        if (choice.External)
        {
            var via = await _engine!.XrefsFrom(native, index, rva, choice, progress, ct);
            return new XrefPart(via.Title, via.Rows, via.Target, null);
        }
        var fn = index.FunctionByStart(rva);
        var refs = fn != null
            ? index.RefsFrom(fn).Concat(index.Ranges(fn).SelectMany(r => index.VirtualEdgesFrom(r.Start, r.End)))
            : index.RefsFrom(rva, rva + 1).Concat(index.VirtualEdgesFrom(rva, rva + 1));
        var rows = refs.OrderBy(x => x.From).ThenBy(x => x.To)
            .Select(x => $"{NativeAddress.Va(index.Image, x.From)}  {x.Kind,-10} {Where(index, x.From)}  -> {NativeAddress.Va(index.Image, x.To)}" +
                         (Target(index, x.To, ct) is { } t ? $" ({t})" : "") + (x.Kind == XrefKind.Pointer && index.PointersUnconfirmed ? "  " + UnconfirmedPointer : ""))
            .ToList();
        var target = $"{NativeAddress.Va(index.Image, rva)}{(Target(index, rva, ct) is { } name ? $" ({name})" : "")}";
        return new XrefPart($"References from {target}{(fn != null ? $" (the whole function, {fn.Size} bytes)" : "")}:\n", rows, target, null);
    }

    private const string UnconfirmedPointer = "unconfirmed: no relocations, accepted by address range";

    private static string Where(NativeCodeIndex index, uint from) => index.FunctionAt(from) is { } f ? $"{f.Name}+0x{from - f.Start:X}" : "(no function)";

    /// <summary>A target's name, pointer name or string.</summary>
    private static string? Target(NativeCodeIndex index, uint rva, CancellationToken ct) =>
        index.NameAt(rva) ?? NativeCallTools.PointerName(index, rva, ct) ?? (index.StringAt(rva) is not null ? index.CommentFor(rva) : null);
}
