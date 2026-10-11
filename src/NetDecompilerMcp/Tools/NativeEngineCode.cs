using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

/// <summary>Which engine answers a native code call (ours, ida or ghidra) and why: the Engine line of the text and the Engine / EngineNote fields.</summary>
internal sealed record EngineChoice(string Engine, string Note)
{
    /// <summary>Whether an external engine answers (not the built-in index).</summary>
    public bool External => Engine != "ours";
    public string Line => $"Engine: {Engine} ({Note})";
}

/// <summary>
/// list_functions, disassemble, get_cfg, find_xrefs and native_call_tree answered through an engine session (IDA or
/// Ghidra) in the same formats, marked "(via IDA)" or "(via Ghidra)": for images whose instruction set the built-in
/// analysis does not decode (ARM), and for any image when the engine preference picks an engine (engine=ida or
/// engine=ghidra, or auto once that engine's analysis is complete). Merging: functions, bounds, references and blocks
/// are the engine's; names in effect here (user, PDB, Il2Cpp, exports) win over the engine's own (they are pushed into
/// the database first); virtual call edges the built-in index resolved through RTTI and the engine has no reference
/// for are added, marked as ours.
/// </summary>
internal sealed class NativeEngineCode(NativeEngineService engines, OutputPager pager, NativeNamePush? names)
{
    /// <summary>The marker of results an engine produced: "(via IDA)", "(via Ghidra)".</summary>
    public static string Via(string engine) => $"(via {NativeEngineService.DisplayName(engine)})";

    /// <summary>Whether the call goes to an engine: the built-in analysis does not decode the code, and an engine is installed.</summary>
    public bool Serves(NativeCodeIndex index) => index.Support == CodeSupport.DeclaredFunctionsOnly && engines.IsAvailable;

    /// <summary>
    /// Which engine answers a call. ours: the built-in index, no engine is asked anything. auto: the engine whose analysis
    /// of the image is complete in this session (IDA's before Ghidra's; checked without a request to the engine), or, when
    /// the built-in analysis does not decode the image's instructions, the first engine installed (IDA, then Ghidra); else
    /// ours (the result says when a saved engine analysis of the image exists that engine=ida or engine=ghidra would
    /// load). ida, ghidra: that engine (the analysis is started or waited for by the call), or provider_unavailable.
    /// </summary>
    /// <param name="named">Whether the call named the engine (else it is the server default).</param>
    public static EngineChoice Choose(EngineMode mode, bool named, NativeEngineService? engines, LoadedNative native, NativeCodeIndex index)
    {
        var origin = named ? $"engine={EngineModes.Name(mode)}" : $"server default {EngineModes.Name(mode)}";
        bool undecoded = index.Support == CodeSupport.DeclaredFunctionsOnly;
        switch (mode)
        {
            case EngineMode.Ours:
                return new("ours", $"{origin}: the built-in index; no engine consulted");
            case EngineMode.Ida or EngineMode.Ghidra:
                var id = EngineModes.ProviderId(mode)!;
                var display = NativeEngineService.DisplayName(id);
                if (engines == null)
                    throw new ToolError(ErrorCode.ProviderUnavailable, $"engine={id}: no analysis engine is set up in this server.", "use engine=auto or engine=ours");
                if (engines.UnavailabilityOf(id) is { } u)
                    throw new ToolError(ErrorCode.ProviderUnavailable, $"engine={id}: {display} is not available: {u.Reason}",
                        (u.Remediation is { } r ? r + "; or " : "") + "use engine=auto or engine=ours for the built-in analysis");
                return new(id, $"{origin}: {display}'s analysis");
            default:
                if (engines?.CompletedSession(native) is { } done)
                    return new(done.ProviderId, $"{origin}: {NativeEngineService.DisplayName(done.ProviderId)}'s analysis of this image is complete in this session");
                if (undecoded && engines?.FirstAvailable() is { } first)
                    return new(first, $"{origin}: the built-in analysis does not decode {index.Image.Arch} instructions");
                if (undecoded)
                    return new("ours", $"{origin}: the built-in analysis does not decode {index.Image.Arch} instructions and no engine (IDA, Ghidra) is available");
                return new("ours", engines?.SavedAnalysis(native) is { } saved
                    ? $"{origin}: {NativeEngineService.DisplayName(saved)}'s saved analysis of this image is not loaded in this session; engine={saved} loads it without analyzing again"
                    : $"{origin}: no completed engine analysis of this image in this session");
        }
    }

    /// <summary>The typed error for an undecoded architecture when no engine is installed.</summary>
    public static ToolError Unsupported(NativeCodeIndex index, NativeEngineService? engines) =>
        new(ErrorCode.Unsupported, $"Instructions are not decoded for {index.Image.Arch} images by the built-in analysis" +
                                   (engines?.Unavailability is { } u ? $", and no engine is available: {u.Reason}" : "."),
            $"install IDA Pro 9 or newer with idalib (or set NDM_IDA_DIR), or Ghidra 12 or newer with a JDK (set NDM_GHIDRA_DIR), so {index.Image.Arch} code is analyzed through it" +
            (engines?.Unavailability is { Remediation: { } r } ? $": {r}" : ""));

    internal async Task<INativeDecompilerSession> Session(LoadedNative native, EngineChoice choice, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var display = NativeEngineService.DisplayName(choice.Engine);
        var session = await engines.Session(native, choice.Engine, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = $"{display} {p.Stage}" })), ct);
        if (names != null) await names.EnsureAsync(native, session, ct);
        return session;
    }

    private static string Va(NativeCodeIndex index, uint rva) => NativeAddress.Va(index.Image, rva);

    /// <summary>Our name at a function start (user, PDB, Il2Cpp, export), else the engine's.</summary>
    private static string Name(NativeCodeIndex index, uint rva, string engineName) =>
        index.Sourced.NameAt(rva)?.Name ?? index.FunctionByStart(rva)?.KnownName ?? (engineName.Length > 0 ? engineName : $"sub_{rva:X}");

    private static List<string> FlagList(NativeFunctionFlags flags)
    {
        var list = new List<string>();
        if (flags.HasFlag(NativeFunctionFlags.Thunk)) list.Add("thunk");
        if (flags.HasFlag(NativeFunctionFlags.Library)) list.Add("library");
        return list;
    }

    private static string Flags(NativeFunctionFlags flags) => FlagList(flags) is { Count: > 0 } list ? $"  [{string.Join(", ", list)}]" : "";

    private sealed class Functions(IReadOnlyList<NativeFunctionInfo> list)
    {
        public readonly IReadOnlyList<NativeFunctionInfo> List = list;
        private readonly uint[] _starts = list.Select(f => f.StartRva).ToArray();
        public readonly Dictionary<uint, NativeFunctionInfo> ByStart = list.GroupBy(f => f.StartRva).ToDictionary(g => g.Key, g => g.First());

        /// <summary>The function whose main chunk contains <paramref name="rva"/>.</summary>
        public NativeFunctionInfo? At(uint rva)
        {
            int i = Array.BinarySearch(_starts, rva);
            if (i < 0) i = ~i - 1;
            return i >= 0 && rva < List[i].EndRva ? List[i] : null;
        }
    }

    private static async Task<Functions> LoadFunctions(INativeDecompilerSession session, bool references, CancellationToken ct) =>
        new((await session.ListFunctionsAsync(references, ct)).OrderBy(f => f.StartRva).ToList());

    /// <summary>Whether the built-in index decodes the image's instructions (its virtual call edges can be merged in).</summary>
    private static bool Decoded(NativeCodeIndex index) => index.Support != CodeSupport.DeclaredFunctionsOnly;

    public async Task<string> ListFunctions(LoadedNative native, NativeCodeIndex index, string? filter, string? sort, int offset, int limit,
        EngineChoice choice, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var order = sort?.Trim().ToLowerInvariant();
        if (order is not (null or "" or "address" or "size" or "callers"))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown sort '{sort}'.", "use address, size or callers");
        var session = await Session(native, choice, progress, ct);
        var functions = await LoadFunctions(session, references: true, ct);
        var rows = functions.List.Select(f => (f, Name: Name(index, f.StartRva, f.Name)))
            .Where(x => filter == null || x.Name.Contains(filter, StringComparison.OrdinalIgnoreCase));
        rows = order switch
        {
            "size" => rows.OrderByDescending(x => x.f.EndRva - x.f.StartRva),
            "callers" => rows.OrderByDescending(x => x.f.References ?? 0),
            _ => rows,
        };
        var list = rows.ToList();
        string Sources(NativeFunctionInfo f) => index.FunctionByStart(f.StartRva)?.Sources is { } declared ? $"{choice.Engine}, {declared}" : choice.Engine;
        var lines = list.Select(x => $"{Va(index, x.f.StartRva)}  {x.f.EndRva - x.f.StartRva,7}  {x.Name}{Flags(x.f.Flags)}  ({Sources(x.f)}; {x.f.References ?? 0} refs)").ToList();
        int thunks = functions.List.Count(f => f.Flags.HasFlag(NativeFunctionFlags.Thunk));
        int library = functions.List.Count(f => f.Flags.HasFlag(NativeFunctionFlags.Library));
        var display = NativeEngineService.DisplayName(choice.Engine);
        var coverage = Decoded(index) ? $"functions, sizes and references come from {display}'s analysis; names in effect here win over {display}'s"
            : $"{index.SupportNote ?? $"{index.Image.Arch} instructions are not decoded by the built-in analysis"}; functions, sizes and references come from {display}";
        var structured = Paged(list, offset, limit, (page, o, total, more) => new FunctionList(native.Id, functions.List.Count,
            page.Select(x => new FunctionEntry(Va(index, x.f.StartRva), (int)(x.f.EndRva - x.f.StartRva), x.Name, FlagList(x.f.Flags), Sources(x.f), x.f.References ?? 0)).ToList(),
            o, total, more, coverage, choice.Engine, choice.Note));
        return StructuredOutput.With($"{native.Id}: {Plural(functions.List.Count, "function")} ({thunks} thunks, {library} library) {Via(choice.Engine)}\n{choice.Line}\n" +
                                     $"Note: {coverage}\n" + pager.PageRows(lines, offset, limit, "function"), structured);
    }

    public async Task<string> Disassemble(LoadedNative native, NativeCodeIndex index, uint rva, bool function, int max, int offset, int? maxChars,
        EngineChoice choice, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var session = await Session(native, choice, progress, ct);
        var sb = new StringBuilder();
        FunctionDisassembly d;
        if (function)
        {
            try
            {
                d = await session.DisassembleAsync(rva, ct);
                sb.AppendLine($"; {Name(index, d.StartRva, d.Name)} at {Va(index, d.StartRva)}, {d.EndRva - d.StartRva} bytes, " +
                              $"{Plural(d.Instructions.Count, "instruction")} {Via(choice.Engine)}");
                if (index.Sourced.CommentAt(d.StartRva) is { } fc)
                    foreach (var c in fc.Text.Split('\n')) sb.AppendLine($"; {c}");
            }
            catch (ToolError e) when (e.Code == ErrorCode.NotFound)
            {
                function = false;
                d = await session.DisassembleRangeAsync(rva, max, ct);
                sb.AppendLine($"; {Plural(max, "instruction")} from {Va(index, rva)} (no function contains it) {Via(choice.Engine)}");
            }
        }
        else
        {
            d = await session.DisassembleRangeAsync(rva, max, ct);
            sb.AppendLine($"; {Plural(max, "instruction")} from {Va(index, rva)} {Via(choice.Engine)}");
        }
        int shown = 0;
        foreach (var i in d.Instructions)
        {
            if (shown++ >= max) { sb.AppendLine($"; ... truncated at {Plural(max, "instruction")}"); break; }
            var comment = index.Sourced.CommentAt(i.Rva) is { } user ? user.Text.Split('\n')[0] : i.Comment;
            sb.AppendLine($"  {index.Image.ImageBase + i.Rva:X}  {Convert.ToHexString(i.Bytes),-24} {i.Text}{(comment != null ? "  ; " + comment : "")}");
        }
        if (d.Truncated && function) sb.AppendLine("; ... truncated by the engine");
        return $"; {choice.Line}\n" + pager.Page(sb.ToString(), offset, maxChars);
    }

    public async Task<string> Cfg(LoadedNative native, NativeCodeIndex index, uint rva, int offset, int? maxChars,
        EngineChoice choice, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var session = await Session(native, choice, progress, ct);
        NativeBlockGraph graph;
        try { graph = await session.GetBlocksAsync(rva, ct); }
        catch (ToolError e) when (e.Code == ErrorCode.NotFound)
        {
            throw new ToolError(ErrorCode.NotFound, $"No function contains {Va(index, rva)} ({NativeEngineService.DisplayName(choice.Engine)}).", "list_functions shows the functions");
        }
        string V(uint rva) => Va(index, rva);
        var name = Name(index, graph.StartRva, graph.Name);
        var sb = new StringBuilder($"{name} at {V(graph.StartRva)}: {Plural(graph.Blocks.Count, "block")} {Via(choice.Engine)}\n");
        var blocks = new List<CfgBlock>();
        foreach (var b in graph.Blocks)
        {
            var end = EndKind(b);
            var succ = b.Successors.Select(s => (To: s, Kind: s == b.EndRva && b.Successors.Count > 1 ? "ConditionalFallThrough"
                : b.Successors.Count > 1 && !b.Switch ? "ConditionalTaken" : b.Switch ? "Switch" : s == b.EndRva ? "FallThrough" : "Jump")).ToList();
            sb.AppendLine($"  {V(b.StartRva)}-{V(b.EndRva)}  {b.Instructions,4} insn  {end}" +
                          (succ.Count > 0 ? "  -> " + string.Join(", ", succ.Select(s => s.Kind is "Jump" or "FallThrough" or "Switch" ? V(s.To) : $"{V(s.To)} {s.Kind}")) : ""));
            blocks.Add(new CfgBlock(V(b.StartRva), V(b.EndRva), b.Instructions, end, [.. succ.Select(s => new CfgSuccessor(V(s.To), s.Kind))]));
        }
        var switches = new List<CfgSwitch>();
        foreach (var b in graph.Blocks.Where(b => b.Switch))
        {
            if (b.SwitchInfo is { } si)
            {
                var view = new SwitchView(si.Jump ?? b.StartRva, si.Table, null, si.EntrySize > 0 ? si.EntrySize : null,
                    si.Entries > 0 ? si.Entries : null, si.IndexTable, si.IndexEntries, si.Bias, si.Default,
                    [.. si.Cases.Where(c => c.Target == si.Default).SelectMany(c => c.Values)], true, [.. si.Cases.Where(c => c.Target != si.Default)]);
                NativeCodeTools.RenderSwitch(sb, view, V, t => index.NameAt(t), null);
                switches.Add(NativeCodeTools.SwitchEntry(view, V, t => index.NameAt(t)));
                continue;
            }
            sb.AppendLine($"  switch at block {V(b.StartRva)}: {Plural(b.Successors.Count, "distinct target")}: " +
                          string.Join(", ", b.Successors.Take(64).Select(V)) + (b.Successors.Count > 64 ? ", ..." : ""));
            switches.Add(new CfgSwitch(V(b.StartRva), null, null, null, null, null, null, 0, null, [], false,
                [.. b.Successors.Select(s => new CfgCase(V(s), index.NameAt(s), []))]));
        }
        var unresolved = new List<CfgUnresolvedJump>();
        foreach (var b in graph.Blocks.Where(b => b.Kind == "indjump" && !b.Switch && b.Successors.Count == 0))
        {
            sb.AppendLine($"  unresolved indirect jump in block {V(b.StartRva)}");
            unresolved.Add(new CfgUnresolvedJump(V(b.StartRva), "no switch recognized by the engine"));
        }
        foreach (var t in graph.TailCalls) sb.AppendLine($"  tail call to {index.NameAt(t) ?? V(t)}");
        return StructuredOutput.With(choice.Line + "\n" + pager.Page(sb.ToString(), offset, maxChars),
            new CfgReport(native.Id, name, V(graph.StartRva), choice.Engine, blocks, switches, unresolved, [.. graph.TailCalls.Select(V)], false));

        string EndKind(NativeBlockInfo b) => b.Kind switch
        {
            "ret" or "cndret" => "Return",
            "noret" or "enoret" => "NoReturnCall",
            "error" => "Invalid",
            // IDA also types ARM64 TBZ / TBNZ blocks indjump: by the successors, those are conditional jumps
            "indjump" => b.Switch ? "Switch" : b.Successors.Count >= 2 ? "ConditionalJump" : b.Successors.Count == 1 ? "Jump" : "IndirectJump",
            _ when b.Switch => "Switch",
            _ when b.Successors.Count >= 2 => "ConditionalJump",
            _ when b.Successors.Count == 1 && b.Successors[0] == b.EndRva => "FallThrough",
            _ when b.Successors.Count == 1 => "Jump",
            _ when graph.TailCalls.Count > 0 => "TailCall",
            _ => "Return",
        };
    }

    /// <summary>
    /// find_xrefs rows in the tool's format, the header lines and the target as shown: the engine's references, plus the
    /// virtual call sites the built-in index resolved through RTTI that the engine has no reference from (marked "ours").
    /// </summary>
    public async Task<(string Title, List<string> Rows, string Target)> Xrefs(LoadedNative native, NativeCodeIndex index, uint rva,
        EngineChoice choice, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var session = await Session(native, choice, progress, ct);
        var functions = await LoadFunctions(session, references: false, ct);
        var xrefs = await session.GetXrefsToAsync(rva, ct);
        string Where(uint from, uint? function) => (function ?? functions.At(from)?.StartRva) is { } f && functions.ByStart.TryGetValue(f, out var info)
            ? $"{Name(index, f, info.Name)}+0x{from - f:X}" : "(no function)";
        var rows = xrefs.Select(x => (From: x.FromRva, Row: $"{Va(index, x.FromRva)}  {x.Kind,-10} {Where(x.FromRva, x.FromFunctionRva)}")).ToList();
        if (Decoded(index))
        {
            var seen = xrefs.Select(x => x.FromRva).ToHashSet();
            foreach (var v in index.VirtualEdgesTo(rva))
                if (seen.Add(v.From))
                    rows.Add((v.From, $"{Va(index, v.From)}  {v.Kind,-10} {Where(v.From, null)}  (ours: virtual call resolved through RTTI)"));
        }
        var name = functions.ByStart.TryGetValue(rva, out var t) ? Name(index, rva, t.Name) : index.NameAt(rva);
        var target = $"{Va(index, rva)}{(name != null ? $" ({name})" : "")}";
        return ($"References to {target} {Via(choice.Engine)}:\n", rows.OrderBy(r => r.From).Select(r => r.Row).ToList(), target);
    }

    /// <summary>
    /// find_xrefs direction=from: the engine's references from the item at <paramref name="rva"/> or, at a function start, from
    /// the whole function, plus the RTTI-resolved virtual calls the built-in index has from there; rows end "-> target (name)".
    /// </summary>
    public async Task<(string Title, List<string> Rows, string Target)> XrefsFrom(LoadedNative native, NativeCodeIndex index, uint rva,
        EngineChoice choice, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var session = await Session(native, choice, progress, ct);
        var functions = await LoadFunctions(session, references: false, ct);
        bool whole = functions.ByStart.TryGetValue(rva, out var self);
        var xrefs = await session.GetXrefsFromAsync(rva, whole, ct);
        string Where(uint from, uint? function) => (function ?? functions.At(from)?.StartRva) is { } f && functions.ByStart.TryGetValue(f, out var info)
            ? $"{Name(index, f, info.Name)}+0x{from - f:X}" : "(no function)";
        string To(uint to) => Va(index, to) + ((functions.ByStart.TryGetValue(to, out var t) ? Name(index, to, t.Name) : index.NameAt(to)) is { } n ? $" ({n})" : "");
        var rows = xrefs.Select(x => (From: x.FromRva, To: x.ToRva, Row: $"{Va(index, x.FromRva)}  {x.Kind,-10} {Where(x.FromRva, x.FromFunctionRva)}  -> {To(x.ToRva)}")).ToList();
        if (Decoded(index))
        {
            var seen = xrefs.Select(x => (x.FromRva, x.ToRva)).ToHashSet();
            uint end = whole ? self!.EndRva : rva + 1;
            foreach (var v in index.VirtualEdgesFrom(rva, end))
                if (seen.Add((v.From, v.To)))
                    rows.Add((v.From, v.To, $"{Va(index, v.From)}  {v.Kind,-10} {Where(v.From, null)}  -> {To(v.To)}  (ours: virtual call resolved through RTTI)"));
        }
        var name = whole ? Name(index, rva, self!.Name) : index.NameAt(rva);
        var target = $"{Va(index, rva)}{(name != null ? $" ({name})" : "")}";
        return ($"References from {target}{(whole ? " (the whole function)" : "")} {Via(choice.Engine)}:\n",
            rows.OrderBy(r => r.From).ThenBy(r => r.To).Select(r => r.Row).ToList(), target);
    }

    /// <summary>
    /// Callers or callees through the engine's call and jump references; with a decoded image, the virtual call edges the
    /// built-in index resolved through RTTI are added where the engine has none (marked "ours"), filtered by <paramref name="edges"/>.
    /// </summary>
    public async Task<string> CallTree(LoadedNative native, NativeCodeIndex index, uint rva, bool callers, int depth, int maxNodes, int offset, int? maxChars,
        CallEdgeFilter edges, EngineChoice choice, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var session = await Session(native, choice, progress, ct);
        var functions = await LoadFunctions(session, references: false, ct);
        var root = functions.At(rva) ?? throw new ToolError(ErrorCode.NotFound, $"No function contains {Va(index, rva)} ({NativeEngineService.DisplayName(choice.Engine)}).", "list_functions shows the functions");
        var imports = index.Image.Imports.GroupBy(i => i.SlotRva).ToDictionary(g => g.Key, g => g.First());
        var sb = new StringBuilder($"; {(callers ? "callers" : "callees")} of {Name(index, root.StartRva, root.Name)} {Via(choice.Engine)}\n");
        bool direct = edges != CallEdgeFilter.Virtual, virtualEdges = edges != CallEdgeFilter.Direct && Decoded(index);
        var expanded = new HashSet<uint>();
        int nodes = 0;

        async Task Walk(uint start, int level, string? tag)
        {
            ct.ThrowIfCancellationRequested();
            nodes++;
            var name = functions.ByStart.TryGetValue(start, out var info) ? Name(index, start, info.Name) : index.NameAt(start) ?? Va(index, start);
            sb.Append(new string(' ', level * 2)).Append(name).Append(tag != null ? "  " + tag : "").Append($"  {Va(index, start)}");
            if (level >= depth) { sb.AppendLine(); return; }
            // a function expanded before (also recursion: it is on the current path) is not expanded again
            if (!expanded.Add(start)) { sb.AppendLine("  (repeated)"); return; }
            var children = new List<(uint Rva, string? Import, string? Tag)>();
            if (callers)
            {
                if (direct)
                    foreach (var x in await session.GetXrefsToAsync(start, ct))
                        if (x.Kind is NativeXrefKind.Call or NativeXrefKind.Jump && (x.FromFunctionRva ?? functions.At(x.FromRva)?.StartRva) is { } from
                            && (x.Kind == NativeXrefKind.Call || from != start))
                            children.Add((from, null, null));
                if (virtualEdges)
                    foreach (var v in index.VirtualEdgesTo(start))
                        if (functions.At(v.From)?.StartRva is { } from) children.Add((from, null, VirtualTag(v)));
            }
            else
            {
                if (direct)
                    foreach (var x in await session.GetXrefsFromAsync(start, wholeFunction: true, ct))
                    {
                        if (imports.TryGetValue(x.ToRva, out var imp)) children.Add((x.ToRva, NativeCodeIndex.ImportName(imp), null));
                        else if (x.Kind == NativeXrefKind.Call || x.Kind == NativeXrefKind.Jump && functions.ByStart.ContainsKey(x.ToRva) && x.ToRva != start)
                            children.Add((functions.At(x.ToRva)?.StartRva ?? x.ToRva, null, null));
                    }
                if (virtualEdges && functions.ByStart.TryGetValue(start, out var self))
                    foreach (var v in index.VirtualEdgesFrom(start, self.EndRva))
                        children.Add((functions.At(v.To)?.StartRva ?? v.To, null, VirtualTag(v)));
            }
            // the engine's edges come first: a virtual edge to a function its references already reach adds nothing
            var distinct = children.DistinctBy(c => c.Rva).ToList();
            sb.AppendLine();
            foreach (var (child, import, childTag) in distinct)
            {
                if (nodes >= maxNodes) { sb.Append(new string(' ', (level + 1) * 2)).AppendLine("(more not shown)"); break; }
                if (import != null)
                {
                    nodes++;
                    sb.Append(new string(' ', (level + 1) * 2)).AppendLine(import);
                    continue;
                }
                await Walk(child, level + 1, childTag);
            }
        }

        string VirtualTag(CodeXref v) => v.Kind == XrefKind.VirtualExact ? "[virtual, ours]"
            : $"[virtual?: one of {index.VirtualCalls.SiteAt(v.From)?.TargetCount ?? 0}, ours]";

        await Walk(root.StartRva, 0, null);
        return choice.Line + "\n" + pager.Page(sb.ToString(), offset, maxChars);
    }
}
