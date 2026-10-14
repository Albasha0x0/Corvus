using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Providers;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

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

    /// <summary>The engine of a call on a native code tool (see <see cref="EngineChoice"/>): the built-in path cannot answer an undecoded instruction set.</summary>
    /// <param name="named">Whether the call named the engine (else it is the server default).</param>
    public static EngineChoice Choose(EngineMode mode, bool named, NativeEngineService? engines, LoadedNative native, NativeCodeIndex index) =>
        EngineChoice.Of(mode, named, engines, native,
            index.Support == CodeSupport.DeclaredFunctionsOnly ? $"the built-in analysis does not decode {index.Image.ArchName()} instructions" : null);

    /// <summary>The typed error for an undecoded architecture when no engine is installed.</summary>
    /// <remarks>details: reason instructions-not-decoded and the file's machine name; Next names an installed engine, else how to install one.</remarks>
    /// <param name="engineNext">Next for a tool without an engine parameter when an engine is installed.</param>
    public static ToolError Unsupported(NativeCodeIndex index, NativeEngineService? engines, string? engineNext = null)
    {
        var arch = index.Image.ArchName();
        var installed = engines?.FirstAvailable();
        return new(ErrorCode.Unsupported, $"Instructions are not decoded for {arch} images by the built-in analysis" +
                                          (installed != null ? "." : engines?.Unavailability is { } u ? $", and no engine is available: {u.Reason}" : "."),
            engineNext != null && (installed != null || engines == null) ? engineNext
            : installed != null ? $"pass engine={installed} to read {arch} code through {NativeEngineService.DisplayName(installed)}"
            : $"install IDA Pro 9 or newer with idalib (or set CORVUS_IDA_DIR), or Ghidra 12 or newer with a JDK (set CORVUS_GHIDRA_DIR), so {arch} code is analyzed through it" +
              (engines?.Unavailability is { Remediation: { } r } ? $": {r}" : ""))
        {
            Details = new { reason = "instructions-not-decoded", arch = index.Image.MachineName },
        };
    }

    internal async Task<INativeDecompilerSession> Session(LoadedNative native, EngineChoice choice, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var display = NativeEngineService.DisplayName(choice.Engine);
        var session = await engines.Session(native, choice.Engine, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = $"{display} {p.Stage}" })), ct);
        EngineReport.Answered(choice, engines, session);
        if (names != null) await names.EnsureAsync(native, session, ct);
        return session;
    }

    private static string Va(NativeCodeIndex index, uint rva) => NativeAddress.Va(index.Image, rva);

    /// <summary>
    /// An engine's function record as lines ("prototype: ..."). <paramref name="compact"/> summarizes the parameters of a
    /// signature the engine only guessed (IDA can guess dozens of stack parameters) in one line and clips the prototype.
    /// </summary>
    public static List<string> RecordLines(EngineFunctionRecord r, Func<uint, string> va, bool compact = false)
    {
        var lines = new List<string>();
        bool guessed = compact && r.SignatureSource is null or "guessed" or "default" or "analysis";
        if (r.Prototype != null) lines.Add($"prototype{(guessed ? " (guessed)" : "")}: {(guessed ? Format.Clip(r.Prototype, 160) : r.Prototype)}");
        lines.Add($"convention {r.CallingConvention ?? "unknown"}, signature from {r.SignatureSource ?? "nothing (untyped)"}" +
                  (r.StackPurge is { } p ? $", callee pops {p} bytes" : "") + (r.VarArgs ? ", varargs" : ""));
        if (r.Namespace != null) lines.Add($"namespace {r.Namespace}");
        if (guessed && r.Parameters.Count > 0)
        {
            int stack = r.Parameters.Count(x => x.Storage.Contains("stack", StringComparison.OrdinalIgnoreCase));
            lines.Add($"{r.Parameters.Count} guessed parameter(s): {r.Parameters.Count - stack} in registers, {stack} on the stack");
        }
        else
            foreach (var x in r.Parameters) lines.Add($"param {x.Type} {x.Name} in {x.Storage}");
        if (r.ReturnType != null) lines.Add($"returns {r.ReturnType}" + (r.ReturnStorage != null ? $" in {r.ReturnStorage}" : ""));
        if (r.Ranges.Count > 0) lines.Add("body " + string.Join(", ", r.Ranges.Select(x => $"{va(x.Start)}-{va(x.End)}")));
        var flags = new List<string>();
        if (r.ThunkTarget != null || r.ThunkTargetName != null) flags.Add($"thunk to {r.ThunkTargetName ?? va(r.ThunkTarget!.Value)}");
        if (r.NoReturn) flags.Add("noreturn");
        if (r.External) flags.Add("external");
        if (r.Library) flags.Add("library");
        if (flags.Count > 0) lines.Add(string.Join(", ", flags));
        return lines;
    }

    /// <summary>The engine record of the function at <paramref name="rva"/> under a header line, or empty when the engine has none.</summary>
    public static async Task<string> RecordDetail(INativeDecompilerSession session, uint rva, Func<uint, string> va, CancellationToken ct)
    {
        try
        {
            var r = await session.GetFunctionRecordAsync(rva, ct);
            return $"{NativeEngineService.DisplayName(session.ProviderId)}'s record of {r.Name}:\n" + string.Concat(RecordLines(r, va).Select(l => $"  {l}\n"));
        }
        catch (ToolError e) when (e.Code is ErrorCode.Unsupported or ErrorCode.NotFound) { return ""; }
    }

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

    /// <summary>Rows formatted when read, so a page of a long list formats only its own rows.</summary>
    private sealed class RowView<T>(IReadOnlyList<T> source, Func<T, string> format) : IList<string>, IReadOnlyList<string>
    {
        public string this[int index] { get => format(source[index]); set => throw new NotSupportedException(); }
        public int Count => source.Count;
        public bool IsReadOnly => true;
        public IEnumerator<string> GetEnumerator() { foreach (var x in source) yield return format(x); }
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
        public int IndexOf(string item) => throw new NotSupportedException();
        public bool Contains(string item) => throw new NotSupportedException();
        public void CopyTo(string[] array, int arrayIndex) { foreach (var s in this) array[arrayIndex++] = s; }
        public void Add(string item) => throw new NotSupportedException();
        public void Insert(int index, string item) => throw new NotSupportedException();
        public bool Remove(string item) => throw new NotSupportedException();
        public void RemoveAt(int index) => throw new NotSupportedException();
        public void Clear() => throw new NotSupportedException();
    }

    /// <summary>Lookups built once per list: a session returns the same list while the database is unchanged.</summary>
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<IReadOnlyList<NativeFunctionInfo>, Functions> Built = new();

    private static async Task<Functions> LoadFunctions(INativeDecompilerSession session, bool references, CancellationToken ct) =>
        Built.GetValue(await session.ListFunctionsAsync(references, ct), list => new(list.OrderBy(f => f.StartRva).ToList()));

    /// <summary>Whether the built-in index decodes the image's instructions (its virtual call edges can be merged in).</summary>
    private static bool Decoded(NativeCodeIndex index) => index.Support != CodeSupport.DeclaredFunctionsOnly;

    public async Task<string> ListFunctions(LoadedNative native, NativeCodeIndex index, FunctionQuery query, int offset, int limit,
        EngineChoice choice, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var session = await Session(native, choice, progress, ct);
        var functions = await LoadFunctions(session, references: true, ct);
        var list = query.Apply(functions.List.Select(f => (f, Name: Name(index, f.StartRva, f.Name))), x => x.f.StartRva, x => x.f.EndRva - x.f.StartRva,
            x => x.Name, x => x.f.References ?? 0, x => x.f.Flags.HasFlag(NativeFunctionFlags.Typed));
        string Sources(NativeFunctionInfo f) => index.FunctionByStart(f.StartRva)?.Sources is { } declared ? $"{choice.Engine}, {declared}" : choice.Engine;
        var lines = new RowView<(NativeFunctionInfo f, string Name)>(list, x => $"{Va(index, x.f.StartRva)}  {x.f.EndRva - x.f.StartRva,7}  {x.Name}{Flags(x.f.Flags)}  ({Sources(x.f)}; {x.f.References ?? 0} refs)");
        int thunks = functions.List.Count(f => f.Flags.HasFlag(NativeFunctionFlags.Thunk));
        int library = functions.List.Count(f => f.Flags.HasFlag(NativeFunctionFlags.Library));
        var display = NativeEngineService.DisplayName(choice.Engine);
        var coverage = Decoded(index) ? $"functions, sizes and references come from {display}'s analysis; names in effect here win over {display}'s"
            : $"{index.SupportNote ?? $"{index.Image.Arch} instructions are not decoded by the built-in analysis"}; functions, sizes and references come from {display}";
        var structured = Paged(list, offset, limit, (page, o, total, more) => new FunctionList(native.Id, functions.List.Count,
            page.Select(x => new FunctionEntry(Va(index, x.f.StartRva), (int)(x.f.EndRva - x.f.StartRva), x.Name, FlagList(x.f.Flags), Sources(x.f), x.f.References ?? 0)).ToList(),
            o, total, more, coverage, choice.Engine, choice.Note));
        int exact = query.ExactIndex(list, x => x.Name);
        var detail = exact >= 0 ? await RecordDetail(session, list[exact].f.StartRva, r => Va(index, r), ct) : "";
        return ToolOutput.With($"{native.Id}: {Plural(functions.List.Count, "function")} ({thunks} thunks, {library} library) {Via(choice.Engine)}\n{choice.Line}\n" +
                                     $"Note: {coverage}\n" + NativeCodeTools.Matching(query, list.Count, index.Image) + pager.PageRows(lines, offset, limit, "function") +
                                     detail, structured);
    }

    public async Task<string> Disassemble(LoadedNative native, NativeCodeIndex index, uint rva, bool function, int max, int offset, int? maxTokens,
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
        return $"; {choice.Line}\n" + pager.Page(sb.ToString(), offset, maxTokens);
    }

    /// <summary>get_cfg through the engine: one page of blocks (<see cref="NativeCodeTools.CfgPage"/>).</summary>
    public async Task<string> Cfg(LoadedNative native, NativeCodeIndex index, uint rva, int offset, int limit,
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
        var rows = new List<NativeCodeTools.CfgRow>();
        var switches = new List<(uint, CfgSwitch)>();
        var unresolved = new List<(uint, CfgUnresolvedJump)>();
        foreach (var b in graph.Blocks)
        {
            var end = EndKind(b);
            var succ = b.Successors.Select(s => (To: s, Kind: s == b.EndRva && b.Successors.Count > 1 ? "ConditionalFallThrough"
                : b.Successors.Count > 1 && !b.Switch ? "ConditionalTaken" : b.Switch ? "Switch" : s == b.EndRva ? "FallThrough" : "Jump")).ToList();
            var line = new StringBuilder($"{V(b.StartRva)}-{V(b.EndRva)}  {b.Instructions,4} insn  {end}" +
                (succ.Count > 0 && !b.Switch ? "  -> " + string.Join(", ", succ.Select(s => s.Kind is "Jump" or "FallThrough" ? V(s.To) : $"{V(s.To)} {s.Kind}"))
                : succ.Count > 0 ? $"  -> {Plural(succ.Count, "target")}" : ""));
            if (b.Switch)
            {
                var sb = new StringBuilder();
                if (b.SwitchInfo is { } si)
                {
                    var view = new SwitchView(si.Jump ?? b.StartRva, si.Table, null, si.EntrySize > 0 ? si.EntrySize : null,
                        si.Entries > 0 ? si.Entries : null, si.IndexTable, si.IndexEntries, si.Bias, si.Default,
                        [.. si.Cases.Where(c => c.Target == si.Default).SelectMany(c => c.Values)], true, [.. si.Cases.Where(c => c.Target != si.Default)]);
                    NativeCodeTools.RenderSwitch(sb, view, V, t => index.NameAt(t), null);
                    switches.Add((view.Jump, NativeCodeTools.SwitchEntry(view, V, t => index.NameAt(t))));
                }
                else
                {
                    sb.AppendLine($"  switch at block {V(b.StartRva)}: {Plural(b.Successors.Count, "distinct target")}: " +
                                  string.Join(", ", b.Successors.Take(64).Select(V)) + (b.Successors.Count > 64 ? ", ..." : ""));
                    switches.Add((b.StartRva, new CfgSwitch(V(b.StartRva), null, null, null, null, null, null, 0, null, [], false,
                        [.. b.Successors.Select(s => new CfgCase(V(s), index.NameAt(s), []))])));
                }
                line.Append('\n').Append(sb.ToString().TrimEnd('\n'));
            }
            if (b.Kind == "indjump" && !b.Switch && b.Successors.Count == 0)
            {
                line.Append($"\n  unresolved indirect jump in block {V(b.StartRva)}");
                unresolved.Add((b.StartRva, new CfgUnresolvedJump(V(b.StartRva), "no switch recognized by the engine")));
            }
            rows.Add(new NativeCodeTools.CfgRow(new CfgBlock(V(b.StartRva), V(b.EndRva), b.Instructions, end, [.. succ.Select(s => new CfgSuccessor(V(s.To), s.Kind))]),
                b.StartRva, b.EndRva, line.ToString()));
        }
        return NativeCodeTools.CfgPage(native.Id, name, V(graph.StartRva), choice, $"{name} at {V(graph.StartRva)} {Via(choice.Engine)}", rows, switches, unresolved,
            [.. graph.TailCalls.Select(t => index.NameAt(t) ?? V(t))], false, offset, limit);

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
        return XrefRows(index, functions, rva, await session.GetXrefsToAsync(rva, ct), choice);
    }

    /// <summary><see cref="Xrefs"/> for several addresses, with one engine request for all.</summary>
    public async Task<List<(string Title, List<string> Rows, string Target)>> XrefsMany(LoadedNative native, NativeCodeIndex index, IReadOnlyList<uint> rvas,
        EngineChoice choice, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var session = await Session(native, choice, progress, ct);
        var functions = await LoadFunctions(session, references: false, ct);
        var all = await session.GetXrefsToManyAsync(rvas, ct);
        return rvas.Select((rva, i) => XrefRows(index, functions, rva, all[i], choice)).ToList();
    }

    private static (string Title, List<string> Rows, string Target) XrefRows(NativeCodeIndex index, Functions functions, uint rva, IReadOnlyList<NativeXref> xrefs,
        EngineChoice choice)
    {
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
    /// <summary>
    /// One level of callers and callees by call site from the engine's call and jump references: a reference through an import
    /// slot is indirect and external, a jump a tail call; with a decoded image the RTTI virtual edges it lacks are added (ours).
    /// </summary>
    public async Task<string> CallSites(LoadedNative native, NativeCodeIndex index, uint rva, CallEdgeFilter edges, EngineChoice choice,
        IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var session = await Session(native, choice, progress, ct);
        var functions = await LoadFunctions(session, references: false, ct);
        var root = functions.At(rva) ?? throw new ToolError(ErrorCode.NotFound, $"No function contains {Va(index, rva)} ({NativeEngineService.DisplayName(choice.Engine)}).", "list_functions shows the functions");
        var imports = index.Image.Imports.GroupBy(i => i.SlotRva).ToDictionary(g => g.Key, g => g.First());
        string FunctionName(uint start) => functions.ByStart.TryGetValue(start, out var info) ? Name(index, start, info.Name) : index.NameAt(start) ?? Va(index, start);
        string Where(uint from) => functions.At(from) is { } f ? $"{FunctionName(f.StartRva)}+0x{from - f.StartRva:X}" : "(no function)";
        bool direct = edges != CallEdgeFilter.Virtual, virtualEdges = edges != CallEdgeFilter.Direct && Decoded(index);
        var callers = new List<(uint Site, string Row)>();
        var callees = new List<(uint Site, string Row)>();
        if (direct)
        {
            foreach (var x in await session.GetXrefsToAsync(root.StartRva, ct))
                if (x.Kind is NativeXrefKind.Call or NativeXrefKind.Jump && !(x.Kind == NativeXrefKind.Jump && functions.At(x.FromRva)?.StartRva == root.StartRva))
                    callers.Add((x.FromRva, $"  {Va(index, x.FromRva)}  {Where(x.FromRva)}  [{(x.Kind == NativeXrefKind.Call ? "call" : "jump")}, direct]"));
            foreach (var x in await session.GetXrefsFromAsync(root.StartRva, wholeFunction: true, ct))
            {
                string kind = x.Kind == NativeXrefKind.Call ? "call" : "jump";
                if (imports.TryGetValue(x.ToRva, out var imp))
                    callees.Add((x.FromRva, $"  {Va(index, x.FromRva)}  -> {NativeCodeIndex.ImportName(imp)}  [{kind}, indirect, external]"));
                else if (x.Kind == NativeXrefKind.Call || x.Kind == NativeXrefKind.Jump && functions.ByStart.ContainsKey(x.ToRva) && x.ToRva != root.StartRva)
                {
                    var target = functions.At(x.ToRva)?.StartRva ?? x.ToRva;
                    callees.Add((x.FromRva, $"  {Va(index, x.FromRva)}  -> {FunctionName(target)}  {Va(index, target)}  [{kind}, direct" +
                                            (functions.ByStart.ContainsKey(target) ? "" : ", external") + "]"));
                }
            }
        }
        if (virtualEdges)
        {
            var seen = callers.Select(c => c.Site).ToHashSet();
            foreach (var v in index.VirtualEdgesTo(root.StartRva))
                if (seen.Add(v.From)) callers.Add((v.From, $"  {Va(index, v.From)}  {Where(v.From)}  [{NativeCodeTools.SiteFlags(v.Kind)}, ours]"));
            foreach (var v in index.VirtualEdgesFrom(root.StartRva, root.EndRva))
            {
                var target = functions.At(v.To)?.StartRva ?? v.To;
                callees.Add((v.From, $"  {Va(index, v.From)}  -> {FunctionName(target)}  {Va(index, target)}  [{NativeCodeTools.SiteFlags(v.Kind)}, ours]"));
            }
        }
        var sb = new StringBuilder($"; callers and callees of {FunctionName(root.StartRva)} at {Va(index, root.StartRva)}, one level, by call site {Via(choice.Engine)}\n");
        sb.AppendLine($"callers ({callers.Count}):");
        foreach (var c in callers.OrderBy(c => c.Site)) sb.AppendLine(c.Row);
        sb.AppendLine($"callees ({callees.Count}):");
        foreach (var c in callees.OrderBy(c => c.Site)) sb.AppendLine(c.Row);
        return sb.ToString();
    }

    /// <summary>The engine's call tree as indented text, unpaged (native_call_tree pages it by nodes).</summary>
    public async Task<string> CallTree(LoadedNative native, NativeCodeIndex index, uint rva, bool callers, int depth, int maxNodes,
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
        return sb.ToString();
    }
}
