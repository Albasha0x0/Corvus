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

/// <summary>
/// list_functions, disassemble, get_cfg, find_xrefs and native_call_tree for images whose instruction set the built-in
/// analysis does not decode (ARM64, ARM): answered through the IDA session in the same formats, marked "(via IDA)".
/// Names in effect here (user, PDB, Il2Cpp, exports) win over IDA's own; they are pushed into the database first.
/// </summary>
internal sealed class NativeEngineCode(NativeEngineService engines, OutputPager pager, NativeNamePush? names)
{
    public const string Via = "(via IDA)";

    /// <summary>Whether the call goes to the engine: the built-in analysis does not decode the code, and an engine is installed.</summary>
    public bool Serves(NativeCodeIndex index) => index.Support == CodeSupport.DeclaredFunctionsOnly && engines.IsAvailable;

    /// <summary>The typed error for an undecoded architecture when no engine is installed.</summary>
    public static ToolError Unsupported(NativeCodeIndex index, NativeEngineService? engines) =>
        new(ErrorCode.Unsupported, $"Instructions are not decoded for {index.Image.Arch} images by the built-in analysis" +
                                   (engines?.Unavailability is { } u ? $", and IDA is not available: {u.Reason}" : "."),
            engines?.Unavailability is { } un
                ? $"install IDA Pro 9 or newer with idalib (or set NDM_IDA_DIR) so {index.Image.Arch} code is analyzed through it" + (un.Remediation is { } r ? $": {r}" : "")
                : "install IDA Pro 9 or newer with idalib (or set NDM_IDA_DIR) so this code is analyzed through it");

    private async Task<INativeDecompilerSession> Session(LoadedNative native, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var session = await engines.Session(native, null, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = $"IDA {p.Stage}" })), ct);
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

    public async Task<string> ListFunctions(LoadedNative native, NativeCodeIndex index, string? filter, string? sort, int offset, int limit,
        IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var order = sort?.Trim().ToLowerInvariant();
        if (order is not (null or "" or "address" or "size" or "callers"))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown sort '{sort}'.", "use address, size or callers");
        var session = await Session(native, progress, ct);
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
        string Sources(NativeFunctionInfo f) => index.FunctionByStart(f.StartRva)?.Sources is { } declared ? $"ida, {declared}" : "ida";
        var lines = list.Select(x => $"{Va(index, x.f.StartRva)}  {x.f.EndRva - x.f.StartRva,7}  {x.Name}{Flags(x.f.Flags)}  ({Sources(x.f)}; {x.f.References ?? 0} refs)").ToList();
        int thunks = functions.List.Count(f => f.Flags.HasFlag(NativeFunctionFlags.Thunk));
        int library = functions.List.Count(f => f.Flags.HasFlag(NativeFunctionFlags.Library));
        var coverage = $"{index.SupportNote ?? $"{index.Image.Arch} instructions are not decoded by the built-in analysis"}; functions, sizes and references come from IDA";
        var structured = Paged(list, offset, limit, (page, o, total, more) => new FunctionList(native.Id, functions.List.Count,
            page.Select(x => new FunctionEntry(Va(index, x.f.StartRva), (int)(x.f.EndRva - x.f.StartRva), x.Name, FlagList(x.f.Flags), Sources(x.f), x.f.References ?? 0)).ToList(),
            o, total, more, coverage));
        return StructuredOutput.With($"{native.Id}: {Plural(functions.List.Count, "function")} ({thunks} thunks, {library} library) {Via}\n" +
                                     $"Note: {coverage}\n" + pager.PageRows(lines, offset, limit, "function"), structured);
    }

    public async Task<string> Disassemble(LoadedNative native, NativeCodeIndex index, uint rva, bool function, int max, int offset, int? maxChars,
        IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var session = await Session(native, progress, ct);
        var sb = new StringBuilder();
        FunctionDisassembly d;
        if (function)
        {
            try
            {
                d = await session.DisassembleAsync(rva, ct);
                sb.AppendLine($"; {Name(index, d.StartRva, d.Name)} at {Va(index, d.StartRva)}, {d.EndRva - d.StartRva} bytes, " +
                              $"{Plural(d.Instructions.Count, "instruction")} {Via}");
                if (index.Sourced.CommentAt(d.StartRva) is { } fc)
                    foreach (var c in fc.Text.Split('\n')) sb.AppendLine($"; {c}");
            }
            catch (ToolError e) when (e.Code == ErrorCode.NotFound)
            {
                function = false;
                d = await session.DisassembleRangeAsync(rva, max, ct);
                sb.AppendLine($"; {Plural(max, "instruction")} from {Va(index, rva)} (no function contains it) {Via}");
            }
        }
        else
        {
            d = await session.DisassembleRangeAsync(rva, max, ct);
            sb.AppendLine($"; {Plural(max, "instruction")} from {Va(index, rva)} {Via}");
        }
        int shown = 0;
        foreach (var i in d.Instructions)
        {
            if (shown++ >= max) { sb.AppendLine($"; ... truncated at {Plural(max, "instruction")}"); break; }
            var comment = index.Sourced.CommentAt(i.Rva) is { } user ? user.Text.Split('\n')[0] : i.Comment;
            sb.AppendLine($"  {index.Image.ImageBase + i.Rva:X}  {Convert.ToHexString(i.Bytes),-24} {i.Text}{(comment != null ? "  ; " + comment : "")}");
        }
        if (d.Truncated && function) sb.AppendLine("; ... truncated by the engine");
        return pager.Page(sb.ToString(), offset, maxChars);
    }

    public async Task<string> Cfg(LoadedNative native, NativeCodeIndex index, uint rva, int offset, int? maxChars,
        IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var session = await Session(native, progress, ct);
        NativeBlockGraph graph;
        try { graph = await session.GetBlocksAsync(rva, ct); }
        catch (ToolError e) when (e.Code == ErrorCode.NotFound)
        {
            throw new ToolError(ErrorCode.NotFound, $"No function contains {Va(index, rva)} (IDA).", "list_functions shows the functions");
        }
        var sb = new StringBuilder($"{Name(index, graph.StartRva, graph.Name)} at {Va(index, graph.StartRva)}: {Plural(graph.Blocks.Count, "block")} {Via}\n");
        var starts = graph.Blocks.Select(b => b.StartRva).ToHashSet();
        foreach (var b in graph.Blocks)
        {
            var end = EndKind(b);
            var succ = b.Successors.Select(s => s == b.EndRva && b.Successors.Count > 1 ? $"{Va(index, s)} ConditionalFallThrough"
                : b.Successors.Count > 1 && !b.Switch ? $"{Va(index, s)} ConditionalTaken" : Va(index, s));
            sb.AppendLine($"  {Va(index, b.StartRva)}-{Va(index, b.EndRva)}  {b.Instructions,4} insn  {end}" +
                          (b.Successors.Count > 0 ? "  -> " + string.Join(", ", succ) : ""));
        }
        foreach (var b in graph.Blocks.Where(b => b.Switch))
            sb.AppendLine($"  switch at block {Va(index, b.StartRva)}: {Plural(b.Successors.Count, "distinct target")}: " +
                          string.Join(", ", b.Successors.Take(64).Select(s => Va(index, s))) + (b.Successors.Count > 64 ? ", ..." : ""));
        foreach (var b in graph.Blocks.Where(b => b.Kind == "indjump" && !b.Switch && b.Successors.Count == 0))
            sb.AppendLine($"  unresolved indirect jump in block {Va(index, b.StartRva)}");
        foreach (var t in graph.TailCalls) sb.AppendLine($"  tail call to {index.NameAt(t) ?? Va(index, t)}");
        return pager.Page(sb.ToString(), offset, maxChars);

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

    /// <summary>find_xrefs rows in the tool's format, the header line and the target as shown.</summary>
    public async Task<(string Header, List<string> Rows, string Target)> Xrefs(LoadedNative native, NativeCodeIndex index, uint rva,
        IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var session = await Session(native, progress, ct);
        var functions = await LoadFunctions(session, references: false, ct);
        var xrefs = await session.GetXrefsToAsync(rva, ct);
        var rows = xrefs.OrderBy(x => x.FromRva).Select(x =>
        {
            var where = (x.FromFunctionRva ?? functions.At(x.FromRva)?.StartRva) is { } f && functions.ByStart.TryGetValue(f, out var info)
                ? $"{Name(index, f, info.Name)}+0x{x.FromRva - f:X}" : "(no function)";
            return $"{Va(index, x.FromRva)}  {x.Kind,-10} {where}";
        }).ToList();
        var name = functions.ByStart.TryGetValue(rva, out var t) ? Name(index, rva, t.Name) : index.NameAt(rva);
        var target = $"{Va(index, rva)}{(name != null ? $" ({name})" : "")}";
        return ($"References to {target} {Via}:\n", rows, target);
    }

    public async Task<string> CallTree(LoadedNative native, NativeCodeIndex index, uint rva, bool callers, int depth, int maxNodes, int offset, int? maxChars,
        IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var session = await Session(native, progress, ct);
        var functions = await LoadFunctions(session, references: false, ct);
        var root = functions.At(rva) ?? throw new ToolError(ErrorCode.NotFound, $"No function contains {Va(index, rva)} (IDA).", "list_functions shows the functions");
        var imports = index.Image.Imports.GroupBy(i => i.SlotRva).ToDictionary(g => g.Key, g => g.First());
        var sb = new StringBuilder($"; {(callers ? "callers" : "callees")} of {Name(index, root.StartRva, root.Name)} {Via}\n");
        var expanded = new HashSet<uint>();
        int nodes = 0;

        async Task Walk(uint start, int level)
        {
            ct.ThrowIfCancellationRequested();
            nodes++;
            var name = functions.ByStart.TryGetValue(start, out var info) ? Name(index, start, info.Name) : index.NameAt(start) ?? Va(index, start);
            sb.Append(new string(' ', level * 2)).Append(name).Append($"  {Va(index, start)}");
            if (level >= depth) { sb.AppendLine(); return; }
            // a function expanded before (also recursion: it is on the current path) is not expanded again
            if (!expanded.Add(start)) { sb.AppendLine("  (repeated)"); return; }
            var children = new List<(uint Rva, string? Import)>();
            if (callers)
            {
                foreach (var x in await session.GetXrefsToAsync(start, ct))
                    if (x.Kind is NativeXrefKind.Call or NativeXrefKind.Jump && (x.FromFunctionRva ?? functions.At(x.FromRva)?.StartRva) is { } from
                        && (x.Kind == NativeXrefKind.Call || from != start))
                        children.Add((from, null));
            }
            else
            {
                foreach (var x in await session.GetXrefsFromAsync(start, wholeFunction: true, ct))
                {
                    if (imports.TryGetValue(x.ToRva, out var imp)) children.Add((x.ToRva, NativeCodeIndex.ImportName(imp)));
                    else if (x.Kind == NativeXrefKind.Call || x.Kind == NativeXrefKind.Jump && functions.ByStart.ContainsKey(x.ToRva) && x.ToRva != start)
                        children.Add((functions.At(x.ToRva)?.StartRva ?? x.ToRva, null));
                }
            }
            var distinct = children.DistinctBy(c => c.Rva).ToList();
            sb.AppendLine();
            foreach (var (child, import) in distinct)
            {
                if (nodes >= maxNodes) { sb.Append(new string(' ', (level + 1) * 2)).AppendLine("(more not shown)"); break; }
                if (import != null)
                {
                    nodes++;
                    sb.Append(new string(' ', (level + 1) * 2)).AppendLine(import);
                    continue;
                }
                await Walk(child, level + 1);
            }
        }

        await Walk(root.StartRva, 0);
        return pager.Page(sb.ToString(), offset, maxChars);
    }
}
