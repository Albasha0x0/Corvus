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
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>Native code: functions, disassembly, control flow, cross-references, call trees and strings (x86 / x64 / ARM64 / ARM32).</summary>
[McpServerToolType]
public sealed partial class NativeCodeTools(AssemblyWorkspace workspace, NativeCodeService code, OutputPager pager, NativeLinkService? link = null,
    NativeEngineService? engines = null, NativeNamePush? names = null, NativeTypePush? types = null, NativeUserTypePush? userTypes = null)
{
    /// <summary>Answers through an engine (IDA or Ghidra): for images whose instructions the built-in analysis does not decode, or when the engine preference picks one.</summary>
    private readonly NativeEngineCode? _engine = engines != null ? new NativeEngineCode(engines, pager, names) : null;

    internal const string EngineDescription = EngineChoice.Description;

    /// <summary>The engine mode a call asks for (checked before the image is opened) and whether it named one.</summary>
    private (EngineMode Mode, bool Named) Mode(string? engine) =>
        (EngineModes.Resolve(engine, engines?.DefaultMode ?? EngineMode.Auto), !string.IsNullOrWhiteSpace(engine));

    /// <summary>The engine for this call (see <see cref="NativeEngineCode.Choose"/>).</summary>
    private EngineChoice Choose((EngineMode Mode, bool Named) mode, LoadedNative native, NativeCodeIndex index) =>
        NativeEngineCode.Choose(mode.Mode, mode.Named, engines, native, index);


    /// <summary>Loads the image if given by path, waits for its index, and resolves the address (names include functions).</summary>
    private async Task<(LoadedNative Native, NativeCodeIndex Index)> Open(string image, RequestContext<CallToolRequestParams>? context,
        IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var native = await Task.Run(() =>
        {
            return Targets.Native(workspace, image);
        }, ct);
        // Progress is the seconds waited: phase counts restart at zero, and progress that goes backwards is not sent.
        var waited = System.Diagnostics.Stopwatch.StartNew();
        var index = await code.Index(native, new Progress<CodeIndexProgress>(p =>
            progress.Report(new ProgressNotificationValue
            {
                Progress = (float)waited.Elapsed.TotalSeconds,
                Message = $"indexing {native.Id}: {p.Phase}" + (p.Total > 0 ? $" {p.Done:N0}/{p.Total:N0}" : p.Done > 0 ? $" ({p.Done:N0} instructions)" : ""),
            })), ct);
        if (index.Support == CodeSupport.DeclaredFunctionsOnly && index.SupportNote != null && _engine?.Serves(index) != true)
            workspace.Notify($"{native.Id}: {index.SupportNote}");
        return (native, index);
    }

    internal static uint Address(NativeCodeIndex index, string text) => NativeAddress.Parse(index.Image, text, name =>
    {
        if (name.StartsWith("sub_", StringComparison.OrdinalIgnoreCase) && NativeAddress.Number(name[4..]) is { } n)
        {
            if (n < index.Image.SizeOfImage && index.FunctionByStart((uint)n) != null) return [new((uint)n, "function")];
            if (n >= index.Image.ImageBase && n - index.Image.ImageBase < index.Image.SizeOfImage) return [new((uint)(n - index.Image.ImageBase), "function")];
        }
        return index.AddressesOfName(name);
    });

    private static NativeFunction FunctionAt(NativeCodeIndex index, uint rva) =>
        index.FunctionAt(rva) ?? throw (index.Image.Imports.FirstOrDefault(i => i.SlotRva == rva) is { } slot
            ? new ToolError(ErrorCode.NotFound, $"{NativeAddress.Va(index.Image, rva)} is the import slot of {NativeCodeIndex.ImportName(slot)}, not a function.",
                $"native_call_tree direction=callers function={NativeCodeIndex.ImportName(slot)} lists the functions calling through it")
            : new ToolError(ErrorCode.NotFound, $"No function contains {NativeAddress.Va(index.Image, rva)}.",
                "list_functions shows the functions; disassemble shows raw instructions at any address"));

    private static string Flags(NativeFunction f, NativeCodeIndex? index = null) => FlagList(f, index) is { Count: > 0 } flags ? $"  [{string.Join(", ", flags)}]" : "";

    internal static List<string> FlagList(NativeFunction f, NativeCodeIndex? index = null)
    {
        var flags = new List<string>();
        if (index != null && EngineLibraryNames.IsLibrary(index, f.Start)) flags.Add("library");
        if (f.Flags.HasFlag(FunctionFlags.Thunk)) flags.Add("thunk");
        if (index?.ArmModes is { } modes && !modes.At(f.Start)) flags.Add("arm");
        if (f.Flags.HasFlag(FunctionFlags.StateGuessed)) flags.Add("state guessed");
        if (f.Flags.HasFlag(FunctionFlags.NoReturn)) flags.Add("noreturn");
        if (f.Flags.HasFlag(FunctionFlags.UnresolvedJumps)) flags.Add("unresolved jumps");
        if (f.Flags.HasFlag(FunctionFlags.InvalidCode)) flags.Add("invalid code");
        if (f.Flags.HasFlag(FunctionFlags.Truncated)) flags.Add("truncated");
        if (f.Flags.HasFlag(FunctionFlags.Funclet)) flags.Add("funclet");
        if (f.Parent != null) flags.Add($"funclet of {f.Parent.Name}");
        if (f.Chunks.Count > 0) flags.Add(Plural(f.Chunks.Count, "exception chunk"));
        return flags;
    }

    private static string Coverage(NativeCodeIndex index)
    {
        var notes = new List<string>();
        if (index.Support == CodeSupport.DeclaredFunctionsOnly)
        {
            notes.Add(index.SupportNote ?? "instructions are not decoded for this architecture");
            ToolOutput.Coverage("partial", $"{index.Image.ArchName()} instructions are not decoded: declared functions only", "architecture-undecoded");
        }
        if (index.AbsoluteRefsUnconfirmed) notes.Add("no relocations: absolute data references are accepted by address range alone");
        if (index.PointersUnconfirmed) notes.Add("no relocations: data pointers are runs of values that are function starts, unconfirmed");
        notes.AddRange(index.Truncations);
        notes.AddRange(index.Issues);
        return notes.Count > 0 ? "Note: " + string.Join("; ", notes) + "\n" : "";
    }

    [McpServerTool(Name = "list_functions", Title = "List native functions", UseStructuredContent = true, OutputSchemaType = typeof(FunctionList))]
    [Description("Functions of a native image (x86 / x64 / ARM): address, size, name (user, PDB, Il2Cpp, export, module!import thunk or sub_<rva>), " +
                 "flags (thunk, arm (A32), noreturn, unresolved jumps, invalid code, funclets and exception chunks), how it was found and its caller " +
                 "count; an exact name filter adds an open engine's function record.")]
    public Task<string> ListFunctions(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Name filter: " + NameFilter.Description + ".")] string? filter = null,
        [Description("address (default), name, size (largest first) or callers (most called first).")] string? sort = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Max rows (default 150).")] int limit = 150,
        [Description(EngineDescription)] string? engine = null,
        [Description("Smallest size in bytes.")] long? minSize = null,
        [Description("Largest size in bytes.")] long? maxSize = null,
        [Description("Lowest start address.")] string? from = null,
        [Description("Start addresses below this one.")] string? to = null,
        [Description("Engines: true keeps functions with a prototype, false those without.")] bool? hasType = null,
        [Description("Sort direction instead of the sort's default.")] bool? descending = null,
        [Description("functions (default), or candidates: IDA or Ghidra code in no function, most referenced first.")] string? view = null,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        FunctionQuery.Create(filter, minSize, maxSize, null, null, hasType, sort, descending); // bad arguments fail before the image is opened
        var mode = Mode(engine);
        if (Candidates(view))
            return await FunctionCandidates(image, mode, offset, limit, context, progress, cancellationToken);
        var (native, index) = await Open(image, context, progress, cancellationToken);
        uint? Bound(string? text) => string.IsNullOrWhiteSpace(text) ? null : Address(index, text);
        // an end at or past the image's end (a VA or an RVA) means to the end
        uint? End(string? text) => text?.Trim().StartsWith("0x", StringComparison.OrdinalIgnoreCase) == true && NativeAddress.Number(text) is { } n
            && n >= index.Image.SizeOfImage && (n < index.Image.ImageBase || n - index.Image.ImageBase >= index.Image.SizeOfImage) ? index.Image.SizeOfImage : Bound(text);
        var query = FunctionQuery.Create(filter, minSize, maxSize, Bound(from), End(to), hasType, sort, descending);
        var choice = Choose(mode, native, index);
        if (choice.External)
            return await _engine!.ListFunctions(native, index, query, offset, limit, choice, progress, cancellationToken);
        if (hasType != null)
            throw new ToolError(ErrorCode.InvalidArgument, "hasType needs an engine's types; the built-in index has none.", "pass engine=ida or engine=ghidra");
        // library names of an IDA session already open (none is started for this)
        if (engines?.LibraryNames(native) is { IsCompleted: false } importing) await importing.WaitAsync(cancellationToken);
        var functions = query.Apply(index.Functions, f => f.Start, f => f.Size, f => f.Name, f => index.CountRefsTo(f.Start), null);
        string Sources(NativeFunction f) => f.Sources + (EngineLibraryNames.IsLibrary(index, f.Start) ? ", ida" : "");
        var rows = functions.Select(f => $"{NativeAddress.Va(index.Image, f.Start)}  {f.Size,7}  {f.Name}{Flags(f, index)}  ({Sources(f)}; {index.CountRefsTo(f.Start)} refs)").ToList();
        var s = index.Stats;
        var coverage = Coverage(index);
        int library = index.Sourced.Count(NativeNameSource.Ida);
        var result = Paged(functions, offset, limit, (page, o, total, more) => new FunctionList(native.Id, s.Functions,
            page.Select(f => new FunctionEntry(NativeAddress.Va(index.Image, f.Start), (int)f.Size, f.Name, FlagList(f, index), Sources(f), index.CountRefsTo(f.Start))).ToList(),
            o, total, more, coverage.Length > 0 ? coverage.Trim() : null, choice.Engine, choice.Note));
        // one exact name match: the record of an engine session already open (none is started for this)
        int exact = query.ExactIndex(functions, f => f.Name);
        var detail = exact >= 0 && engines?.OpenSession(native) is { } open
            ? await NativeEngineCode.RecordDetail(open, functions[exact].Start, r => NativeAddress.Va(index.Image, r), cancellationToken) : "";
        return ToolOutput.With($"{native.Id}: {Plural(s.Functions, "function")} ({s.Thunks} thunks, {s.NoReturnFunctions} noreturn" +
               (library > 0 ? $", {library} library functions named by IDA" : "") + $"), {s.Instructions:N0} instructions, " +
               $"{s.Xrefs:N0} references, {Plural(s.Strings, "string")}\n{choice.Line}\n" + coverage + Matching(query, functions.Count, index.Image) +
               pager.PageRows(rows, offset, limit, "function") + detail, result);
    });

    /// <summary>"Matching (name 'Get*', size >= 64): 12" when the query narrows the list, plus a regex timeout note.</summary>
    internal static string Matching(FunctionQuery query, int count, INativeImage image) =>
        (query.Narrows ? $"Matching ({query.Describe(r => NativeAddress.Va(image, r))}): {count:N0}\n" : "") + (query.Filter?.Note("function name") ?? "");

    /// <summary>disassemble's record: the page of the listing (D3) and what it disassembles.</summary>
    public sealed record DisassemblyPage(
        [property: Description("The page of the listing.")] string Code,
        int Offset,
        [property: Description("Character offset of the next page; absent on the last.")] int? NextOffset,
        int TotalChars)
    {
        public string? Image { get; init; }
        [Description("The function disassembled; absent for a linear range.")] public string? Function { get; init; }
        [Description("VA the listing starts at.")] public string? Address { get; init; }
        [Description(EngineDoc.Engine)] public string? Engine { get; init; }
    }

    [McpServerTool(Name = "disassemble", Title = "Disassemble native code", UseStructuredContent = true, OutputSchemaType = typeof(DisassemblyPage))]
    [Description("MASM-syntax disassembly of the native function containing an address (with block labels), or of maxInstructions from the address " +
                 "when it is in no function or function=false. References and NativeAOT loads are named, strings shown as comments, calls commented " +
                 "with their recovered arguments. Data in the way (strings, pointers, IAT slots, switch tables, gaps) is rendered as data; warnings " +
                 "(mid-instruction, data, bss) repeat in a footer.")]
    public Task<string> Disassemble(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description("The whole containing function; false: maxInstructions from the address.")] bool function = true,
        [Description("Max instructions.")] int maxInstructions = 2000,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        [Description(EngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var mode = Mode(engine);
        var (native, index) = await Open(image, context, progress, cancellationToken);
        int max = Math.Clamp(maxInstructions, 1, 200_000);
        var choice = Choose(mode, native, index);
        if (choice.External)
        {
            var at = Address(index, address);
            var listing = await _engine!.Disassemble(native, index, at, function, max, offset, maxTokens, choice, progress, cancellationToken);
            if (OutputCall.Current is { } call)
            {
                call.Record = new DisassemblyPage("", offset, null, 0) { Image = native.Id, Address = NativeAddress.Va(index.Image, at), Engine = choice.Engine };
                call.RecordHasBody = true;
            }
            return listing;
        }
        if (index.Support == CodeSupport.DeclaredFunctionsOnly) throw NativeEngineCode.Unsupported(index, engines);
        var rva = Address(index, address);
        var fn = function ? index.FunctionAt(rva) : null;
        var text = pager.GetOrCreate($"disasm|{index.Image.Sha256}|{(fn != null ? "f" + fn.Start : "r")}{rva}|{max}|{index.Sourced.Version}", () =>
        {
            var sb = new StringBuilder();
            var classifier = new AddressClassifier(index);
            var warnings = new List<string>();
            if (StartWarning(classifier, rva, cancellationToken) is { } start && !(function && fn == null && start.StartsWith("note:", StringComparison.Ordinal)))
            {
                sb.AppendLine("; " + start);
                if (start.StartsWith("warning:", StringComparison.Ordinal)) warnings.Add(start);
            }
            if (fn != null)
            {
                sb.AppendLine($"; {fn.Name} at {NativeAddress.Va(index.Image, fn.Start)}, {fn.Size} bytes, {Plural(fn.BlockCount, "block")}{Flags(fn)}");
                if (index.Sourced.CommentAt(fn.Start) is { } fc)
                    foreach (var c in fc.Text.Split('\n')) sb.AppendLine($"; {c}");
                var calls = new Dictionary<uint, string>(NativeCallTools.CallComments(index, fn, cancellationToken));
                foreach (var (at, note) in NativeAotCode.Comments(native, index, fn, cancellationToken))
                    calls[at] = calls.TryGetValue(at, out var known) ? $"{note}; {known}" : note;
                AppendFunction(sb, index, classifier, fn, max, calls, warnings, cancellationToken);
            }
            else
            {
                sb.AppendLine($"; {Plural(max, "instruction")} from {NativeAddress.Va(index.Image, rva)}" + (function ? " (no function contains it)" : ""));
                AppendLinear(sb, index, classifier, rva, max, warnings, cancellationToken);
            }
            if (warnings.Count > 0) sb.Append("; warnings:\n").AppendJoin("", warnings.Select(w => $";   {w}\n"));
            return sb.ToString();
        });
        var record = new DisassemblyPage("", offset, null, 0)
        {
            Image = native.Id, Function = fn?.Name, Address = NativeAddress.Va(index.Image, fn?.Start ?? rva), Engine = choice.Engine,
        };
        return $"; {choice.Line}\n" + Coverage(index) + ToolOutput.Text(pager, text + await BoundImports(native, index, fn, cancellationToken), offset, record, maxTokens);
    });

    /// <summary>Where the imports a function calls are bound (one line each), for the disassembly footer.</summary>
    private async Task<string> BoundImports(LoadedNative native, NativeCodeIndex index, NativeFunction? fn, CancellationToken ct)
    {
        if (link == null || fn == null) return "";
        var imports = index.Callees(fn).Select(c => c.Import).OfType<NativeImport>().Distinct().ToList();
        if (imports.Count == 0) return "";
        await link.WarmUp(null, ct);
        var sb = new StringBuilder("; imports called, bound to:\n");
        foreach (var import in imports.Take(200))
            sb.AppendLine($";   {NativeCodeIndex.ImportName(import)} -> {NativeLinkService.Describe(link.BindImport(native, import))}");
        return sb.ToString();
    }

    private static string Line(DisasmLine l, IReadOnlyDictionary<uint, string>? calls = null)
    {
        var comment = l.Comment;
        if (calls != null && calls.TryGetValue(l.Rva, out var call)) comment = comment == null ? call : comment.Contains(call, StringComparison.Ordinal) ? comment : call + "; " + comment;
        return $"  {l.Address:X}  {l.Bytes,-24} {l.Text}{(comment != null ? "  ; " + comment : "")}";
    }

    [McpServerTool(Name = "get_cfg", Title = "Native control-flow graph", UseStructuredContent = true, OutputSchemaType = typeof(CfgReport))]
    [Description("Basic blocks of the native function containing an address: range, instruction count, how each ends and its successors; switch " +
                 "tables with values per target; unresolved indirect jumps with the reason.")]
    public Task<string> GetCfg(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        [Description(EngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var mode = Mode(engine);
        var (native, index) = await Open(image, context, progress, cancellationToken);
        var choice = Choose(mode, native, index);
        if (choice.External)
            return await _engine!.Cfg(native, index, Address(index, address), offset, maxTokens, choice, progress, cancellationToken);
        if (index.Support == CodeSupport.DeclaredFunctionsOnly) throw NativeEngineCode.Unsupported(index, engines);
        var fn = FunctionAt(index, Address(index, address));
        var graph = index.GetGraph(fn, cancellationToken);
        var (text, report) = OurCfg(native, index, fn, graph);
        return ToolOutput.With(choice.Line + "\n" + pager.Page(text, offset, maxTokens), report);
    });

    /// <summary>"case 3, 4" (or "default ...") for a switch case reference from the jump at <paramref name="jump"/> to <paramref name="target"/>.</summary>
    private static string? CaseText(NativeCodeIndex index, uint jump, uint target, Dictionary<uint, FunctionGraph?> graphs, CancellationToken ct)
    {
        if (index.FunctionAt(jump) is not { } f) return null;
        if (!graphs.TryGetValue(f.Start, out var graph)) graphs[f.Start] = graph = index.Support == CodeSupport.Full ? index.GetGraph(f, ct) : null;
        if (graph?.Switches.FirstOrDefault(s => s.JumpRva == jump) is not { } sw) return null;
        if (sw.Cases.FirstOrDefault(c => c.Target == target) is { } c) return "case " + string.Join(", ", ValueRanges(c.Values));
        return sw.Default == target ? "default" + (sw.DefaultValues.Count > 0 ? $" (also {string.Join(", ", ValueRanges(sw.DefaultValues))})" : "") : null;
    }

    /// <summary>
    /// find_xrefs rows ("[image] VA  Kind  function+0xN  detail") as fields; a row of another form (an importer whose index is
    /// not built) has only its text, as Detail.
    /// </summary>
    private static XrefList Xrefs(string image, string target, List<string> rows, int offset, int limit, string? boundTo, EngineChoice choice) =>
        Paged(rows, offset, limit, (page, o, total, more) => new XrefList(image, target, page.Select(row =>
            XrefRow().Match(row) is { Success: true } m
                ? new XrefEntry(m.Groups["image"].Success ? m.Groups["image"].Value : null, m.Groups["va"].Value, m.Groups["kind"].Value, m.Groups["where"].Value,
                    m.Groups["rest"].Value.Length > 0 ? m.Groups["rest"].Value : null)
                {
                    // direction=from rows end "-> target"
                    Target = m.Groups["rest"].Value.StartsWith("-> ", StringComparison.Ordinal) ? m.Groups["rest"].Value[3..].Split(' ')[0] : null,
                }
                : new XrefEntry(null, null, null, null, row)).ToList(), o, total, more, boundTo, choice.Engine, choice.Note));

    [GeneratedRegex(@"^(?:\[(?<image>[^\]]+)\] )?(?<va>0x[0-9A-F]+)\s+(?<kind>\S+)\s+(?<where>\(no function\)|\S+)\s*(?<rest>.*)$")]
    private static partial Regex XrefRow();

    [McpServerTool(Name = "native_call_tree", Title = "Native call tree", UseStructuredContent = true, OutputSchemaType = typeof(NativeCallTreeResult))]
    [Description("Callers or callees of a native function, several levels deep, through thunks and import slots, as nodes paged in tree order. " +
                 "Callers of module!import: the functions calling through it. Imports continue into loaded providers' exports; callers span " +
                 "loaded images. Callees include GetProcAddress pointers ([dynamic]) and RTTI virtual targets " +
                 "([virtual], [virtual?: one of n]). Repeats are not expanded; frontier lists nodes cut by depth or maxNodes. " +
                 "direction=both: one level each way by call site.")]
    public Task<string> NativeCallTree(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string function,
        [Description("callees (default), callers, or both (depth 1, by call site).")] string direction = "callees",
        [Description("Levels (1-8).")] int depth = 3,
        [Description("Max nodes in the tree (default 250).")] int maxNodes = 250,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Max nodes per page.")] int limit = 200,
        [Description("Call edges: all (default), direct or virtual.")] string? calls = null,
        [Description(EngineDescription)] string? engine = null,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        bool both = direction?.Trim().ToLowerInvariant() == "both";
        bool callers = direction?.Trim().ToLowerInvariant() switch
        {
            "callers" => true,
            "callees" or "both" or null or "" => false,
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown direction '{direction}'.", "use callers, callees or both"),
        };
        var edges = calls?.Trim().ToLowerInvariant() switch
        {
            null or "" or "all" => CallEdgeFilter.All,
            "direct" => CallEdgeFilter.Direct,
            "virtual" => CallEdgeFilter.Virtual,
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown calls filter '{calls}'.", "use all, direct or virtual"),
        };
        string dir = both ? "both" : callers ? "callers" : "callees";
        depth = Math.Clamp(depth, 1, 8);
        maxNodes = ClampLimit(maxNodes, 20_000);
        var mode = Mode(engine);
        var (native, index) = await Open(image, context, progress, cancellationToken);
        var choice = Choose(mode, native, index);
        if (!choice.External && index.Support == CodeSupport.DeclaredFunctionsOnly) throw NativeEngineCode.Unsupported(index, engines);
        uint at = Address(index, function);
        if (both)
        {
            var fn = choice.External ? null : FunctionAt(index, at);
            var sites = choice.External ? await _engine!.CallSites(native, index, at, edges, choice, progress, cancellationToken)
                : OurCallSites(index, fn!, edges, cancellationToken);
            var head = sites.Split('\n')[0];
            var rootFn = fn ?? index.FunctionAt(at);
            var rows = ParseSites(sites, index, rootFn != null ? index.NameAt(rootFn.Start) ?? rootFn.Name : NativeAddress.Va(index.Image, at), rootFn?.Start ?? at);
            int up = rows.Count(r => r.Node.Flags?[0] == "caller"), down = rows.Count - 1 - up;
            return TreePage(limit, native, rows[0].Line, dir, rows, offset, $"{head}: {Plural(up, "caller")}, {Plural(down, "callee")}\n", choice);
        }
        if (choice.External)
        {
            var text = await _engine!.CallTree(native, index, at, callers, depth, maxNodes, edges, choice, progress, cancellationToken);
            var rows = ParseTree(text);
            return TreePage(limit, native, rows.Count > 0 ? rows[0].Node.Name : function, dir, rows, offset, text.Split('\n')[0] + "\n", choice);
        }
        if (callers && index.FunctionAt(at) == null && index.Image.Imports.FirstOrDefault(i => i.SlotRva == at) is { } import)
        {
            if (link != null) await link.WarmUp(null, cancellationToken);
            var rows = workspace.Read(() => ImportCallerTree(native, index, import, depth, maxNodes, edges, cancellationToken));
            return TreePage(limit, native, rows[0].Node.Name, dir, rows, offset, "", choice);
        }
        var root = FunctionAt(index, at);
        if (link != null)
        {
            await link.WarmUp(null, cancellationToken);
            var nodes = new List<NativeTreeNode>();
            var text = new StringBuilder();
            workspace.Read(() => link.AppendTree(text, native, root, callers, depth, maxNodes, 0, true, cancellationToken, edges, nodes, null, native));
            return TreePage(limit, native, root.Name, dir, Zip(text.ToString(), nodes), offset, "", choice);
        }
        var tree = index.CallTree(root, depth, callers, maxNodes, edges);
        var dynamic = callers || edges == CallEdgeFilter.Virtual ? new HashSet<CallTreeNode>() : NativeCallTools.AddDynamicCallees(index, tree, cancellationToken);
        return TreePage(limit, native, root.Name, dir, IndexTree(index, tree, dynamic), offset, "", choice);
    });

    /// <summary>Callers of an import: the functions calling through its slot (or a thunk jumping through it), each with its own callers.</summary>
    private List<TreeRow> ImportCallerTree(LoadedNative native, NativeCodeIndex index, NativeImport import, int depth, int maxNodes, CallEdgeFilter edges, CancellationToken ct)
    {
        var name = NativeCodeIndex.ImportName(import);
        var slot = NativeAddress.Va(index.Image, import.SlotRva);
        var nodes = new List<NativeTreeNode> { new(0, null, 0, name, slot, null, null, null) { Note = "import slot" } };
        var text = new StringBuilder($"{name}  (import slot at {slot})\n");
        var callers = index.Callers(import).Where(c => c.Caller != null).Select(c => c.Caller!).DistinctBy(f => f.Start).ToList();
        int count = 0;
        bool more = false;
        foreach (var caller in callers)
        {
            if (count >= maxNodes) { more = true; break; }
            if (link != null)
            {
                count += link.AppendTree(text, native, caller, callers: true, depth - 1, maxNodes - count, 1, withRoot: true, ct, edges, nodes, 0, native);
                continue;
            }
            var tree = index.CallTree(caller, depth - 1, callers: true, maxNodes - count, edges);
            int start = nodes.Count;
            foreach (var r in IndexTree(index, tree, []))
            {
                count++;
                nodes.Add(r.Node with { Id = r.Node.Id + start, Parent = r.Node.Parent is { } p ? p + start : 0, Depth = r.Node.Depth + 1 });
                text.Append("  ").AppendLine(r.Line);
            }
        }
        var rows = Zip(text.ToString(), nodes);
        for (int i = 1; i < rows.Count; i++)
            if (rows[i].Node.Parent == 0 && rows[i].Node.Edge == null) rows[i] = rows[i] with { Node = rows[i].Node with { Edge = "import" } };
        if (callers.Count == 0) rows[0] = rows[0] with { Line = rows[0].Line + "  (nothing calls through it)" };
        if (more) rows[0] = rows[0] with { Node = rows[0].Node with { Flags = ["more"] }, Line = rows[0].Line + "  (more not shown)" };
        return rows;
    }

    [McpServerTool(Name = "search_native_strings", Title = "Search native strings", UseStructuredContent = true, OutputSchemaType = typeof(NativeStringList))]
    [Description("Strings (ASCII and UTF-16) a native image's code or data references, with address, reference count and first referencing " +
                 "function. Also Il2Cpp literals (after apply_il2cpp_names) and NativeAOT frozen strings, by the slot or object code loads; with an " +
                 "engine, its unreferenced strings in other encodings too.")]
    public Task<string> SearchNativeStrings(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Case-insensitive substring, or a regex with regex=true; omit to list all.")] string? query = null,
        [Description("Treat query as a regular expression.")] bool regex = false,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Max rows (default 100).")] int limit = 100,
        [Description(EngineDescription)] string? engine = null,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        Regex? pattern = null;
        if (regex && !string.IsNullOrEmpty(query))
        {
            try { pattern = new Regex(query, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeouts.Limit); }
            catch (ArgumentException ex) { throw new ToolError(ErrorCode.InvalidArgument, $"Invalid regex: {ex.Message}"); }
        }
        var mode = Mode(engine);
        var (native, index) = await Open(image, context, progress, cancellationToken);
        var choice = Choose(mode, native, index);
        IReadOnlyList<Native.Providers.EngineString> engineStrings = [];
        if (choice.External)
            engineStrings = await (await _engine!.Session(native, choice, progress, cancellationToken)).ListStringsAsync(MaxEngineData, cancellationToken);
        // Image strings include packed tables of rare names, which the estimate counts up to a quarter low.
        OutputCall.Budgeted?.Tighten(80);
        var timeouts = new RegexTimeouts();
        var rows = new List<string>();
        var items = new List<NativeStringEntry>();
        int pageStart = Math.Max(0, offset), pageEnd = pageStart + Math.Clamp(limit, 1, 5_000); // the page PageRows shows
        // NativeAOT string literals are frozen String objects; code loads the object, so they are listed by it rather than by their characters.
        var frozen = NativeAotNames.View(native, cancellationToken)?.Frozen.Objects.Where(o => o.Text != null).ToList() ?? [];
        var frozenChars = frozen.Select(o => o.Rva + 12).ToHashSet();
        foreach (var s in index.Strings)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (frozenChars.Contains(s.Rva)) continue;
            var text = index.ReadString(s, 400);
            bool match = query == null || (pattern != null ? timeouts.IsMatch(pattern, text) : text.Contains(query, StringComparison.OrdinalIgnoreCase));
            if (!match) continue;
            var refs = index.RefsTo(s.Rva, 1);
            var first = refs.Count > 0 && index.FunctionAt(refs[0].From) is { } f ? f.Name : null;
            rows.Add($"{NativeAddress.Va(index.Image, s.Rva)}  {(s.Encoding == StringEncoding.Utf16 ? "L" : " ")}\"{Format.Clip(Escape(text), 200)}\"  " +
                     $"{index.CountRefsTo(s.Rva)} refs{(first != null ? $", first in {first}" : "")}");
            if (rows.Count - 1 >= pageStart && rows.Count - 1 < pageEnd) items.Add(new NativeStringEntry(NativeAddress.Va(index.Image, s.Rva), s.Encoding == StringEncoding.Utf16 ? "utf16" : "ascii", text, index.CountRefsTo(s.Rva), first));
        }
        // Il2Cpp string literals live in the metadata file; code loads them through slots named by apply_il2cpp_names.
        if (Il2CppNativeNames.Of(native) is { } il2cpp)
            for (int i = 0; i < il2cpp.LiteralSlots.Length; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var text = il2cpp.LiteralTexts[i];
                if (query != null && !(pattern != null ? timeouts.IsMatch(pattern, text) : text.Contains(query, StringComparison.OrdinalIgnoreCase))) continue;
                uint slot = il2cpp.LiteralSlots[i];
                var refs = index.RefsTo(slot, 1);
                var first = refs.Count > 0 && index.FunctionAt(refs[0].From) is { } f ? f.Name : null;
                rows.Add($"{NativeAddress.Va(index.Image, slot)}  il2cpp \"{Format.Clip(Escape(text), 200)}\"  slot {index.NameAt(slot)}, " +
                         $"{index.CountRefsTo(slot)} refs{(first != null ? $", first in {first}" : "")}");
                if (rows.Count - 1 >= pageStart && rows.Count - 1 < pageEnd) items.Add(new NativeStringEntry(NativeAddress.Va(index.Image, slot), "il2cpp", Format.Clip(text, 400), index.CountRefsTo(slot), first));
            }
        foreach (var o in frozen)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (query != null && !(pattern != null ? timeouts.IsMatch(pattern, o.Text!) : o.Text!.Contains(query, StringComparison.OrdinalIgnoreCase))) continue;
            var refs = index.RefsTo(o.Rva, 1);
            var first = refs.Count > 0 && index.FunctionAt(refs[0].From) is { } f ? f.Name : null;
            rows.Add($"{NativeAddress.Va(index.Image, o.Rva)}  nativeaot \"{Format.Clip(Escape(o.Text!), 200)}\"  {index.NameAt(o.Rva) ?? "frozen string"}, " +
                     $"{index.CountRefsTo(o.Rva)} refs{(first != null ? $", first in {first}" : "")}");
            if (rows.Count - 1 >= pageStart && rows.Count - 1 < pageEnd) items.Add(new NativeStringEntry(NativeAddress.Va(index.Image, o.Rva), "nativeaot", Format.Clip(o.Text!, 400), index.CountRefsTo(o.Rva), first));
        }
        // the engine's strings the built-in index has not listed (unreferenced, or of other string types)
        var listed = index.Strings.Select(s => s.Rva).ToHashSet();
        foreach (var s in engineStrings)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (listed.Contains(s.Rva)) continue;
            if (query != null && !(pattern != null ? timeouts.IsMatch(pattern, s.Text) : s.Text.Contains(query, StringComparison.OrdinalIgnoreCase))) continue;
            var refs = index.RefsTo(s.Rva, 1);
            var first = refs.Count > 0 && index.FunctionAt(refs[0].From) is { } f ? f.Name : null;
            var kind = $"{choice.Engine}:{s.Type}";
            rows.Add($"{NativeAddress.Va(index.Image, s.Rva)}  {kind} \"{Format.Clip(Escape(s.Text), 200)}\"  {index.CountRefsTo(s.Rva)} refs{(first != null ? $", first in {first}" : "")}");
            if (rows.Count - 1 >= pageStart && rows.Count - 1 < pageEnd) items.Add(new NativeStringEntry(NativeAddress.Va(index.Image, s.Rva), kind, s.Text, index.CountRefsTo(s.Rva), first));
        }
        return ToolOutput.With((choice.External ? choice.Line + "\n" : "") + timeouts.Note("string") + pager.PageRows(rows, offset, limit, "string"),
            new NativeStringList(native.Id, items, pageStart, rows.Count, pageStart + items.Count < rows.Count) { NotEvaluated = timeouts.Count });
    });

    private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t").Replace("\"", "\\\"");
}
