using System.ComponentModel;
using System.Text;
using System.Text.RegularExpressions;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

/// <summary>Native code: functions, disassembly, control flow, cross-references, call trees and strings (x86 / x64).</summary>
[McpServerToolType]
public sealed partial class NativeCodeTools(AssemblyWorkspace workspace, NativeCodeService code, OutputPager pager, NativeLinkService? link = null,
    NativeEngineService? engines = null, NativeNamePush? names = null, NativeTypePush? types = null, NativeUserTypePush? userTypes = null)
{
    /// <summary>Answers for images whose instructions the built-in analysis does not decode (ARM64, ARM), through IDA.</summary>
    private readonly NativeEngineCode? _engine = engines != null ? new NativeEngineCode(engines, pager, names) : null;

    internal const string EngineDescription = "Where functions, references and control flow come from: auto (default: IDA's analysis when one of this image " +
                                              "is complete in this session, else the built-in index; never starts IDA), ours (the built-in index only) or ida " +
                                              "(IDA's analysis, started or waited for when needed). The server default is set with --engine or NDM_ENGINE.";

    /// <summary>The engine mode a call asks for (checked before the image is opened) and whether it named one.</summary>
    private (EngineMode Mode, bool Named) Mode(string? engine) =>
        (EngineModes.Resolve(engine, engines?.DefaultMode ?? EngineMode.Auto), !string.IsNullOrWhiteSpace(engine));

    /// <summary>The engine for this call (see <see cref="NativeEngineCode.Choose"/>).</summary>
    private EngineChoice Choose((EngineMode Mode, bool Named) mode, LoadedNative native, NativeCodeIndex index) =>
        NativeEngineCode.Choose(mode.Mode, mode.Named, engines, native, index);

    private const string IndexNote ="The first call on an image waits for its code index (built in the background after loading; seconds for a typical DLL, " +
                                     "one to two minutes for a 300 MB browser DLL; progress is reported).";

    /// <summary>Loads the image if given by path, waits for its index, and resolves the address (names include functions).</summary>
    private async Task<(LoadedNative Native, NativeCodeIndex Index)> Open(string image, RequestContext<CallToolRequestParams>? context,
        IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var native = await Task.Run(() =>
        {
            var id = workspace.Read(() => workspace.FindNative(image)?.Id);
            if (id == null && !string.IsNullOrWhiteSpace(image) && Path.IsPathFullyQualified(image.Trim()) && File.Exists(image.Trim()))
                id = workspace.LoadAny(image.Trim()).Native?.Id ?? throw new ToolError(ErrorCode.Unsupported, $"{image} is a .NET assembly, not a native image.",
                    "use the .NET tools for it");
            return workspace.Read(() => workspace.GetNative(id ?? image));
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
        index.FunctionAt(rva) ?? throw new ToolError(ErrorCode.NotFound, $"No function contains {NativeAddress.Va(index.Image, rva)}.",
            "list_functions shows the functions; disassemble shows raw instructions at any address");

    private static string Flags(NativeFunction f, NativeCodeIndex? index = null) => FlagList(f, index) is { Count: > 0 } flags ? $"  [{string.Join(", ", flags)}]" : "";

    private static List<string> FlagList(NativeFunction f, NativeCodeIndex? index = null)
    {
        var flags = new List<string>();
        if (index != null && EngineLibraryNames.IsLibrary(index, f.Start)) flags.Add("library");
        if (f.Flags.HasFlag(FunctionFlags.Thunk)) flags.Add("thunk");
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
        if (index.Support == CodeSupport.DeclaredFunctionsOnly) notes.Add(index.SupportNote ?? "instructions are not decoded for this architecture");
        if (index.AbsoluteRefsUnconfirmed) notes.Add("no relocations: absolute data references are accepted by address range alone");
        notes.AddRange(index.Truncations);
        return notes.Count > 0 ? "Note: " + string.Join("; ", notes) + "\n" : "";
    }

    [McpServerTool(Name = "list_functions", Title = "List native functions", UseStructuredContent = true, OutputSchemaType = typeof(FunctionList))]
    [Description("Functions of a native image (x86 / x64): address, size, name (export name, module!import for thunks, or sub_<rva>), flags " +
                 "(thunk, noreturn, unresolved jumps, invalid code, funclet, funclet of its parent, exception chunks: catch blocks, unwind funclets, filters " +
                 "and handlers attached to their function), how it was found and how many call sites reach it. get_exception_info shows the details. " +
                 "Names from rename_native, PDB symbols and apply_il2cpp_names take precedence in that order. " + IndexNote)]
    public Task<string> ListFunctions(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Only functions whose name contains this text (case-insensitive).")] string? filter = null,
        [Description("Order: address (default), size (largest first) or callers (most called first).")] string? sort = null,
        [Description("Index of the first row.")] int offset = 0,
        [Description("Max rows (default 300).")] int limit = 300,
        [Description(EngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var mode = Mode(engine);
        var (native, index) = await Open(image, context, progress, cancellationToken);
        var choice = Choose(mode, native, index);
        if (choice.Ida)
            return await _engine!.ListFunctions(native, index, filter, sort, offset, limit, choice, progress, cancellationToken);
        // library names of an IDA session already open (none is started for this)
        if (engines?.LibraryNames(native) is { IsCompleted: false } importing) await importing.WaitAsync(cancellationToken);
        IEnumerable<NativeFunction> list = index.Functions.Where(f => filter == null || f.Name.Contains(filter, StringComparison.OrdinalIgnoreCase));
        list = (sort?.Trim().ToLowerInvariant()) switch
        {
            null or "" or "address" => list,
            "size" => list.OrderByDescending(f => f.Size),
            "callers" => list.OrderByDescending(f => index.CountRefsTo(f.Start)),
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown sort '{sort}'.", "use address, size or callers"),
        };
        var functions = list.ToList();
        string Sources(NativeFunction f) => f.Sources + (EngineLibraryNames.IsLibrary(index, f.Start) ? ", ida" : "");
        var rows = functions.Select(f => $"{NativeAddress.Va(index.Image, f.Start)}  {f.Size,7}  {f.Name}{Flags(f, index)}  ({Sources(f)}; {index.CountRefsTo(f.Start)} refs)").ToList();
        var s = index.Stats;
        var coverage = Coverage(index);
        int library = index.Sourced.Count(NativeNameSource.Ida);
        var result = Paged(functions, offset, limit, (page, o, total, more) => new FunctionList(native.Id, s.Functions,
            page.Select(f => new FunctionEntry(NativeAddress.Va(index.Image, f.Start), (int)f.Size, f.Name, FlagList(f, index), Sources(f), index.CountRefsTo(f.Start))).ToList(),
            o, total, more, coverage.Length > 0 ? coverage.Trim() : null, choice.Engine, choice.Note));
        return StructuredOutput.With($"{native.Id}: {Plural(s.Functions, "function")} ({s.Thunks} thunks, {s.NoReturnFunctions} noreturn" +
               (library > 0 ? $", {library} library functions named by IDA" : "") + $"), {s.Instructions:N0} instructions, " +
               $"{s.Xrefs:N0} references, {Plural(s.Strings, "string")}\n{choice.Line}\n" + coverage + pager.PageRows(rows, offset, limit, "function"), result);
    });

    [McpServerTool(Name = "disassemble", Title = "Disassemble native code")]
    [Description("MASM-syntax disassembly of the native function containing an address (with block labels), or of maxInstructions from the address " +
                 "when it is in no function or function=false. Calls and data references are named (module!import, exports, sub_<rva>, loc_<rva>) " +
                 "and string references shown as comments; calls are commented with their recovered arguments (CreateFileW(L\"a.ini\", GENERIC_READ, ...), see get_call_arguments). " +
                 "Warns when the address is inside an instruction, in data or in bss; a listing from an address renders strings, pointers, IAT slots and switch " +
                 "tables as data and resynchronizes when it runs into a known instruction; a function listing names the gaps between its blocks " +
                 "(switch table, padding, unreached bytes). Warnings are repeated in a footer. " + IndexNote)]
    public Task<string> Disassemble(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description("Disassemble the whole containing function (default true); false: maxInstructions from the address.")] bool function = true,
        [Description("Max instructions (default 2000).")] int maxInstructions = 2000,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        [Description(EngineDescription + " With IDA, the function's bounds and instructions are IDA's.")] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var mode = Mode(engine);
        var (native, index) = await Open(image, context, progress, cancellationToken);
        int max = Math.Clamp(maxInstructions, 1, 200_000);
        var choice = Choose(mode, native, index);
        if (choice.Ida)
            return await _engine!.Disassemble(native, index, Address(index, address), function, max, offset, maxChars, choice, progress, cancellationToken);
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
                var calls = NativeCallTools.CallComments(index, fn, cancellationToken);
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
        return $"; {choice.Line}\n" + Coverage(index) + pager.Page(text + await BoundImports(native, index, fn, cancellationToken), offset, maxChars);
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
        if (calls != null && calls.TryGetValue(l.Rva, out var call)) comment = comment != null ? call + "; " + comment : call;
        return $"  {l.Address:X}  {l.Bytes,-24} {l.Text}{(comment != null ? "  ; " + comment : "")}";
    }

    [McpServerTool(Name = "get_cfg", Title = "Native control-flow graph")]
    [Description("Basic blocks of the native function containing an address: each block's range, instruction count, how it ends (return, jump, " +
                 "switch, tail call, noreturn call...) and its successors; resolved switch tables with their cases; indirect jumps whose targets are unknown. " + IndexNote)]
    public Task<string> GetCfg(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        [Description(EngineDescription + " With IDA, the blocks and edges are IDA's.")] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var mode = Mode(engine);
        var (native, index) = await Open(image, context, progress, cancellationToken);
        var choice = Choose(mode, native, index);
        if (choice.Ida)
            return await _engine!.Cfg(native, index, Address(index, address), offset, maxChars, choice, progress, cancellationToken);
        if (index.Support == CodeSupport.DeclaredFunctionsOnly) throw NativeEngineCode.Unsupported(index, engines);
        var fn = FunctionAt(index, Address(index, address));
        var graph = index.GetGraph(fn, cancellationToken);
        string Va(uint rva) => NativeAddress.Va(index.Image, rva);
        var sb = new StringBuilder($"{fn.Name} at {Va(fn.Start)}: {Plural(graph.Blocks.Count, "block")}{(graph.Truncated ? " (truncated)" : "")}\n");
        foreach (var b in graph.Blocks)
            sb.AppendLine($"  {Va(b.Start)}-{Va(b.End)}  {b.InstructionCount,4} insn  {b.EndKind}" +
                          (b.Successors.Count > 0 ? "  -> " + string.Join(", ", b.Successors.Select(e => $"{Va(e.To)}{(e.Kind is EdgeKind.FallThrough or EdgeKind.Jump ? "" : " " + e.Kind)}")) : ""));
        foreach (var sw in graph.Switches)
            sb.AppendLine($"  switch at {Va(sw.JumpRva)}: table {Va(sw.TableRva)}, {sw.EntryCount} entries, {Plural(sw.Targets.Count, "distinct target")}: " +
                          string.Join(", ", sw.Targets.Take(64).Select(Va)) + (sw.Targets.Count > 64 ? ", ..." : ""));
        foreach (var j in graph.UnresolvedJumps) sb.AppendLine($"  unresolved indirect jump at {Va(j)}");
        foreach (var t in graph.TailCalls) sb.AppendLine($"  tail call to {index.NameAt(t) ?? Va(t)}");
        return choice.Line + "\n" + pager.Page(sb.ToString(), offset, maxChars);
    });

    [McpServerTool(Name = "find_xrefs", Title = "Native cross-references", UseStructuredContent = true, OutputSchemaType = typeof(XrefList))]
    [Description("Everything in a native image that references an address: calls (direct and through import slots and thunks), jumps, data reads " +
                 "and writes, address-taken uses, switch tables and relocated data pointers, each with the function it is in; for a virtual method, the " +
                 "virtual call sites that reach it (VirtualExact: the only implementation; VirtualPossible: one of several; resolved through MSVC RTTI). For an import " +
                 "(module!name) lists the call sites of that API (x86 calls through a register loaded from the slot included) and what it is bound to; " +
                 "for an export, also the call sites in other loaded images that import it ([image] prefix). Call rows show the recovered arguments. " +
                 "A late-bound import (module!name resolved by GetProcAddress) lists where it is resolved and the calls through its pointer. " +
                 "A struct member (Type::member, Type.member or Type+0x18, from the engine's types: PDB, RTTI classes, Il2Cpp, declare_native_types) " +
                 "lists its uses through IDA: operands typed as the member, and reads, writes and address-of in the pseudocode of the functions " +
                 "whose prototype names the type (methods with a typed this). " + IndexNote)]
    public Task<string> FindXrefs(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription + " Or a struct member: Type::member, Type.member, Type+0xOFFSET.")] string address,
        [Description("Index of the first row.")] int offset = 0,
        [Description("Max rows (default 500).")] int limit = 500,
        [Description(EngineDescription + " With IDA, the references are IDA's, plus the RTTI-resolved virtual call sites IDA has none for (marked ours).")]
        string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var mode = Mode(engine);
        var (native, index) = await Open(image, context, progress, cancellationToken);
        if (FieldTarget(address) is { } field && !IsAddress(index, address))
            return await FieldXrefs(native, field, mode.Mode, offset, limit, progress, cancellationToken);
        var choice = Choose(mode, native, index);
        if (choice.Ida)
        {
            var via = await _engine!.Xrefs(native, index, Address(index, address), choice, progress, cancellationToken);
            return StructuredOutput.With(via.Header + pager.PageRows(via.Rows, offset, limit, "reference"),
                Xrefs(native.Id, via.Target, via.Rows, offset, limit, null, choice));
        }
        // a late-bound import (GetProcAddress) by name: its resolution and the calls through its pointer
        var dynamicRows = NativeCallTools.DynamicXrefRows(index, address, cancellationToken);
        uint rva;
        try { rva = Address(index, address); }
        catch (ToolError) when (dynamicRows != null)
        {
            return StructuredOutput.With($"References to {address.Trim()} (late-bound import):\n{choice.Line}\n" + Coverage(index) +
                                         pager.PageRows(dynamicRows, offset, limit, "reference"),
                Xrefs(native.Id, $"{address.Trim()} (late-bound import)", dynamicRows, offset, limit, null, choice));
        }
        string Va(uint r) => NativeAddress.Va(index.Image, r);
        string Where(uint from) => index.FunctionAt(from) is { } f ? $"{f.Name}+0x{from - f.Start:X}" : "(no function)";
        var rows = new List<string>();
        var import = index.Image.Imports.FirstOrDefault(i => i.SlotRva == rva);
        if (import != null)
            rows.AddRange(NativeCallTools.ImportRows(index, import, Where, cancellationToken));
        else
        {
            // virtual call sites that may reach the address (RTTI resolution) among the instruction references, by source
            var refs = index.RefsTo(rva).Concat(index.VirtualEdgesTo(rva)).OrderBy(x => x.From).ToList();
            rows.AddRange(NativeCallTools.WithArguments(index, refs.Select(x => (x.From, x.Kind.ToString(), x.Kind is XrefKind.Call or XrefKind.TailCall || x.IsVirtualCall)),
                Where, cancellationToken));
        }
        if (dynamicRows != null) rows.AddRange(dynamicRows);
        var target = index.NameAt(rva) ?? NativeCallTools.PointerName(index, rva, cancellationToken) ?? (index.StringAt(rva) is { } s ? index.CommentFor(rva) : null);
        var header = $"References to {Va(rva)}{(target != null ? $" ({target})" : "")}:\n";
        string? boundTo = null;
        if (link != null)
        {
            // Other loaded images reach this address through their imports; an import slot shows what it is bound to.
            await link.WarmUp(null, cancellationToken);
            if (import != null) header += $"Bound to: {boundTo = NativeLinkService.Describe(link.BindImport(native, import))}\n";
            rows.AddRange(workspace.Read(() => link.ImportCallSites(native, rva, cancellationToken)));
        }
        return StructuredOutput.With(header + choice.Line + "\n" + Coverage(index) + pager.PageRows(rows, offset, limit, "reference"),
            Xrefs(native.Id, $"{Va(rva)}{(target != null ? $" ({target})" : "")}", rows, offset, limit, boundTo, choice));
    });

    /// <summary>
    /// find_xrefs rows ("[image] VA  Kind  function+0xN  detail") as fields; a row of another form (an importer whose index is
    /// not built) has only its text, as Detail.
    /// </summary>
    private static XrefList Xrefs(string image, string target, List<string> rows, int offset, int limit, string? boundTo, EngineChoice choice) =>
        Paged(rows, offset, limit, (page, o, total, more) => new XrefList(image, target, page.Select(row =>
            XrefRow().Match(row) is { Success: true } m
                ? new XrefEntry(m.Groups["image"].Success ? m.Groups["image"].Value : null, m.Groups["va"].Value, m.Groups["kind"].Value, m.Groups["where"].Value,
                    m.Groups["rest"].Value.Length > 0 ? m.Groups["rest"].Value : null)
                : new XrefEntry(null, null, null, null, row)).ToList(), o, total, more, boundTo, choice.Engine, choice.Note));

    [GeneratedRegex(@"^(?:\[(?<image>[^\]]+)\] )?(?<va>0x[0-9A-F]+)\s+(?<kind>\S+)\s+(?<where>\(no function\)|\S+)\s*(?<rest>.*)$")]
    private static partial Regex XrefRow();

    [McpServerTool(Name = "native_call_tree", Title = "Native call tree")]
    [Description("Callers or callees of a native function, several levels deep (calls through thunks and import slots included). Across images: " +
                 "a call through module!import continues into the provider's function when that image is loaded (shown as module!import -> " +
                 "PROVIDER.dll!export at VA [image], forwarders and jump thunks followed; otherwise the provider's path, or why it does not resolve), " +
                 "and callers include call sites in other loaded images that import the function. Callees include late-bound imports called " +
                 "through a GetProcAddress pointer stored once ([dynamic]) and the implementations virtual calls reach, resolved through MSVC RTTI " +
                 "([virtual]: the only one; [virtual?: one of n]: one of several; find_virtual_calls lists the sites). Repeated subtrees and recursion are " +
                 "marked instead of expanded. " + IndexNote)]
    public Task<string> NativeCallTree(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string function,
        [Description("callers or callees (default callees).")] string direction = "callees",
        [Description("Levels (1-8, default 3).")] int depth = 3,
        [Description("Max nodes (default 500).")] int maxNodes = 500,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        [Description("Call edges to follow: all (default), direct (no virtual call edges) or virtual (only virtual_exact / virtual_possible edges).")] string? calls = null,
        [Description(EngineDescription + " With IDA, edges are IDA's call and jump references plus the RTTI-resolved virtual calls IDA has none for " +
                     "(marked ours); calls into other loaded images are followed with the built-in index only.")] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        bool callers = direction?.Trim().ToLowerInvariant() switch
        {
            "callers" => true,
            "callees" or null or "" => false,
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown direction '{direction}'.", "use callers or callees"),
        };
        var edges = calls?.Trim().ToLowerInvariant() switch
        {
            null or "" or "all" => CallEdgeFilter.All,
            "direct" => CallEdgeFilter.Direct,
            "virtual" => CallEdgeFilter.Virtual,
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown calls filter '{calls}'.", "use all, direct or virtual"),
        };
        var mode = Mode(engine);
        var (native, index) = await Open(image, context, progress, cancellationToken);
        var choice = Choose(mode, native, index);
        if (choice.Ida)
            return await _engine!.CallTree(native, index, Address(index, function), callers, Math.Clamp(depth, 1, 8), ClampLimit(maxNodes, 20_000), offset, maxChars,
                edges, choice, progress, cancellationToken);
        var fn = FunctionAt(index, Address(index, function));
        if (link != null)
        {
            await link.WarmUp(null, cancellationToken);
            var text = new StringBuilder();
            workspace.Read(() => link.AppendTree(text, native, fn, callers, Math.Clamp(depth, 1, 8), ClampLimit(maxNodes, 20_000), 0, true, cancellationToken, edges));
            return choice.Line + "\n" + pager.Page(text.ToString());
        }
        var root = index.CallTree(fn, Math.Clamp(depth, 1, 8), callers, ClampLimit(maxNodes, 20_000), edges);
        var dynamic = callers || edges == CallEdgeFilter.Virtual ? new HashSet<CallTreeNode>() : NativeCallTools.AddDynamicCallees(index, root, cancellationToken);
        var sb = new StringBuilder();
        void Walk(CallTreeNode node, int level)
        {
            var name = node.Function?.Name ?? (node.Import != null ? NativeCodeIndex.ImportName(node.Import) : NativeAddress.Va(index.Image, node.Address));
            sb.Append(new string(' ', level * 2)).Append(name)
              .Append(dynamic.Contains(node) ? "  [dynamic]" : "")
              .Append(node.Via switch
              {
                  XrefKind.VirtualExact => "  [virtual]",
                  XrefKind.VirtualPossible => $"  [virtual?: one of {index.VirtualCalls.SiteAt(node.Site)?.TargetCount ?? 0}]",
                  _ => "",
              })
              .Append(node.Function != null ? $"  {NativeAddress.Va(index.Image, node.Function.Start)}" : "")
              .Append(node.Repeated ? "  (repeated)" : "").Append(node.Truncated ? "  (more not shown)" : "").AppendLine();
            foreach (var child in node.Children) Walk(child, level + 1);
        }
        Walk(root, 0);
        return choice.Line + "\n" + pager.Page(sb.ToString(), offset, maxChars);
    });

    [McpServerTool(Name = "search_native_strings", Title = "Search native strings", UseStructuredContent = true, OutputSchemaType = typeof(NativeStringList))]
    [Description("Strings (ASCII and UTF-16) a native image's code or data references, with the address, the number of references and the first " +
                 "referencing function; filter by substring or regex. After apply_il2cpp_names also the Il2Cpp string literals, by the slot code loads them from; " +
                 "in a NativeAOT image the string literals (frozen String objects), by the object code loads. " + IndexNote)]
    public Task<string> SearchNativeStrings(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Text to find (case-insensitive substring), or a regex with regex=true; omit to list all.")] string? query = null,
        [Description("Treat query as a regular expression.")] bool regex = false,
        [Description("Index of the first row.")] int offset = 0,
        [Description("Max rows (default 300).")] int limit = 300,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        Regex? pattern = null;
        if (regex && !string.IsNullOrEmpty(query))
        {
            try { pattern = new Regex(query, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeouts.Limit); }
            catch (ArgumentException ex) { throw new ToolError(ErrorCode.InvalidArgument, $"Invalid regex: {ex.Message}"); }
        }
        var (native, index) = await Open(image, context, progress, cancellationToken);
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
        return StructuredOutput.With(timeouts.Note("string") + pager.PageRows(rows, offset, limit, "string"),
            new NativeStringList(native.Id, items, pageStart, rows.Count, pageStart + items.Count < rows.Count) { NotEvaluated = timeouts.Count });
    });

    private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t").Replace("\"", "\\\"");
}
