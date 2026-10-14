using System.ComponentModel;
using System.Text;
using Iced.Intel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Calls;
using Corvus.Native.Code;
using Corvus.Native.Providers;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>Interprocedural value tracing in native code (x86 / x64 / ARM64).</summary>
[McpServerToolType]
public sealed class NativeTraceTools(AssemblyWorkspace workspace, NativeCodeService code, NativeEngineService? engines = null, NativeNamePush? names = null,
    NativeLinkService? link = null)
{
    [Description("What the trace starts from.")]
    public sealed record TraceSeedRecord(
        [property: Description("location, argument, parameter, result or global.")] string Kind,
        [property: Description("VA of the instruction, call, function or global.")] string Address,
        [property: Description("The function and offset, null for a global.")] string? Function,
        [property: Description("The register or slot (for arguments and parameters: at the callee's entry), null for results and globals.")] string? Location,
        [property: Description("The seed in words.")] string Description);

    [Description("A node: a value (backward) or a use (forward).")]
    public sealed record TraceNodeRecord(
        int Id,
        [property: Description("seed, const, address, string, function, import (pointer of an imported function), api_result, call_result, parameter, global, " +
                               "field ([base+off] load), stack_local, merge (paths with different values), loop, unknown; forward: argument (into a callee of " +
                               "the image), sink (argument of an API or unresolved callee), store, field_store, return, compare, switch, dereference, call_target.")]
        string Kind,
        [property: Description("VA of the defining or using instruction (the function for parameters, the global for initial contents).")] string Address,
        [property: Description("The loaded image Address is in when it is not the seed's (reached through an import or export).")] string? Image,
        [property: Description("Function and offset of Address.")] string? Function,
        [property: Description("Register or slot, when the node has one.")] string? Location,
        [property: Description("The value or use as text (quoted strings, names, decoded constants).")] string Text,
        [property: Description("The number, for constants and compares (hex).")] string? Value,
        [property: Description("The address the value is: string, function, global (VA).")] string? ValueAddress,
        [property: Description("The value named by the API parameter or return it meets (GENERIC_READ|GENERIC_WRITE, WAIT_TIMEOUT).")] string? Decoded,
        [property: Description("Function boundaries crossed from the seed.")] int Depth,
        [property: Description("The node it was reached from (-1 for the seed).")] int Parent,
        [property: Description("backward (a value reaching the seed) or forward (a use of the seed's value).")] string Direction,
        [property: Description("The instructions it came through, or why it is unknown.")] string Derivation);

    [Description("A data-flow edge, From's value flows to To.")]
    public sealed record TraceEdgeRecord(int From, int To,
        [property: Description("copy, merge, loop, field, use, argument (caller's argument to a parameter), parameter (into a callee), return, store, load.")] string Kind,
        [property: Description("The call, store or load instruction (VA), when the edge crosses one.")] string? Site);

    [Description("Something a budget left unexplored.")]
    public sealed record TraceFrontierRecord(
        [property: Description("The node it continues from.")] int Node,
        [property: Description("depth, functions, nodes, callers, writers, readers or steps.")] string Reason,
        string Detail,
        [property: Description("The call that continues there.")] string Next);

    [Description("A distinct value reaching the seed (backward), or an API argument or switch case the seed's value reaches (forward).")]
    public sealed record TraceValueRecord(string Text,
        [property: Description("const, string, function, address, import, api_result, sink, or switch (the case a constant selects).")] string Kind,
        [property: Description("VA, for strings, functions and addresses.")] string? Address,
        [property: Description("The node.")] int Node);

    public sealed record ValueTraceReport(
        [property: Description("Image id.")] string Image,
        [property: Description("Engine of the per-function slices.")] string Engine,
        TraceSeedRecord Seed,
        [property: Description("backward, forward or both.")] string Direction,
        [property: Description("The answer: distinct values (backward) or API arguments reached (forward), over the whole graph.")] IReadOnlyList<TraceValueRecord> Values,
        [property: Description("Nodes of this page, in discovery order.")] IReadOnlyList<TraceNodeRecord> Nodes,
        [property: Description("Edges with either end on this page.")] IReadOnlyList<TraceEdgeRecord> Edges,
        [property: Description("Unexplored items, each with its follow-up call.")] IReadOnlyList<TraceFrontierRecord> Frontier,
        int TotalNodes,
        int TotalEdges,
        [property: Description("Functions sliced.")] int Functions,
        [property: Description("Index of the first node on this page.")] int Offset,
        [property: Description("More nodes follow (call again with offset).")] bool Truncated,
        IReadOnlyList<string> Notes);

    private const string LocationHelp = "a register (rdx, xmm1, x1, w2, r1), a stack slot ([rsp+28h], [ebp-8], [x29-8]), op1 / op2 (an operand) " +
                                        "or result (the call's return)";

    [McpServerTool(Name = "trace_native_values", Title = "Native value trace", UseStructuredContent = true, OutputSchemaType = typeof(ValueTraceReport))]
    [Description("Traces a value through native code (x86 / x64 / ARM) across functions. Backward: constants, strings, function pointers, API " +
                 "results, through copies, stack slots, merges and loops; parameters bind to every caller's argument, call results to the callee's " +
                 "returns, globals to their writers. Forward: API arguments, callees' parameters, globals and their readers, returns, compares, " +
                 "switch indexes, dereferences. Crosses loaded images; what the budgets leave out is a frontier entry with the follow-up call.")]
    public Task<string> TraceNativeValues(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("An instruction, a call, a function start (with argument) or a writable global. " + NativeTools.AddressDescription)] string address,
        [Description("The value at address: " + LocationHelp + ".")] string? location = null,
        [Description("An argument of the call at address, or a parameter of the function starting there: 1-based position or API parameter name.")]
        string? argument = null,
        [Description("backward (default: the values that reach it), forward (its uses) or both.")] string? direction = null,
        [Description("Function boundaries to cross (0-8).")] int maxDepth = 3,
        [Description("Functions to slice (1-256).")] int maxFunctions = 32,
        [Description("Nodes in the graph (1-5000).")] int maxNodes = 500,
        [Description("Call sites bound per parameter or return (1-256).")] int maxCallers = 16,
        [Description("Writers (backward) or readers (forward) per global (1-256).")] int maxWriters = 16,
        [Description("Stop at writable globals, not following their writers / readers.")] bool stopAtGlobals = false,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description("Nodes per page (max 1000).")] int limit = 200,
        [Description("Slices: ours, ida or ghidra (its IR, started when needed; ours where it cannot place the seed), or auto (default: an " +
                     "engine that analyzed the bytes, else ours).")] string? engine = null,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var mode = EngineModes.Resolve(engine, engines?.DefaultMode ?? EngineMode.Auto);
        var dir = (direction?.Trim().ToLowerInvariant()) switch
        {
            null or "" or "backward" or "back" => TraceDirection.Backward,
            "forward" or "fwd" => TraceDirection.Forward,
            "both" => TraceDirection.Both,
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown direction '{direction}'.", "use backward, forward or both"),
        };
        var (native, index) = await OpenIndex(workspace, code, image, progress, cancellationToken);
        var choice = NativeEngineCode.Choose(mode, !string.IsNullOrWhiteSpace(engine), engines, native, index);
        INativeDecompilerSession? session = null;
        if (choice.External)
        {
            session = await engines!.Session(native, choice.Engine, new Progress<NativeProviderProgress>(p => progress.Report(new ProgressNotificationValue
            {
                Progress = (float)p.Elapsed.TotalSeconds, Message = $"{NativeEngineService.DisplayName(choice.Engine)} {p.Stage}",
            })), cancellationToken);
            if (!session.DecompilerAvailable)
                throw new ToolError(ErrorCode.Unsupported, $"The {session.ProviderId} decompiler is not available for {session.Arch} code here.", "use engine=ours");
            if (names != null) await names.EnsureAsync(native, session, cancellationToken);
        }
        if (link != null && workspace.Read(() => workspace.Natives.Count) > 1) await link.WarmUp(null, cancellationToken);
        return await Task.Run(() =>
        {
            var links = link != null ? new NativeTraceLinks(workspace, link, code) : null;
            ITraceHost host = Arm64Trace.Supports(index) ? Arm64Trace.For(index) : Arm32Trace.Supports(index) ? Arm32Trace.For(index) : CallAnalysis.For(index);
            var seed = host is Arm64Trace arm ? Arm64Seed(arm, address, location, argument, cancellationToken)
                : host is Arm32Trace arm32 ? Arm32Trace.Seed(arm32, address, NativeCodeTools.Address(index, address), location, argument, cancellationToken)
                : Seed(CallAnalysis.For(index), address, location, argument, cancellationToken);
            var options = new ValueTraceOptions(dir, Math.Clamp(maxDepth, 0, 8), Math.Clamp(maxFunctions, 1, 256), Math.Clamp(maxNodes, 1, 5000),
                Math.Clamp(maxCallers, 1, 256), Math.Clamp(maxWriters, 1, 256), !stopAtGlobals);
            var provider = session != null ? new EngineSliceProvider(host, session) : null;
            var graph = ValueTrace.Build(host, seed, options, provider, cancellationToken, links is { Any: true } ? links : null, new NativeTraceTypes(workspace, code));
            var report = Report(index, graph, offset, limit);
            if (provider != null && SliceNote(graph, provider) is { } note) report = report with { Notes = [.. report.Notes, note] };
            return ToolOutput.With(choice.Line + "\n" + Text(index, graph, report), report);
        }, cancellationToken);
    });

    /// <summary>Engine and fallback slice counts of a built graph, recorded by the call that built it.</summary>
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<ValueTraceGraph, Tuple<int, int>> SliceCounts = new();

    /// <summary>
    /// "ida answered N slices; M fell back": a graph is built once per key and reused (pages, repeats), so its counts are kept
    /// with it and every call on it says the same.
    /// </summary>
    internal static string? SliceNote(ValueTraceGraph graph, EngineSliceProvider provider)
    {
        var counts = SliceCounts.GetValue(graph, _ => new Tuple<int, int>(provider.EngineSlices, provider.Fallbacks));
        return counts.Item1 + counts.Item2 == 0 ? null
            : $"{provider.Engine} answered {ToolSupport.Plural(counts.Item1, "slice")}; {ToolSupport.Plural(counts.Item2, "slice")} fell back to the built-in analysis";
    }

    /// <summary>Loads the image if given by path and waits for its code index (x86 / x64 / ARM64).</summary>
    internal static async Task<(LoadedNative Native, NativeCodeIndex Index)> OpenIndex(AssemblyWorkspace workspace, NativeCodeService code, string image, IProgress<ProgressNotificationValue> progress,
        CancellationToken ct)
    {
        var native = await Task.Run(() =>
        {
            return Targets.Native(workspace, image);
        }, ct);
        var waited = System.Diagnostics.Stopwatch.StartNew();
        var index = await code.Index(native, new Progress<CodeIndexProgress>(p => progress.Report(new ProgressNotificationValue
        {
            Progress = (float)waited.Elapsed.TotalSeconds, Message = $"indexing {native.Id}: {p.Phase}",
        })), ct);
        if (index.Support == CodeSupport.DeclaredFunctionsOnly) throw NativeEngineCode.Unsupported(index, null, "decompile_native reads the code through IDA or Ghidra");
        if (!CallAnalysis.Supports(index) && !Arm64Trace.Supports(index) && !Arm32Trace.Supports(index))
            throw new ToolError(ErrorCode.Unsupported, $"Values are traced in x86 / x64 / ARM code, not {index.Image.Arch}.", "decompile_native shows the code through IDA");
        return (native, index);
    }

    /// <summary>The seed named by address plus location, argument, or a global alone.</summary>
    internal static TraceSeed Seed(CallAnalysis a, string address, string? location, string? argument, CancellationToken ct)
    {
        var index = a.Index;
        var rva = NativeCodeTools.Address(index, address);
        string Va(uint r) => NativeAddress.Va(index.Image, r);
        string Where(uint r) => index.FunctionAt(r) is { } f ? $"{f.Name}+0x{r - f.Start:X}" : Va(r);
        var fn = index.FunctionAt(rva);
        var slices = a.Slices;
        if (!string.IsNullOrWhiteSpace(argument))
        {
            if (fn == null) throw new ToolError(ErrorCode.NotFound, $"No function contains {Va(rva)}.", "argument needs a call instruction or a function start");
            if (a.CallAt(rva, ct) is { } call)
            {
                var code = a.Code(fn, ct);
                var (b, i) = code.Position(rva);
                bool tail = a.SiteKindOf(code, in code.Blocks[b][i]) == 2;
                var sig = call.Signature;
                int k = ArgumentIndex(argument, sig, call.Callee);
                Loc entry;
                if (sig != null && k < sig.Params.Count)
                    entry = slices.CallToEntry(a.ParameterLocations(sig, tail)[k].Loc, tail) ?? slices.ParameterEntry(k);
                else entry = slices.ParameterEntry(k);
                var p = sig != null && k < sig.Params.Count ? sig.Params[k] : null;
                return new TraceSeed(TraceSeedKind.Argument, rva, fn, slices.LocationName(entry),
                    $"argument {k + 1}{(p != null ? " " + p.Name : "")} ({slices.LocationName(slices.EntryToCall(entry, tail))}) of {call.Callee} at {Va(rva)} ({Where(rva)})", p);
            }
            if (fn.Start == rva)
            {
                int k = ArgumentIndex(argument, null, fn.Name);
                var entry = slices.ParameterEntry(k);
                return new TraceSeed(TraceSeedKind.Parameter, rva, fn, slices.LocationName(entry), $"parameter {k + 1} ({slices.LocationName(entry)}) of {fn.Name}");
            }
            throw new ToolError(ErrorCode.InvalidArgument, $"{Va(rva)} ({Where(rva)}) is neither a call nor a function start.",
                "pass a call instruction or a function start with argument, or use location at other instructions");
        }
        if (string.IsNullOrWhiteSpace(location))
        {
            if (fn == null && index.Image.SectionAt(rva) is { } section && (section.Access & SectionAccess.Write) != 0)
                return new TraceSeed(TraceSeedKind.Global, rva, null, null, $"global [{index.NameAt(rva) ?? Va(rva)}]");
            throw new ToolError(ErrorCode.InvalidArgument, "Pass location (" + LocationHelp + ") or argument; address alone is for a writable global.",
                $"for example location=rax, or argument=1 at a call");
        }
        if (fn == null) throw new ToolError(ErrorCode.NotFound, $"No function contains {Va(rva)}.", "list_functions shows the functions; a writable global needs no location");
        var fc = a.Code(fn, ct);
        var (block, at) = fc.Position(rva);
        if (block < 0)
            throw new ToolError(ErrorCode.InvalidArgument, $"{Va(rva)} is not the start of an instruction of {fn.Name}.", "disassemble shows the instruction addresses");
        var loc = location.Trim();
        if (loc.Equals("result", StringComparison.OrdinalIgnoreCase))
        {
            var call = a.CallAt(rva, ct) ?? throw new ToolError(ErrorCode.InvalidArgument, $"{Va(rva)} is not a call: location=result needs one.");
            return new TraceSeed(TraceSeedKind.Result, rva, fn, null, $"result of {call.Callee} at {Va(rva)} ({Where(rva)})", Returns: ApiSignatures.FindReturn(call.Callee));
        }
        ref readonly var d = ref fc.Blocks[block][at];
        if (loc.Length == 3 && loc.StartsWith("op", StringComparison.OrdinalIgnoreCase) && char.IsAsciiDigit(loc[2]))
        {
            int k = loc[2] - '1';
            var x = d.I;
            if (k < 0 || k >= x.OpCount) throw new ToolError(ErrorCode.InvalidArgument, $"{x} has {x.OpCount} operands.", "op1 is the first operand");
            if (x.GetOpKind(k) == OpKind.Register) loc = slices.LocationName(Loc.Of(x.GetOpRegister(k)));
            else if (x.GetOpKind(k) == OpKind.Memory && d.HasMem && index.Image.SectionAt(d.MemRva) is { } s && (s.Access & SectionAccess.Write) != 0)
                return new TraceSeed(TraceSeedKind.Global, d.MemRva, null, null, $"global [{index.NameAt(d.MemRva) ?? Va(d.MemRva)}] ({x} at {Where(rva)})");
            else if (x.GetOpKind(k) == OpKind.Memory && x.MemoryIndex == Register.None && x.MemoryBase.GetFullRegister() is Register.RSP or Register.RBP)
                loc = slices.LocationName(x.MemoryBase.GetFullRegister() == Register.RSP ? Loc.Stack((int)(long)x.MemoryDisplacement64) : Loc.Frame((int)(long)x.MemoryDisplacement64));
            else
                throw new ToolError(ErrorCode.InvalidArgument, $"Operand {k + 1} of {x} is not a register, stack slot or writable global.",
                    "trace the base register of a memory operand instead (location=<register>)");
        }
        var parsed = OursSliceProvider.ParseLocation(loc, a.Is64)
                     ?? throw new ToolError(ErrorCode.InvalidArgument, $"Unknown location '{location}'.", "use " + LocationHelp);
        var name = slices.LocationName(parsed);
        return new TraceSeed(TraceSeedKind.Location, rva, fn, name, $"{name} at {Va(rva)} ({Where(rva)}: {d.I})");
    }

    /// <summary>The ARM64 seed: registers x0-x30 (w views), stack slots relative to sp or x29 at the instruction, AAPCS64 argument positions.</summary>
    internal static TraceSeed Arm64Seed(Arm64Trace a, string address, string? location, string? argument, CancellationToken ct)
    {
        var index = a.Index;
        var rva = NativeCodeTools.Address(index, address);
        string Va(uint r) => NativeAddress.Va(index.Image, r);
        string Where(uint r) => index.FunctionAt(r) is { } f ? $"{f.Name}+0x{r - f.Start:X}" : Va(r);
        var fn = index.FunctionAt(rva);
        if (!string.IsNullOrWhiteSpace(argument))
        {
            if (fn == null) throw new ToolError(ErrorCode.NotFound, $"No function contains {Va(rva)}.", "argument needs a call instruction or a function start");
            if (a.CallAt(rva, ct) is { } call)
            {
                var sig = call.Signature;
                int k = ArgumentIndex(argument, sig, call.Callee);
                var entry = A64Function.Name(A64Function.ParameterEntry(k), null);
                var p = sig != null && k < sig.Params.Count ? sig.Params[k] : null;
                return new TraceSeed(TraceSeedKind.Argument, rva, fn, entry, $"argument {k + 1}{(p != null ? " " + p.Name : "")} ({entry}) of {call.Callee} at {Va(rva)} ({Where(rva)})", p);
            }
            if (fn.Start == rva)
            {
                int k = ArgumentIndex(argument, null, fn.Name);
                var entry = A64Function.Name(A64Function.ParameterEntry(k), null);
                return new TraceSeed(TraceSeedKind.Parameter, rva, fn, entry, $"parameter {k + 1} ({entry}) of {fn.Name}");
            }
            throw new ToolError(ErrorCode.InvalidArgument, $"{Va(rva)} ({Where(rva)}) is neither a call nor a function start.",
                "pass a call instruction or a function start with argument, or use location at other instructions");
        }
        if (string.IsNullOrWhiteSpace(location))
        {
            if (fn == null && index.Image.SectionAt(rva) is { } section && (section.Access & SectionAccess.Write) != 0)
                return new TraceSeed(TraceSeedKind.Global, rva, null, null, $"global [{index.NameAt(rva) ?? Va(rva)}]");
            throw new ToolError(ErrorCode.InvalidArgument, "Pass location (" + LocationHelp + ") or argument; address alone is for a writable global.",
                "for example location=x0, or argument=1 at a call");
        }
        if (fn == null) throw new ToolError(ErrorCode.NotFound, $"No function contains {Va(rva)}.", "list_functions shows the functions; a writable global needs no location");
        var code = a.Code(fn, ct);
        var (block, at) = code.Position(rva);
        if (block < 0)
            throw new ToolError(ErrorCode.InvalidArgument, $"{Va(rva)} is not the start of an instruction of {fn.Name}.", "disassemble shows the instruction addresses");
        var step = code.Blocks[block][at];
        var loc = location.Trim();
        if (loc.Equals("result", StringComparison.OrdinalIgnoreCase))
        {
            var call = a.CallAt(rva, ct) ?? throw new ToolError(ErrorCode.InvalidArgument, $"{Va(rva)} is not a call: location=result needs one.");
            return new TraceSeed(TraceSeedKind.Result, rva, fn, null, $"result of {call.Callee} at {Va(rva)} ({Where(rva)})", Returns: ApiSignatures.FindReturn(call.Callee));
        }
        if (loc.Length == 3 && loc.StartsWith("op", StringComparison.OrdinalIgnoreCase) && char.IsAsciiDigit(loc[2]))
        {
            int k = loc[2] - '1';
            var x = step.I;
            if (k < 0 || k >= x.OperandCount) throw new ToolError(ErrorCode.InvalidArgument, $"{step.Text} has {x.OperandCount} operands.", "op1 is the first operand");
            if (A64Function.Gpr(x, k) is var r and >= 0 and < 31) loc = $"x{r}";
            else if (x.GetOperand(k).Kind == AsmArm64.Arm64OperandKind.Memory && step.Facts.HasMem && index.Image.SectionAt(step.Facts.MemTarget) is { } s && (s.Access & SectionAccess.Write) != 0)
                return new TraceSeed(TraceSeedKind.Global, step.Facts.MemTarget, null, null, $"global [{index.NameAt(step.Facts.MemTarget) ?? Va(step.Facts.MemTarget)}] ({step.Text} at {Where(rva)})");
            else if (x.GetOperand(k).Kind == AsmArm64.Arm64OperandKind.Memory && A64Function.Memory(step) is { Slot: { } slot }) loc = A64Function.Name(A64Loc.Slot(slot), step);
            else
                throw new ToolError(ErrorCode.InvalidArgument, $"Operand {k + 1} of {step.Text} is not a register, stack slot or writable global.",
                    "trace the base register of a memory operand instead (location=<register>)");
        }
        var parsed = A64Function.Parse(loc, step) ?? throw new ToolError(ErrorCode.InvalidArgument, $"Unknown location '{location}'.", "use " + LocationHelp);
        var name = A64Function.Name(parsed, step);
        return new TraceSeed(TraceSeedKind.Location, rva, fn, name, $"{name} at {Va(rva)} ({Where(rva)}: {step.Text})");
    }

    /// <summary>A 0-based argument index from a 1-based position or an API parameter name.</summary>
    private static int ArgumentIndex(string argument, ApiSignature? sig, string callee)
    {
        var text = argument.Trim();
        if (int.TryParse(text, out int n))
        {
            if (n < 1) throw new ToolError(ErrorCode.InvalidArgument, $"argument {n}: positions are 1-based (1 is the first).", "pass argument=1 for the first");
            if (n > 32) throw new ToolError(ErrorCode.InvalidArgument, $"argument {n}: at most 32.");
            if (sig is { Variadic: false } && n > sig.Params.Count)
                throw new ToolError(ErrorCode.InvalidArgument, $"{callee} takes {sig.Params.Count} arguments.", $"pass 1 to {sig.Params.Count}");
            return n - 1;
        }
        if (sig == null) throw new ToolError(ErrorCode.InvalidArgument, $"No signature is known for {callee}: pass the argument's position.");
        for (int k = 0; k < sig.Params.Count; k++)
            if (sig.Params[k].Name.Equals(text, StringComparison.OrdinalIgnoreCase)) return k;
        throw new ToolError(ErrorCode.InvalidArgument, $"{callee} has no parameter '{text}'.", "its parameters: " + string.Join(", ", sig.Params.Select(p => p.Name)));
    }

    private static string Kind(TraceNodeKind k) => k switch
    {
        TraceNodeKind.ApiResult => "api_result",
        TraceNodeKind.CallResult => "call_result",
        TraceNodeKind.StackLocal => "stack_local",
        TraceNodeKind.FieldStore => "field_store",
        TraceNodeKind.CallTarget => "call_target",
        _ => k.ToString().ToLowerInvariant(),
    };

    private static ValueTraceReport Report(NativeCodeIndex index, ValueTraceGraph g, int offset, int limit)
    {
        string Va(uint r, int image = 0) => NativeAddress.Va(g.Images[image].Image, r);
        // a node without an instruction of its own (address 0) is in its function, at no offset
        string? Where(TraceNode n) => n.Function is { } f ? n.Address >= f.Start ? $"{f.Name}+0x{n.Address - f.Start:X}" : f.Name : null;
        int start = Math.Clamp(offset, 0, g.Nodes.Count);
        var page = g.Nodes.Skip(start).Take(Math.Clamp(limit, 1, 1000)).ToList();
        var ids = page.Select(n => n.Id).ToHashSet();
        var s = g.Seed;
        return new ValueTraceReport(Path.GetFileName(index.Image.Path), g.Engine,
            new TraceSeedRecord(s.Kind.ToString().ToLowerInvariant(), Va(s.Address), s.Function is { } sf ? $"{sf.Name}+0x{s.Address - sf.Start:X}" : null, s.Location, s.Description),
            g.Options.Direction.ToString().ToLowerInvariant(),
            g.Values.Select(v => new TraceValueRecord(v.Text, Kind(v.Kind), v.Rva is { } r ? Va(r, v.Image) : null, v.Node)).ToList(),
            page.Select(n => new TraceNodeRecord(n.Id, Kind(n.Kind), Va(n.Address, n.Image), n.Image == 0 ? null : g.Images[n.Image].Id, Where(n), n.Location, n.Text,
                n.Value is { } v ? $"0x{v:X}" : null, n.ValueRva is { } r ? Va(r, n.Image) : null, n.Decoded, n.Depth, n.Parent, n.Backward ? "backward" : "forward",
                n.Derivation)).ToList(),
            g.Edges.Where(e => ids.Contains(e.From) || ids.Contains(e.To)).Select(e => new TraceEdgeRecord(e.From, e.To, e.Kind, e.Site != 0 ? Va(e.Site, e.Image) : null)).ToList(),
            g.Frontier.Select(f => new TraceFrontierRecord(f.Node, f.Reason, f.Detail, f.Next)).ToList(),
            g.Nodes.Count, g.Edges.Count, g.Functions, start, start + page.Count < g.Nodes.Count, g.Notes);
    }

    private static string Text(NativeCodeIndex index, ValueTraceGraph g, ValueTraceReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Value trace ({r.Direction}) of {g.Seed.Description}; engine {g.Engine}");
        sb.AppendLine(r.Values.Count == 0 ? "Values reached: none recovered" : $"Values reached ({r.Values.Count}): " +
            string.Join(", ", r.Values.Take(40).Select(v => v.Text)) + (r.Values.Count > 40 ? ", ..." : ""));
        sb.AppendLine($"Graph: {ToolSupport.Plural(r.TotalNodes, "node")}, {ToolSupport.Plural(r.TotalEdges, "edge")}, {ToolSupport.Plural(r.Functions, "function")}, " +
                      $"{ToolSupport.Plural(r.Frontier.Count, "frontier item")}; nodes {r.Offset}-{r.Offset + r.Nodes.Count - 1}:");
        var depthOf = new Dictionary<int, int>();
        int Indent(TraceNode n)
        {
            if (depthOf.TryGetValue(n.Id, out int d)) return d;
            d = n.Parent < 0 || n.Parent >= n.Id ? 0 : Math.Min(12, Indent(g.Nodes[n.Parent]) + 1);
            depthOf[n.Id] = d;
            return d;
        }
        foreach (var n in r.Nodes)
        {
            var node = g.Nodes[n.Id];
            var arrow = node.Kind == TraceNodeKind.Seed ? "" : node.Backward ? "<- " : "-> ";
            sb.Append(' ', 2 * Indent(node) + 2).Append('#').Append(n.Id).Append(' ').Append(arrow).Append(n.Kind).Append(": ").Append(Format.Clip(n.Text, 200));
            if (n.Decoded != null && !n.Text.Contains(n.Decoded, StringComparison.Ordinal)) sb.Append(" [").Append(n.Decoded).Append(']');
            if (n.Function != null && node.Kind != TraceNodeKind.Seed) sb.Append("  @").Append(n.Image != null ? $"[{n.Image}] " : "").Append(n.Function);
            sb.AppendLine();
        }
        if (r.Frontier.Count > 0)
        {
            sb.AppendLine("Frontier (not explored):");
            foreach (var f in r.Frontier.Take(50)) sb.AppendLine($"  #{f.Node} {f.Reason}: {f.Detail} -> {f.Next}");
            if (r.Frontier.Count > 50) sb.AppendLine($"  ... {r.Frontier.Count - 50} more (structured output)");
        }
        foreach (var note in r.Notes) sb.AppendLine("Note: " + note);
        if (index.Truncations.Count > 0) sb.AppendLine("Note: " + string.Join("; ", index.Truncations));
        if (r.Truncated) sb.AppendLine($"[More: offset={r.Offset + r.Nodes.Count}]");
        sb.AppendLine("Derivations and edges are in the structured output.");
        return sb.ToString();
    }
}
