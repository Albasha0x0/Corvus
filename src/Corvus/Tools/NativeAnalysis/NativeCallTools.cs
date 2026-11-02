using System.ComponentModel;
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

/// <summary>Call sites of native code with their recovered argument values.</summary>
[McpServerToolType]
public sealed class NativeCallTools(NativeCodeService code, NativeEngineService? engines = null)
{
    [Description("One argument of a call.")]
    public sealed record CallArgumentRecord(
        [property: Description("0-based position.")] int Index,
        [property: Description("Parameter name from the API signature; null for callees without one.")] string? Name,
        [property: Description("Parameter type (str, int, ptr, enum or flags name...); null without a signature.")] string? Type,
        [property: Description("Register or slot: rcx, rdi, xmm0, [rsp+20h], [esp+4h]; ARM64 x0-x7, s0-s7, d0-d7.")] string Location,
        [property: Description("immediate, string, address, name, result (of a call), global (contents), unknown.")] string Kind,
        [property: Description("The value as shown: decoded flags, quoted string, name, or ? when unknown.")] string Text,
        [property: Description("The number for immediates (hex).")] string? Value,
        [property: Description("The address (VA) for strings, addresses, names and globals.")] string? Address,
        [property: Description("The instructions from the call back to the definition, or why it is unknown.")] string Derivation);

    [Description("One call site.")]
    public sealed record CallSiteRecord(
        [property: Description("VA of the call instruction.")] string Address,
        [property: Description("The calling function.")] string Function,
        [property: Description("module!name for imports (also late-bound), a function, or the indirect pointer.")] string Callee,
        [property: Description("import, function, dynamic (GetProcAddress / dlsym), virtual_exact (one RTTI target), " +
                               "virtual_possible (several, listed in Callee), indirect.")] string CalleeKind,
        [property: Description("A jump to the callee (tail call) rather than a call.")] bool TailCall,
        [property: Description("Callee signature known (names, count, decoding); else the slots set before the call.")] bool SignatureKnown,
        IReadOnlyList<CallArgumentRecord> Arguments);

    public sealed record CallArgumentsReport(
        [property: Description("Image id.")] string Image,
        [property: Description("What was searched: a call, the calls in a function, or the calls to a callee.")] string Scope,
        IReadOnlyList<CallSiteRecord> Items, int Offset, int Total,
        [property: Description("Coverage notes: limits reached, what is not analyzed.")] IReadOnlyList<string> Notes);

    private async Task<(LoadedNative Native, NativeCodeIndex Index)> OpenCalls(string image, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var (native, index) = await code.Open(image, NativeCodeTools.IndexProgress(image, progress), ct);
        if (index.Support == CodeSupport.DeclaredFunctionsOnly) throw NativeEngineCode.Unsupported(index, null, "decompile_native reads the code through IDA or Ghidra");
        if (Sites(index) == null)
            throw new ToolError(ErrorCode.Unsupported, $"Call arguments are recovered for x86, x64, ARM64 and ARM32 code, not {index.Image.Arch}.", "decompile_native shows calls through IDA");
        return (native, index);
    }

    [McpServerTool(Name = "get_call_arguments", Title = "Native call arguments", UseStructuredContent = true, OutputSchemaType = typeof(CallArgumentsReport))]
    [Description("Call sites with recovered argument values: constants, strings, addresses, earlier call results. Known Win32, CRT and " +
                 "libc APIs name parameters and decode flags. Pass address, callee or both.")]
    public Task<string> GetCallArguments(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("A call, or an address in a function (all its calls): " + NativeTools.AddressDescription)] string? address = null,
        [Description("Only calls to this API, module!name or function; without address, image-wide.")] string? callee = null,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description("Max call sites (max 1000).")] int limit = 50,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        if (string.IsNullOrWhiteSpace(address) && string.IsNullOrWhiteSpace(callee))
            throw new ToolError(ErrorCode.InvalidArgument, "Pass address (a call or a function) or callee (an API or function name).");
        var (native, index) = await OpenCalls(image, progress, cancellationToken);
        var session = engines?.OpenSession(native);
        Func<uint, ApiSignature?>? prototype = session == null ? null : start => EnginePrototype(session, index, start, cancellationToken);
        return await Task.Run(() => Report(index, address, callee, offset, limit, cancellationToken, prototype), cancellationToken);
    });

    /// <summary>The call sites of an index (x86, x64, ARM64, ARM32); null for other instruction sets.</summary>
    internal static ICallSites? Sites(NativeCodeIndex index)
    {
        ICallSites? sites = CallAnalysis.Supports(index) ? new X86Sites(CallAnalysis.For(index)) : Arm64CallSites.Supports(index) ? Arm64CallSites.For(index)
            : Arm32CallSites.Supports(index) ? Arm32CallSites.For(index) : null;
        return sites == null ? null : new NamedSites(index, sites);
    }

    // Every reader of the call sites gets the slot targets metadata names.
    private sealed class NamedSites(NativeCodeIndex index, ICallSites inner) : ICallSites
    {
        public CallSiteInfo? CallAt(uint rva, CancellationToken ct = default) => inner.CallAt(rva, ct) is { } s ? SlotCallNames.Resolve(index, s, ct) : null;
        public IReadOnlyList<CallSiteInfo> CallsIn(NativeFunction f, CancellationToken ct = default) => SlotCallNames.Resolve(index, inner.CallsIn(f, ct), ct);
        public IEnumerable<CallSiteInfo> CallsTo(NativeImport import, int max, CancellationToken ct = default) => inner.CallsTo(import, max, ct);
        public CallSiteInfo? Retyped(CallSiteInfo site, ApiSignature signature, CancellationToken ct = default) => inner.Retyped(site, signature, ct);
    }

    private sealed class X86Sites(CallAnalysis analysis) : ICallSites
    {
        public CallSiteInfo? CallAt(uint rva, CancellationToken ct = default) => analysis.CallAt(rva, ct);
        public IReadOnlyList<CallSiteInfo> CallsIn(NativeFunction f, CancellationToken ct = default) => analysis.CallsIn(f, ct);
        public IEnumerable<CallSiteInfo> CallsTo(NativeImport import, int max, CancellationToken ct = default) => analysis.CallsTo(import, max, ct);
        public CallSiteInfo? Retyped(CallSiteInfo site, ApiSignature signature, CancellationToken ct = default) => analysis.Retyped(site, signature, ct);
    }

    /// <summary>The signature of the engine's typed function at <paramref name="start"/>; null when the record has none. Throws when the record cannot be read.</summary>
    private static ApiSignature? EnginePrototype(INativeDecompilerSession session, NativeCodeIndex index, uint start, CancellationToken ct)
    {
        var record = session.GetFunctionRecordAsync(start, ct).GetAwaiter().GetResult();
        return record.Start == start ? EngineSignatures.From(record, index.Image.Arch) : null;
    }

    /// <summary>
    /// Lists the call sites as text. <paramref name="prototype"/> gives the
    /// engine's signature for a function start; calls to a function without a
    /// built-in signature are decoded under it; otherwise they keep the slots
    /// set before the call.
    /// </summary>
    internal static string Report(NativeCodeIndex index, string? address, string? callee, int offset, int limit, CancellationToken ct,
        Func<uint, ApiSignature?>? prototype = null)
    {
        var analysis = Sites(index)!;
        var notes = new List<string>();
        List<CallSiteInfo> sites;
        string scope;
        const int maxSites = 20_000;
        if (!string.IsNullOrWhiteSpace(address))
        {
            var rva = NativeCodeTools.Address(index, address);
            var fn = index.FunctionAt(rva) ?? throw new ToolError(ErrorCode.NotFound, $"No function contains {NativeAddress.Va(index.Image, rva)}.",
                "list_functions shows the functions");
            if (analysis.CallAt(rva, ct) is { } one)
            {
                sites = [one];
                scope = $"call at {NativeAddress.Va(index.Image, rva)} in {fn.Name}";
            }
            else
            {
                sites = [.. analysis.CallsIn(fn, ct)];
                scope = $"calls in {fn.Name} at {NativeAddress.Va(index.Image, fn.Start)}";
            }
            if (!string.IsNullOrWhiteSpace(callee))
            {
                callee = ResolveCallee(index, callee, out var fnStart, byAddress: true);
                sites = sites.Where(s => fnStart is { } t ? s.Target == t : CalleeMatches(s, callee)).ToList();
                scope += $" to {callee}";
            }
        }
        else
        {
            callee = ResolveCallee(index, callee!, out _);
            // Mach-O symbols carry the C underscore: dlsym is _dlsym.
            if (index.Image.Format == ImageFormat.MachO && !callee!.Trim().StartsWith('_') && !callee.Contains('!') && !KnownCallee(index, callee.Trim())
                && KnownCallee(index, "_" + callee.Trim()))
                callee = "_" + callee.Trim();
            sites = CallsTo(index, analysis, callee!.Trim(), maxSites, ct);
            scope = $"calls to {callee.Trim()}";
            if (sites.Count == 0 && !KnownCallee(index, callee.Trim()))
                throw new ToolError(ErrorCode.NotFound, $"No import or function named '{callee.Trim()}'.", "list_imports and list_functions show the names");
            if (sites.Count >= maxSites) notes.Add($"stopped at {maxSites} call sites");
        }
        int max = Math.Clamp(limit, 1, 1000);
        int start = Math.Clamp(offset, 0, sites.Count);
        var typed = new Dictionary<uint, ApiSignature?>();
        var failed = new HashSet<uint>();
        int unknown = 0, unavailable = 0, noSession = 0;
        CallSiteInfo Prototyped(CallSiteInfo s)
        {
            if (!s.Guessed || s.Target is not { } target || s.Kind != CalleeKind.Function) return s;
            if (prototype == null) { noSession++; return s; }
            if (!typed.TryGetValue(target, out var sig))
            {
                try { typed[target] = sig = prototype(target); }
                catch (Exception e) when (e is not OperationCanceledException || !ct.IsCancellationRequested)
                {
                    typed[target] = null;
                    failed.Add(target);
                }
            }
            if (failed.Contains(target)) { unavailable++; return s; }
            if (sig == null) { unknown++; return s; }
            return analysis.Retyped(s, sig, ct) ?? s;
        }
        var page = sites.Skip(start).Take(max).Select(Prototyped).Select(s => (Record: Record(index, s), s.Display)).ToList();
        if (noSession > 0) notes.Add($"{noSession} call(s) to functions without a built-in signature show the slots set before the call; no engine session is open");
        if (unavailable > 0) notes.Add($"{unavailable} call(s) to functions whose engine record could not be read show the slots set before the call");
        if (unknown > 0) notes.Add($"{unknown} call(s) to functions without an engine prototype show the slots set before the call");
        if (index.Truncations.Count > 0) notes.AddRange(index.Truncations);
        var image = Path.GetFileName(index.Image.Path);
        var header = $"{image}: {scope}\n" + string.Concat(notes.Select(n => $"Note: {n}\n"));
        return ToolOutput.List(page, start, max, sites.Count, r => $"{r.Record.Address}  {r.Record.Function}  {Format.EscapeMarkers(r.Display)}  [{r.Record.CalleeKind}" +
                                                                    (r.Record.TailCall ? ", tail" : "") + (r.Record.SignatureKnown ? "" : ", no signature") + "]",
            rows => new CallArgumentsReport(image, scope, rows.Select(r => r.Record).ToList(), start, sites.Count, notes), "call site", header);
    }

    /// <summary>
    /// Returns the callee as a name: a known name is kept, a 0x-prefixed
    /// address becomes the name of the function starting there, with its start
    /// in <paramref name="start"/>. An address outside the image is kept as
    /// text. Rejects an address inside a function; unless
    /// <paramref name="byAddress"/> is set, also a name shared by functions.
    /// </summary>
    internal static string ResolveCallee(NativeCodeIndex index, string callee, out uint? start, bool byAddress = false)
    {
        start = null;
        var text = callee.Trim();
        if (KnownCallee(index, text) || !text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) || NativeAddress.Number(text) is null) return text;
        uint rva;
        try { rva = NativeCodeTools.Address(index, text); }
        catch (ToolError) { return text; }
        var fn = index.FunctionByStart(rva) ?? throw new ToolError(ErrorCode.InvalidArgument,
            $"{NativeAddress.Va(index.Image, rva)} is not the start of a function.",
            "list_functions shows the function starts");
        if (!byAddress && index.Functions.Count(f => f.Name.Equals(fn.Name, StringComparison.OrdinalIgnoreCase)) > 1)
            throw new ToolError(ErrorCode.InvalidArgument, $"Several functions are named '{fn.Name}'; {text} cannot select one.",
                "rename one of them, or pass address with callee");
        start = fn.Start;
        return fn.Name;
    }

    private static bool KnownCallee(NativeCodeIndex index, string callee) =>
        index.Image.Imports.Any(i => ImportMatches(i, callee)) || index.Functions.Any(f => f.Name.Equals(callee, StringComparison.OrdinalIgnoreCase));

    private static bool ImportMatches(NativeImport imp, string callee) =>
        callee.Contains('!')
            ? NativeCodeIndex.ImportName(imp).Equals(callee, StringComparison.OrdinalIgnoreCase)
              || $"{imp.Module}!{imp.Name}".Equals(callee, StringComparison.OrdinalIgnoreCase)
            : string.Equals(imp.Name, callee, StringComparison.OrdinalIgnoreCase);

    private static bool CalleeMatches(CallSiteInfo s, string callee)
    {
        callee = callee.Trim();
        if (s.Callee.Equals(callee, StringComparison.OrdinalIgnoreCase) || s.ShortCallee.Equals(callee, StringComparison.OrdinalIgnoreCase)) return true;
        return s.Import != null && ImportMatches(s.Import, callee);
    }

    /// <summary>Calls to imports and functions named <paramref name="callee"/>.</summary>
    internal static List<CallSiteInfo> CallsTo(NativeCodeIndex index, ICallSites analysis, string callee, int max, CancellationToken ct)
    {
        var result = new Dictionary<uint, CallSiteInfo>();
        foreach (var imp in index.Image.Imports.Where(i => ImportMatches(i, callee)))
            foreach (var s in analysis.CallsTo(imp, max, ct))
                if (result.Count < max) result.TryAdd(s.Rva, s);
        foreach (var f in index.Functions.Where(f => f.Name.Equals(callee, StringComparison.OrdinalIgnoreCase) && f.ThunkImport == null))
            foreach (var c in index.Callers(f))
            {
                if (result.Count >= max) break;
                ct.ThrowIfCancellationRequested();
                if (analysis.CallAt(c.From, ct) is { } s) result.TryAdd(s.Rva, s);
            }
        return result.Values.OrderBy(s => s.Rva).ToList();
    }

    private static CallSiteRecord Record(NativeCodeIndex index, CallSiteInfo s)
    {
        string Va(uint rva) => NativeAddress.Va(index.Image, rva);
        var kind = s.Kind switch { CalleeKind.VirtualExact => "virtual_exact", CalleeKind.VirtualPossible => "virtual_possible", _ => s.Kind.ToString().ToLowerInvariant() };
        return new CallSiteRecord(Va(s.Rva), Format.Within(s.Caller.Name, s.Caller.Start, s.Rva), s.Callee, kind, s.TailCall,
            !s.Guessed,
            s.Arguments.Select(a => new CallArgumentRecord(a.Index, a.Name, a.Type, a.Location, a.Kind.ToString().ToLowerInvariant(), a.Text,
                a.Value is { } v ? $"0x{v:X}" : null, a.Rva is { } r ? Va(r) : null, a.Derivation)).ToList());
    }

    private const int MaxAnalyzedRows = 3000;

    /// <summary>find_xrefs rows for an import: calls through its slot, thunks and (x86) registers loaded from it, with arguments.</summary>
    internal static List<string> ImportRows(NativeCodeIndex index, NativeImport import, Func<uint, string> where, CancellationToken ct)
    {
        string Va(uint r) => NativeAddress.Va(index.Image, r);
        var callers = index.Callers(import);
        if (Sites(index) is not { } analysis)
            return callers.Select(c => $"{Va(c.From)}  {c.Kind,-10} {where(c.From)}").ToList();
        var sites = analysis.CallsTo(import, MaxAnalyzedRows, ct).ToDictionary(s => s.Rva);
        var rows = new List<(uint From, string Text)>();
        foreach (var c in callers)
            rows.Add((c.From, $"{Va(c.From)}  {c.Kind,-10} {where(c.From)}" + (sites.TryGetValue(c.From, out var s) ? "  " + s.Display : "")));
        foreach (var s in sites.Values)
            if (!callers.Any(c => c.From == s.Rva)) rows.Add((s.Rva, $"{Va(s.Rva)}  {"CallReg",-10} {where(s.Rva)}  {s.Display}"));
        return rows.OrderBy(r => r.From).Select(r => r.Text).ToList();
    }

    /// <summary>Rows "address  kind  where"; only the page's calls (at most <see cref="MaxAnalyzedRows"/>) get arguments, as each costs an analysis.</summary>
    internal static List<string> WithArguments(NativeCodeIndex index, IEnumerable<(uint From, string Kind, bool IsCall)> refs, Func<uint, string> where, CancellationToken ct,
        int first = 0, int count = MaxAnalyzedRows)
    {
        var analysis = Sites(index);
        int analyzed = 0;
        var rows = new List<string>();
        foreach (var (from, kind, isCall) in refs)
        {
            var text = $"{NativeAddress.Va(index.Image, from)}  {kind,-10} {where(from)}";
            if (isCall && analysis != null && rows.Count >= first && rows.Count - first < count && analyzed++ < MaxAnalyzedRows && analysis.CallAt(from, ct) is { } s && (s.Arguments.Count > 0 || !s.Guessed))
                text += "  " + s.Display;
            rows.Add(text);
        }
        return rows;
    }

    private static string Where(NativeCodeIndex index, uint rva) =>
        index.FunctionAt(rva) is { } f ? Format.Within(f.Name, f.Start, rva) : NativeAddress.Va(index.Image, rva);

    /// <summary>get_pe_info view=code: late-bound imports and modules loaded by name at run time.</summary>
    internal static string DynamicSection(NativeCodeIndex index, CancellationToken ct)
    {
        if (!CallAnalysis.Supports(index)) return "";
        var set = CallAnalysis.For(index).DynamicImports(ct);
        if (set.GetProcAddressSites == 0 && set.Modules.Count == 0) return "Dynamic imports: none (no GetProcAddress / LoadLibrary / GetModuleHandle calls with constant names)\n";
        var sb = new System.Text.StringBuilder();
        int moduleCount = set.Imports.Select(i => i.Module?.ToLowerInvariant()).Distinct().Count(m => m != null);
        sb.AppendLine($"Dynamic imports (GetProcAddress): {set.Imports.Count} resolved from {moduleCount} modules, {set.UnresolvedSites} of {set.GetProcAddressSites} " +
                      "calls with a name not recovered (list_imports includeDynamic=true lists them)");
        foreach (var d in set.Imports.Take(40))
            sb.AppendLine($"  {d.FullName}  [{d.Confidence}] at {Where(index, d.CallSite)}" +
                          (d.PointerGlobal is { } g ? $", pointer {NativeAddress.Va(index.Image, g)} ({d.PointerCalls.Count} calls)" : "") + $"; {d.How}");
        if (set.Imports.Count > 40) sb.AppendLine($"  ... {set.Imports.Count - 40} more");
        if (set.Modules.Count > 0)
            sb.AppendLine("Modules loaded or looked up by name: " + string.Join(", ", set.Modules.Select(m => m.Module).Distinct(StringComparer.OrdinalIgnoreCase).Take(40)));
        foreach (var n in set.Notes.Take(10)) sb.AppendLine("Note: " + n);
        return sb.ToString();
    }

    /// <summary>list_imports rows for late-bound imports, marked [dynamic].</summary>
    internal static List<string> DynamicImportRows(NativeCodeIndex index, string? module, string? filter, CancellationToken ct)
    {
        var rows = new List<string>();
        if (!CallAnalysis.Supports(index)) return rows;
        var set = CallAnalysis.For(index).DynamicImports(ct);
        foreach (var d in set.Imports)
        {
            if (module != null && (d.Module == null || !Path.GetFileNameWithoutExtension(d.Module).Equals(Path.GetFileNameWithoutExtension(module.Trim()), StringComparison.OrdinalIgnoreCase))) continue;
            if (filter != null && !d.Name.Contains(filter, StringComparison.OrdinalIgnoreCase)) continue;
            rows.Add($"{NativeAddress.Va(index.Image, d.PointerGlobal ?? d.CallSite)}  {d.Module ?? "?"}!{d.Name}  [dynamic: GetProcAddress at {Where(index, d.CallSite)}" +
                     (d.PointerGlobal != null ? $", pointer with {d.PointerCalls.Count} calls" : "") + $"; {d.Confidence}; {d.How}]");
        }
        return rows;
    }

    /// <summary>"late-bound pointer to kernel32!X" for a pointer global a GetProcAddress result is stored to, else null.</summary>
    internal static string? PointerName(NativeCodeIndex index, uint rva, CancellationToken ct) =>
        CallAnalysis.Supports(index) && CallAnalysis.For(index).DynamicImports(ct).ByGlobal.GetValueOrDefault(rva) is { } d
            ? $"late-bound pointer to {d.FullName}" : null;

    /// <summary>find_xrefs rows for a late-bound import named by <paramref name="address"/> ("module!name" or "name"); null when none matches.</summary>
    internal static List<string>? DynamicXrefRows(NativeCodeIndex index, string address, CancellationToken ct)
    {
        if (!CallAnalysis.Supports(index) || string.IsNullOrWhiteSpace(address) || NativeAddress.Number(address.Trim()) != null) return null;
        var analysis = CallAnalysis.For(index);
        var matches = analysis.DynamicImports(ct).Find(address);
        if (matches.Count == 0) return null;
        var rows = new List<string>();
        foreach (var d in matches)
        {
            rows.Add($"{NativeAddress.Va(index.Image, d.CallSite)}  {"Resolve",-10} {Where(index, d.CallSite)}  GetProcAddress -> {d.FullName} [{d.Confidence}]");
            foreach (var call in d.PointerCalls)
                rows.Add($"{NativeAddress.Va(index.Image, call)}  {"DynCall",-10} {Where(index, call)}" +
                         (analysis.CallAt(call, ct) is { } s ? "  " + s.Display : ""));
        }
        return rows;
    }

    /// <summary>Adds the late-bound imports each function of a callee tree calls through pointer globals; returns the added leaves.</summary>
    internal static HashSet<CallTreeNode> AddDynamicCallees(NativeCodeIndex index, CallTreeNode root, CancellationToken ct)
    {
        var added = new HashSet<CallTreeNode>();
        if (!CallAnalysis.Supports(index)) return added;
        var set = CallAnalysis.For(index).DynamicImports(ct);
        if (set.CallsByFunction.Count == 0) return added;
        var stack = new Stack<CallTreeNode>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var node = stack.Pop();
            foreach (var child in node.Children) stack.Push(child);
            if (node.Function == null || node.Repeated || (node.Truncated && node.Children.Count == 0)) continue;
            if (!set.CallsByFunction.TryGetValue(node.Function.Start, out var calls)) continue;
            foreach (var (site, d) in calls.DistinctBy(c => c.Import.FullName))
            {
                var leaf = new CallTreeNode { Function = null, Import = new NativeImport(d.Module ?? "?", d.Name, null, 0, d.PointerGlobal ?? 0, false), Address = site };
                node.Children.Add(leaf);
                added.Add(leaf);
            }
        }
        return added;
    }

    /// <summary>Call comments for a function's disassembly: call RVA -> "CreateFileW(...)"; empty when the analysis fails.</summary>
    internal static IReadOnlyDictionary<uint, string> CallComments(NativeCodeIndex index, NativeFunction fn, CancellationToken ct)
    {
        if (Sites(index) is not { } analysis) return new Dictionary<uint, string>();
        return analysis.CallsIn(fn, ct).Where(s => s.Arguments.Count > 0 || !s.Guessed).ToDictionary(s => s.Rva, s => s.Display);
    }
}
