using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Calls;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tools;

/// <summary>Call sites of native code with their recovered argument values.</summary>
[McpServerToolType]
public sealed class NativeCallTools(AssemblyWorkspace workspace, NativeCodeService code)
{
    [Description("One argument of a call.")]
    public sealed record CallArgumentRecord(
        [property: Description("0-based position.")] int Index,
        [property: Description("Parameter name from the API signature; null for callees without one.")] string? Name,
        [property: Description("Parameter type (str, int, ptr, an enumeration or flags name...); null without a signature.")] string? Type,
        [property: Description("Where it is passed: rcx, rdi, xmm0, [rsp+20h], [esp+4h], ecx; ARM64 x0-x7, s0-s7 / d0-d7, stack.")] string Location,
        [property: Description("immediate, string, address, name, result (of an earlier call), global (contents of a variable) or unknown.")] string Kind,
        [property: Description("The value as shown in the call: decoded flags, quoted string, name, ? when unknown.")] string Text,
        [property: Description("The number for immediates (hex).")] string? Value,
        [property: Description("The address (VA) for strings, addresses, names and globals.")] string? Address,
        [property: Description("How it was derived: the instructions from the call back to the definition, or why it is unknown.")] string Derivation);

    [Description("One call site.")]
    public sealed record CallSiteRecord(
        [property: Description("VA of the call instruction.")] string Address,
        [property: Description("The calling function.")] string Function,
        [property: Description("Callee: module!name for imports and late-bound imports, a function name, or the pointer for indirect calls.")] string Callee,
        [property: Description("import, function, dynamic (GetProcAddress / dlsym pointer), virtual_exact (a virtual call with one implementation, resolved through RTTI), " +
                               "virtual_possible (one of several implementations, listed in Callee) or indirect.")] string CalleeKind,
        [property: Description("A jump to the callee (tail call) rather than a call.")] bool TailCall,
        [property: Description("The callee's signature is known (parameter names, count and constant decoding); otherwise the arguments are the registers / stack slots set just before the call.")] bool SignatureKnown,
        [property: Description("The call with its arguments, e.g. CreateFileW(L\"config.ini\", GENERIC_READ, ...).")] string Display,
        IReadOnlyList<CallArgumentRecord> Arguments);

    public sealed record CallArgumentsReport(
        [property: Description("Image id.")] string Image,
        [property: Description("What was searched: a call, the calls in a function, or the calls to a callee.")] string Scope,
        [property: Description("Call sites found.")] int Total,
        [property: Description("Index of the first returned call site.")] int Offset,
        IReadOnlyList<CallSiteRecord> Calls,
        [property: Description("Coverage notes: limits reached, what is not analyzed.")] IReadOnlyList<string> Notes);

    private async Task<NativeCodeIndex> Open(string image, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var native = await Task.Run(() =>
        {
            var id = workspace.Read(() => workspace.FindNative(image)?.Id);
            if (id == null && !string.IsNullOrWhiteSpace(image) && Path.IsPathFullyQualified(image.Trim()) && File.Exists(image.Trim()))
                id = workspace.LoadAny(image.Trim()).Native?.Id ?? throw new ToolError(ErrorCode.Unsupported, $"{image} is a .NET assembly, not a native image.",
                    "use the .NET tools for it");
            return workspace.Read(() => workspace.GetNative(id ?? image));
        }, ct);
        var index = await code.Index(native, new Progress<CodeIndexProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = p.Done, Total = p.Total > 0 ? p.Total : null, Message = $"indexing {native.Id}: {p.Phase}" })), ct);
        if (Sites(index) == null)
            throw new ToolError(ErrorCode.Unsupported, $"Call arguments are recovered for x86, x64, ARM64 and ARM32 code, not {index.Image.Arch}.", "decompile_native shows calls through IDA");
        return index;
    }

    [McpServerTool(Name = "get_call_arguments", Title = "Native call arguments", UseStructuredContent = true)]
    [Description("Call sites of a native image (x86 / x64 / ARM) with their argument values, recovered by backward constant propagation in the calling " +
                 "function under the platform conventions (x64 Microsoft on PE, System V on ELF / Mach-O; x86 pushed / stored stack slots; ARM x0-x7 / r0-r3): " +
                 "immediates, strings, named addresses, results of earlier calls, globals; merges of different values are unknown. " +
                 "Known Win32 / CRT / libc APIs give parameter names and decoded constants (GENERIC_READ, printf formats). " +
                 "Pass address (a call instruction, or any address in a function for all its calls) and/or callee (an API or function name: all calls to it).")]
    public Task<CallArgumentsReport> GetCallArguments(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("A call instruction, or an address in a function (all calls in it). " + NativeTools.AddressDescription)] string? address = null,
        [Description("Only calls to this callee: API name (CreateFileW), module!name, or function name; without address, every call to it in the image.")] string? callee = null,
        [Description("Index of the first call site.")] int offset = 0,
        [Description("Max call sites (default 100, max 1000).")] int limit = 100,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        if (string.IsNullOrWhiteSpace(address) && string.IsNullOrWhiteSpace(callee))
            throw new ToolError(ErrorCode.InvalidArgument, "Pass address (a call or a function) or callee (an API or function name).");
        var index = await Open(image, progress, cancellationToken);
        return await Task.Run(() => Report(index, address, callee, offset, limit, cancellationToken), cancellationToken);
    });

    /// <summary>The call sites of an index: the x86 / x64 analysis or the ARM64 one; null for other instruction sets.</summary>
    internal static ICallSites? Sites(NativeCodeIndex index) =>
        CallAnalysis.Supports(index) ? new X86Sites(CallAnalysis.For(index)) : Arm64CallSites.Supports(index) ? Arm64CallSites.For(index)
            : Arm32CallSites.Supports(index) ? Arm32CallSites.For(index) : null;

    private sealed class X86Sites(CallAnalysis analysis) : ICallSites
    {
        public CallSiteInfo? CallAt(uint rva, CancellationToken ct = default) => analysis.CallAt(rva, ct);
        public IReadOnlyList<CallSiteInfo> CallsIn(NativeFunction f, CancellationToken ct = default) => analysis.CallsIn(f, ct);
        public IEnumerable<CallSiteInfo> CallsTo(NativeImport import, int max, CancellationToken ct = default) => analysis.CallsTo(import, max, ct);
    }

    private CallArgumentsReport Report(NativeCodeIndex index, string? address, string? callee, int offset, int limit, CancellationToken ct)
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
                sites = sites.Where(s => CalleeMatches(s, callee)).ToList();
                scope += $" to {callee.Trim()}";
            }
        }
        else
        {
            sites = CallsTo(index, analysis, callee!.Trim(), maxSites, ct);
            scope = $"calls to {callee.Trim()}";
            if (sites.Count == 0 && !KnownCallee(index, callee.Trim()))
                throw new ToolError(ErrorCode.NotFound, $"No import or function named '{callee.Trim()}'.", "list_imports and list_functions show the names");
            if (sites.Count >= maxSites) notes.Add($"stopped at {maxSites} call sites");
        }
        int max = Math.Clamp(limit, 1, 1000);
        int start = Math.Clamp(offset, 0, sites.Count);
        var page = sites.Skip(start).Take(max).Select(s => Record(index, s)).ToList();
        if (start + page.Count < sites.Count) notes.Add($"{sites.Count - start - page.Count} more: offset={start + page.Count}");
        if (index.Truncations.Count > 0) notes.AddRange(index.Truncations);
        return new CallArgumentsReport(Path.GetFileName(index.Image.Path), scope, sites.Count, start, page, notes);
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
        return new CallSiteRecord(Va(s.Rva), $"{s.Caller.Name}+0x{s.Rva - s.Caller.Start:X}", s.Callee, kind, s.TailCall,
            !s.Guessed, s.Display,
            s.Arguments.Select(a => new CallArgumentRecord(a.Index, a.Name, a.Type, a.Location, a.Kind.ToString().ToLowerInvariant(), a.Text,
                a.Value is { } v ? $"0x{v:X}" : null, a.Rva is { } r ? Va(r) : null, a.Derivation)).ToList());
    }

    private const int MaxAnalyzedRows = 3000;

    /// <summary>
    /// find_xrefs rows for an import: calls through its slot and thunks, and (x86) calls through a register loaded from the
    /// slot, each with its arguments.
    /// </summary>
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

    /// <summary>Rows "address  kind  where", with the call's arguments for calls (the first <see cref="MaxAnalyzedRows"/>).</summary>
    internal static List<string> WithArguments(NativeCodeIndex index, IEnumerable<(uint From, string Kind, bool IsCall)> refs, Func<uint, string> where, CancellationToken ct)
    {
        var analysis = Sites(index);
        int analyzed = 0;
        var rows = new List<string>();
        foreach (var (from, kind, isCall) in refs)
        {
            var text = $"{NativeAddress.Va(index.Image, from)}  {kind,-10} {where(from)}";
            if (isCall && analysis != null && analyzed++ < MaxAnalyzedRows && analysis.CallAt(from, ct) is { } s && (s.Arguments.Count > 0 || !s.Guessed))
                text += "  " + s.Display;
            rows.Add(text);
        }
        return rows;
    }

    private static string Where(NativeCodeIndex index, uint rva) =>
        index.FunctionAt(rva) is { } f ? $"{f.Name}+0x{rva - f.Start:X}" : NativeAddress.Va(index.Image, rva);

    /// <summary>The get_pe_info section: late-bound imports and modules loaded by name at run time.</summary>
    internal static string DynamicSection(NativeCodeIndex? index, CancellationToken ct)
    {
        if (index == null) return "Dynamic imports: not computed yet (the code index is still building; list_imports includeDynamic=true waits for it)\n";
        if (!CallAnalysis.Supports(index)) return "";
        var set = CallAnalysis.For(index).DynamicImports(ct);
        if (set.GetProcAddressSites == 0 && set.Modules.Count == 0) return "Dynamic imports: none (no GetProcAddress / LoadLibrary / GetModuleHandle calls with constant names)\n";
        var sb = new System.Text.StringBuilder();
        int moduleCount = set.Imports.Select(i => i.Module?.ToLowerInvariant()).Distinct().Count(m => m != null);
        sb.AppendLine($"Dynamic imports (GetProcAddress): {set.Imports.Count} resolved from {moduleCount} modules, {set.UnresolvedSites} of {set.GetProcAddressSites} " +
                      "calls with a name not recovered (list_imports includeDynamic=true)");
        foreach (var d in set.Imports.Take(40))
            sb.AppendLine($"  {d.FullName}  [{d.Confidence}] at {Where(index, d.CallSite)}" +
                          (d.PointerGlobal is { } g ? $", pointer {NativeAddress.Va(index.Image, g)} ({d.PointerCalls.Count} calls)" : "") + $"; {d.How}");
        if (set.Imports.Count > 40) sb.AppendLine($"  ... {set.Imports.Count - 40} more");
        if (set.Modules.Count > 0)
            sb.AppendLine("Modules loaded or looked up by name: " + string.Join(", ", set.Modules.Select(m => m.Module).Distinct(StringComparer.OrdinalIgnoreCase).Take(40)));
        foreach (var n in set.Notes.Take(10)) sb.AppendLine("  note: " + n);
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
