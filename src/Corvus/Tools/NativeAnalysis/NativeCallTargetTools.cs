using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Calls;
using Corvus.Native.Providers;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>Targets of native call sites, the indirect ones included, with how each was found.</summary>
[McpServerToolType]
public sealed class NativeCallTargetTools(AssemblyWorkspace workspace, NativeCodeService code, NativeEngineService? engines = null)
{
    [Description("One target of a call site.")]
    public sealed record CallTargetRecord(
        [property: Description("Target VA (imports: the import slot; late-bound imports: the pointer global).")] string Address,
        string Name,
        [property: Description("direct_branch, import_slot, thunk_import, constant_pointer, getprocaddress, rtti_vftable_exact, rtti_vftable_possible, " +
                               "global_writers, initial_contents, pointer_table, caller_argument, interface_dispatch_cell, ida_xref, hexrays_direct, ghidra_xref, ghidra_direct.")] string Basis,
        [property: Description("exact, possible, or candidate (incomplete set, or another engine's view only).")] string Confidence,
        string Evidence);

    [Description("One call or tail-jump site.")]
    public sealed record CallTargetSiteRecord(
        [property: Description("VA of the instruction.")] string Address,
        [property: Description("Function and offset.")] string Function,
        [property: Description("The instruction.")] string Text,
        [property: Description("direct, import_slot, thunk, register, memory_pointer, vftable_slot, cfg_dispatch, tail_jump, pointer_table or interface_dispatch.")] string Mechanism,
        [property: Description("direct, import, resolved (complete set), possible (several or unproven), virtual_exact, virtual_possible, " +
                               "ambiguous (engines disagree), unresolved.")] string Status,
        [property: Description("Distinct targets (all of them; at most 64 listed).")] int TargetCount,
        IReadOnlyList<CallTargetRecord> Targets,
        [property: Description("Why unresolved, or why the set may be incomplete.")] string? Reason,
        [property: Description("The call that traces the target's value.")] string? Hint);

    public sealed record CallTargetsReport(
        [property: Description("Image id.")] string Image,
        [property: Description("site, function or image.")] string Scope,
        [property: Description("Engines whose views are merged: ours, ours+ida or ours+ghidra.")] string Engine,
        [property: Description("Sites matching the filter.")] int Total,
        [property: Description("Sites per status, before the filter.")] IReadOnlyDictionary<string, int> ByStatus,
        [property: Description("Sites per mechanism, before the filter.")] IReadOnlyDictionary<string, int> ByMechanism,
        [property: Description("Image scope: the functions with the most unresolved sites.")] IReadOnlyList<string> TopUnresolved,
        [property: Description("Index of the first returned site.")] int Offset,
        [property: Description("More sites follow.")] bool Truncated,
        IReadOnlyList<CallTargetSiteRecord> Items,
        IReadOnlyList<string> Notes);

    [McpServerTool(Name = "resolve_call_targets", Title = "Native call targets", UseStructuredContent = true, OutputSchemaType = typeof(CallTargetsReport))]
    [Description("Targets of call and tail-jump sites in native code (x86 / x64 / ARM) with basis and confidence: branches, import and GOT slots, " +
                 "thunks, constant pointers (also CFG dispatch), GetProcAddress, RTTI virtual calls, NativeAOT dispatch cells, global writers, " +
                 "pointer tables. Unresolved: reason, trace_native_values call. engine= merges its targets.")]
    public Task<string> ResolveCallTargets(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("A call, or an address in a function (its sites): " + NativeTools.AddressDescription)] string? address = null,
        [Description("site, function or image (all indirect sites); default: site at a call, else function.")] string? scope = null,
        [Description("Default all; indirect: all but direct branches.")] string? status = null,
        [Description("Trace pointers that arrive as parameters back into the callers (slower).")] bool deep = false,
        [Description(NativeCodeTools.EngineDescription)] string? engine = null,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description("Max sites (default 75, max 1000).")] int limit = 75,
        [Description(NativeTools.EngineTimeoutDescription)] int? timeoutSeconds = null,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        using var engineLimit = EngineRequestLimit.Use(NativeTools.EngineTimeout(timeoutSeconds));
        var filter = (status?.Trim().ToLowerInvariant()) switch
        {
            null or "" or "all" => "all",
            "resolved" or "possible" or "ambiguous" or "unresolved" or "indirect" => status.Trim().ToLowerInvariant(),
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown status '{status}'.", "use all, resolved, possible, ambiguous, unresolved or indirect"),
        };
        var wantedScope = (scope?.Trim().ToLowerInvariant()) switch
        {
            null or "" => null,
            "site" or "function" or "image" => scope.Trim().ToLowerInvariant(),
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown scope '{scope}'.", "use site, function or image"),
        };
        var mode = (EngineModes.Resolve(engine, engines?.DefaultMode ?? EngineMode.Auto), !string.IsNullOrWhiteSpace(engine));
        var (native, index) = await NativeTraceTools.OpenIndex(workspace, code, image, progress, cancellationToken);
        var choice = NativeEngineCode.Choose(mode.Item1, mode.Item2, engines, native, index);
        var arm = Arm64Trace.Supports(index) ? Arm64Trace.For(index) : null;
        var arm32 = Arm32Trace.Supports(index) ? Arm32Trace.For(index) : null;
        var analysis = arm == null && arm32 == null ? CallAnalysis.For(index) : null;
        List<CallTargetSite> Image() => arm != null ? Arm64CallTargets.Image(arm, deep, cancellationToken) : arm32 != null ? Arm32CallTargets.Image(arm32, deep, cancellationToken)
            : CallTargets.Image(analysis!, deep, cancellationToken);
        string Va(uint r) => NativeAddress.Va(index.Image, r);

        var (sites, scopeText) = await Task.Run(() =>
        {
            if (string.IsNullOrWhiteSpace(address))
            {
                if (wantedScope is "site" or "function") throw new ToolError(ErrorCode.InvalidArgument, $"scope={wantedScope} needs address.");
                return (Image(), "image (indirect sites)");
            }
            var rva = NativeCodeTools.Address(index, address);
            var fn = index.FunctionAt(rva) ?? throw new ToolError(ErrorCode.NotFound, $"No function contains {Va(rva)}.", "list_functions shows the functions");
            var one = wantedScope is null or "site" ? arm != null ? Arm64CallTargets.At(arm, rva, deep, cancellationToken)
                : arm32 != null ? Arm32CallTargets.At(arm32, rva, deep, cancellationToken) : CallTargets.At(analysis!, rva, deep, cancellationToken) : null;
            if (wantedScope == "site" && one == null)
                throw new ToolError(ErrorCode.InvalidArgument, $"{Va(rva)} is not a call or tail jump.", "scope=function lists the sites of its function");
            if (wantedScope == "image") return (Image(), "image (indirect sites)");
            return one != null ? ([one], $"site {Va(rva)}")
                : (arm != null ? Arm64CallTargets.In(arm, fn, deep, cancellationToken) : arm32 != null ? Arm32CallTargets.In(arm32, fn, deep, cancellationToken)
                    : CallTargets.In(analysis!, fn, deep, cancellationToken), $"function {fn.Name}");
        }, cancellationToken);

        var notes = new List<string>();
        int start = Math.Clamp(offset, 0, int.MaxValue);
        var filtered = sites.Where(s => Matches(s, filter)).ToList();
        start = Math.Min(start, filtered.Count);
        var page = filtered.Skip(start).Take(Math.Clamp(limit, 1, 1000)).ToList();
        string engineText = "ours";
        if (choice.External && page.Count > 0)
        {
            var session = await engines!.Session(native, choice.Engine, new Progress<NativeProviderProgress>(p =>
                progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
            var functions = page.Select(s => s.Function.Start).Distinct().ToList();
            var rows = await session.GetCallTargetsAsync(functions, page.Select(s => s.Rva).ToList(), timeoutSeconds ?? 120, cancellationToken);
            page = page.Select(s => Merge(index, s, rows.Targets.Where(t => t.Site == s.Rva).ToList(), choice.Engine)).ToList();
            engineText = "ours+" + choice.Engine;
            var display = NativeEngineService.DisplayName(choice.Engine);
            if (!rows.DecompilerAvailable) notes.Add($"the {display} decompiler is not available: only {display}'s code references are merged");
            if (rows.Failed.Count > 0) notes.Add($"{display} could not decompile {rows.Failed.Count} functions");
            if (rows.Skipped > 0) notes.Add($"{display} had no time for {rows.Skipped} functions" +
                (rows.Partial != null ? $" (PARTIAL: {NativeCodeTools.PartialReason(rows.Partial)}; call again with a larger timeoutSeconds, or a smaller limit)" : ""));
        }
        notes.Add(choice.Line);
        if (start + page.Count < filtered.Count) notes.Add($"{filtered.Count - start - page.Count} more: offset={start + page.Count}");
        notes.AddRange(index.Truncations);

        var byStatus = sites.GroupBy(s => s.Status).OrderBy(g => g.Key).ToDictionary(g => g.Key, g => g.Count());
        var byMechanism = sites.GroupBy(s => s.Mechanism).OrderBy(g => g.Key).ToDictionary(g => g.Key, g => g.Count());
        var top = scopeText.StartsWith("image", StringComparison.Ordinal)
            ? sites.Where(s => s.Status == "unresolved").GroupBy(s => s.Function).OrderByDescending(g => g.Count()).ThenBy(g => g.Key.Start).Take(10)
                .Select(g => $"{g.Key.Name} ({g.Count()})").ToList()
            : [];
        var items = page.Select(s => new CallTargetSiteRecord(Va(s.Rva), $"{s.Function.Name}+0x{s.Rva - s.Function.Start:X}", s.Text, s.Mechanism, s.Status, s.TargetCount,
            s.Targets.Select(t => new CallTargetRecord(Va(t.Address), t.Name, t.Basis, t.Confidence, t.Evidence)).ToList(), s.Reason, s.Hint)).ToList();
        var report = new CallTargetsReport(native.Id, scopeText, engineText, filtered.Count, byStatus, byMechanism, top, start, start + page.Count < filtered.Count, items, notes);
        return ToolOutput.With(Text(report), report);
    });

    private static bool Matches(CallTargetSite s, string filter) => filter switch
    {
        "resolved" => s.Status is "direct" or "import" or "resolved" or "virtual_exact",
        "possible" => s.Status is "possible" or "virtual_possible",
        "ambiguous" => s.Status == "ambiguous",
        "unresolved" => s.Status == "unresolved",
        "indirect" => s.IsIndirect,
        _ => true,
    };

    /// <summary>Adds an engine's view of a site: targets ours lacks are candidates; disjoint target sets make the site ambiguous.</summary>
    internal static CallTargetSite Merge(Native.Code.NativeCodeIndex index, CallTargetSite s, IReadOnlyList<NativeCallTarget> rows, string engine = "ida")
    {
        bool ida = engine == "ida";
        var display = NativeEngineService.DisplayName(engine);
        var decompiler = ida ? "Hex-Rays" : display + "'s decompiler";
        if (rows.Count == 0) return s;
        var ours = s.Targets.Select(t => t.Address).ToHashSet();
        var added = new List<CallTarget>();
        var notes = new List<string>();
        foreach (var r in rows)
        {
            if (r.Kind is "xref" or "direct" && r.Target is { } t)
            {
                if (!ours.Contains(t) && added.All(a => a.Address != t))
                    added.Add(new CallTarget(t, index.NameAt(t) ?? $"sub_{t:X}", r.Kind == "xref" ? engine + "_xref" : ida ? "hexrays_direct" : engine + "_direct", "candidate",
                        r.Kind == "xref" ? display + " code reference" : decompiler + " resolved the call"));
            }
            else if (r.Kind == "vftable") notes.Add($"{decompiler}: through {r.TypeName}+0x{r.MemberOffset:X}");
        }
        bool idaAgrees = rows.Any(r => r.Target is { } t && ours.Contains(t));
        var status = s.Status;
        if (added.Count > 0 && ours.Count > 0 && !idaAgrees && s.Status is not ("virtual_possible" or "possible")) status = "ambiguous";
        else if (added.Count > 0 && ours.Count == 0) status = "possible";
        var reason = notes.Count > 0 ? string.Join("; ", new[] { s.Reason }.Where(x => x != null).Concat(notes.Distinct())) : s.Reason;
        var targets = s.Targets.Concat(added).ToList();
        return s with { Status = status, Targets = targets.Take(CallTargets.MaxTargets).ToList(), TargetCount = s.TargetCount + added.Count, Reason = reason };
    }

    private static string Text(CallTargetsReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Call targets in {r.Image}, {r.Scope}; engine {r.Engine}");
        sb.AppendLine("By status: " + string.Join(", ", r.ByStatus.Select(kv => $"{kv.Key} {kv.Value}")) +
                      "; by mechanism: " + string.Join(", ", r.ByMechanism.Select(kv => $"{kv.Key} {kv.Value}")));
        if (r.TopUnresolved.Count > 0) sb.AppendLine("Most unresolved: " + string.Join(", ", r.TopUnresolved));
        sb.AppendLine($"{ToolSupport.Plural(r.Total, "site")} (showing {(r.Items.Count == 0 ? 0 : r.Offset + 1)}-{r.Offset + r.Items.Count}):");
        foreach (var s in r.Items)
        {
            sb.Append("  ").Append(s.Address).Append("  ").Append(s.Function).Append("  ").Append(s.Text).Append("  [").Append(s.Mechanism).Append(", ").Append(s.Status).Append(']');
            if (s.Targets.Count > 0)
                sb.Append(" -> ").Append(string.Join(" | ", s.Targets.Take(8).Select(t => $"{t.Name} ({t.Basis}, {t.Confidence})")))
                  .Append(s.TargetCount > 8 ? $" | ... {s.TargetCount - 8} more" : "");
            if (s.Reason != null) sb.Append("; ").Append(s.Reason);
            if (s.Hint != null) sb.Append("; next: ").Append(s.Hint);
            sb.AppendLine();
        }
        foreach (var n in r.Notes) sb.AppendLine("Note: " + n);
        return sb.ToString();
    }
}
