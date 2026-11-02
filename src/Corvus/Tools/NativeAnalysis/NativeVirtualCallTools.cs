using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Msvc;
using Corvus.Native.Providers;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>Virtual call sites of native code resolved through RTTI, and their cross-check against an engine.</summary>
[McpServerToolType]
public sealed class NativeVirtualCallTools(AssemblyWorkspace workspace, NativeCodeService code, NativeEngineService? engines = null, NativeTypePush? types = null, AotNativeNames? aotNames = null)
{
    [Description("One virtual call site.")]
    public sealed record VirtualCallRow(
        [property: Description("VA of the call (or tail jump) instruction.")] string Address,
        [property: Description("The calling function and offset.")] string Function,
        [property: Description("exact (one implementation), possible (several) or unresolved.")] string Status,
        [property: Description("receiver_unknown, no_vftable_at_offset, slot_out_of_range, only_pure_targets, too_many_targets.")] string? Reason,
        [property: Description("this (in a virtual method), vftable (stored into the object or by its constructor), field (a field of this), unknown.")] string Receiver,
        [property: Description("The receiver's class (static type), null when unknown.")] string? Class,
        [property: Description("vftable slot index.")] int Slot,
        [property: Description("vfptr offset in the receiver (the subobject the call goes through).")] int VfptrOffset,
        [property: Description("VA of the receiver class's vftable the slot is read from, null when unknown.")] string? Vftable,
        [property: Description("A jump (tail call) rather than a call.")] bool TailCall,
        [property: Description("A derived class reaches it via a virtual base; its overrides are not included.")] bool Incomplete,
        [property: Description("Distinct implementations found (pure virtual stubs excluded).")] int TargetCount,
        [property: Description("The implementations, \"name @ VA\" (at most 16).")] IReadOnlyList<string> Targets,
        [property: Description("The receiver as this or this->field, null when not read from this.")] string? ReceiverExpression = null);

    public sealed record VirtualCallReport(
        [property: Description("Image id.")] string Image,
        [property: Description("Virtual call sites in the image.")] int Sites,
        [property: Description("Sites with one implementation.")] int Exact,
        [property: Description("Sites with several possible implementations.")] int Possible,
        [property: Description("Sites without targets.")] int Unresolved,
        [property: Description("virtual_exact + virtual_possible edges added to the call graph.")] int Edges,
        [property: Description("Direct call graph edges (calls, tail calls, import calls), for comparison.")] long DirectEdges,
        [property: Description("RTTI classes with vftables.")] int RttiClasses,
        [property: Description("Sites matching the filters.")] int Total,
        [property: Description("Index of the first returned site.")] int Offset,
        [property: Description("More sites follow.")] bool Truncated,
        IReadOnlyList<VirtualCallRow> Items,
        [property: Description("The cross-check against IDA, when asked for.")] VirtualCallCheck.Report? CrossCheck,
        [property: Description("Coverage notes.")] IReadOnlyList<string> Notes);

    [McpServerTool(Name = "find_virtual_calls", Title = "Native virtual calls", UseStructuredContent = true, OutputSchemaType = typeof(VirtualCallReport))]
    [Description("Resolve virtual call sites through RTTI or NativeAOT MethodTables: receiver class, vftable slot and the implementations it " +
                 "can reach (exact, possible or unresolved).")]
    public async Task<string> FindVirtualCalls(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Only sites in this function: " + NativeTools.AddressDescription)] string? function = null,
        [Description("Only sites with this status.")] string? status = null,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description("Max sites (max 1000).")] int limit = 100,
        [Description("Compare a sample with IDA (else Ghidra); minutes on a large image at first.")] bool crossCheck = false,
        [Description("Cross-check: functions to sample.")] int sampleFunctions = 100,
        [Description("Cross-check: time budget in seconds.")] int timeoutSeconds = 300,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default)
    {
        var report = await Report(image, function, status, offset, limit, crossCheck, sampleFunctions, timeoutSeconds, context, cancellationToken);
        return ToolOutput.With(Text(report), report);
    }

    /// <summary>The report as text: the counts, one line per site with its targets or reason, the cross-check and notes.</summary>
    internal static string Text(VirtualCallReport r)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"{r.Image}: {r.Sites:N0} virtual call sites ({r.Exact:N0} exact, {r.Possible:N0} possible, {r.Unresolved:N0} unresolved); " +
                      $"{r.Edges:N0} virtual edges beside {r.DirectEdges:N0} direct call edges; {r.RttiClasses:N0} RTTI classes with vftables");
        sb.AppendLine(r.Total == 0 ? "No site matches." : $"{r.Total:N0} matching, {r.Items.Count} from #{r.Offset}:");
        foreach (var s in r.Items)
        {
            var receiver = $"{s.Class ?? "class unknown"} slot {s.Slot}" + (s.VfptrOffset != 0 ? $" (vfptr +0x{s.VfptrOffset:X})" : "") + $", receiver from {s.ReceiverExpression ?? s.Receiver}";
            sb.AppendLine($"  {s.Address}  {s.Function}  {(s.TailCall ? "jump" : "call")}  {s.Status}{(s.Reason != null ? $" ({s.Reason})" : "")}  {receiver}" +
                          (s.Incomplete ? "; overrides through a virtual base not included" : ""));
            foreach (var t in s.Targets) sb.AppendLine($"      -> {t}");
            if (s.TargetCount > s.Targets.Count) sb.AppendLine($"      ... {s.TargetCount - s.Targets.Count} more");
        }
        if (r.CrossCheck is { } c)
            sb.AppendLine($"Cross-check with {c.Engine}: {c.SitesChecked} sites in {c.FunctionsDecompiled} decompiled functions; agree {c.Agree}, compatible {c.Compatible}, " +
                          $"disagree {c.Disagree}, {c.Engine} only {c.IdaOnly}, ours only {c.OursOnly}, neither {c.BothNone}" +
                          (c.AgreementRate is { } rate ? $"; agreement {Corvus.Core.Format.Percent(rate, 1)}" : ""));
        foreach (var n in r.Notes) sb.AppendLine("Note: " + n);
        return sb.ToString();
    }

    /// <summary>The sites inside one function and a note naming the scope.</summary>
    internal static (IReadOnlyList<VirtualCallSite> Sites, string Note) Scope(NativeCodeIndex index, string function)
    {
        var rva = NativeCodeTools.Address(index, function);
        var fn = index.FunctionAt(rva) ?? throw new ToolError(ErrorCode.NotFound, $"No function contains {NativeAddress.Va(index.Image, rva)}.",
            "list_functions shows the functions");
        var sites = index.Ranges(fn).SelectMany(r => index.VirtualCalls.SitesIn(r.Start, r.End)).ToList();
        var total = index.VirtualCalls.Sites.Count;
        var partial = index.VirtualCalls.Stats.FunctionsNotConverged > 0;
        var note = sites.Count == 0
            ? $"function {fn.Name}: no virtual call site {(partial ? "reported (the analysis is partial, so none is unknown)" : "found")}; "
              + $"the totals cover the whole image ({total:N0} sites). Call find_virtual_calls without function to list them"
            : $"function {fn.Name}: {sites.Count:N0} of {total:N0} sites; the totals cover the whole image";
        return (sites, note);
    }

    /// <summary>The scope note of a function with slot calls: both kinds of site, and what the image totals leave out.</summary>
    internal static string SlotScopeNote(string function, int rttiSites, int slotCalls, int imageSites) =>
        $"function {function}: {rttiSites:N0} RTTI sites and {slotCalls:N0} AOT slot calls from metadata; " +
        $"the totals cover the RTTI sites of the whole image ({imageSites:N0}) and leave out slot calls";

    /// <summary>find_virtual_calls' report as fields.</summary>
    internal Task<VirtualCallReport> Report(string image, string? function = null, string? status = null, int offset = 0, int limit = 100, bool crossCheck = false,
        int sampleFunctions = 100, int seconds = 300, RequestContext<CallToolRequestParams> context = null!, CancellationToken cancellationToken = default) =>
        OrderedProgress.Run(context, async progress =>
    {
        var wanted = status?.Trim().ToLowerInvariant() switch
        {
            null or "" => (VirtualCallStatus?)null,
            "exact" => VirtualCallStatus.Exact,
            "possible" => VirtualCallStatus.Possible,
            "unresolved" => VirtualCallStatus.Unresolved,
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown status '{status}'.", "use exact, possible or unresolved"),
        };
        var native = await Task.Run(() =>
        {
            return Targets.Native(workspace, image);
        }, cancellationToken);
        var waited = System.Diagnostics.Stopwatch.StartNew();
        var index = await code.Index(native, new Progress<CodeIndexProgress>(p => progress.Report(new ProgressNotificationValue
        {
            Progress = (float)waited.Elapsed.TotalSeconds, Message = $"indexing {native.Id}: {p.Phase}",
        })), cancellationToken);
        if (index.Support != CodeSupport.Full) throw NativeEngineCode.Unsupported(index, engines, "decompile_native reads the code through IDA or Ghidra");

        // Restore first, so slot calls are read on a fresh load as after apply_metadata_names.
        var restoreNotice = aotNames?.Restore(native, cancellationToken);
        var set = index.VirtualCalls;
        IEnumerable<VirtualCallSite> sites = set.Sites;
        string? scopeNote = null;
        var slotCalls = new List<AotSlotNotes.SlotCall>();
        int scopedSites = 0;
        if (!string.IsNullOrWhiteSpace(function))
        {
            var scope = Scope(index, function);
            sites = scope.Sites;
            scopeNote = scope.Note;
            scopedSites = scope.Sites.Count;
            // Slot calls come from the resolver that disassemble uses for its notes.
            var owner = index.FunctionAt(NativeCodeTools.Address(index, function));
            if (owner != null) slotCalls = AotSlotNotes.Calls(native, index, owner, cancellationToken);
            // One note for both kinds of site: the slot calls are not in the image totals.
            if (slotCalls.Count > 0) scopeNote = SlotScopeNote(owner!.Name, scopedSites, slotCalls.Count, set.Sites.Count);
        }
        else if (AotNativeNames.Of(native) != null)
            scopeNote = "AOT slot calls are listed per function: call find_virtual_calls with function=<name>";
        if (wanted is { } w)
        {
            sites = sites.Where(s => s.Status == w);
            slotCalls = [.. slotCalls.Where(c => (c.Method != null ? VirtualCallStatus.Exact : VirtualCallStatus.Unresolved) == w)];
        }
        var list = sites.ToList();
        int total = list.Count + slotCalls.Count;
        if (scopeNote != null && wanted != null) scopeNote += $"; status={status!.Trim().ToLowerInvariant()} keeps {total:N0} of them";

        var rtti = list.Any(s => s.ClassTypeDescriptor != 0) ? native.GetAnalysis(n => Native.Itanium.CppRtti.Analyze(n.Image, cancellationToken)) : null;
        var classNames = rtti?.Classes.GroupBy(c => c.TypeDescriptorRva).ToDictionary(g => g.Key, g => g.First().Name) ?? [];
        var aotTypes = list.Any(s => s.ClassTypeDescriptor == 0 && s.VftableRva != 0) ? NativeAotNames.View(native, cancellationToken)?.Types : null;
        string? ClassOf(VirtualCallSite s) => s.ClassTypeDescriptor != 0 ? classNames.GetValueOrDefault(s.ClassTypeDescriptor)
            : aotTypes?.ByRva.GetValueOrDefault(s.VftableRva)?.Name; // NativeAOT: the MethodTable holds the vtable
        string Va(uint r) => NativeAddress.Va(index.Image, r);
        string Where(uint r) => index.FunctionAt(r) is { } f ? Format.Within(f.Name, f.Start, r) : Va(r);
        int start = Math.Clamp(offset, 0, total);
        VirtualCallRow SlotRow(AotSlotNotes.SlotCall c) => new(Va(c.Rva), Where(c.Rva), c.Method != null ? "exact" : "unresolved",
            c.Method != null ? null : c.Receiver != null ? "slot_out_of_range" : "receiver_unknown",
            c.Expression == "this" ? "this" : c.Expression != null ? "field" : "unknown", c.Receiver?.Name, (int)c.Slot, 0, null, false, false,
            c.Method != null ? 1 : 0, c.Method != null ? [c.Note] : [], c.Expression);
        var page = list.Select(s =>
        {
            var targets = index.VirtualTargets(s.Rva);
            return new VirtualCallRow(Va(s.Rva), Where(s.Rva), VirtualCallSet.StatusCode(s.Status), VirtualCallSet.ReasonCode(s.Reason),
                VirtualCallSet.ReceiverCode(s.Receiver), ClassOf(s), s.Slot,
                s.VfptrOffset, s.VftableRva != 0 ? Va(s.VftableRva) : null, s.TailCall, s.Incomplete, s.TargetCount,
                targets.Take(16).Select(t => $"{index.NameAt(t) ?? $"sub_{t:X}"} @ {Va(t)}").ToList());
        }).Concat(slotCalls.Select(SlotRow)).Skip(start).Take(Math.Clamp(limit, 1, 1000)).ToList();

        var notes = new List<string>(set.Notes);
        if (restoreNotice != null) notes.Add(restoreNotice);
        if (scopeNote != null) notes.Add(scopeNote);
        if (start + page.Count < total) notes.Add($"{total - start - page.Count} more: offset={start + page.Count}");
        // Sites in functions whose data flow did not settle are not reported: the counts are lower bounds.
        if (set.Stats.FunctionsNotConverged > 0)
            ToolOutput.Coverage("partial", $"{set.Stats.FunctionsNotConverged} functions were not analyzed to the end (visit budget); their sites are missing", "indirect-calls");
        notes.AddRange(index.Truncations);
        long direct = 0;
        foreach (var f in index.Functions) direct += index.Callees(f, CallEdgeFilter.Direct).Count;

        VirtualCallCheck.Report? check = null;
        if (crossCheck)
        {
            if (engines == null) throw new ToolError(ErrorCode.ProviderUnavailable, "No native engine is configured.", "install IDA (idalib) or Ghidra to cross-check");
            if (set.Sites.Count == 0)
                notes.Add("cross-check skipped: no virtual call sites");
            else
            {
                var session = await engines.Session(native, null, new Progress<NativeProviderProgress>(p =>
                    progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
                check = await VirtualCallCheck.RunAsync(native, index, session, types, sampleFunctions, seconds,
                    new Progress<string>(m => progress.Report(new ProgressNotificationValue { Progress = (float)waited.Elapsed.TotalSeconds, Message = m })),
                    cancellationToken);
            }
        }
        var st = set.Stats;
        return new VirtualCallReport(native.Id, st.Sites, st.Exact, st.Possible, st.Unresolved, st.Edges, direct, st.RttiClasses, total, start,
            start + page.Count < total, page, check, notes);
    });
}
