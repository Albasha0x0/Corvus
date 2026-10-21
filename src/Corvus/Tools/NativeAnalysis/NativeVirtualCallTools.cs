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

/// <summary>Virtual call sites of native code resolved through MSVC RTTI, and their cross-check against IDA.</summary>
[McpServerToolType]
public sealed class NativeVirtualCallTools(AssemblyWorkspace workspace, NativeCodeService code, NativeEngineService? engines = null, NativeTypePush? types = null)
{
    [Description("One virtual call site.")]
    public sealed record VirtualCallRow(
        [property: Description("VA of the call (or tail jump) instruction.")] string Address,
        [property: Description("The calling function and offset.")] string Function,
        [property: Description("exact (one implementation), possible (several) or unresolved.")] string Status,
        [property: Description("receiver_unknown, no_vftable_at_offset, slot_out_of_range, only_pure_targets, too_many_targets.")] string? Reason,
        [property: Description("this (in a virtual method), vftable (stored into the object or by its constructor), unknown.")] string Receiver,
        [property: Description("The receiver's class (static type), null when unknown.")] string? Class,
        [property: Description("vftable slot index.")] int Slot,
        [property: Description("vfptr offset in the receiver (the subobject the call goes through).")] int VfptrOffset,
        [property: Description("VA of the receiver class's vftable the slot is read from, null when unknown.")] string? Vftable,
        [property: Description("A jump (tail call) rather than a call.")] bool TailCall,
        [property: Description("A derived class reaches it via a virtual base; its overrides are not included.")] bool Incomplete,
        [property: Description("Distinct implementations found (pure virtual stubs excluded).")] int TargetCount,
        [property: Description("The implementations, \"name @ VA\" (at most 16).")] IReadOnlyList<string> Targets);

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
    [Description("Virtual call sites resolved through RTTI (MSVC, Itanium) or NativeAOT MethodTables: calls through a vftable slot, also via stack " +
                 "spills, this adjustments, CFG dispatch. Receiver class from a stored vftable, the this of a virtual method or decorated names; " +
                 "targets: the slot implementations (exact, possible, else unresolved).")]
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
            var receiver = $"{s.Class ?? "class unknown"} slot {s.Slot}" + (s.VfptrOffset != 0 ? $" (vfptr +0x{s.VfptrOffset:X})" : "") + $", receiver from {s.Receiver}";
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

        var set = index.VirtualCalls;
        IEnumerable<VirtualCallSite> sites = set.Sites;
        if (!string.IsNullOrWhiteSpace(function))
        {
            var rva = NativeCodeTools.Address(index, function);
            var fn = index.FunctionAt(rva) ?? throw new ToolError(ErrorCode.NotFound, $"No function contains {NativeAddress.Va(index.Image, rva)}.",
                "list_functions shows the functions");
            sites = index.Ranges(fn).SelectMany(r => set.SitesIn(r.Start, r.End));
        }
        if (wanted is { } w) sites = sites.Where(s => s.Status == w);
        var list = sites.ToList();

        var rtti = list.Any(s => s.ClassTypeDescriptor != 0) ? native.GetAnalysis(n => Native.Itanium.CppRtti.Analyze(n.Image, cancellationToken)) : null;
        var classNames = rtti?.Classes.GroupBy(c => c.TypeDescriptorRva).ToDictionary(g => g.Key, g => g.First().Name) ?? [];
        var aotTypes = list.Any(s => s.ClassTypeDescriptor == 0 && s.VftableRva != 0) ? NativeAotNames.View(native, cancellationToken)?.Types : null;
        string? ClassOf(VirtualCallSite s) => s.ClassTypeDescriptor != 0 ? classNames.GetValueOrDefault(s.ClassTypeDescriptor)
            : aotTypes?.ByRva.GetValueOrDefault(s.VftableRva)?.Name; // NativeAOT: the MethodTable holds the vtable
        string Va(uint r) => NativeAddress.Va(index.Image, r);
        string Where(uint r) => index.FunctionAt(r) is { } f ? Format.Within(f.Name, f.Start, r) : Va(r);
        int start = Math.Clamp(offset, 0, list.Count);
        var page = list.Skip(start).Take(Math.Clamp(limit, 1, 1000)).Select(s =>
        {
            var targets = index.VirtualTargets(s.Rva);
            return new VirtualCallRow(Va(s.Rva), Where(s.Rva), VirtualCallSet.StatusCode(s.Status), VirtualCallSet.ReasonCode(s.Reason),
                VirtualCallSet.ReceiverCode(s.Receiver), ClassOf(s), s.Slot,
                s.VfptrOffset, s.VftableRva != 0 ? Va(s.VftableRva) : null, s.TailCall, s.Incomplete, s.TargetCount,
                targets.Take(16).Select(t => $"{index.NameAt(t) ?? $"sub_{t:X}"} @ {Va(t)}").ToList());
        }).ToList();

        var notes = new List<string>(set.Notes);
        if (start + page.Count < list.Count) notes.Add($"{list.Count - start - page.Count} more: offset={start + page.Count}");
        // sites in functions whose data flow did not settle are not reported: the counts are lower bounds
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
        return new VirtualCallReport(native.Id, st.Sites, st.Exact, st.Possible, st.Unresolved, st.Edges, direct, st.RttiClasses, list.Count, start,
            start + page.Count < list.Count, page, check, notes);
    });
}
