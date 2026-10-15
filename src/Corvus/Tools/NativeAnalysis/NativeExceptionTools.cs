using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Msvc;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>A handler, funclet or landing pad of a function's exception metadata.</summary>
public sealed record EhHandler(
    [property: Description("catch, unwind, destructor, filter, except, finally, landing_pad, or chunk kind.")] string Kind,
    string Address,
    [property: Description("The function name at the address, when it has one.")] string? Name,
    [property: Description("catch: the caught type (... for all); landing_pad: the actions.")] string? Detail);

/// <summary>A protected range: an SEH __try scope or an Itanium call site.</summary>
public sealed record EhRange(string Start, string End,
    [property: Description("__except / __finally block or landing pad; absent when it unwinds through.")] string? Handler,
    [property: Description("finally, except (with its filter) or call_site.")] string Kind,
    string? Filter);

/// <summary>get_exception_info's record: one function's handlers and ranges, or the image's counts.</summary>
public sealed record ExceptionReport(string Image,
    [property: Description("The function; absent for the image summary.")] string? Function,
    string? Address,
    [property: Description("msvc or itanium.")] string Format,
    [property: Description("The handler scheme (MSVC) or personality routine (Itanium).")] string? Scheme,
    [property: Description("The function this funclet or fragment belongs to.")] string? Parent,
    IReadOnlyList<EhHandler> Handlers, IReadOnlyList<EhRange> Ranges,
    [property: Description("Image summary: frames, FDEs and the like by kind.")] IReadOnlyDictionary<string, int>? Counts);

/// <summary>MSVC exception handling metadata of native functions (x86 / x64).</summary>
[McpServerToolType]
public sealed class NativeExceptionTools(AssemblyWorkspace workspace, NativeCodeService code, OutputPager pager)
{
    private const int MaxIpStates = 64;

    [McpServerTool(Name = "get_exception_info", Title = "Native exception handling", UseStructuredContent = true, OutputSchemaType = typeof(ExceptionReport))]
    [Description("Exception handling of the native function at an address. ELF / Mach-O: FDE, compact unwind or EHABI entry, personality, LSDA " +
                 "call sites, landing pads, caught types. MSVC: handler, try blocks, caught types, unwind map, SEH scopes, IP-to-state, catch " +
                 "blocks, funclets, filters, chained fragments. No address: image counts, failed metadata checks.")]
    public Task<string> GetExceptionInfo(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription + " Omit for an image summary.")] string? address = null,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, index) = await Open(image, progress, cancellationToken);
        if (index.Image.Format != ImageFormat.Pe)
        {
            var (itext, irecord) = Itanium(native.Id, index, address);
            return ToolOutput.Report(pager.Page(itext, offset, maxTokens), irecord);
        }
        var eh = index.ExceptionInfo;
        if (string.IsNullOrWhiteSpace(address))
        {
            var s = eh.Stats;
            return ToolOutput.Report(pager.Page(Summary(native.Id, index, eh), offset, maxTokens), new ExceptionReport(native.Id, null, null, "msvc", null, null, [], [],
                new Dictionary<string, int>
                {
                    ["frames"] = s.Frames, ["cxx3"] = s.Cxx3, ["cxx4"] = s.Cxx4, ["cSpecific"] = s.CSpecific, ["seh4"] = s.Seh4, ["seh3"] = s.Seh3,
                    ["gsOnly"] = s.GsOnly, ["unknown"] = s.Unknown, ["children"] = s.Children, ["fragments"] = s.Fragments, ["rejected"] = eh.RejectCount,
                }));
        }

        uint rva = NativeCodeTools.Address(index, address);
        var fn = index.FunctionAt(rva) ?? throw new ToolError(ErrorCode.NotFound, $"No function contains {NativeAddress.Va(index.Image, rva)}.",
            "list_functions shows the functions");
        var sb = new StringBuilder();
        string Name(uint r) => index.NameAt(r) is { } n ? $"{n} ({NativeAddress.Va(index.Image, r)})" : NativeAddress.Va(index.Image, r);
        sb.AppendLine($"{fn.Name} at {NativeAddress.Va(index.Image, fn.Start)}");
        foreach (var c in fn.Chunks)
            if (c.Start == rva) sb.AppendLine($"{NativeAddress.Va(index.Image, rva)} is the {Describe(c.Kind)} chunk of {fn.Name}");
        if (fn.Parent != null) sb.AppendLine($"C++ funclet of {Name(fn.Parent.Start)}");
        if (fn.Chunks.Count > 0)
            sb.AppendLine("Chunks: " + string.Join(", ", fn.Chunks.Select(c => $"{Describe(c.Kind)} {NativeAddress.Va(index.Image, c.Start)}")));
        var fragments = eh.Fragments.Where(kv => kv.Value == fn.Start).Select(kv => kv.Key).Order().ToList();
        if (fragments.Count > 0) sb.AppendLine("Chained fragments (.pdata): " + string.Join(", ", fragments.Select(f => NativeAddress.Va(index.Image, f))));
        if (eh.Fragments.TryGetValue(fn.Start, out uint primary)) sb.AppendLine($"Fragment of {Name(primary)}");

        var frames = new List<MsvcEhFrame>();
        if (eh.FrameOf(fn.Start) is { } own) frames.Add(own);
        if (fn.Parent != null && eh.FrameOf(fn.Parent.Start) is { } parentFrame) frames.Add(parentFrame);
        if (frames.Count == 0) sb.AppendLine("No exception handling metadata.");
        foreach (var frame in frames) AppendFrame(sb, index, frame, Name);
        var (handlers, ranges) = Facts(index, fn, frames);
        var report = new ExceptionReport(native.Id, fn.Name, NativeAddress.Va(index.Image, fn.Start), "msvc", frames.Count > 0 ? Scheme(frames[0].Scheme) : null,
            fn.Parent?.Name ?? (eh.Fragments.TryGetValue(fn.Start, out uint owner) ? index.NameAt(owner) ?? NativeAddress.Va(index.Image, owner) : null), handlers, ranges, null);
        return ToolOutput.Report(pager.Page(sb.ToString(), offset, maxTokens), report);
    });

    /// <summary>The handlers and protected ranges of an MSVC function's frames, and its chunks.</summary>
    private static (List<EhHandler>, List<EhRange>) Facts(NativeCodeIndex index, NativeFunction fn, List<MsvcEhFrame> frames)
    {
        string Va(uint r) => NativeAddress.Va(index.Image, r);
        var handlers = new List<EhHandler>();
        var ranges = new List<EhRange>();
        foreach (var c in fn.Chunks) handlers.Add(new EhHandler(Describe(c.Kind).Replace(' ', '_'), Va(c.Start), null, null));
        foreach (var f in frames)
        {
            foreach (var t in f.TryBlocks)
                foreach (var c in t.Catches)
                    handlers.Add(new EhHandler("catch", Va(c.HandlerRva), index.NameAt(c.HandlerRva),
                        c.TypeName ?? (c.TypeDescriptorRva == null ? "..." : c.DecoratedTypeName ?? Va(c.TypeDescriptorRva.Value))));
            foreach (var u in f.Unwind)
                if (u.ActionRva is { } a)
                    handlers.Add(new EhHandler(u.Kind == MsvcEhUnwindKind.Funclet ? "unwind" : "destructor", Va(a), index.NameAt(a), $"state {u.State} -> {u.ToState}"));
            foreach (var s in f.Scopes)
            {
                string? filter = s.IsFinally ? null : s.FilterRva is { } fr ? Va(fr) : $"constant {s.FilterConstant}";
                if (s.BeginRva is { } b) ranges.Add(new EhRange(Va(b), Va(s.EndRva!.Value), Va(s.HandlerRva), s.IsFinally ? "finally" : "except", filter));
                else handlers.Add(new EhHandler(s.IsFinally ? "finally" : "except", Va(s.HandlerRva), index.NameAt(s.HandlerRva), $"level {s.Index}"));
            }
        }
        return (handlers.DistinctBy(h => (h.Kind, h.Address, h.Detail)).ToList(), ranges);
    }

    private async Task<(LoadedNative Native, NativeCodeIndex Index)> Open(string image, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var native = await Task.Run(() =>
        {
            return Targets.Native(workspace, image);
        }, ct);
        var index = await code.Index(native, new Progress<CodeIndexProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = p.Done, Total = p.Total > 0 ? p.Total : null, Message = $"indexing {native.Id}: {p.Phase}" })), ct);
        if (index.Image.Format == ImageFormat.Pe && index.Image.Arch is not (NativeArch.X86 or NativeArch.X64))
            throw new ToolError(ErrorCode.Unsupported, $"Exception metadata of PE images is decoded for x86 and x64; {native.Id} is {index.Image.Arch}.");
        return (native, index);
    }

    /// <summary>ELF and Mach-O: the Itanium tables (FDE or compact unwind, personality, LSDA call sites) of one function or the image.</summary>
    private static (string Text, ExceptionReport Record) Itanium(string id, NativeCodeIndex index, string? address)
    {
        var image = index.Image;
        var table = Native.Itanium.ItaniumEh.Of(image);
        string Va(uint r) => NativeAddress.Va(image, r);
        var sb = new StringBuilder();
        if (string.IsNullOrWhiteSpace(address))
        {
            var withLsda = table.Functions.Where(f => f.Lsda != null).ToList();
            sb.AppendLine($"{id}: {Plural(table.Fdes, "FDE")} (.eh_frame)" + (image.Format == ImageFormat.MachO ? $", {Plural(table.CompactEntries, "compact unwind entry")}" : "") +
                          (table.ExidxEntries > 0 ? $", {Plural(table.ExidxEntries, "entry")} (.ARM.exidx)" : "") +
                          $"; {Plural(withLsda.Count, "function")} with an LSDA, {Plural(withLsda.Sum(f => f.CallSites.Count), "call site")}, " +
                          $"{Plural(withLsda.Sum(f => f.CallSites.Count(c => c.LandingPad != null)), "landing pad")}");
            foreach (var g in table.Functions.Where(f => f.Personality != null).GroupBy(f => f.Personality!).OrderByDescending(g => g.Count()))
                sb.AppendLine($"Personality {g.Key}: {Plural(g.Count(), "function")}");
            var caught = withLsda.SelectMany(f => f.CallSites).SelectMany(c => c.Actions).Where(a => a.StartsWith("catch", StringComparison.Ordinal))
                .GroupBy(a => a).OrderByDescending(g => g.Count()).Take(20).ToList();
            if (caught.Count > 0) sb.AppendLine("Caught: " + string.Join(", ", caught.Select(g => $"{g.Key[7..^1]} ({g.Count()})")));
            int attached = index.Functions.Sum(f => f.Chunks.Count);
            if (attached > 0) sb.AppendLine($"Landing pads no flow reaches, attached to their functions as chunks: {attached}");
            foreach (var note in table.Notes) sb.AppendLine($"Note: {note}");
            sb.AppendLine("Pass an address for one function's call sites and landing pads.");
            return (sb.ToString(), new ExceptionReport(id, null, null, "itanium", null, null, [], [], new Dictionary<string, int>
            {
                ["fdes"] = table.Fdes, ["compactEntries"] = table.CompactEntries, ["exidxEntries"] = table.ExidxEntries, ["withLsda"] = withLsda.Count,
                ["callSites"] = withLsda.Sum(f => f.CallSites.Count), ["landingPads"] = withLsda.Sum(f => f.CallSites.Count(c => c.LandingPad != null)),
            }));
        }
        uint rva = NativeCodeTools.Address(index, address);
        var fn = index.FunctionAt(rva) ?? throw new ToolError(ErrorCode.NotFound, $"No function contains {Va(rva)}.", "list_functions shows the functions");
        sb.AppendLine($"{fn.Name} at {Va(fn.Start)}");
        if (fn.Chunks.Any(c => c.Start == rva)) sb.AppendLine($"{Va(rva)} is a landing pad of {fn.Name} (a chunk of its code)");
        var empty = new ExceptionReport(id, fn.Name, Va(fn.Start), "itanium", null, null, [], [], null);
        if (table.At(fn.Start) is not { } eh)
        {
            sb.AppendLine("No exception handling metadata (no FDE, compact unwind or .ARM.exidx entry).");
            return (sb.ToString(), empty);
        }
        sb.AppendLine($"{eh.Source} {Va(eh.Begin)}-{Va(eh.End)}" + (eh.Personality != null ? $", personality {eh.Personality}" : "") + (eh.Lsda is { } l ? $", {(ArmPersonality(eh) ? "scope descriptors" : "LSDA")} {Va(l)}" : ", no LSDA"));
        foreach (var note in eh.Notes) sb.AppendLine($"Note: {note}");
        if (eh.CallSites.Count > 0) sb.AppendLine($"Call sites ({eh.CallSites.Count}):");
        string Name(uint r) => index.NameAt(r) is { } n ? $"{n} ({Va(r)})" : Va(r);
        foreach (var c in eh.CallSites)
            sb.AppendLine($"  {Va(c.Start)}-{Va(c.End)}: " + (c.LandingPad is { } pad ? $"landing pad {Name(pad)}" + (c.Actions.Count > 0 ? ": " + string.Join(", ", c.Actions) : "") : c.Actions.Count > 0 ? string.Join(", ", c.Actions) : "no landing pad (unwinds through)"));
        var pads = eh.CallSites.Where(c => c.LandingPad != null).GroupBy(c => c.LandingPad!.Value)
            .Select(g => new EhHandler("landing_pad", Va(g.Key), index.NameAt(g.Key), g.SelectMany(c => c.Actions).Distinct() is var a && a.Any() ? string.Join(", ", a) : null)).ToList();
        var sites = eh.CallSites.Select(c => new EhRange(Va(c.Start), Va(c.End), c.LandingPad is { } p ? Va(p) : null, "call_site", null)).ToList();
        return (sb.ToString(), empty with { Scheme = eh.Personality, Handlers = pads, Ranges = sites });
    }

    /// <summary>__aeabi_unwind_cpp_pr1 / pr2: the entry's data are scope descriptors, not an LSDA.</summary>
    private static bool ArmPersonality(Native.Itanium.ItaniumEhFunction eh) => eh.Source == "ARM EHABI" && eh.Personality is "__aeabi_unwind_cpp_pr1" or "__aeabi_unwind_cpp_pr2";

    private static string Summary(string id, NativeCodeIndex index, MsvcEhResult eh)
    {
        var s = eh.Stats;
        var sb = new StringBuilder($"{id}: {Plural(s.Frames, "frame")} with exception metadata " +
            $"(C++ FuncInfo {s.Cxx3}, C++ FuncInfo4 {s.Cxx4}, __C_specific_handler {s.CSpecific}, SEH4 {s.Seh4}, SEH3 {s.Seh3}, GS only {s.GsOnly}, unknown {s.Unknown}); " +
            $"{Plural(s.Children, "handler or funclet")}, {Plural(s.Fragments, "chained fragment")}\n");
        var chunks = index.Functions.SelectMany(f => f.Chunks).GroupBy(c => c.Kind).OrderBy(g => g.Key).ToList();
        if (chunks.Count > 0)
            sb.AppendLine("Attached to their functions: " + string.Join(", ", chunks.Select(g => $"{g.Count()} {Describe(g.Key)}")));
        int funclets = index.Functions.Count(f => f.Parent != null);
        if (funclets > 0) sb.AppendLine($"C++ funclets kept as functions with a parent: {funclets}");
        if (eh.RejectCount > 0)
        {
            sb.AppendLine($"Rejected ({eh.RejectCount}):");
            foreach (var r in eh.Rejects.Take(100)) sb.AppendLine($"  {NativeAddress.Va(index.Image, r.Rva)}  {r.Structure}: {r.Reason}");
            if (eh.RejectCount > 100) sb.AppendLine($"  ... {eh.RejectCount - 100} more");
        }
        sb.AppendLine("Pass an address for one function's handlers.");
        return sb.ToString();
    }

    private static void AppendFrame(StringBuilder sb, NativeCodeIndex index, MsvcEhFrame f, Func<uint, string> name)
    {
        string Va(uint r) => NativeAddress.Va(index.Image, r);
        sb.AppendLine();
        sb.Append($"Frame of {name(f.FunctionRva)}: {Scheme(f.Scheme)}");
        if (f.HandlerRva != 0) sb.Append($", handler {f.HandlerName ?? index.NameAt(f.HandlerRva) ?? Va(f.HandlerRva)}");
        sb.Append($", data {Va(f.DataRva)}");
        if (f.GsCookieOffset is { } gs) sb.Append($", GS cookie at frame offset {gs}");
        if (f.IsCatchFunclet) sb.Append(" (catch funclet)");
        sb.AppendLine();
        foreach (var (t, i) in f.TryBlocks.Select((t, i) => (t, i)))
        {
            sb.AppendLine($"  try {i}: states {t.TryLow}-{t.TryHigh}, catch states to {t.CatchHigh}");
            foreach (var c in t.Catches)
                sb.AppendLine($"    catch ({c.TypeName ?? (c.TypeDescriptorRva == null ? "..." : c.DecoratedTypeName ?? Va(c.TypeDescriptorRva.Value))}) -> {Va(c.HandlerRva)}" +
                              (c.Continuations.Count > 0 ? ", continues at " + string.Join(", ", c.Continuations.Select(Va)) : ""));
        }
        foreach (var u in f.Unwind)
        {
            string action = u.Kind switch
            {
                MsvcEhUnwindKind.Funclet => $"funclet {name(u.ActionRva!.Value)}",
                MsvcEhUnwindKind.DestructorWithObject => $"destructor {name(u.ActionRva!.Value)} on frame object +0x{u.ObjectOffset:X}",
                MsvcEhUnwindKind.DestructorWithPointer => $"destructor {name(u.ActionRva!.Value)} on the object frame slot +0x{u.ObjectOffset:X} points to",
                _ => "nothing",
            };
            sb.AppendLine($"  unwind state {u.State} -> {u.ToState}: {action}");
        }
        foreach (var s in f.Scopes)
        {
            string where = s.BeginRva is { } b ? $"{Va(b)}-{Va(s.EndRva!.Value)}" : $"level {s.Index} (encloses {s.EnclosingLevel})";
            if (s.IsFinally) sb.AppendLine($"  __try {where}: __finally {Va(s.HandlerRva)}");
            else
            {
                string filter = s.FilterRva is { } fr ? Va(fr) : $"constant {s.FilterConstant}";
                sb.AppendLine($"  __try {where}: filter {filter}, __except block {Va(s.HandlerRva)}");
            }
        }
        if (f.IpToState.Count > 0)
            sb.AppendLine($"  IP-to-state ({f.IpToState.Count}): " + string.Join(", ", f.IpToState.Take(MaxIpStates).Select(x => $"{Va(x.Rva)}={x.State}")) +
                          (f.IpToState.Count > MaxIpStates ? ", ..." : ""));
    }

    private static string Scheme(MsvcEhScheme s) => s switch
    {
        MsvcEhScheme.CSpecific => "SEH scope table (__C_specific_handler)",
        MsvcEhScheme.Cxx3 => "C++ FuncInfo (__CxxFrameHandler3)",
        MsvcEhScheme.Cxx4 => "C++ FuncInfo4 (__CxxFrameHandler4)",
        MsvcEhScheme.GsOnly => "stack cookie check only (__GSHandlerCheck)",
        MsvcEhScheme.Seh3 => "SEH3 scope table (_except_handler3)",
        MsvcEhScheme.Seh4 => "SEH4 scope table (_except_handler4)",
        _ => "unknown handler data",
    };

    private static string Describe(MsvcEhChildKind k) => k switch
    {
        MsvcEhChildKind.Catch => "catch block",
        MsvcEhChildKind.Unwind => "unwind funclet",
        MsvcEhChildKind.Filter => "filter",
        MsvcEhChildKind.ExceptBlock => "__except block",
        MsvcEhChildKind.Finally => "__finally block",
        MsvcEhChildKind.Continuation => "catch continuation",
        MsvcEhChildKind.HandlerStub => "__ehhandler$ stub",
        _ => "fragment",
    };
}
