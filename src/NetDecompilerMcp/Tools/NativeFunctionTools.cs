using System.ComponentModel;
using System.Text;
using Iced.Intel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Calls;
using NetDecompilerMcp.Native.Code;
using MaskedDecoder = NetDecompilerMcp.Native.Diff.MaskedDecoder;
using MaskedInsn = NetDecompilerMcp.Native.Diff.MaskedInsn;
using NetDecompilerMcp.Native.Itanium;
using NetDecompilerMcp.Native.Msvc;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

/// <summary>analyze_native_function: one function's facts from every analysis, sectioned and bounded.</summary>
[McpServerToolType]
public sealed class NativeFunctionTools(AssemblyWorkspace workspace, NativeCodeService code, OutputPager pager, NativeLinkService? link = null,
    NativeEngineService? engines = null, NativeNamePush? names = null)
{
    [Description("One fact of a section.")]
    public sealed record DossierItem([property: Description("VA, when the fact has an address.")] string? Address, string Text,
        [property: Description("What the fact is within its section (caller, call, string, read, write, switch, loop, ...).")] string? Kind);

    [Description("One section; Total counts every fact, Items holds at most maxItems.")]
    public sealed record DossierSection(
        [property: Description("identity, signature, frame, callers, callees, data, flow, annotations, params or pseudocode.")] string Name,
        int Total, IReadOnlyList<DossierItem> Items, [property: Description("Why the section is missing or partial; the other sections are unaffected.")] string? Error);

    public sealed record FunctionDossier(string Image, string Address, string Name, [property: Description("Bytes of code in its blocks.")] long Size,
        [property: Description("Exclusive end of its highest range (VA).")] string End, IReadOnlyList<DossierSection> Sections,
        [property: Description("Follow-up calls.")] IReadOnlyList<string> Next,
        [property: Description("Several addresses: the dossiers after the first, and the addresses that are in no function; null for one.")] IReadOnlyList<DossierPart>? Batch,
        [property: Description("component=true: how the functions work together.")] ComponentView? Component = null);

    [Description("A set of functions as one component.")]
    public sealed record ComponentView(IReadOnlyList<ComponentFunction> Functions,
        [property: Description("Calls between functions of the set.")] IReadOnlyList<ComponentEdge> Edges,
        [property: Description("Data (not strings) that two or more of the functions read, write or take the address of.")] IReadOnlyList<SharedItem> SharedGlobals,
        [property: Description("Strings two or more of the functions use.")] IReadOnlyList<SharedItem> SharedStrings);

    public sealed record ComponentFunction(string Address, string Name, long Size, int? Blocks, int? Complexity, int Callers, int Callees,
        [property: Description("Called, referenced or exported from outside the set; false: only the set reaches it.")] bool Interface);

    public sealed record ComponentEdge(string From, string To, int Sites);

    public sealed record SharedItem(string Address, string Text, IReadOnlyList<string> Functions);

    [Description("A further dossier of a batch, or an address that could not be analyzed (Error).")]
    public sealed record DossierPart(string Query, string? Address, string? Name, long Size, string? End, IReadOnlyList<DossierSection> Sections, string? Error);

    /// <summary>Records of the dossiers whose text the pager holds, by the same key (a later page needs both).</summary>
    private static readonly Dictionary<string, FunctionDossier> Reports = [];

    private static readonly string[] AllSections = ["identity", "signature", "frame", "callers", "callees", "data", "constants", "flow", "annotations", "params", "pseudocode"];
    private static readonly string[] DefaultSections = ["identity", "signature", "frame", "callers", "callees", "data", "flow", "annotations"];

    /// <summary>Most addresses in one call.</summary>
    private const int MaxBatch = 16;

    [McpServerTool(Name = "analyze_native_function", Title = "Native function dossier", UseStructuredContent = true, OutputSchemaType = typeof(FunctionDossier))]
    [Description("Everything known about one native function, in sections bounded by maxItems with totals: identity (name and source, ranges, " +
                 "flags, demangled and Il2Cpp names, vftable slots), signature evidence (ret n, argument registers read before written, this class, " +
                 "result use), frame (stack, saved registers, frame pointer, address-taken locals, EH), callers (edge kinds, importers in other " +
                 "images, roots), callees (targets, basis, arguments; unresolved with the reason), data (strings, globals read and written, import " +
                 "slots), flow (blocks, loops, switches, cyclomatic complexity, unresolved jumps, noreturn and tail calls), annotations. Optional: " +
                 "constants, params (values callers pass) and pseudocode (IDA or Ghidra). Several addresses: a dossier each, or with component=true " +
                 "a component view (sections only when asked). A failing section reports its error.")]
    public Task<string> AnalyzeNativeFunction(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("An address inside the function, or up to 16 comma-separated. " + NativeTools.AddressDescription)] string address,
        [Description("Comma-separated section names (default all but constants, params and pseudocode).")] string? sections = null,
        [Description("Facts per section (default 40, 1-500).")] int maxItems = 40,
        [Description("Add the pseudocode section.")] bool pseudocode = false,
        [Description("With several addresses: how they work together (internal calls, shared data and strings, interface or internal).")] bool component = false,
        [Description("Pseudocode engine: auto (default), ida or ghidra.")] string? engine = null,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var wanted = component && string.IsNullOrWhiteSpace(sections) ? Sections("identity", pseudocode).Where(s => s != "identity").ToList() : Sections(sections, pseudocode);
        int max = Math.Clamp(maxItems, 1, 500);
        var native = await Task.Run(() => NativeAnalysisTools.ResolveImage(workspace, image), cancellationToken);
        var waited = System.Diagnostics.Stopwatch.StartNew();
        var index = await code.Index(native, new Progress<CodeIndexProgress>(p => progress.Report(new ProgressNotificationValue
        {
            Progress = (float)waited.Elapsed.TotalSeconds, Message = $"indexing {native.Id}: {p.Phase}",
        })), cancellationToken);
        var queries = address.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (queries.Count == 0) throw new ToolError(ErrorCode.InvalidArgument, "Pass an address.");
        if (queries.Count > MaxBatch) throw new ToolError(ErrorCode.LimitExceeded, $"{queries.Count} addresses; at most {MaxBatch} per call.");
        var found = new List<(string Query, NativeFunction? Function, string? Error)>();
        foreach (var q in queries)
        {
            try
            {
                uint rva = NativeCodeTools.Address(index, q);
                var at = index.FunctionAt(rva);
                if (at == null && queries.Count == 1)
                    throw new ToolError(ErrorCode.NotFound, $"No function contains {NativeAddress.Va(index.Image, rva)}.",
                        "list_functions shows the functions; inspect_instruction says what is at any address");
                found.Add((q, at, at == null ? $"no function contains {NativeAddress.Va(index.Image, rva)}" : null));
            }
            catch (ToolError e) when (queries.Count > 1) { found.Add((q, null, e.Message)); }
        }
        var functions = found.Where(x => x.Function != null).Select(x => x.Function!).DistinctBy(x => x.Start).ToList();
        if (functions.Count == 0) throw new ToolError(ErrorCode.NotFound, "None of the addresses is inside a function.", "list_functions shows the functions");
        if (component && functions.Count < 2)
            throw new ToolError(ErrorCode.InvalidArgument, "component=true needs two or more functions.", "pass the functions as comma-separated addresses");
        var pseudo = wanted.Contains("pseudocode") ? await Pseudocode(native, functions, engine, progress, cancellationToken) : [];
        var key = $"dossier|{native.Image.Sha256}|{string.Join(",", found.Select(x => $"{x.Query}={x.Function?.Start:X}"))}|{string.Join(",", wanted)}|{max}|{component}|" +
                  $"{index.Sourced.Version}|{engine}|{string.Join(",", pseudo.Values.Select(p => $"{p.Text?.GetHashCode()}:{p.Error}"))}";
        var (text, report) = await Task.Run(() =>
        {
            lock (Reports)
                if (Reports.TryGetValue(key, out var hit) && pager.TryGet(key, out var cached)) return (cached, hit);
            var parts = functions.Select(f => Build(native, index, f, wanted, max, pseudo.GetValueOrDefault(f.Start).Text, pseudo.GetValueOrDefault(f.Start).Error,
                cancellationToken)).ToList();
            var sb = new StringBuilder();
            var view = component ? Component(native, index, functions, max, sb, cancellationToken) : null;
            if (wanted.Count > 0 || !component) foreach (var p in parts) sb.Append(p.Text).AppendLine();
            foreach (var (q, _, error) in found.Where(x => x.Function == null)) sb.AppendLine($"{q}: {error}");
            sb.AppendLine("Next:");
            foreach (var n in parts[0].Report.Next) sb.AppendLine("  " + n);
            var first = parts[0].Report;
            var batch = queries.Count == 1 ? null
                : functions.Zip(parts).Skip(1).Select(t => new DossierPart(found.First(x => x.Function?.Start == t.First.Start).Query, t.Second.Report.Address,
                        t.Second.Report.Name, t.Second.Report.Size, t.Second.Report.End, t.Second.Report.Sections, null))
                    .Concat(found.Where(x => x.Function == null).Select(x => new DossierPart(x.Query, null, null, 0, null, [], x.Error))).ToList();
            var built = (Text: sb.ToString(), Report: first with { Batch = batch, Component = view });
            pager.GetOrCreate(key, () => built.Text);
            lock (Reports)
            {
                if (Reports.Count >= 64) Reports.Clear();
                Reports[key] = built.Report;
            }
            return built;
        }, cancellationToken);
        return StructuredOutput.With(pager.Page(text, offset, maxChars), report);
    });

    private static List<string> Sections(string? list, bool pseudocode)
    {
        var wanted = string.IsNullOrWhiteSpace(list) ? [.. DefaultSections]
            : list.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(s => s.ToLowerInvariant()).Distinct().ToList();
        foreach (var s in wanted)
            if (!AllSections.Contains(s))
                throw new ToolError(ErrorCode.InvalidArgument, $"Unknown section '{s}'.", "sections: " + string.Join(", ", AllSections));
        if (pseudocode && !wanted.Contains("pseudocode")) wanted.Add("pseudocode");
        return AllSections.Where(wanted.Contains).ToList();
    }

    /// <summary>Pseudocode of each function by start, or why there is none.</summary>
    private async Task<Dictionary<uint, (string? Text, string? Error)>> Pseudocode(LoadedNative native, List<NativeFunction> functions, string? engine,
        IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        Dictionary<uint, (string?, string?)> All(string error) => functions.ToDictionary(f => f.Start, _ => ((string?)null, (string?)error));
        if (engines == null) return All("no decompiler engine is set up in this server");
        try
        {
            var session = await engines.Session(native, engine, new Progress<NativeProviderProgress>(p =>
                progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), ct);
            if (!session.DecompilerAvailable) return All($"the {session.ProviderId} decompiler is not available for {session.Arch} code here");
            if (names != null) await names.EnsureAsync(native, session, ct);
            var items = await session.DecompileManyAsync([.. functions.Select(f => f.Start)], 60, 60 * functions.Count, ct);
            return functions.Zip(items).ToDictionary(t => t.First.Start, t => t.Second.Function is { } d
                ? ($"// {session.ProviderId}\n{d.Text}", (string?)null)
                : ((string?)null, $"{t.Second.ErrorCode ?? "skipped"}: {t.Second.Error ?? "not decompiled in time"}"));
        }
        catch (ToolError e) { return All($"{ToolError.CodeName(e.Code)}: {e.Message}"); }
    }

    /// <summary>Collects one section's facts; an exception becomes the section's error.</summary>
    private sealed class Section(string name, int max)
    {
        public readonly List<DossierItem> Items = [];
        public int Total;
        public string? Error;
        public string Name => name;

        public void Add(string? address, string text, string? kind = null)
        {
            Total++;
            if (Items.Count < max) Items.Add(new DossierItem(address, text, kind));
        }

        public DossierSection Record() => new(name, Total, Items, Error);
    }

    private (string Text, FunctionDossier Report) Build(LoadedNative native, NativeCodeIndex index, NativeFunction f, List<string> wanted, int max, string? pseudo,
        string? pseudoError, CancellationToken ct)
    {
        var image = index.Image;
        string Va(uint r) => NativeAddress.Va(image, r);
        string Where(uint r) => index.FunctionAt(r) is { } fn ? $"{index.NameAt(fn.Start) ?? fn.Name}+0x{r - fn.Start:X}" : Va(r);
        var calls = CallAnalysis.Supports(index) ? CallAnalysis.For(index) : null;
        var name = index.NameAt(f.Start) ?? f.Name;
        var ranges = index.Ranges(f).ToList();
        uint end = ranges.Count > 0 ? ranges.Max(r => r.End) : f.End;
        var rtti = image.Format == ImageFormat.Pe ? native.GetAnalysis(n => MsvcRtti.Analyze(n.Image, ct: ct)) : null;
        var slots = rtti?.Classes.SelectMany(c => c.Vtables.SelectMany(v => v.SlotRvas.Select((s, i) => (Class: c, Vtable: v, Slot: i, Target: s))))
            .Where(x => x.Target == f.Start).ToList() ?? [];
        var built = new List<Section>();
        bool decoded = index.Support != CodeSupport.DeclaredFunctionsOnly;
        foreach (var s in wanted)
        {
            var section = new Section(s, max);
            try
            {
                if (!decoded && s is "signature" or "frame" or "callees" or "data" or "flow" or "params")
                    section.Error = $"{index.SupportNote ?? $"{image.Arch} instructions are not decoded by the built-in analysis"}; pseudocode=true reads the function through IDA or Ghidra";
                else switch (s)
                {
                    case "identity": Identity(section); break;
                    case "signature": Signature(section); break;
                    case "frame": Frame(section); break;
                    case "callers": Callers(section); break;
                    case "callees": Callees(section); break;
                    case "data": Data(section); break;
                    case "constants": Constants(section); break;
                    case "flow": Flow(section); break;
                    case "annotations": Annotations(section); break;
                    case "params": Params(section); break;
                    case "pseudocode":
                        if (pseudo == null) section.Error = pseudoError;
                        else foreach (var line in pseudo.Split('\n')) section.Add(null, line.TrimEnd('\r'), "line");
                        break;
                }
            }
            catch (Exception e) when (e is ToolError or InvalidOperationException or ArgumentException or IndexOutOfRangeException or NullReferenceException or NotSupportedException)
            {
                section.Error = e.Message;
            }
            built.Add(section);
        }

        var next = new List<string>
        {
            $"disassemble image={native.Id} address={Va(f.Start)}",
            $"get_cfg image={native.Id} address={Va(f.Start)}",
        };
        if (calls != null)
        {
            next.Add($"trace_native_values image={native.Id} address={Va(f.Start)} argument=1 direction=forward");
            next.Add($"resolve_call_targets image={native.Id} address={Va(f.Start)} scope=function");
        }
        if (!wanted.Contains("pseudocode")) next.Add($"decompile_native image={native.Id} address={Va(f.Start)}");

        var sb = new StringBuilder($"{name} at {Va(f.Start)} [{native.Id}]: {f.Size:N0} bytes, ends at {Va(end)} (ends are exclusive throughout)\n");
        foreach (var section in built)
        {
            sb.Append($"\n== {section.Name}");
            if (section.Total > 0) sb.Append($" ({section.Total}{(section.Total > section.Items.Count ? $"; first {section.Items.Count}" : "")})");
            sb.AppendLine(" ==");
            if (section.Error != null) sb.AppendLine($"  error: {section.Error}");
            foreach (var item in section.Items)
                sb.AppendLine(section.Name == "pseudocode" ? item.Text : $"  {(item.Address != null ? item.Address + "  " : "")}{item.Text}");
            if (section.Total == 0 && section.Error == null) sb.AppendLine("  (none)");
        }
        return (sb.ToString(), new FunctionDossier(native.Id, Va(f.Start), name, f.Size, Va(end), built.Select(b => b.Record()).ToList(), next, null));

        void Identity(Section x)
        {
            var named = index.Sourced.NameAt(f.Start);
            x.Add(Va(f.Start), $"name {name} ({(named is { } nm ? nm.Source.Id() : f.KnownName != null ? "export or import" : "discovered")})", "name");
            foreach (var (s, e) in ranges) x.Add(Va(s), $"range {Va(s)}-{Va(e)} ({e - s} bytes)", "range");
            x.Add(null, $"{Plural(f.BlockCount, "block")}, {Plural(f.InstructionCount, "instruction")}", "size");
            var callers = index.Callers(f);
            var refs = index.CountRefsTo(f.Start);
            x.Add(null, $"xrefs: {Plural(refs, "reference")} to it ({Plural(callers.Count, "call site")} in {Plural(callers.Select(c => c.Caller?.Start).Distinct().Count(), "caller")}), " +
                        $"{Plural(index.Callees(f).Count, "call")} out", "xrefs");
            if (NativeCodeTools.FlagList(f, index) is { Count: > 0 } flags) x.Add(null, "flags: " + string.Join(", ", flags), "flags");
            x.Add(null, $"found by: {f.Sources}", "discovery");
            if (name.StartsWith('?') && MsvcDemangler.Undecorate(name) is { } msvc && msvc != name) x.Add(null, $"demangled: {msvc}", "demangled");
            else if (ItaniumDemangler.IsMangled(name, stripUnderscore: image.Format == ImageFormat.MachO) && ItaniumDemangler.Demangle(name, image.Format == ImageFormat.MachO) is { } it)
                x.Add(null, $"demangled: {it}", "demangled");
            foreach (var line in Il2CppNativeNames.Describe(native, index, f.Start)) x.Add(null, line, "il2cpp");
            foreach (var slot in slots)
                x.Add(Va(slot.Vtable.VftableRva), $"slot {slot.Slot} of {slot.Class.Name}'s vftable at {Va(slot.Vtable.VftableRva)} (subobject +0x{slot.Vtable.Offset:X})", "vftable_slot");
            if (index.Sourced.CommentAt(f.Start) is { } c) x.Add(Va(f.Start), $"comment ({c.Source.Id()}): {c.Text}", "comment");
        }

        void Signature(Section x)
        {
            if (calls == null) { x.Error = $"signature evidence is read from x86 / x64 code; {image.Arch} is not analyzed here"; return; }
            var fc = calls.Code(f, ct);
            var rets = fc.Blocks.SelectMany(b => b).Where(d => d.I.Mnemonic == Mnemonic.Ret).Select(d => d.I.OpCount > 0 ? (int)d.I.Immediate16 : 0).Distinct().ToList();
            if (!calls.Is64 && rets.Count > 0)
                x.Add(null, rets.All(r => r == 0) ? "plain ret: the caller cleans the stack (cdecl) or there are no stack arguments"
                    : $"ret {string.Join(" / ", rets)}: pops {rets.Max()} bytes ({rets.Max() / 4} stack arguments; stdcall, thiscall or fastcall)", "ret");
            var read = ArgumentRegisters(fc, calls.Is64);
            if (read.Count > 0) x.Add(null, $"argument registers read before written: {string.Join(", ", read)}", "registers");
            else x.Add(null, calls.Is64 ? "no argument register is read before written (no register arguments, or they are only passed on)" : "ecx / edx not read before written", "registers");
            foreach (var cls in slots.Select(s => s.Class.Name).Distinct()) x.Add(null, $"this: {cls} (a slot of its vftable)", "this");
            var sites = index.Callers(f, CallEdgeFilter.Direct).Where(c => c.Kind == XrefKind.Call && c.Caller != null).Take(8).ToList();
            if (sites.Count > 0)
            {
                int used = sites.Count(c => calls.Slices.Forward(c.Caller!, new SliceSeed(SliceSeedKind.Result, c.From, calls.Is64 ? "rax" : "eax"), ct).Nodes.Count > 1);
                x.Add(null, $"{used} of {Plural(sites.Count, "call site")} checked use the returned value", "return");
            }
        }

        void Frame(Section x)
        {
            if (calls == null) { x.Error = $"the frame is read from x86 / x64 code; {image.Arch} is not analyzed here"; return; }
            var fc = calls.Code(f, ct);
            var entry = fc.Blocks.Length > 0 ? fc.Blocks[Math.Max(0, fc.BlockIndexOf(f.Start))] : [];
            var pushed = new List<string>();
            foreach (var d in entry.Take(16))
            {
                var i = d.I;
                if (i.Mnemonic == Mnemonic.Push && i.Op0Kind == OpKind.Register) pushed.Add(i.Op0Register.ToString().ToLowerInvariant());
                else if (i.Mnemonic == Mnemonic.Sub && i.Op0Kind == OpKind.Register && i.Op0Register.GetFullRegister() == Register.RSP && i.OpCount > 1 && i.Op1Kind != OpKind.Register)
                    x.Add(Va(d.Rva), $"allocates 0x{i.GetImmediate(1):X} bytes of stack ({i})", "allocation");
                else if (i.Mnemonic == Mnemonic.Call && i.NearBranchTarget != 0 && index.NameAt((uint)(i.NearBranchTarget - image.ImageBase)) is { } probe
                         && probe.Contains("chkstk", StringComparison.OrdinalIgnoreCase))
                    x.Add(Va(d.Rva), $"stack probe {probe} (a large frame)", "allocation");
            }
            if (pushed.Count > 0) x.Add(null, "saved registers: " + string.Join(", ", pushed), "saved");
            x.Add(null, fc.HasFramePointer ? $"frame pointer {(calls.Is64 ? "rbp" : "ebp")}" : "no frame pointer", "frame_pointer");
            var taken = fc.Blocks.SelectMany(b => b).Where(d => d.I.Mnemonic == Mnemonic.Lea && d.I.MemoryBase.GetFullRegister() is Register.RSP or Register.RBP)
                .Select(d => (d.Rva, Text: $"[{d.I.MemoryBase.ToString().ToLowerInvariant()}{(long)d.I.MemoryDisplacement64:+0x0;-0x0}]"))
                .GroupBy(t => t.Text).ToList();
            foreach (var g in taken) x.Add(Va(g.First().Rva), $"address taken: local {g.Key} ({Plural(g.Count(), "site")})", "taken_local");
            if (index.ExceptionInfo.FrameOf(f.Start) is { } eh)
                x.Add(null, $"exception handling: {eh.Scheme}, {Plural(eh.TryBlocks.Count, "try block")}, {Plural(eh.Unwind.Count, "unwind state")}, " +
                            $"{Plural(eh.Scopes.Count, "SEH scope")}, {Plural(eh.Children.Count, "funclet")}{(eh.GsCookieOffset is { } gs ? $", GS cookie at {gs:+0x0;-0x0}" : "")} " +
                            $"(get_exception_info)", "exception");
            foreach (var chunk in f.Chunks) x.Add(Va(chunk.Start), $"exception chunk: {chunk.Kind}", "chunk");
        }

        void Callers(Section x)
        {
            if (f.Start == image.EntryPointRva) x.Add(Va(f.Start), "the image entry point", "root");
            foreach (var e in image.Exports.Where(e => e.Rva == f.Start)) x.Add(Va(f.Start), $"exported as {e.Name ?? $"#{e.Ordinal}"}", "root");
            if (image.TlsCallbackRvas.Contains(f.Start)) x.Add(Va(f.Start), "a TLS callback", "root");
            foreach (var r in index.RefsTo(f.Start).Where(r => r.Kind is XrefKind.Address or XrefKind.Pointer))
                x.Add(Va(r.From), r.Kind == XrefKind.Address ? $"address taken at {Where(r.From)} (a callback or a stored pointer)" : $"pointer in data at {Va(r.From)}", "reference");
            foreach (var c in index.Callers(f))
                x.Add(Va(c.From), $"{c.Kind switch { XrefKind.TailCall => "tail call", XrefKind.VirtualExact => "virtual call (exact)", XrefKind.VirtualPossible => "virtual call (possible)", _ => "call" }} " +
                                  $"from {Where(c.From)}", "caller");
            if (link != null)
                foreach (var (importer, imp) in link.ImportersOf(native, f.Start, ct))
                    if (code.Ready(importer) is { } other)
                        foreach (var c in other.Callers(imp))
                            x.Add(NativeAddress.Va(importer.Image, c.From), $"[{importer.Id}] calls it through {NativeCodeIndex.ImportName(imp)} from " +
                                                                           $"{(c.Caller is { } cf ? other.NameAt(cf.Start) ?? cf.Name : "(no function)")}", "importer");
        }

        void Callees(Section x)
        {
            if (calls == null)
            {
                foreach (var c in index.Callees(f)) x.Add(Va(c.From), $"{c.Kind} {(c.Function is { } t ? index.NameAt(t.Start) ?? t.Name : c.Import is { } i ? NativeCodeIndex.ImportName(i) : Va(c.Target))}", "call");
                return;
            }
            foreach (var s in CallTargets.In(calls, f, deep: false, ct))
            {
                var display = calls.CallAt(s.Rva, ct)?.Display ?? s.Text;
                var targets = s.Targets.Count > 0 && s.IsIndirect ? $" -> {string.Join(", ", s.Targets.Take(4).Select(t => $"{t.Name} ({t.Basis})"))}{(s.TargetCount > 4 ? ", ..." : "")}" : "";
                x.Add(Va(s.Rva), $"{display}  [{s.Mechanism}, {s.Status}]{targets}{(s.Reason != null ? $"; {s.Reason}" : "")}", s.Status == "unresolved" ? "unresolved" : "call");
            }
        }

        void Data(Section x)
        {
            var refs = ranges.SelectMany(r => index.RefsFrom(r.Start, r.End)).Where(r => r.Kind is XrefKind.Read or XrefKind.Write or XrefKind.Address).ToList();
            foreach (var g in refs.GroupBy(r => (r.To, r.Kind)).OrderBy(g => g.Key.To))
            {
                var to = g.Key.To;
                if (index.FunctionByStart(to) != null) continue; // a function address: callers / callees
                string kind = g.Key.Kind switch { XrefKind.Read => "read", XrefKind.Write => "write", _ => "address" };
                string what = index.StringAt(to) is { } s
                    ? $"string {(s.Encoding == StringEncoding.Utf16 ? "L" : "")}\"{Format.Clip(index.ReadString(s, 200), 120)}\""
                    : image.Imports.FirstOrDefault(i => i.SlotRva == to) is { } imp ? $"import slot {NativeCodeIndex.ImportName(imp)}"
                    : $"{(image.SectionAt(to) is { } sec && (sec.Access & SectionAccess.Write) != 0 ? "global" : "constant data")} {index.NameAt(to) ?? Va(to)}";
                x.Add(Va(to), $"{kind} {what} ({Plural(g.Count(), "site")}, first at {Va(g.First().From)})", index.StringAt(to) != null ? "string" : kind);
            }
        }

        void Flow(Section x)
        {
            var graph = index.GetGraph(f, ct);
            x.Add(null, $"{Plural(graph.Blocks.Count, "block")}{(graph.Truncated ? " (truncated)" : "")}, cyclomatic complexity {Cyclomatic(graph)}", "blocks");
            foreach (var b in graph.Blocks)
                foreach (var e in b.Successors)
                    if (graph.BlockAt(e.To) is { } t && t.Start <= b.Start && e.Kind != EdgeKind.TailCall)
                        x.Add(Va(b.LastInstruction), $"loop: back edge {Va(b.LastInstruction)} -> {Va(t.Start)}", "loop");
            foreach (var s in graph.Switches)
                x.Add(Va(s.JumpRva), $"switch at {Va(s.JumpRva)}: {Plural(s.Cases.Count > 0 ? s.Cases.Count : s.Targets.Count, "case target")}, table {Va(s.TableRva)} " +
                                     $"({s.EntryCount} entries){(s.Default is { } d ? $", default {Va(d)}" : "")} (get_cfg lists the values)", "switch");
            foreach (var u in graph.UnresolvedJumps) x.Add(Va(u.Rva), $"unresolved indirect jump: {u.Reason}", "unresolved");
            foreach (var b in graph.Blocks.Where(b => b.EndKind == BlockEnd.NoReturnCall)) x.Add(Va(b.LastInstruction), "call that does not return", "noreturn");
            foreach (var t in graph.TailCalls) x.Add(Va(t), $"tail call to {index.NameAt(t) ?? Va(t)}", "tail_call");
        }

        void Constants(Section x)
        {
            // the masked decoder keeps only immediates worth matching on: not addresses, small counts, all-ones masks or frame sizes
            var decoder = new MaskedDecoder(image);
            var insns = new List<MaskedInsn>();
            foreach (var (s, e) in ranges) decoder.Decode(s, e, insns);
            foreach (var g in insns.Where(i => i.Constant != null).GroupBy(i => i.Constant!.Value).OrderByDescending(g => g.Count()).ThenBy(g => g.Key))
                x.Add(Va(g.First().Rva), $"0x{g.Key:X} ({(long)g.Key}) ({Plural(g.Count(), "site")})", "constant");
        }

        void Annotations(Section x)
        {
            foreach (var (s, e) in ranges)
                foreach (var a in index.Sourced.In(s, e))
                    if (a.Rva != f.Start || a.Comment != null)
                        x.Add(Va(a.Rva), $"{(a.Name != null && a.Rva != f.Start ? $"name {a.Name}" : "")}{(a.Name != null && a.Rva != f.Start && a.Comment != null ? "; " : "")}" +
                                         $"{(a.Comment != null ? $"comment {a.Comment}" : "")} ({a.Source.Id()})", a.Comment != null ? "comment" : "name");
        }

        void Params(Section x)
        {
            if (calls == null) { x.Error = $"values are traced in x86 / x64 code; {image.Arch} is not analyzed here"; return; }
            var registers = ArgumentRegisters(calls.Code(f, ct), calls.Is64);
            int count = calls.Is64 ? Math.Max(1, registers.Count) : 2;
            for (int k = 0; k < Math.Min(4, count); k++)
            {
                var seed = NativeTraceTools.Seed(calls, Va(f.Start), null, (k + 1).ToString(System.Globalization.CultureInfo.InvariantCulture), ct);
                var g = ValueTrace.Build(calls, seed, new ValueTraceOptions(TraceDirection.Backward, MaxDepth: 1, MaxFunctions: 16, MaxNodes: 200, MaxCallers: 16), ct: ct);
                x.Add(Va(f.Start), $"parameter {k + 1} ({seed.Location}): " + (g.Values.Count > 0 ? string.Join(", ", g.Values.Take(12).Select(v => v.Text)) +
                                   (g.Values.Count > 12 ? ", ..." : "") : "no constant values from callers") + (g.Frontier.Count > 0 ? $"; {Plural(g.Frontier.Count, "frontier item")}" : ""), "parameter");
            }
        }
    }

    /// <summary>component=true: the set's internal calls, shared data and strings, and which functions the rest of the image reaches; written to <paramref name="sb"/>.</summary>
    private static ComponentView Component(LoadedNative native, NativeCodeIndex index, List<NativeFunction> functions, int max, StringBuilder sb, CancellationToken ct)
    {
        var image = index.Image;
        string Va(uint r) => NativeAddress.Va(image, r);
        string Name(NativeFunction f) => index.NameAt(f.Start) ?? f.Name;
        var set = functions.Select(f => f.Start).ToHashSet();
        var rows = new List<ComponentFunction>();
        var edges = new List<ComponentEdge>();
        var globals = new Dictionary<uint, SortedSet<string>>();
        var strings = new Dictionary<uint, SortedSet<string>>();
        foreach (var f in functions)
        {
            ct.ThrowIfCancellationRequested();
            int? blocks = null, complexity = null;
            try
            {
                var graph = index.GetGraph(f, ct);
                (blocks, complexity) = (graph.Blocks.Count, Cyclomatic(graph));
            }
            catch (NotSupportedException) { }
            var callers = index.Callers(f);
            var callees = index.Callees(f);
            bool root = f.Start == image.EntryPointRva || image.Exports.Any(e => e.Rva == f.Start) || image.TlsCallbackRvas.Contains(f.Start);
            bool outside = callers.Any(c => c.Caller is not { } cf || !set.Contains(cf.Start))
                           || index.RefsTo(f.Start).Any(r => r.Kind is XrefKind.Address or XrefKind.Pointer && (index.FunctionAt(r.From) is not { } by || !set.Contains(by.Start)));
            rows.Add(new ComponentFunction(Va(f.Start), Name(f), f.Size, blocks, complexity, callers.Count, callees.Count, root || outside));
            foreach (var g in callees.Where(c => c.Function != null && set.Contains(c.Function.Start)).GroupBy(c => c.Function!.Start))
                edges.Add(new ComponentEdge(Name(f), Name(index.FunctionByStart(g.Key)!), g.Count()));
            foreach (var (s, e) in index.Ranges(f))
                foreach (var r in index.RefsFrom(s, e).Where(r => r.Kind is XrefKind.Read or XrefKind.Write or XrefKind.Address))
                {
                    if (index.FunctionByStart(r.To) != null || image.Imports.Any(i => i.SlotRva == r.To)) continue;
                    var into = index.StringAt(r.To) != null ? strings : globals;
                    if (!into.TryGetValue(r.To, out var users)) into[r.To] = users = new SortedSet<string>(StringComparer.Ordinal);
                    users.Add(Name(f));
                }
        }
        List<SharedItem> Shared(Dictionary<uint, SortedSet<string>> map, bool isString) => map.Where(m => m.Value.Count >= 2).OrderByDescending(m => m.Value.Count).ThenBy(m => m.Key)
            .Select(m => new SharedItem(Va(m.Key), isString && index.StringAt(m.Key) is { } s
                ? $"{(s.Encoding == StringEncoding.Utf16 ? "L" : "")}\"{Format.Clip(index.ReadString(s, 200), 80)}\"" : index.NameAt(m.Key) ?? Va(m.Key), m.Value.ToList())).ToList();
        var view = new ComponentView(rows, edges, Shared(globals, false), Shared(strings, true));

        sb.AppendLine($"Component of {Plural(functions.Count, "function")} [{native.Id}] (ends are exclusive throughout)");
        sb.AppendLine("\n== functions (address, size, blocks, complexity, callers, callees) ==");
        foreach (var r in rows)
            sb.AppendLine($"  {r.Address}  {r.Name}  {r.Size} bytes, {(r.Blocks?.ToString() ?? "?")} blocks, complexity {(r.Complexity?.ToString() ?? "?")}, " +
                          $"{r.Callers} callers, {r.Callees} callees, {(r.Interface ? "interface" : "internal")}");
        void List(string title, IEnumerable<string> lines)
        {
            var all = lines.ToList();
            sb.AppendLine($"\n== {title} ({all.Count}{(all.Count > max ? $"; first {max}" : "")}) ==");
            foreach (var l in all.Take(max)) sb.AppendLine("  " + l);
            if (all.Count == 0) sb.AppendLine("  (none)");
        }
        List("internal calls", edges.Select(e => $"{e.From} -> {e.To} ({Plural(e.Sites, "site")})"));
        List("shared globals", view.SharedGlobals.Select(g => $"{g.Address}  {g.Text}: {string.Join(", ", g.Functions)}"));
        List("shared strings", view.SharedStrings.Select(g => $"{g.Address}  {g.Text}: {string.Join(", ", g.Functions)}"));
        List("internal only (reached from the set alone)", rows.Where(r => !r.Interface).Select(r => r.Name));
        sb.AppendLine();
        return view;
    }

    /// <summary>Edges between the graph's blocks minus blocks plus 2 (McCabe).</summary>
    internal static int Cyclomatic(FunctionGraph graph) =>
        graph.Blocks.Sum(b => b.Successors.Count(e => e.Kind != EdgeKind.TailCall && graph.BlockAt(e.To) != null)) - graph.Blocks.Count + 2;

    /// <summary>The argument registers the function reads before it writes them, in address order up to its first call.</summary>
    private static List<string> ArgumentRegisters(FunctionCode fc, bool is64)
    {
        Register[] candidates = is64
            ? [Register.RCX, Register.RDX, Register.R8, Register.R9, Register.XMM0, Register.XMM1, Register.XMM2, Register.XMM3]
            : [Register.ECX, Register.EDX];
        var written = new HashSet<Register>();
        var read = new List<string>();
        var info = new InstructionInfoFactory();
        foreach (var d in fc.Blocks.OrderBy(b => b.Length > 0 ? b[0].Rva : uint.MaxValue).SelectMany(b => b))
        {
            if (d.I.FlowControl is FlowControl.Call or FlowControl.IndirectCall or FlowControl.Return) break;
            foreach (var u in info.GetInfo(d.I).GetUsedRegisters())
            {
                var full = u.Register.GetFullRegister();
                var match = candidates.FirstOrDefault(c => c.GetFullRegister() == full);
                if (match == Register.None) continue;
                if (u.Access is OpAccess.Read or OpAccess.ReadWrite or OpAccess.CondRead or OpAccess.ReadCondWrite && !written.Contains(full)
                    && !read.Contains(match.ToString().ToLowerInvariant()))
                    read.Add(match.ToString().ToLowerInvariant());
                if (u.Access is OpAccess.Write or OpAccess.ReadWrite or OpAccess.CondWrite) written.Add(full);
            }
        }
        return read;
    }
}
