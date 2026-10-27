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
using MaskedDecoder = Corvus.Native.Diff.MaskedDecoder;
using MaskedInsn = Corvus.Native.Diff.MaskedInsn;
using Corvus.Native.Itanium;
using Corvus.Native.Msvc;
using Corvus.Native.Providers;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>analyze_native_function: one function's facts from every analysis, sectioned and bounded.</summary>
[McpServerToolType]
public sealed class NativeFunctionTools(AssemblyWorkspace workspace, NativeCodeService code, OutputPager pager, NativeLinkService? link = null,
    NativeEngineService? engines = null, NativeNamePush? names = null)
{
    [Description("One fact of a section.")]
    public sealed record DossierItem([property: Description("VA, when the fact has an address.")] string? Address, string Text,
        [property: Description("Kind in its section (caller, call, string, read, write, switch, loop...).")] string? Kind);

    [Description("One section; Total counts every fact, Items holds at most maxItems.")]
    public sealed record DossierSection(
        [property: Description("identity, signature, frame, callers, callees, data, constants, flow, annotations, params, pseudocode.")] string Name,
        int Total, IReadOnlyList<DossierItem> Items, [property: Description("Why the section is missing or partial; the other sections are unaffected.")] string? Error);

    public sealed record FunctionDossier(string Image, string Address, string Name, [property: Description("Bytes of code in its blocks.")] long Size,
        [property: Description("Exclusive end of its highest range (VA).")] string End, IReadOnlyList<DossierSection> Sections,
        [property: Description("Follow-up calls.")] IReadOnlyList<string> Next,
        [property: Description("Several addresses: the dossiers after the first, and addresses in no function.")] IReadOnlyList<DossierPart>? Batch,
        [property: Description("component=true: how the functions work together.")] ComponentView? Component = null);

    [Description("A set of functions as one component.")]
    public sealed record ComponentView(IReadOnlyList<ComponentFunction> Functions,
        [property: Description("Calls between functions of the set.")] IReadOnlyList<ComponentEdge> Edges,
        [property: Description("Data (not strings) that 2+ functions read, write or take the address of.")] IReadOnlyList<SharedItem> SharedGlobals,
        [property: Description("Strings two or more of the functions use.")] IReadOnlyList<SharedItem> SharedStrings);

    public sealed record ComponentFunction(string Address, string Name, long Size, int? Blocks, int? Complexity, int Callers, int Callees,
        [property: Description("Reached from outside the set (called, referenced, exported); false: only the set.")] bool Interface);

    public sealed record ComponentEdge(string From, string To, int Sites);

    public sealed record SharedItem(string Address, string Text, IReadOnlyList<string> Functions);

    [Description("A further dossier of a batch, or an address that could not be analyzed (Error).")]
    public sealed record DossierPart(string Query, string? Address, string? Name, long Size, string? End, IReadOnlyList<DossierSection> Sections, string? Error);

    /// <summary>Records of the dossiers whose text the pager holds, by the same key, with the warnings and coverage a hit replays.</summary>
    private static readonly Dictionary<string, (FunctionDossier Report, string[] Warnings, (string, string, IReadOnlyList<string>)? Coverage,
        KeyValuePair<string, string?>[] Facets)> Reports = [];

    private static readonly string[] AllSections = ["identity", "signature", "frame", "callers", "callees", "data", "constants", "flow", "annotations", "params", "pseudocode"];
    private static readonly string[] DefaultSections = ["identity", "signature", "frame", "callers", "callees", "data", "flow", "annotations"];

    /// <summary>Most addresses in one call.</summary>
    private const int MaxBatch = 16;

    [McpServerTool(Name = "analyze_native_function", Title = "Native function dossier", UseStructuredContent = true, OutputSchemaType = typeof(FunctionDossier))]
    [Description("Everything known about one native function, in sections: identity, signature, frame, callers, callees, data, flow, " +
                 "annotations; constants, params and pseudocode on request.")]
    public Task<string> AnalyzeNativeFunction(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("In the function; up to 16 comma-separated (a dossier each): " + NativeTools.AddressDescription)] string address,
        [Description("Comma-separated sections (default all but constants, params, pseudocode).")] string? sections = null,
        [Description("Facts per section (1-500).")] int maxItems = 40,
        [Description("Add the pseudocode section.")] bool pseudocode = false,
        [Description("Several addresses: one component view (internal calls, shared data, interface).")] bool component = false,
        [Description("Pseudocode engine (default auto).")] string? engine = null,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
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
        var records = new Dictionary<uint, (string Engine, EngineFunctionRecord Value)>();
        if (wanted.Contains("identity"))
            foreach (var f in functions)
                if (await EngineRecord(native, f.Start, engine, cancellationToken) is { } rec) records[f.Start] = rec;
        var key = $"dossier|{native.Image.Sha256}|{string.Join(",", found.Select(x => $"{x.Query}={x.Function?.Start:X}"))}|{string.Join(",", wanted)}|{max}|{component}|" +
                  $"{index.Sourced.Version}|{Services.Analysis.NativeCapa.Cached(native.FilePath)?.Labels.Count}|{engine}|{string.Join(",", pseudo.Values.Select(p => $"{p.Text?.GetHashCode()}:{p.Error}"))}|" +
                  string.Join(",", records.Values.Select(x => string.Join(";", NativeEngineCode.RecordLines(x.Value, r => r.ToString("X")))));
        var (text, report) = await Task.Run(() =>
        {
            var call = OutputCall.Current;
            lock (Reports)
                if (Reports.TryGetValue(key, out var hit) && pager.TryGet(key, out var cached))
                {
                    foreach (var w in hit.Warnings) ToolOutput.Warn(w);
                    if (hit.Coverage is { } c) call?.Coverage = c;
                    // Replay the facets the build reported, so a repeat answers the same record.
                    foreach (var (name, unavailable) in hit.Facets) ToolOutput.Facet(name, unavailable);
                    return (cached, hit.Report);
                }
            int warned = call?.Warnings.Count ?? 0;
            var parts = functions.Select(f => Build(native, index, f, wanted, max, pseudo.GetValueOrDefault(f.Start).Text, pseudo.GetValueOrDefault(f.Start).Error,
                cancellationToken, records.TryGetValue(f.Start, out var rec) ? rec : null)).ToList();
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
                Reports[key] = (built.Report, call?.Warnings.Skip(warned).ToArray() ?? [], call?.Coverage, call?.Facets?.ToArray() ?? []);
            }
            return built;
        }, cancellationToken);
        return ToolOutput.With(pager.Page(text, offset, maxTokens), report);
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

    /// <summary>The function record of an engine session already open (the one engine names, else any); none is started for it.</summary>
    private async Task<(string Engine, EngineFunctionRecord Value)?> EngineRecord(LoadedNative native, uint start, string? engine, CancellationToken ct)
    {
        var named = string.IsNullOrWhiteSpace(engine) || engine.Trim().Equals("auto", StringComparison.OrdinalIgnoreCase) ? null : engine.Trim().ToLowerInvariant();
        if (engines?.OpenSession(native, named) is not { } session) return null;
        try { return (session.ProviderId, await session.GetFunctionRecordAsync(start, ct)); }
        catch (ToolError) { return null; }
    }

    /// <summary>The facet a dossier section shows.</summary>
    private static string? FacetOf(string section) => section switch
    {
        "callers" or "callees" or "pseudocode" => section,
        "data" => "strings",
        "flow" => "cfg",
        _ => null,
    };

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

    /// <summary>Bytes after a no-return call that decode as the body going on, up to a return or jump; null when the call ends the function.</summary>
    internal static int? CutAfter(NativeCodeIndex index, FunctionGraph graph, BasicBlock call)
    {
        uint after = call.End;
        // A function discovered there that nothing references is the same code split off.
        if (graph.BlockAt(after) != null || index.FunctionAt(after) is { } next && (next.Start != after || index.CountRefsTo(after) > 0)) return null;
        var bytes = new byte[8];
        int read = index.Image.Read(after, bytes);
        if (read < 4 || bytes.Take(read).All(b => b is 0xCC or 0x90 or 0x00)) return null;
        var lines = new NativeDisassembler(index.Image).Disassemble(after, 16, after + 128);
        int n = 0;
        foreach (var l in lines)
        {
            n++;
            if (l.Facts.Flow is FlowKind.Invalid or FlowKind.Trap) return null;
            if (l.Facts.Flow is FlowKind.Return or FlowKind.Jump or FlowKind.IndirectJump)
                return n >= 2 ? (int)(l.Rva + (uint)l.Facts.Length - after) : null;
        }
        return null;
    }

    private (string Text, FunctionDossier Report) Build(LoadedNative native, NativeCodeIndex index, NativeFunction f, List<string> wanted, int max, string? pseudo,
        string? pseudoError, CancellationToken ct, (string Engine, EngineFunctionRecord Value)? record = null)
    {
        var image = index.Image;
        string Va(uint r) => NativeAddress.Va(image, r);
        string Where(uint r) => index.FunctionAt(r) is { } fn ? Format.Within(index.NameAt(fn.Start) ?? fn.Name, fn.Start, r) : Va(r);
        var calls = CallAnalysis.Supports(index) ? CallAnalysis.For(index) : null;
        var name = index.NameAt(f.Start) ?? f.Name;
        var ranges = index.Ranges(f).ToList();
        uint end = ranges.Count > 0 ? ranges.Max(r => r.End) : f.End;
        var rtti = native.GetAnalysis(n => Native.Itanium.CppRtti.Analyze(n.Image, ct));
        var slots = rtti?.Classes.SelectMany(c => c.Vtables.SelectMany(v => v.SlotRvas.Select((s, i) => (Class: c, Vtable: v, Slot: i, Target: s))))
            .Where(x => x.Target == f.Start).ToList() ?? [];
        var built = new List<Section>();
        bool decoded = index.Support != CodeSupport.DeclaredFunctionsOnly;
        if (!decoded) ToolOutput.Coverage("partial", $"{image.ArchName()} instructions are not decoded: code sections are empty", "architecture-undecoded");
        foreach (var s in wanted)
        {
            var section = new Section(s, max);
            try
            {
                if (!decoded && s is "signature" or "frame" or "callers" or "callees" or "data" or "constants" or "flow" or "params")
                    section.Error = $"not decoded ({image.ArchName()}): pseudocode=true reads the function through IDA or Ghidra";
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
            if (FacetOf(s) is { } facet) ToolOutput.Facet(facet, section.Error);
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
            if (index.Support == CodeSupport.DeclaredFunctionsOnly)
                x.Add(null, $"blocks, instructions and references: not decoded ({image.ArchName()})", "size");
            else
            {
                x.Add(null, $"{Plural(f.BlockCount, "block")}, {Plural(f.InstructionCount, "instruction")}", "size");
                var callers = index.Callers(f);
                var refs = index.CountRefsTo(f.Start);
                x.Add(null, $"xrefs: {Plural(refs, "reference")} to it ({Plural(callers.Count, "call site")} in {Plural(callers.Select(c => c.Caller?.Start).Distinct().Count(), "caller")}), " +
                            $"{Plural(index.Callees(f).Count, "call")} out", "xrefs");
            }
            if (NativeCodeTools.FlagList(f, index) is { Count: > 0 } flags) x.Add(null, "flags: " + string.Join(", ", flags), "flags");
            x.Add(null, $"found by: {f.Sources}", "discovery");
            if (name.StartsWith('?') && MsvcDemangler.Undecorate(name) is { } msvc && msvc != name) x.Add(null, $"demangled: {msvc}", "demangled");
            else if (NativeTools.Demangled(name, image.Format) is { } it) x.Add(null, $"demangled: {it}", "demangled");
            foreach (var line in AotNativeNames.Describe(native, index, f.Start)) x.Add(null, line, "metadata");
            foreach (var slot in slots)
                x.Add(Va(slot.Vtable.VftableRva), $"slot {slot.Slot} of {slot.Class.Name}'s vftable at {Va(slot.Vtable.VftableRva)} (subobject +0x{slot.Vtable.Offset:X})", "vftable_slot");
            if (PdbService.StateOf(native)?.Pdb is { } pdb && PdbPrototype(pdb, image, f.Start) is { } proto) x.Add(Va(f.Start), $"prototype (pdb): {proto}", "prototype");
            if (code.Annotations(native).UserTypes.Types.GetValueOrDefault(f.Start) is { } user) x.Add(Va(f.Start), $"prototype (user): {user}", "prototype");
            if (index.Sourced.CommentAt(f.Start) is { } c) x.Add(Va(f.Start), $"comment ({c.Source.Id()}): {c.Text}", "comment");
            if (record is { } engineRecord)
                foreach (var line in NativeEngineCode.RecordLines(engineRecord.Value, Va, compact: true)) x.Add(null, $"{engineRecord.Engine}: {line}", "engine");
        }

        void Signature(Section x)
        {
            var incoming = IncomingParameters(index, f, ct);
            if (incoming.Count > 0)
                x.Add(null, $"parameters read at entry: {string.Join(", ", incoming.Select(p => $"{p.Index + 1} ({p.Location})"))}: at least {incoming.Max(p => p.Index) + 1} arguments",
                    "parameters");
            if (calls == null)
            {
                if (!Arm64Trace.Supports(index)) x.Error = $"signature evidence is read from x86 / x64 / ARM64 code; {image.Arch} is not analyzed here";
                return;
            }
            var fc = calls.Code(f, ct);
            var rets = fc.Blocks.SelectMany(b => b).Where(d => d.I.Mnemonic == Mnemonic.Ret).Select(d => d.I.OpCount > 0 ? (int)d.I.Immediate16 : 0).Distinct().ToList();
            if (!calls.Is64 && rets.Count > 0)
                x.Add(null, rets.All(r => r == 0) ? "plain ret: the caller cleans the stack (cdecl) or there are no stack arguments"
                    : $"ret {string.Join(" / ", rets)}: pops {rets.Max()} bytes ({rets.Max() / 4} stack arguments; stdcall, thiscall or fastcall)", "ret");
            var read = ArgumentRegisters(fc, calls);
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
            if (UnwindFrames.Of(image, f.Start) is { } u)
            {
                x.Add(Va(u.Begin), $"unwind data ({u.Format}, {Va(u.Begin)}-{Va(u.End)}): allocates 0x{u.Allocation:X} bytes" +
                                   (u.PrologBytes > 0 ? $", prolog {u.PrologBytes} bytes" : ""), "unwind");
                if (u.Saved.Count > 0) x.Add(null, "unwind data saves: " + string.Join(", ", u.Saved), "saved");
                if (u.FramePointer != null) x.Add(null, $"unwind data frame pointer: {u.FramePointer}", "frame_pointer");
                foreach (var note in u.Notes) x.Add(null, "unwind data: " + note, "unwind");
            }
            if (calls == null)
            {
                if (Arm64Trace.Supports(index))
                {
                    var code = Arm64Trace.For(index).Code(f, ct);
                    foreach (var g in code.Blocks.SelectMany(b => b).Where(s => s.I.Mnemonic is AsmArm64.Arm64Mnemonic.ADD or AsmArm64.Arm64Mnemonic.SUB && s.I.OperandCount > 2
                                 && s.I.GetOperand(1) is { Kind: AsmArm64.Arm64OperandKind.Register } r && ((AsmArm64.Arm64RegisterOperand)r).Value.Kind == AsmArm64.Arm64RegisterKind.SP
                                 && A64Function.Gpr(s.I, 0) is >= 0 and < 29 && s.Sp is not null && A64Function.Imm(s.I, 2) is not null)
                                 .GroupBy(s => s.Sp!.Value + (s.I.Mnemonic == AsmArm64.Arm64Mnemonic.SUB ? -1 : 1) * (int)A64Function.Imm(s.I, 2)!.Value))
                        x.Add(Va(g.First().Rva), $"address taken: local {A64Function.Name(A64Loc.Slot(g.Key), null)} from entry sp ({Plural(g.Count(), "site")})", "taken_local");
                }
                else if (x.Total == 0) x.Error = $"the frame is read from x86 / x64 / ARM64 code or unwind data; {image.Arch} is not analyzed here";
                return;
            }
            var fc = calls.Code(f, ct);
            var entry = fc.Blocks.Length > 0 ? fc.Blocks[Math.Max(0, fc.BlockIndexOf(f.Start))] : [];
            var pushed = new List<string>();
            var allocations = AllocationPushes(fc, calls);
            foreach (var d in entry.Take(16))
            {
                var i = d.I;
                if (allocations.Contains(d.Rva)) x.Add(Va(d.Rva), $"allocates {(calls.Is64 ? 8 : 4)} bytes of stack ({i})", "allocation");
                else if (i.Mnemonic == Mnemonic.Push && i.Op0Kind == OpKind.Register) pushed.Add(i.Op0Register.ToString().ToLowerInvariant());
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
            else if (image.Format != ImageFormat.Pe && Native.Itanium.ItaniumEh.Of(image).At(f.Start) is { Lsda: not null } it)
                x.Add(null, $"exception handling: {it.Personality ?? "a personality routine"}, {Plural(it.CallSites.Count, "call site")}, " +
                            $"{Plural(it.CallSites.Count(c => c.LandingPad != null), "landing pad")} (get_exception_info)", "exception");
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
            int importers = 0;
            if (link != null)
                foreach (var (importer, imp) in link.ImportersOf(native, f.Start, ct))
                    if (code.Ready(importer) is { } other)
                        foreach (var c in other.Callers(imp))
                        {
                            importers++;
                            x.Add(NativeAddress.Va(importer.Image, c.From), $"[{importer.Id}] calls it through {NativeCodeIndex.ImportName(imp)} from " +
                                                                           $"{(c.Caller is { } cf ? other.NameAt(cf.Start) ?? cf.Name : "(no function)")}", "importer");
                        }
            Reachability(x, importers);
        }

        // How control reaches the function: calls, or only its address (a callback or a stored pointer).
        void Reachability(Section x, int importers)
        {
            bool root = f.Start == image.EntryPointRva || image.Exports.Any(e => e.Rva == f.Start) || image.TlsCallbackRvas.Contains(f.Start);
            int called = index.Callers(f).Count + importers;
            var taken = index.RefsTo(f.Start).Where(r => r.Kind is XrefKind.Address or XrefKind.Pointer).ToList();
            var uses = new List<string>();
            var sites = NativeCallTools.Sites(index);
            foreach (var r in taken.Take(16))
            {
                if (r.Kind == XrefKind.Pointer) { uses.Add($"pointer in data at {Va(r.From)}"); continue; }
                var passed = index.FunctionAt(r.From) is { } user && sites != null
                    ? sites.CallsIn(user, ct).Select(c => (Call: c, Argument: c.Arguments.FirstOrDefault(a => a.Rva == f.Start && a.Derivation.Contains(Va(r.From), StringComparison.OrdinalIgnoreCase))))
                        .FirstOrDefault(c => c.Argument != null) : default;
                uses.Add(passed.Call != null ? $"passed to {passed.Call.ShortCallee} as {passed.Argument!.Name ?? $"argument {passed.Argument.Index + 1}"} at {Va(passed.Call.Rva)}"
                    : $"address taken at {Where(r.From)}");
            }
            if (taken.Count > uses.Count) uses.Add($"{taken.Count - uses.Count} more");
            if (called == 0 && taken.Count > 0)
                x.Add(Va(f.Start), $"reachable only through its address{(root ? " (and as an entry point or export)" : "")}: a callback or a stored pointer ({string.Join("; ", uses)})", "reachability");
            else if (taken.Count > 0)
                x.Add(Va(f.Start), $"called directly and also through its address ({string.Join("; ", uses)})", "reachability");
            else if (called == 0 && !root)
                x.Add(Va(f.Start), "no known callers or references: reached through a computed pointer, from another module, or unused", "reachability");
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
            foreach (var b in graph.Blocks.Where(b => b.EndKind == BlockEnd.NoReturnCall))
            {
                x.Add(Va(b.LastInstruction), "call that does not return", "noreturn");
                if (CutAfter(index, graph, b) is { } cut)
                {
                    var callee = index.Callees(f).FirstOrDefault(c => c.From == b.LastInstruction) is { } site
                        ? site.Import != null ? NativeCodeIndex.ImportName(site.Import) : site.Function?.Name ?? Va(site.Target) : "its callee";
                    var warning = $"the body may be cut at {Va(b.End)} by the call to {callee} at {Va(b.LastInstruction)} (treated as no-return): " +
                                  $"the {Plural(cut, "byte")} after it decode as code nothing else reaches";
                    x.Add(Va(b.End), warning, "noreturn_cut");
                    ToolOutput.Warn(warning);
                }
            }
            foreach (var t in graph.TailCalls) x.Add(Va(t), $"tail call to {index.NameAt(t) ?? Va(t)}", "tail_call");
        }

        void Constants(Section x)
        {
            // The masked decoder drops addresses, small counts, all-ones masks and frame sizes.
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
            // capa runs from a survey only, as it reads the whole file for minutes; the dossier shows the labels it kept.
            if (Services.Analysis.NativeCapa.Cached(native.FilePath) is { } capa)
            {
                foreach (var l in capa.Labels)
                    if (l.Addresses.Any(a => capa.Rebase(a, image.ImageBase) is var va && va >= image.ImageBase && va - image.ImageBase <= uint.MaxValue
                                             && index.FunctionAt((uint)(va - image.ImageBase))?.Start == f.Start))
                        x.Add(Va(f.Start), $"capa {l.Name}{(l.Namespace != null ? $" ({l.Namespace})" : "")}" +
                                           string.Concat(l.Attack.Select(t => $"; ATT&CK {t}").Concat(l.Mbc.Select(m => $"; MBC {m}"))), "capa");
            }
            else if (image is Native.Pe.PeFile or Native.Elf.ElfFile && ExternalTools.Locate(ExternalTools.Capa) != null)
                x.Add(null, $"capa labels not read: survey_features image={native.Id} category=capa runs capa", "capa");
        }

        void Params(Section x)
        {
            var arm = Arm64Trace.Supports(index) ? Arm64Trace.For(index) : null;
            if (calls == null && arm == null) { x.Error = $"values are traced in x86 / x64 / ARM64 code; {image.Arch} is not analyzed here"; return; }
            var incoming = IncomingParameters(index, f, ct);
            int count = Math.Clamp(incoming.Count > 0 ? incoming.Max(p => p.Index) + 1 : calls is { Is64: false } ? 2 : 1, 1, MaxParams);
            for (int k = 0; k < count; k++)
            {
                var position = (k + 1).ToString(System.Globalization.CultureInfo.InvariantCulture);
                ITraceHost host = calls != null ? calls : arm!;
                var seed = calls != null ? NativeTraceTools.Seed(calls, Va(f.Start), null, position, ct) : NativeTraceTools.Arm64Seed(arm!, Va(f.Start), null, position, ct);
                var g = ValueTrace.Build(host, seed, new ValueTraceOptions(TraceDirection.Backward, MaxDepth: 1, MaxFunctions: 16, MaxNodes: 200, MaxCallers: 16), ct: ct);
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

    /// <summary>Most parameters the params section traces.</summary>
    private const int MaxParams = 12;

    /// <summary>Parameters a function reads on entry (0-based position, location): argument registers read before written and caller stack slots.</summary>
    internal static List<(int Index, string Location)> IncomingParameters(NativeCodeIndex index, NativeFunction f, CancellationToken ct)
    {
        var found = new SortedDictionary<int, string>();
        if (CallAnalysis.Supports(index))
        {
            var calls = CallAnalysis.For(index);
            var fc = calls.Code(f, ct);
            foreach (var name in ArgumentRegisters(fc, calls))
                if (OursSliceProvider.ParseLocation(name, calls.Is64) is { } r && calls.Slices.ParameterIndex(r) is var k and >= 0) found.TryAdd(k, name);
            int checkedReads = 0;
            for (int b = 0; b < fc.Blocks.Length && checkedReads < 400; b++)
                for (int i = 0; i < fc.Blocks[b].Length && checkedReads < 400; i++)
                {
                    var x = fc.Blocks[b][i].I;
                    if (x.Mnemonic == Mnemonic.Lea || x.MemoryIndex != Register.None || x.MemoryBase.GetFullRegister() is not (Register.RSP or Register.RBP)) continue;
                    if (!Enumerable.Range(0, x.OpCount).Any(k => x.GetOpKind(k) == OpKind.Memory && k > 0 || x.GetOpKind(k) == OpKind.Memory && x.Mnemonic is Mnemonic.Push or Mnemonic.Cmp or Mnemonic.Test))
                        continue;
                    checkedReads++;
                    int disp = (int)(long)x.MemoryDisplacement64;
                    var loc = x.MemoryBase.GetFullRegister() == Register.RSP ? Loc.Stack(disp) : Loc.Frame(disp);
                    var v = new ValueResolver(calls, fc) { Slice = true, Budget = 800 }.ValueBefore(loc, b, i);
                    if (v.Kind != VKind.Incoming) continue;
                    var entry = v.Site != 0 ? Loc.Of((Register)v.Site) : Loc.Stack((int)(long)v.Num);
                    if (calls.Slices.ParameterIndex(entry) is var p and >= 0) found.TryAdd(p, calls.Slices.LocationName(entry));
                }
        }
        else if (Arm64Trace.Supports(index))
        {
            var code = Arm64Trace.For(index).Code(f, ct);
            var written = new HashSet<int>();
            foreach (var s in code.Blocks.OrderBy(b => b.Length > 0 ? b[0].Rva : uint.MaxValue).SelectMany(b => b))
            {
                if (A64Function.IsCall(s.I) || s.Facts.Flow == FlowKind.Return) break;
                for (int k = 0; k < s.I.OperandCount; k++)
                    if (s.I.GetOperand(k) is { Kind: AsmArm64.Arm64OperandKind.Register } op && (op.Flags & AsmArm64.Arm64OperandFlags.Read) != 0
                        && ((AsmArm64.Arm64RegisterOperand)op).Value is { Kind: AsmArm64.Arm64RegisterKind.X or AsmArm64.Arm64RegisterKind.W, Index: < 8 } r && !written.Contains(r.Index))
                        found.TryAdd(r.Index, $"x{r.Index}");
                if (A64Function.Dest(s.I) is { Kind: AsmArm64.Arm64RegisterKind.X or AsmArm64.Arm64RegisterKind.W } d) written.Add(d.Index);
            }
            foreach (var s in code.Blocks.SelectMany(b => b))
                if (Arm64Resolver.IsLoad(s.I) && A64Function.Memory(s) is { Slot: >= 0 and < 8 * 24 and var slot } && slot % 8 == 0)
                    found.TryAdd(8 + slot / 8, A64Function.Name(A64Loc.Slot(slot), null));
        }
        return found.Select(p => (p.Key, p.Value)).ToList();
    }

    /// <summary>"int __cdecl helper(Widget *, int)" from the PDB procedure at <paramref name="start"/>, or null.</summary>
    private static string? PdbPrototype(Native.Pdb.PdbFile pdb, INativeImage image, uint start)
    {
        var proc = pdb.Symbols.FirstOrDefault(s => s.Kind is Native.Pdb.PdbSymbolKind.GlobalProc or Native.Pdb.PdbSymbolKind.LocalProc && s.Rva == start && s.TypeIndex != 0);
        if (proc == null) return null;
        Native.Pdb.PdbTypeModel model;
        try { model = Native.Pdb.PdbTypeModel.Of(pdb, image.Is64Bit ? 8 : 4); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException) { return null; }
        if (model.FunctionTypeOf(proc.TypeIndex) is not (> 0 and var type) || model.Node(type)?.Function is not { } fn) return null;
        var parameters = new List<string>();
        if (fn.This != 0) parameters.Add(model.Spell(fn.This) + " this");
        parameters.AddRange(fn.Parameters.Select(model.Spell));
        if (fn.Variadic) parameters.Add("...");
        return $"{model.Spell(fn.Return)} {fn.Convention} {proc.Name}({string.Join(", ", parameters)})";
    }

    /// <summary>Edges between the graph's blocks minus blocks plus 2 (McCabe).</summary>
    internal static int Cyclomatic(FunctionGraph graph) =>
        graph.Blocks.Sum(b => b.Successors.Count(e => e.Kind != EdgeKind.TailCall && graph.BlockAt(e.To) != null)) - graph.Blocks.Count + 2;

    /// <summary>The argument registers the function reads before it writes them, in address order up to its first call.</summary>
    private static List<string> ArgumentRegisters(FunctionCode fc, CallAnalysis calls)
    {
        Register[] candidates = calls.Is64
            ? [.. calls.Abi.IntArgs, .. Enumerable.Range(0, calls.Abi.FloatArgs).Select(k => Register.XMM0 + k)]
            : [Register.ECX, Register.EDX];
        var written = new HashSet<Register>();
        var read = new List<string>();
        var info = new InstructionInfoFactory();
        var allocations = AllocationPushes(fc, calls);
        foreach (var d in fc.Blocks.OrderBy(b => b.Length > 0 ? b[0].Rva : uint.MaxValue).SelectMany(b => b))
        {
            if (d.I.FlowControl is FlowControl.Call or FlowControl.IndirectCall or FlowControl.Return) break;
            if (allocations.Contains(d.Rva)) continue;
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

    /// <summary>Prologue pushes of volatile registers (MSVC push ecx, clang push rax) that allocate stack; pushes before a call pass arguments.</summary>
    private static HashSet<uint> AllocationPushes(FunctionCode fc, CallAnalysis calls)
    {
        var result = new HashSet<uint>();
        int b = fc.BlockIndexOf(fc.Function.Start);
        if (b < 0) return result;
        Register[] volatiles = calls.Is64 ? calls.Abi.VolatileInts : [Register.EAX, Register.ECX, Register.EDX];
        var candidates = new List<uint>();
        foreach (var d in fc.Blocks[b])
        {
            var i = d.I;
            if (i.Mnemonic == Mnemonic.Push && i.Op0Kind == OpKind.Register)
            {
                if (volatiles.Contains(i.Op0Register)) candidates.Add(d.Rva);
                continue;
            }
            if (i.Mnemonic == Mnemonic.Mov && i.Op0Kind == OpKind.Register && i.Op1Kind == OpKind.Register
                && i.Op0Register.GetFullRegister() == Register.RBP && i.Op1Register.GetFullRegister() == Register.RSP)
                continue;
            if (i.FlowControl is not (FlowControl.Call or FlowControl.IndirectCall)) result.UnionWith(candidates);
            break;
        }
        return result;
    }
}
