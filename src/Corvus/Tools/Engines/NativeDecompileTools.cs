using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Msvc;
using Corvus.Native.Pe;
using Corvus.Native.Providers;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>decompile_native: pseudocode through an engine, single, batch or callers, with the refs footer.</summary>
public sealed partial class NativeAnalysisTools
{
    [Description("One function of the call.")]
    public sealed record DecompileItem(
        [property: Description("The address or name as given.")] string Input,
        [property: Description("Its VA; null when the input is that VA or did not resolve.")] string? Address,
        [property: Description("Start VA of the function decompiled; null when that is the input or address.")] string? Function,
        string? Name,
        [property: Description("ok, error, skipped (time budget or maxFunctions) or duplicate (the same function as an earlier item).")] string Status,
        string? ErrorCode,
        string? Error,
        int Lines,
        int Chars)
    {
        [Description("refs=true: the globals, functions, strings and imports the pseudocode names, in first-use order.")]
        public IReadOnlyList<DecompileRef>? Refs { get; init; }
    }

    public sealed record DecompileRef(string Address, string Name,
        [property: Description("function, import, string or data.")] string Kind,
        [property: Description("A string's text.")] string? Text,
        [property: Description("Uses in the pseudocode (IDA) or references from the function (other engines).")] int Uses);

    public sealed record DecompileReport(
        string Image,
        [property: Description("ida or ghidra.")] string Engine,
        IReadOnlyList<DecompileItem> Items,
        [property: Description("Functions asked for.")] int Inputs,
        int Succeeded,
        int Failed,
        [property: Description("Inputs not reached (maxFunctions or the time budget).")] int Skipped,
        [property: Description("functions / callersOf: offset= of the first input not reached.")] int? NextInput)
    {
        [Description("functions / callersOf: the first input of this call.")] public int? Offset { get; init; }
        [Description("Why this engine answered.")] public string? EngineNote { get; init; }
    }

    /// <summary>A WebAssembly image's lifted pseudocode, one function or several, without an engine (engine=ghidra or ida still asks one).</summary>
    private string WasmDecompile(LoadedNative native, WasmImage wasm, string[] inputs, uint rva, bool batch, int offset, int? maxTokens)
    {
        var items = new List<DecompileItem>();
        var sb = new StringBuilder();
        foreach (var input in batch ? inputs : [inputs[0]])
        {
            try
            {
                uint at = batch ? workspace.Read(() => NativeAddress.Parse(wasm, input, code?.Ready(native) is { } idx ? idx.AddressesOfName : null)) : rva;
                uint function = WasmCodeViews.Function(wasm, at);
                var text = pager.GetOrCreate($"wasm-lift|{wasm.Sha256}|{function}", () => WasmCodeViews.Lifted(wasm, function));
                sb.Append(text).Append('\n');
                items.Add(new DecompileItem(input, NativeAddress.Va(wasm, at), NativeAddress.Va(wasm, wasm.Module.BodyOf(function) is { } b ? (uint)b.Start : at),
                    wasm.FunctionNames[(int)function], "ok", null, null, text.Count(c => c == '\n'), text.Length));
            }
            catch (ToolError e) when (batch)
            {
                sb.Append($"// {input}: {e.Message}\n\n");
                items.Add(new DecompileItem(input, null, null, null, "error", e.Code.ToString(), e.Message, 0, 0));
            }
        }
        int ok = items.Count(i => i.Status == "ok");
        var report = new DecompileReport(native.Id, "ours", items, items.Count, ok, items.Count - ok, 0, null)
        {
            EngineNote = "WebAssembly lifted by the built-in bytecode reader; engine=ghidra asks Ghidra (its WebAssembly extension must be installed)",
        };
        return ToolOutput.Text(pager, sb.ToString(), batch ? 0 : offset, report, maxTokens);
    }

    [McpServerTool(Name = "decompile_native", Title = "Decompile native function", UseStructuredContent = true, OutputSchemaType = typeof(DecompileReport))]
    [Description("C pseudocode of a native function from IDA or Ghidra, with the names, comments and types made here. The first call " +
                 "analyzes the image (seconds to minutes); functions= decompiles several per request.")]
    public Task<string> DecompileNative(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string? address = null,
        [Description("Default auto; all: each installed engine in turn.")] string? engine = null,
        [Description("Prefix lines with their source address.")] bool addresses = false,
        [Description("Character offset; with functions/callersOf the first input (nextInput).")] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        [Description("Several functions instead of address: addresses or names, in order.")] string[]? functions = null,
        [Description("With functions: seconds per function (1-600).")] int perFunctionSeconds = 60,
        [Description("With functions: most decompiled (1-200); the rest follow.")] int maxFunctions = 32,
        [Description("With address: a footer of the globals, functions, strings and imports used.")] bool refs = false,
        [Description("Seconds per engine request (1-600); Ghidra retries once with 4x.")] int? timeoutSeconds = null,
        [Description("Instead of address: decompile the callers of this function (engine references).")] string? callersOf = null,
        [Description("c, or pcode (Ghidra high p-code per block).")] string view = "c",
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        bool callers = !string.IsNullOrWhiteSpace(callersOf);
        bool batch = functions is { Length: > 0 } || callers;
        bool pcode = view.Trim().ToLowerInvariant() switch
        {
            "c" => false,
            "pcode" => true,
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"unknown view '{view}'.", "view=c or view=pcode"),
        };
        if (pcode && (batch || refs || addresses))
            throw new ToolError(ErrorCode.InvalidArgument, "view=pcode takes one address, without refs or addresses.", "pass address alone");
        if ((functions is { Length: > 0 } ? 1 : 0) + (callers ? 1 : 0) + (string.IsNullOrWhiteSpace(address) ? 0 : 1) != 1)
            throw new ToolError(ErrorCode.InvalidArgument, batch ? "Pass one of address, functions or callersOf." : "address is required (or functions / callersOf for several).",
                "address=<one function>, functions=[...] for several, or callersOf=<function>");
        if (timeoutSeconds is { } ts && (ts < 1 || ts > 600))
            throw new ToolError(ErrorCode.InvalidArgument, $"timeoutSeconds {ts} is outside 1-600.", "timeoutSeconds=120");
        TimeSpan? limit = timeoutSeconds is { } t ? TimeSpan.FromSeconds(t) : null;
        using var engineLimit = EngineRequestLimit.Use(limit);
        var native = batch ? await Task.Run(() => ResolveImage(workspace, image), cancellationToken) : null;
        uint rva = 0;
        if (!batch || callers) (native, rva) = await Task.Run(() => Resolve(image, callers ? callersOf! : address!), cancellationToken);
        if (native!.Image is WasmImage wasm && string.IsNullOrWhiteSpace(engine))
            return await Task.Run(() => WasmDecompile(native, wasm, batch && !callers ? functions! : [address ?? callersOf!], rva, batch && !callers, offset, maxTokens), cancellationToken);
        if (string.Equals(engine?.Trim(), AllEngines, StringComparison.OrdinalIgnoreCase))
        {
            if (batch || pcode || refs)
                throw new ToolError(ErrorCode.InvalidArgument, "engine=all takes one address, without functions, callersOf, refs or view=pcode.", "pass address alone");
            return await EachEngine(native!, address!, rva, addresses, offset, maxTokens, limit, progress, cancellationToken);
        }
        var choice = EngineChoice.EngineOnly(engine, engines, native!);
        // An answer stored by another process after the same pushes needs no engine.
        string? setup = !batch && !refs && !pcode && engines.OutputCache != null ? SetupDigest(native!) : null;
        if (setup != null && engines.Answer<DecompileAnswer>(native!, choice.Engine, setup, AnswerKind(addresses), rva) is { } answered)
        {
            EngineReport.Answered(choice, engines);
            EngineReport.Cached(1, 0);
            ToolOutput.Facet("pseudocode");
            return NotesHeader(native!, rva, offset) + answered.Header + ToolOutput.Text(pager, answered.Text, offset,
                new DecompileReport(native!.Id, choice.Engine, [SingleItem(native, address!, rva, answered.Start, answered.Name, answered.Text)], 1, 1, 0, 0, null)
                    { EngineNote = choice.Note }, maxTokens);
        }
        var session = await DecompilerSession(native!, choice.Engine, progress, cancellationToken);
        EngineReport.Answered(choice, engines, session);
        var pushed = await Push(native!, session, cancellationToken);
        if (pcode)
        {
            if (session is not Native.Providers.Ghidra.GhidraSession ghidra)
                throw new ToolError(ErrorCode.Unsupported, $"view=pcode is Ghidra's high p-code; {NativeEngineService.DisplayName(session.ProviderId)} has none here.", "engine=ghidra");
            var p = await ghidra.PcodeAsync(rva, cancellationToken);
            return $"// {p.Name} at {NativeAddress.Va(native!.Image, p.StartRva)}: high p-code (ghidra)\n" + ToolOutput.Text(pager, p.Text, offset,
                new DecompileReport(native.Id, choice.Engine, [SingleItem(native, address!, rva, p.StartRva, p.Name, p.Text)], 1, 1, 0, 0, null) { EngineNote = choice.Note }, maxTokens);
        }
        if (batch)
        {
            if (refs) throw new ToolError(ErrorCode.InvalidArgument, "refs applies to one function (address), not functions.", "drop refs, or decompile one address");
            if (callers) functions = await Callers(native!, session, rva, callersOf!, cancellationToken);
            var (text, report) = await Batch(native!, session, functions!, addresses, Math.Clamp(perFunctionSeconds, 1, 600), Math.Clamp(maxFunctions, 1, 200), offset, cancellationToken);
            // Here offset counts inputs.
            return ToolOutput.Report(pushed + text, report with { EngineNote = choice.Note });
        }
        var (single, functionStart, name) = await Single(native!, session, rva, addresses, limit, progress, cancellationToken);
        // Take the digest after the open: a PDB the engine fetched during it is part of this answer's state.
        if (setup != null) engines.Remember(native!, session, SetupDigest(native!), AnswerKind(addresses), rva, new DecompileAnswer(pushed, single, functionStart, name));
        (string Text, List<DecompileRef> Items)? objects = refs
            ? await References(native!, session, TextKey(native!, session, rva, addresses) + "|refs", functionStart ?? rva, cancellationToken)
            : null;
        var item = SingleItem(native!, address!, rva, functionStart, name, single) with { Refs = objects?.Items };
        ToolOutput.Facet("pseudocode");
        return NotesHeader(native!, rva, offset) + pushed + ToolOutput.Text(pager, single, offset, new DecompileReport(native!.Id, session.ProviderId, [item], 1, 1, 0, 0, null)
            { EngineNote = choice.Note }, maxTokens) + (offset == 0 && objects != null ? objects.Value.Text : "");
    });

    /// <summary>The engine value that decompiles with each installed engine in turn.</summary>
    private const string AllEngines = "all";

    /// <summary>The engine's session; unsupported when its decompiler cannot read this architecture.</summary>
    private async Task<INativeDecompilerSession> DecompilerSession(LoadedNative native, string engine, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var session = await engines.Session(native, engine, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), ct);
        if (!session.DecompilerAvailable)
            throw new ToolError(ErrorCode.Unsupported, $"The {session.ProviderId} decompiler is not available for {session.Arch} code here.",
                "disassemble the function instead, or install/license the decompiler for this architecture");
        return session;
    }

    /// <summary>One function's pseudocode text (cached per push state), its start and the name in effect.</summary>
    private async Task<(string Text, uint? Start, string? Name)> Single(LoadedNative native, INativeDecompilerSession session, uint rva, bool addresses,
        TimeSpan? limit, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        if (types != null) await types.EnsureMethodAsync(native, session, code?.Ready(native)?.FunctionAt(rva)?.Start ?? rva, ct);
        DecompiledFunction? decompiled = null;
        string text;
        using (EngineReport.Heartbeat(progress, $"{session.ProviderId} decompiling {NativeAddress.Va(native.Image, rva)}"))
        {
            try
            {
                text = pager.GetOrCreate(TextKey(native, session, rva, addresses), () =>
                {
                    decompiled = session.DecompileWithinAsync(rva, limit, ct).GetAwaiter().GetResult();
                    return FunctionText(native, session, decompiled, addresses);
                });
            }
            catch (ToolError e) when (e.Code == ErrorCode.NotFound && code?.Ready(native)?.FunctionAt(rva) is { } ours)
            {
                // The engine has no function there but the built-in analysis has; say how to make one.
                var other = session.ProviderId == "ida" ? "ghidra" : "ida";
                throw new ToolError(ErrorCode.NotFound, $"{e.Message} ({NativeEngineService.DisplayName(session.ProviderId)}); the built-in analysis has a function at " +
                    $"{NativeAddress.Va(native.Image, ours.Start)}.",
                    $"define_native image={native.Id} address={NativeAddress.Va(native.Image, ours.Start)} kind=function engine={session.ProviderId} makes it, or engine={other}")
                    { Details = e.Details };
            }
        }
        uint? start = decompiled?.StartRva ?? code?.Ready(native)?.FunctionAt(rva)?.Start;
        return (text, start, FunctionName(native, start, decompiled?.Name));
    }

    /// <summary>engine=all: one item per installed engine in turn; a failing engine is its item's error; provider_unavailable without any.</summary>
    private async Task<string> EachEngine(LoadedNative native, string address, uint rva, bool addresses, int offset, int? maxTokens, TimeSpan? limit,
        IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var sb = new StringBuilder(NotesHeader(native, rva, offset));
        var items = new List<DecompileItem>();
        List<string> used = [], missing = [];
        foreach (var id in engines.ProviderIds)
        {
            if (engines.UnavailabilityOf(id) is { } u) { missing.Add($"{NativeEngineService.DisplayName(id)} not available ({u.Reason})"); continue; }
            used.Add(id);
            try
            {
                var session = await DecompilerSession(native, id, progress, ct);
                var pushed = await Push(native, session, ct);
                var (text, start, name) = await Single(native, session, rva, addresses, limit, progress, ct);
                sb.Append(pushed).Append(text).Append('\n');
                items.Add(SingleItem(native, address, rva, start, name, text));
            }
            catch (ToolError e)
            {
                sb.Append($"// {id}: {ToolError.CodeName(e.Code)}: {e.Message}\n\n");
                items.Add(new DecompileItem(address, NativeAddress.Va(native.Image, rva), null, null, "error", ToolError.CodeName(e.Code), e.Message, 0, 0));
            }
        }
        if (used.Count == 0)
        {
            var u = engines.Unavailability!.Value;
            throw new ToolError(ErrorCode.ProviderUnavailable, $"No native decompiler engine is available: {u.Reason}", u.Remediation);
        }
        ToolOutput.Facet("pseudocode");
        int ok = items.Count(i => i.Status == "ok");
        var note = $"engine=all: {string.Join(", ", used)}, one item each in that order" + (missing.Count > 0 ? "; " + string.Join("; ", missing) : "");
        return ToolOutput.Text(pager, sb.ToString(), offset,
            new DecompileReport(native.Id, AllEngines, items, used.Count, ok, used.Count - ok, 0, null) { EngineNote = note }, maxTokens);
    }

    /// <summary>One function's pseudocode as served without an engine: the stable header, the text, its start and name.</summary>
    internal sealed record DecompileAnswer(string Header, string Text, uint? Start, string? Name);

    private static string AnswerKind(bool addresses) => addresses ? "decompile-text-addresses" : "decompile-text";

    /// <summary>The name in effect at a function start (user, PDB, ..., the engine's last), the same in every call and tool.</summary>
    private string? FunctionName(LoadedNative native, uint? start, string? engineName) =>
        (start is { } s && code?.Ready(native)?.NameAt(s) is { } known ? known : engineName) is { } shown ? NativeTools.DisplayName(shown, native.Image.Format) : null;

    private static DecompileItem SingleItem(LoadedNative native, string input, uint rva, uint? start, string? name, string text) =>
        new(input, NativeAddress.Va(native.Image, rva), start is { } s ? NativeAddress.Va(native.Image, s) : null, name, "ok", null, null, text.Count(c => c == '\n'), text.Length);

    /// <summary>The open notes on the function, as the first lines of its first page.</summary>
    private string NotesHeader(LoadedNative native, uint rva, int offset)
    {
        if (notes == null || offset != 0) return "";
        var fn = code?.Ready(native)?.FunctionAt(rva);
        uint start = fn?.Start ?? rva, end = fn != null ? fn.Start + Math.Max(1u, fn.Size) : rva + 1;
        return NotesService.Header(notes.OpenCount(native.OriginalSha256.ToLowerInvariant(), a => a.Kind == NoteAnchor.Native && a.Rva >= start && a.Rva < end),
            $"{native.Id}@{NativeAddress.Va(native.Image, start)}");
    }

    private string SetupDigest(LoadedNative native) =>
        EngineReport.SetupDigest(native, code, notes != null ? NoteMarks.Digest(native, notes) : "", types != null, userTypes != null, names != null);

    /// <summary>Most objects the refs footer lists.</summary>
    private const int MaxRefs = 200;

    private readonly Dictionary<string, (string, List<DecompileRef>)> _refs = [];

    /// <summary>The refs footer and its rows: IDA's ctree objects, or the targets of the function's references in other engines.</summary>
    private async Task<(string Text, List<DecompileRef> Items)> References(LoadedNative native, INativeDecompilerSession session, string key, uint start, CancellationToken ct)
    {
        lock (_refs) if (_refs.TryGetValue(key, out var cached)) return cached;
        var index = code?.Ready(native);
        var image = native.Image;
        var imports = image.Imports.GroupBy(i => i.SlotRva).ToDictionary(g => g.Key, g => g.First());
        var objects = await NativeEngineQueries.DecompileRefs(session, start, ct);
        if (objects == null)
        {
            var functions = (await session.ListFunctionsAsync(ct)).GroupBy(f => f.StartRva).ToDictionary(g => g.Key, g => g.First());
            var self = functions.GetValueOrDefault(start);
            objects = (await session.GetXrefsFromAsync(start, wholeFunction: true, ct))
                .Where(x => self == null || x.ToRva < start || x.ToRva >= self.EndRva)
                .Where(x => x.Kind is not (NativeXrefKind.Jump or NativeXrefKind.Code) || functions.ContainsKey(x.ToRva))
                .GroupBy(x => x.ToRva).OrderBy(g => g.Min(x => x.FromRva))
                .Select(g => new NativeEngineQueries.PseudocodeObject(g.Key, functions.GetValueOrDefault(g.Key)?.Name ?? "", null, g.Count(), functions.ContainsKey(g.Key)))
                .ToList();
        }
        var items = new List<DecompileRef>();
        foreach (var o in objects)
        {
            var name = (imports.TryGetValue(o.Rva, out var imp) ? Native.Code.NativeCodeIndex.ImportName(imp) : null) ?? index?.NameAt(o.Rva) ?? (o.Name.Length > 0 ? o.Name : NativeAddress.Va(image, o.Rva));
            var text = o.Text ?? (index?.StringAt(o.Rva) is { } s ? index.ReadString(s, 400) : index == null && !o.Function && !imports.ContainsKey(o.Rva) ? ImageString(image, o.Rva) : null);
            var kind = imports.ContainsKey(o.Rva) ? "import" : o.Function ? "function" : text != null ? "string" : "data";
            items.Add(new DecompileRef(NativeAddress.Va(image, o.Rva), kind == "import" ? name : NativeTools.DisplayName(name, image.Format), kind, text, o.Uses));
        }
        var sb = new StringBuilder($"// refs: {(items.Count == 0 ? "none" : string.Join(", ", items.GroupBy(i => i.Kind).Select(g => Plural(g.Count(), g.Key))))}" +
                                   (session is Native.Providers.Ida.IdaSession ? "" : $" (from {session.ProviderId}'s references)") + "\n");
        foreach (var i in items.Take(MaxRefs))
            sb.Append($"//   {i.Kind,-8}  {i.Address}  {(i.Text != null ? Quote(i.Text) : i.Name)}{(i.Uses > 1 ? $"  x{i.Uses}" : "")}").Append('\n');
        if (items.Count > MaxRefs) sb.Append($"//   ... {items.Count - MaxRefs} more (structured refs has all)").Append('\n');
        var result = (sb.ToString(), items);
        lock (_refs)
        {
            // Bounded; footers are cheap to rebuild.
            if (_refs.Count >= 256) _refs.Clear();
            _refs[key] = result;
        }
        return result;
    }

    /// <summary>A string literal at <paramref name="rva"/> read from the image (no code index yet): 4+ printable ASCII or UTF-16 characters, terminated; else null.</summary>
    internal static string? ImageString(INativeImage image, uint rva)
    {
        if (image.SectionAt(rva) is not { } section || section.IsExecutable) return null;
        var bytes = new byte[802];
        int n = image.Read(rva, bytes);
        static bool Printable(int c) => c is >= 0x20 and < 0x7F or 9 or 10 or 13;
        int ascii = 0;
        while (ascii < n && Printable(bytes[ascii])) ascii++;
        if (ascii >= 4 && ascii < n && bytes[ascii] == 0) return Encoding.ASCII.GetString(bytes, 0, ascii);
        int wide = 0;
        while (2 * wide + 1 < n && bytes[2 * wide + 1] == 0 && Printable(bytes[2 * wide])) wide++;
        if (wide >= 4 && 2 * wide + 1 < n && bytes[2 * wide] == 0 && bytes[2 * wide + 1] == 0) return Encoding.Unicode.GetString(bytes, 0, 2 * wide);
        return null;
    }

    private static string Quote(string text) =>
        "\"" + Format.Clip(text.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r").Replace("\t", "\\t"), 120) + "\"";

    /// <summary>Pushes names and types into the session; returns the stable header lines, with each push's details in _meta.</summary>
    private async Task<string> Push(LoadedNative native, INativeDecompilerSession session, CancellationToken ct)
    {
        var pdb = NativePdbTypes.Report(session);
        EngineReport.Pushed(NativePdbTypes.Describe(pdb));
        if (names != null) EngineReport.Pushed(NativeNamePush.Describe(await names.EnsureAsync(native, session, ct)));
        if (notes != null) EngineReport.Pushed(NoteMarks.Describe(await NoteMarks.EnsureAsync(native, session, notes, ct), session.ProviderId));
        if (types != null) EngineReport.Pushed(NativeTypePush.Describe(await types.EnsureAsync(native, session, ct)));
        if (userTypes != null) EngineReport.Pushed(NativeUserTypePush.Describe(await userTypes.EnsureAsync(native, session, ct)));
        var sb = new StringBuilder();
        if (TypeSource(pdb) is { } source) sb.Append("// types: ").Append(source).Append('\n');
        if (native.HasPatches)
            sb.Append("// ").Append(engines.ServesPatchedCopy(native, session.ProviderId)
                ? $"patched image: analyzed as a patched copy (the database could not take {Plural(native.Patches.Patches.Count, "patch")})"
                : $"patched image: {Plural(native.Patches.Patches.Count, "patch")} applied in the database").Append('\n');
        return sb.ToString();
    }

    /// <summary>Where the pseudocode's types come from, the same on every call: the PDB and its loader, or null without a PDB.</summary>
    internal static string? TypeSource(NativePdbTypes.PdbTypeSource? r) => r switch
    {
        null => null,
        { Route: null } => $"the PDB {Path.GetFileName(r.PdbPath)} could not be applied; the engine's own types",
        _ => $"{(r.Route == NativePdbTypes.RouteDwarf ? "DWARF" : "PDB")} {Path.GetFileName(r.PdbPath)} via " + r.Route switch
        {
            NativePdbTypes.RouteIda => "IDA's PDB loader",
            NativePdbTypes.RouteGhidra => "Ghidra's PDB loader",
            NativePdbTypes.RouteDwarf => "the server's DWARF reader",
            _ => "the server's PDB type reader",
        },
    };

    /// <summary>The text cache key of one function's pseudocode: single and batch calls share it; push stamps are equal across engines.</summary>
    internal static string TextKey(LoadedNative native, INativeDecompilerSession session, uint rva, bool addresses) =>
        $"decompile|{session.ProviderId}|{native.Image.Sha256}|{rva:X}|{addresses}|{NativeNamePush.CurrentStamp(session)}|{NativeTypePush.CurrentStamp(session)}|" +
        $"{NativePdbTypes.CurrentStamp(session)}|{NativeUserTypePush.CurrentStamp(session)}|{EngineControl.Generation(session)}";

    private string FunctionText(LoadedNative native, INativeDecompilerSession session, DecompiledFunction function, bool addresses)
    {
        var lines = function.Text.Split('\n');
        var byLine = function.LineAddresses.GroupBy(l => l.Line).ToDictionary(g => g.Key, g => g.Min(l => l.Rva));
        // The name in effect, as list_functions and search_decompiled show it.
        var (display, symbol) = NativeTools.Named(code?.Ready(native)?.NameAt(function.StartRva) ?? function.Name, native.Image.Format);
        // One stable header line; open time and saved-analysis state go in _meta.
        var sb = new StringBuilder($"// {display} at {NativeAddress.Va(native.Image, function.StartRva)} ({session.ProviderId}" +
                                   $"{(session.DatabaseNote is { } note ? ", " + note : "")}{symbol})\n");
        for (int i = 0; i < lines.Length; i++)
            sb.Append(addresses ? (byLine.TryGetValue(i, out var at) ? $"/* {native.Image.ImageBase + at:X} */ " : new string(' ', 6 + 16 - 2)) : "")
              .Append(lines[i].TrimEnd('\r')).Append('\n');
        return sb.ToString();
    }

    /// <summary>Several functions in one engine request; a bad input is its item's error, duplicates are marked, cached texts reused.</summary>
    private async Task<(string Text, DecompileReport Report)> Batch(LoadedNative native, INativeDecompilerSession session, string[] inputs, bool addresses,
        int perItem, int max, int start, CancellationToken ct)
    {
        if (start < 0 || start > inputs.Length)
            throw new ToolError(ErrorCode.InvalidArgument, $"offset {start} is outside the {inputs.Length} inputs.", "offset=0, or the nextOffset of the previous result");
        var image = native.Image;
        var index = code?.Ready(native);
        string Va(uint r) => NativeAddress.Va(image, r);
        int n = inputs.Length;
        var rvas = new uint?[n];
        var errors = new (string Code, string Message)?[n];
        var starts = new uint?[n];
        for (int i = 0; i < n; i++)
        {
            try
            {
                rvas[i] = NativeAddress.Parse(image, inputs[i], index != null ? index.AddressesOfName : null);
                starts[i] = index?.FunctionAt(rvas[i]!.Value)?.Start;
            }
            catch (ToolError e) { errors[i] = (ToolError.CodeName(e.Code), e.Message); }
        }
        var status = new string[n];
        var texts = new string?[n];
        var outcomes = new DecompileOutcome?[n];
        var firstOf = new Dictionary<uint, int>();
        var asked = new List<int>();
        int taken = 0;
        for (int i = start; i < n; i++)
        {
            if (errors[i] != null) { status[i] = "error"; continue; }
            if (starts[i] is { } s && firstOf.ContainsKey(s)) { status[i] = "duplicate"; continue; }
            if (taken >= max) { status[i] = "skipped"; continue; }
            taken++;
            if (starts[i] is { } st) firstOf[st] = i;
            if (pager.TryGet(TextKey(native, session, rvas[i]!.Value, addresses), out var cached)) { texts[i] = cached; status[i] = "ok"; continue; }
            asked.Add(i);
        }
        if (asked.Count > 0)
        {
            if (types != null)
                foreach (var i in asked) await types.EnsureMethodAsync(native, session, starts[i] ?? rvas[i]!.Value, ct);
            var results = await session.DecompileManyAsync(asked.Select(i => rvas[i]!.Value).ToList(), perItem, (double)perItem * asked.Count, ct);
            for (int k = 0; k < asked.Count; k++)
            {
                int i = asked[k];
                var o = k < results.Count ? results[k] : new DecompileOutcome(rvas[i]!.Value, DecompileStatus.Skipped, null, null, null);
                outcomes[i] = o;
                status[i] = o.Status switch { DecompileStatus.Ok => "ok", DecompileStatus.Skipped => "skipped", _ => "error" };
                if (o.Function is not { } f) continue;
                // Without the code index, duplicates show only in the engine's answer.
                if (starts[i] == null && firstOf.TryGetValue(f.StartRva, out int earlier) && earlier != i) { status[i] = "duplicate"; starts[i] = f.StartRva; continue; }
                starts[i] = f.StartRva;
                firstOf.TryAdd(f.StartRva, i);
                texts[i] = FunctionText(native, session, f, addresses);
                pager.GetOrCreate(TextKey(native, session, rvas[i]!.Value, addresses), () => texts[i]!);
            }
        }

        // Inputs from the first skipped one on belong to the next call; skipped ones are counted, not listed.
        int firstSkipped = Enumerable.Range(start, n - start).Where(i => status[i] == "skipped").DefaultIfEmpty(-1).First();
        int end = firstSkipped >= 0 ? firstSkipped : n;
        var items = new List<DecompileItem>(end - start);
        var sb = new StringBuilder();
        for (int i = start; i < end; i++)
        {
            var o = outcomes[i];
            var name = FunctionName(native, starts[i], o?.Function?.Name);
            var where = starts[i] is { } st ? Va(st) : rvas[i] is { } r ? Va(r) : null;
            bool same = string.Equals(where, inputs[i], StringComparison.OrdinalIgnoreCase);
            var head = $"// [{i + 1}/{n}] {name ?? where ?? inputs[i]}{(where != null && name != null ? $" at {where}" : "")}{(same ? "" : $" (input \"{inputs[i]}\")")}";
            string? code = null, message = null;
            switch (status[i])
            {
                case "ok":
                    sb.Append(head).Append('\n').Append(texts[i]).Append('\n');
                    ToolOutput.Facet("pseudocode");
                    break;
                case "duplicate":
                    var first = Array.FindIndex(starts, x => x == starts[i]);
                    sb.Append($"{head}: the same function as [{first + 1}]").Append('\n');
                    break;
                default:
                    (code, message) = errors[i] ?? (o?.ErrorCode ?? "failed", o?.Error ?? "failed");
                    sb.Append($"{head}: error {code}: {message}").Append('\n');
                    if (status[i] == "error") ToolOutput.Facet("pseudocode", $"{inputs[i]}: {message}");
                    break;
            }
            // callersOf inputs are the callers' start VAs; drop repeats of the same VA.
            var address = rvas[i] is { } a ? Va(a) : null;
            var function = starts[i] is { } fs ? Va(fs) : null;
            if (string.Equals(address, inputs[i], StringComparison.OrdinalIgnoreCase)) address = null;
            if (function != null && (string.Equals(function, inputs[i], StringComparison.OrdinalIgnoreCase) || function == address)) function = null;
            items.Add(new DecompileItem(inputs[i], address, function, name, status[i], code, message,
                texts[i]?.Count(c => c == '\n') ?? 0, texts[i]?.Length ?? 0));
        }
        int ok = items.Count(x => x.Status == "ok"), failed = items.Count(x => x.Status == "error"), skipped = n - end;
        var summary = $"// {Plural(n, "input")}" + (start > 0 ? $" from offset {start}" : "") + $": {ok} decompiled, {failed} failed, {skipped} not reached, " +
                      $"{items.Count(x => x.Status == "duplicate")} duplicate ({session.ProviderId})\n";
        if (skipped > 0)
            sb.Append($"// {Plural(skipped, "input")} not reached ({(outcomes[end] != null ? "time budget used" : $"maxFunctions={max}")}) [More: offset={end}]\n");
        return (summary + sb, new DecompileReport(native.Id, session.ProviderId, items, n, ok, failed, skipped, skipped > 0 ? end : null) { Offset = start });
    }

    /// <summary>callersOf: functions that call or tail-jump to the function at <paramref name="rva"/>, in address order.</summary>
    private async Task<string[]> Callers(LoadedNative native, INativeDecompilerSession session, uint rva, string input, CancellationToken ct)
    {
        var all = await session.ListFunctionsAsync(ct);
        var target = all.FirstOrDefault(f => rva >= f.StartRva && rva < f.EndRva)?.StartRva ?? code?.Ready(native)?.FunctionAt(rva)?.Start ?? rva;
        var callers = (await session.GetXrefsToAsync(target, ct))
            .Where(x => x.Kind is NativeXrefKind.Call or NativeXrefKind.Jump && x.FromFunctionRva is { } from && from != target)
            .Select(x => x.FromFunctionRva!.Value).Distinct().Order().ToList();
        if (callers.Count == 0)
            throw new ToolError(ErrorCode.NotFound, $"The {session.ProviderId} analysis has no calls to {input} ({NativeAddress.Va(native.Image, target)}).",
                $"find_xrefs image={native.Id} address={NativeAddress.Va(native.Image, target)} lists every reference, including data and indirect ones");
        return [.. callers.Select(c => NativeAddress.Va(native.Image, c))];
    }
}
