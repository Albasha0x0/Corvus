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
        [property: Description("Its VA; null when it did not resolve.")] string? Address,
        [property: Description("Start VA of the function decompiled.")] string? Function,
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
        int Skipped,
        [property: Description("The call that decompiles the skipped items, when there are any.")] string? Next)
    {
        [Description("Why this engine answered.")] public string? EngineNote { get; init; }
    }

    [McpServerTool(Name = "decompile_native", Title = "Decompile native function", UseStructuredContent = true, OutputSchemaType = typeof(DecompileReport))]
    [Description("C pseudocode of the native function at an address, via IDA (Hex-Rays) or Ghidra. The first call runs the engine's " +
                 "auto-analysis (seconds to minutes); the database is kept per file hash. Names, comments, PDB types and prototypes are pushed " +
                 "first (the first line names the type source); user types win. functions=: several in one request, each within " +
                 "perFunctionSeconds; a failure affects only its item.")]
    public Task<string> DecompileNative(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription + " Required unless functions is given.")] string? address = null,
        [Description(EngineChoice.EngineOnlyDescription)] string? engine = null,
        [Description("Prefix each line with the address it was generated from.")] bool addresses = false,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        [Description("Several functions instead of address: addresses or names, in the order wanted.")] string[]? functions = null,
        [Description("With functions: seconds per function (1-600).")] int perFunctionSeconds = 60,
        [Description("With functions: most decompiled (1-200); the rest get a follow-up call.")] int maxFunctions = 32,
        [Description("With address: a footer listing the globals, functions, strings and imports used.")] bool refs = false,
        [Description("Seconds per engine request (1-600; default CORVUS_ENGINE_REQUEST_TIMEOUT); Ghidra retries once with 4x.")] int? timeoutSeconds = null,
        [Description("Instead of address: decompile the functions calling this one (engine references).")] string? callersOf = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        bool callers = !string.IsNullOrWhiteSpace(callersOf);
        bool batch = functions is { Length: > 0 } || callers;
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
        var choice = EngineChoice.EngineOnly(engine, engines, native!);
        var session = await engines.Session(native!, choice.Engine, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
        EngineReport.Answered(choice, engines, session);
        if (!session.DecompilerAvailable)
            throw new ToolError(ErrorCode.Unsupported, $"The {session.ProviderId} decompiler is not available for {session.Arch} code here.",
                "disassemble the function instead, or install/license the decompiler for this architecture");
        var pushed = await Push(native!, session, cancellationToken);
        if (batch)
        {
            if (refs) throw new ToolError(ErrorCode.InvalidArgument, "refs applies to one function (address), not functions.", "drop refs, or decompile one address");
            if (callers) functions = await Callers(native!, session, rva, callersOf!, cancellationToken);
            var (text, report) = await Batch(native!, session, functions!, addresses, Math.Clamp(perFunctionSeconds, 1, 600), Math.Clamp(maxFunctions, 1, 200), cancellationToken);
            return pushed + ToolOutput.Text(pager, text, offset, report with { EngineNote = choice.Note }, maxTokens);
        }
        if (types != null) await types.EnsureMethodAsync(native!, session, code?.Ready(native!)?.FunctionAt(rva)?.Start ?? rva, cancellationToken);
        DecompiledFunction? decompiled = null;
        var single = pager.GetOrCreate(TextKey(native!, session, rva, addresses), () =>
        {
            decompiled = session.DecompileWithinAsync(rva, limit, cancellationToken).GetAwaiter().GetResult();
            return FunctionText(native!, session, decompiled, addresses);
        });
        string header = "";
        if (notes != null && offset == 0)
        {
            var fn = code?.Ready(native!)?.FunctionAt(rva);
            uint start = fn?.Start ?? rva, end = fn != null ? fn.Start + Math.Max(1u, fn.Size) : rva + 1;
            header = NotesService.Header(notes.OpenCount(native!.OriginalSha256.ToLowerInvariant(), a => a.Kind == NoteAnchor.Native && a.Rva >= start && a.Rva < end),
                $"{native.Id}@{NativeAddress.Va(native.Image, start)}");
        }
        var known = code?.Ready(native!)?.FunctionAt(rva);
        uint? functionStart = decompiled?.StartRva ?? known?.Start;
        (string Text, List<DecompileRef> Items)? objects = refs
            ? await References(native!, session, TextKey(native!, session, rva, addresses) + "|refs", functionStart ?? rva, cancellationToken)
            : null;
        var item = new DecompileItem(address!, NativeAddress.Va(native!.Image, rva), functionStart is { } fs ? NativeAddress.Va(native.Image, fs) : null,
            (decompiled?.Name ?? known?.Name) is { } shown ? NativeTools.DisplayName(shown, native.Image.Format) : null, "ok", null, null, single.Count(c => c == '\n'), single.Length)
            { Refs = objects?.Items };
        return header + pushed + ToolOutput.Text(pager, single, offset, new DecompileReport(native.Id, session.ProviderId, [item], 1, 1, 0, 0, null) { EngineNote = choice.Note },
            maxTokens) + (offset == 0 && objects != null ? objects.Value.Text : "");
    });

    /// <summary>Most objects the refs footer lists.</summary>
    private const int MaxRefs = 200;

    private readonly Dictionary<string, (string, List<DecompileRef>)> _refs = [];

    /// <summary>
    /// The refs footer of a function and its rows, cached under the pseudocode's key: IDA lists the ctree's objects; other
    /// engines the targets of the function's references (calls and data, not jumps inside it).
    /// </summary>
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
            if (_refs.Count >= 256) _refs.Clear(); // a bounded cache: footers are cheap to rebuild
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

    /// <summary>
    /// Pushes names, recovered and user types into the session (each once per change). Returns the stable header lines
    /// (the type source, a patched image); what each push did goes to _meta, as it differs between the first call and later ones.
    /// </summary>
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
        _ => $"PDB {Path.GetFileName(r.PdbPath)} via " + r.Route switch
        {
            NativePdbTypes.RouteIda => "IDA's PDB loader",
            NativePdbTypes.RouteGhidra => "Ghidra's PDB loader",
            _ => "the server's PDB type reader",
        },
    };

    /// <summary>The text cache key of one function's pseudocode: single and batch calls share it; push stamps are equal across engines.</summary>
    internal static string TextKey(LoadedNative native, INativeDecompilerSession session, uint rva, bool addresses) =>
        $"decompile|{session.ProviderId}|{native.Image.Sha256}|{rva:X}|{addresses}|{NativeNamePush.CurrentStamp(session)}|{NativeTypePush.CurrentStamp(session)}|" +
        $"{NativePdbTypes.CurrentStamp(session)}|{NativeUserTypePush.CurrentStamp(session)}|{EngineControl.Generation(session)}";

    private static string FunctionText(LoadedNative native, INativeDecompilerSession session, DecompiledFunction function, bool addresses)
    {
        var lines = function.Text.Split('\n');
        var byLine = function.LineAddresses.GroupBy(l => l.Line).ToDictionary(g => g.Key, g => g.Min(l => l.Rva));
        var (display, symbol) = NativeTools.Named(function.Name, native.Image.Format);
        // one stable header line: open time and saved-analysis state are in _meta
        var sb = new StringBuilder($"// {display} at {NativeAddress.Va(native.Image, function.StartRva)} ({session.ProviderId}" +
                                   $"{(session.DatabaseNote is { } note ? ", " + note : "")}{symbol})\n");
        for (int i = 0; i < lines.Length; i++)
            sb.Append(addresses ? (byLine.TryGetValue(i, out var at) ? $"/* {native.Image.ImageBase + at:X} */ " : new string(' ', 6 + 16 - 2)) : "")
              .Append(lines[i].TrimEnd('\r')).Append('\n');
        return sb.ToString();
    }

    /// <summary>
    /// Several functions in one engine request: inputs resolve one by one (a bad one is its item's error), duplicates of an
    /// earlier function are marked, texts already cached are reused, and the engine's per-item outcomes are kept as they come.
    /// </summary>
    private async Task<(string Text, DecompileReport Report)> Batch(LoadedNative native, INativeDecompilerSession session, string[] inputs, bool addresses,
        int perItem, int max, CancellationToken ct)
    {
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
        for (int i = 0; i < n; i++)
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
                // without the code index, duplicates show only in the engine's answer
                if (starts[i] == null && firstOf.TryGetValue(f.StartRva, out int earlier) && earlier != i) { status[i] = "duplicate"; starts[i] = f.StartRva; continue; }
                starts[i] = f.StartRva;
                firstOf.TryAdd(f.StartRva, i);
                texts[i] = FunctionText(native, session, f, addresses);
                pager.GetOrCreate(TextKey(native, session, rvas[i]!.Value, addresses), () => texts[i]!);
            }
        }

        var items = new List<DecompileItem>(n);
        var sb = new StringBuilder();
        var skipped = new List<string>();
        for (int i = 0; i < n; i++)
        {
            var o = outcomes[i];
            var name = (o?.Function?.Name ?? (starts[i] is { } s ? index?.NameAt(s) : null)) is { } symbol ? NativeTools.DisplayName(symbol, image.Format) : null;
            var where = starts[i] is { } st ? Va(st) : rvas[i] is { } r ? Va(r) : null;
            var head = $"// [{i + 1}/{n}] {name ?? where ?? inputs[i]}{(where != null && name != null ? $" at {where}" : "")} (input \"{inputs[i]}\")";
            string? code = null, message = null;
            switch (status[i])
            {
                case "ok":
                    sb.Append(head).Append('\n').Append(texts[i]).Append('\n');
                    break;
                case "duplicate":
                    var first = Array.FindIndex(starts, x => x == starts[i]);
                    sb.Append($"{head}: the same function as [{first + 1}]").Append('\n');
                    break;
                case "skipped":
                    skipped.Add(inputs[i]);
                    sb.Append($"{head}: skipped ({(outcomes[i] != null ? "time budget used" : $"maxFunctions={max}")})").Append('\n');
                    break;
                default:
                    (code, message) = errors[i] ?? (o?.ErrorCode ?? "failed", o?.Error ?? "failed");
                    sb.Append($"{head}: error {code}: {message}").Append('\n');
                    break;
            }
            items.Add(new DecompileItem(inputs[i], rvas[i] is { } a ? Va(a) : null, starts[i] is { } fs ? Va(fs) : null, name, status[i], code, message,
                texts[i]?.Count(c => c == '\n') ?? 0, texts[i]?.Length ?? 0));
        }
        int ok = items.Count(x => x.Status == "ok"), failed = items.Count(x => x.Status == "error");
        string? next = skipped.Count > 0
            ? $"decompile_native image={native.Id} functions=[{string.Join(", ", skipped.Select(x => $"\"{x}\""))}]"
            : null;
        var summary = $"// {Plural(n, "input")}: {ok} decompiled, {failed} failed, {skipped.Count} skipped, {items.Count(x => x.Status == "duplicate")} duplicate ({session.ProviderId})\n";
        if (next != null) sb.Append($"// Next: {next}").Append('\n');
        return (summary + sb, new DecompileReport(native.Id, session.ProviderId, items, n, ok, failed, skipped.Count, next));
    }

    /// <summary>
    /// callersOf: the functions with a call (or a tail-call jump) to the start of the function at <paramref name="rva"/>, by the
    /// engine's references, as batch inputs in address order.
    /// </summary>
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
