using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Msvc;
using NetDecompilerMcp.Native.Pe;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

/// <summary>Native analysis built on the PE model: decompilation through an engine, C++ classes, P/Invoke checks.</summary>
[McpServerToolType]
public sealed class NativeAnalysisTools(AssemblyWorkspace workspace, NativeEngineService engines, OutputPager pager, NativeNamePush? names = null,
    NativeCodeService? code = null, NativeTypePush? types = null, NativeUserTypePush? userTypes = null, NotesService? notes = null)
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
        int Total,
        int Succeeded,
        int Failed,
        int Skipped,
        [property: Description("The call that decompiles the skipped items, when there are any.")] string? Next);

    [McpServerTool(Name = "decompile_native", Title = "Decompile native function", UseStructuredContent = true, OutputSchemaType = typeof(DecompileReport))]
    [Description("C pseudocode of the native function containing an address, through IDA (Hex-Rays) or Ghidra. The first call on an image runs the engine's auto-analysis (seconds to " +
                 "minutes, with progress) and keeps the database per file hash. Names and comments in effect " +
                 "(rename_native, comment_native, Il2Cpp, PDB) are pushed first, once per change. A PDB (beside the image, in " +
                 "the symbol cache, or from load_pdb) has its types and prototypes loaded once through the engine's PDB loader (else the server's " +
                 "reader); the first line names the type source. User types (declare_native_types, set_native_type, set_native_local, " +
                 "set_native_stack_var) apply last and win. functions decompiles several in one request: deduplicated, each within " +
                 "perFunctionSeconds; a failure affects only its item.")]
    public Task<string> DecompileNative(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription + " Required unless functions is given.")] string? address = null,
        [Description("auto (default: an engine open on this image, else IDA, else Ghidra; or the server's --engine), ida or ghidra.")] string? engine = null,
        [Description("Prefix each line with the address it was generated from.")] bool addresses = false,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        [Description("Several functions instead of address: addresses or names, in the order wanted.")] string[]? functions = null,
        [Description("With functions: seconds per function (default 60, 1-600).")] int perFunctionSeconds = 60,
        [Description("With functions: functions decompiled (default 32, 1-200); the rest are skipped with a follow-up call.")] int maxFunctions = 32,
        [Description("With address: a footer on the first page listing the globals, functions, strings and imports used.")] bool refs = false,
        [Description("Seconds for this call's engine requests (1-600; default NDM_ENGINE_REQUEST_TIMEOUT); Ghidra's decompiler retries once with 4x.")] int? timeoutSeconds = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        bool batch = functions is { Length: > 0 };
        if (batch == !string.IsNullOrWhiteSpace(address))
            throw new ToolError(ErrorCode.InvalidArgument, batch ? "Pass address or functions, not both." : "address is required (or functions for several).",
                "address=<one function>, or functions=[...] for several");
        if (timeoutSeconds is { } ts && (ts < 1 || ts > 600))
            throw new ToolError(ErrorCode.InvalidArgument, $"timeoutSeconds {ts} is outside 1-600.", "timeoutSeconds=120");
        TimeSpan? limit = timeoutSeconds is { } t ? TimeSpan.FromSeconds(t) : null;
        using var engineLimit = EngineRequestLimit.Use(limit);
        var native = batch ? await Task.Run(() => ResolveImage(workspace, image), cancellationToken) : null;
        uint rva = 0;
        if (!batch) (native, rva) = await Task.Run(() => Resolve(image, address!), cancellationToken);
        var session = await engines.Session(native!, engine, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
        if (!session.DecompilerAvailable)
            throw new ToolError(ErrorCode.Unsupported, $"The {session.ProviderId} decompiler is not available for {session.Arch} code here.",
                "disassemble the function instead, or install/license the decompiler for this architecture");
        var pushed = await Push(native!, session, cancellationToken);
        if (batch)
        {
            if (refs) throw new ToolError(ErrorCode.InvalidArgument, "refs applies to one function (address), not functions.", "drop refs, or decompile one address");
            var (text, report) = await Batch(native!, session, functions!, addresses, Math.Clamp(perFunctionSeconds, 1, 600), Math.Clamp(maxFunctions, 1, 200), cancellationToken);
            return StructuredOutput.With((pushed != null ? $"// {pushed}\n" : "") + pager.Page(text, offset, maxChars), report);
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
        return StructuredOutput.With(header + (pushed != null ? $"// {pushed}\n" : "") + pager.Page(single, offset, maxChars) + (offset == 0 && objects != null ? objects.Value.Text : ""),
            new DecompileReport(native.Id, session.ProviderId, [item], 1, 1, 0, 0, null));
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
            var text = o.Text ?? (index?.StringAt(o.Rva) is { } s ? index.ReadString(s, 400) : null);
            var kind = imports.ContainsKey(o.Rva) ? "import" : o.Function ? "function" : text != null ? "string" : "data";
            items.Add(new DecompileRef(NativeAddress.Va(image, o.Rva), kind == "import" ? name : NativeTools.DisplayName(name, image.Format), kind, text, o.Uses));
        }
        var sb = new StringBuilder($"// refs: {(items.Count == 0 ? "none" : string.Join(", ", items.GroupBy(i => i.Kind).Select(g => Plural(g.Count(), g.Key))))}" +
                                   (session is Native.Providers.Ida.IdaSession ? "" : $" (from {session.ProviderId}'s references)") + "\n");
        foreach (var i in items.Take(MaxRefs))
            sb.AppendLine($"//   {i.Kind,-8}  {i.Address}  {(i.Text != null ? Quote(i.Text) : i.Name)}{(i.Uses > 1 ? $"  x{i.Uses}" : "")}");
        if (items.Count > MaxRefs) sb.AppendLine($"//   ... {items.Count - MaxRefs} more (structured refs has all)");
        var result = (sb.ToString(), items);
        lock (_refs)
        {
            if (_refs.Count >= 256) _refs.Clear(); // a bounded cache: footers are cheap to rebuild
            _refs[key] = result;
        }
        return result;
    }

    private static string Quote(string text) =>
        "\"" + Format.Clip(text.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r").Replace("\t", "\\t"), 120) + "\"";

    /// <summary>Pushes names, recovered and user types into the session (each once per change); what was pushed, for the header.</summary>
    private async Task<string?> Push(LoadedNative native, INativeDecompilerSession session, CancellationToken ct)
    {
        var pushed = NativePdbTypes.Describe(NativePdbTypes.Report(session));
        if (names != null && NativeNamePush.Describe(await names.EnsureAsync(native, session, ct)) is { } named)
            pushed = (pushed != null ? pushed + "\n// " : "") + named;
        if (types != null && NativeTypePush.Describe(await types.EnsureAsync(native, session, ct)) is { } typed)
            pushed = (pushed != null ? pushed + "\n// " : "") + typed;
        if (userTypes != null && NativeUserTypePush.Describe(await userTypes.EnsureAsync(native, session, ct)) is { } user)
            pushed = (pushed != null ? pushed + "\n// " : "") + user;
        if (native.HasPatches)
            pushed = (pushed != null ? pushed + "\n// " : "") + (engines.ServesPatchedCopy(native, session.ProviderId)
                ? $"patched image: analyzed as a patched copy (the database could not take {Plural(native.Patches.Patches.Count, "patch")})"
                : $"patched image: {Plural(native.Patches.Patches.Count, "patch")} applied in the database");
        return pushed;
    }

    /// <summary>The text cache key of one function's pseudocode: single and batch calls share it.</summary>
    private static string TextKey(LoadedNative native, INativeDecompilerSession session, uint rva, bool addresses) =>
        $"decompile|{native.Image.Sha256}|{rva:X}|{addresses}|{NativeNamePush.CurrentStamp(session)}|{NativeTypePush.CurrentStamp(session)}|" +
        $"{NativePdbTypes.CurrentStamp(session)}|{NativeUserTypePush.CurrentStamp(session)}";

    private static string FunctionText(LoadedNative native, INativeDecompilerSession session, DecompiledFunction function, bool addresses)
    {
        var lines = function.Text.Split('\n');
        var byLine = function.LineAddresses.GroupBy(l => l.Line).ToDictionary(g => g.Key, g => g.Min(l => l.Rva));
        var (display, symbol) = NativeTools.Named(function.Name, native.Image.Format);
        var sb = new StringBuilder($"// {display} at {NativeAddress.Va(native.Image, function.StartRva)} ({session.ProviderId}" +
                                   $"{(session.ReusedDatabase ? ", saved analysis" : $", analyzed in {session.OpenTime.TotalSeconds:0.0} s")}" +
                                   $"{(session.DatabaseNote is { } note ? ", " + note : "")}{symbol})\n");
        for (int i = 0; i < lines.Length; i++)
            sb.Append(addresses ? (byLine.TryGetValue(i, out var at) ? $"/* {native.Image.ImageBase + at:X} */ " : new string(' ', 6 + 16 - 2)) : "")
              .AppendLine(lines[i].TrimEnd('\r'));
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
                    sb.AppendLine(head).Append(texts[i]).AppendLine();
                    break;
                case "duplicate":
                    var first = Array.FindIndex(starts, x => x == starts[i]);
                    sb.AppendLine($"{head}: the same function as [{first + 1}]");
                    break;
                case "skipped":
                    skipped.Add(inputs[i]);
                    sb.AppendLine($"{head}: skipped ({(outcomes[i] != null ? "time budget used" : $"maxFunctions={max}")})");
                    break;
                default:
                    (code, message) = errors[i] ?? (o?.ErrorCode ?? "failed", o?.Error ?? "failed");
                    sb.AppendLine($"{head}: error {code}: {message}");
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
        if (next != null) sb.AppendLine($"// Next: {next}");
        return (summary + sb, new DecompileReport(native.Id, session.ProviderId, items, n, ok, failed, skipped.Count, next));
    }

    /// <summary>The native image named by id or path (loaded by path when needed).</summary>
    internal static LoadedNative ResolveImage(AssemblyWorkspace workspace, string image)
    {
        var id = workspace.Read(() => workspace.FindNative(image)?.Id);
        if (id == null && !string.IsNullOrWhiteSpace(image) && Path.IsPathFullyQualified(image.Trim()) && File.Exists(image.Trim()))
            id = workspace.LoadAny(image.Trim()).Native?.Id ?? throw new ToolError(ErrorCode.Unsupported, $"{image} is a .NET assembly, not a native image.");
        return workspace.Read(() => workspace.GetNative(id ?? image));
    }

    private (LoadedNative Native, uint Rva) Resolve(string image, string address) => Resolve(workspace, code, image, address);

    /// <summary>The native image (loaded by path when needed) and an address in it; names resolve through the code index when it is ready.</summary>
    internal static (LoadedNative Native, uint Rva) Resolve(AssemblyWorkspace workspace, NativeCodeService? code, string image, string address)
    {
        var native = ResolveImage(workspace, image);
        return (native, workspace.Read(() => NativeAddress.Parse(native.Image, address, code?.Ready(native) is { } index ? index.AddressesOfName : null)));
    }

    [McpServerTool(Name = "list_cpp_classes", Title = "C++ classes from RTTI")]
    [Description("C++ classes of an MSVC-built native image recovered from RTTI: demangled class names, base classes (with offsets, virtual and multiple " +
                 "inheritance), and vftables with their slot targets. Every structure is cross-checked; rejected candidates are counted with the reason. " +
                 "engine=ghidra lists Ghidra's class namespaces instead (also PDB and Itanium classes), with function counts and vftables.")]
    public async Task<string> ListCppClasses(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Only classes whose name contains this text (case-insensitive).")] string? filter = null,
        [Description("Include each vftable's slot addresses.")] bool slots = false,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        [Description("auto or ours (default: RTTI), or ghidra.")] string? engine = null,
        [Description("engine=ghidra: plain namespaces and libraries too.")] bool namespaces = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default)
    {
        var mode = EngineModes.Resolve(engine, EngineMode.Auto);
        if (mode == EngineMode.Ida)
            throw new ToolError(ErrorCode.Unsupported, "IDA has no class namespaces to list.", "use engine=ours for RTTI classes or engine=ghidra");
        if (mode == EngineMode.Ghidra)
            return await OrderedProgress.Run(context, progress => EngineClasses(image, filter, namespaces, offset, maxChars, progress, cancellationToken));
        return await Task.Run(() => RttiClasses(image, filter, slots, offset, maxChars, cancellationToken), cancellationToken);
    }

    /// <summary>Ghidra's class namespaces (and with <paramref name="all"/> its other namespaces), sorted by name.</summary>
    private async Task<string> EngineClasses(string image, string? filter, bool all, int offset, int? maxChars, IProgress<ProgressNotificationValue> progress,
        CancellationToken ct)
    {
        var native = await Task.Run(() => ResolveImage(workspace, image), ct);
        var session = await engines.Session(native, Native.Providers.Ghidra.GhidraProvider.ProviderId, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = $"Ghidra {p.Stage}" })), ct);
        if (names != null) await names.EnsureAsync(native, session, ct);
        var list = await session.ListNamespacesAsync(ct);
        var shown = list.Where(n => (all || n.Kind == "class") && (filter == null || n.Name.Contains(filter, StringComparison.OrdinalIgnoreCase))).ToList();
        var sb = new StringBuilder($"{native.Id}: {Plural(list.Count(n => n.Kind == "class"), "class")} in Ghidra's namespaces" +
                                   (all ? $", {Plural(list.Count(n => n.Kind == "namespace"), "namespace")}, {Plural(list.Count(n => n.Kind == "library"), "library")}" : "") +
                                   (filter != null ? $"; {shown.Count} match '{filter}'" : "") + "\nEngine: ghidra\n");
        foreach (var n in shown)
            sb.AppendLine($"{n.Kind} {n.Name}  ({Plural(n.Functions, "function")})" + (n.Vftable is { } v ? $"  vftable {NativeAddress.Va(native.Image, v)}" : ""));
        return pager.Page(sb.ToString(), offset, maxChars);
    }

    private string RttiClasses(string image, string? filter, bool slots, int offset, int? maxChars, CancellationToken cancellationToken)
    {
        var (native, _) = Resolve(image, "rva:0");
        var result = native.GetAnalysis(n => MsvcRtti.Analyze(n.Image, ct: cancellationToken));
        var pe = native.Image;
        var classes = result.Classes.Where(c => filter == null || c.Name.Contains(filter, StringComparison.OrdinalIgnoreCase)).ToList();
        var sb = new StringBuilder($"{native.Id}: {Plural(result.Classes.Count, "class")} with RTTI, {Plural(result.Stats.Vtables, "vftable")}, " +
                                   $"{Plural(result.TypeDescriptors.Count, "type descriptor")}" +
                                   (filter != null ? $"; {classes.Count} match '{filter}'" : "") + "\n");
        foreach (var note in result.Notes) sb.AppendLine($"Note: {note}");
        if (result.Stats.TypeDescriptorCandidatesRejected + result.Stats.LocatorCandidatesRejected > 0)
            sb.AppendLine($"Rejected candidates: {result.Stats.TypeDescriptorCandidatesRejected} type descriptors, {result.Stats.LocatorCandidatesRejected} locators (failed cross-checks)");
        foreach (var c in classes)
        {
            sb.Append($"{c.Kind} {c.Name}");
            var direct = c.Bases.Where(b => b.Depth == 1).ToList();
            if (direct.Count > 0)
                sb.Append(" : " + string.Join(", ", direct.Select(b => $"{(b.IsVirtual ? "virtual " : "")}{b.Name}{(b.IsVirtual ? "" : b.Mdisp != 0 ? $" @+0x{b.Mdisp:X}" : "")}")));
            if ((c.Attributes & MsvcHierarchyAttributes.Ambiguous) != 0) sb.Append("  [ambiguous bases]");
            sb.AppendLine();
            foreach (var v in c.Vtables)
            {
                sb.AppendLine($"  vftable {NativeAddress.Va(pe, v.VftableRva)} for subobject +0x{v.Offset:X}: {Plural(v.SlotRvas.Count, "slot")}");
                if (slots)
                    for (int i = 0; i < v.SlotRvas.Count; i++)
                        sb.AppendLine($"    [{i}] {NativeAddress.Va(pe, v.SlotRvas[i])}");
            }
            foreach (var issue in c.Issues) sb.AppendLine($"  issue: {issue}");
        }
        return pager.Page(sb.ToString(), offset, maxChars);
    }

    public sealed record VerdictCount(string Status, string Reason, int Count);

    public sealed record NativeImportReport(
        string Assembly,
        [property: Description("P/Invoke declarations checked.")] int Declarations,
        [property: Description("Declarations per verdict and reason.")] IReadOnlyList<VerdictCount> Counts,
        [property: Description("The status or reason filter applied, or null.")] string? Filter,
        int Offset,
        [property: Description("Declarations matching the filter.")] int Total,
        bool Truncated,
        [property: Description("Contradicted, unresolved and dynamic_only first, then not_checked and verified.")] IReadOnlyList<NativeImportVerifier.Check> Items,
        [property: Description("Run-time native loading found in the IL (first 100).")] IReadOnlyList<DynamicNativeLoad> DynamicLoads,
        int DynamicLoadsTotal,
        [property: Description("Malformed metadata found while reading the declarations, with locations.")] IReadOnlyList<MetadataIssue> MetadataIssues,
        IReadOnlyList<string> Notes);

    [McpServerTool(Name = "verify_native_imports", Title = "Verify P/Invoke imports", UseStructuredContent = true)]
    [Description("Check a .NET assembly's P/Invoke declarations ([DllImport]) against the exports of the libraries they bind to, with the " +
                 "runtime's lookup rules: DLL search order (app folder, system folder for the assembly's bitness), API set redirection, A/W suffixes, " +
                 "x86 stdcall decoration (_Name@N), ordinals and forwarder chains; for Linux / macOS / Android / iOS targets (platform=, or detected from " +
                 "deps.json and the libraries shipped) .so / .dylib probing along the RID chain, ELF / Mach-O exports and __Internal in an Il2Cpp game binary. " +
                 "Verdict per declaration, with a reason: verified (exact, suffixed, decorated, forwarded, ordinal, versioned, internal), contradicted (missing_export, " +
                 "missing_ordinal, exact_spelling, ordinal_points_elsewhere, forwarder_broken, arch_mismatch, mangled_only), unresolved (dll_not_found with the places " +
                 "searched, system_dll_not_on_host, wrong_platform, malformed_metadata with its location), dynamic_only (the assembly loads the library itself: " +
                 "NativeLibrary.Load/GetExport, LoadLibrary/GetProcAddress, a DllImportResolver), not_checked (runtime-internal). Run-time loading found in the IL " +
                 "is listed; a missing static import does not rule out dynamic loading. Malformed metadata is reported with locations.")]
    public Task<NativeImportReport> VerifyNativeImports(
        [Description(AssemblyDescription)] string assembly,
        [Description("Only declarations with this status (verified, contradicted, unresolved, dynamic_only, not_checked) or reason (e.g. missing_export).")] string? status = null,
        [Description("Index of the first row.")] int offset = 0,
        [Description("Max rows (default 500, max 5000).")] int limit = 500,
        [Description("Target platform (default auto).")] string? platform = null,
        CancellationToken cancellationToken = default) => Task.Run(() => workspace.Read(() =>
    {
        var asm = workspace.Get(assembly);
        var result = new NativeImportVerifier(path => NativeImageLoader.Open(path)).Verify(asm, cancellationToken, platform);
        var checks = result.Checks;
        var filter = string.IsNullOrWhiteSpace(status) ? null : status.Trim().ToLowerInvariant();
        offset = Math.Max(0, offset);
        limit = ClampLimit(limit);
        var selected = checks.Where(c => filter == null || c.Status == filter || c.Reason == filter)
            .OrderBy(c => c.Status switch { NativeImportVerifier.Contradicted => 0, NativeImportVerifier.Unresolved => 1, NativeImportVerifier.DynamicOnly => 2,
                NativeImportVerifier.NotChecked => 3, _ => 4 })
            .ThenBy(c => c.Module, StringComparer.OrdinalIgnoreCase).ThenBy(c => c.EntryPoint, StringComparer.Ordinal).ToList();
        var counts = checks.GroupBy(c => (c.Status, c.Reason)).OrderBy(g => Array.IndexOf(NativeImportVerifier.Statuses, g.Key.Status)).ThenBy(g => g.Key.Reason)
            .Select(g => new VerdictCount(g.Key.Status, g.Key.Reason, g.Count())).ToList();

        var notes = new List<string>();
        if (checks.Count == 0) notes.Add($"{asm.Id} declares no P/Invoke methods.");
        if (filter != null && !NativeImportVerifier.Statuses.Contains(filter) && selected.Count == 0 && checks.Count > 0)
            notes.Add($"No declaration has status or reason '{filter}'.");
        notes.Add("A declaration that is unresolved or contradicted statically does not rule out dynamic loading: native code can also be loaded at run " +
                  "time (NativeLibrary.Load/GetExport, LoadLibrary/GetProcAddress, a DllImportResolver), by this assembly (dynamicLoads lists what its IL does) " +
                  "or by another one in the process.");
        if (result.DynamicTruncated) notes.Add("dynamicLoads stopped at 2000 call sites.");
        if (!result.Platform.IsWindows || result.Platform.Source != "default")
            notes.Add($"Target platform: {result.Platform.Os}{(result.Platform.Rid != null ? $" ({result.Platform.Rid})" : "")}, from {result.Platform.Source}.");
        if (!OperatingSystem.IsWindows() && result.Platform.IsWindows)
            notes.Add("This host has no Windows system DLLs: DLLs next to the assembly are checked (exports, ordinals, forwarders); declarations bound to " +
                      "system DLLs are unresolved (system_dll_not_on_host).");
        return new NativeImportReport(asm.Id, checks.Count, counts, filter, offset, selected.Count, offset + limit < selected.Count,
            selected.Skip(offset).Take(limit).ToList(), result.DynamicLoads.Take(100).ToList(), result.DynamicLoads.Count, result.MetadataIssues, notes);
    }), cancellationToken);
}
