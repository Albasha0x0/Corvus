using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Code;
using Corvus.Native.Patching;
using Corvus.Native.Providers;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>Native annotations (rename, comment, export) and byte/assembly patching with undo and save.</summary>
[McpServerToolType]
public sealed class NativeEditTools(AssemblyWorkspace workspace, NativeCodeService code, NativeEditService edits, EditJournal? journal = null,
    NativeEngineService? engines = null, NativeNamePush? names = null, NativeTypePush? types = null, NativeUserTypePush? userTypes = null,
    ServerOptions? options = null)
{
    private const string ProvisionalNote = "Previewed on the analysis from before the last patch (function extents as they were), without waiting for the code index to rebuild.\n";

    /// <summary><see cref="Open"/> for a patch; a dry run right after a patch takes the analysis from before it instead of waiting for the rebuild.</summary>
    private async Task<(LoadedNative Native, NativeCodeIndex Index, string Note)> OpenToPatch(string image, bool dryRun, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        if (dryRun && await Task.Run(() => workspace.Read(() => workspace.FindNative(image)), ct) is { } native
            && code.Ready(native) == null && code.Provisional(native) is { } provisional)
            return (native, provisional, ProvisionalNote);
        var (n, index) = await Open(image, progress, ct);
        return (n, index, "");
    }

    private async Task<(LoadedNative Native, NativeCodeIndex Index)> Open(string image, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var native = await Task.Run(() =>
        {
            return Targets.Native(workspace, image);
        }, ct);
        var index = await code.Index(native, new Progress<CodeIndexProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = p.Done, Total = p.Total > 0 ? p.Total : null, Message = $"indexing {native.Id}: {p.Phase}" })), ct);
        return (native, index);
    }

    private static uint Address(NativeCodeIndex index, string text) => NativeAddress.Parse(index.Image, text, name =>
    {
        if (name.StartsWith("sub_", StringComparison.OrdinalIgnoreCase) && NativeAddress.Number(name[4..]) is { } n)
        {
            if (n < index.Image.SizeOfImage && index.FunctionByStart((uint)n) != null) return [new((uint)n, "function")];
            if (n >= index.Image.ImageBase && n - index.Image.ImageBase < index.Image.SizeOfImage) return [new((uint)(n - index.Image.ImageBase), "function")];
        }
        return index.AddressesOfName(name);
    });

    private const string RelocationsDescription =
        "PE relocations: auto (default; keep valid, clear stale, add new), keep, or neutralize (clear all).";

    private const string ExtendDescription =
        "Put code larger than the site in a stub (placement) it jumps to and back. Refused when unsafe.";

    private const string StubModeDescription = "With extend: replace (default; the displaced instructions), before or after them.";

    private const string PlacementDescription =
        "With extend: auto (default; cave, else section), cave or section (a new PE section or ELF/Mach-O segment).";

    private const string AllowUnsafeDescription = "Allow mid-instruction, past-function-end, header or loader-written bytes.";

    [McpServerTool(Name = "rename_native", Title = "Name a native address", UseStructuredContent = true, OutputSchemaType = typeof(EditOutcome))]
    [Description("Name a native address: used by every native tool, pushed to the engines, kept per file SHA-256, undoable by editId. C-identifier-like " +
                 "(<=255 chars), unique unless allowDuplicate. Empty clears. " + BatchNote)]
    public Task<string> RenameNative(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string? address = null,
        [Description("The new name; empty to clear the name at this address.")] string? name = null,
        [Description("Allow a name already used at another address.")] bool allowDuplicate = false,
        [Description("Lines 'address = name', or JSON [{address, name}].")] string? items = null,
        [Description(ToolSupport.DryRunDefaultTrueDescription)] bool dryRun = true,
        [Description("Stop at the first failing item.")] bool stopOnError = false,
        [Description(DecompileDiff.Description)] string? showDecompile = null,
        [Description(PushEngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var show = DecompileDiff.Parse(showDecompile);
        if (show != null && items != null) throw new ToolError(ErrorCode.InvalidArgument, "showDecompile takes one address, not items.");
        if (show != null && dryRun) throw new ToolError(ErrorCode.InvalidArgument, "showDecompile shows the pseudocode after the rename, so it needs dryRun=false.", "pass dryRun=false with showDecompile");
        var list = BatchItems(items, address, name, "name");
        var (native, index) = await Open(image, progress, cancellationToken);
        var results = new List<ItemResult>();
        var changes = new List<(uint Rva, string? Name)>();
        var used = edits.Annotations(native).Names().ToDictionary(n => n.Rva, n => n.Name);
        foreach (var item in list)
        {
            try
            {
                var rva = Address(index, item.Address);
                var next = string.IsNullOrWhiteSpace(item.Value) ? null : NativeName.Validate(item.Value);
                if (next != null && !allowDuplicate && used.FirstOrDefault(u => u.Key != rva && u.Value == next) is { Value: not null } other)
                    throw new ToolError(ErrorCode.Conflict, $"'{next}' is already used at {NativeAddress.Va(index.Image, other.Key)}.",
                        "pass allowDuplicate=true to use it anyway, or pick another name");
                if (changes.Any(c => c.Rva == rva)) throw new ToolError(ErrorCode.Conflict, "the address is named twice in this batch", "name each address once");
                if (next == null) used.Remove(rva);
                else used[rva] = next;
                changes.Add((rva, next));
                var where = index.FunctionAt(rva) is { } f && f.Start == rva ? "function " : "";
                results.Add(new ItemResult(item.Address, new EditChange("name", NativeAddress.Va(index.Image, rva), index.NameAt(rva), next), where));
            }
            catch (ToolError e)
            {
                results.Add(new ItemResult(item.Address, null, null, e));
                if (stopOnError) break;
            }
        }
        ThrowIfAllFailed(results, "rename_native");
        EditId? id = null;
        string? engineUsed = null;
        string decompiled = "";
        if (!dryRun && changes.Count > 0)
        {
            if (show != null)
            {
                // the session is opened first so the pseudocode before the rename is the engine's with every earlier name
                if (engines == null) throw new ToolError(ErrorCode.Unsupported, "showDecompile needs a decompiler engine.", "omit showDecompile; decompile_native shows the function");
                var session = await engines.Session(native, string.IsNullOrWhiteSpace(engine) ? null : engine, new Progress<NativeProviderProgress>(p =>
                    progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
                await EnsurePushed(native, session, cancellationToken);
                var function = await DecompileDiff.FunctionFor(session, changes[0].Rva, cancellationToken);
                var before = show == "diff" ? await DecompileDiff.Text(session, function, cancellationToken) : default;
                id = edits.ApplyNames(native, index, changes, allowDuplicate: true);
                await EnsurePushed(native, session, cancellationToken);
                engineUsed = session.ProviderId;
                var after = await DecompileDiff.Text(session, function, cancellationToken);
                decompiled = DecompileDiff.Render(show, before, after, function is { } f ? $"the function at rva 0x{f:X}" : "the function");
            }
            else
            {
                id = edits.ApplyNames(native, index, changes, allowDuplicate: true); // checked above, across the batch
                engineUsed = (await PushNames(native, engine, progress, cancellationToken)).Engine;
            }
        }
        var text = Outcome("name", results, list.Count, dryRun, id, engineUsed, single: items == null,
            r => items != null ? $"{r.Change!.Before ?? "(no name)"} -> {r.Change.After ?? "(cleared)"}" : r.Change!.After == null ? $"cleared the name at {r.Change.Target} (was {r.Change.Before ?? "unnamed"})"
                : $"named {r.Where}{r.Change.Target} '{r.Change.After}'{(r.Change.Before is { } b && b != r.Change.After ? $" (was {b})" : "")}") + decompiled;
        return ToolOutput.Edit(Record(results, dryRun, id, engineUsed), text);
    });

    private const string BatchNote = "items: many in one push.";

    private const string PushEngineDescription = "Engine to push to now (default: one with this image open, else at its next use).";

    /// <summary>One item of a batch: the address and the value (a name or a comment's text), plus the optional per-item fields.</summary>
    internal sealed record BatchItem(string Address, string Value, string? Scope = null, bool? Append = null);

    /// <summary>A batch item planned (<see cref="Change"/>; null: nothing changes there) or refused (<see cref="Error"/>); <see cref="Where"/> a prefix for the text.</summary>
    private sealed record ItemResult(string Address, EditChange? Change, string? Where, ToolError? Error = null, string? Text = null);

    private static void ThrowIfAllFailed(List<ItemResult> results, string tool)
    {
        if (results.Count == 0 || results.Any(r => r.Error == null)) return;
        if (results.Count == 1) throw results[0].Error!;
        new BatchResult<int>([.. results.Select(r => new BatchItem<int>(r.Address, 0, BatchError.From(r.Error!, tool)))]).ThrowIfAllFailed();
    }

    /// <summary>The outcome record: the planned or made changes, the edit id, failed items with their errors.</summary>
    private static EditOutcome Record(List<ItemResult> results, bool dryRun, EditId? id, string? engine)
    {
        var changes = results.Where(r => r.Change != null).Select(r => r.Change!).ToList();
        int failed = results.Count(r => r.Error != null);
        return new EditOutcome(!dryRun && id != null, dryRun, changes, id is { } e ? [e] : [])
        {
            Digest = changes.Count > 0 ? EditDigest.Of(changes) : null,
            Failed = failed > 0 ? failed : null,
            Items = failed > 0 ? [.. results.Where(r => r.Error != null).Select(r => (object)new { target = r.Address, error = BatchError.From(r.Error!) })] : null,
            PushedTo = engine != null ? [engine] : null,
        };
    }

    /// <summary>The text: one line for a single item, else a summary line and one line per item; then the edit id and where it went.</summary>
    private static string Outcome(string what, List<ItemResult> results, int total, bool dryRun, EditId? id, string? engine, bool single, Func<ItemResult, string> line)
    {
        string Line(ItemResult r) => r.Error != null ? $"failed: {r.Error.Message}" : r.Text ?? (r.Change == null ? "unchanged" : line(r));
        var sb = new System.Text.StringBuilder();
        if (single) sb.Append(dryRun ? results[0].Text != null || results[0].Error != null ? "Dry run: " : "Dry run: would have " : "").Append(Upper(Line(results[0]).TrimEnd('.'), !dryRun)).Append('.').Append('\n');
        else
        {
            int failed = results.Count(r => r.Error != null);
            sb.Append($"{(dryRun ? "Dry run: " : "")}{total} {what} item(s): {results.Count - failed} ok, {failed} failed" +
                      (results.Count < total ? $", stopped after item {results.Count}" : "") + "\n");
            foreach (var r in results) sb.Append($"  {r.Address}  {Line(r)}\n");
        }
        if (dryRun) sb.Append("Nothing recorded; dryRun=false applies it.\n");
        else if (id is { } e) sb.Append($"Recorded as {e} (undo_native_edit editId={e}); " +
                                        (engine != null ? $"pushed to {NativeEngineService.DisplayName(engine)}.\n" : "engines take it at their next use.\n"));
        else if (results.Any(r => r.Error == null)) sb.Append("Nothing changed.\n");
        return sb.ToString();
    }

    private static string Upper(string s, bool upper) => upper && s.Length > 0 ? char.ToUpperInvariant(s[0]) + s[1..] : s;

    /// <summary>Most items in one call.</summary>
    private const int MaxBatchItems = 5000;

    /// <summary>
    /// The items: lines "address = value" (the value may hold '='), or a JSON array of objects with address and
    /// <paramref name="valueKey"/> (and scope, append for comments); without items the single address and value.
    /// </summary>
    internal static List<BatchItem> BatchItems(string? items, string? address, string? value, string valueKey)
    {
        if (string.IsNullOrWhiteSpace(items))
            return string.IsNullOrWhiteSpace(address) || value == null
                ? throw new ToolError(ErrorCode.InvalidArgument, $"Pass address and {valueKey}, or items.")
                : [new BatchItem(address, value)];
        if (!string.IsNullOrWhiteSpace(address) || value != null)
            throw new ToolError(ErrorCode.InvalidArgument, $"Pass items, or address and {valueKey}, not both.");
        var list = new List<BatchItem>();
        var text = items.Trim();
        if (text.StartsWith('['))
        {
            System.Text.Json.JsonElement root;
            try { root = System.Text.Json.JsonDocument.Parse(text).RootElement; }
            catch (System.Text.Json.JsonException e) { throw new ToolError(ErrorCode.InvalidArgument, $"items is not valid JSON: {e.Message}"); }
            foreach (var o in root.EnumerateArray())
            {
                string? Str(string key) => o.ValueKind == System.Text.Json.JsonValueKind.Object && o.TryGetProperty(key, out var v)
                    ? v.ValueKind == System.Text.Json.JsonValueKind.String ? v.GetString() : v.ToString() : null;
                var a = Str("address") ?? Str("addr") ?? throw new ToolError(ErrorCode.InvalidArgument, $"items: {o} has no address.");
                bool? append = o.ValueKind == System.Text.Json.JsonValueKind.Object && o.TryGetProperty("append", out var ap)
                    && ap.ValueKind is System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False ? ap.GetBoolean() : null;
                list.Add(new BatchItem(a, Str(valueKey) ?? "", Str("scope"), append));
            }
        }
        else
            foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                int eq = line.IndexOf('=', StringComparison.Ordinal);
                if (eq <= 0) throw new ToolError(ErrorCode.InvalidArgument, $"items: '{line}' is not 'address = {valueKey}'.");
                list.Add(new BatchItem(line[..eq].Trim(), line[(eq + 1)..].Trim()));
            }
        if (list.Count == 0) throw new ToolError(ErrorCode.InvalidArgument, "items is empty.");
        if (list.Count > MaxBatchItems) throw new ToolError(ErrorCode.InvalidArgument, $"{list.Count} items; at most {MaxBatchItems} per call.", "split the items");
        return list;
    }

    [McpServerTool(Name = "comment_native", Title = "Comment a native address", UseStructuredContent = true, OutputSchemaType = typeof(EditOutcome))]
    [Description("Comment a native address (undoable, pushed to engines). scope: line (repeatable: also where referenced), eol, pre " +
                 "or plate (engine kinds; Ghidra pseudocode shows pre), pseudocode (on its statement), function, or auto (function at a " +
                 "function start, else line and pseudocode). append adds a line; empty clears. " + BatchNote)]
    public Task<string> CommentNative(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string? address = null,
        [Description("The comment text; empty to clear it.")] string? text = null,
        [Description("See the description; default auto.")] string? scope = null,
        [Description("Add text as a new line of the existing comment; a line it has is skipped.")] bool append = false,
        [Description("With append: add the line even when the comment has it.")] bool repeatLine = false,
        [Description("Lines 'address = text', or JSON [{address, text, scope?, append?}].")] string? items = null,
        [Description(ToolSupport.DryRunDefaultTrueDescription)] bool dryRun = true,
        [Description("Stop at the first failing item.")] bool stopOnError = false,
        [Description(PushEngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var list = BatchItems(items, address, text, "text");
        var defaultScope = CommentScopes.Parse(scope);
        var (native, index) = await Open(image, progress, cancellationToken);
        var plans = new List<CommentPlan>();
        var results = new List<ItemResult>();
        foreach (var item in list)
        {
            try
            {
                var rva = Address(index, item.Address);
                var itemScope = item.Scope != null ? CommentScopes.Parse(item.Scope) : defaultScope;
                var plan = PlanComment(native, index, rva, item.Value, itemScope, item.Append ?? append, !repeatLine,
                    itemScope == CommentScopes.Function ? await EngineFunctionStart(native, index, rva, engine, progress, cancellationToken) : null);
                if (plan.Change != null && plans.Any(p => p.Change?.Rva == plan.Rva))
                    throw new ToolError(ErrorCode.Conflict, "the address is commented twice in this batch", "comment each address once, or use append");
                plans.Add(plan);
                results.Add(new ItemResult(item.Address, plan.Change is { } c ? CommentChange(native, index, c) : null, null, Text: plan.Text));
            }
            catch (ToolError e)
            {
                results.Add(new ItemResult(item.Address, null, null, e));
                if (stopOnError) break;
            }
        }
        ThrowIfAllFailed(results, "comment_native");
        var changes = plans.Select(p => p.Change).OfType<NativeEditService.CommentChange>().ToList();
        NativeNamePush.PushResult? pushed = null;
        string? engineUsed = null;
        EditId? id = null;
        if (!dryRun && changes.Count > 0)
        {
            id = edits.ApplyComments(native, index, changes);
            (pushed, engineUsed) = await PushNames(native, engine, progress, cancellationToken);
        }
        var pseudo = changes.Where(c => c.Pseudo != null).Select(c => c.Rva).ToList();
        var note = dryRun || pseudo.Count == 0 ? "" : PushNote(pushed, pseudo).TrimStart() + "\n";
        var outcome = Outcome("comment", results, list.Count, dryRun, id, engineUsed, single: items == null, r => r.Text!.TrimEnd('.'));
        return ToolOutput.Edit(Record(results, dryRun, id, engineUsed), outcome + note);
    });

    /// <summary>The comment change at one address as an edit change: the line comment when it changes, else the pseudocode one.</summary>
    private EditChange CommentChange(LoadedNative native, NativeCodeIndex index, NativeEditService.CommentChange c)
    {
        var va = NativeAddress.Va(index.Image, c.Rva);
        return c.Line != null
            ? new EditChange("comment", va, index.Sourced.CommentAt(c.Rva)?.Text, c.Line.Trim().Length == 0 ? null : c.Line.Trim())
            : new EditChange("pseudocode", va, edits.Annotations(native).PseudoCommentAt(c.Rva), c.Pseudo!.Trim().Length == 0 ? null : c.Pseudo.Trim());
    }

    /// <summary>comment_native scopes.</summary>
    internal static class CommentScopes
    {
        public const string Auto = "auto", Line = "line", Pseudocode = "pseudocode", Function = "function";
        public static readonly string[] All = [Auto, Line, NativeCommentKinds.Eol, NativeCommentKinds.Pre, NativeCommentKinds.Plate, Pseudocode, Function];

        public static string Parse(string? scope) => (scope ?? "").Trim().ToLowerInvariant() switch
        {
            "" or Auto => Auto,
            Line or "disassembly" or "repeatable" => Line,
            NativeCommentKinds.Eol => NativeCommentKinds.Eol,
            NativeCommentKinds.Pre => NativeCommentKinds.Pre,
            NativeCommentKinds.Plate => NativeCommentKinds.Plate,
            Pseudocode or "decompiler" => Pseudocode,
            Function or "func" => Function,
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown scope '{scope}'.", "use auto, line, eol, pre, plate, pseudocode or function"),
        };
    }

    /// <summary>One comment request resolved: the change to record (null: nothing changes) and what it did per scope.</summary>
    internal sealed record CommentPlan(uint Rva, NativeEditService.CommentChange? Change, string Text);

    /// <summary>
    /// Resolves the scope (a function start in auto scope is the function comment; elsewhere the line and the pseudocode
    /// comment) and the text (append onto the comment in effect there, which may be an imported one; dedupe).
    /// </summary>
    /// <param name="engineStart">The start of the function an engine places the address in, when the built-in index has none there.</param>
    internal CommentPlan PlanComment(LoadedNative native, NativeCodeIndex index, uint rva, string text, string scope, bool append, bool dedupe, uint? engineStart = null)
    {
        uint? start = index.FunctionAt(rva)?.Start ?? engineStart;
        if (scope == CommentScopes.Function && start == null)
            throw new ToolError(ErrorCode.NotFound, $"No function contains {NativeAddress.Va(index.Image, rva)}.", "use scope=line, or list_functions for the functions");
        if (scope == CommentScopes.Auto) scope = start == rva ? CommentScopes.Function : "both";
        uint at = scope == CommentScopes.Function ? start!.Value : rva;
        var ann = edits.Annotations(native);
        var parts = new List<string>();
        string? kind = scope is NativeCommentKinds.Eol or NativeCommentKinds.Pre or NativeCommentKinds.Plate ? scope : null;
        bool kindChanges = scope is not (CommentScopes.Pseudocode or "both" or CommentScopes.Function) && ann.CommentAt(at) != null && ann.CommentKindAt(at) != kind;
        string? Next(string? current, string label, bool changes = false)
        {
            if (!append)
            {
                var t = text.Trim();
                if (t.Length == 0 && current == null) { parts.Add($"{label}: no comment to clear"); return null; }
                if (t == current && !changes) { parts.Add($"{label}: unchanged"); return null; }
                parts.Add(t.Length == 0 ? $"{label} comment cleared" : $"{label} comment set");
                return t;
            }
            var next = NativeEditService.AppendComment(current, text, dedupe);
            parts.Add(next == null ? $"{label}: already has this line" : $"{label} comment appended");
            return next;
        }
        string? line = null, pseudo = null;
        if (scope is not CommentScopes.Pseudocode)
            line = Next(index.Sourced.CommentAt(at)?.Text, scope == CommentScopes.Function ? $"function {index.FunctionByStart(at)?.Name ?? index.NameAt(at) ?? $"sub_{at:X}"}" : kind ?? "line", kindChanges);
        if (scope is CommentScopes.Pseudocode or "both")
            pseudo = Next(ann.PseudoCommentAt(at), "pseudocode");
        return new CommentPlan(at, line == null && pseudo == null ? null : new NativeEditService.CommentChange(at, line, pseudo) { Kind = kind },
            $"{NativeAddress.Va(index.Image, at)}: {string.Join("; ", parts)}.");
    }

    /// <summary>With engine=ida|ghidra and no built-in function at <paramref name="rva"/>: the start of the engine's function there, else null.</summary>
    private async Task<uint?> EngineFunctionStart(LoadedNative native, NativeCodeIndex index, uint rva, string? engine, IProgress<ProgressNotificationValue> progress,
        CancellationToken ct)
    {
        if (engines == null || string.IsNullOrWhiteSpace(engine) || index.FunctionAt(rva) != null) return null;
        var session = await engines.Session(native, engine, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), ct);
        try { return (await session.GetFunctionRecordAsync(rva, ct)).Start; }
        catch (ToolError) { return null; }
    }

    /// <summary>Pushes the names and comments into an engine session now: the one asked for, else one open on the image; null when none.</summary>
    private async Task<(NativeNamePush.PushResult? Result, string? Engine)> PushNames(LoadedNative native, string? engine, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        if (engines == null || names == null) return (null, null);
        var session = string.IsNullOrWhiteSpace(engine) ? engines.CompletedSession(native)
            : await engines.Session(native, engine, new Progress<NativeProviderProgress>(p =>
                progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), ct);
        if (session == null) return (null, null);
        return (await EnsurePushed(native, session, ct) ?? new NativeNamePush.PushResult(0, 0, null, true, "", TimeSpan.Zero), session.ProviderId);
    }

    /// <summary>Brings the session's names, recovered types and user types up to date (in that order); the names push's result.</summary>
    private async Task<NativeNamePush.PushResult?> EnsurePushed(LoadedNative native, INativeDecompilerSession session, CancellationToken ct)
    {
        var pushed = names != null ? await names.EnsureAsync(native, session, ct) : null;
        if (types != null) await types.EnsureAsync(native, session, ct);
        if (userTypes != null) await userTypes.EnsureAsync(native, session, ct);
        return pushed;
    }

    /// <summary>Where the pseudocode comments went: placed by the engine now, refused (with the reason), or kept for its next use.</summary>
    private static string PushNote(NativeNamePush.PushResult? pushed, IReadOnlyCollection<uint> rvas)
    {
        if (pushed == null) return " Pseudocode comments reach the engine at its next use.";
        var failed = pushed.PseudoFailures.Where(f => rvas.Contains(f.Rva)).ToList();
        return failed.Count == 0 ? " Pushed to the engine." :
            " Not placed in the pseudocode: " + string.Join("; ", failed.Take(10).Select(f => $"rva 0x{f.Rva:X}: {f.Error}")) + ".";
    }

    /// <summary>export_native_annotations' record.</summary>
    public sealed record AnnotationExportResult(string OutputPath, string Format, int Names, int Comments, int PseudoComments, int Types,
        [property: Description("Names and comments of the imported layers beneath the user's.")] int Imported, long Bytes, string Sha256);

    [McpServerTool(Name = "export_native_annotations", Title = "Export native annotations", UseStructuredContent = true, OutputSchemaType = typeof(AnnotationExportResult))]
    [Description("Write the image's names and comments (also NativeAOT, Il2Cpp, ObjC, Swift) as IDAPython, a Ghidra script or JSON (IDA and " +
                 "JSON add the user's engine types; scripts apply by rebased RVA). header: C header of declared types, prototypes and typed " +
                 "globals. objc-header: class-dump style Objective-C (Mach-O), Swift types as comments.")]
    public Task<string> ExportNativeAnnotations(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Output file path.")] string outputPath,
        [Description("Default json.")] string? format = null,
        [Description("Replace outputPath if it exists.")] bool overwrite = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, index) = await Open(image, progress, cancellationToken);
        var fmt = AnnotationExport.ParseFormat(format);
        if (fmt == AnnotationExport.Format.ObjcHeader) return ObjcHeaderExport(native, outputPath, overwrite, cancellationToken);
        var ann = edits.Annotations(native);
        var imported = ImportedNames.Of(NativeNameLayers.OfOrNull(native)?.Layers ?? [], ann);
        var text = fmt == AnnotationExport.Format.Header
            ? AnnotationHeader.Render(ann, index.NameAt, rva => index.FunctionByStart(rva) != null, imported)
            : AnnotationExport.Render(ann, fmt, imported);
        var target = SafeFile.WriteAllText(outputPath, text, overwrite);
        var bytes = System.Text.Encoding.UTF8.GetBytes(text);
        var record = new AnnotationExportResult(target, fmt.ToString().ToLowerInvariant(), ann.NameCount, ann.CommentCount, ann.PseudoCommentCount, ann.UserTypes.Count,
            imported.Count, bytes.Length, Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes)));
        return ToolOutput.Report($"Exported {ann.NameCount} name(s), {ann.CommentCount} comment(s), {ann.PseudoCommentCount} pseudocode comment(s) and {ann.UserTypes.Count} user type(s)" +
               (imported.Count > 0 ? $", with {imported.Count} name(s) and comment(s) of the {imported.Sources} layer(s) beneath them," : "") + $" to {target} ({record.Format} format)" +
               (fmt == AnnotationExport.Format.Ghidra && ann.UserTypes.Count > 0 ? "; user types are not in Ghidra scripts." : "."), record);
    });

    private static string ObjcHeaderExport(LoadedNative native, string outputPath, bool overwrite, CancellationToken ct)
    {
        var (objc, swift) = AppleNames.Metadata(native, ct);
        if (objc == null && swift == null)
            throw new ToolError(ErrorCode.Unsupported, $"{native.Id} has no Objective-C or Swift metadata.", "format=objc-header reads a Mach-O with __objc_* or __swift5_* sections");
        var text = Native.MachO.ObjcHeader.Render(objc, swift, Path.GetFileName(native.Image.Path));
        var target = SafeFile.WriteAllText(outputPath, text, overwrite);
        var bytes = System.Text.Encoding.UTF8.GetBytes(text);
        int types = (objc?.Classes.Count ?? 0) + (objc?.Protocols.Count ?? 0) + (objc?.Categories.Count ?? 0) + (swift?.Types.Count ?? 0);
        var record = new AnnotationExportResult(target, "objc-header", 0, 0, 0, types, 0, bytes.Length, Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes)));
        return ToolOutput.Report($"Exported {objc?.Classes.Count ?? 0} class(es), {objc?.Protocols.Count ?? 0} protocol(s), {objc?.Categories.Count ?? 0} category(ies) " +
                                 $"and {swift?.Types.Count ?? 0} Swift type(s) to {target} (objc-header format).", record);
    }

    [McpServerTool(Name = "patch_bytes", Title = "Patch native bytes", UseStructuredContent = true, OutputSchemaType = typeof(EditOutcome))]
    [Description("Replace bytes at a native address in memory, as an undoable edit every read path sees. A partly overwritten instruction is padded " +
                 "with NOPs; mid-instruction, past the function end, header bytes or ELF/Mach-O loader-rewritten bytes need allowUnsafe; encrypted bytes " +
                 "are refused; signatures become invalid.")]
    public Task<string> PatchBytes(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description("Replacement bytes as hex ('90 90', '9090' or '0x90,0x90').")] string? hex = null,
        [Description("Instead of hex: a number of type (range-checked); ptr: or a name.")] string? value = null,
        [Description("With value: i8-i64, u8-u64, f32, f64 or ptr; a be suffix for big-endian.")] string? type = null,
        [Description(AllowUnsafeDescription)] bool allowUnsafe = false,
        [Description(ToolSupport.DryRunDefaultTrueDescription)] bool dryRun = true,
        [Description(RelocationsDescription)] string? relocations = null,
        [Description(ExtendDescription)] bool extend = false,
        [Description(StubModeDescription)] string? stubMode = null,
        [Description(PlacementDescription)] string? placement = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, index, note) = await OpenToPatch(image, dryRun, progress, cancellationToken);
        var rva = Address(index, address);
        if ((hex == null) == (value == null) || (value == null) != (type == null))
            throw new ToolError(ErrorCode.InvalidArgument, "Pass hex, or value with type.", "e.g. value=0x10 type=u32");
        // ptr takes a name or address too: the VA it resolves to
        if (value != null && TypedValue.IsPointer(type) && !TypedValue.IsInteger(value))
            value = $"0x{index.Image.ImageBase + Address(index, value):X}";
        var bytes = value != null ? TypedValue.Encode(type!, value, index.Image.Is64Bit) : ParseHex(hex!);
        var prepared = extend
            ? edits.PrepareExtendedPatch(index, rva, bytes, null, PatchExtension.ParseMode(stubMode), $"patch_bytes {bytes.Length} bytes (stub)", null, PatchExtension.ParsePlacement(placement))
            : edits.PreparePatch(index, rva, bytes, allowUnsafe, value != null ? $"patch_bytes {type} {value}" : $"patch_bytes {bytes.Length} bytes", NativeEditService.ParseRelocationMode(relocations));
        return PatchOutcome(native, index, prepared, dryRun, note);
    });

    [McpServerTool(Name = "patch_asm", Title = "Assemble and patch native code", UseStructuredContent = true, OutputSchemaType = typeof(EditOutcome))]
    [Description("Assemble x86/x64 instructions (multi-line; labels, numeric and symbol branch targets; 'db <hex>') and write them at a native " +
                 "address in memory, branches and RIP-relative references computed for that address. Same safety rules, NOP padding and undo as " +
                 "patch_bytes; PE absolute addresses ([addr], 'offset name', imm64) get relocations.")]
    public Task<string> PatchAsm(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description("Assembly, one instruction per line.")] string assembly,
        [Description(AllowUnsafeDescription)] bool allowUnsafe = false,
        [Description(ToolSupport.DryRunDefaultTrueDescription)] bool dryRun = true,
        [Description(RelocationsDescription)] string? relocations = null,
        [Description(ExtendDescription)] bool extend = false,
        [Description(StubModeDescription)] string? stubMode = null,
        [Description(PlacementDescription)] string? placement = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, index, note) = await OpenToPatch(image, dryRun, progress, cancellationToken);
        var rva = Address(index, address);
        if (index.Image.Arch is not (NativeArch.X86 or NativeArch.X64))
            throw new ToolError(ErrorCode.Unsupported, $"patch_asm assembles x86 and x64; {native.Id} is {index.Image.ArchName()}.",
                "assemble the instructions elsewhere and pass their bytes to patch_bytes")
            {
                Details = new { reason = "not-assembled", arch = index.Image.MachineName },
            };
        ulong startVa = index.Image.ImageBase + rva;
        Func<string, ulong?> resolve = name =>
        {
            try { return index.Image.ImageBase + Address(index, name); }
            catch (ToolError) { return null; }
        };
        NativeEditService.PatchResult prepared;
        if (extend)
        {
            // Assemble the new code at the eventual stub address inside the extension; here only validate it decodes.
            var newBytes = X86Assembler.Assemble(index.Image.Arch, startVa, assembly, resolve).Bytes;
            prepared = edits.PrepareExtendedPatch(index, rva, newBytes, assembly, PatchExtension.ParseMode(stubMode), "patch_asm (stub)", resolve, PatchExtension.ParsePlacement(placement));
        }
        else
        {
            var result = X86Assembler.Assemble(index.Image.Arch, startVa, assembly, resolve);
            prepared = edits.PreparePatch(index, rva, result.Bytes, allowUnsafe, "patch_asm", NativeEditService.ParseRelocationMode(relocations), result.Constants, assembly);
        }
        return PatchOutcome(native, index, prepared, dryRun, note);
    });

    private string PatchOutcome(LoadedNative native, NativeCodeIndex index, NativeEditService.PatchResult prepared, bool dryRun, string note)
    {
        var applied = edits.Apply(native, index, prepared, dryRun);
        var change = PatchChange(native, applied.Patch);
        var digest = EditDigest.Of([change]);
        return ToolOutput.Edit(new EditOutcome(!dryRun, dryRun, [change], applied.EditId is { } id ? [id] : []) { Digest = digest },
            note + applied.Text + $"\nDigest {digest}{(dryRun ? " (the applied patch and the save report the same)" : "")}.");
    }

    /// <summary>A byte patch as an edit change: the dry run, the applied patch and the save's edit list digest the same.</summary>
    private static EditChange PatchChange(LoadedNative native, NativePatch p) =>
        new("bytes", NativeAddress.Va(native.Image, p.Rva), Convert.ToHexString(p.Original), Convert.ToHexString(p.Replacement));

    /// <summary>list_native_edits' row: an edit (id, tool, kind) or, with search, a matching name or comment (source, kind).</summary>
    public sealed record NativeEditRow(
        [property: Description("Edit id for undo_native_edit; absent on search rows.")] string? EditId,
        [property: Description("patch, annotation or engine; name or comment on search rows.")] string Kind,
        string? Address,
        [property: Description("What the edit did, or the matching text.")] string Text,
        [property: Description("The tool that made the edit, or the name source (user, pdb, ...).")] string Source,
        [property: Description("Addresses or items the edit changed.")] int Changes);

    /// <summary>list_native_edits' record.</summary>
    public sealed record NativeEditList(string Image, IReadOnlyList<NativeEditRow> Items, int Total,
        [property: Description("The name layers: the user's and each imported one with counts and origin.")] IReadOnlyList<string> Layers)
    {
        public int Offset { get; init; }
    }

    [McpServerTool(Name = "list_native_edits", Title = "List native edits", UseStructuredContent = true, OutputSchemaType = typeof(NativeEditList))]
    [Description("Native edits of an image in the order made, each with the editId undo_native_edit takes: byte patches, names, comments, " +
                 "engine type edits. Then the name layers (user, pdb, il2cpp, ida, ...) with counts and origin. search: the names and comments that match instead.")]
    public Task<string> ListNativeEdits(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Instead: matching names and comments: " + NameFilter.Description + ".")] string? search = null,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description("Rows per page (default 100).")] int limit = 100,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var filter = NameFilter.Parse(search);
        var (native, _) = await Open(image, progress, cancellationToken);
        var layers = edits.NameLayers(native);
        int from = Math.Max(0, offset), count = ToolSupport.ClampLimit(limit);
        List<NativeEditRow> rows;
        string header;
        if (filter == null)
        {
            rows = [.. edits.Journal.Entries(native).Select(e => Row(native, e))];
            header = $"{native.Id}: native edits in the order made (undo_native_edit editId=...)\n" +
                     (layers.Count > 0 ? "Names (priority user > pdb > nativeaot > il2cpp > objc > swift > ida > ghidra > discovered):\n" + string.Concat(layers.Select(l => $"  {l}\n")) : "");
        }
        else
        {
            rows = [.. NoteMarks.Search(native, code, filter).Select(m =>
                new NativeEditRow(null, m.Kind, NativeAddress.Va(native.Image, m.Rva), Format.Clip(m.Text.ReplaceLineEndings(" "), 200), m.Source, 1))];
            header = $"{native.Id}: names and comments matching '{filter.Text}'{filter.Note("annotation")}\n";
        }
        return ToolOutput.List(rows.Skip(from).Take(count).ToList(), from, count, rows.Count,
            r => r.EditId != null ? $"{r.EditId}  {r.Kind,-10} {r.Address ?? "",-18} {r.Text}" : $"{r.Address}  {r.Source,-9} {r.Kind,-7}  {r.Text}",
            page => new NativeEditList(native.Id, page, rows.Count, layers) { Offset = from }, filter == null ? "edit" : "hit", header);
    });

    private static NativeEditRow Row(LoadedNative native, NativeJournalEntry e)
    {
        string? address = null;
        string text = e.Description;
        int changes = 1;
        if (e.Patch is { } p)
        {
            address = NativeAddress.Va(native.Image, p.Rva);
            text = $"{p.Description}: {NativeEditService.PatchDetail(native.Image, p)}";
        }
        else if (e.Annotations.Count > 0)
        {
            changes = e.Annotations.Count;
            address = NativeAddress.Va(native.Image, e.Annotations[0].Rva);
            if (changes == 1) text = $"{e.Tool}: {Describe(e.Annotations[0])}";
        }
        else if (e.UserTypes is { } d)
        {
            changes = d.Items.Count;
            if (changes == 1 && d.Describe().First() is var (kind, target, before, after))
                text = $"{e.Tool} ({e.Engine}): {kind} {target}: {before ?? "(none)"} -> {after ?? "(none)"}";
        }
        return new NativeEditRow(e.Id.ToString(), e.Kind, address, text, e.Tool, changes);
    }

    private static string Describe(NativeAnnotationChange c)
    {
        var parts = new List<string>();
        if (c.Before.Name != c.After.Name) parts.Add($"name {c.Before.Name ?? "(none)"} -> {c.After.Name ?? "(none)"}");
        if (c.Before.Comment != c.After.Comment) parts.Add($"comment {Format.Clip((c.Before.Comment ?? "(none)").ReplaceLineEndings(" "), 60)} -> {Format.Clip((c.After.Comment ?? "(none)").ReplaceLineEndings(" "), 60)}");
        if (c.Before.Pseudo != c.After.Pseudo) parts.Add("pseudocode comment");
        if (parts.Count == 0 && c.Before.CommentKind != c.After.CommentKind) parts.Add($"comment kind {c.Before.CommentKind ?? "repeatable"} -> {c.After.CommentKind ?? "repeatable"}");
        return string.Join("; ", parts);
    }

    [McpServerTool(Name = "undo_native_edit", Title = "Undo a native edit", UseStructuredContent = true, OutputSchemaType = typeof(EditOutcome))]
    [Description("Undo native edits by editId (list_native_edits), the last by default: a patch, name, comment or engine type edit gets its previous " +
                 "value back, pushed to the engines. Refused while a later edit changed the same item.")]
    public Task<string> UndoNativeEdit(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("image#n or #n; comma-separated for several, undone in order; default the last.")] string? editId = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, _) = await Open(image, progress, cancellationToken);
        var ids = string.IsNullOrWhiteSpace(editId) ? [null] : editId.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(t => (string?)t).ToList();
        var done = new List<NativeUndoResult>();
        var results = new List<ItemResult>();
        foreach (var text in ids)
        {
            try
            {
                var r = await edits.Journal.UndoAsync(native, text == null ? null : ParseEditId(native, text), cancellationToken);
                done.Add(r);
                results.Add(new ItemResult(text ?? r.Entry.Id.ToString(), null, null, Text: UndoLine(r)));
            }
            catch (ToolError e) { results.Add(new ItemResult(text ?? "(last)", null, null, e)); }
        }
        ThrowIfAllFailed(results, "undo_native_edit");
        var sb = new System.Text.StringBuilder();
        foreach (var r in results) sb.Append(r.Error != null ? $"{r.Address}: failed: {r.Error.Message}\n" : r.Text + "\n");
        sb.Append($"{edits.Journal.Entries(native).Count} native edit(s) remain.");
        int failed = results.Count(r => r.Error != null);
        var outcome = new EditOutcome(true, false, [.. done.SelectMany(r => r.Changes)], [.. done.Select(r => r.Entry.Id)])
        {
            Failed = failed > 0 ? failed : null,
            Items = failed > 0 ? [.. results.Where(r => r.Error != null).Select(r => (object)new { target = r.Address, error = BatchError.From(r.Error!) })] : null,
            PushedTo = done.SelectMany(r => r.PushedTo).Distinct().ToList() is { Count: > 0 } engines ? engines : null,
        };
        return ToolOutput.Edit(outcome, sb.ToString());
    });

    private static string UndoLine(NativeUndoResult r)
    {
        var what = r.Changes.Count == 1 ? $"{r.Changes[0].Kind} at {r.Changes[0].Target} back to {r.Changes[0].After ?? "(none)"}" : $"{r.Changes.Count} change(s)";
        return $"Undid {r.Entry.Id} ({r.Entry.Description}): {what}" +
               (r.PushedTo.Count > 0 ? $"; pushed to {string.Join(", ", r.PushedTo.Select(NativeEngineService.DisplayName))}" : "") + "." +
               string.Concat(r.Notes.Select(n => $"\n  note: {n}"));
    }

    /// <summary>An edit id of <paramref name="native"/>: "image#n", "#n" or "n".</summary>
    internal static EditId ParseEditId(LoadedNative native, string text)
    {
        var t = text.Trim();
        if (EditId.TryParse(t, out var id) && id.Target.Length > 0) return id;
        if (int.TryParse(t.TrimStart('#'), out var n) && n > 0) return new EditId(native.Id, n);
        throw new ToolError(ErrorCode.InvalidArgument, $"'{text}' is not an edit id.", "pass an id from list_native_edits, e.g. " + native.Id + "#1");
    }

    /// <summary>save_native's record.</summary>
    public sealed record NativeSaveResult(string OutputPath, long Bytes, int Patches, string Sha256,
        [property: Description("The recomputed PE checksum, when the original had one.")] string? Checksum,
        [property: Description("The original's backup, when the original was replaced.")] string? Backup,
        [property: Description("Every byte outside the patches matches the original and the relocations re-parse as planned.")] bool Verified,
        IReadOnlyList<string> Notes)
    {
        [Description("The byte patches written: edit id and the digest their dry run and the applied patch reported.")]
        public IReadOnlyList<SavedEdit> EditList { get; init; } = [];
    }

    [McpServerTool(Name = "save_native", Title = "Save patched native image", UseStructuredContent = true, OutputSchemaType = typeof(NativeSaveResult))]
    [Description("Write the patched native image to a new file: unpatched bytes identical, PE checksum recomputed, a signature invalidated " +
                 "(stripSignature removes it). Atomic and verified before it replaces the target; replaceOriginal=true keeps a .bak and refuses a file changed on disk.")]
    public Task<string> SaveNative(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Output file path.")] string outputPath,
        [Description("Replace an existing file, not the original.")] bool overwrite = false,
        [Description("Remove the Authenticode certificate table from the output.")] bool stripSignature = false,
        [Description("Replace the loaded file itself (needs --allow-replace-original).")] bool replaceOriginal = false,
        [Description("Write '<name>.N.dll', the first free N.")] bool versioned = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        SaveTarget.RequireReplaceAllowed(replaceOriginal, options);
        var (native, _) = await Open(image, progress, cancellationToken);
        var saved = edits.Write(native, outputPath, overwrite, stripSignature, replaceOriginal, versioned);
        journal?.Saved(native);
        var written = edits.Journal.Entries(native).Where(e => e.Patch != null).Select(e => new SavedEdit(e.Id, EditDigest.Of([PatchChange(native, e.Patch!)]))).ToList();
        var text = saved.Text + (written.Count > 0 ? $"\nPatches written: {string.Join(", ", written.Select(e => $"{e.Id} ({e.Digest})"))}." : "");
        return ToolOutput.Report(text, new NativeSaveResult(saved.OutputPath, saved.Bytes, saved.Patches, saved.Sha256, saved.Checksum, saved.Backup, saved.Verified, saved.Notes)
            { EditList = written });
    });

    private static byte[] ParseHex(string hex)
    {
        var t = (hex ?? "").Replace(",", " ").Replace("0x", " ", StringComparison.OrdinalIgnoreCase).Replace("\\x", " ");
        var compact = new string(t.Where(c => !char.IsWhiteSpace(c)).ToArray());
        if (compact.Length == 0 || compact.Length % 2 != 0 || !compact.All(Uri.IsHexDigit))
            throw new ToolError(ErrorCode.InvalidArgument, $"'{hex}' is not a hex byte string.", "pass bytes as hex, e.g. '90 90' or '9090'");
        var bytes = new byte[compact.Length / 2];
        for (int i = 0; i < bytes.Length; i++) bytes[i] = Convert.ToByte(compact.Substring(i * 2, 2), 16);
        return bytes;
    }
}
