using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Patching;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tools;

/// <summary>Native annotations (rename, comment, export) and byte/assembly patching with undo and save.</summary>
[McpServerToolType]
public sealed class NativeEditTools(AssemblyWorkspace workspace, NativeCodeService code, NativeEditService edits, EditJournal? journal = null,
    NativeEngineService? engines = null, NativeNamePush? names = null, NativeTypePush? types = null, NativeUserTypePush? userTypes = null)
{
    private async Task<(LoadedNative Native, NativeCodeIndex Index)> Open(string image, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var native = await Task.Run(() =>
        {
            var id = workspace.Read(() => workspace.FindNative(image)?.Id);
            if (id == null && !string.IsNullOrWhiteSpace(image) && Path.IsPathFullyQualified(image.Trim()) && File.Exists(image.Trim()))
                id = workspace.LoadAny(image.Trim()).Native?.Id ?? throw new ToolError(ErrorCode.Unsupported, $"{image} is a .NET assembly, not a native image.", "use the .NET tools for it");
            return workspace.Read(() => workspace.GetNative(id ?? image));
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
        "Base relocations under the patch: auto (default) keeps entries where the new bytes still hold an address, neutralizes the rest and " +
        "adds entries for new absolute addresses in a free slot of the page's block; keep leaves them; neutralize neutralizes all. Reported; " +
        "undo restores them. Ignored with extend=true.";

    private const string ExtendDescription =
        "Place the new code in a stub (a code cave or a new section, see placement): the site becomes a near jump to it and control returns " +
        "after the site. For code larger than the site, or to keep the site intact. Refused with a reason code when unsafe (branch_target_in_site, " +
        "displaced_absolute_reloc, unwind_data, no_space, no_space_at_site, no_header_space, stub_needs_reloc, unreachable_section, arm64_unsupported). One undoable edit.";

    private const string StubModeDescription =
        "With extend=true: replace (default; the new code instead of the displaced instructions), before (new code, then them) or after.";

    private const string PlacementDescription =
        "With extend=true: auto (default; a code cave if one fits, else a new executable section), cave (no_space when none fits) or " +
        "section (always new; header fields and checksum updated, undo restores the file byte-for-byte).";

    [McpServerTool(Name = "rename_native", Title = "Name a native address")]
    [Description("Name a native address: shown by list_functions, disassemble, find_xrefs and native_call_tree, pushed to the engines, and kept in " +
                 "a per-user sidecar keyed by the file's SHA-256. C-identifier-like (<=255 chars), unique unless allowDuplicate. Empty clears. " + BatchNote)]
    public Task<string> RenameNative(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string? address = null,
        [Description("The new name; empty to clear the name at this address.")] string? name = null,
        [Description("Allow a name already used at another address.")] bool allowDuplicate = false,
        [Description("Lines 'address = name', or JSON [{address, name}].")] string? items = null,
        [Description("Check only; record nothing.")] bool dryRun = false,
        [Description("Stop at the first failing item.")] bool stopOnError = false,
        [Description(DecompileDiff.Description)] string? showDecompile = null,
        [Description(PushEngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var show = DecompileDiff.Parse(showDecompile);
        if (show != null && items != null) throw new ToolError(ErrorCode.InvalidArgument, "showDecompile takes one address, not items.");
        var (native, index) = await Open(image, progress, cancellationToken);
        if (items == null && !dryRun)
        {
            if (string.IsNullOrWhiteSpace(address) || name == null)
                throw new ToolError(ErrorCode.InvalidArgument, "Pass address and name, or items.", "items takes lines 'address = name'");
            var rva = Address(index, address);
            if (show == null)
            {
                var done = string.IsNullOrWhiteSpace(name) ? edits.ClearName(native, index, rva) : edits.Rename(native, index, rva, name, allowDuplicate);
                await PushNames(native, engine, progress, cancellationToken);
                return done;
            }
            // the session is opened first so the pseudocode before the rename is the engine's with every earlier name
            if (engines == null) throw new ToolError(ErrorCode.Unsupported, "showDecompile needs a decompiler engine.");
            var session = await engines.Session(native, string.IsNullOrWhiteSpace(engine) ? null : engine, new Progress<NativeProviderProgress>(p =>
                progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
            await EnsurePushed(native, session, cancellationToken);
            var function = await DecompileDiff.FunctionFor(session, rva, cancellationToken);
            var before = show == "diff" ? await DecompileDiff.Text(session, function, cancellationToken) : default;
            var text = string.IsNullOrWhiteSpace(name) ? edits.ClearName(native, index, rva) : edits.Rename(native, index, rva, name, allowDuplicate);
            await EnsurePushed(native, session, cancellationToken);
            var after = await DecompileDiff.Text(session, function, cancellationToken);
            return text + DecompileDiff.Render(show, before, after, function is { } f ? $"the function at rva 0x{f:X}" : "the function");
        }
        var list = BatchItems(items, address, name, "name");
        var results = new List<BatchResult>();
        var changes = new List<(uint Rva, string? Name)>();
        var used = edits.Annotations(native).Names().ToDictionary(n => n.Rva, n => n.Name);
        foreach (var item in list)
        {
            string? error = null, shown = item.Value;
            uint rva = 0;
            try
            {
                rva = Address(index, item.Address);
                var next = string.IsNullOrWhiteSpace(item.Value) ? null : NativeName.Validate(item.Value);
                shown = $"{index.NameAt(rva) ?? "(no name)"} -> {next ?? "(cleared)"}";
                if (next != null && !allowDuplicate && used.FirstOrDefault(u => u.Key != rva && u.Value == next) is { Value: not null } other)
                    throw new ToolError(ErrorCode.Conflict, $"'{next}' is already used at {NativeAddress.Va(index.Image, other.Key)}");
                if (changes.Any(c => c.Rva == rva)) throw new ToolError(ErrorCode.Conflict, "the address is named twice in this batch");
                if (next == null) used.Remove(rva);
                else used[rva] = next;
                changes.Add((rva, next));
            }
            catch (ToolError e) { error = e.Message; }
            results.Add(new BatchResult(item.Address, shown, error));
            if (error != null && stopOnError) break;
        }
        if (!dryRun && changes.Count > 0)
        {
            edits.ApplyNames(native, index, changes, allowDuplicate: true); // checked above, across the batch
            await PushNames(native, engine, progress, cancellationToken);
        }
        return Summary("name", results, list.Count, dryRun);
    });

    private const string BatchNote = "items: many in one sidecar write and one engine push, each reported.";

    private const string PushEngineDescription = "Engine to push the change to now (default: one with this image open; else at its next use): auto, ida or ghidra.";

    /// <summary>One item of a batch: the address and the value (a name or a comment's text), plus the optional per-item fields.</summary>
    internal sealed record BatchItem(string Address, string Value, string? Scope = null, bool? Append = null);

    internal sealed record BatchResult(string Address, string Shown, string? Error);

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

    private static string Summary(string what, IReadOnlyList<BatchResult> results, int total, bool dryRun)
    {
        int failed = results.Count(r => r.Error != null);
        var sb = new System.Text.StringBuilder($"{(dryRun ? "Dry run: " : "")}{total} {what} item(s): {results.Count - failed} ok, {failed} failed" +
                                               (results.Count < total ? $", stopped after item {results.Count}" : "") + (dryRun ? "; nothing recorded" : "") + "\n");
        foreach (var r in results) sb.AppendLine($"  {r.Address}  {(r.Error == null ? r.Shown : $"failed: {r.Error}")}");
        return sb.ToString();
    }

    [McpServerTool(Name = "comment_native", Title = "Comment a native address")]
    [Description("Comment a native address (kept, pushed to engines). scope: line (repeatable: also where the address is " +
                 "referenced), eol, pre or plate (engine kinds; Ghidra's decompiler shows pre), pseudocode (on the statement made from the address), " +
                 "function, or auto (function at a function start, else line and pseudocode). append adds a line (dedupe skips one it has). Empty clears. " + BatchNote)]
    public Task<string> CommentNative(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string? address = null,
        [Description("The comment text; empty to clear it.")] string? text = null,
        [Description("auto, line, eol, pre, plate, pseudocode or function.")] string? scope = null,
        [Description("Add text as a new line of the existing comment.")] bool append = false,
        [Description("With append: skip a line the comment already has (default true).")] bool dedupe = true,
        [Description("Lines 'address = text', or JSON [{address, text, scope?, append?}].")] string? items = null,
        [Description("Check only; record nothing.")] bool dryRun = false,
        [Description("Stop at the first failing item.")] bool stopOnError = false,
        [Description(PushEngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, index) = await Open(image, progress, cancellationToken);
        var list = BatchItems(items, address, text, "text");
        var defaultScope = CommentScopes.Parse(scope);
        var plans = new List<CommentPlan>();
        var results = new List<BatchResult>();
        foreach (var item in list)
        {
            try
            {
                var plan = PlanComment(native, index, Address(index, item.Address), item.Value, item.Scope != null ? CommentScopes.Parse(item.Scope) : defaultScope,
                    item.Append ?? append, dedupe);
                if (plan.Change != null && plans.Any(p => p.Change?.Rva == plan.Rva))
                    throw new ToolError(ErrorCode.Conflict, "the address is commented twice in this batch");
                plans.Add(plan);
                results.Add(new BatchResult(item.Address, plan.Text, null));
            }
            catch (ToolError e) when (items != null)
            {
                results.Add(new BatchResult(item.Address, "", e.Message));
                if (stopOnError) break;
            }
        }
        var changes = plans.Select(p => p.Change).OfType<NativeEditService.CommentChange>().ToList();
        NativeNamePush.PushResult? pushed = null;
        if (!dryRun && changes.Count > 0)
        {
            edits.ApplyComments(native, index, changes);
            pushed = await PushNames(native, engine, progress, cancellationToken);
        }
        var pseudo = changes.Where(c => c.Pseudo != null).Select(c => c.Rva).ToList();
        var note = dryRun || pseudo.Count == 0 ? "" : PushNote(pushed, pseudo);
        if (items == null) return (dryRun ? "Dry run: " : "") + (results[0].Error ?? results[0].Shown) + note;
        return Summary("comment", results, list.Count, dryRun) + note.TrimStart();
    });

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
    internal CommentPlan PlanComment(LoadedNative native, NativeCodeIndex index, uint rva, string text, string scope, bool append, bool dedupe)
    {
        var fn = index.FunctionAt(rva);
        if (scope == CommentScopes.Function && fn == null)
            throw new ToolError(ErrorCode.NotFound, $"No function contains {NativeAddress.Va(index.Image, rva)}.", "use scope=line, or list_functions for the functions");
        if (scope == CommentScopes.Auto) scope = fn?.Start == rva ? CommentScopes.Function : "both";
        uint at = scope == CommentScopes.Function ? fn!.Start : rva;
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
            line = Next(index.Sourced.CommentAt(at)?.Text, scope == CommentScopes.Function ? $"function {fn!.Name}" : kind ?? "line", kindChanges);
        if (scope is CommentScopes.Pseudocode or "both")
            pseudo = Next(ann.PseudoCommentAt(at), "pseudocode");
        return new CommentPlan(at, line == null && pseudo == null ? null : new NativeEditService.CommentChange(at, line, pseudo) { Kind = kind },
            $"{NativeAddress.Va(index.Image, at)}: {string.Join("; ", parts)}.");
    }

    /// <summary>Pushes the names and comments into an engine session now: the one asked for, else one open on the image; null when none.</summary>
    private async Task<NativeNamePush.PushResult?> PushNames(LoadedNative native, string? engine, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        if (engines == null || names == null) return null;
        var session = string.IsNullOrWhiteSpace(engine) ? engines.CompletedSession(native)
            : await engines.Session(native, engine, new Progress<NativeProviderProgress>(p =>
                progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), ct);
        return session == null ? null : await EnsurePushed(native, session, ct) ?? new NativeNamePush.PushResult(0, 0, null, true, "", TimeSpan.Zero);
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

    [McpServerTool(Name = "export_native_annotations", Title = "Export native annotations")]
    [Description("Write the image's names and comments as an IDAPython script (ida), a Ghidra script (ghidra) or JSON; the IDA script and JSON " +
                 "also carry the user's engine types. Scripts apply by RVA, rebased to the database's image base. header: a C header of declared " +
                 "types, prototypes by name and externs of typed globals.")]
    public Task<string> ExportNativeAnnotations(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Output file path.")] string outputPath,
        [Description("ida, ghidra, json (default) or header.")] string? format = null,
        [Description("Replace outputPath if it exists.")] bool overwrite = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, index) = await Open(image, progress, cancellationToken);
        var fmt = AnnotationExport.ParseFormat(format);
        var ann = edits.Annotations(native);
        var text = fmt == AnnotationExport.Format.Header
            ? AnnotationHeader.Render(ann, index.NameAt, rva => index.FunctionByStart(rva) != null)
            : AnnotationExport.Render(ann, fmt);
        var target = SafeFile.WriteAllText(outputPath, text, overwrite);
        return $"Exported {ann.NameCount} name(s), {ann.CommentCount} comment(s), {ann.PseudoCommentCount} pseudocode comment(s) and {ann.UserTypes.Count} user type(s) to {target} ({fmt} format)" +
               (fmt == AnnotationExport.Format.Ghidra && ann.UserTypes.Count > 0 ? "; user types are not in Ghidra scripts." : ".");
    });

    [McpServerTool(Name = "patch_bytes", Title = "Patch native bytes")]
    [Description("Replace bytes at a native address with a hex string, in memory. The patch is recorded as an undoable edit and every read path " +
                 "(disassemble, strings, search_bytes, read_bytes) then sees the patched bytes. Over code, trailing bytes of a partly overwritten " +
                 "instruction are padded with NOPs; refused mid-instruction, past the function end or on zero-fill/header bytes unless force=true. " +
                 "Relocations under the patch are planned (see relocations). dryRun previews without recording.")]
    public Task<string> PatchBytes(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description("Replacement bytes as hex (e.g. '90 90' or '9090' or '0x90,0x90').")] string? hex = null,
        [Description("Instead of hex: a number written as type (range-checked).")] string? value = null,
        [Description("With value: i8-i64, u8-u64, f32, f64 or ptr; a be suffix for big-endian.")] string? type = null,
        [Description("Override the safety checks (mid-instruction, past function end, header bytes, a new address with no free relocation slot).")] bool force = false,
        [Description("Preview only; do not record the patch.")] bool dryRun = false,
        [Description(RelocationsDescription)] string? relocations = null,
        [Description(ExtendDescription)] bool extend = false,
        [Description(StubModeDescription)] string? stubMode = null,
        [Description(PlacementDescription)] string? placement = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, index) = await Open(image, progress, cancellationToken);
        var rva = Address(index, address);
        if ((hex == null) == (value == null) || (value == null) != (type == null))
            throw new ToolError(ErrorCode.InvalidArgument, "Pass hex, or value with type.", "e.g. value=0x10 type=u32");
        var bytes = value != null ? TypedValue.Encode(type!, value, index.Image.Is64Bit) : ParseHex(hex!);
        if (extend)
        {
            var extended = edits.PrepareExtendedPatch(index, rva, bytes, null, PatchExtension.ParseMode(stubMode), $"patch_bytes {bytes.Length} bytes (stub)", null, PatchExtension.ParsePlacement(placement));
            return edits.ApplyPatch(native, index, extended, dryRun);
        }
        var mode = NativeEditService.ParseRelocationMode(relocations);
        var prepared = edits.PreparePatch(index, rva, bytes, force, value != null ? $"patch_bytes {type} {value}" : $"patch_bytes {bytes.Length} bytes", mode);
        return edits.ApplyPatch(native, index, prepared, dryRun);
    });

    [McpServerTool(Name = "patch_asm", Title = "Assemble and patch native code")]
    [Description("Assemble x86/x64 instructions (multi-line; labels, numeric and symbol branch targets; a 'db <hex>' escape) and write them at a " +
                 "native address, in memory. Branch displacements and RIP-relative references are computed for the target address. Same safety rules " +
                 "and NOP padding as patch_bytes; the patch is recorded as an undoable edit. Absolute addresses (x86 [addr] operands, 'offset name' / " +
                 "symbol immediates, x64 imm64 addresses) get base relocations and overwritten ones are neutralized (see relocations). dryRun previews.")]
    public Task<string> PatchAsm(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description("Assembly, one instruction per line (e.g. 'jmp target' with a 'target:' label, or 'mov eax, 1\\nret').")] string assembly,
        [Description("Override the safety checks (mid-instruction, past function end, header bytes, a new address with no free relocation slot).")] bool force = false,
        [Description("Preview only; do not record the patch.")] bool dryRun = false,
        [Description(RelocationsDescription)] string? relocations = null,
        [Description(ExtendDescription)] bool extend = false,
        [Description(StubModeDescription)] string? stubMode = null,
        [Description(PlacementDescription)] string? placement = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, index) = await Open(image, progress, cancellationToken);
        var rva = Address(index, address);
        ulong startVa = index.Image.ImageBase + rva;
        Func<string, ulong?> resolve = name =>
        {
            try { return index.Image.ImageBase + Address(index, name); }
            catch (ToolError) { return null; }
        };
        if (extend)
        {
            // Assemble the new code at the eventual stub address inside the extension; here only validate it decodes.
            var newBytes = X86Assembler.Assemble(index.Image.Arch, startVa, assembly, resolve).Bytes;
            var extended = edits.PrepareExtendedPatch(index, rva, newBytes, assembly, PatchExtension.ParseMode(stubMode), "patch_asm (stub)", resolve, PatchExtension.ParsePlacement(placement));
            return edits.ApplyPatch(native, index, extended, dryRun);
        }
        var mode = NativeEditService.ParseRelocationMode(relocations);
        var result = X86Assembler.Assemble(index.Image.Arch, startVa, assembly, resolve);
        var prepared = edits.PreparePatch(index, rva, result.Bytes, force, "patch_asm", mode, result.Constants, assembly);
        return edits.ApplyPatch(native, index, prepared, dryRun);
    });

    [McpServerTool(Name = "list_native_edits", Title = "List native byte patches")]
    [Description("The in-memory byte patches of a native image, numbered; undo_native_edit reverts by number and save_native writes them to a file. " +
                 "Then the names by source: the user's (rename_native / comment_native) and each imported layer (pdb, il2cpp, ida) with counts, origin, " +
                 "source file and identity, and whether it was saved or restored from the saved copy when the image loaded (with the import time).")]
    public Task<string> ListNativeEdits(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Instead: the names and comments (user and layers) whose text matches: " + NameFilter.Description + ".")] string? search = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var filter = NameFilter.Parse(search);
        var (native, _) = await Open(image, progress, cancellationToken);
        if (filter == null) return edits.List(native);
        var matches = NoteMarks.Search(native, code, filter);
        var rows = matches.Select(m => $"{NativeAddress.Va(native.Image, m.Rva)}  {m.Source,-9} {m.Kind,-7}  {Format.Clip(m.Text.ReplaceLineEndings(" "), 200)}").ToList();
        int shown = Math.Min(rows.Count, MaxSearchRows);
        return $"{native.Id}: {matches.Count} name(s) and comment(s) matching '{filter.Text}'\n" + string.Join("\n", rows.Take(shown)) +
               (rows.Count > shown ? $"\n... {rows.Count - shown} more: narrow the search" : "") + filter.Note("annotation");
    });

    /// <summary>Rows list_native_edits search= shows.</summary>
    private const int MaxSearchRows = 500;

    [McpServerTool(Name = "undo_native_edit", Title = "Undo a native byte patch")]
    [Description("Undo one in-memory byte patch of a native image — the last by default, or any earlier one by number (from list_native_edits).")]
    public Task<string> UndoNativeEdit(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Patch number (1-based, from list_native_edits). Omit to undo the last.")] int? number = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, _) = await Open(image, progress, cancellationToken);
        return edits.Undo(native, number);
    });

    [McpServerTool(Name = "save_native", Title = "Save patched native image")]
    [Description("Write the patched native image to a file: unpatched bytes identical, PE checksum recomputed when present, a signed file becomes " +
                 "unsigned (stripSignature removes the certificate table). Atomic; overwrite=true backs the original up to .bak and refuses one changed " +
                 "on disk; the written file is re-parsed and every byte outside the patches and every relocation entry checked before it replaces the target.")]
    public Task<string> SaveNative(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Output file path.")] string outputPath,
        [Description("Allow replacing an existing file.")] bool overwrite = false,
        [Description("Remove the Authenticode certificate table from the output.")] bool stripSignature = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, _) = await Open(image, progress, cancellationToken);
        var report = edits.Save(native, outputPath, overwrite, stripSignature);
        journal?.Saved(native);
        return report;
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
