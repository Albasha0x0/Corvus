using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Providers;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>
/// The user's types in the decompiler engine (declarations, prototypes and global types, locals, stack variables) and a
/// view of the engine's types and frames. Every edit is kept in the image's annotation sidecar (re-applied to a new
/// database, exported, carried to new builds).
/// </summary>
[McpServerToolType]
public sealed class NativeTypeTools(AssemblyWorkspace workspace, NativeEngineService engines, NativeUserTypePush userTypes, NativeCodeService? code = null,
    NativeNamePush? names = null, NativeTypePush? types = null, NativeEditJournal? journal = null)
{
    private const string EngineDescription = EngineChoice.EngineOnlyDescription;

    private const string KeptNote = " Kept with the image's annotations.";

    /// <summary>The image, an address in it and its engine session, with names and recovered types pushed first so user types apply on top.</summary>
    private async Task<(LoadedNative Native, uint Rva, INativeDecompilerSession Session)> Open(string image, string address, string? engine,
        IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        EngineChoice.Mode(engine, engines); // an unknown engine fails before the image is opened
        var (native, rva) = await Task.Run(() => NativeAnalysisTools.Resolve(workspace, code, image, address), ct);
        var choice = EngineChoice.EngineOnly(engine, engines, native);
        var session = await engines.Session(native, choice.Engine, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), ct);
        EngineReport.Answered(choice, engines, session);
        if (names != null) await names.EnsureAsync(native, session, ct);
        if (types != null) await types.EnsureAsync(native, session, ct);
        await userTypes.EnsureAsync(native, session, ct);
        return (native, rva, session);
    }

    /// <summary>An engine edit kept in the image's user types and recorded in the native edit journal (its id, or null when nothing changed).</summary>
    private async Task<(UserTypeResult Result, EditId? Id)> Apply(LoadedNative native, INativeDecompilerSession session, string tool, NativeUserTypeBatch batch,
        Func<UserTypeResult, UserTypeLayer, UserTypeLayer?> record, CancellationToken ct, NativeUserTypeBatch? inverse = null) =>
        journal != null ? await journal.ApplyUserTypesAsync(native, session, tool, batch, record, ct, inverse: inverse)
            : (await userTypes.ApplyAsync(native, session, batch, record, ct), null);

    /// <summary>The outcome of an engine edit in both parts: the text, then the edit id an undo takes.</summary>
    private static string Edited(string text, EditId? id, params EditChange[] changes) => Edited(text, id, changes, null);

    private static string Edited(string text, EditId? id, IReadOnlyList<EditChange> changes, int? failed)
    {
        text = text.TrimEnd('\n') + (id is { } e ? $"\nEdit {e} (undo_native_edit editId={e} takes it back)" : "") + "\n";
        return ToolOutput.With(text, new EditResult(changes.Count > 0, false, [.. changes.Select(c => new EditResult.Change(c.Kind, c.Target))], id is { } i ? [i.ToString()] : [])
            { Failed = failed is > 0 ? failed : null });
    }

    public sealed record FrameRow(
        string Kind,
        string Name,
        string Type,
        int? Offset,
        int? BaseOffset,
        int? Size,
        string? Slot,
        string? Location,
        bool? Argument,
        bool? UserName,
        bool? UserType);

    public sealed record FrameReport(string Image, string Engine, string Function, string Name,
        int LocalSize, int SavedRegisters, int ReturnAddressOffset, int Members, int Locals,
        string? LocalsNote,
        IReadOnlyList<FrameRow> Items, int Offset, int Total);

    [McpServerTool(Name = "get_native_frame", Title = "Native stack frame and locals", UseStructuredContent = true, OutputSchemaType = typeof(FrameReport))]
    [Description("Stack frame of a native function as the engine has it (members: offset, name, type, size; Ghidra counts saved registers as " +
                 "locals); locals=true adds the decompiler's locals (name, type, register or stack offset, user edits). Offsets count from the lowest " +
                 "address; brackets from the return address.")]
    public Task<string> GetNativeFrame(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("The function: " + NativeTools.AddressDescription)] string function,
        [Description(EngineDescription)] string? engine = null,
        [Description("Decompile for the locals too.")] bool locals = false,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description("Max rows (max 5000).")] int limit = 200,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        string? setup = null;
        if (locals && engines.OutputCache != null)
        {
            // another process read this frame in the database state saved on disk, after the same pushes: no engine needed
            EngineChoice.Mode(engine, engines);
            var (saved, at) = await Task.Run(() => NativeAnalysisTools.Resolve(workspace, code, image, function), cancellationToken);
            var answer = EngineChoice.EngineOnly(engine, engines, saved);
            setup = EngineReport.SetupDigest(saved, code, "frame", names != null, types != null);
            if (engines.Answer<NativeFrame>(saved, answer.Engine, setup, OutputCacheKinds.Frame, at) is { } stored)
            {
                EngineReport.Answered(answer, engines);
                EngineReport.Cached(1, 0);
                return FrameResult(saved, stored, answer.Engine, locals, offset, limit);
            }
        }
        var (native, rva, session) = await Open(image, function, engine, progress, cancellationToken);
        NativeFrame f;
        using (EngineReport.Heartbeat(progress, $"{session.ProviderId} reading the frame at {Va(native, rva)}"))
            f = await session.GetFrameAsync(rva, locals, cancellationToken);
        // the digest after the open: a PDB the engine fetched during it is part of the state this answer was made in
        if (setup != null) engines.Remember(native, session, EngineReport.SetupDigest(native, code, "frame", names != null, types != null), OutputCacheKinds.Frame, rva, f);
        return FrameResult(native, f, session.ProviderId, locals, offset, limit);
    });

    private static string FrameResult(LoadedNative native, NativeFrame f, string engine, bool locals, int offset, int limit)
    {
        var (display, symbol) = NativeTools.Named(f.Name, native.Image.Format);
        var rows = new List<FrameRow>();
        foreach (var m in f.Members)
            rows.Add(new FrameRow("member", m.Name, m.Type, m.Offset, m.Offset - f.ReturnAddressOffset, m.Size, m.Kind, null, null, null, null));
        var named = f.Locals.Where(l => l.Name.Length > 0).ToList();
        foreach (var l in named)
            rows.Add(new FrameRow("local", l.Name, l.Type, l.Stack, null, null, null, l.Stack is { } ? "stack" : l.Location, l.IsArgument ? true : null,
                l.UserName ? true : null, l.UserType ? true : null));
        string? localsNote = !locals ? "not asked (locals=true adds them)" : f.DecompilerError;
        var header = $"Frame of {display} at {Va(native, f.StartRva)}{(symbol.Length > 0 ? $" ({symbol[2..]})" : "")} ({engine}): {f.LocalSize} bytes of " +
                     $"locals, {f.SavedRegisters} of saved registers; return address at +0x{f.ReturnAddressOffset:X}; {Plural(f.Members.Count, "member")}, " +
                     (localsNote != null ? $"no decompiler locals ({localsNote})" : Plural(named.Count, "decompiler local")) + "\n";
        offset = Math.Max(0, offset);
        return ToolOutput.List(rows.Skip(offset).ToList(), offset, limit, rows.Count, Row,
            page => new FrameReport(native.Id, engine, Va(native, f.StartRva), display, f.LocalSize, f.SavedRegisters, f.ReturnAddressOffset,
                f.Members.Count, named.Count, localsNote, page, offset, rows.Count), "row", header);
    }

    private static string Row(FrameRow r) => r.Kind == "member"
        ? $"member +0x{r.Offset:X} [{(r.BaseOffset < 0 ? "-" : "+")}0x{Math.Abs(r.BaseOffset ?? 0):X}]  {r.Name}  {r.Type}  {r.Size}  {r.Slot}"
        : $"local  {r.Name}  {r.Type}  {(r.Offset is { } s ? $"stack:0x{s:X}" : r.Location)}" +
          (r.Argument == true ? "  argument" : "") + (r.UserName == true ? "  user name" : "") + (r.UserType == true ? "  user type" : "");

    private static string Plural(int n, string noun) => ToolSupport.Plural(n, noun);

    [McpServerTool(Name = "set_native_stack_var", Title = "Rename, retype or delete a stack variable", UseStructuredContent = true, OutputSchemaType = typeof(EditResult))]
    [Description("Rename and/or retype a stack frame member, by its get_native_frame name (var_28) or frame offset (0x20, from the lowest " +
                 "address); a type at an empty offset creates one. The return address and saved registers are refused." + KeptNote)]
    public Task<string> SetNativeStackVar(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("The function: " + NativeTools.AddressDescription)] string function,
        [Description("The member: its name, or its frame offset (hex).")] string variable,
        [Description("New name (a C identifier).")] string? newName = null,
        [Description("New C type.")] string? type = null,
        [Description("Delete the member.")] bool delete = false,
        [Description("Drop the user's edit, restoring the engine's member.")] bool clear = false,
        [Description(DecompileDiff.Description)] string? showDecompile = null,
        [Description(EngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var name = string.IsNullOrWhiteSpace(newName) ? null : newName.Trim();
        var decl = string.IsNullOrWhiteSpace(type) ? null : type.Trim();
        if ((delete || clear) && (name != null || decl != null || (delete && clear)))
            throw new ToolError(ErrorCode.InvalidArgument, "delete and clear take no newName or type, and not each other.", "pass one of: newName/type, delete=true, clear=true");
        if (!delete && !clear && name == null && decl == null)
            throw new ToolError(ErrorCode.InvalidArgument, "Nothing to change.", "pass newName, type or both, delete=true or clear=true");
        if (name != null && !Identifier(name))
            throw new ToolError(ErrorCode.InvalidArgument, $"'{name}' is not a C identifier.", "use letters, digits and _, not starting with a digit");
        var show = DecompileDiff.Parse(showDecompile);
        var (native, rva, session) = await Open(image, function, engine, progress, cancellationToken);
        return await WithDecompile(show, session, rva, async () =>
        {
        var frame = await session.GetFrameAsync(rva, false, cancellationToken);
        var v = (variable ?? "").Trim();
        int offset = frame.Members.FirstOrDefault(m => m.Name == v) is { } byName ? byName.Offset
            : NativeAddress.Number(v.TrimStart('+')) is { } n && n <= int.MaxValue ? (int)n
            : throw MissingMember(frame, v);
        var edit = new NativeStackVarEdit(frame.StartRva, offset, name, decl) { Delete = delete, Clear = clear };
        var (result, id) = await Apply(native, session, "set_native_stack_var", new NativeUserTypeBatch([], [], [edit], []),
            (r, layer) => r.Items is not [{ Applied: true } item] ? null
                : clear ? layer.WithoutStackVar(item.Rva, offset) : layer.WithStackVar(edit with { Function = item.Rva }), cancellationToken);
        var done = Outcome(result, session.ProviderId, frame);
        var where = $"{Va(native, done.Rva)}+0x{offset:X}";
        var change = new EditChange("stack_var", where, done.Resolved, clear ? "(engine's)" : delete ? null : done.Text);
        if (clear) return Edited($"Stack member +0x{offset:X} of {frame.Name} at {Va(native, done.Rva)}: the user edit is cleared; now {done.Text}", id, change);
        return Edited(delete ? $"Stack member +0x{offset:X} of {frame.Name} at {Va(native, done.Rva)}: {(done.Resolved != null ? $"{done.Resolved} " : "")}{done.Text}"
            : $"Stack member +0x{offset:X} of {frame.Name} at {Va(native, done.Rva)}{(done.Resolved != null ? $" (was {done.Resolved})" : "")} is now: {done.Text}", id, change);
        }, cancellationToken);
    });

    /// <summary>A stack member the frame does not have, with a Next naming members or a valid offset (never an empty list).</summary>
    internal static ToolError MissingMember(NativeFrame frame, string member) =>
        new(ErrorCode.InvalidArgument, $"The frame of {frame.Name} has no member '{member}'.",
            frame.Members.Count == 0
                ? $"the frame has no members; pass a frame offset such as 0x{Math.Max(0, frame.ReturnAddressOffset - 8):X} (get_native_frame shows the frame)"
                : $"members: {string.Join(", ", frame.Members.Select(m => m.Name).Take(40))}; or pass a frame offset such as 0x{frame.Members[0].Offset:X}");

    /// <summary>Runs <paramref name="edit"/>, with the function's pseudocode after it (or before and after) when <paramref name="show"/> asks.</summary>
    private static async Task<string> WithDecompile(string? show, INativeDecompilerSession session, uint rva, Func<Task<string>> edit, CancellationToken ct)
    {
        if (show == null) return await edit();
        var function = await DecompileDiff.FunctionFor(session, rva, ct);
        var before = show == "diff" ? await DecompileDiff.Text(session, function, ct) : default;
        var result = await edit();
        var after = await DecompileDiff.Text(session, function, ct);
        return result + DecompileDiff.Render(show, before, after, function is { } f ? $"the function at rva 0x{f:X}" : "the function");
    }

    private static string Va(LoadedNative native, uint rva) => NativeAddress.Va(native.Image, rva);

    [McpServerTool(Name = "set_native_type", Title = "Set a native prototype or global type", UseStructuredContent = true, OutputSchemaType = typeof(EditResult))]
    [Description("Set the prototype of a native function ('int __fastcall Parse(Packet *p, int len)') or the type of a global ('Handler *[8]') " +
                 "in the engine. Named types must exist there (pushed PDB, RTTI and Il2Cpp types, or declare_native_types). User types win over " +
                 "recovered ones; empty clears; __noreturn stops the callers' flow at the call. rename=true also names the function as its prototype does." + KeptNote)]
    public Task<string> SetNativeType(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("A function start or a global: " + NativeTools.AddressDescription)] string? address = null,
        [Description("C prototype for a function, C type for a global; empty to clear the user type.")] string? type = null,
        [Description("Instead of address and type: lines 'address = type'.")] string? items = null,
        [Description("Name the function as its prototype does.")] bool rename = false,
        [Description("Report the engine's guess at address without applying it.")] bool guess = false,
        [Description(DecompileDiff.Description)] string? showDecompile = null,
        [Description(EngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        if (!string.IsNullOrWhiteSpace(items))
        {
            if (!string.IsNullOrWhiteSpace(address) || type != null)
                throw new ToolError(ErrorCode.InvalidArgument, "Pass items, or address and type, not both.");
            return await SetTypes(image, items, engine, progress, cancellationToken);
        }
        if (guess)
        {
            if (string.IsNullOrWhiteSpace(address) || type != null) throw new ToolError(ErrorCode.InvalidArgument, "guess takes an address and no type.");
            var (gn, grva, gs) = await Open(image, address, engine, progress, cancellationToken);
            var g = await gs.GuessTypeAsync(grva, cancellationToken);
            return g.Type == null ? $"No type guess at {Va(gn, grva)}."
                : $"Guess at {Va(gn, grva)}: {g.Type} (from {g.Method}, {g.Confidence} confidence; not applied; pass it as type to apply)";
        }
        if (string.IsNullOrWhiteSpace(address) || type == null)
            throw new ToolError(ErrorCode.InvalidArgument, "Pass address and type, or items.", "items takes lines 'address = type'");
        var show = DecompileDiff.Parse(showDecompile);
        var (native, rva, session) = await Open(image, address, engine, progress, cancellationToken);
        var decl = type.Trim();
        return await WithDecompile(show, session, rva, async () =>
        {
            var (result, id) = await Apply(native, session, "set_native_type", new NativeUserTypeBatch([], [new NativePrototype(rva, decl)], [], []),
                (r, layer) => r.Items is [{ Applied: true }] ? layer.WithType(rva, decl) : null, cancellationToken);
            var item = Outcome(result, session.ProviderId);
            if (decl.Length == 0) return Edited($"Cleared the user type at {Va(native, rva)}.", id, new EditChange("type", Va(native, rva), null, null));
            var renamed = rename ? await RenameFromPrototype(native, session, rva, decl, cancellationToken) : null;
            var changes = new List<EditChange> { new("type", Va(native, rva), null, item.Text ?? decl) };
            if (renamed != null) changes.Add(new("name", Va(native, rva), null, renamed));
            return Edited($"Type at {Va(native, rva)}: {item.Text ?? decl}" + (renamed != null ? $"; the function is now named {renamed}" : ""), id, changes, null);
        }, cancellationToken);
    });

    private static readonly HashSet<string> NotNames = new(StringComparer.Ordinal)
    {
        "void", "int", "char", "short", "long", "unsigned", "signed", "float", "double", "bool", "_BOOL", "struct", "union", "enum", "const", "volatile",
        "__int8", "__int16", "__int32", "__int64", "__cdecl", "__stdcall", "__fastcall", "__thiscall", "__vectorcall", "__usercall", "__userpurge", "__noreturn",
    };

    /// <summary>The function name a prototype declares ("int __fastcall Parse(Packet *p)": Parse), or null (a pointer or abstract type).</summary>
    internal static string? PrototypeName(string decl)
    {
        var m = System.Text.RegularExpressions.Regex.Match(decl, @"^[^(]*?([A-Za-z_][\w:]*)\s*\(");
        return m.Success && !NotNames.Contains(m.Groups[1].Value) ? m.Groups[1].Value : null;
    }

    /// <summary>
    /// Records the prototype's function name in the user's name layer (so every engine gets it with the names) when it
    /// differs from the name in effect at a function start; returns it, or null when nothing changed.
    /// </summary>
    private async Task<string?> RenameFromPrototype(LoadedNative native, INativeDecompilerSession session, uint rva, string decl, CancellationToken ct)
    {
        if (code == null || PrototypeName(decl) is not { } wanted) return null;
        var index = code.Ready(native) ?? await code.Index(native, null, ct);
        if (index.FunctionAt(rva)?.Start != rva) return null;
        string valid;
        try { valid = NativeName.Validate(wanted.Replace("::", "__", StringComparison.Ordinal)); }
        catch (ToolError) { return null; }
        if (index.NameAt(rva) == valid) return null;
        var ann = code.Annotations(native);
        workspace.Write(() => { ann.Apply([(rva, valid)], [], [], allowDuplicate: true); index.SetUserName(rva, valid); return 0; });
        if (names != null) await names.EnsureAsync(native, session, ct);
        return valid;
    }

    /// <summary>Most lines of one set_native_type items call.</summary>
    private const int MaxTypeItems = 5000;

    /// <summary>set_native_type items: every line in one engine request; the applied ones are recorded.</summary>
    private async Task<string> SetTypes(string image, string items, string? engine, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var lines = items.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (lines.Length > MaxTypeItems) throw new ToolError(ErrorCode.InvalidArgument, $"{lines.Length} lines; at most {MaxTypeItems} per call.", "split the items");
        var (native, _, session) = await Open(image, "rva:0", engine, progress, ct);
        var wanted = new List<NativePrototype>();
        var problems = new List<string>();
        foreach (var line in lines)
        {
            int eq = line.IndexOf('=', StringComparison.Ordinal);
            if (eq <= 0) { problems.Add($"'{line}': not 'address = type'"); continue; }
            try
            {
                var (_, rva) = NativeAnalysisTools.Resolve(workspace, code, native.Id, line[..eq].Trim());
                wanted.Add(new NativePrototype(rva, line[(eq + 1)..].Trim()));
            }
            catch (ToolError e) { problems.Add($"'{line[..eq].Trim()}': {e.Message}"); }
        }
        var (result, id) = await Apply(native, session, "set_native_type", new NativeUserTypeBatch([], wanted, [], []),
            (r, layer) => r.Items.Where(i => i.Applied).Aggregate(layer, (l, i) => l.WithType(i.Rva, i.Target)), ct);
        int applied = result.Items.Count(i => i.Applied);
        if (applied == 0 && lines.Length > 0)
            throw new ToolError(ErrorCode.InvalidArgument, $"None of the {lines.Length} type(s) was applied: " +
                string.Join("; ", result.Items.Select(i => $"{Va(native, i.Rva)}: {i.Error}").Concat(problems).Take(5)), Refusal(result.Items.FirstOrDefault()?.Error, session.ProviderId));
        var sb = new System.Text.StringBuilder($"{applied} of {lines.Length} type(s) applied\n");
        foreach (var i in result.Items)
            sb.Append($"  {Va(native, i.Rva)}  {(i.Applied ? (i.Target.Length == 0 ? "cleared" : i.Text ?? i.Target) : "not applied: " + i.Error)}\n");
        foreach (var p in problems) sb.Append($"  not applied: {p}\n");
        return Edited(sb.ToString(), id, [.. result.Items.Where(i => i.Applied).Select(i => new EditChange("type", Va(native, i.Rva), null, i.Target.Length == 0 ? null : i.Text ?? i.Target))],
            lines.Length - applied);
    }

    [McpServerTool(Name = "set_native_local", Title = "Rename or retype a decompiler local", UseStructuredContent = true, OutputSchemaType = typeof(EditResult))]
    [Description("Rename and/or retype a local or argument in a native function's pseudocode, named as decompile_native shows it (v3, a1) or " +
                 "stack:0x28. Later edits may use its new name; its first name again, or clear, drops the edit. A type that does not fit is refused." + KeptNote)]
    public Task<string> SetNativeLocal(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("The function: " + NativeTools.AddressDescription)] string function,
        [Description("The variable: its name in the pseudocode, or stack:<offset> (hex).")] string? local = null,
        [Description("New name (a C identifier).")] string? newName = null,
        [Description("New C type.")] string? type = null,
        [Description("Drop the user's name and type of the variable.")] bool clear = false,
        [Description("Instead of local: lines 'local = newName', or JSON [{local, newName?, type?, clear?}].")] string? items = null,
        [Description(DecompileDiff.Description)] string? showDecompile = null,
        [Description(EngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        if (items != null)
        {
            if (local != null || newName != null || type != null || clear)
                throw new ToolError(ErrorCode.InvalidArgument, "Pass items, or local with newName/type/clear, not both.");
            return await SetLocals(image, function, items, DecompileDiff.Parse(showDecompile), engine, progress, cancellationToken);
        }
        var request = LocalRequest(local ?? throw new ToolError(ErrorCode.InvalidArgument, "Pass local, or items."), newName, type, clear);
        var show = DecompileDiff.Parse(showDecompile);
        var (native, rva, session) = await Open(image, function, engine, progress, cancellationToken);
        return await WithDecompile(show, session, rva, async () =>
        {
        var edits = LocalEdits(native, rva, [request]);
        var (result, id) = await Apply(native, session, "set_native_local", new NativeUserTypeBatch([], [], [], edits), (r, layer) => RecordLocals(r, layer, edits), cancellationToken);
        if (result.Items.FirstOrDefault(i => !i.Applied) is { } failed) Outcome(result with { Items = [failed] }, session.ProviderId);
        var done = result.Items.Count > 0 ? result.Items[^1] : throw new ToolError(ErrorCode.Failed, "The engine did not report the edit.");
        return Edited($"Local {done.Resolved} of the function at {Va(native, done.Rva)}{(done.Stack is { } k ? $" (stack 0x{k:X})" : "")} " +
               (done.Kind == "local_clear" ? $"is cleared; now {done.Text}" : $"is now: {done.Text}"), id,
            new EditChange("local", $"{Va(native, done.Rva)}:{done.Resolved}", done.Resolved, done.Text));
        }, cancellationToken);
    });

    /// <summary>set_native_local items: the requests that parse in one engine request; every outcome and refusal reported.</summary>
    private async Task<string> SetLocals(string image, string function, string items, string? show, string? engine, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var requests = new List<LocalChange>();
        var problems = new List<string>();
        var text = items.Trim();
        if (text.StartsWith('['))
        {
            System.Text.Json.JsonElement root;
            try { root = System.Text.Json.JsonDocument.Parse(text).RootElement; }
            catch (System.Text.Json.JsonException e) { throw new ToolError(ErrorCode.InvalidArgument, $"items is not valid JSON: {e.Message}"); }
            foreach (var o in root.EnumerateArray())
            {
                string? Str(string key) => o.ValueKind == System.Text.Json.JsonValueKind.Object && o.TryGetProperty(key, out var v) && v.ValueKind == System.Text.Json.JsonValueKind.String ? v.GetString() : null;
                bool clear = o.ValueKind == System.Text.Json.JsonValueKind.Object && o.TryGetProperty("clear", out var c) && c.ValueKind == System.Text.Json.JsonValueKind.True;
                try { requests.Add(LocalRequest(Str("local") ?? "", Str("newName") ?? Str("name"), Str("type"), clear)); }
                catch (ToolError e) { problems.Add($"{o}: {e.Message}"); }
            }
        }
        else
            foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                int eq = line.IndexOf('=', StringComparison.Ordinal);
                try { requests.Add(eq > 0 ? LocalRequest(line[..eq].Trim(), line[(eq + 1)..].Trim(), null, false) : throw new ToolError(ErrorCode.InvalidArgument, "not 'local = newName'")); }
                catch (ToolError e) { problems.Add($"'{line}': {e.Message}"); }
            }
        if (requests.Count + problems.Count > MaxTypeItems) throw new ToolError(ErrorCode.InvalidArgument, $"At most {MaxTypeItems} items per call.", "split the items");
        var (native, rva, session) = await Open(image, function, engine, progress, ct);
        return await WithDecompile(show, session, rva, async () =>
        {
        var edits = LocalEdits(native, rva, requests);
        var (result, id) = edits.Count == 0 ? (null, null)
            : await Apply(native, session, "set_native_local", new NativeUserTypeBatch([], [], [], edits), (r, layer) => RecordLocals(r, layer, edits), ct);
        var outcomes = result?.Items ?? [];
        int applied = outcomes.Count(i => i.Applied), total = outcomes.Count + problems.Count;
        if (applied == 0 && total > 0)
            throw new ToolError(ErrorCode.InvalidArgument, $"None of the {total} local edit(s) was applied: " +
                string.Join("; ", outcomes.Select(i => $"{i.Resolved ?? i.Target}: {i.Error}").Concat(problems).Take(5)), Refusal(outcomes.FirstOrDefault()?.Error, session.ProviderId));
        var sb = new System.Text.StringBuilder($"{applied} of {total} local edit(s) applied\n");
        foreach (var i in outcomes)
            sb.Append($"  {i.Resolved ?? i.Target}  " + (!i.Applied ? "not applied: " + i.Error : i.Kind == "local_clear" ? "cleared; now " + i.Text : i.Text)).Append('\n');
        foreach (var p in problems) sb.Append($"  not applied: {p}\n");
        return Edited(sb.ToString(), id, [.. outcomes.Where(i => i.Applied).Select(i => new EditChange("local", $"{Va(native, i.Rva)}:{i.Resolved ?? i.Target}", i.Resolved, i.Text))],
            total - applied);
        }, ct);
    }

    /// <summary>One local to change: its target (name or stack offset), the new name and type, or a clear.</summary>
    internal sealed record LocalChange(string Target, int? Stack, string? Name, string? Type, bool Clear);

    internal static LocalChange LocalRequest(string local, string? newName, string? type, bool clear)
    {
        var name = string.IsNullOrWhiteSpace(newName) ? null : newName.Trim();
        var decl = string.IsNullOrWhiteSpace(type) ? null : type.Trim();
        if (clear && (name != null || decl != null)) throw new ToolError(ErrorCode.InvalidArgument, "clear takes no newName or type.", "drop newName and type");
        if (!clear && name == null && decl == null) throw new ToolError(ErrorCode.InvalidArgument, "Nothing to change.", "pass newName, type or both, or clear=true");
        if (name != null && !Identifier(name))
            throw new ToolError(ErrorCode.InvalidArgument, $"'{name}' is not a C identifier.", "use letters, digits and _, not starting with a digit");
        var (target, stack) = LocalTarget(local);
        return new(target, stack, name, decl, clear);
    }

    /// <summary>
    /// The engine edits for the changes, clears first (the engine applies them first). A variable given back the name it had
    /// before the user's first edit is cleared, keeping a user type.
    /// </summary>
    private List<NativeLocalEdit> LocalEdits(LoadedNative native, uint rva, IEnumerable<LocalChange> changes)
    {
        var layer = code?.Annotations(native).UserTypes ?? UserTypeLayer.Empty;
        var start = code?.Ready(native)?.FunctionAt(rva)?.Start ?? rva;
        var clears = new List<NativeLocalEdit>();
        var sets = new List<NativeLocalEdit>();
        foreach (var c in changes)
        {
            var existing = layer.LocalEdit(rva, c.Target, c.Stack) ?? layer.LocalEdit(start, c.Target, c.Stack);
            bool clear = c.Clear || (c.Name != null && existing is { Name: not null } && c.Name == existing.Local);
            if (!clear)
            {
                sets.Add(new NativeLocalEdit(rva, c.Target, c.Stack, c.Name, c.Type));
                continue;
            }
            clears.Add(new NativeLocalEdit(rva, c.Target, c.Stack ?? existing?.Stack, existing?.Name, null) { Clear = true });
            if (!c.Clear && (c.Type ?? existing?.Type) is { } keep) sets.Add(new NativeLocalEdit(rva, existing!.Local, c.Stack ?? existing.Stack, null, keep));
        }
        return [.. clears, .. sets];
    }

    /// <summary>
    /// Records the applied ones of <paramref name="edits"/> (outcomes in the same order): a clear removes the variable's edit,
    /// and an edit left with its first name and no type is dropped.
    /// </summary>
    private static UserTypeLayer RecordLocals(UserTypeResult result, UserTypeLayer layer, IReadOnlyList<NativeLocalEdit> edits)
    {
        var firstNames = new Dictionary<(uint, int?), string>();
        for (int i = 0; i < Math.Min(result.Items.Count, edits.Count); i++)
        {
            var (item, edit) = (result.Items[i], edits[i]);
            if (!item.Applied) continue;
            if (edit.Clear)
            {
                if (item.Resolved != null && layer.LocalEdit(item.Rva, item.Resolved, item.Stack) is { } old)
                {
                    layer = layer.WithoutLocal(old);
                    firstNames[(item.Rva, item.Stack)] = old.Local;
                }
                continue;
            }
            var first = firstNames.GetValueOrDefault((item.Rva, item.Stack)) ?? item.Resolved ?? edit.Local;
            layer = layer.WithLocal(new NativeLocalEdit(item.Rva, first, item.Stack, edit.Name, edit.Type));
            if (layer.LocalEdit(item.Rva, first, item.Stack) is { Type: null } merged && (merged.Name == null || merged.Name == merged.Local))
                layer = layer.WithoutLocal(merged);
        }
        return layer;
    }

    [McpServerTool(Name = "declare_native_types", Title = "Declare C types in the engine", UseStructuredContent = true, OutputSchemaType = typeof(EditResult))]
    [Description("Declare C types (structs, unions, enums, typedefs, function types) in the engine; a type of the same name is replaced, and " +
                 "declarations win over recovered types. Errors carry the engine's messages and are not saved. typeName with members upserts or " +
                 "removes enum members, with fields struct or union members (+name@0x10 inserts, moving later members down), resize and " +
                 "nameGaps change a struct's layout; delete or rename edits a named type." + KeptNote)]
    public Task<string> DeclareNativeTypes(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("C declarations; types they name must exist or be declared too.")] string? declarations = null,
        [Description("Enum, struct or union to edit.")] string? typeName = null,
        [Description("Enum: 'NAME=value, ...' (hex or decimal; or lines); 'NAME=' removes.")] string? members = null,
        [Description("Struct or union: 'name: type; name@0x10: type; @0x10: type' (or lines); 'name:' removes; '+name@0x10: type' inserts.")] string? fields = null,
        [Description("Struct: its new size (hex or decimal); goes alone.")] string? resize = null,
        [Description("Struct: name its unnamed gaps gap_<offset>.")] bool nameGaps = false,
        [Description("A type to delete.")] string? delete = null,
        [Description("'Old=New'; kept edits naming it follow.")] string? rename = null,
        [Description(EngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var text = (declarations ?? "").Trim();
        if (!string.IsNullOrWhiteSpace(members) && !string.IsNullOrWhiteSpace(fields))
            throw new ToolError(ErrorCode.InvalidArgument, "Pass members (an enum) or fields (a struct or union), not both.");
        bool layout = !string.IsNullOrWhiteSpace(resize) || nameGaps;
        if (layout && !string.IsNullOrWhiteSpace(members)) throw new ToolError(ErrorCode.InvalidArgument, "resize and nameGaps change a struct; members edits an enum.", "make them in separate calls");
        var enumMembers = string.IsNullOrWhiteSpace(fields) && !layout ? EnumMembers(typeName, members) : [];
        var fieldEdits = string.IsNullOrWhiteSpace(fields) ? [] : FieldEdits(typeName, fields);
        if (nameGaps) fieldEdits.Add(new NativeFieldEdit(StructName(typeName, "nameGaps"), null, null, "char") { Op = NativeFieldEdit.Gaps });
        int? newSize = null;
        if (!string.IsNullOrWhiteSpace(resize))
        {
            if (text.Length > 0 || enumMembers.Count > 0 || fieldEdits.Count > 0)
                throw new ToolError(ErrorCode.InvalidArgument, "resize goes alone.", "make the other changes in another call");
            newSize = NativeAddress.Number(resize.Trim()) is { } n and > 0 and <= int.MaxValue ? (int)n
                : throw new ToolError(ErrorCode.InvalidArgument, $"'{resize.Trim()}' is not a size.", "e.g. resize=0x40");
            fieldEdits.Add(new NativeFieldEdit(StructName(typeName, "resize"), null, newSize, null) { Op = NativeFieldEdit.Resize });
        }
        var typeEdit = TypeEditRequest(delete, rename);
        if (typeEdit != null)
        {
            if (text.Length > 0 || enumMembers.Count > 0 || fieldEdits.Count > 0)
                throw new ToolError(ErrorCode.InvalidArgument, "delete and rename go alone.", "make the other changes in another call");
            return await EditType(image, typeEdit, engine, progress, cancellationToken);
        }
        if (text.Length == 0 && enumMembers.Count == 0 && fieldEdits.Count == 0)
            throw new ToolError(ErrorCode.InvalidArgument, "Nothing to declare.", "pass C declarations such as 'struct S { int a; };', or typeName with members or fields");
        var (native, _, session) = await Open(image, "rva:0", engine, progress, cancellationToken);
        var edits = userTypes.Layer(native).TypeEdits;
        // a resize is undone by the size the struct has now
        NativeUserTypeBatch? resizeInverse = newSize != null
            ? NativeUserTypeBatch.Empty with { Fields = [fieldEdits[0] with { Offset = (int)(await session.GetTypeAsync(fieldEdits[0].Type, cancellationToken)).Size }] }
            : null;
        // the engine replaces a type of the same name: the undo puts back the earlier declarations and deletes the new types
        NativeUserTypeBatch? inverse = null;
        if (text.Length > 0 && enumMembers.Count == 0 && fieldEdits.Count == 0)
        {
            var before = new List<string>();
            var added = new List<NativeTypeEdit>();
            foreach (var declared in DeclaredNames(text))
            {
                try { before.Add((await session.GetTypeAsync(declared, cancellationToken)).Declaration); }
                catch (ToolError e) when (e.Code == ErrorCode.NotFound) { added.Add(new NativeTypeEdit(declared, null)); }
            }
            inverse = new NativeUserTypeBatch(before.Count > 0 ? [string.Join("\n", before)] : [], [], [], []) { TypeEdits = added.Count > 0 ? [.. edits, .. added] : null };
        }
        var (result, id) = await Apply(native, session, "declare_native_types",
            new NativeUserTypeBatch(text.Length > 0 ? [text] : [], [], [], []) { EnumMembers = enumMembers, Fields = fieldEdits },
            (r, layer) => r.DeclarationErrors > 0 ? null : RecordMembers(r, text.Length > 0 ? layer.WithDeclarations(text, r.DeclaredTypes) : layer, enumMembers, fieldEdits),
            cancellationToken, inverse ?? resizeInverse);
        if (result.DeclarationErrors > 0)
            throw new ToolError(ErrorCode.InvalidArgument, $"{result.DeclarationErrors} error(s) in the declarations" +
                (result.DeclarationMessages.Count > 0 ? ": " + string.Join("; ", result.DeclarationMessages) : "."), "fix the declarations and declare them again");
        // a declared name drops the kept rename or deletion of it, in the engine too
        if (userTypes.Layer(native).TypeEdits is var kept && kept.Count != edits.Count)
            await userTypes.ApplyAsync(native, session, NativeUserTypeBatch.Empty with { TypeEdits = kept }, (_, _) => null, cancellationToken);
        var sb = new System.Text.StringBuilder();
        if (text.Length > 0)
            sb.Append(result.DeclaredTypes.Count == 0 ? "Declared (the engine reported no type names)."
                : $"Declared {result.DeclaredTypes.Count} type(s): {string.Join(", ", result.DeclaredTypes.Distinct())}").Append('\n');
        foreach (var i in result.Items.Where(i => i.Kind is "enum" or "field")) sb.Append(i.Applied ? $"  {i.Text}" : $"  {i.Target} not applied: {i.Error}").Append('\n');
        if (enumMembers.Count + fieldEdits.Count > 0 && result.Items.All(i => !i.Applied))
            throw new ToolError(ErrorCode.InvalidArgument, "No member was applied:\n" + sb, "check the type's name and the member names; list_native_types name= shows them");
        var changes = result.DeclaredTypes.Distinct().Select(t => new EditChange("declaration", t, null, t))
            .Concat(result.Items.Where(i => i.Kind is "enum" or "field" && i.Applied).Select(i => new EditChange(i.Kind, i.Target, null, i.Text))).ToList();
        return Edited(sb.ToString(), id, changes, result.Items.Count(i => i.Kind is "enum" or "field" && !i.Applied));
    });

    /// <summary>The type names C declarations define (struct/union/enum tags with a body, typedef names), in order.</summary>
    internal static IReadOnlyList<string> DeclaredNames(string text)
    {
        var names = new List<string>();
        foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(text, @"\b(?:struct|union|enum)\s+([A-Za-z_]\w*)\s*(?::[^{;]*)?\{"))
            names.Add(m.Groups[1].Value);
        foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(text, @"\btypedef\b([^;{]*(?:\{[^}]*\}[^;]*)?);"))
        {
            var body = m.Groups[1].Value;
            // a function pointer names itself after "(*"; else the last identifier, past array bounds
            var pointer = System.Text.RegularExpressions.Regex.Match(body, @"\(\s*\*\s*([A-Za-z_]\w*)\s*\)");
            var last = System.Text.RegularExpressions.Regex.Match(System.Text.RegularExpressions.Regex.Replace(body, @"\[[^\]]*\]", ""), @"([A-Za-z_]\w*)\s*$");
            if ((pointer.Success ? pointer : last) is { Success: true } n) names.Add(n.Groups[1].Value);
        }
        return names.Distinct().ToList();
    }

    /// <summary>The applied enum members and fields (field outcomes in the order sent) recorded in the layer.</summary>
    private static UserTypeLayer RecordMembers(UserTypeResult result, UserTypeLayer layer, List<NativeEnumMemberEdit> enums, List<NativeFieldEdit> fields)
    {
        foreach (var i in result.Items.Where(i => i.Kind == "enum" && i.Applied))
            if (enums.FirstOrDefault(e => $"{e.Enum}::{e.Member}" == i.Target) is { } e) layer = layer.WithEnumMember(e);
        foreach (var (item, edit) in result.Items.Where(i => i.Kind == "field").Zip(fields))
            if (item.Applied) layer = layer.WithField(edit);
        return layer;
    }

    /// <summary>The struct a layout parameter names: typeName, checked.</summary>
    private static string StructName(string? typeName, string parameter)
    {
        var type = (typeName ?? "").Trim();
        return Identifier(type) ? type : throw new ToolError(ErrorCode.InvalidArgument, $"{parameter} needs typeName, the struct to change.", $"e.g. typeName=Packet {parameter}=...");
    }

    /// <summary>
    /// "len: int; data@0x8: char[16]; @0x20: int; old:" for a struct or union: members to set, an empty type removing one;
    /// "+name@0x10: type" inserts, moving the later members down ("+name:" cuts it and moves them back).
    /// </summary>
    internal static List<NativeFieldEdit> FieldEdits(string? typeName, string? fields)
    {
        var type = (typeName ?? "").Trim();
        if (!Identifier(type)) throw new ToolError(ErrorCode.InvalidArgument, type.Length == 0 ? "fields needs typeName." : $"'{type}' is not a type name.",
            "e.g. typeName=Packet fields='length: int; data@0x8: char[16]'");
        var result = new List<NativeFieldEdit>();
        foreach (var entry in (fields ?? "").Split([';', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int colon = entry.IndexOf(':', StringComparison.Ordinal);
            if (colon < 0) throw new ToolError(ErrorCode.InvalidArgument, $"'{entry}' has no ':'.", "write 'name: type', 'name@0x10: type', or 'name:' to remove it");
            var head = entry[..colon].Trim();
            bool insert = head.StartsWith('+');
            if (insert) head = head[1..].Trim();
            var fieldType = entry[(colon + 1)..].Trim();
            int at = head.IndexOf('@', StringComparison.Ordinal);
            var name = (at < 0 ? head : head[..at]).Trim();
            int? offset = null;
            if (at >= 0)
                offset = NativeAddress.Number(head[(at + 1)..].Trim()) is { } n && n <= int.MaxValue ? (int)n
                    : throw new ToolError(ErrorCode.InvalidArgument, $"'{head[(at + 1)..].Trim()}' is not an offset.", "use @0x10 or @16");
            if (name.Length > 0 && !Identifier(name)) throw new ToolError(ErrorCode.InvalidArgument, $"'{name}' is not a C identifier.");
            if (name.Length == 0 && offset == null) throw new ToolError(ErrorCode.InvalidArgument, $"'{entry}' names no member.", "give a name, an @offset or both");
            if (insert && offset == null && fieldType.Length > 0)
                throw new ToolError(ErrorCode.InvalidArgument, $"'{entry}' inserts without an offset.", "write '+name@0x10: type'");
            result.Add(new NativeFieldEdit(type, name.Length > 0 ? name : null, offset, fieldType.Length > 0 ? fieldType : null) { Op = insert ? NativeFieldEdit.Insert : null });
        }
        return result;
    }

    /// <summary>declare_native_types delete=Name or rename='Old=New' as a type edit; null for neither.</summary>
    internal static NativeTypeEdit? TypeEditRequest(string? delete, string? rename)
    {
        var d = (delete ?? "").Trim();
        var r = (rename ?? "").Trim();
        if (d.Length > 0 && r.Length > 0) throw new ToolError(ErrorCode.InvalidArgument, "Pass delete or rename, not both.");
        if (d.Length > 0) return Identifier(d) ? new NativeTypeEdit(d, null) : throw new ToolError(ErrorCode.InvalidArgument, $"'{d}' is not a type name.");
        if (r.Length == 0) return null;
        int eq = r.IndexOf('=', StringComparison.Ordinal);
        var (from, to) = eq < 0 ? ("", "") : (r[..eq].Trim(), r[(eq + 1)..].Trim());
        if (!Identifier(from) || !Identifier(to) || from == to)
            throw new ToolError(ErrorCode.InvalidArgument, $"'{r}' is not 'Old=New' with two different type names.", "e.g. rename='Packet=NetPacket'");
        return new NativeTypeEdit(from, to);
    }

    /// <summary>A type renamed or deleted: the old name must exist and a new one must not; the engine gets the whole kept list.</summary>
    private async Task<string> EditType(string image, NativeTypeEdit edit, string? engine, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var (native, _, session) = await Open(image, "rva:0", engine, progress, ct);
        var old = await session.GetTypeAsync(edit.Name, ct);
        var kept = userTypes.Layer(native).TypeEdits;
        // a deleted type comes back from its declaration; a rename is undone by the generic inverse
        var inverse = edit.NewName == null ? new NativeUserTypeBatch([old.Declaration], [], [], []) { TypeEdits = kept } : null;
        if (edit.NewName is { } to)
        {
            bool taken;
            try { taken = (await session.GetTypeAsync(to, ct)).Name == to; }
            catch (ToolError e) when (e.Code == ErrorCode.NotFound) { taken = false; }
            if (taken) throw new ToolError(ErrorCode.InvalidArgument, $"A type named {to} exists.", $"delete it first (delete={to}), or pick another name");
        }
        var (result, id) = await Apply(native, session, "declare_native_types", NativeUserTypeBatch.Empty with { TypeEdits = userTypes.Layer(native).WithTypeEdit(edit).TypeEdits },
            (r, layer) => r.Items.LastOrDefault(i => i.Kind == "type_edit" && i.Target == edit.Name) is { Applied: true } ? layer.WithTypeEdit(edit) : null, ct, inverse);
        var done = result.Items.LastOrDefault(i => i.Kind == "type_edit" && i.Target == edit.Name)
            ?? throw new ToolError(ErrorCode.Failed, "The engine did not report the edit.");
        if (!done.Applied) throw new ToolError(ErrorCode.InvalidArgument, done.Error ?? "The engine did not apply the edit.", Refusal(done.Error, session.ProviderId));
        return Edited(edit.NewName == null ? $"Deleted type {edit.Name}." : $"Renamed type {edit.Name} to {edit.NewName}; the kept edits that named it now name {edit.NewName}.",
            id, new EditChange("type_edit", edit.Name, edit.Name, edit.NewName));
    }

    /// <summary>"A=1, B=0x10, C=" for an enum: members to set, an empty value removing one.</summary>
    internal static List<NativeEnumMemberEdit> EnumMembers(string? typeName, string? members)
    {
        var name = (typeName ?? "").Trim();
        var list = (members ?? "").Split([',', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (name.Length == 0 != (list.Length == 0))
            throw new ToolError(ErrorCode.InvalidArgument, "typeName goes with members or fields.", "e.g. typeName=Color members='Red=1, Green=2'");
        if (name.Length > 0 && !Identifier(name)) throw new ToolError(ErrorCode.InvalidArgument, $"'{name}' is not a C identifier.");
        var result = new List<NativeEnumMemberEdit>();
        foreach (var pair in list)
        {
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            var member = (eq < 0 ? pair : pair[..eq]).Trim();
            var value = eq < 0 ? "" : pair[(eq + 1)..].Trim();
            if (!Identifier(member)) throw new ToolError(ErrorCode.InvalidArgument, $"'{member}' is not a C identifier.", "members: 'NAME=value, ...'");
            if (eq < 0) throw new ToolError(ErrorCode.InvalidArgument, $"'{pair}' has no value.", "write NAME=value, or NAME= to remove the member");
            long? number = null;
            if (value.Length > 0)
            {
                bool negative = value.StartsWith('-');
                var digits = negative ? value[1..] : value;
                number = digits.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                    && ulong.TryParse(digits[2..], System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out var h) ? unchecked((long)h)
                    : long.TryParse(digits, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var d) ? d
                    : throw new ToolError(ErrorCode.InvalidArgument, $"'{value}' is not a number.", "use decimal or 0x hex");
                if (negative) number = -number;
            }
            result.Add(new NativeEnumMemberEdit(name, member, number));
        }
        return result;
    }

    [McpServerTool(Name = "define_native", Title = "Redefine code or data in the engine", UseStructuredContent = true, OutputSchemaType = typeof(EditResult))]
    [Description("Change the engine's analysis at an address. code decodes instructions (to end, else following the flow); function makes " +
                 "a function (with end: its extent; on one: moves its end); undefine makes unknown bytes (to end, else the item; at a function start " +
                 "the function); data makes a data item of type; flow (Ghidra) clears an instruction's flow override, or sets type branch, call, " +
                 "call_return or return, and repairs the function. Data and undefine replace a user type on a global there." + KeptNote)]
    public Task<string> DefineNative(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Start: " + NativeTools.AddressDescription)] string address,
        [Description("What to make.")] string kind,
        [Description("Exclusive end address (same forms as address).")] string? end = null,
        [Description("kind=data: byte, word, dword, qword, float, double, string, string16 (UTF-16) or a C type, with an optional [count] (dword[8]).")] string? type = null,
        [Description(EngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var k = (kind ?? "").Trim().ToLowerInvariant();
        if (k is not (NativeAnalysisEdit.Code or NativeAnalysisEdit.Function or NativeAnalysisEdit.Undefine or NativeAnalysisEdit.Data or NativeAnalysisEdit.Flow))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown kind '{kind}'.", "use code, function, undefine, data or flow");
        var t = string.IsNullOrWhiteSpace(type) ? null : type.Trim();
        if (k == NativeAnalysisEdit.Data && t == null)
            throw new ToolError(ErrorCode.InvalidArgument, "kind=data needs a type.", "pass type, e.g. dword, dword[8], string or a C type such as Packet");
        if (k == NativeAnalysisEdit.Flow && t != null && !NativeAnalysisEdit.FlowOverrides.Contains(t.ToLowerInvariant()))
            throw new ToolError(ErrorCode.InvalidArgument, $"'{t}' is not a flow override.", "use " + string.Join(", ", NativeAnalysisEdit.FlowOverrides));
        if (k is not (NativeAnalysisEdit.Data or NativeAnalysisEdit.Flow) && t != null)
            throw new ToolError(ErrorCode.InvalidArgument, $"type applies to kind=data or flow, not {k}.", "drop type, or use kind=data");
        if (k == NativeAnalysisEdit.Flow) t = t?.ToLowerInvariant() ?? "none";
        var (native, rva, session) = await Open(image, address, engine, progress, cancellationToken);
        if (k == NativeAnalysisEdit.Flow && session.ProviderId != "ghidra")
            throw new ToolError(ErrorCode.Unsupported, $"Flow overrides are Ghidra's; {NativeEngineService.DisplayName(session.ProviderId)} has none.", "engine=ghidra");
        uint? stop = null;
        if (!string.IsNullOrWhiteSpace(end))
        {
            stop = workspace.Read(() => NativeAddress.Parse(native.Image, end, code?.Ready(native) is { } index ? index.AddressesOfName : null));
            if (stop <= rva) throw new ToolError(ErrorCode.InvalidArgument, $"end {Va(native, stop.Value)} is not after {Va(native, rva)}.", "pass an end above the start");
        }
        var edit = new NativeAnalysisEdit(rva, k, stop, t);
        var (result, id) = await Apply(native, session, "define_native", NativeUserTypeBatch.Empty with { Analysis = [edit] },
            (r, layer) => r.Items is [{ Applied: true }] ? layer.WithAnalysis(edit) : null, cancellationToken);
        var done = Outcome(result, session.ProviderId);
        if (k != NativeAnalysisEdit.Data) _ = GhidraNames.Refresh(native, session, code);
        var where = $"{Va(native, rva)}{(stop is { } s ? $"-{Va(native, s)}" : "")}";
        return Edited($"{k} at {where} ({session.ProviderId}): {done.Text}", id, new EditChange(k, where, null, done.Text));
    });

    [McpServerTool(Name = "set_native_operand", Title = "Set how an operand displays", UseStructuredContent = true, OutputSchemaType = typeof(EditResult))]
    [Description("Set how an instruction operand displays in the engine's disassembly and, where the decompiler follows it, the pseudocode: " +
                 "offset (the constant as an address), stack (a stack variable), enum (type: the enum; a member of the constant's value), struct " +
                 "(type: 'Packet' or 'Packet+0x10'; IDA only) or default (the engine's). Ghidra shows numbers and enum members as equates." + KeptNote)]
    public Task<string> SetNativeOperand(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("The instruction: " + NativeTools.AddressDescription)] string address,
        [Description("Operand index, 0 for the first.")] int operand,
        [Description("How to display it (see the description).")] string display,
        [Description("display=enum or struct: the type's name (struct: optionally +delta).")] string? type = null,
        [Description(EngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var d = (display ?? "").Trim().ToLowerInvariant();
        if (!NativeOperandEdit.Displays.Contains(d))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown display '{display}'.", $"use {string.Join(", ", NativeOperandEdit.Displays)}");
        if (operand is < 0 or > 7) throw new ToolError(ErrorCode.InvalidArgument, $"operand must be 0-7, not {operand}.");
        var t = string.IsNullOrWhiteSpace(type) ? null : type.Trim();
        if (d is "enum" or "struct" && t == null) throw new ToolError(ErrorCode.InvalidArgument, $"display={d} needs the type's name.", "pass type");
        if (d is not ("enum" or "struct") && t != null) throw new ToolError(ErrorCode.InvalidArgument, $"type applies to display=enum or struct, not {d}.", "drop type");
        var (native, rva, session) = await Open(image, address, engine, progress, cancellationToken);
        var edit = new NativeOperandEdit(rva, operand, d, t);
        var (result, id) = await Apply(native, session, "set_native_operand", NativeUserTypeBatch.Empty with { Operands = [edit] },
            (r, layer) => r.Items is [{ Applied: true }] ? layer.WithOperand(edit) : null, cancellationToken);
        var done = Outcome(result, session.ProviderId);
        return Edited($"Operand {operand} at {Va(native, rva)} shows as {d}{(t != null ? " " + t : "")} ({session.ProviderId}): {done.Text}", id,
            new EditChange("operand", $"{Va(native, rva)}#{operand}", null, d + (t != null ? " " + t : "")));
    });

    [McpServerTool(Name = "list_native_types", Title = "Browse the engine's types", UseStructuredContent = true, OutputSchemaType = typeof(TypeListReport))]
    [Description("Named types of the engine's database (PDB, RTTI, Il2Cpp, type libraries, declare_native_types) with size and member " +
                 "count; name= shows one type as a C declaration with member offsets.")]
    public Task<string> ListNativeTypes(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Name filter: " + NameFilter.Description + ".")] string? filter = null,
        [Description("udt: struct or union.")] string? kind = null,
        [Description("Show this one type in full instead of a list.")] string? name = null,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description("Max rows (max 5000).")] int limit = 200,
        [Description(EngineDescription)] string? engine = null,
        [Description("name (default), size, or ordinal (the engine's order).")] string? sort = null,
        [Description("Reverse the order.")] bool descending = false,
        [Description("List each type's first 32 members (enums: name = value).")] bool members = false,
        [Description("Add the types each one refers to.")] bool related = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var k = string.IsNullOrWhiteSpace(kind) ? null : kind.Trim().ToLowerInvariant();
        if (k is not (null or "struct" or "union" or "udt" or "enum" or "typedef" or "func" or "ptr"))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown kind '{kind}'.", "use struct, union, udt, enum, typedef, func or ptr");
        var order = string.IsNullOrWhiteSpace(sort) ? "name" : sort.Trim().ToLowerInvariant();
        if (order is not ("ordinal" or "name" or "size")) throw new ToolError(ErrorCode.InvalidArgument, $"Unknown sort '{sort}'.", "use name or size");
        var nameFilter = NameFilter.Parse(filter);
        var (_, _, session) = await Open(image, "rva:0", engine, progress, cancellationToken);
        if (!string.IsNullOrWhiteSpace(name))
        {
            var t = await session.GetTypeAsync(name.Trim(), cancellationToken);
            var sb = new System.Text.StringBuilder($"{t.Kind} {t.Name}" + (t.Size >= 0 ? $", {t.Size} bytes" : "") + $" ({session.ProviderId})\n" + t.Declaration.TrimEnd() + "\n");
            if (t.Members.Count > 0)
            {
                sb.Append("Members (offset  name  type  size):\n");
                foreach (var m in t.Members) sb.Append($"  +0x{m.Offset:X}  {m.Name}  {m.Type}  {m.Size}\n");
            }
            var entry = new TypeEntry(t.Name, t.Kind, t.Size >= 0 ? t.Size : null, t.Members.Count,
                [.. t.Members.Select(m => new TypeMemberEntry(m.Name, t.Kind == "enum" ? null : m.Type, m.Offset, t.Kind == "enum" ? null : m.Size))], null)
                { Declaration = t.Declaration.TrimEnd() };
            return ToolOutput.Report(sb.ToString(), new TypeListReport(session.ProviderId, [entry], 0, 1));
        }
        offset = Math.Max(0, offset);
        limit = Math.Clamp(limit, 1, 5000);
        var (total, rows) = await NativeEngineQueries.Types(session, new NativeEngineQueries.TypeQuery(nameFilter, k, order, descending,
            related ? RelatedMemberRows : members ? MemberRows : 0, offset, limit), cancellationToken);
        var relatedNames = new Dictionary<string, IReadOnlyList<string>>();
        if (related)
        {
            int declarations = 0;
            foreach (var t in rows)
            {
                var texts = (t.Members ?? []).Where(_ => t.Kind != "enum").Select(m => m.Type).ToList();
                // aliases, pointers and function types name what they refer to only in their declaration
                if (t.MemberCount == 0 && t.Kind is not "enum" && declarations++ < RelatedDeclarations)
                    texts.Add((await session.GetTypeAsync(t.Name, cancellationToken)).Declaration);
                relatedNames[t.Name] = RelatedTypes(texts, t.Name);
            }
        }
        var entries = rows.Select(t => new TypeEntry(t.Name, t.Kind, t.Size >= 0 ? t.Size : null, t.MemberCount,
            members ? t.Members?.Take(MemberRows).Select(m => new TypeMemberEntry(m.Name, t.Kind == "enum" ? null : m.Type, m.Offset, t.Kind == "enum" ? null : m.Size)).ToList() : null,
            relatedNames.TryGetValue(t.Name, out var refs) && refs.Count > 0 ? refs : null)).ToList();
        var header = (nameFilter != null ? $"matching '{nameFilter.Text}'" : "") + (k != null ? $" of kind {k}" : "") + $" by {order}{(descending ? " descending" : "")} " +
                     $"({session.ProviderId})\n";
        return ToolOutput.List(entries, offset, limit, total, TypeLine,
            page => new TypeListReport(session.ProviderId, page, offset, total), "type", header.TrimStart());
    });

    public sealed record TypeMemberEntry(string Name, string? Type,
        long Offset, long? Size);

    public sealed record TypeEntry(string Name, string Kind, long? Size, int MemberCount,
        IReadOnlyList<TypeMemberEntry>? Members,
        IReadOnlyList<string>? Related)
    {
        public string? Declaration { get; init; }
    }

    public sealed record TypeListReport(string Engine, IReadOnlyList<TypeEntry> Items, int Offset, int Total);

    private static string TypeLine(TypeEntry t)
    {
        var b = new System.Text.StringBuilder($"{t.Kind} {t.Name}" + (t.Size is { } size ? $"  {size} bytes" : "") + (t.MemberCount > 0 ? $"  {t.MemberCount} members" : ""));
        foreach (var m in t.Members ?? [])
            b.Append('\n').Append(t.Kind == "enum" ? $"  {m.Name} = {m.Offset}" : $"  +0x{m.Offset:X}  {m.Name}  {m.Type}  {m.Size}");
        if (t.Members != null && t.MemberCount > t.Members.Count) b.Append('\n').Append($"  ... {t.MemberCount - t.Members.Count} more (name={t.Name} lists them)");
        if (t.Related != null) b.Append('\n').Append("  related: " + string.Join(", ", t.Related));
        return b.ToString();
    }

    /// <summary>Members listed per type with members=true (the parameter text says 32).</summary>
    private const int MemberRows = 32;
    /// <summary>Members read per type for related=true, and declarations read per page (aliases, pointers, function types).</summary>
    private const int RelatedMemberRows = 4096, RelatedDeclarations = 50;

    private static readonly HashSet<string> Primitive = new(StringComparer.Ordinal)
    {
        "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "bool", "_Bool", "wchar_t", "char8_t", "char16_t", "char32_t",
        "const", "volatile", "struct", "union", "enum", "class", "typedef", "restrict", "__restrict", "__ptr32", "__ptr64", "__unaligned",
        "__cdecl", "__stdcall", "__fastcall", "__thiscall", "__vectorcall", "__usercall", "__userpurge", "__noreturn", "__int8", "__int16",
        "__int32", "__int64", "__int128", "_BYTE", "_WORD", "_DWORD", "_QWORD", "_OWORD", "_TBYTE", "_UNKNOWN", "_BOOL1", "_BOOL2", "_BOOL4", "_BOOL8",
        "BYTE", "WORD", "DWORD", "QWORD", "byte", "word", "dword", "qword", "uchar", "ushort", "uint", "ulong", "longlong", "ulonglong", "undefined",
        "undefined1", "undefined2", "undefined4", "undefined8", "pointer", "pointer32", "pointer64", "size_t", "ssize_t", "ptrdiff_t", "intptr_t",
        "uintptr_t", "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t", "string", "unicode", "float10",
    };

    /// <summary>The named types the type texts mention (identifiers that are no keywords, primitives or <paramref name="self"/>), in first-seen order.</summary>
    internal static IReadOnlyList<string> RelatedTypes(IEnumerable<string> texts, string self)
    {
        var result = new List<string>();
        foreach (var text in texts)
            foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(text ?? "", @"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*"))
                // a1, a2: parameter names of a function type's declaration
                if (!Primitive.Contains(m.Value) && m.Value != self && !System.Text.RegularExpressions.Regex.IsMatch(m.Value, @"^a\d+$")
                    && !result.Contains(m.Value) && result.Count < 64) result.Add(m.Value);
        return result;
    }

    /// <summary>A local named as "stack:0x28" (by stack offset) or by its name.</summary>
    internal static (string Local, int? Stack) LocalTarget(string text)
    {
        var t = (text ?? "").Trim();
        if (t.StartsWith("stack:", StringComparison.OrdinalIgnoreCase))
        {
            var n = NativeAddress.Number(t[6..].Trim());
            if (n is not { } v || v > int.MaxValue)
                throw new ToolError(ErrorCode.InvalidArgument, $"'{t}' is not a stack offset.", "use stack:0x28");
            return (t, (int)v);
        }
        if (!Identifier(t)) throw new ToolError(ErrorCode.InvalidArgument, $"'{t}' is not a local's name.", "use the name decompile_native shows, or stack:<offset>");
        return (t, null);
    }

    private static bool Identifier(string s) =>
        s.Length is > 0 and <= 255 && (char.IsAsciiLetter(s[0]) || s[0] == '_') && s.All(c => char.IsAsciiLetterOrDigit(c) || c == '_');

    /// <summary>
    /// Why an engine refused an edit (EL-7), from the worker's message: no_frame, reserved_slot, name_in_use, no_local,
    /// no_storage, no_effect, parse_error, no_function; null for a reason without its own guidance.
    /// </summary>
    internal static string? RefusalCode(string? error) => error switch
    {
        null => null,
        _ when error.Contains("has no stack frame", StringComparison.Ordinal) => "no_frame",
        _ when error.Contains("return address", StringComparison.Ordinal) || error.Contains("saved registers", StringComparison.Ordinal) => "reserved_slot",
        _ when error.Contains("already has a local named", StringComparison.Ordinal) => "name_in_use",
        _ when error.Contains("has no local", StringComparison.Ordinal) => "no_local",
        _ when error.Contains("no storage", StringComparison.Ordinal) => "no_storage",
        _ when error.Contains("not take", StringComparison.Ordinal) => "no_effect",
        _ when error.Contains("does not parse", StringComparison.Ordinal) => "parse_error",
        _ when error.Contains("no function contains", StringComparison.Ordinal) => "no_function",
        _ => null,
    };

    /// <summary>The Next of an engine refusal, by its code; <paramref name="frame"/> names a valid offset for frame refusals.</summary>
    internal static string Refusal(string? error, string engine, NativeFrame? frame = null) => RefusalCode(error) switch
    {
        "no_frame" => $"the function has no stack frame in {NativeEngineService.DisplayName(engine)}; set_native_local edits its register variables, or try " +
                      $"engine={(engine == "ida" ? "ghidra" : "ida")}",
        "reserved_slot" => frame is { ReturnAddressOffset: > 0 } f ? $"pick a frame offset below +0x{f.ReturnAddressOffset:X} (locals) or past the saved registers (arguments); get_native_frame shows the frame"
            : "pick another frame offset; get_native_frame shows the frame",
        "name_in_use" => "pick another name, or clear=true on the local that holds it (a kept edit may have named it; get_native_frame shows user names)",
        "no_local" => "use a name decompile_native shows for this function, or stack:<offset> (get_native_frame lists the locals)",
        "no_storage" or "no_effect" => "rename a local that decompile_native shows, or the variable this one is copied from",
        "parse_error" => "declare the types it names first (declare_native_types), and spell the calling convention as the engine does (__cdecl, __stdcall, __fastcall)",
        "no_function" => "define_native kind=function at the start first, or list_functions for a valid address",
        _ => "check the spelling; list_native_types shows the engine's types and declare_native_types adds missing ones",
    };

    /// <summary>The single item of a one-edit batch, or the engine's refusal with a Next by its reason.</summary>
    private static NativeUserTypeOutcome Outcome(UserTypeResult result, string engine, NativeFrame? frame = null)
    {
        var item = result.Items.Count == 1 ? result.Items[0] : throw new ToolError(ErrorCode.Failed, "The engine did not report the edit.");
        if (item.Applied) return item;
        var code = RefusalCode(item.Error);
        // the engine took the request but its state did not change: not a spelling problem
        throw new ToolError(code is "no_effect" or "no_storage" ? ErrorCode.Failed : ErrorCode.InvalidArgument, item.Error ?? "The engine did not apply the edit.",
            Refusal(item.Error, engine, frame)) { Details = code != null ? new { reason = code } : null };
    }
}
