using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
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
    NativeNamePush? names = null, NativeTypePush? types = null, OutputPager? pager = null)
{
    private const string EngineDescription = "auto (default): the engine with this image open, else IDA when installed, else Ghidra.";

    private const string KeptNote = " Kept with the image's annotations.";

    /// <summary>The image, an address in it and its engine session, with names and recovered types pushed first so user types apply on top.</summary>
    private async Task<(LoadedNative Native, uint Rva, INativeDecompilerSession Session)> Open(string image, string address, string? engine,
        IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        engines.Provider(engine); // an unknown engine fails before the image is opened
        var (native, rva) = await Task.Run(() => NativeAnalysisTools.Resolve(workspace, code, image, address), ct);
        var session = await engines.Session(native, engine, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), ct);
        if (names != null) await names.EnsureAsync(native, session, ct);
        if (types != null) await types.EnsureAsync(native, session, ct);
        await userTypes.EnsureAsync(native, session, ct);
        return (native, rva, session);
    }

    [McpServerTool(Name = "get_native_frame", Title = "Native stack frame and locals")]
    [Description("A native function's stack frame as the engine has it (members: offset, name, type, size; Ghidra counts saved registers as " +
                 "locals) and its decompiler locals (name, type, register or stack offset, user edits). Offsets count from the frame's lowest " +
                 "address; brackets give the offset from the return address (IDA's var_/arg_).")]
    public Task<string> GetNativeFrame(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("The function: " + NativeTools.AddressDescription)] string function,
        [Description(EngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, rva, session) = await Open(image, function, engine, progress, cancellationToken);
        var f = await session.GetFrameAsync(rva, cancellationToken);
        var (display, symbol) = NativeTools.Named(f.Name, native.Image.Format);
        var sb = new System.Text.StringBuilder($"Frame of {display} at {Va(native, f.StartRva)}{(symbol.Length > 0 ? $" ({symbol[2..]})" : "")}: {f.LocalSize} bytes of " +
                                               $"locals, {f.SavedRegisters} of saved registers; return address at +0x{f.ReturnAddressOffset:X}\n");
        sb.AppendLine(f.Members.Count == 0 ? "No stack members." : "Stack members (offset [base-relative]  name  type  size  kind):");
        foreach (var m in f.Members)
        {
            int rel = m.Offset - f.ReturnAddressOffset;
            sb.AppendLine($"  +0x{m.Offset:X} [{(rel < 0 ? "-" : "+")}0x{Math.Abs(rel):X}]  {m.Name}  {m.Type}  {m.Size}  {m.Kind}");
        }
        if (f.DecompilerError != null) sb.AppendLine($"Decompiler locals: none ({f.DecompilerError})");
        else
        {
            sb.AppendLine("Decompiler locals (name  type  location):");
            foreach (var l in f.Locals.Where(l => l.Name.Length > 0))
                sb.AppendLine($"  {l.Name}  {l.Type}  {(l.Stack is { } s ? $"stack:0x{s:X}" : l.Location)}" +
                              (l.IsArgument ? "  argument" : "") + (l.UserName ? "  user name" : "") + (l.UserType ? "  user type" : ""));
        }
        return sb.ToString();
    });

    [McpServerTool(Name = "set_native_stack_var", Title = "Rename, retype or delete a stack variable")]
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
        var frame = await session.GetFrameAsync(rva, cancellationToken);
        var v = (variable ?? "").Trim();
        int offset = frame.Members.FirstOrDefault(m => m.Name == v) is { } byName ? byName.Offset
            : NativeAddress.Number(v.TrimStart('+')) is { } n && n <= int.MaxValue ? (int)n
            : throw new ToolError(ErrorCode.InvalidArgument, $"The frame of {frame.Name} has no member '{v}'.",
                $"members: {string.Join(", ", frame.Members.Select(m => m.Name).Take(40))}; or pass a frame offset such as 0x20");
        var edit = new NativeStackVarEdit(frame.StartRva, offset, name, decl) { Delete = delete, Clear = clear };
        var result = await userTypes.ApplyAsync(native, session, new NativeUserTypeBatch([], [], [edit], []),
            (r, layer) => r.Items is not [{ Applied: true } item] ? null
                : clear ? layer.WithoutStackVar(item.Rva, offset) : layer.WithStackVar(edit with { Function = item.Rva }), cancellationToken);
        var done = Outcome(result);
        if (clear) return $"Stack member +0x{offset:X} of {frame.Name} at {Va(native, done.Rva)}: the user edit is cleared; now {done.Text}";
        return delete ? $"Stack member +0x{offset:X} of {frame.Name} at {Va(native, done.Rva)}: {(done.Resolved != null ? $"{done.Resolved} " : "")}{done.Text}"
            : $"Stack member +0x{offset:X} of {frame.Name} at {Va(native, done.Rva)}{(done.Resolved != null ? $" (was {done.Resolved})" : "")} is now: {done.Text}";
        }, cancellationToken);
    });

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

    [McpServerTool(Name = "set_native_type", Title = "Set a native prototype or global type")]
    [Description("Set the prototype of a native function ('int __fastcall Parse(Packet *p, int len)') or the type of a global ('Handler *[8]') " +
                 "in the engine. Named types must exist there (pushed PDB, RTTI and Il2Cpp types, or declare_native_types). User types win over " +
                 "recovered ones; empty clears. A prototype's name renames the function unless rename=false." + KeptNote)]
    public Task<string> SetNativeType(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("A function start or a global: " + NativeTools.AddressDescription)] string? address = null,
        [Description("C prototype for a function, C type for a global; empty to clear the user type.")] string? type = null,
        [Description("Instead of address and type: lines 'address = type'.")] string? items = null,
        [Description("Name the function as its prototype does.")] bool rename = true,
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
            var result = await userTypes.ApplyAsync(native, session, new NativeUserTypeBatch([], [new NativePrototype(rva, decl)], [], []),
                (r, layer) => r.Items is [{ Applied: true }] ? layer.WithType(rva, decl) : null, cancellationToken);
            var item = Outcome(result);
            if (decl.Length == 0) return $"Cleared the user type at {Va(native, rva)}.";
            var renamed = rename ? await RenameFromPrototype(native, session, rva, decl, cancellationToken) : null;
            return $"Type at {Va(native, rva)}: {item.Text ?? decl}" + (renamed != null ? $"; the function is now named {renamed} (rename=false keeps its name)" : "");
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
        var result = await userTypes.ApplyAsync(native, session, new NativeUserTypeBatch([], wanted, [], []),
            (r, layer) => r.Items.Where(i => i.Applied).Aggregate(layer, (l, i) => l.WithType(i.Rva, i.Target)), ct);
        var sb = new System.Text.StringBuilder($"{result.Items.Count(i => i.Applied)} of {lines.Length} type(s) applied\n");
        foreach (var i in result.Items)
            sb.AppendLine($"  {Va(native, i.Rva)}  {(i.Applied ? (i.Target.Length == 0 ? "cleared" : i.Text ?? i.Target) : "not applied: " + i.Error)}");
        foreach (var p in problems) sb.AppendLine($"  not applied: {p}");
        return sb.ToString();
    }

    [McpServerTool(Name = "set_native_local", Title = "Rename or retype a decompiler local")]
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
        var result = await userTypes.ApplyAsync(native, session, new NativeUserTypeBatch([], [], [], edits), (r, layer) => RecordLocals(r, layer, edits), cancellationToken);
        if (result.Items.FirstOrDefault(i => !i.Applied) is { } failed) Outcome(result with { Items = [failed] });
        var done = result.Items.Count > 0 ? result.Items[^1] : throw new ToolError(ErrorCode.Failed, "The engine did not report the edit.");
        return $"Local {done.Resolved} of the function at {Va(native, done.Rva)}{(done.Stack is { } k ? $" (stack 0x{k:X})" : "")} " +
               (done.Kind == "local_clear" ? $"is cleared; now {done.Text}" : $"is now: {done.Text}");
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
        var result = edits.Count == 0 ? null
            : await userTypes.ApplyAsync(native, session, new NativeUserTypeBatch([], [], [], edits), (r, layer) => RecordLocals(r, layer, edits), ct);
        var outcomes = result?.Items ?? [];
        var sb = new System.Text.StringBuilder($"{outcomes.Count(i => i.Applied)} of {outcomes.Count + problems.Count} local edit(s) applied\n");
        foreach (var i in outcomes)
            sb.AppendLine($"  {i.Resolved ?? i.Target}  " + (!i.Applied ? "not applied: " + i.Error : i.Kind == "local_clear" ? "cleared; now " + i.Text : i.Text));
        foreach (var p in problems) sb.AppendLine($"  not applied: {p}");
        return sb.ToString();
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

    [McpServerTool(Name = "declare_native_types", Title = "Declare C types in the engine")]
    [Description("Declare C types (structs, unions, enums, typedefs, function types) in the engine; a type of the same name is replaced, and " +
                 "declarations win over recovered types. Errors carry the engine's messages and are not saved. typeName with members upserts or " +
                 "removes enum members, with fields struct or union members; delete or rename edits a named type." + KeptNote)]
    public Task<string> DeclareNativeTypes(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("C declarations; types they name must exist or be declared too.")] string? declarations = null,
        [Description("Enum, struct or union to edit.")] string? typeName = null,
        [Description("Enum: 'NAME=value, ...' (hex or decimal; or lines); 'NAME=' removes.")] string? members = null,
        [Description("Struct or union: 'name: type; name@0x10: type; @0x10: type' (or lines); 'name:' removes.")] string? fields = null,
        [Description("A type to delete.")] string? delete = null,
        [Description("'Old=New'; kept edits naming it follow.")] string? rename = null,
        [Description(EngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var text = (declarations ?? "").Trim();
        if (!string.IsNullOrWhiteSpace(members) && !string.IsNullOrWhiteSpace(fields))
            throw new ToolError(ErrorCode.InvalidArgument, "Pass members (an enum) or fields (a struct or union), not both.");
        var enumMembers = string.IsNullOrWhiteSpace(fields) ? EnumMembers(typeName, members) : [];
        var fieldEdits = string.IsNullOrWhiteSpace(fields) ? [] : FieldEdits(typeName, fields);
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
        var result = await userTypes.ApplyAsync(native, session,
            new NativeUserTypeBatch(text.Length > 0 ? [text] : [], [], [], []) { EnumMembers = enumMembers, Fields = fieldEdits },
            (r, layer) => r.DeclarationErrors > 0 ? null : RecordMembers(r, text.Length > 0 ? layer.WithDeclarations(text, r.DeclaredTypes) : layer, enumMembers, fieldEdits),
            cancellationToken);
        if (result.DeclarationErrors > 0)
            throw new ToolError(ErrorCode.InvalidArgument, $"{result.DeclarationErrors} error(s) in the declarations" +
                (result.DeclarationMessages.Count > 0 ? ": " + string.Join("; ", result.DeclarationMessages) : "."), "fix the declarations and declare them again");
        // a declared name drops the kept rename or deletion of it, in the engine too
        if (userTypes.Layer(native).TypeEdits is var kept && kept.Count != edits.Count)
            await userTypes.ApplyAsync(native, session, NativeUserTypeBatch.Empty with { TypeEdits = kept }, (_, _) => null, cancellationToken);
        var sb = new System.Text.StringBuilder();
        if (text.Length > 0)
            sb.AppendLine(result.DeclaredTypes.Count == 0 ? "Declared (the engine reported no type names)."
                : $"Declared {result.DeclaredTypes.Count} type(s): {string.Join(", ", result.DeclaredTypes.Distinct())}");
        foreach (var i in result.Items.Where(i => i.Kind is "enum" or "field")) sb.AppendLine(i.Applied ? $"  {i.Text}" : $"  {i.Target} not applied: {i.Error}");
        if (enumMembers.Count + fieldEdits.Count > 0 && result.Items.All(i => !i.Applied))
            throw new ToolError(ErrorCode.InvalidArgument, "No member was applied:\n" + sb, "check the type's name and the member names; list_native_types name= shows them");
        return sb.ToString().TrimEnd();
    });

    /// <summary>The applied enum members and fields (field outcomes in the order sent) recorded in the layer.</summary>
    private static UserTypeLayer RecordMembers(UserTypeResult result, UserTypeLayer layer, List<NativeEnumMemberEdit> enums, List<NativeFieldEdit> fields)
    {
        foreach (var i in result.Items.Where(i => i.Kind == "enum" && i.Applied))
            if (enums.FirstOrDefault(e => $"{e.Enum}::{e.Member}" == i.Target) is { } e) layer = layer.WithEnumMember(e);
        foreach (var (item, edit) in result.Items.Where(i => i.Kind == "field").Zip(fields))
            if (item.Applied) layer = layer.WithField(edit);
        return layer;
    }

    /// <summary>"len: int; data@0x8: char[16]; @0x20: int; old:" for a struct or union: members to set, an empty type removing one.</summary>
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
            var fieldType = entry[(colon + 1)..].Trim();
            int at = head.IndexOf('@', StringComparison.Ordinal);
            var name = (at < 0 ? head : head[..at]).Trim();
            int? offset = null;
            if (at >= 0)
                offset = NativeAddress.Number(head[(at + 1)..].Trim()) is { } n && n <= int.MaxValue ? (int)n
                    : throw new ToolError(ErrorCode.InvalidArgument, $"'{head[(at + 1)..].Trim()}' is not an offset.", "use @0x10 or @16");
            if (name.Length > 0 && !Identifier(name)) throw new ToolError(ErrorCode.InvalidArgument, $"'{name}' is not a C identifier.");
            if (name.Length == 0 && offset == null) throw new ToolError(ErrorCode.InvalidArgument, $"'{entry}' names no member.", "give a name, an @offset or both");
            result.Add(new NativeFieldEdit(type, name.Length > 0 ? name : null, offset, fieldType.Length > 0 ? fieldType : null));
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
        await session.GetTypeAsync(edit.Name, ct);
        if (edit.NewName is { } to)
        {
            bool taken;
            try { taken = (await session.GetTypeAsync(to, ct)).Name == to; }
            catch (ToolError e) when (e.Code == ErrorCode.NotFound) { taken = false; }
            if (taken) throw new ToolError(ErrorCode.InvalidArgument, $"A type named {to} exists.", $"delete it first (delete={to}), or pick another name");
        }
        var result = await userTypes.ApplyAsync(native, session, NativeUserTypeBatch.Empty with { TypeEdits = userTypes.Layer(native).WithTypeEdit(edit).TypeEdits },
            (r, layer) => r.Items.LastOrDefault(i => i.Kind == "type_edit" && i.Target == edit.Name) is { Applied: true } ? layer.WithTypeEdit(edit) : null, ct);
        var done = result.Items.LastOrDefault(i => i.Kind == "type_edit" && i.Target == edit.Name)
            ?? throw new ToolError(ErrorCode.Failed, "The engine did not report the edit.");
        if (!done.Applied) throw new ToolError(ErrorCode.InvalidArgument, done.Error ?? "The engine did not apply the edit.");
        return edit.NewName == null ? $"Deleted type {edit.Name}." : $"Renamed type {edit.Name} to {edit.NewName}; the kept edits that named it now name {edit.NewName}.";
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

    [McpServerTool(Name = "define_native", Title = "Redefine code or data in the engine")]
    [Description("Change the engine's analysis at an address. code decodes instructions (to end, else following the flow); function makes " +
                 "a function (with end: its extent; on one: moves its end); undefine makes unknown bytes (to end, else the item; at a function start " +
                 "the function); data makes a data item of type. Data and undefine replace a user type on a global there." + KeptNote)]
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
        if (k is not (NativeAnalysisEdit.Code or NativeAnalysisEdit.Function or NativeAnalysisEdit.Undefine or NativeAnalysisEdit.Data))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown kind '{kind}'.", "use code, function, undefine or data");
        var t = string.IsNullOrWhiteSpace(type) ? null : type.Trim();
        if (k == NativeAnalysisEdit.Data && t == null)
            throw new ToolError(ErrorCode.InvalidArgument, "kind=data needs a type.", "pass type, e.g. dword, dword[8], string or a C type such as Packet");
        if (k != NativeAnalysisEdit.Data && t != null)
            throw new ToolError(ErrorCode.InvalidArgument, $"type applies to kind=data, not {k}.", "drop type, or use kind=data");
        var (native, rva, session) = await Open(image, address, engine, progress, cancellationToken);
        uint? stop = null;
        if (!string.IsNullOrWhiteSpace(end))
        {
            stop = workspace.Read(() => NativeAddress.Parse(native.Image, end, code?.Ready(native) is { } index ? index.AddressesOfName : null));
            if (stop <= rva) throw new ToolError(ErrorCode.InvalidArgument, $"end {Va(native, stop.Value)} is not after {Va(native, rva)}.", "pass an end above the start");
        }
        var edit = new NativeAnalysisEdit(rva, k, stop, t);
        var result = await userTypes.ApplyAsync(native, session, NativeUserTypeBatch.Empty with { Analysis = [edit] },
            (r, layer) => r.Items is [{ Applied: true }] ? layer.WithAnalysis(edit) : null, cancellationToken);
        var done = Outcome(result);
        if (k != NativeAnalysisEdit.Data) _ = GhidraNames.Refresh(native, session, code);
        return $"{k} at {Va(native, rva)}{(stop is { } s ? $"-{Va(native, s)}" : "")}: {done.Text}";
    });

    [McpServerTool(Name = "set_native_operand", Title = "Set how an operand displays")]
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
        var result = await userTypes.ApplyAsync(native, session, NativeUserTypeBatch.Empty with { Operands = [edit] },
            (r, layer) => r.Items is [{ Applied: true }] ? layer.WithOperand(edit) : null, cancellationToken);
        var done = Outcome(result);
        return $"Operand {operand} at {Va(native, rva)} shows as {d}{(t != null ? " " + t : "")}: {done.Text}";
    });

    [McpServerTool(Name = "list_native_types", Title = "Browse the engine's types")]
    [Description("The named types of the engine's database (PDB, RTTI, Il2Cpp, type libraries, declare_native_types) with size and member " +
                 "count; name= shows one type as a C declaration with member offsets.")]
    public Task<string> ListNativeTypes(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Name filter: " + NameFilter.Description + ".")] string? filter = null,
        [Description("udt: struct or union.")] string? kind = null,
        [Description("Show this one type in full instead of a list.")] string? name = null,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description("Max rows (max 5000).")] int limit = 200,
        [Description(EngineDescription)] string? engine = null,
        [Description("Default: the engine's order.")] string? sort = null,
        [Description("Reverse the order.")] bool descending = false,
        [Description("List each type's first 32 members (enums: name = value).")] bool members = false,
        [Description("Add the types each one refers to.")] bool related = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var k = string.IsNullOrWhiteSpace(kind) ? null : kind.Trim().ToLowerInvariant();
        if (k is not (null or "struct" or "union" or "udt" or "enum" or "typedef" or "func" or "ptr"))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown kind '{kind}'.", "use struct, union, udt, enum, typedef, func or ptr");
        var order = string.IsNullOrWhiteSpace(sort) ? "ordinal" : sort.Trim().ToLowerInvariant();
        if (order is not ("ordinal" or "name" or "size")) throw new ToolError(ErrorCode.InvalidArgument, $"Unknown sort '{sort}'.", "use name or size");
        var nameFilter = NameFilter.Parse(filter);
        var (_, _, session) = await Open(image, "rva:0", engine, progress, cancellationToken);
        if (!string.IsNullOrWhiteSpace(name))
        {
            var t = await session.GetTypeAsync(name.Trim(), cancellationToken);
            var sb = new System.Text.StringBuilder($"{t.Kind} {t.Name}" + (t.Size >= 0 ? $", {t.Size} bytes" : "") + "\n" + t.Declaration.TrimEnd() + "\n");
            if (t.Members.Count > 0)
            {
                sb.AppendLine("Members (offset  name  type  size):");
                foreach (var m in t.Members) sb.AppendLine($"  +0x{m.Offset:X}  {m.Name}  {m.Type}  {m.Size}");
            }
            return sb.ToString();
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
        var blocks = rows.Select(t =>
        {
            var b = new System.Text.StringBuilder($"  {t.Kind} {t.Name}" + (t.Size >= 0 ? $"  {t.Size} bytes" : "") + (t.MemberCount > 0 ? $"  {t.MemberCount} members" : ""));
            var shown = members ? t.Members?.Take(MemberRows).ToList() : null;
            foreach (var m in shown ?? [])
                b.AppendLine().Append(t.Kind == "enum" ? $"      {m.Name} = {m.Offset}" : $"      +0x{m.Offset:X}  {m.Name}  {m.Type}  {m.Size}");
            if (shown != null && t.MemberCount > shown.Count) b.AppendLine().Append($"      ... {t.MemberCount - shown.Count} more (name={t.Name} lists them)");
            if (relatedNames.TryGetValue(t.Name, out var refs) && refs.Count > 0) b.AppendLine().Append("      related: " + string.Join(", ", refs));
            return b.ToString();
        }).ToList();
        int fit = (pager ?? new OutputPager(new ServerOptions())).FitRows(blocks, 400);
        var text = new System.Text.StringBuilder($"{total} type(s)" + (nameFilter != null ? $" matching '{nameFilter.Text}'" : "") + (k != null ? $" of kind {k}" : "") +
                                                 (order != "ordinal" ? $" by {order}{(descending ? " descending" : "")}" : "") +
                                                 (fit < total ? $"; rows {offset + 1}-{offset + fit}" : "") + "\n");
        foreach (var block in blocks.Take(fit)) text.AppendLine(block);
        if (fit < blocks.Count) text.AppendLine(OutputPager.CapNote(fit, blocks.Count, offset + fit));
        else if (offset + rows.Count < total) text.AppendLine($"More: offset={offset + rows.Count}");
        return text.ToString();
    });

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

    /// <summary>The single item of a one-edit batch, or the engine's reason as an invalid_argument error.</summary>
    /// <summary>How the engine workers word an edit they verified had no effect.</summary>
    private const string NoEffect = "not take";

    private static NativeUserTypeOutcome Outcome(UserTypeResult result)
    {
        var item = result.Items.Count == 1 ? result.Items[0] : throw new ToolError(ErrorCode.Failed, "The engine did not report the edit.");
        // The engine took the request but its state did not change: not a spelling problem.
        if (!item.Applied && item.Error is { } noEffect && noEffect.Contains(NoEffect, StringComparison.Ordinal))
            throw new ToolError(ErrorCode.Failed, noEffect, "rename a local that decompile_native shows, or the variable this one is copied from");
        if (!item.Applied)
            throw new ToolError(ErrorCode.InvalidArgument, item.Error ?? "The engine did not apply the edit.",
                "check the spelling; list_native_types shows the engine's types and declare_native_types adds missing ones");
        return item;
    }
}
