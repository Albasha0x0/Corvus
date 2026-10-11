using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tools;

/// <summary>
/// The user's types in the decompiler engine (declarations, prototypes and global types, locals, stack variables) and a
/// view of the engine's types and frames. Every edit is kept in the image's annotation sidecar (re-applied to a new
/// database, exported, carried to new builds).
/// </summary>
[McpServerToolType]
public sealed class NativeTypeTools(AssemblyWorkspace workspace, NativeEngineService engines, NativeUserTypePush userTypes, NativeCodeService? code = null,
    NativeNamePush? names = null, NativeTypePush? types = null)
{
    private const string EngineDescription = "Engine: auto (default: an engine with a session of this image open, else IDA when installed, else Ghidra), ida or ghidra.";

    private const string KeptNote = " Saved per file hash with the image's annotations: re-applied to a new database, exported by export_native_annotations " +
                                    "and carried by migrate_native_names and update_to_new_build.";

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
    [Description("A native function's stack frame as the engine has it (members: offset, name, type, size; locals, arguments, return address, " +
                 "saved registers, which Ghidra counts as locals) and its decompiler locals (name, type, register or stack offset, argument, user " +
                 "name / type). Offsets count from the frame's lowest address; brackets give the offset from the return address (IDA's var_/arg_). " +
                 "set_native_stack_var and set_native_local edit them.")]
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
    [Description("Rename and/or retype a member of a native function's stack frame in the engine, named as get_native_frame lists it (var_28) or by " +
                 "frame offset (0x20 or +0x20, from the frame's lowest address); a type at an offset with no member creates one; delete=true removes " +
                 "it. The return address and saved registers are refused. Stack variables the decompiler has not renamed take the member's name." + KeptNote)]
    public Task<string> SetNativeStackVar(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("The function: " + NativeTools.AddressDescription)] string function,
        [Description("The member: its name, or its frame offset (hex).")] string variable,
        [Description("New name (a C identifier).")] string? newName = null,
        [Description("New C type, e.g. 'int', 'char[16]', 'Packet'.")] string? type = null,
        [Description("Delete the member instead (no newName or type).")] bool delete = false,
        [Description(EngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var name = string.IsNullOrWhiteSpace(newName) ? null : newName.Trim();
        var decl = string.IsNullOrWhiteSpace(type) ? null : type.Trim();
        if (delete && (name != null || decl != null)) throw new ToolError(ErrorCode.InvalidArgument, "delete takes no newName or type.", "drop newName and type");
        if (!delete && name == null && decl == null) throw new ToolError(ErrorCode.InvalidArgument, "Nothing to change.", "pass newName, type or both, or delete=true");
        if (name != null && !Identifier(name))
            throw new ToolError(ErrorCode.InvalidArgument, $"'{name}' is not a C identifier.", "use letters, digits and _, not starting with a digit");
        var (native, rva, session) = await Open(image, function, engine, progress, cancellationToken);
        var frame = await session.GetFrameAsync(rva, cancellationToken);
        var v = (variable ?? "").Trim();
        int offset = frame.Members.FirstOrDefault(m => m.Name == v) is { } byName ? byName.Offset
            : NativeAddress.Number(v.TrimStart('+')) is { } n && n <= int.MaxValue ? (int)n
            : throw new ToolError(ErrorCode.InvalidArgument, $"The frame of {frame.Name} has no member '{v}'.",
                $"members: {string.Join(", ", frame.Members.Select(m => m.Name).Take(40))}; or pass a frame offset such as 0x20");
        var edit = new NativeStackVarEdit(frame.StartRva, offset, name, decl) { Delete = delete };
        var result = await userTypes.ApplyAsync(native, session, new NativeUserTypeBatch([], [], [edit], []),
            (r, layer) => r.Items is [{ Applied: true } item] ? layer.WithStackVar(edit with { Function = item.Rva }) : null, cancellationToken);
        var done = Outcome(result);
        return delete ? $"Stack member +0x{offset:X} of {frame.Name} at {Va(native, done.Rva)}: {(done.Resolved != null ? $"{done.Resolved} " : "")}{done.Text}"
            : $"Stack member +0x{offset:X} of {frame.Name} at {Va(native, done.Rva)}{(done.Resolved != null ? $" (was {done.Resolved})" : "")} is now: {done.Text}";
    });

    private static string Va(LoadedNative native, uint rva) => NativeAddress.Va(native.Image, rva);

    [McpServerTool(Name = "set_native_type", Title = "Set a native prototype or global type")]
    [Description("Set the type of a native function (its prototype, e.g. 'int __fastcall Parse(Packet *p, int len)') or of a global (e.g. " +
                 "'Config', 'char[64]', 'Handler *[8]') in the decompiler engine (IDA or Ghidra). Named types must exist there (the PDB, RTTI and Il2Cpp types " +
                 "decompile_native pushes, or declare_native_types). User types win over recovered ones. An empty type clears it. items applies " +
                 "many in one request, one 'address = type' per line, each reported." + KeptNote)]
    public Task<string> SetNativeType(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("A function start or a global: " + NativeTools.AddressDescription)] string? address = null,
        [Description("C prototype for a function, C type for a global; empty to clear the user type.")] string? type = null,
        [Description("Instead of address and type: lines 'address = type', e.g. '0x140010000 = Config'.")] string? items = null,
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
        if (string.IsNullOrWhiteSpace(address) || type == null)
            throw new ToolError(ErrorCode.InvalidArgument, "Pass address and type, or items.", "items takes lines 'address = type'");
        var (native, rva, session) = await Open(image, address, engine, progress, cancellationToken);
        var decl = type.Trim();
        var result = await userTypes.ApplyAsync(native, session, new NativeUserTypeBatch([], [new NativePrototype(rva, decl)], [], []),
            (r, layer) => r.Items is [{ Applied: true }] ? layer.WithType(rva, decl) : null, cancellationToken);
        var item = Outcome(result);
        return decl.Length == 0 ? $"Cleared the user type at {Va(native, rva)}." : $"Type at {Va(native, rva)}: {item.Text ?? decl}";
    });

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
    [Description("Rename and/or retype a local variable or argument in the pseudocode of a native function (IDA Hex-Rays or Ghidra's decompiler): name it as " +
                 "decompile_native shows it (v3, a1), or by stack offset as stack:0x28. Later edits may name it by its new name; it stays one edit. " +
                 "The decompiler can refuse a type that does not fit the variable (reported)." + KeptNote)]
    public Task<string> SetNativeLocal(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("The function: " + NativeTools.AddressDescription)] string function,
        [Description("The variable: its name in the pseudocode, or stack:<offset> (hex).")] string local,
        [Description("New name (a C identifier).")] string? newName = null,
        [Description("New C type, e.g. 'unsigned int', 'Packet *', 'char[16]'.")] string? type = null,
        [Description(EngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var name = string.IsNullOrWhiteSpace(newName) ? null : newName.Trim();
        var decl = string.IsNullOrWhiteSpace(type) ? null : type.Trim();
        if (name == null && decl == null) throw new ToolError(ErrorCode.InvalidArgument, "Nothing to change.", "pass newName, type or both");
        if (name != null && !Identifier(name))
            throw new ToolError(ErrorCode.InvalidArgument, $"'{name}' is not a C identifier.", "use letters, digits and _, not starting with a digit");
        var (target, stack) = LocalTarget(local);
        var (native, rva, session) = await Open(image, function, engine, progress, cancellationToken);
        var result = await userTypes.ApplyAsync(native, session, new NativeUserTypeBatch([], [], [], [new NativeLocalEdit(rva, target, stack, name, decl)]),
            (r, layer) => r.Items is [{ Applied: true } item] ? layer.WithLocal(new NativeLocalEdit(item.Rva, item.Resolved ?? target, item.Stack, name, decl)) : null,
            cancellationToken);
        var done = Outcome(result);
        return $"Local {done.Resolved} of the function at {Va(native, done.Rva)}{(done.Stack is { } k ? $" (stack 0x{k:X})" : "")} is now: {done.Text}";
    });

    [McpServerTool(Name = "declare_native_types", Title = "Declare C types in the engine")]
    [Description("Declare C types (structs, unions, enums, typedefs, function pointer types) in the decompiler engine (IDA or Ghidra) from C declarations, " +
                 "e.g. 'struct Packet { int length; char data[256]; };'. A type of the same name is replaced, and user declarations win over the " +
                 "recovered PDB, RTTI and Il2Cpp types of that name. Declarations with errors are reported with the engine's messages and not saved. " +
                 "Use the types with set_native_type, set_native_local and set_native_stack_var. enumName with members adds, changes or removes " +
                 "members of an enum (created when missing; also a recovered one), kept over later declarations." + KeptNote)]
    public Task<string> DeclareNativeTypes(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("C declarations, several allowed; types they name must exist or be declared in the same text.")] string? declarations = null,
        [Description("An enum whose members to upsert.")] string? enumName = null,
        [Description("With enumName: 'NAME=value' pairs separated by commas or lines (hex or decimal); 'NAME=' removes the member.")] string? members = null,
        [Description(EngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var text = (declarations ?? "").Trim();
        var enumMembers = EnumMembers(enumName, members);
        if (text.Length == 0 && enumMembers.Count == 0)
            throw new ToolError(ErrorCode.InvalidArgument, "No declarations or enum members given.", "pass C declarations such as 'struct S { int a; };', or enumName and members");
        var (native, _, session) = await Open(image, "rva:0", engine, progress, cancellationToken);
        var result = await userTypes.ApplyAsync(native, session, new NativeUserTypeBatch(text.Length > 0 ? [text] : [], [], [], []) { EnumMembers = enumMembers },
            (r, layer) => r.DeclarationErrors > 0 ? null : r.Items.Where(i => i.Applied).Aggregate(text.Length > 0 ? layer.WithDeclarations(text) : layer,
                (l, i) => enumMembers.FirstOrDefault(e => $"{e.Enum}::{e.Member}" == i.Target) is { } e ? l.WithEnumMember(e) : l), cancellationToken);
        if (result.DeclarationErrors > 0)
            throw new ToolError(ErrorCode.InvalidArgument, $"{result.DeclarationErrors} error(s) in the declarations" +
                (result.DeclarationMessages.Count > 0 ? ": " + string.Join("; ", result.DeclarationMessages) : "."), "fix the declarations and declare them again");
        var sb = new System.Text.StringBuilder();
        if (text.Length > 0)
            sb.AppendLine(result.DeclaredTypes.Count == 0 ? "Declared (the engine reported no type names)."
                : $"Declared {result.DeclaredTypes.Count} type(s): {string.Join(", ", result.DeclaredTypes.Distinct())}");
        foreach (var i in result.Items.Where(i => i.Kind == "enum")) sb.AppendLine(i.Applied ? $"  {i.Text}" : $"  {i.Target} not applied: {i.Error}");
        if (enumMembers.Count > 0 && result.Items.All(i => !i.Applied))
            throw new ToolError(ErrorCode.InvalidArgument, "No enum member was applied:\n" + sb, "check the enum's name and the member names");
        return sb.ToString().TrimEnd();
    });

    /// <summary>"A=1, B=0x10, C=" for an enum: members to set, an empty value removing one.</summary>
    internal static List<NativeEnumMemberEdit> EnumMembers(string? enumName, string? members)
    {
        var name = (enumName ?? "").Trim();
        var list = (members ?? "").Split([',', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (name.Length == 0 != (list.Length == 0))
            throw new ToolError(ErrorCode.InvalidArgument, "enumName and members go together.", "pass both, e.g. enumName=Color members='Red=1, Green=2'");
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
    [Description("Change the engine's analysis (IDA or Ghidra) at an address. kind=code decodes instructions (up to end, else following the flow); " +
                 "function makes a function (with end: its extent; on an existing function: moves its end); undefine turns items back into unknown " +
                 "bytes (up to end, else the item there; at a function start the whole function); data makes a data item of type: byte, word, dword, " +
                 "qword, float, double, string (C string, ends at end or its terminator), string16 (UTF-16) or a C type ('Packet', 'char[16]'), each " +
                 "with an optional [count] such as dword[8]. Data and undefine replace a user type set on a global there." + KeptNote)]
    public Task<string> DefineNative(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Start: " + NativeTools.AddressDescription)] string address,
        [Description("code, function, undefine or data.")] string kind,
        [Description("Exclusive end address (same forms as address).")] string? end = null,
        [Description("kind=data: byte, word, dword, qword, float, double, string, string16 or a C type, optionally with [count].")] string? type = null,
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
        return $"{k} at {Va(native, rva)}{(stop is { } s ? $"-{Va(native, s)}" : "")}: {done.Text}";
    });

    [McpServerTool(Name = "set_native_operand", Title = "Set how an operand displays")]
    [Description("Set how an instruction operand displays in the engine's disassembly and, where the decompiler follows it, the pseudocode: hex, dec, " +
                 "oct, bin, char, offset (the constant as an address), stack (a stack variable), enum (type: the enum, a member of the constant's value; " +
                 "declare_native_types declares enums and members), struct (type: 'Packet' or 'Packet+0x10' for a pointer into it; IDA only) or " +
                 "default (the engine's own). Ghidra shows numbers and enum members as equates." + KeptNote)]
    public Task<string> SetNativeOperand(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("The instruction: " + NativeTools.AddressDescription)] string address,
        [Description("Operand index, 0 for the first.")] int operand,
        [Description("hex, dec, oct, bin, char, offset, stack, enum, struct or default.")] string display,
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
    [Description("The named types of the decompiler engine's database (IDA local types, Ghidra data types: from the PDB, RTTI classes, Il2Cpp, the " +
                 "engine's type libraries and declare_native_types) with size and member count; members=true adds each type's first members. " +
                 "name= shows one type as a C declaration with its members' offsets.")]
    public Task<string> ListNativeTypes(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Name filter: " + NameFilter.Description + ".")] string? filter = null,
        [Description("struct, union, udt (either), enum, typedef, func or ptr (IDA).")] string? kind = null,
        [Description("Show this one type in full instead of a list.")] string? name = null,
        [Description("Index of the first row.")] int offset = 0,
        [Description("Max rows (default 200, max 5000).")] int limit = 200,
        [Description(EngineDescription)] string? engine = null,
        [Description("Order: the engine's (default), name or size.")] string? sort = null,
        [Description("Reverse the order.")] bool descending = false,
        [Description("List each type's first 32 members (enums: name = value).")] bool members = false,
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
        var (total, rows) = await NativeEngineQueries.Types(session, new NativeEngineQueries.TypeQuery(nameFilter, k, order, descending, members ? MemberRows : 0, offset, limit),
            cancellationToken);
        var text = new System.Text.StringBuilder($"{total} type(s)" + (nameFilter != null ? $" matching '{nameFilter.Text}'" : "") + (k != null ? $" of kind {k}" : "") +
                                                 (order != "ordinal" ? $" by {order}{(descending ? " descending" : "")}" : "") +
                                                 (rows.Count < total ? $"; rows {offset + 1}-{offset + rows.Count}" : "") + "\n");
        foreach (var t in rows)
        {
            text.AppendLine($"  {t.Kind} {t.Name}" + (t.Size >= 0 ? $"  {t.Size} bytes" : "") + (t.MemberCount > 0 ? $"  {t.MemberCount} members" : ""));
            foreach (var m in t.Members ?? [])
                text.AppendLine(t.Kind == "enum" ? $"      {m.Name} = {m.Offset}" : $"      +0x{m.Offset:X}  {m.Name}  {m.Type}  {m.Size}");
            if (t.Members is { } shown && t.MemberCount > shown.Count) text.AppendLine($"      ... {t.MemberCount - shown.Count} more (name={t.Name} lists them)");
        }
        if (offset + rows.Count < total) text.AppendLine($"More: offset={offset + rows.Count}");
        return text.ToString();
    });

    /// <summary>Members listed per type with members=true (the parameter text says 32).</summary>
    private const int MemberRows = 32;

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
    private static NativeUserTypeOutcome Outcome(UserTypeResult result)
    {
        var item = result.Items.Count == 1 ? result.Items[0] : throw new ToolError(ErrorCode.Failed, "The engine did not report the edit.");
        if (!item.Applied)
            throw new ToolError(ErrorCode.InvalidArgument, item.Error ?? "The engine did not apply the edit.",
                "check the spelling; list_native_types shows the engine's types and declare_native_types adds missing ones");
        return item;
    }
}
