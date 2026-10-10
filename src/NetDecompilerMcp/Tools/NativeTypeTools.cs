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
/// The user's types in the decompiler engine: prototypes and global types. Every edit is kept in the image's annotation
/// sidecar (re-applied to a new database, exported, carried to new builds).
/// </summary>
[McpServerToolType]
public sealed class NativeTypeTools(AssemblyWorkspace workspace, NativeEngineService engines, NativeUserTypePush userTypes, NativeCodeService? code = null,
    NativeNamePush? names = null, NativeTypePush? types = null)
{
    private const string EngineDescription = "Engine: auto (default) or ida.";

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
    [Description("The stack frame of a native function as IDA has it (members with offsets, names, types and sizes: locals, arguments, return " +
                 "address and saved registers) and its Hex-Rays locals (name, type, register or stack offset, argument, user-named / user-typed). " +
                 "Offsets count from the frame's lowest address; the base-relative offset IDA's var_/arg_ names use is in brackets. " +
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
        var sb = new System.Text.StringBuilder($"Frame of {f.Name} at {Va(native, f.StartRva)}: {f.LocalSize} bytes of locals, {f.SavedRegisters} of saved registers; " +
                                               $"return address at +0x{f.ReturnAddressOffset:X}\n");
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

    [McpServerTool(Name = "set_native_stack_var", Title = "Rename or retype a stack variable")]
    [Description("Rename and/or retype a member of a native function's stack frame in IDA, named as get_native_frame lists it (var_28) or by " +
                 "frame offset (0x20 or +0x20, from the frame's lowest address); a type at an offset with no member creates one. The return address " +
                 "and saved registers are refused. Stack variables the decompiler has not renamed take the member's name." + KeptNote)]
    public Task<string> SetNativeStackVar(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("The function: " + NativeTools.AddressDescription)] string function,
        [Description("The member: its name, or its frame offset (hex).")] string variable,
        [Description("New name (a C identifier).")] string? newName = null,
        [Description("New C type, e.g. 'int', 'char[16]', 'Packet'.")] string? type = null,
        [Description(EngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var name = string.IsNullOrWhiteSpace(newName) ? null : newName.Trim();
        var decl = string.IsNullOrWhiteSpace(type) ? null : type.Trim();
        if (name == null && decl == null) throw new ToolError(ErrorCode.InvalidArgument, "Nothing to change.", "pass newName, type or both");
        if (name != null && !Identifier(name))
            throw new ToolError(ErrorCode.InvalidArgument, $"'{name}' is not a C identifier.", "use letters, digits and _, not starting with a digit");
        var (native, rva, session) = await Open(image, function, engine, progress, cancellationToken);
        var frame = await session.GetFrameAsync(rva, cancellationToken);
        var v = (variable ?? "").Trim();
        int offset = frame.Members.FirstOrDefault(m => m.Name == v) is { } byName ? byName.Offset
            : NativeAddress.Number(v.TrimStart('+')) is { } n && n <= int.MaxValue ? (int)n
            : throw new ToolError(ErrorCode.InvalidArgument, $"The frame of {frame.Name} has no member '{v}'.",
                $"members: {string.Join(", ", frame.Members.Select(m => m.Name).Take(40))}; or pass a frame offset such as 0x20");
        var result = await userTypes.ApplyAsync(native, session, new NativeUserTypeBatch([], [], [new NativeStackVarEdit(frame.StartRva, offset, name, decl)], []),
            (r, layer) => r.Items is [{ Applied: true } item] ? layer.WithStackVar(new NativeStackVarEdit(item.Rva, offset, name, decl)) : null, cancellationToken);
        var done = Outcome(result);
        return $"Stack member +0x{offset:X} of {frame.Name} at {Va(native, done.Rva)}{(done.Resolved != null ? $" (was {done.Resolved})" : "")} is now: {done.Text}";
    });

    private static string Va(LoadedNative native, uint rva) => NativeAddress.Va(native.Image, rva);

    [McpServerTool(Name = "set_native_type", Title = "Set a native prototype or global type")]
    [Description("Set the type of a native function (its prototype, e.g. 'int __fastcall Parse(Packet *p, int len)') or of a global (e.g. " +
                 "'Config', 'char[64]', 'Handler *[8]') in the decompiler engine (IDA). Named types must exist there (the PDB, RTTI and Il2Cpp types " +
                 "decompile_native pushes). User types win over recovered ones. An empty type clears it." + KeptNote)]
    public Task<string> SetNativeType(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("A function start or a global: " + NativeTools.AddressDescription)] string address,
        [Description("C prototype for a function, C type for a global; empty to clear the user type.")] string type,
        [Description(EngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, rva, session) = await Open(image, address, engine, progress, cancellationToken);
        var decl = (type ?? "").Trim();
        var result = await userTypes.ApplyAsync(native, session, new NativeUserTypeBatch([], [new NativePrototype(rva, decl)], [], []),
            (r, layer) => r.Items is [{ Applied: true }] ? layer.WithType(rva, decl) : null, cancellationToken);
        var item = Outcome(result);
        return decl.Length == 0 ? $"Cleared the user type at {Va(native, rva)}." : $"Type at {Va(native, rva)}: {item.Text ?? decl}";
    });

    [McpServerTool(Name = "set_native_local", Title = "Rename or retype a decompiler local")]
    [Description("Rename and/or retype a local variable or argument in the pseudocode of a native function (IDA Hex-Rays): name it as " +
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
                "check the spelling; types it names must exist in the engine");
        return item;
    }
}
