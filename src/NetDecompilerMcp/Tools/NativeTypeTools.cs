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
        return (native, rva, session);
    }

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
