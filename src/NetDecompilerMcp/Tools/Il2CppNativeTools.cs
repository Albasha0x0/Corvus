using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

/// <summary>Il2Cpp metadata names on a native game binary (GameAssembly.dll).</summary>
[McpServerToolType]
public sealed class Il2CppNativeTools(AssemblyWorkspace workspace, NativeCodeService code, Il2CppNativeNames names)
{
    [McpServerTool(Name = "apply_il2cpp_names", Title = "Name a native Il2Cpp binary from its metadata", OpenWorld = false)]
    [Description("Names the functions and data of a native Il2Cpp game binary (GameAssembly.dll) from the loaded Il2CppDumper / Cpp2IL dummy assemblies " +
                 "([Address] RVAs) and the dump's script.json (every function start, generic instantiations, Ns_Type_TypeInfo metadata and MethodInfo slots) " +
                 "and stringliteral.json (StringLiteral_<n> slots commented with the text). Functions are named Ns_Type__Method (the Il2CppDumper name " +
                 "Ns.Type$$Method as a C identifier, as IDA accepts it: '$$' becomes '__', '.', '<', '>', ',' and spaces '_'; a name used twice gets _<RVA>), commented with the C# form Ns.Type::Method(args) " +
                 "and the other methods sharing the code. The names show in list_functions, disassemble, find_xrefs, native_call_tree, search_native_strings, " +
                 "resolve_address and as addresses, and decompile_native pushes them into the IDA database. They rank below user names (rename_native) and " +
                 "PDB names; applying again replaces them, clear=true removes them. Not saved: apply again after a reload. Reports counts of functions named, " +
                 "shared code, strings, slots, collisions and misses. Explicit, not automatic: run it once both the binary and the dummy assemblies are loaded.")]
    public Task<string> ApplyIl2CppNames(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Dummy assemblies to use (id, name, file name or path); omit to use every loaded one with Il2Cpp metadata.")] string? assembly = null,
        [Description("Remove the il2cpp names instead of applying them.")] bool clear = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var native = await Task.Run(() =>
        {
            var id = workspace.Read(() => workspace.FindNative(image)?.Id);
            if (id == null && !string.IsNullOrWhiteSpace(image) && Path.IsPathFullyQualified(image.Trim()) && File.Exists(image.Trim()))
                id = workspace.LoadAny(image.Trim()).Native?.Id ?? throw new ToolError(ErrorCode.Unsupported, $"{image} is a .NET assembly, not a native image.",
                    "pass the game's GameAssembly.dll");
            return workspace.Read(() => workspace.GetNative(id ?? image));
        }, cancellationToken);
        var index = await code.Index(native, new Progress<CodeIndexProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = p.Done, Total = p.Total > 0 ? p.Total : null, Message = $"indexing {native.Id}: {p.Phase}" })), cancellationToken);
        if (clear)
        {
            var removed = workspace.Read(() => Il2CppNativeNames.Clear(native, index));
            return removed is { } n ? $"{native.Id}: removed {Plural(n, "il2cpp name")}." : $"{native.Id}: no il2cpp names were applied.";
        }
        var report = await Task.Run(() => workspace.Read(() => names.Apply(native, index, workspace.Scope(assembly), cancellationToken)), cancellationToken);
        return Render(native.Id, report);
    });

    internal static string Render(string id, Il2CppNativeNames.Report r)
    {
        var sb = new StringBuilder($"{id}: il2cpp names from {r.Assemblies}{(r.DumpDirectory != null ? $" (dump {r.DumpDirectory})" : "")} in {r.Elapsed.TotalSeconds:0.00} s\n");
        sb.AppendLine($"  functions named: {r.Functions}" + (r.FunctionsNotDiscovered > 0
            ? $" ({r.FunctionsNotDiscovered} at addresses the code index did not find as function starts: named as labels)" : ""));
        if (r.SharedFunctions > 0)
            sb.AppendLine($"  shared code: {Plural(r.SharedFunctions, "function")} hold {Plural(r.SharedExtraMethods, "more method")} (named after the first, the rest in the comment)");
        sb.AppendLine($"  string literals: {r.Strings}; metadata slots: {r.MetadataSlots}; MethodInfo slots: {r.MethodInfoSlots}" +
                      (r.HasScript ? "" : " (no script.json beside the dummy assemblies: only the dummy methods' addresses are known)"));
        sb.AppendLine($"  conflicts: {r.UserNamesKept} user name(s) kept over il2cpp names; {r.Suffixed} repeated name(s) suffixed with the RVA");
        sb.AppendLine($"  misses: {r.UnnamedStarts} function start(s) without a method, {r.OutsideImage} address(es) outside the image's sections");
        foreach (var note in r.Notes) sb.AppendLine($"  note: {note}");
        sb.AppendLine("Priority: user > pdb > il2cpp > discovered. find_method_by_address goes from an address back to the managed method.");
        return sb.ToString();
    }
}
