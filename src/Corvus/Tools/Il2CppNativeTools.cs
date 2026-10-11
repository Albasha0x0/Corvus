using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Native.Code;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>Il2Cpp metadata names on a native game binary (GameAssembly.dll).</summary>
[McpServerToolType]
public sealed class Il2CppNativeTools(AssemblyWorkspace workspace, NativeCodeService code, Il2CppNativeNames names, Il2CppRawLoader? il2cppRaw = null)
{
    [McpServerTool(Name = "apply_il2cpp_names", Title = "Name a native Il2Cpp binary from its metadata")]
    [Description("Name the functions and data of a native Il2Cpp binary (GameAssembly, libil2cpp.so) from the loaded dummy assemblies, script.json (function starts, " +
                 "generic instantiations, TypeInfo and MethodInfo slots) and stringliteral.json. Functions become Ns_Type__Method (a C identifier; a duplicate " +
                 "gets _<RVA>), commented with Ns.Type::Method(args) and the methods sharing the code; every native tool and the engines show them, below user and " +
                 "PDB names. Saved per file hash and reapplied on load; applying again replaces them. Run it once the binary and the dummy assemblies are loaded.")]
    public Task<string> ApplyIl2CppNames(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Dummy assemblies to use; omit for every loaded one with Il2Cpp metadata.")] string? assembly = null,
        [Description("Remove the il2cpp names (and their saved copy) instead of applying them.")] bool clear = false,
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
            var removed = workspace.Read(() => names.Clear(native, index));
            return removed is { } n ? $"{native.Id}: removed {Plural(n, "il2cpp name")} and the saved copy." : $"{native.Id}: no il2cpp names were applied.";
        }
        string read = "";
        var report = await Task.Run(() =>
        {
            try { return workspace.Read(() => names.Apply(native, index, workspace.Scope(assembly), cancellationToken)); }
            catch (ToolError e) when (e.Code == ErrorCode.NotLoaded && assembly == null && Il2CppGame(native.FilePath, native.SliceName) is { } game)
            {
                // No dummy assemblies loaded: read the Il2Cpp metadata with the built-in reader first.
                var loaded = (il2cppRaw ?? new Il2CppRawLoader(workspace)).Load(game, loadBinary: false,
                    m => progress.Report(new ProgressNotificationValue { Progress = 0, Message = $"Il2Cpp: {m}" }), cancellationToken);
                read = Il2CppRawLoader.Describe(loaded) + Environment.NewLine + Environment.NewLine;
                return workspace.Read(() => names.Apply(native, index, workspace.Scope(null), cancellationToken));
            }
        }, cancellationToken);
        return read + Render(native.Id, report);
    });

    /// <summary>The game files around a game binary, when its metadata is found; null otherwise.</summary>
    private static Il2CppGameFiles? Il2CppGame(string binary, string? slice)
    {
        try { return Il2CppGameFiles.Find(binary, slice) is { } g && string.Equals(Path.GetFullPath(g.Binary), Path.GetFullPath(binary), StringComparison.OrdinalIgnoreCase) ? g : null; }
        catch (ToolError) { return null; }
    }

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
        if (!r.Notes.Any(n => n.StartsWith("names not saved", StringComparison.Ordinal)))
            sb.AppendLine("Saved with the image's annotations: reapplied automatically when this file is loaded again (clear=true removes them).");
        sb.AppendLine("Priority: user > pdb > il2cpp > discovered. find_method_by_address goes from an address back to the managed method.");
        return sb.ToString();
    }
}
