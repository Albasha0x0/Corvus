using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native.Code;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>Il2Cpp metadata names on a native binary (GameAssembly.dll).</summary>
[McpServerToolType]
public sealed class Il2CppNativeTools(AssemblyWorkspace workspace, NativeCodeService code, Il2CppNativeNames names, Il2CppRawLoader? il2cppRaw = null)
{
    [McpServerTool(Name = "apply_il2cpp_names", Title = "Name a native Il2Cpp binary from its metadata", UseStructuredContent = true, OutputSchemaType = typeof(Il2CppNamesResult))]
    [Description("Name the functions and data of a native Il2Cpp binary (GameAssembly, libil2cpp.so) from the loaded dummy assemblies, script.json " +
                 "and stringliteral.json: Ns_Type__Method (duplicates get _<RVA>), commented with Ns.Type::Method(args) and methods sharing the code; " +
                 "below user and PDB names. Saved per file hash, reapplied on load.")]
    public Task<string> ApplyIl2CppNames(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Dummy assemblies to use; omit for every loaded one with Il2Cpp metadata.")] string? assembly = null,
        [Description("Remove the il2cpp names and saved copy instead.")] bool clear = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var native = await Task.Run(() => Targets.Native(workspace, image), cancellationToken);
        var index = await code.Index(native, new Progress<CodeIndexProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = p.Done, Total = p.Total > 0 ? p.Total : null, Message = $"indexing {native.Id}: {p.Phase}" })), cancellationToken);
        if (clear)
        {
            var removed = workspace.Read(() => names.Clear(native, index));
            return ToolOutput.With(removed is { } n ? $"{native.Id}: removed {Plural(n, "il2cpp name")} and the saved copy." : $"{native.Id}: no il2cpp names were applied.",
                new Il2CppNamesResult(native.Id, removed != null) { Removed = removed ?? 0, ElapsedMs = clock.ElapsedMilliseconds });
        }
        string read = "";
        var report = await Task.Run(() =>
        {
            try { return workspace.Read(() => names.Apply(native, index, workspace.Scope(assembly), cancellationToken)); }
            catch (ToolError e) when (e.Code == ErrorCode.NotLoaded && assembly == null && Il2CppBuild(native.FilePath, native.SliceName) is { } build)
            {
                // No dummy assemblies loaded: read the Il2Cpp metadata with the built-in reader first.
                var loaded = (il2cppRaw ?? new Il2CppRawLoader(workspace)).Load(build, loadBinary: false,
                    m => progress.Report(new ProgressNotificationValue { Progress = 0, Message = $"Il2Cpp: {m}" }), cancellationToken);
                read = Il2CppRawLoader.Describe(loaded) + Environment.NewLine + Environment.NewLine;
                return workspace.Read(() => names.Apply(native, index, workspace.Scope(null), cancellationToken));
            }
        }, cancellationToken);
        return ToolOutput.With(read + Render(native.Id, report), Outcome(native.Id, report) with { ElapsedMs = clock.ElapsedMilliseconds });
    });

    /// <summary>The Il2Cpp files around a binary, when its metadata is found; null otherwise.</summary>
    private static Il2CppBuildFiles? Il2CppBuild(string binary, string? slice)
    {
        try { return Il2CppBuildFiles.Find(binary, slice) is { } g && string.Equals(Path.GetFullPath(g.Binary), Path.GetFullPath(binary), StringComparison.OrdinalIgnoreCase) ? g : null; }
        catch (ToolError) { return null; }
    }

    internal static Il2CppNamesResult Outcome(string id, Il2CppNativeNames.Report r) => new(id, true)
    {
        Assemblies = r.Assemblies, Functions = r.Functions, Labels = r.FunctionsNotDiscovered, SharedFunctions = r.SharedFunctions, Strings = r.Strings,
        MetadataSlots = r.MetadataSlots, MethodInfoSlots = r.MethodInfoSlots, UserNamesKept = r.UserNamesKept, Suffixed = r.Suffixed,
        Misses = r.UnnamedStarts + r.OutsideImage, Saved = !r.Notes.Any(n => n.StartsWith("names not saved", StringComparison.Ordinal)), Notes = r.Notes,
    };

    /// <summary>The report; timings go to _meta through the record.</summary>
    internal static string Render(string id, Il2CppNativeNames.Report r)
    {
        var sb = new StringBuilder($"{id}: il2cpp names from {r.Assemblies}{(r.DumpDirectory != null ? $" (from {r.DumpDirectory})" : "")}\n");
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

/// <summary>apply_il2cpp_names: what was named (or, with clear, removed).</summary>
public sealed record Il2CppNamesResult(string Image, bool Applied)
{
    public string? Assemblies { get; init; }
    public int Functions { get; init; }
    [Description("Named at addresses the code index did not find as function starts.")] public int Labels { get; init; }
    [Description("Functions holding more than one method (the rest named in the comment).")] public int SharedFunctions { get; init; }
    public int Strings { get; init; }
    public int MetadataSlots { get; init; }
    public int MethodInfoSlots { get; init; }
    [Description("User names kept over il2cpp names.")] public int UserNamesKept { get; init; }
    [Description("Repeated names suffixed with the RVA.")] public int Suffixed { get; init; }
    [Description("Function starts without a method, and addresses outside the image's sections.")] public int Misses { get; init; }
    [Description("Saved with the image's annotations and reapplied on load.")] public bool Saved { get; init; }
    [Description("clear=true: names removed.")] public int Removed { get; init; }
    public long ElapsedMs { get; init; }
    public IReadOnlyList<string>? Notes { get; init; }
}
