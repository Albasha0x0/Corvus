using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Msvc;
using Corvus.Native.Pe;
using Corvus.Native.Providers;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>Native analysis built on the PE model: C++ classes, P/Invoke checks; decompile_native is in NativeDecompileTools.cs.</summary>
[McpServerToolType]
public sealed partial class NativeAnalysisTools(AssemblyWorkspace workspace, NativeEngineService engines, OutputPager pager, NativeNamePush? names = null,
    NativeCodeService? code = null, NativeTypePush? types = null, NativeUserTypePush? userTypes = null, NotesService? notes = null)
{
    /// <summary>The native image named by id or path (loaded by path when needed).</summary>
    internal static LoadedNative ResolveImage(AssemblyWorkspace workspace, string image)
    {
        return Targets.Native(workspace, image);
    }

    private (LoadedNative Native, uint Rva) Resolve(string image, string address) => Resolve(workspace, code, image, address);

    /// <summary>The native image (loaded by path when needed) and an address in it; names resolve through the code index when it is ready.</summary>
    internal static (LoadedNative Native, uint Rva) Resolve(AssemblyWorkspace workspace, NativeCodeService? code, string image, string address)
    {
        var native = ResolveImage(workspace, image);
        return (native, workspace.Read(() => NativeAddress.Parse(native.Image, address, code?.Ready(native) is { } index ? index.AddressesOfName : null)));
    }

    [McpServerTool(Name = "list_cpp_classes", Title = "C++ classes from RTTI")]
    [Description("C++ classes recovered from RTTI (MSVC on PE, Itanium on ELF / Mach-O): demangled names, base classes (offsets, virtual and multiple " +
                 "inheritance) and vftables with slot targets; rejects are counted with the reason. Mach-O: also ObjC classes, categories, protocols and Swift types. engine=ghidra lists Ghidra's class namespaces " +
                 "instead (PDB classes too), ida its C++ structs.")]
    public async Task<string> ListCppClasses(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Name substring (case-insensitive).")] string? filter = null,
        [Description("Include each vftable's slot addresses.")] bool slots = false,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        [Description("auto or ours (default: RTTI), ida or ghidra.")] string? engine = null,
        [Description("engine=ghidra: plain namespaces and libraries too.")] bool namespaces = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default)
    {
        var mode = EngineModes.Resolve(engine, EngineMode.Auto);
        if (mode == EngineMode.Ida)
            return await OrderedProgress.Run(context, progress => IdaClasses(image, filter, offset, maxTokens, progress, cancellationToken));
        if (mode == EngineMode.Ghidra)
            return await OrderedProgress.Run(context, progress => EngineClasses(image, filter, namespaces, offset, maxTokens, progress, cancellationToken));
        return await Task.Run(() => RttiClasses(image, filter, slots, offset, maxTokens, cancellationToken), cancellationToken);
    }

    /// <summary>Ghidra's class namespaces (and with <paramref name="all"/> its other namespaces), sorted by name.</summary>
    private async Task<string> EngineClasses(string image, string? filter, bool all, int offset, int? maxTokens, IProgress<ProgressNotificationValue> progress,
        CancellationToken ct)
    {
        var native = await Task.Run(() => ResolveImage(workspace, image), ct);
        var session = await engines.Session(native, Native.Providers.Ghidra.GhidraProvider.ProviderId, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = $"Ghidra {p.Stage}" })), ct);
        if (names != null) await names.EnsureAsync(native, session, ct);
        var list = await session.ListNamespacesAsync(ct);
        var shown = list.Where(n => (all || n.Kind == "class") && (filter == null || n.Name.Contains(filter, StringComparison.OrdinalIgnoreCase))).ToList();
        var sb = new StringBuilder($"{native.Id}: {Plural(list.Count(n => n.Kind == "class"), "class")} in Ghidra's namespaces" +
                                   (all ? $", {Plural(list.Count(n => n.Kind == "namespace"), "namespace")}, {Plural(list.Count(n => n.Kind == "library"), "library")}" : "") +
                                   (filter != null ? $"; {shown.Count} match '{filter}'" : "") + "\nEngine: ghidra\n");
        foreach (var n in shown)
            sb.AppendLine($"{n.Kind} {n.Name}  ({Plural(n.Functions, "function")})" + (n.Vftable is { } v ? $"  vftable {NativeAddress.Va(native.Image, v)}" : ""));
        return pager.Page(sb.ToString(), offset, maxTokens);
    }

    /// <summary>IDA's C++ structs (C++ objects, base classes or a vftable pointer) with their bases, vftable and Class:: functions.</summary>
    private async Task<string> IdaClasses(string image, string? filter, int offset, int? maxTokens, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var native = await Task.Run(() => ResolveImage(workspace, image), ct);
        var session = await engines.Session(native, Native.Providers.Ida.IdaProvider.ProviderId, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = $"IDA {p.Stage}" })), ct);
        if (names != null) await names.EnsureAsync(native, session, ct);
        if (types != null) await types.EnsureAsync(native, session, ct);
        if (session is not Native.Providers.Ida.IdaSession ida) throw new ToolError(ErrorCode.Unsupported, "engine=ida needs an IDA session.");
        var rows = (await ida.CallAsync("classes", Native.Providers.Ida.IdaProvider.Args(), ct)).GetProperty("rows").EnumerateArray().ToList();
        var shown = rows.Where(r => filter == null || (r[0].GetString() ?? "").Contains(filter, StringComparison.OrdinalIgnoreCase))
            .OrderBy(r => r[0].GetString(), StringComparer.Ordinal).ToList();
        var sb = new StringBuilder($"{native.Id}: {Plural(rows.Count, "class")} in IDA's local types" + (filter != null ? $"; {shown.Count} match '{filter}'" : "") + "\nEngine: ida\n");
        foreach (var r in shown)
        {
            var bases = r[4].EnumerateArray().Select(b => $"{(b[2].GetBoolean() ? "virtual " : "")}{b[0].GetString()}{(b[1].GetInt64() != 0 ? $" @+0x{b[1].GetInt64():X}" : "")}").ToList();
            sb.Append($"class {r[0].GetString()}" + (bases.Count > 0 ? " : " + string.Join(", ", bases) : "") + (r[1].GetInt64() > 0 ? $"  {r[1].GetInt64()} bytes" : "") +
                      $"  ({Plural(r[5].GetInt32(), "function")})");
            if (r[2].ValueKind == System.Text.Json.JsonValueKind.Number) sb.Append($"  vftable {NativeAddress.Va(native.Image, r[2].GetUInt32())} ({Plural(r[3].GetInt32(), "slot")})");
            else if (r[3].GetInt32() > 0) sb.Append($"  vftable type with {Plural(r[3].GetInt32(), "slot")}");
            sb.AppendLine();
        }
        return pager.Page(sb.ToString(), offset, maxTokens);
    }

    private string RttiClasses(string image, string? filter, bool slots, int offset, int? maxTokens, CancellationToken cancellationToken)
    {
        var (native, _) = Resolve(image, "rva:0");
        var result = native.GetAnalysis(n => Native.Itanium.CppRtti.Analyze(n.Image, cancellationToken));
        var pe = native.Image;
        // slot targets are named from the code index, built for this when it is not yet
        var index = !slots || code == null ? null : code.Ready(native) ?? code.Index(native, null, cancellationToken).GetAwaiter().GetResult();
        var classes = result.Classes.Where(c => filter == null || c.Name.Contains(filter, StringComparison.OrdinalIgnoreCase)).ToList();
        var sb = new StringBuilder($"{native.Id}: {Plural(result.Classes.Count, "class")} with RTTI, {Plural(result.Stats.Vtables, "vftable")}, " +
                                   $"{Plural(result.TypeDescriptors.Count, pe.Format == ImageFormat.Pe ? "type descriptor" : "typeinfo")}" +
                                   (filter != null ? $"; {classes.Count} match '{filter}'" : "") + "\n");
        foreach (var note in result.Notes) sb.AppendLine($"Note: {note}");
        if (result.Stats.TypeDescriptorCandidatesRejected + result.Stats.LocatorCandidatesRejected > 0)
            sb.AppendLine(pe.Format == ImageFormat.Pe
                ? $"Rejected candidates: {result.Stats.TypeDescriptorCandidatesRejected} type descriptors, {result.Stats.LocatorCandidatesRejected} locators (failed cross-checks)"
                : $"Rejected candidates: {result.Stats.TypeDescriptorCandidatesRejected} typeinfos (unreadable name or bases)");
        foreach (var c in classes)
        {
            sb.Append($"{c.Kind} {c.Name}");
            var direct = c.Bases.Where(b => b.Depth == 1).ToList();
            if (direct.Count > 0)
                sb.Append(" : " + string.Join(", ", direct.Select(b => $"{(b.IsVirtual ? "virtual " : "")}{b.Name}{(b.IsVirtual ? "" : b.Mdisp != 0 ? $" @+0x{b.Mdisp:X}" : "")}")));
            if ((c.Attributes & MsvcHierarchyAttributes.Ambiguous) != 0) sb.Append("  [ambiguous bases]");
            sb.AppendLine();
            foreach (var v in c.Vtables)
            {
                sb.AppendLine($"  vftable {NativeAddress.Va(pe, v.VftableRva)} for subobject +0x{v.Offset:X}: {Plural(v.SlotRvas.Count, "slot")}");
                if (slots)
                    for (int i = 0; i < v.SlotRvas.Count; i++)
                        sb.AppendLine($"    [{i}] {(v.SlotRvas[i] == 0 ? "(import)" : NativeAddress.Va(pe, v.SlotRvas[i]))}" +
                                      (v.SlotRvas[i] != 0 && index?.NameAt(v.SlotRvas[i]) is { } name ? "  " + name : ""));
            }
            foreach (var issue in c.Issues) sb.AppendLine($"  issue: {issue}");
        }
        if (pe.Format == ImageFormat.MachO)
            foreach (var line in AppleNames.ClassLines(native, filter, slots, rva => index?.NameAt(rva) is { } n ? NativeTools.DisplayName(n, ImageFormat.MachO) : null, cancellationToken)) sb.AppendLine(line);
        return pager.Page(sb.ToString(), offset, maxTokens);
    }

    public sealed record VerdictCount(string Status, string Reason, int Count);

    public sealed record NativeImportReport(
        string Assembly,
        [property: Description("P/Invoke declarations checked.")] int Declarations,
        [property: Description("Declarations per verdict and reason.")] IReadOnlyList<VerdictCount> Counts,
        [property: Description("The status or reason filter applied, or null.")] string? Filter,
        int Offset,
        [property: Description("Declarations matching the filter.")] int Total,
        bool Truncated,
        [property: Description("Contradicted, unresolved and dynamic_only first, then not_checked and verified.")] IReadOnlyList<NativeImportVerifier.Check> Items,
        [property: Description("Run-time native loading found in the IL (first 100).")] IReadOnlyList<DynamicNativeLoad> DynamicLoads,
        int DynamicLoadsTotal,
        [property: Description("Malformed metadata found while reading the declarations, with locations.")] IReadOnlyList<MetadataIssue> MetadataIssues,
        IReadOnlyList<string> Notes);

    [McpServerTool(Name = "verify_native_imports", Title = "Verify P/Invoke imports", UseStructuredContent = true)]
    [Description("Check a .NET assembly's P/Invoke declarations ([DllImport]) against the exports of their libraries, with the " +
                 "runtime's lookup rules: DLL search order, API sets, A/W suffixes, stdcall decoration, ordinals and forwarders; for Linux/macOS/" +
                 "Android/iOS targets (platform=, or detected) .so/.dylib probing along the RID chain and __Internal in an Il2Cpp binary. Verdict " +
                 "per declaration with a reason code: verified, contradicted (e.g. missing_export, arch_mismatch), unresolved (e.g. dll_not_found " +
                 "with places searched), dynamic_only (loaded by the assembly itself), not_checked (runtime-internal). Run-time loading " +
                 "found in the IL is listed too.")]
    public Task<NativeImportReport> VerifyNativeImports(
        [Description(AssemblyDescription)] string assembly,
        [Description("Only declarations with this status or reason code (e.g. contradicted, missing_export).")] string? status = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Max rows (max 5000).")] int limit = 500,
        [Description("Target platform (default auto).")] string? platform = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, progress => Task.Run(() =>
    {
        var asm = workspace.Read(() => workspace.Get(assembly), cancellationToken);
        // Outside the lock: the verifier takes it in short sections.
        var result = new NativeImportVerifier(path => NativeImageLoader.Open(path)).Verify(asm, cancellationToken, platform, workspace,
            (done, total, status) => Report(progress, done, total, status));
        var checks = result.Checks;
        var filter = string.IsNullOrWhiteSpace(status) ? null : status.Trim().ToLowerInvariant();
        offset = Math.Max(0, offset);
        limit = ClampLimit(limit);
        var selected = checks.Where(c => filter == null || c.Status == filter || c.Reason == filter)
            .OrderBy(c => c.Status switch { NativeImportVerifier.Contradicted => 0, NativeImportVerifier.Unresolved => 1, NativeImportVerifier.DynamicOnly => 2,
                NativeImportVerifier.NotChecked => 3, _ => 4 })
            .ThenBy(c => c.Module, StringComparer.OrdinalIgnoreCase).ThenBy(c => c.EntryPoint, StringComparer.Ordinal).ToList();
        var counts = checks.GroupBy(c => (c.Status, c.Reason)).OrderBy(g => Array.IndexOf(NativeImportVerifier.Statuses, g.Key.Status)).ThenBy(g => g.Key.Reason)
            .Select(g => new VerdictCount(g.Key.Status, g.Key.Reason, g.Count())).ToList();

        var notes = new List<string>();
        if (checks.Count == 0) notes.Add($"{asm.Id} declares no P/Invoke methods.");
        if (filter != null && !NativeImportVerifier.Statuses.Contains(filter) && selected.Count == 0 && checks.Count > 0)
            notes.Add($"No declaration has status or reason '{filter}'.");
        notes.Add("A declaration that is unresolved or contradicted statically does not rule out dynamic loading: native code can also be loaded at run " +
                  "time (NativeLibrary.Load/GetExport, LoadLibrary/GetProcAddress, a DllImportResolver), by this assembly (dynamicLoads lists what its IL does) " +
                  "or by another one in the process.");
        if (result.DynamicTruncated) notes.Add("dynamicLoads stopped at 2000 call sites.");
        if (!result.Platform.IsWindows || result.Platform.Source != "default")
            notes.Add($"Target platform: {result.Platform.Os}{(result.Platform.Rid != null ? $" ({result.Platform.Rid})" : "")}, from {result.Platform.Source}.");
        if (!OperatingSystem.IsWindows() && result.Platform.IsWindows)
            notes.Add("This host has no Windows system DLLs: DLLs next to the assembly are checked (exports, ordinals, forwarders); declarations bound to " +
                      "system DLLs are unresolved (system_dll_not_on_host).");
        return new NativeImportReport(asm.Id, checks.Count, counts, filter, offset, selected.Count, offset + limit < selected.Count,
            selected.Skip(offset).Take(limit).ToList(), result.DynamicLoads.Take(100).ToList(), result.DynamicLoads.Count, result.MetadataIssues, notes);
    }, cancellationToken));
}
