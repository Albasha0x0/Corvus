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

    /// <summary>A vftable of a class: where it is, the subobject it serves and its slots.</summary>
    public sealed record CppVftable(string Address, [property: Description("Subobject offset.")] int Offset, int Slots,
        [property: Description("slots=true: the slot targets (VA; 0 for an import).")] IReadOnlyList<string>? Targets);

    /// <summary>A class of list_cpp_classes.</summary>
    public sealed record CppClass(
        [property: Description("class or struct (RTTI), an engine's kind, or objc / swift lines on Mach-O.")] string Kind,
        string Name,
        [property: Description("Direct bases: virtual, name, @+offset.")] IReadOnlyList<string>? Bases,
        IReadOnlyList<CppVftable>? Vftables,
        [property: Description("Engine: functions in the class namespace.")] int? Functions,
        IReadOnlyList<string>? Issues);

    public sealed record CppClassList(string Image,
        [property: Description("rtti, ida or ghidra.")] string Source,
        IReadOnlyList<CppClass> Items, int Offset, int Total, IReadOnlyList<string> Notes);

    [McpServerTool(Name = "list_cpp_classes", Title = "C++ classes from RTTI", UseStructuredContent = true, OutputSchemaType = typeof(CppClassList))]
    [Description("C++ classes recovered from RTTI (MSVC on PE, Itanium on ELF / Mach-O): demangled names, bases (offsets, virtual and multiple " +
                 "inheritance), vftables with slot targets; rejects counted by reason. Mach-O: also ObjC classes, categories, protocols, Swift " +
                 "types. engine=ghidra: Ghidra's class namespaces (PDB too); ida: its C++ structs.")]
    public async Task<string> ListCppClasses(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Name substring (case-insensitive).")] string? filter = null,
        [Description("Include each vftable's slot addresses.")] bool slots = false,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Max classes (default 100).")] int limit = 100,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        [Description("auto or ours (default: RTTI), ida or ghidra.")] string? engine = null,
        [Description("engine=ghidra: plain namespaces and libraries too.")] bool namespaces = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default)
    {
        var mode = EngineModes.Resolve(engine, EngineMode.Auto);
        offset = Math.Max(0, offset);
        limit = ClampLimit(limit);
        if (mode == EngineMode.Ida)
            return await OrderedProgress.Run(context, progress => IdaClasses(image, filter, offset, limit, progress, cancellationToken));
        if (mode == EngineMode.Ghidra)
            return await OrderedProgress.Run(context, progress => EngineClasses(image, filter, namespaces, offset, limit, progress, cancellationToken));
        return await Task.Run(() => RttiClasses(image, filter, slots, offset, limit, cancellationToken), cancellationToken);
    }

    /// <summary>A page of class rows: (record, text) pairs in order.</summary>
    private static string ClassPage(string image, string source, List<(CppClass Class, string Text)> rows, int offset, int limit, string head, List<string> notes) =>
        ToolOutput.List(rows.Skip(offset).Take(limit).ToList(), offset, limit, rows.Count, r => r.Text,
            page => new CppClassList(image, source, page.Select(r => r.Class).ToList(), offset, rows.Count, notes), "class", head);

    /// <summary>Ghidra's class namespaces (and with <paramref name="all"/> its other namespaces), sorted by name.</summary>
    private async Task<string> EngineClasses(string image, string? filter, bool all, int offset, int limit, IProgress<ProgressNotificationValue> progress,
        CancellationToken ct)
    {
        var native = await Task.Run(() => ResolveImage(workspace, image), ct);
        var session = await engines.Session(native, Native.Providers.Ghidra.GhidraProvider.ProviderId, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = $"Ghidra {p.Stage}" })), ct);
        if (names != null) await names.EnsureAsync(native, session, ct);
        var list = await session.ListNamespacesAsync(ct);
        var shown = list.Where(n => (all || n.Kind == "class") && (filter == null || n.Name.Contains(filter, StringComparison.OrdinalIgnoreCase))).ToList();
        var head = $"{native.Id}: {Plural(list.Count(n => n.Kind == "class"), "class")} in Ghidra's namespaces" +
                   (all ? $", {Plural(list.Count(n => n.Kind == "namespace"), "namespace")}, {Plural(list.Count(n => n.Kind == "library"), "library")}" : "") +
                   (filter != null ? $"; {shown.Count} match '{filter}'" : "") + "\nEngine: ghidra\n";
        var rows = shown.Select(n => (new CppClass(n.Kind, n.Name, null,
                n.Vftable is { } v ? [new CppVftable(NativeAddress.Va(native.Image, v), 0, 0, null)] : null, n.Functions, null),
            $"{n.Kind} {n.Name}  ({Plural(n.Functions, "function")})" + (n.Vftable is { } vt ? $"  vftable {NativeAddress.Va(native.Image, vt)}" : ""))).ToList();
        return ClassPage(native.Id, "ghidra", rows, offset, limit, head, []);
    }

    /// <summary>IDA's C++ structs (C++ objects, base classes or a vftable pointer) with their bases, vftable and Class:: functions.</summary>
    private async Task<string> IdaClasses(string image, string? filter, int offset, int limit, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
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
        var head = $"{native.Id}: {Plural(rows.Count, "class")} in IDA's local types" + (filter != null ? $"; {shown.Count} match '{filter}'" : "") + "\nEngine: ida\n";
        var classes = new List<(CppClass, string)>();
        foreach (var r in shown)
        {
            var bases = r[4].EnumerateArray().Select(b => $"{(b[2].GetBoolean() ? "virtual " : "")}{b[0].GetString()}{(b[1].GetInt64() != 0 ? $" @+0x{b[1].GetInt64():X}" : "")}").ToList();
            var sb = new StringBuilder($"class {r[0].GetString()}" + (bases.Count > 0 ? " : " + string.Join(", ", bases) : "") + (r[1].GetInt64() > 0 ? $"  {r[1].GetInt64()} bytes" : "") +
                                       $"  ({Plural(r[5].GetInt32(), "function")})");
            CppVftable? vft = null;
            if (r[2].ValueKind == System.Text.Json.JsonValueKind.Number)
            {
                vft = new CppVftable(NativeAddress.Va(native.Image, r[2].GetUInt32()), 0, r[3].GetInt32(), null);
                sb.Append($"  vftable {vft.Address} ({Plural(r[3].GetInt32(), "slot")})");
            }
            else if (r[3].GetInt32() > 0) sb.Append($"  vftable type with {Plural(r[3].GetInt32(), "slot")}");
            classes.Add((new CppClass("class", r[0].GetString() ?? "", bases.Count > 0 ? bases : null, vft != null ? [vft] : null, r[5].GetInt32(), null), sb.ToString()));
        }
        return ClassPage(native.Id, "ida", classes, offset, limit, head, []);
    }

    private string RttiClasses(string image, string? filter, bool slots, int offset, int limit, CancellationToken cancellationToken)
    {
        var (native, _) = Resolve(image, "rva:0");
        var result = native.GetAnalysis(n => Native.Itanium.CppRtti.Analyze(n.Image, cancellationToken));
        var pe = native.Image;
        // slot targets are named from the code index, built for this when it is not yet
        var index = !slots || code == null ? null : code.Ready(native) ?? code.Index(native, null, cancellationToken).GetAwaiter().GetResult();
        var classes = result.Classes.Where(c => filter == null || c.Name.Contains(filter, StringComparison.OrdinalIgnoreCase)).ToList();
        var head = $"{native.Id}: {Plural(result.Classes.Count, "class")} with RTTI, {Plural(result.Stats.Vtables, "vftable")}, " +
                   $"{Plural(result.TypeDescriptors.Count, pe.Format == ImageFormat.Pe ? "type descriptor" : "typeinfo")}" +
                   (filter != null ? $"; {classes.Count} match '{filter}'" : "") + "\n";
        var notes = result.Notes.ToList();
        if (result.Stats.TypeDescriptorCandidatesRejected + result.Stats.LocatorCandidatesRejected > 0)
            notes.Add(pe.Format == ImageFormat.Pe
                ? $"Rejected candidates: {result.Stats.TypeDescriptorCandidatesRejected} type descriptors, {result.Stats.LocatorCandidatesRejected} locators (failed cross-checks)"
                : $"Rejected candidates: {result.Stats.TypeDescriptorCandidatesRejected} typeinfos (unreadable name or bases)");
        head += string.Concat(notes.Select(n => $"Note: {n}\n"));
        var rows = new List<(CppClass, string)>();
        foreach (var c in classes)
        {
            var sb = new StringBuilder($"{c.Kind} {c.Name}");
            var direct = c.Bases.Where(b => b.Depth == 1).Select(b => $"{(b.IsVirtual ? "virtual " : "")}{b.Name}{(b.IsVirtual ? "" : b.Mdisp != 0 ? $" @+0x{b.Mdisp:X}" : "")}").ToList();
            if (direct.Count > 0) sb.Append(" : " + string.Join(", ", direct));
            if ((c.Attributes & MsvcHierarchyAttributes.Ambiguous) != 0) sb.Append("  [ambiguous bases]");
            var vftables = new List<CppVftable>();
            foreach (var v in c.Vtables)
            {
                sb.Append($"\n  vftable {NativeAddress.Va(pe, v.VftableRva)} for subobject +0x{v.Offset:X}: {Plural(v.SlotRvas.Count, "slot")}");
                if (slots)
                    for (int i = 0; i < v.SlotRvas.Count; i++)
                        sb.Append($"\n    [{i}] {(v.SlotRvas[i] == 0 ? "(import)" : NativeAddress.Va(pe, v.SlotRvas[i]))}" +
                                  (v.SlotRvas[i] != 0 && index?.NameAt(v.SlotRvas[i]) is { } name ? "  " + name : ""));
                vftables.Add(new CppVftable(NativeAddress.Va(pe, v.VftableRva), (int)v.Offset, v.SlotRvas.Count,
                    slots ? v.SlotRvas.Select(s => s == 0 ? "0" : NativeAddress.Va(pe, s)).ToList() : null));
            }
            foreach (var issue in c.Issues) sb.Append($"\n  issue: {issue}");
            rows.Add((new CppClass(c.Kind, c.Name, direct.Count > 0 ? direct : null, vftables.Count > 0 ? vftables : null, null, c.Issues.Count > 0 ? c.Issues.ToList() : null),
                sb.ToString()));
        }
        if (pe.Format == ImageFormat.MachO)
            foreach (var line in AppleNames.ClassLines(native, filter, slots, rva => index?.NameAt(rva) is { } n ? NativeTools.DisplayName(n, ImageFormat.MachO) : null, cancellationToken))
                rows.Add((new CppClass(line.TrimStart().StartsWith("swift", StringComparison.OrdinalIgnoreCase) ? "swift" : "objc", line.Trim(), null, null, null, null), line));
        return ClassPage(native.Id, "rtti", rows, offset, limit, head, notes);
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
        [property: Description("Run-time native loading found in the IL (first 20).")] IReadOnlyList<DynamicNativeLoad> DynamicLoads,
        int DynamicLoadsTotal,
        [property: Description("Malformed metadata found while reading the declarations, with locations.")] IReadOnlyList<MetadataIssue> MetadataIssues,
        IReadOnlyList<string> Notes);

    [McpServerTool(Name = "verify_native_imports", Title = "Verify P/Invoke imports", UseStructuredContent = true, OutputSchemaType = typeof(NativeImportReport))]
    [Description("Check imports against library exports. .NET: each P/Invoke by the runtime's lookup (search order, API sets, A/W, stdcall names, " +
                 "ordinals, forwarders, RID, __Internal) and run-time loading in IL. Mach-O: each load command as dyld resolves it. Verdicts: " +
                 "verified, contradicted (missing_export, arch_mismatch), unresolved, dynamic_only, not_checked.")]
    public Task<string> VerifyNativeImports(
        [Description(AssemblyDescription)] string assembly,
        [Description("Only this verdict or reason (contradicted, missing_export...).")] string? status = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Max rows (default 100, max 5000).")] int limit = 100,
        [Description("Target platform (default auto).")] string? platform = null,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, progress => Task.Run(() =>
    {
        // a loaded Mach-O image (no managed assembly of that name): its load commands and bound symbols
        var macho = workspace.Read(() =>
        {
            if (workspace.FindNative(assembly) is not { Image: Native.MachO.MachOFile } n) return null;
            try { workspace.Get(assembly); return null; }
            catch (ToolError) { return n; }
        }, cancellationToken);
        if (macho != null) return MachOImports(macho, status, offset, limit, cancellationToken);
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
        var loads = result.DynamicLoads.Take(20).ToList();
        var head = new StringBuilder($"{asm.Id}: {Plural(checks.Count, "P/Invoke declaration")}" + (counts.Count > 0
            ? ": " + string.Join(", ", counts.Select(c => $"{c.Count} {c.Status} ({c.Reason})")) : "") + "\n");
        if (result.DynamicLoads.Count > 0)
        {
            head.AppendLine($"Run-time native loading in the IL ({result.DynamicLoads.Count}{(loads.Count < result.DynamicLoads.Count ? $", first {loads.Count}" : "")}):");
            foreach (var d in loads) head.AppendLine($"  {d.Kind}  {Format.EscapeMarkers(d.Method)}+{d.IlOffset}" + (d.Library != null ? $"  {Format.EscapeMarkers(d.Library)}" : ""));
        }
        foreach (var m in result.MetadataIssues.Take(10)) head.AppendLine($"Metadata issue: {m}");
        foreach (var n in notes) head.AppendLine($"Note: {n}");
        var page = selected.Skip(offset).Take(limit).ToList();
        return ToolOutput.List(page, offset, limit, selected.Count,
            c => $"{c.Status} ({c.Reason})  {Format.EscapeMarkers(c.Method)}  {c.Module}!{c.EntryPoint}" + (c.ResolvedFile != null ? $"  -> {Path.GetFileName(c.ResolvedFile)}" : "") +
                 (c.Export != null && c.Export != c.EntryPoint ? $"!{c.Export}" : "") + (c.Detail.Length > 0 ? $": {Format.EscapeMarkers(c.Detail)}" : ""),
            rows => new NativeImportReport(asm.Id, checks.Count, counts, filter, offset, selected.Count, offset + rows.Count < selected.Count,
                rows, loads, result.DynamicLoads.Count, result.MetadataIssues.Take(10).ToList(), notes), "declaration", head.ToString());
    }, cancellationToken));

    private static string MachOImports(LoadedNative native, string? status, int offset, int limit, CancellationToken ct)
    {
        var checks = MachOLinkCheck.Check((Native.MachO.MachOFile)native.Image, native.FilePath, ct);
        var filter = string.IsNullOrWhiteSpace(status) ? null : status.Trim().ToLowerInvariant();
        offset = Math.Max(0, offset);
        limit = ClampLimit(limit);
        var selected = checks.Where(c => filter == null || c.Status == filter || c.Reason == filter)
            .OrderBy(c => c.Status switch { NativeImportVerifier.Contradicted => 0, NativeImportVerifier.Unresolved => 1, NativeImportVerifier.NotChecked => 3, _ => 4 }).ToList();
        var counts = checks.Where(c => c.EntryPoint.Length == 0).GroupBy(c => (c.Status, c.Reason)).OrderBy(g => Array.IndexOf(NativeImportVerifier.Statuses, g.Key.Status))
            .Select(g => new VerdictCount(g.Key.Status, g.Key.Reason, g.Count())).ToList();
        int libraries = checks.Count(c => c.EntryPoint.Length == 0);
        List<string> notes = ["Mach-O mode: each load command resolved as dyld does (@rpath, @loader_path, @executable_path), its slice and compatibility version " +
                              "checked, and the symbols bound to it looked up in its exports; system libraries live in the dyld shared cache and are not checked."];
        var head = $"{native.Id}: {Plural(libraries, "load command")}" + (counts.Count > 0 ? ": " + string.Join(", ", counts.Select(c => $"{c.Count} {c.Status} ({c.Reason})")) : "") + "\n";
        var page = selected.Skip(offset).Take(limit).ToList();
        return ToolOutput.List(page, offset, limit, selected.Count,
            c => $"{c.Status} ({c.Reason})  {c.Module}" + (c.EntryPoint.Length > 0 ? $"!{c.EntryPoint}" : "") + (c.ResolvedFile != null ? $"  -> {c.ResolvedFile}" : "") +
                 (c.Detail.Length > 0 ? $": {Format.EscapeMarkers(c.Detail)}" : ""),
            rows => new NativeImportReport(native.Id, libraries, counts, filter, offset, selected.Count, offset + rows.Count < selected.Count, rows, [], 0, [], notes),
            "load", head + $"Note: {notes[0]}\n");
    }
}
