using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Msvc;
using NetDecompilerMcp.Native.Pe;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

/// <summary>Native analysis built on the PE model: decompilation through an engine, C++ classes, P/Invoke checks.</summary>
[McpServerToolType]
public sealed class NativeAnalysisTools(AssemblyWorkspace workspace, NativeEngineService engines, OutputPager pager, NativeNamePush? names = null,
    NativeCodeService? code = null, NativeTypePush? types = null)
{
    [McpServerTool(Name = "decompile_native", Title = "Decompile native function")]
    [Description("C pseudocode of the native function containing an address, through IDA (idalib; Hex-Rays). The first call on an image runs IDA's " +
                 "auto-analysis (seconds for a small DLL, minutes for a large game executable; progress is reported) and keeps the database per file " +
                 "hash, so later calls and later sessions are fast. Lines are annotated with the address they come from. Names and comments in effect " +
                 "(rename_native / comment_native, apply_il2cpp_names, PDB names) are pushed into the database first, once per change, and saved with it. " +
                 "When the image has a PDB (found next to it or in the symbol cache, or loaded with load_pdb), its structs, enums, typedefs and " +
                 "prototypes are loaded into the database through IDA's PDB loader (the server's own PDB type reader when that loader is not " +
                 "available), once per PDB; the first line says which type source applies.")]
    public Task<string> DecompileNative(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description("Engine: auto (default) or ida.")] string? engine = null,
        [Description("Prefix each line with the address it was generated from.")] bool addresses = false,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, rva) = await Task.Run(() => Resolve(image, address), cancellationToken);
        var session = await engines.Session(native, engine, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
        if (!session.DecompilerAvailable)
            throw new ToolError(ErrorCode.Unsupported, $"The {session.ProviderId} decompiler is not available for {session.Arch} code here.",
                "disassemble the function instead, or install/license the decompiler for this architecture");
        var pushed = NativePdbTypes.Describe(NativePdbTypes.Report(session));
        if (names != null && NativeNamePush.Describe(await names.EnsureAsync(native, session, cancellationToken)) is { } named)
            pushed = (pushed != null ? pushed + "\n// " : "") + named;
        if (types != null && NativeTypePush.Describe(await types.EnsureAsync(native, session, cancellationToken)) is { } typed)
            pushed = (pushed != null ? pushed + "\n// " : "") + typed;
        if (types != null) await types.EnsureMethodAsync(native, session, code?.Ready(native)?.FunctionAt(rva)?.Start ?? rva, cancellationToken);
        if (native.HasPatches)
            pushed = (pushed != null ? pushed + "\n// " : "") + (engines.ServesPatchedCopy(native)
                ? $"patched image: analyzed as a patched copy (the database could not take {Plural(native.Patches.Patches.Count, "patch")})"
                : $"patched image: {Plural(native.Patches.Patches.Count, "patch")} applied in the database");
        var key = $"decompile|{native.Image.Sha256}|{rva:X}|{addresses}|{NativeNamePush.CurrentStamp(session)}|{NativeTypePush.CurrentStamp(session)}|{NativePdbTypes.CurrentStamp(session)}";
        var text = pager.GetOrCreate(key, () =>
        {
            var function = session.DecompileAsync(rva, cancellationToken).GetAwaiter().GetResult();
            var lines = function.Text.Split('\n');
            var byLine = function.LineAddresses.GroupBy(l => l.Line).ToDictionary(g => g.Key, g => g.Min(l => l.Rva));
            var sb = new StringBuilder($"// {function.Name} at {NativeAddress.Va(native.Image, function.StartRva)} ({session.ProviderId}" +
                                       $"{(session.ReusedDatabase ? ", saved analysis" : $", analyzed in {session.OpenTime.TotalSeconds:0.0} s")})\n");
            for (int i = 0; i < lines.Length; i++)
                sb.Append(addresses ? (byLine.TryGetValue(i, out var at) ? $"/* {native.Image.ImageBase + at:X} */ " : new string(' ', 6 + 16 - 2)) : "")
                  .AppendLine(lines[i].TrimEnd('\r'));
            return sb.ToString();
        });
        return (pushed != null ? $"// {pushed}\n" : "") + pager.Page(text, offset, maxChars);
    });

    private (LoadedNative Native, uint Rva) Resolve(string image, string address)
    {
        var id = workspace.Read(() => workspace.FindNative(image)?.Id);
        if (id == null && !string.IsNullOrWhiteSpace(image) && Path.IsPathFullyQualified(image.Trim()) && File.Exists(image.Trim()))
            id = workspace.LoadAny(image.Trim()).Native?.Id ?? throw new ToolError(ErrorCode.Unsupported, $"{image} is a .NET assembly, not a native image.");
        return workspace.Read(() =>
        {
            var native = workspace.GetNative(id ?? image);
            return (native, NativeAddress.Parse(native.Image, address, code?.Ready(native) is { } index ? index.AddressesOfName : null));
        });
    }

    [McpServerTool(Name = "list_cpp_classes", Title = "C++ classes from RTTI")]
    [Description("C++ classes of an MSVC-built native image recovered from RTTI: demangled class names, base classes (with offsets, virtual and multiple " +
                 "inheritance), and vftables with their slot targets. Every structure is cross-checked; rejected candidates are counted with the reason.")]
    public Task<string> ListCppClasses(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Only classes whose name contains this text (case-insensitive).")] string? filter = null,
        [Description("Include each vftable's slot addresses.")] bool slots = false,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        var (native, _) = Resolve(image, "rva:0");
        var result = native.GetAnalysis(n => MsvcRtti.Analyze(n.Image, ct: cancellationToken));
        var pe = native.Image;
        var classes = result.Classes.Where(c => filter == null || c.Name.Contains(filter, StringComparison.OrdinalIgnoreCase)).ToList();
        var sb = new StringBuilder($"{native.Id}: {Plural(result.Classes.Count, "class")} with RTTI, {Plural(result.Stats.Vtables, "vftable")}, " +
                                   $"{Plural(result.TypeDescriptors.Count, "type descriptor")}" +
                                   (filter != null ? $"; {classes.Count} match '{filter}'" : "") + "\n");
        foreach (var note in result.Notes) sb.AppendLine($"Note: {note}");
        if (result.Stats.TypeDescriptorCandidatesRejected + result.Stats.LocatorCandidatesRejected > 0)
            sb.AppendLine($"Rejected candidates: {result.Stats.TypeDescriptorCandidatesRejected} type descriptors, {result.Stats.LocatorCandidatesRejected} locators (failed cross-checks)");
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
                        sb.AppendLine($"    [{i}] {NativeAddress.Va(pe, v.SlotRvas[i])}");
            }
            foreach (var issue in c.Issues) sb.AppendLine($"  issue: {issue}");
        }
        return pager.Page(sb.ToString(), offset, maxChars);
    }, cancellationToken);

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
    [Description("Check a .NET assembly's P/Invoke declarations ([DllImport]) against the exports of the DLLs they bind to on this machine, with the " +
                 "runtime's lookup rules: DLL search order (app folder, system folder for the assembly's bitness), API set redirection, A/W suffixes, " +
                 "x86 stdcall decoration (_Name@N computed from the signature), ordinals and forwarder chains. Verdict per declaration, with a reason: " +
                 "verified (exact, suffixed, decorated, forwarded, ordinal), contradicted (DLL found but missing_export, missing_ordinal, exact_spelling, " +
                 "ordinal_points_elsewhere, forwarder_broken), unresolved (dll_not_found with the places searched, not checkable here, malformed_metadata " +
                 "with its location), dynamic_only (the assembly loads the library itself: NativeLibrary.Load/GetExport, LoadLibrary/GetProcAddress, " +
                 "a DllImportResolver), not_checked (runtime-internal). Run-time loading found in the IL is listed; a missing static import does not rule " +
                 "out dynamic loading. Malformed metadata (duplicate or bogus streams, unknown tables, rows pointing out of range) is reported with locations.")]
    public Task<NativeImportReport> VerifyNativeImports(
        [Description(AssemblyDescription)] string assembly,
        [Description("Only declarations with this status (verified, contradicted, unresolved, dynamic_only, not_checked) or reason (e.g. missing_export).")] string? status = null,
        [Description("Index of the first row.")] int offset = 0,
        [Description("Max rows (default 500, max 5000).")] int limit = 500,
        CancellationToken cancellationToken = default) => Task.Run(() => workspace.Read(() =>
    {
        var asm = workspace.Get(assembly);
        var result = new NativeImportVerifier(PeFile.Open).Verify(asm, cancellationToken);
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
        if (!OperatingSystem.IsWindows()) notes.Add("DLL lookup is checked on Windows hosts only: declarations are unresolved (not_windows) here.");
        return new NativeImportReport(asm.Id, checks.Count, counts, filter, offset, selected.Count, offset + limit < selected.Count,
            selected.Skip(offset).Take(limit).ToList(), result.DynamicLoads.Take(100).ToList(), result.DynamicLoads.Count, result.MetadataIssues, notes);
    }), cancellationToken);
}
