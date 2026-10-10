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
    NativeCodeService? code = null)
{
    [McpServerTool(Name = "decompile_native", Title = "Decompile native function", ReadOnly = true, OpenWorld = false)]
    [Description("C pseudocode of the native function containing an address, through IDA (idalib; Hex-Rays). The first call on an image runs IDA's " +
                 "auto-analysis (seconds for a small DLL, minutes for a large game executable; progress is reported) and keeps the database per file " +
                 "hash, so later calls and later sessions are fast. Lines are annotated with the address they come from. Names and comments in effect " +
                 "(rename_native / comment_native, apply_il2cpp_names, PDB names) are pushed into the database first, once per change, and saved with it.")]
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
        var pushed = names != null ? NativeNamePush.Describe(await names.EnsureAsync(native, session, cancellationToken)) : null;
        var key = $"decompile|{native.Image.Sha256}|{rva:X}|{addresses}|{NativeNamePush.CurrentStamp(session)}";
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
            return (native, NativeAddress.Parse(native.Image, address, code?.Ready(native) is { } index ? index.AddressOfName : null));
        });
    }

    [McpServerTool(Name = "list_cpp_classes", Title = "C++ classes from RTTI", ReadOnly = true, Idempotent = true, OpenWorld = false)]
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

    [McpServerTool(Name = "verify_native_imports", Title = "Verify P/Invoke imports", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Check a .NET assembly's P/Invoke declarations ([DllImport]) against the exports of the DLLs they bind to on this machine, with the " +
                 "runtime's lookup rules: DLL search order (app folder, system folder for the assembly's bitness), API set redirection, A/W suffixes, " +
                 "x86 stdcall decoration (_Name@N computed from the signature), ordinals and forwarder chains. Status per declaration: verified, " +
                 "decorated, forwarded, ordinal, missing_export (with similar exports), dll_not_found (with the places searched), not_checked (runtime-internal).")]
    public Task<string> VerifyNativeImports(
        [Description(AssemblyDescription)] string assembly,
        [Description("Only declarations with this status (e.g. missing_export).")] string? status = null,
        [Description("Index of the first row.")] int offset = 0,
        [Description("Max rows (default 500).")] int limit = 500,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var asm = workspace.Get(assembly);
        var checks = new NativeImportVerifier(PeFile.Open).Verify(asm, cancellationToken);
        if (checks.Count == 0) return $"{asm.Id} declares no P/Invoke methods.";
        var summary = string.Join(", ", checks.GroupBy(c => c.Status).OrderBy(g => g.Key).Select(g => $"{g.Key} {g.Count()}"));
        var rows = checks.Where(c => status == null || c.Status.Equals(status.Trim(), StringComparison.OrdinalIgnoreCase))
            .OrderBy(c => c.Status == NativeImportVerifier.Verified ? 1 : 0).ThenBy(c => c.Module, StringComparer.OrdinalIgnoreCase).ThenBy(c => c.EntryPoint)
            .Select(c => $"{c.Status,-15} {c.Module}!{c.EntryPoint}  ({c.Method}; {c.CharSet}{(c.ExactSpelling ? ", exact" : "")}, {c.CallingConvention})" +
                         $"{(c.Export != null && c.Export != c.EntryPoint ? $" -> {c.Export}" : "")}{(c.ResolvedFile != null ? $" in {c.ResolvedFile}" : "")}" +
                         (c.Status == NativeImportVerifier.Verified ? "" : $": {c.Detail}"))
            .ToList();
        return $"{asm.Id}: {Plural(checks.Count, "P/Invoke declaration")} ({summary})\n" + pager.PageRows(rows, offset, limit, "declaration");
    }, cancellationToken);
}
