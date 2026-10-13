using System.ComponentModel;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using Corvus.Services.Analysis;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class InspectionTools(InspectionService inspection, AssemblyWorkspace? workspace = null, NativeCodeService? code = null)
{
    private const string AssemblyParam = "A loaded assembly; pass this or path.";
    private const string PathParam = "A .NET assembly file to analyze without loading it; pass this or assembly.";

    [McpServerTool(Name = "summarize_file", Title = "Summarize file", UseStructuredContent = true)]
    [Description("First look at any file or loaded assembly, without executing it: hashes, type, entropy; per managed assembly identity, signature " +
                 "(strong name, Authenticode), toolchain markers, features with ATT&CK techniques, extracted values and entry points. Containers " +
                 "(single-file bundles, packages, APKs, zips, Costura) are opened: the app's assembly in full, 7 more in brief. Also: NativeAOT " +
                 "recovery counts, ELF / Mach-O format, signature, Go build info, packers, protectors, Android package, SDKs, ABIs, components, " +
                 "Electron (versions, fuses, .asar integrity, webPreferences with file:line), and for a loaded native image triage (entry points, " +
                 "top functions, strings, import groups).")]
    public async Task<InspectionService.FileSummary> SummarizeFile(
        [Description("Any file (assembly, bundle, .nupkg, .apk, zip, .asar, native executable); pass this or assembly.")] string? path = null,
        [Description(AssemblyParam)] string? assembly = null,
        CancellationToken cancellationToken = default)
    {
        var native = NativeNamed(assembly, path);
        if (native == null || code == null) return await Task.Run(() => inspection.Summarize(assembly, path, cancellationToken), cancellationToken);
        var index = await code.Index(native, null, cancellationToken);
        var summary = await Task.Run(() => inspection.Summarize(null, native.FilePath, cancellationToken), cancellationToken);
        return summary with { Triage = await Task.Run(() => NativeTriageBuilder.Build(index, cancellationToken), cancellationToken) };
    }

    /// <summary>The loaded native image an argument names (a managed assembly of that name wins), or null.</summary>
    private LoadedNative? NativeNamed(string? assembly, string? path)
    {
        if (workspace == null || (assembly == null) == (path == null)) return null;
        return workspace.Read(() =>
        {
            if (assembly != null)
            {
                if (workspace.FindNative(assembly) is not { } n) return null;
                try { workspace.Get(assembly); return null; }
                catch (ToolError) { return n; }
            }
            return File.Exists(path) ? workspace.FindNative(Path.GetFullPath(path!)) : null;
        });
    }

    [McpServerTool(Name = "survey_features", Title = "Survey features", UseStructuredContent = true, OutputSchemaType = typeof(SurveyRecord))]
    [Description("Rule-based (capa-style) survey of the APIs an assembly calls, its P/Invokes and strings: network, execution, registry, persistence, collection, " +
                 "anti-analysis, evasion, code loading, injection, crypto; each feature with its ATT&CK technique and match count, evidence (up to 5 locations) " +
                 "with category=. Native images: the same rules over imports, call arguments, strings, sections and RTTI names.")]
    public async Task<string> SurveyFeatures(
        [Description(AssemblyParam)] string? assembly = null,
        [Description("A .NET or native file to analyze without loading it; pass this, assembly or image.")] string? path = null,
        [Description("Only this category (network, ...) or ATT&CK prefix (T1055), with evidence; all: every feature with evidence.")] string? category = null,
        [Description("A native image, loaded or a path (instead of assembly).")] string? image = null,
        CancellationToken cancellationToken = default)
    {
        if (image != null && assembly != null)
            throw new ToolError(ErrorCode.InvalidArgument, "Pass assembly or image, not both: they name the same thing.");
        if (image != null && path == null && workspace?.Read(() => workspace.FindNative(image)) == null && File.Exists(image)) (path, image) = (image, null);
        var report = await Task.Run(() => inspection.SurveyFeatures(assembly ?? image, path, category, cancellationToken), cancellationToken);
        var record = ContainerText.Survey(report, category);
        return ToolOutput.Report(ContainerText.Survey(record), record);
    }

    [McpServerTool(Name = "extract_strings", Title = "Extract typed strings", UseStructuredContent = true)]
    [Description("Typed values (URLs, domains, IPs, emails, file paths, pipes, registry keys, mutexes, user agents, crypto keys) from an assembly's literals, constants, " +
                 "resource text and decoded base64 / hex / compressed text, each with count, locations and the APIs it is passed to; savePath exports JSON or CSV.")]
    public Task<InspectionService.ValueReport> ExtractStrings(
        [Description(AssemblyParam)] string? assembly = null,
        [Description(PathParam)] string? path = null,
        [Description("Only these comma-separated types: url, domain, ipv4, ipv6, email, file_path, named_pipe, registry_key, mutex, user_agent, crypto_key.")] string? types = null,
        [Description("Write the values to this file.")] string? savePath = null,
        [Description("json (default) or csv (implied by a .csv savePath).")] string? format = null,
        [Description("Replace savePath if it exists.")] bool overwrite = false,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => inspection.ExtractStrings(assembly, path,
            types?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), savePath, format, overwrite, cancellationToken), cancellationToken);

    [McpServerTool(Name = "extract_embedded", Title = "Extract embedded content", UseStructuredContent = true)]
    [Description("Embedded content of an assembly (resources, static byte arrays, long string literals) decoded through hex, base64, compression and XOR " +
                 "(key from a known header) until a PE, archive, ELF / Mach-O or text appears, plus high-entropy blobs; each with its source and encoding chain. " +
                 "save=true writes them (defanged names), load=true also loads the .NET ones. Nothing is executed.")]
    public Task<InspectionService.EmbeddedReport> ExtractEmbedded(
        [Description(AssemblyParam)] string? assembly = null,
        [Description(PathParam)] string? path = null,
        [Description("Write the items to disk.")] bool save = false,
        [Description("New or empty directory (or an earlier extraction of the same file); default under temp.")] string? outputDirectory = null,
        [Description("Load the .NET assemblies found into the workspace (implies save).")] bool load = false,
        [Description("Also recover 1-16 byte XOR keys over unreadable data, keeping clearly natural text or configuration (heuristic, slower).")] bool xorText = false,
        [Description("Also list and save images (else only counted).")] bool includeMedia = false,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => inspection.ExtractEmbedded(assembly, path, save, outputDirectory, load, cancellationToken, xorText, includeMedia), cancellationToken);
}
