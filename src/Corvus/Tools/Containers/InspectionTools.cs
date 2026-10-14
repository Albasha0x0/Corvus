using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using Corvus.Services.Analysis;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class InspectionTools(InspectionService inspection, AssemblyWorkspace? workspace = null, NativeCodeService? code = null, ResultStore? results = null)
{
    private const string AssemblyParam = "A loaded assembly; pass this or path.";
    private const string PathParam = "A .NET assembly file to analyze without loading it; pass this or assembly.";

    [McpServerTool(Name = "summarize_file", Title = "Summarize file", UseStructuredContent = true, OutputSchemaType = typeof(FileSummaryRecord))]
    [Description("First look at any file or loaded assembly, never executed: type, hashes, signature, container wrapping (bundles, packages, APKs, " +
                 "zips, Costura opened), its assemblies, highlights (toolchain markers, ATT&CK features, packers), entry points, value counts. " +
                 "view= gives the details: managed (identity, markers, features, values), native (ELF / Mach-O, packers, NativeAOT; " +
                 "a loaded image's triage), android, apple, electron, go, all; views lists those that apply.")]
    public Task<string> SummarizeFile(
        [Description("Any file (assembly, bundle, .nupkg, .apk, .ipa, zip, .asar, executable) or .app folder; this or assembly.")] string? path = null,
        [Description(AssemblyParam)] string? assembly = null,
        [Description("overview (default) or a view the overview lists.")] string view = "overview",
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
        {
            var native = NativeNamed(assembly, path);
            InspectionService.FileSummary summary;
            if (native == null || code == null) summary = await Task.Run(() => inspection.Summarize(assembly, path, cancellationToken), cancellationToken);
            else
            {
                var index = await code.Index(native, new Progress<Corvus.Native.Code.CodeIndexProgress>(p => progress.Report(new ProgressNotificationValue
                    { Progress = p.Done, Total = p.Total > 0 ? p.Total : null, Message = $"indexing {native.Id}: {p.Phase}" })), cancellationToken);
                summary = await Task.Run(() => inspection.Summarize(null, native.FilePath, cancellationToken), cancellationToken);
                summary = summary with { Triage = await Task.Run(() => NativeTriageBuilder.Build(index, cancellationToken), cancellationToken) };
            }
            var record = ContainerText.Summary(summary, string.IsNullOrWhiteSpace(view) ? "overview" : view);
            return ToolOutput.Report(ContainerText.Summary(record), record);
        });

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

    [McpServerTool(Name = "extract_strings", Title = "Extract typed strings", UseStructuredContent = true, OutputSchemaType = typeof(ValuePage))]
    [Description("Typed values (URLs, domains, IPs, emails, file paths, pipes, registry keys, mutexes, user agents, crypto keys) from an assembly's literals, constants, " +
                 "resource text and decoded base64 / hex / compressed text, each with count, locations and the APIs it is passed to. All values are kept: " +
                 "read_result outputPath exports them (text: CSV, json).")]
    public async Task<string> ExtractStrings(
        [Description(AssemblyParam)] string? assembly = null,
        [Description(PathParam)] string? path = null,
        [Description("Only these types.")] string[]? types = null,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = 100,
        CancellationToken cancellationToken = default)
    {
        var report = await Task.Run(() => inspection.ExtractStrings(assembly, path, types, cancellationToken), cancellationToken);
        string? kept = null;
        if (results != null && report.Total > 0)
            kept = results.Keep(Values.ToCsv(report.Values), new KeptOrigin("extract_strings"),
                System.Text.Json.JsonSerializer.Serialize(new { items = report.Values, total = report.Total }, ToolOutput.Json));
        return ContainerText.Values(report, offset, ToolSupport.ClampLimit(limit), kept);
    }

    [McpServerTool(Name = "extract_embedded", Title = "Extract embedded content", UseStructuredContent = true, OutputSchemaType = typeof(EmbeddedPage))]
    [Description("Embedded content of an assembly, or of every assembly in a container (resources, static byte arrays, long string literals) decoded through hex, " +
                 "base64, compression and XOR (key from a known header) until a PE, archive, ELF / Mach-O or text appears, plus high-entropy blobs; each with " +
                 "its source and encoding chain. save=true writes them all (defanged names), load=true also loads the .NET ones. Nothing is executed.")]
    public async Task<string> ExtractEmbedded(
        [Description(AssemblyParam)] string? assembly = null,
        [Description("An assembly or container file, read without loading; pass this or assembly.")] string? path = null,
        [Description("Write the items to disk.")] bool save = false,
        [Description("New or empty directory (or an earlier extraction of the same file); default under temp.")] string? outputDirectory = null,
        [Description("Load the .NET assemblies found (implies save).")] bool load = false,
        [Description("Also brute-force 1-16 byte XOR keys over unreadable data, keeping natural text or configuration (slower).")] bool xorText = false,
        [Description("Also list and save images (else counted).")] bool includeMedia = false,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = 100,
        CancellationToken cancellationToken = default)
    {
        var report = await Task.Run(() => inspection.ExtractEmbedded(assembly, path, save, outputDirectory, load, cancellationToken, xorText, includeMedia), cancellationToken);
        return ContainerText.Embedded(report, offset, ToolSupport.ClampLimit(limit));
    }
}
