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
    [Description("First look at a file or loaded assembly (never executed): type, hashes, signature, containers, assemblies, highlights " +
                 "(toolchain, ATT&CK features, packers), entry points. view=: managed, native, android, apple, electron, flutter, go, nib, pcap, " +
                 "plist, protobuf, rust, sqlite (table= pages rows), sqlite-recover, all; views lists those that apply.")]
    public Task<string> SummarizeFile(
        [Description("File (assembly, bundle, .nupkg, .apk, .ipa, zip, .asar, executable) or .app folder.")] string? path = null,
        [Description(AssemblyParam)] string? assembly = null,
        [Description("overview (default) or a view the overview lists.")] string view = "overview",
        [Description("sqlite, sqlite-recover: the table to page.")] string? table = null,
        [Description("With table=: these columns (rowid too).")] string[]? columns = null,
        [Description(ToolSupport.RowOffsetDescription)] long offset = 0,
        [Description(ToolSupport.LimitDescription)] int? limit = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
        {
            var name = string.IsNullOrWhiteSpace(view) ? "overview" : view.Trim().ToLowerInvariant();
            if ((table != null || columns != null) && name is not ("sqlite" or "sqlite-recover")
                || (offset != 0 || limit != null) && name is not ("sqlite" or "sqlite-recover" or "protobuf"))
                throw new ToolError(ErrorCode.InvalidArgument, "table, columns, offset and limit page the rows of view=sqlite and view=sqlite-recover (offset and limit also view=protobuf).",
                    "pass view=sqlite with table=, or drop them");
            if (columns != null && table == null) throw new ToolError(ErrorCode.InvalidArgument, "columns selects columns of a table: pass table= with it.");
            var options = new FileViewOptions(name, table, columns, offset, limit);
            var native = NativeNamed(assembly, path);
            InspectionService.FileSummary summary;
            if (native == null || code == null) summary = await Task.Run(() => inspection.Summarize(assembly, path, cancellationToken, options), cancellationToken);
            else
            {
                var index = await code.Index(native, new Progress<Corvus.Native.Code.CodeIndexProgress>(p => progress.Report(new ProgressNotificationValue
                    { Progress = p.Done, Total = p.Total > 0 ? p.Total : null, Message = $"indexing {native.Id}: {p.Phase}" })), cancellationToken);
                summary = await Task.Run(() => inspection.Summarize(null, native.FilePath, cancellationToken, options), cancellationToken);
                summary = summary with { Triage = await Task.Run(() => NativeTriageBuilder.Build(index, cancellationToken), cancellationToken) };
            }
            var record = ContainerText.Summary(summary, name);
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
    [Description("Rule-based (capa-style) survey of an assembly's API calls, P/Invokes and strings: network, execution, registry, persistence, " +
                 "collection, anti-analysis, evasion, code loading, injection, crypto; each with its ATT&CK technique and match count; category= adds " +
                 "evidence (5 locations). Native images: imports, call arguments, strings, sections, RTTI.")]
    public async Task<string> SurveyFeatures(
        [Description(AssemblyParam)] string? assembly = null,
        [Description("A .NET or native file, analyzed without loading; or pass assembly or image.")] string? path = null,
        [Description("A category (network, ...) or ATT&CK prefix (T1055) with evidence; all: every feature.")] string? category = null,
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
    [Description("Typed values (URLs, domains, IPs, emails, file paths, pipes, registry keys, mutexes, user agents, crypto keys) from an assembly's " +
                 "literals, constants, resource text and decoded base64 / hex / compressed text, with count, locations and the APIs receiving them. " +
                 "read_result outputPath exports all (text: CSV).")]
    public async Task<string> ExtractStrings(
        [Description(AssemblyParam)] string? assembly = null,
        [Description(PathParam)] string? path = null,
        [Description("Only these types.")] string[]? types = null,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = 100,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
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
    [Description("Embedded content of an assembly or of every assembly in a container (resources, byte arrays, long literals), decoded through " +
                 "hex, base64, compression and XOR until a PE, archive, ELF / Mach-O or text appears, plus high-entropy blobs, each with its encoding " +
                 "chain. save=true writes them (defanged names). Nothing is executed.")]
    public async Task<string> ExtractEmbedded(
        [Description(AssemblyParam)] string? assembly = null,
        [Description("An assembly or container file, read without loading; pass this or assembly.")] string? path = null,
        [Description("Write the items to disk.")] bool save = false,
        [Description("New or empty directory, or an earlier extraction of this file; default under temp.")] string? outputDirectory = null,
        [Description("Load the .NET assemblies found (implies save).")] bool load = false,
        [Description("Also brute-force 1-16 byte XOR keys over unreadable data for text (slower).")] bool xorText = false,
        [Description("Also list and save images (else counted).")] bool includeMedia = false,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = 100,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default)
    {
        var report = await Task.Run(() => inspection.ExtractEmbedded(assembly, path, save, outputDirectory, load, cancellationToken, xorText, includeMedia), cancellationToken);
        return ContainerText.Embedded(report, offset, ToolSupport.ClampLimit(limit));
    }
}
