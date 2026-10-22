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
public sealed class InspectionTools(InspectionService inspection, AssemblyWorkspace? workspace = null, NativeCodeService? code = null, ResultStore? results = null,
    Services.Mobile.AppGraph? graph = null, ServerOptions? serverOptions = null,
    Native.Providers.Worker.WorkerPool? workers = null)
{
    private const string AssemblyParam = "A loaded assembly; pass this or path.";
    private const string PathParam = "A .NET assembly file to analyze without loading; pass this or assembly.";

    [McpServerTool(Name = "summarize_file", Title = "Summarize file", UseStructuredContent = true, OutputSchemaType = typeof(FileSummaryRecord))]
    [Description("First look at a file or loaded assembly (never executed): type, hashes, signature, containers, assemblies, highlights (toolchain, " +
                 "capability features, packaging tools), entry points. view=: managed, dependencies, native, android, apple, electron, flutter, go, layers, nib, " +
                 "pcap, package (review before install), plist, protobuf, rust, script (layers peeled), sqlite (table= pages rows), sqlite-recover, unity (MonoBehaviour fields), " +
                 "all; views lists those that apply.")]
    public Task<string> SummarizeFile(
        [Description("File (assembly, bundle, .nupkg, .apk, .ipa, zip, .asar, executable) or .app folder.")] string? path = null,
        [Description(AssemblyParam)] string? assembly = null,
        [Description("A view the overview lists.")] string view = "overview",
        [Description("sqlite, sqlite-recover: table to page.")] string? table = null,
        [Description("With table=: these columns (rowid too).")] string[]? columns = null,
        [Description("unity: only assets of this script class.")] string? script = null,
        [Description(ToolSupport.RowOffsetDescription)] long offset = 0,
        [Description(ToolSupport.LimitDescription)] int? limit = null,
        [Description("Write the dependencies view here (CycloneDX 1.6).")] string? sbomPath = null,
        [Description("Overwrite sbomPath.")] bool overwrite = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
        {
            var name = string.IsNullOrWhiteSpace(view) ? "overview" : view.Trim().ToLowerInvariant();
            if ((table != null || columns != null) && name is not ("sqlite" or "sqlite-recover")
                || limit != null && name is not ("sqlite" or "sqlite-recover" or "protobuf" or "layers" or "unity")
                || offset != 0 && name is not ("sqlite" or "sqlite-recover" or "protobuf" or "layers" or "script" or "unity"))
                throw new ToolError(ErrorCode.InvalidArgument, "table, columns, offset and limit page the rows of view=sqlite and view=sqlite-recover (offset and limit also view=protobuf, view=layers and view=unity, offset view=script).",
                    "pass view=sqlite with table=, or drop them");
            if (script != null && name != "unity") throw new ToolError(ErrorCode.InvalidArgument, "script selects the assets of view=unity.", "pass view=unity with script=, or drop it");
            if (columns != null && table == null) throw new ToolError(ErrorCode.InvalidArgument, "columns selects columns of a table: pass table= with it.");
            var options = new FileViewOptions(name, table, columns, offset, limit) { Sbom = sbomPath != null, Script = script };
            var native = NativeNamed(assembly, path);
            FileSummaryRecord record;
            // A file the workspace has not loaded is read where a crashing reader cannot end the server.
            if (assembly == null && path != null && native == null)
            {
                var args = new FileWork.SummarizeArgs(path, name, table, columns, offset, limit, sbomPath, overwrite, script);
                record = await FileIsolation.RunAsync(serverOptions, workers, FileWork.Summarize, args, path, () => FileWork.SummarizeWith(inspection, graph, args, cancellationToken), cancellationToken);
                return ToolOutput.Report(ContainerText.Summary(record), record);
            }
            InspectionService.FileSummary summary;
            if (native == null || code == null) summary = await Task.Run(() => inspection.Summarize(assembly, path, cancellationToken, options), cancellationToken);
            else
            {
                var index = await code.Index(native, new Progress<Corvus.Native.Code.CodeIndexProgress>(p => progress.Report(new ProgressNotificationValue
                    { Progress = p.Done, Total = p.Total > 0 ? p.Total : null, Message = $"indexing {native.Id}: {p.Phase}" })), cancellationToken);
                summary = await Task.Run(() => inspection.Summarize(null, native.FilePath, cancellationToken, options), cancellationToken);
                summary = summary with { Triage = await Task.Run(() => NativeTriageBuilder.Build(index, cancellationToken), cancellationToken) };
            }
            record = ContainerText.Summary(summary, name);
            if (sbomPath != null) record = record with { Notes = [.. record.Notes ?? [], FileWork.WriteSbom(summary, sbomPath, overwrite)] };
            if (name == "layers" && graph != null)
            {
                var facts = await Task.Run(() => graph.Build(summary.File.Path, (int)Math.Min(offset, int.MaxValue), limit ?? Services.Mobile.AppGraph.DefaultLimit, cancellationToken), cancellationToken);
                record = record with { Detail = ToolOutput.Serialize(facts) as System.Text.Json.Nodes.JsonObject };
            }
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
    [Description("Rules over API calls, P/Invokes and strings (network, execution, registry, persistence, collection, system changes, code loading, " +
                 "cross-process, crypto); category= adds evidence. Native: imports, call arguments, strings, sections, RTTI. Apps: MASVS findings " +
                 "(WebView, TLS, pinning, root checks, code loading, weak crypto, keys) by method offset. Il2Cpp: capa rule matches over the game " +
                 "binary's direct calls (category capa, CORVUS_CAPA).")]
    public async Task<string> SurveyFeatures(
        [Description(AssemblyParam)] string? assembly = null,
        [Description("A .NET, native or app file, read without loading.")] string? path = null,
        [Description("Category or MASVS prefix: with evidence; all: everything.")] string? category = null,
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
    [Description("Typed values (URLs, domains, IPs, emails, file paths, pipes, registry keys, mutexes, user agents, crypto keys) from assembly " +
                 "literals, constants, resource text and decoded base64 / hex / compressed text, with count, locations and receiving APIs. " +
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
    [Description("Embedded content of an assembly or each assembly in a container (resources, byte arrays, long literals), decoded through hex, " +
                 "base64, compression and XOR until a PE, archive, ELF, Mach-O or text appears, plus high-entropy blobs, each with its encoding " +
                 "chain. save=true writes them (defanged names).")]
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
