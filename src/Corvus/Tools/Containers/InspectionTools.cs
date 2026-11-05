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
    private const string AssemblyParam = "A loaded assembly; this or path.";
    private const string PathParam = "An assembly, container, build folder, package, or serialized asset file or bundle.";

    // The views that read each paging parameter; any other view refuses it.
    private static readonly string[] TableViews = ["sqlite", "sqlite-recover", "lmdb", "ese", "berkeleydb", "realm", "evtx", "procmon", "registry", "pri", "esp32"];
    private static readonly string[] ColumnViews = ["sqlite", "sqlite-recover"];
    private static readonly string[] LimitViews = [.. TableViews, "protobuf", "layers", "assets", "leveldb", "qlog", "certificate", "model"];
    private static readonly string[] OffsetViews = [.. LimitViews, "script", "python", "xbf"];

    /// <summary>The first paging parameter passed that <paramref name="view"/> does not read, with the views that do; null when all apply.</summary>
    internal static (string Parameter, string[] Views)? Refused(string view, bool table, bool columns, bool offset, bool limit) =>
        table && !TableViews.Contains(view) ? ("table", TableViews)
        : columns && !ColumnViews.Contains(view) ? ("columns", ColumnViews)
        : offset && !OffsetViews.Contains(view) ? ("offset", OffsetViews)
        : limit && !LimitViews.Contains(view) ? ("limit", LimitViews)
        : null;

    [McpServerTool(Name = "summarize_file", Title = "Summarize file", UseStructuredContent = true, OutputSchemaType = typeof(FileSummaryRecord))]
    [Description("Summarize a file, folder or assembly, never run: type, hashes, signature, containers, assemblies, " +
                 "entry points. view= opens one aspect.")]
    public Task<string> SummarizeFile(
        [Description("A file or folder.")] string? path = null,
        [Description(AssemblyParam)] string? assembly = null,
        [Description("A view the overview lists.")] string view = "overview",
        [Description("Table; lmdb, berkeleydb: database; evtx: provider/id; procmon: process/PID/operation/result; registry: key; pri: name; esp32: namespace.")] string? table = null,
        [Description("With table=: these columns and rowid.")] string[]? columns = null,
        [Description("assets: assets of this script class.")] string? script = null,
        [Description(ToolSupport.RowOffsetDescription)] long offset = 0,
        [Description(ToolSupport.LimitDescription)] int? limit = null,
        [Description("Write dependencies here, CycloneDX 1.6.")] string? sbomPath = null,
        [Description("Write findings here, STIX 2.1.")] string? stixPath = null,
        [Description("Write hunting queries and disabled rules here, JSON.")] string? huntsPath = null,
        [Description("Write component rows here, JSON lines.")] string? componentsPath = null,
        [Description("Overwrite these files.")] bool overwrite = false,
        [Description("Password to decrypt with; only it is tried.")] string? password = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
        {
            var name = string.IsNullOrWhiteSpace(view) ? "overview" : view.Trim().ToLowerInvariant();
            if (Refused(name, table != null, columns != null, offset != 0, limit != null) is { } refused)
                throw new ToolError(ErrorCode.InvalidArgument, $"{refused.Parameter}= applies to view={string.Join(", view=", refused.Views)}, not view={name}.",
                    $"drop {refused.Parameter}=, or pass one of those views");
            if (script != null && name != "assets") throw new ToolError(ErrorCode.InvalidArgument, "script selects the assets of view=assets.", "pass view=assets with script=, or drop it");
            if (columns != null && table == null) throw new ToolError(ErrorCode.InvalidArgument, "columns selects columns of a table: pass table= with it.");
            var options = new FileViewOptions(name, table, columns, offset, limit) { Sbom = sbomPath != null || componentsPath != null, Stix = stixPath != null, Hunts = huntsPath != null, Script = script };
            var native = NativeNamed(assembly, path);
            FileSummaryRecord record;
            // A file the workspace has not loaded is read where a crashing reader cannot end the server.
            if (assembly == null && path != null && native == null)
            {
                var args = new FileWork.SummarizeArgs(path, name, table, columns, offset, limit, sbomPath, overwrite, script, stixPath, password, huntsPath, componentsPath);
                // A sandboxed worker cannot write the caller's folders: it writes staged files the server then moves.
                FileWork.CheckOutputs(args);
                var staged = FileIsolation.PoolFor(serverOptions, workers) is { Sandboxed: true } ? FileWork.StageOutputs(args) : null;
                try
                {
                    var sent = staged?.Args ?? args;
                    record = await FileIsolation.RunAsync(serverOptions, workers, FileWork.Summarize, sent, path, () => FileWork.SummarizeWith(inspection, graph, sent, cancellationToken), cancellationToken);
                    if (staged is { } s) record = FileWork.PlaceOutputs(record, s.Files, overwrite);
                }
                finally { if (staged is { } s) FileWork.DeleteStaging(s.Staging); }
                Coverage(record);
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
            if (sbomPath != null) record = record with { Notes = [.. record.Notes ?? [], FileWork.WriteSbom(summary, sbomPath, overwrite, name == "dependencies")] };
            if (stixPath != null) record = record with { Notes = [.. record.Notes ?? [], FileWork.WriteStix(summary, stixPath, overwrite)] };
            if (huntsPath != null) record = record with { Notes = [.. record.Notes ?? [], FileWork.WriteHunts(summary, huntsPath, overwrite)] };
            if (componentsPath != null)
                record = record with { Notes = [.. record.Notes ?? [], FileWork.WriteComponents(inspection, summary, componentsPath, overwrite, cancellationToken)] };
            if (name == "layers" && graph != null)
            {
                var facts = await Task.Run(() => graph.Build(summary.File.Path, (int)Math.Min(offset, int.MaxValue), limit ?? Services.Mobile.AppGraph.DefaultLimit, cancellationToken), cancellationToken);
                record = record with { Detail = ToolOutput.Serialize(facts) as System.Text.Json.Nodes.JsonObject };
            }
            Coverage(record);
            return ToolOutput.Report(ContainerText.Summary(record), record);
        });

    /// <summary>view=package states what it read: partial with the files not read, else complete; other views leave coverage unknown.</summary>
    private static void Coverage(FileSummaryRecord record)
    {
        if (record.View != "package" || record.Detail == null) return;
        if ((string?)record.Detail["partial"] is { Length: > 0 } partial) ToolOutput.Coverage("partial", partial, Limitations.Id(Limitation.RowCap));
        else ToolOutput.Complete();
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
    [Description("Capabilities by rules over calls, imports and strings; category= adds evidence. " +
                 "Apps add MASVS findings; category=capa adds labels (CORVUS_CAPA): waitSeconds waits, cancel stops it.")]
    public async Task<string> SurveyFeatures(
        [Description(AssemblyParam)] string? assembly = null,
        [Description("A .NET, native or app file, not loaded.")] string? path = null,
        [Description("Category or MASVS prefix; all: everything.")] string? category = null,
        [Description("A native image or path (instead of assembly).")] string? image = null,
        [Description("Locations per entry, 1-100; default 5.")] int locations = ContainerText.ShownLocations,
        [Description("Seconds to wait for capa, 0-600.")] int waitSeconds = 0,
        [Description("Stop the capa run.")] bool cancel = false,
        CancellationToken cancellationToken = default)
    {
        if (locations is < 1 or > Evidence.MaxLocations)
            throw new ToolError(ErrorCode.InvalidArgument, $"locations must be 1-{Evidence.MaxLocations}.");
        if (waitSeconds is < 0 or > 600)
            throw new ToolError(ErrorCode.InvalidArgument, $"waitSeconds {waitSeconds} is outside 0-600.", "waitSeconds=60");
        if (image != null && assembly != null)
            throw new ToolError(ErrorCode.InvalidArgument, "Pass assembly or image, not both: they name the same thing.");
        if (image != null && path == null && workspace?.Read(() => workspace.FindNative(image)) == null && File.Exists(image)) (path, image) = (image, null);
        if (cancel)
        {
            if (assembly == null && image == null && path == null)
                throw new ToolError(ErrorCode.InvalidArgument, "cancel needs the file of the run.", "survey_features path=<file> category=capa cancel=true");
            var stopped = ContainerText.Survey(inspection.CancelCapa(assembly ?? image, path), null, locations);
            return ToolOutput.Report(ContainerText.Survey(stopped), stopped);
        }
        SurveyRecord record;
        var capa = string.Equals(category, "capa", StringComparison.OrdinalIgnoreCase);
        if (assembly == null && image == null && path != null)
        {
            // The capa job outlives the call and runs in its own worker; the file worker takes its report.
            var run = capa ? await Task.Run(() => inspection.CapaOf(path, TimeSpan.FromSeconds(waitSeconds), cancellationToken), cancellationToken) : null;
            var args = new FileWork.SurveyArgs(path, category, locations, run);
            record = await FileIsolation.RunAsync(serverOptions, workers, FileWork.Survey, args, path,
                () => FileWork.SurveyWith(inspection, args, cancellationToken), cancellationToken);
        }
        else record = ContainerText.Survey(await Task.Run(() => inspection.SurveyFeatures(assembly ?? image, path, category, cancellationToken, TimeSpan.FromSeconds(waitSeconds)), cancellationToken), category, locations);
        return ToolOutput.Report(ContainerText.Survey(record), record);
    }

    [McpServerTool(Name = "extract_strings", Title = "Extract typed strings", UseStructuredContent = true, OutputSchemaType = typeof(ValuePage))]
    [Description("Typed values (URLs, IPs, paths, registry keys, crypto keys, base64) from literals, constants, resources and " +
                 "serialized asset fields, or native image strings (section, VA; view=indicators gives file offsets from a bounded scan), with count, locations and receiving APIs. " +
                 "read_result outputPath exports all (text: CSV).")]
    public async Task<string> ExtractStrings(
        [Description(AssemblyParam)] string? assembly = null,
        [Description(PathParam)] string? path = null,
        [Description("Only these types.")] string[]? types = null,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = 100,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        [Description("Asset bytes to read; at most 4 GiB (default).")] long? maxAssetBytes = null,
        [Description("Seconds until the asset read stops.")] double? timeLimit = null,
        CancellationToken cancellationToken = default)
    {
        if (maxAssetBytes is <= 0) throw new ToolError(ErrorCode.InvalidArgument, "maxAssetBytes must be above 0.");
        if (timeLimit is not null and (<= 0 or > 86_400)) throw new ToolError(ErrorCode.InvalidArgument, "timeLimit must be above 0 seconds, at most 86400.");
        var assets = new InspectionService.AssetReadLimits(Math.Min(maxAssetBytes ?? AssetFileStrings.MaxBytes, AssetFileStrings.MaxBytes),
            timeLimit is { } seconds ? TimeSpan.FromSeconds(seconds) : null);
        InspectionService.ValueReport report;
        if (assembly == null && path != null)
        {
            var args = new FileWork.StringsArgs(path, types, assets.MaxBytes, timeLimit);
            report = await FileIsolation.RunAsync(serverOptions, workers, FileWork.Strings, args, path,
                () => FileWork.StringsWith(inspection, args, cancellationToken), cancellationToken);
        }
        else report = await Task.Run(() => inspection.ExtractStrings(assembly, path, types, cancellationToken, assets), cancellationToken);
        if (report.Partial is { } partial) ToolOutput.Coverage("partial", partial, [.. report.PartialIn]);
        string? kept = null;
        if (results != null && report.Total > 0)
            kept = results.Keep(Values.ToCsv(report.Values), new KeptOrigin("extract_strings"),
                System.Text.Json.JsonSerializer.Serialize(new { items = report.Values, total = report.Total }, ToolOutput.Json));
        return ContainerText.Values(report, offset, ToolSupport.ClampLimit(limit), kept);
    }

    [McpServerTool(Name = "extract_embedded", Title = "Extract embedded content", UseStructuredContent = true, OutputSchemaType = typeof(EmbeddedPage))]
    [Description("Embedded content of an assembly, container or native PE (resources, byte arrays, literals, inner PEs), " +
                 "decoded (hex, base64, compression, XOR) to an image, archive or text with its encoding chain; save=true writes them.")]
    public async Task<string> ExtractEmbedded(
        [Description(AssemblyParam)] string? assembly = null,
        [Description("An assembly or container file, read without loading.")] string? path = null,
        [Description("Write the items to disk.")] bool save = false,
        [Description("Empty directory or an earlier extraction; default: temp.")] string? outputDirectory = null,
        [Description("Load .NET assemblies found (implies save).")] bool load = false,
        [Description("Also try 1-16 byte XOR keys (slower).")] bool xorText = false,
        [Description("Also list and save images (else counted).")] bool includeMedia = false,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = 100,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default)
    {
        InspectionService.EmbeddedReport report;
        // A sandboxed worker cannot write the named folder, so a save stays in the server.
        if (assembly == null && path != null && !load && !(save && FileIsolation.PoolFor(serverOptions, workers) is { Sandboxed: true }))
        {
            var args = new FileWork.EmbeddedArgs(path, save, outputDirectory, xorText, includeMedia);
            report = await FileIsolation.RunAsync(serverOptions, workers, FileWork.Embedded, args, path,
                () => FileWork.EmbeddedWith(inspection, args, cancellationToken), cancellationToken);
        }
        else report = await Task.Run(() => inspection.ExtractEmbedded(assembly, path, save, outputDirectory, load, cancellationToken, xorText, includeMedia), cancellationToken);
        return ContainerText.Embedded(report, offset, ToolSupport.ClampLimit(limit));
    }
}
