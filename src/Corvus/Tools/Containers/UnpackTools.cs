using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Services.Analysis;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class UnpackTools(UnpackService unpacker)
{
    [McpServerTool(Name = "unpack_container", Title = "Unpack container", UseStructuredContent = true, OutputSchemaType = typeof(UnpackPage))]
    [Description("Extract the .NET assemblies inside a container and load them: single-file bundles, Costura.Fody, .nupkg, Xamarin / MAUI .apk / " +
                 ".aab (per ABI), zips, embedded .NET images, nested containers; Electron .asar, Unity WebGL .data and HAR / mitmproxy captures give " +
                 "every file. Nothing is executed; runnable extensions get .bin.")]
    public Task<string> UnpackContainer(
        [Description("Container file, or a Blazor _framework folder.")] string path,
        [Description("New or empty directory, or an earlier unpack of this file; default under temp.")] string? outputDirectory = null,
        [Description("Extract without loading the assemblies; default: loaded, ids in loadedAs.")] bool extractOnly = false,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description(LimitDescription)] int limit = 100,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
        {
            int step = 0;
            var report = await Task.Run(() => unpacker.Unpack(path, outputDirectory, !extractOnly, AnalysisLimits.Default, cancellationToken,
                message => progress.Report(new ProgressNotificationValue { Progress = ++step, Message = message })), cancellationToken);
            return ContainerText.Unpack(report, offset, ClampLimit(limit));
        });

    [McpServerTool(Name = "search_container", Title = "Search inside a container", UseStructuredContent = true, OutputSchemaType = typeof(UnpackService.ContainerSearch))]
    [Description("Find types and members by name in every managed assembly inside a container (bundle, .nupkg, .apk / .aab, Costura, zip, " +
                 "nested) or an assembly, without extracting: substring or * / ? wildcards, exact first. kind=file: inner " +
                 "file paths; packet: a pcap display filter; endpoint: endpoints the code names or a capture's requests.")]
    public async Task<string> SearchContainer(
        [Description("Container or assembly file (absolute).")] string path,
        [Description("Name or part of a name.")] string query,
        [Description("Restrict to this kind; omit for all members (events included).")] string? kind = null,
        [Description(LimitDescription)] int limit = 100,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("kind=endpoint: a HAR, mitmproxy, .saz or pcap capture to join.")] string? capture = null,
        CancellationToken cancellationToken = default)
    {
        var found = await Task.Run(() => unpacker.Search(path, query, kind, ClampLimit(limit), AnalysisLimits.Default, cancellationToken, offset, capture), cancellationToken);
        return ContainerText.Search(found, ClampLimit(limit));
    }
}
