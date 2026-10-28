using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Services.Analysis;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class UnpackTools(UnpackService unpacker, ServerOptions? options = null, Native.Providers.Worker.WorkerPool? workers = null)
{
    [McpServerTool(Name = "unpack_container", Title = "Extract container", UseStructuredContent = true, OutputSchemaType = typeof(UnpackPage))]
    [Description("Extract a container and load the .NET assemblies inside: single-file bundles, Costura, .nupkg, .apk / .aab, zips, " +
                 ".asar, captures (HAR, pcap), JS bundles with source maps. Nothing runs; runnable and shell-parsed names get .bin.")]
    public Task<string> UnpackContainer(
        [Description("Container file, Blazor or ClickOnce folder.")] string path,
        [Description("New or empty directory, or an earlier extract of this file; default under temp.")] string? outputDirectory = null,
        [Description("Extract without loading the assemblies; default: loaded, ids in loadedAs.")] bool extractOnly = false,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description(LimitDescription)] int limit = 100,
        [Description("TLS key log of a pcap (SSLKEYLOGFILE) to decrypt with.")] string? keyLog = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
        {
            int step = 0;
            void Report(string message) => progress.Report(new ProgressNotificationValue { Progress = ++step, Message = message });
            // The worker writes the files; loading them stays here, where the workspace is.
            var args = new FileWork.ExtractArgs(path, outputDirectory, keyLog);
            Func<UnpackService.Extraction> extract = () => unpacker.Extract(path, outputDirectory, AnalysisLimits.Default, cancellationToken, Report, keyLog);
            var extraction = await FileIsolation.RunAsync(options, workers, FileWork.Extract, args, path, extract, cancellationToken);
            var report = await Task.Run(() => unpacker.Finish(extraction, !extractOnly, Report), cancellationToken);
            return ContainerText.Unpack(report, offset, ClampLimit(limit));
        });

    [McpServerTool(Name = "search_container", Title = "Search inside a container", UseStructuredContent = true, OutputSchemaType = typeof(UnpackService.ContainerSearch))]
    [Description("Find types and members by name in the managed assemblies inside a container or an assembly, without extracting. " +
                 "Other kinds search file paths, pcap packets, endpoints, capture requests, JS features or YARA rules.")]
    public async Task<string> SearchContainer(
        [Description("Container or assembly file (absolute).")] string path,
        [Description("Name, substring or * ? wildcards; packet: display filter; feature: JS text; yara: rule file, folder or text.")] string query,
        [Description("Restrict to this kind; omit for all members (events included).")] string? kind = null,
        [Description(LimitDescription)] int limit = 100,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("kind=endpoint: a HAR, mitmproxy, .saz or pcap capture to join, or compare if path is one.")] string? capture = null,
        [Description("kind=request: show header, cookie and query values.")] bool values = false,
        CancellationToken cancellationToken = default)
    {
        var args = new FileWork.SearchArgs(path, query, kind, ClampLimit(limit), offset, capture, values);
        Func<UnpackService.ContainerSearch> search = () => unpacker.Search(path, query, kind, ClampLimit(limit), AnalysisLimits.Default, cancellationToken, offset, capture, values);
        // kind=yara scans in a worker of its own, so it is not nested in a files worker.
        var isolated = string.Equals(kind?.Trim(), "yara", StringComparison.OrdinalIgnoreCase) ? null : workers;
        var found = await FileIsolation.RunAsync(options, isolated, FileWork.Search, args, path, search, cancellationToken);
        return ContainerText.Search(found, ClampLimit(limit));
    }
}
