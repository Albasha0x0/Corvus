using System.Collections.Concurrent;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Services.Analysis;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class UnpackTools(UnpackService unpacker, ServerOptions? options = null, Native.Providers.Worker.WorkerPool? workers = null, ResultStore? results = null)
{
    [McpServerTool(Name = "unpack_container", Title = "Extract container", UseStructuredContent = true, OutputSchemaType = typeof(UnpackPage))]
    [Description("Extract a container, load its .NET assemblies: single-file bundles, Costura, .nupkg, .apk, .aab, zips, " +
                 ".asar, captures (HAR, pcap), JS bundles with source maps, single compressed streams. Nothing runs; runnable and shell-parsed names get .bin. " +
                 "algorithm: cipher dry run. A repeat call pages the kept report.")]
    public Task<string> UnpackContainer(
        [Description("Container file, Blazor or ClickOnce folder.")] string path,
        [Description("Empty directory or earlier extract; default: temp.")] string? outputDirectory = null,
        [Description("Extract without loading; ids are in loadedAs.")] bool extractOnly = false,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description(LimitDescription)] int limit = 100,
        [Description("TLS key log (SSLKEYLOGFILE) to decrypt a pcap.")] string? keyLog = null,
        [Description("Password of encrypted zip, 7z, RAR, PDF, Office document; only it is tried.")] string? password = null,
        [Description("aes-128 or blowfish.")] string? algorithm = null,
        [Description("ecb (default) or cbc.")] string? mode = null,
        [Description("JSON: key, iv, expected (hex), direction, padding, offset, length.")] string? parameterFile = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
        {
            if (algorithm == null && (mode != null || parameterFile != null))
                throw new ToolError(ErrorCode.InvalidArgument, "mode and parameterFile apply to a dry run only.", "pass algorithm as aes-128 or blowfish, or omit mode and parameterFile");
            if (algorithm != null)
            {
                if (outputDirectory != null || extractOnly || keyLog != null || password != null)
                    throw new ToolError(ErrorCode.InvalidArgument, "algorithm runs a dry run that extracts nothing; outputDirectory, extractOnly, keyLog and password do not apply.", "omit those parameters, or omit algorithm to extract");
                return await Task.Run(() => ContainerText.Transform(TransformVerifier.Run(path, algorithm, mode, parameterFile, cancellationToken)), cancellationToken);
            }
            // A repeat call pages the kept report; a concurrent one joins the
            // running extraction.
            var key = results != null && File.Exists(path) ? ReportKey(path, outputDirectory, extractOnly, keyLog, password) : null;
            async Task<(UnpackService.UnpackReport Report, string? Id)> Produce()
            {
                int step = 0;
                void Report(string message) => progress.Report(new ProgressNotificationValue { Progress = ++step, Message = message });
                // The worker writes the files; loading them stays here, where the workspace is.
                // A sandboxed worker writes only under labelled folders: it extracts to a staging folder and the server fills the named one.
                var staging = outputDirectory != null && FileIsolation.PoolFor(options, workers) is { Sandboxed: true } ? StagedExtraction.NewStaging() : null;
                var args = new FileWork.ExtractArgs(path, staging ?? outputDirectory, keyLog, password);
                Func<UnpackService.Extraction> extract = () => unpacker.Extract(path, outputDirectory, AnalysisLimits.Default, cancellationToken, Report, keyLog, password);
                var extraction = await FileIsolation.RunAsync(options, workers, FileWork.Extract, args, path, extract, cancellationToken);
                if (staging != null) extraction = StagedExtraction.Place(extraction, staging, outputDirectory!);
                var made = await Task.Run(() => unpacker.Finish(extraction, !extractOnly, Report), cancellationToken);
                return (made, key != null ? unpacker.Keep(results!, key, made) : null);
            }
            async Task<(UnpackService.UnpackReport Report, string? Id)> Shared()
            {
                try { return await Produce(); }
                finally { _running.TryRemove(key!, out _); }
            }
            (UnpackService.UnpackReport Report, string? Id) page;
            while (true)
            {
                if (key != null && unpacker.KeptReport(results!, key) is { } held) { page = (held.Report, held.Id); break; }
                if (key == null) { page = await Produce(); break; }
                try
                {
                    page = await _running.GetOrAdd(key, _ => new Lazy<Task<(UnpackService.UnpackReport Report, string? Id)>>(Shared)).Value.WaitAsync(cancellationToken);
                    break;
                }
                // The call that ran the extraction was cancelled, not this one.
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { }
            }
            var (report, resultId) = page;
            return ContainerText.Unpack(report, offset, ClampLimit(limit), resultId);
        });

    [McpServerTool(Name = "search_container", Title = "Search inside a container", UseStructuredContent = true, OutputSchemaType = typeof(UnpackService.ContainerSearch))]
    [Description("Find managed types and members by name in a container or assembly, without extracting. " +
                 "Other kinds: paths, pcap packets, endpoints, capture requests, JS features, YARA rules, locked packages, incident lists.")]
    public async Task<string> SearchContainer(
        [Description("Container or assembly file (absolute).")] string path,
        [Description("Name, substring or * ? wildcards; packet: display filter; feature: JS text; yara: rule file, folder or text.")] string query,
        [Description("Kind to restrict to; omit: all members.")] string? kind = null,
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

    private readonly ConcurrentDictionary<string, Lazy<Task<(UnpackService.UnpackReport Report, string? Id)>>> _running = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> _hashes = new(StringComparer.Ordinal);

    // Hashed so a password is not held in the map; the file hash is reused
    // while its path, length and write time are unchanged.
    private string ReportKey(string path, string? outputDirectory, bool extractOnly, string? keyLog, string? password)
    {
        var info = new FileInfo(path);
        var stamp = $"{info.FullName}|{info.Length}|{info.LastWriteTimeUtc.Ticks}";
        if (!_hashes.TryGetValue(stamp, out var sha))
        {
            using var stream = File.OpenRead(path);
            sha = _hashes[stamp] = Convert.ToHexStringLower(SHA256.HashData(stream));
        }
        var folder = outputDirectory != null ? Path.GetFullPath(outputDirectory) : null;
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('|', sha, folder, extractOnly, keyLog, password))));
    }
}
