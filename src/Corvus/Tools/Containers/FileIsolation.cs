using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native.Providers.Worker;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Native.Dump.Managed;

namespace Corvus.Tools;

/// <summary>
/// One file read that can run in the server or in a <c>corvus worker</c>: its op name and the work, given the services of
/// the process it runs in. Arguments and result cross the worker pipe as JSON.
/// </summary>
public sealed record FileOp<TArgs, TResult>(string Name, Func<IServiceProvider, TArgs, CancellationToken, TResult> Run);

/// <summary>
/// Runs the file tools' reads in the "files" worker (<see cref="WorkerPool"/>), so a file that crashes, overflows the stack
/// or exhausts memory in a reader ends the worker and not the server. The worker answers the same record the in-process
/// path builds, and the tool renders it in the server, so both paths give the same result. In process when
/// <see cref="ServerOptions.InProcessParsing"/> is set, the worker host is off, or a tool was made without options or a pool.
/// </summary>
public static class FileIsolation
{
    public const string Kind = "files";

    /// <summary>The longest a read may take when its call has no deadline; past it the worker is stopped.</summary>
    public static readonly TimeSpan OpLimit = TimeSpan.FromHours(1);

    /// <summary>Records and arguments cross the pipe in the tools' own serialization.</summary>
    internal static JsonSerializerOptions Json => Catalog.ToolSerializerOptions;

    /// <summary>The pool reads go to (a test's override first), or null when they stay in this process.</summary>
    public static WorkerPool? PoolFor(ServerOptions? options, WorkerPool? workers) =>
        options is { InProcessParsing: false } && (WorkerPool.Override ?? workers) is { Enabled: true } pool ? pool : null;

    /// <summary>
    /// The result of <paramref name="op"/> on <paramref name="args"/>: from the worker when <see cref="Isolated"/>, else
    /// from <paramref name="inProcess"/>. <paramref name="file"/> names the input in a crash or limit error. A worker that
    /// cannot start is provider_unavailable naming <see cref="ServerOptions.InProcessParsingVariable"/>; one that crashes
    /// or reaches its memory limit fails the call with nothing from the read kept.
    /// </summary>
    public static async Task<TResult> RunAsync<TArgs, TResult>(ServerOptions? options, WorkerPool? workers, FileOp<TArgs, TResult> op, TArgs args, string file,
        Func<TResult> inProcess, CancellationToken cancellationToken)
    {
        if (PoolFor(options, workers) is not { } pool) return await Task.Run(inProcess, cancellationToken);
        try { await pool.StartAsync(Kind, cancellationToken); }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            throw new ToolError(ErrorCode.ProviderUnavailable, $"The file worker could not start, so {file} was not read: {e.Message}",
                $"set {ServerOptions.InProcessParsingVariable}=1 (or pass {ServerOptions.InProcessParsingOption}) to read files in the server process");
        }
        JsonElement answer;
        try { answer = await pool.RunAsync(Kind, op.Name, (JsonObject)JsonSerializer.SerializeToNode(args, Json)!, OpLimit, cancellationToken, file); }
        catch (ToolError e) when (e.Code == ErrorCode.ProviderUnavailable)
        {
            throw new ToolError(ErrorCode.ProviderUnavailable, $"Reading {file} ('{op.Name}') ended the file worker; nothing from that read is kept. {e.Message}",
                "the file stops this reader, while other files and calls still work; if the file is valid, report its type and size") { Retryable = false };
        }
        return FileOps.Unwrap<TResult>(answer);
    }
}

/// <summary>
/// The file reads a <c>corvus worker</c> answers. Each runs the same <see cref="FileOp{TArgs, TResult}"/> as the server's
/// in-process path, over this process's own services, and answers {result} or the error the server would have shown:
/// {error} for a <see cref="ToolError"/> (a path the file system rejects included), {exception} for any other failure.
/// Running out of memory and cancellation are left to the worker host.
/// </summary>
internal sealed class FileOps : IWorkerOps
{
    private static readonly Lazy<ServiceProvider> Services = new(() =>
    {
        var options = ServerOptions.Parse([]);
        options.InProcessParsing = true;
        options.BackgroundIndexing = false;
        options.WatchFiles = false;
        return ServerHost.AddServices(new ServiceCollection().AddLogging(), options).BuildServiceProvider();
    });

    public IReadOnlyDictionary<string, WorkerOp> Ops => new Dictionary<string, WorkerOp>(StringComparer.Ordinal)
    {
        [FileWork.Summarize.Name] = Op(FileWork.Summarize),
        [FileWork.List.Name] = Op(FileWork.List),
        [FileWork.Search.Name] = Op(FileWork.Search),
        [FileWork.Extract.Name] = Op(FileWork.Extract),
        [FileWork.DumpView.Name] = Op(FileWork.DumpView),
        [FileWork.DumpRead.Name] = Op(FileWork.DumpRead),
        [FileWork.DumpHeap.Name] = Op(FileWork.DumpHeap),
        [FileWork.DumpObject.Name] = Op(FileWork.DumpObject),
    };

    /// <summary>Tests: a file that starts with a <see cref="FixtureMarker"/> line makes the read fail that way.</summary>
    private static readonly bool Fixtures = Environment.GetEnvironmentVariable(WorkerHost.FixtureOpsVariable) == "1";

    /// <summary>Followed by exit, stack, allocate or loop: the failure a fixture file asks for.</summary>
    public const string FixtureMarker = "corvus-worker-fixture:";

    private static WorkerOp Op<TArgs, TResult>(FileOp<TArgs, TResult> op) => (args, cancellationToken) => Task.Run<JsonNode?>(() =>
    {
        if (Fixtures && ((string?)args["path"] ?? (string?)args["dump"]?["path"]) is { } path) Fault(path);
        try
        {
            var result = op.Run(Services.Value, args.Deserialize<TArgs>(FileIsolation.Json)!, cancellationToken);
            return new JsonObject { ["result"] = JsonSerializer.SerializeToNode(result, FileIsolation.Json) };
        }
        catch (ToolError e) { return new JsonObject { ["error"] = Error(e) }; }
        catch (Exception e) when (ArgumentCheck.FileSystemError(e) is { } error) { return new JsonObject { ["error"] = Error(error) }; }
        catch (Exception e) when (e is not (OutOfMemoryException or OperationCanceledException))
        {
            return new JsonObject { ["exception"] = new JsonObject { ["type"] = e.GetType().Name, ["message"] = e.Message } };
        }
    }, cancellationToken);

    private static void Fault(string path)
    {
        string head;
        try { head = File.Exists(path) ? File.ReadLines(path).FirstOrDefault() ?? "" : ""; }
        catch (IOException) { return; }
        if (!head.StartsWith(FixtureMarker, StringComparison.Ordinal)) return;
        switch (head[FixtureMarker.Length..].Trim())
        {
            case "exit": Environment.FailFast("fixture: the reader ends the worker"); break;
            case "stack": Recurse(0); break;
            case "allocate":
                var kept = new List<byte[]>();
                while (true)
                {
                    var block = new byte[16 << 20];
                    for (int i = 0; i < block.Length; i += 4096) block[i] = 1;
                    kept.Add(block);
                }
            case "loop":
                // Ignores cancellation, as a reader stuck in a loop would.
                while (true) Thread.SpinWait(1000);
        }
    }

    private static int Recurse(int depth) => Recurse(depth + 1) + 1;

    private static JsonObject Error(ToolError e) => new()
    {
        ["code"] = ToolError.CodeName(e.Code),
        ["message"] = e.Message,
        ["remediation"] = e.Remediation,
        ["retryable"] = e.Retryable,
        ["retryAfterMs"] = e.RetryAfter is { } wait ? (long)wait.TotalMilliseconds : null,
        ["partial"] = e.Partial is { } partial ? JsonSerializer.SerializeToNode(partial, partial.GetType(), ToolError.JsonOptions) : null,
        ["details"] = e.Details is { } details ? JsonSerializer.SerializeToNode(details, details.GetType(), ToolError.JsonOptions) : null,
    };

    /// <summary>A worker answer as the server's result, or the same error raised in the server.</summary>
    internal static TResult Unwrap<TResult>(JsonElement answer)
    {
        var node = JsonNode.Parse(answer.GetRawText()) as JsonObject ?? throw new ToolError(ErrorCode.Failed, "The file worker answered something that is not an object.");
        if (node["error"] is JsonObject e)
            throw new ToolError(Native.Providers.WorkerProtocol.MapCode((string?)e["code"]), (string?)e["message"] ?? "", (string?)e["remediation"])
            {
                Retryable = (bool?)e["retryable"] ?? false,
                RetryAfter = (long?)e["retryAfterMs"] is { } ms ? TimeSpan.FromMilliseconds(ms) : null,
                Partial = e["partial"]?.DeepClone(),
                Details = e["details"]?.DeepClone(),
            };
        if (node["exception"] is JsonObject x) throw new ForwardedException((string?)x["type"] ?? "Exception", (string?)x["message"] ?? "");
        return node["result"].Deserialize<TResult>(FileIsolation.Json)!;
    }
}

/// <summary>The file tools' reads, shared by the in-process path and the worker.</summary>
public static class FileWork
{
    public sealed record SummarizeArgs(string Path, string View, string? Table, string[]? Columns, long Offset, int? Limit, string? SbomPath = null,
        bool Overwrite = false, string? Script = null, string? StixPath = null);

    public sealed record ListArgs(string Path, string? Filter, int Offset, int Limit);

    public sealed record SearchArgs(string Path, string Query, string? Kind, int Limit, int Offset, string? Capture, bool Values);

    public sealed record ExtractArgs(string Path, string? OutputDirectory, string? KeyLog);

    /// <summary>summarize_file over a path: the overview or view record, layers with the app graph's facts.</summary>
    public static readonly FileOp<SummarizeArgs, FileSummaryRecord> Summarize = new("file_summarize",
        (services, a, ct) => SummarizeWith(services.GetRequiredService<InspectionService>(), services.GetService<Services.Mobile.AppGraph>(), a, ct));

    /// <summary>The managed assemblies or archive entries inside a container, one page, not extracted.</summary>
    public static readonly FileOp<ListArgs, UnpackService.ContainerListing> List = new("file_list",
        (services, a, ct) => services.GetRequiredService<UnpackService>().List(a.Path, AnalysisLimits.Default, ct, a.Filter, a.Offset, a.Limit));

    /// <summary>search_container: one page of matches.</summary>
    public static readonly FileOp<SearchArgs, UnpackService.ContainerSearch> Search = new("file_search",
        (services, a, ct) => services.GetRequiredService<UnpackService>().Search(a.Path, a.Query, a.Kind, a.Limit, AnalysisLimits.Default, ct, a.Offset, a.Capture, a.Values));

    /// <summary>unpack_container's reading half: the files written, nothing loaded.</summary>
    public static readonly FileOp<ExtractArgs, UnpackService.Extraction> Extract = new("file_extract",
        (services, a, ct) => services.GetRequiredService<UnpackService>().Extract(a.Path, a.OutputDirectory, AnalysisLimits.Default, ct, null, a.KeyLog));

    /// <summary>A dump the server resolved: the id it gave the file and the image folders it is read with.</summary>
    public sealed record DumpTarget(string Id, string Path, string? ImageDirectories);

    public sealed record DumpViewArgs(DumpTarget Dump, string View, int Offset, int Limit, string? DacPath, bool DownloadDac);

    public sealed record DumpReadArgs(DumpTarget Dump, string Address, int Length, bool ImageFallback);

    public sealed record DumpHeapArgs(DumpTarget Dump, string? Mode, string? Type, ulong MinSize, int Offset, int Limit, long MaxObjects);

    public sealed record DumpObjectArgs(DumpTarget Dump, string Address, int Depth, int MaxFields, int MaxArrayItems);

    /// <summary>One open_minidump view: the summary, or the id, one page of rows and the total of a list view.</summary>
    public sealed record DumpViewResult(MinidumpService.DumpReport? Summary, string? Id, int Total)
    {
        public IReadOnlyList<MinidumpService.ModuleSummary>? Modules { get; init; }
        public IReadOnlyList<MinidumpService.ThreadSummary>? Threads { get; init; }
        public IReadOnlyList<MinidumpService.MemoryRow>? Memory { get; init; }
        public IReadOnlyList<MinidumpService.UnloadedModuleSummary>? Unloaded { get; init; }
    }

    /// <summary>open_minidump: one view of a dump.</summary>
    public static readonly FileOp<DumpViewArgs, DumpViewResult> DumpView = new("dump_view",
        (services, a, ct) => ViewOf(Pinned(services, a.Dump), a, ct));

    /// <summary>read_dump_memory: the bytes at an address and what is there.</summary>
    internal static readonly FileOp<DumpReadArgs, MinidumpService.MemoryBytes> DumpRead = new("dump_read",
        (services, a, ct) => Pinned(services, a.Dump).ReadBytes(a.Dump.Id, a.Address, a.Length, a.ImageFallback, ct).GetAwaiter().GetResult());

    /// <summary>dump_heap on a dump file.</summary>
    public static readonly FileOp<DumpHeapArgs, MinidumpService.HeapReport> DumpHeap = new("dump_heap",
        (services, a, ct) => Pinned(services, a.Dump).Heap(a.Dump.Id, a.Mode, a.Type, a.MinSize, a.Offset, a.Limit, a.MaxObjects, ct).GetAwaiter().GetResult());

    /// <summary>dump_object on a dump file.</summary>
    public static readonly FileOp<DumpObjectArgs, MinidumpService.ObjectReport> DumpObject = new("dump_object",
        (services, a, ct) => Pinned(services, a.Dump).Object(a.Dump.Id, a.Address, a.Depth, a.MaxFields, a.MaxArrayItems, ct).GetAwaiter().GetResult());

    private static MinidumpService Pinned(IServiceProvider services, DumpTarget dump)
    {
        var dumps = services.GetRequiredService<MinidumpService>();
        dumps.Pin(dump.Id, dump.Path, dump.ImageDirectories);
        return dumps;
    }

    /// <summary>One open_minidump view through <paramref name="dumps"/>, which knows the dump by <see cref="DumpTarget.Id"/>.</summary>
    public static DumpViewResult ViewOf(MinidumpService dumps, DumpViewArgs a, CancellationToken ct)
    {
        var id = a.Dump.Id;
        var directories = a.Dump.ImageDirectories;
        switch (a.View)
        {
            case "summary":
                var report = dumps.Summarize(id, directories, new DacRequest(string.IsNullOrWhiteSpace(a.DacPath) ? null : a.DacPath, a.DownloadDac), ct).GetAwaiter().GetResult();
                return new DumpViewResult(report, null, 0);
            case "modules":
                var (mId, modules, mTotal) = dumps.Modules(id, directories, a.Offset, a.Limit);
                return new DumpViewResult(null, mId, mTotal) { Modules = modules };
            case "threads":
                var (tId, threads, tTotal) = dumps.Threads(id, directories, a.Offset, a.Limit, ct).GetAwaiter().GetResult();
                return new DumpViewResult(null, tId, tTotal) { Threads = threads };
            case "memory":
                var (rId, memory, rTotal) = dumps.Memory(id, a.Offset, a.Limit);
                return new DumpViewResult(null, rId, rTotal) { Memory = memory };
            case "unloaded":
                var (uId, unloaded, uTotal) = dumps.Unloaded(id, a.Offset, a.Limit);
                return new DumpViewResult(null, uId, uTotal) { Unloaded = unloaded };
            default:
                throw new ToolError(ErrorCode.InvalidArgument, $"Unknown view '{a.View}'.", "pass view as one of " + string.Join(", ", MinidumpService.Views));
        }
    }

    /// <summary>The summary record of a path, as summarize_file shows it.</summary>
    public static FileSummaryRecord SummarizeWith(InspectionService inspection, Services.Mobile.AppGraph? graph, SummarizeArgs a, CancellationToken ct)
    {
        var summary = inspection.Summarize(null, a.Path, ct, new FileViewOptions(a.View, a.Table, a.Columns, a.Offset, a.Limit) { Sbom = a.SbomPath != null, Stix = a.StixPath != null, Script = a.Script });
        var record = ContainerText.Summary(summary, a.View);
        if (a.SbomPath != null) record = record with { Notes = [.. record.Notes ?? [], WriteSbom(summary, a.SbomPath, a.Overwrite)] };
        if (a.StixPath != null) record = record with { Notes = [.. record.Notes ?? [], WriteStix(summary, a.StixPath, a.Overwrite)] };
        if (a.View == "layers" && graph != null)
        {
            var facts = graph.Build(summary.File.Path, (int)Math.Min(a.Offset, int.MaxValue), a.Limit ?? Services.Mobile.AppGraph.DefaultLimit, ct);
            record = record with { Detail = ToolOutput.Serialize(facts) as JsonObject };
        }
        return record;
    }

    /// <summary>Writes the dependencies view to <paramref name="sbomPath"/> (an existing file is refused unless <paramref name="overwrite"/>) and returns the note naming it.</summary>
    public static string WriteSbom(InspectionService.FileSummary summary, string sbomPath, bool overwrite)
    {
        if (summary.Views.GetValueOrDefault("dependencies")?.Detail is not Services.Analysis.Dependencies.DependencyFacts facts)
            throw new ToolError(ErrorCode.NotFound, "found no component in the file, so no SBOM was written.", "pass path= with a .NET app, bundle or package, or a Go or Rust program");
        var bytes = Services.Analysis.Dependencies.CycloneDx.Write(facts, summary.File.Path, summary.File.Sha256, ServerIdentity.InformationalVersion,
            DateTimeOffset.UtcNow, Guid.NewGuid());
        var full = SafeFile.WriteAllBytes(sbomPath, bytes, overwrite);
        return $"CycloneDX {Services.Analysis.Dependencies.CycloneDx.SpecVersion} SBOM written to {full}: {facts.ComponentTotal} components, {facts.WithPurl} with a package URL.";
    }

    /// <summary>Writes the summary as a STIX 2.1 bundle to <paramref name="stixPath"/> (an existing file is refused unless <paramref name="overwrite"/>) and returns the note naming it.</summary>
    public static string WriteStix(InspectionService.FileSummary summary, string stixPath, bool overwrite)
    {
        var bytes = Services.Analysis.StixBundle.Write(summary, ServerIdentity.InformationalVersion, DateTimeOffset.UtcNow, Guid.NewGuid(), Guid.NewGuid());
        var full = SafeFile.WriteAllBytes(stixPath, bytes, overwrite);
        using var bundle = JsonDocument.Parse(bytes);
        return $"STIX {Services.Analysis.StixBundle.SpecVersion} bundle written to {full}: {bundle.RootElement.GetProperty("objects").GetArrayLength()} objects.";
    }
}
