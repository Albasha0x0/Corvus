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
/// A file read of <paramref name="Tool"/> that runs in the server or a
/// <c>corvus worker</c>; arguments and result cross the pipe as JSON.
/// </summary>
public sealed record FileOp<TArgs, TResult>(string Name, string Tool, Func<IServiceProvider, TArgs, CancellationToken, TResult> Run);

/// <summary>Runs file reads in the "files" worker so a crashing reader ends the worker, not the server; in process when <see cref="ServerOptions.InProcessParsing"/> is set or no pool is given.</summary>
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

    /// <summary>The result of <paramref name="op"/>, from the worker when one is enabled; a worker that cannot start or crashes fails the call as provider_unavailable.</summary>
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
                "other files and calls still work; if the file is valid, report its type and size") { Retryable = false };
        }
        return FileOps.Unwrap<TResult>(answer);
    }
}

/// <summary>The file reads a <c>corvus worker</c> answers: {result}, {error} for a <see cref="ToolError"/>, or {exception}.</summary>
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

    /// <summary>
    /// The op table: each op's name, the tool it reads for, and its worker
    /// entry.
    /// </summary>
    private static readonly (string Name, string Tool, WorkerOp Op)[] Table =
    [
        Entry(FileWork.Summarize), Entry(FileWork.List), Entry(FileWork.Search), Entry(FileWork.Extract),
        Entry(FileWork.DumpView), Entry(FileWork.DumpRead), Entry(FileWork.DumpHeap), Entry(FileWork.DumpObject),
        Entry(FileWork.DumpStack), Entry(FileWork.DumpBuckets), Entry(FileWork.Symbolize),
    ];

    private static (string, string, WorkerOp) Entry<TArgs, TResult>(FileOp<TArgs, TResult> op) => (op.Name, op.Tool, Op(op));

    public IReadOnlyDictionary<string, WorkerOp> Ops => Table.ToDictionary(e => e.Name, e => e.Op, StringComparer.Ordinal);

    /// <summary>
    /// The tools whose file reads the worker answers, in op table order.
    /// </summary>
    internal static IReadOnlyList<string> WorkerTools => [.. Table.Select(e => e.Tool).Distinct()];

    /// <summary>Tests: a file that starts with a <see cref="FixtureMarker"/> line makes the read fail that way.</summary>
    private static readonly bool Fixtures = Environment.GetEnvironmentVariable(WorkerHost.FixtureOpsVariable) == "1";

    /// <summary>Followed by exit, stack, allocate or loop: the failure a fixture file asks for.</summary>
    public const string FixtureMarker = "corvus-worker-fixture:";

    private static WorkerOp Op<TArgs, TResult>(FileOp<TArgs, TResult> op) => (args, cancellationToken) => Task.Run<JsonNode?>(() =>
    {
        if (Fixtures && ((string?)args["path"] ?? (string?)args["dump"]?["path"]) is { } path) Fault(path);
        if (Fixtures && (string?)args["folder"] is { } folder && Directory.Exists(folder))
            foreach (var file in Directory.EnumerateFiles(folder)) Fault(file);
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
    public static readonly FileOp<SummarizeArgs, FileSummaryRecord> Summarize = new("file_summarize", "summarize_file",
        (services, a, ct) => SummarizeWith(services.GetRequiredService<InspectionService>(), services.GetService<Services.Mobile.AppGraph>(), a, ct));

    /// <summary>The managed assemblies or archive entries inside a container, one page, not extracted.</summary>
    public static readonly FileOp<ListArgs, UnpackService.ContainerListing> List = new("file_list", "list_assemblies",
        (services, a, ct) => services.GetRequiredService<UnpackService>().List(a.Path, AnalysisLimits.Default, ct, a.Filter, a.Offset, a.Limit));

    /// <summary>search_container: one page of matches.</summary>
    public static readonly FileOp<SearchArgs, UnpackService.ContainerSearch> Search = new("file_search", "search_container",
        (services, a, ct) => services.GetRequiredService<UnpackService>().Search(a.Path, a.Query, a.Kind, a.Limit, AnalysisLimits.Default, ct, a.Offset, a.Capture, a.Values));

    /// <summary>unpack_container's reading half: the files written, nothing loaded.</summary>
    public static readonly FileOp<ExtractArgs, UnpackService.Extraction> Extract = new("file_extract", "unpack_container",
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
    public static readonly FileOp<DumpViewArgs, DumpViewResult> DumpView = new("dump_view", "open_minidump",
        (services, a, ct) => ViewOf(Pinned(services, a.Dump), a, ct));

    /// <summary>read_dump_memory: the bytes at an address and what is there.</summary>
    internal static readonly FileOp<DumpReadArgs, MinidumpService.MemoryBytes> DumpRead = new("dump_read", "read_dump_memory",
        (services, a, ct) => Pinned(services, a.Dump).ReadBytes(a.Dump.Id, a.Address, a.Length, a.ImageFallback, ct).GetAwaiter().GetResult());

    /// <summary>dump_heap on a dump file.</summary>
    public static readonly FileOp<DumpHeapArgs, MinidumpService.HeapReport> DumpHeap = new("dump_heap", "dump_heap",
        (services, a, ct) => Pinned(services, a.Dump).Heap(a.Dump.Id, a.Mode, a.Type, a.MinSize, a.Offset, a.Limit, a.MaxObjects, ct).GetAwaiter().GetResult());

    /// <summary>dump_object on a dump file.</summary>
    public static readonly FileOp<DumpObjectArgs, MinidumpService.ObjectReport> DumpObject = new("dump_object", "dump_object",
        (services, a, ct) => Pinned(services, a.Dump).Object(a.Dump.Id, a.Address, a.Depth, a.MaxFields, a.MaxArrayItems, ct).GetAwaiter().GetResult());

    public sealed record StackArgs(DumpTarget Dump, string? Thread, bool ExceptionContext, int MaxFrames, int Offset, int Limit, bool Managed);

    public sealed record BucketArgs(string Folder, bool Recursive, string? Pattern, int TopFrames, string? SkipModules, bool SplitByVersion, bool Managed,
        int MaxDumps, string? ImageDirectories, int Offset, int Limit);

    public sealed record SymbolizeArgs(string? Text, string? Path, string? Format, string? Images, string? ModuleBases, int Offset, int Limit, bool Compact);

    /// <summary>The buckets of a folder and the path behind each dump id they name.</summary>
    public sealed record BucketResult(MinidumpService.DumpBuckets Buckets, IReadOnlyDictionary<string, string> Paths);

    /// <summary>dump_stack on a dump file.</summary>
    public static readonly FileOp<StackArgs, MinidumpService.StackReport> DumpStack = new("dump_stack", "dump_stack",
        (services, a, ct) => Pinned(services, a.Dump).Stack(a.Dump.Id, a.Thread, a.ExceptionContext, a.MaxFrames, a.Offset, a.Limit, a.Dump.ImageDirectories, a.Managed, ct)
            .GetAwaiter().GetResult());

    /// <summary>bucket_minidumps over a folder; the ids are the worker's, with their paths.</summary>
    public static readonly FileOp<BucketArgs, BucketResult> DumpBuckets = new("dump_buckets", "bucket_minidumps",
        (services, a, ct) => BucketsOf(services.GetRequiredService<MinidumpService>(), a, null, ct));

    /// <summary>symbolize_stack_text over crash text or a log file.</summary>
    public static readonly FileOp<SymbolizeArgs, StackTextService.SymbolizedStack> Symbolize = new("stack_symbolize", "symbolize_stack_text",
        (services, a, ct) => SymbolizeWith(services.GetRequiredService<StackTextService>(), a, ct));

    /// <summary>The buckets of a folder with the path of every id they name; <paramref name="progress"/> counts dumps.</summary>
    public static BucketResult BucketsOf(MinidumpService dumps, BucketArgs a, Action<int, int>? progress, CancellationToken ct)
    {
        var buckets = dumps.Bucket(a.Folder, a.Recursive, a.Pattern, a.TopFrames, a.SkipModules, a.SplitByVersion, a.Managed, a.MaxDumps, a.ImageDirectories, a.Offset, a.Limit,
            progress, ct).GetAwaiter().GetResult();
        var paths = buckets.Items.SelectMany(b => b.Sample.Append(b.Representative)).Distinct()
            .Select(id => (id, path: dumps.PathOf(id))).Where(e => e.path != null).ToDictionary(e => e.id, e => e.path!);
        return new BucketResult(buckets, paths);
    }

    /// <summary>The symbolized rows of crash text through <paramref name="stacks"/>.</summary>
    public static StackTextService.SymbolizedStack SymbolizeWith(StackTextService stacks, SymbolizeArgs a, CancellationToken ct) =>
        stacks.Symbolize(a.Text, a.Path, a.Format, a.Images, a.ModuleBases, a.Offset, a.Limit, a.Compact, ct).GetAwaiter().GetResult();

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
            throw new ToolError(ErrorCode.NotFound, "Found no component in the file; no SBOM written.", "pass path= with a .NET app, bundle or package, or a Go or Rust program");
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
