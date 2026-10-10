using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Protocol;
using NetDecompilerMcp;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Services.Analysis;

if (NetDecompilerMcp.Setup.SetupCli.TryRun(args) is { } setupExitCode) return setupExitCode;

ServerOptions options;
try
{
    options = ServerOptions.Parse(args);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"net-decompiler: {ex.Message}");
    return 2;
}

// Parallel decompilation (export_project, comparisons) occupies a pool thread per core; spare threads let the transport
// read a cancellation or the next request at once instead of after the pool grows, which takes seconds.
ThreadPool.GetMinThreads(out var minWorkers, out var minIo);
ThreadPool.SetMinThreads(Math.Max(minWorkers, Environment.ProcessorCount * 2 + 8), minIo);

// Arguments are not passed to the host, and stdout carries the MCP protocol, so all logging goes to stderr.
// No configuration files and no content root in the client's working directory: clients start servers from any
// folder, and watching or reading it slows startup and lets a stray appsettings.json change the server.
var builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings { Args = [], ContentRootPath = AppContext.BaseDirectory });
builder.Logging.ClearProviders();
builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);
builder.Logging.SetMinimumLevel(options.LogLevel);

builder.Services
    .AddSingleton(options)
    .AddSingleton<AssemblyWorkspace>()
    .AddSingleton<OutputPager>()
    .AddSingleton<ResultStore>()
    .AddSingleton<DecompilerService>()
    .AddSingleton<SearchService>()
    .AddSingleton<ReferenceService>()
    .AddSingleton<Il2CppService>()
    .AddSingleton<Il2CppStringService>()
    .AddSingleton<Il2CppNavigator>()
    .AddSingleton<Il2CppRawLoader>()
    .AddSingleton<ResourceService>()
    .AddSingleton<AssemblyReport>()
    .AddSingleton<IlAssembler>()
    .AddSingleton<CSharpPatcher>()
    .AddSingleton<EditService>()
    .AddSingleton<EditHistoryService>()
    .AddSingleton<AssemblyComparer>()
    .AddSingleton<CallGraphService>()
    .AddSingleton<Il2CppExporter>()
    .AddSingleton<CppBindingGenerator>()
    .AddSingleton<IndexingService>()
    .AddSingleton<FileWatchService>()
    .AddSingleton<UnpackService>()
    .AddSingleton<InspectionService>()
    .AddSingleton<NativeEngineService>()
    .AddSingleton<NetDecompilerMcp.Native.Annotations.AnnotationStore>()
    .AddSingleton<NativeCodeService>()
    .AddSingleton<NativeLinkService>()
    .AddSingleton<NativeEditService>()
    .AddSingleton<Il2CppNativeNames>()
    .AddSingleton<NativeNamePush>()
    .AddSingleton<NativeTypePush>()
    .AddSingleton<ReadyToRunService>()
    .AddSingleton<PdbService>()
    .AddSingleton<MinidumpService>()
    .AddSingleton<LiveProcessService>()
    .AddSingleton<ResourceSubscriptions>();

builder.Services
    .AddMcpServer(o =>
    {
        o.ServerInfo = new Implementation
        {
            Name = "net-decompiler",
            Title = ".NET Decompiler",
            Version = typeof(ServerOptions).Assembly.GetName().Version?.ToString(3) ?? "1.0.0",
        };
        o.ServerInstructions = ServerInstructions.Text;
    })
    .WithStdioServerTransport()
    // Tools (annotations from Mcp/ToolEffects.cs), resources and prompts.
    .WithCatalog()
    .WithCompleteHandler((context, _) =>
        ValueTask.FromResult(Completions.Complete(context.Services!.GetRequiredService<AssemblyWorkspace>(), context.Params!)))
    .WithSubscribeToResourcesHandler((context, _) =>
    {
        context.Services!.GetRequiredService<ResourceSubscriptions>().Subscribe(context.Params!.Uri);
        return ValueTask.FromResult(new EmptyResult());
    })
    .WithUnsubscribeFromResourcesHandler((context, _) =>
    {
        context.Services!.GetRequiredService<ResourceSubscriptions>().Unsubscribe(context.Params!.Uri);
        return ValueTask.FromResult(new EmptyResult());
    })
    .WithRequestFilters(filters => filters.AddCallToolFilter(CallFilter.Wrap));

var host = builder.Build();
// Resolve before preloading so preloaded assemblies are indexed and watched.
host.Services.GetRequiredService<IndexingService>();
host.Services.GetRequiredService<NativeCodeService>();
host.Services.GetRequiredService<PdbService>(); // reads matching local PDBs during index builds
host.Services.GetRequiredService<NativeEngineService>(); // with --ida-prewarm, analyzes preloaded native images in the background
var subscriptions = host.Services.GetRequiredService<ResourceSubscriptions>();
host.Services.GetRequiredService<FileWatchService>().Changed += _ => subscriptions.Check();
Preload(host.Services.GetRequiredService<AssemblyWorkspace>(), host.Services.GetRequiredService<ILogger<AssemblyWorkspace>>(), options);
await host.RunAsync();
return 0;

static void Preload(AssemblyWorkspace workspace, ILogger log, ServerOptions options)
{
    foreach (var path in options.Preload)
    {
        try
        {
            if (Directory.Exists(path))
            {
                var report = workspace.LoadDirectory(path, recursive: false);
                log.LogInformation("Preloaded {Count} assemblies from {Dir} ({Skipped} skipped)", report.Loaded.Count, path, report.Skipped.Count);
            }
            else
            {
                workspace.Load(path);
            }
        }
        catch (Exception ex)
        {
            log.LogWarning("Could not preload {Path}: {Message}", path, ex.Message);
        }
    }
}
