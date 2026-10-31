using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;

namespace Corvus.Mcp;

/// <summary>The MCP server host: services, catalog and request filters, with the transport chosen by the caller.</summary>
public static class ServerHost
{
    /// <summary>Builds the host; <paramref name="transport"/> adds the transport (stdio for the server, streams in process).</summary>
    public static IHost Build(ServerOptions options, string instructions, Action<IMcpServerBuilder> transport)
    {
        // Stdout carries the protocol, so logging goes to stderr; no config files or content root in the client's folder,
        // since reading it slows startup and lets a stray appsettings.json change the server.
        var builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings { Args = [], ContentRootPath = AppContext.BaseDirectory });
        builder.Logging.ClearProviders();
        builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);
        // One line per entry, UTC; CORVUS_LOG_FORMAT=json writes JSON lines with each value as its own field.
        if (Environment.GetEnvironmentVariable(ServerOptions.LogFormatVariable)?.Trim().Equals("json", StringComparison.OrdinalIgnoreCase) == true)
            builder.Logging.AddJsonConsole(o => { o.UseUtcTimestamp = true; o.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ"; });
        else
            builder.Logging.AddSimpleConsole(o => { o.SingleLine = true; o.UseUtcTimestamp = true; o.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ "; });
        builder.Logging.SetMinimumLevel(options.LogLevel);

        AddServices(builder.Services, options);

        var server = builder.Services
            .AddMcpServer(o =>
            {
                o.ServerInfo = new Implementation
                {
                    Name = "corvus",
                    Title = ServerIdentity.Product,
                    Version = typeof(ServerOptions).Assembly.GetName().Version?.ToString(3) ?? "1.0.0",
                };
                o.ServerInstructions = instructions;
            });
        transport(server);
        server
            // Tools (annotations from Mcp/ToolEffects.cs), resources and prompts.
            .WithCatalog()
            .WithCompleteHandler((context, _) =>
                ValueTask.FromResult(Completions.Complete(context.Services!.GetRequiredService<AssemblyWorkspace>(), context.Params!,
                    context.Services!.GetRequiredService<MinidumpService>().OpenIds)))
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
            // Requests that read the workspace wait for the --load paths, so a call right after initialize sees them;
            // the wait is inside the call filters, so it is traced, bounded and cancelled like the call.
            .WithRequestFilters(filters => filters
                .AddCallToolFilter(CallFilter.Wrap).AddReadResourceFilter(ProtocolFilter.ReadResource)
                .AddGetPromptFilter(ProtocolFilter.GetPrompt).AddCompleteFilter(ProtocolFilter.Complete)
                .AddCallToolFilter(AfterPreload).AddReadResourceFilter(AfterPreload).AddGetPromptFilter(AfterPreload).AddCompleteFilter(AfterPreload))
            .WithMessageFilters(filters => filters.AddIncomingFilter(next => async (context, ct) =>
                await context.Services!.GetRequiredService<ResourceSubscriptions>().ListenFilter(next)(context, ct)));

        // Registered after the server: the transport is up first.
        builder.Services.AddSingleton<PreloadRun>();
        builder.Services.AddHostedService(sp => new PreloadStarter(sp.GetRequiredService<PreloadRun>(), sp.GetRequiredService<AssemblyWorkspace>(),
            sp.GetRequiredService<ILogger<AssemblyWorkspace>>(), options));

        var host = builder.Build();
        // The tools and the full tools/list are made while the rest starts; the transport's first request waits for them.
        _ = Task.Run(() =>
        {
            // A failure here shows again, and is reported, where the transport makes the same objects.
            try
            {
                if (host.Services.GetService<Microsoft.Extensions.Options.IOptions<McpServerOptions>>()?.Value is { ToolCollection: not null } mcp) ToolListCache.For(mcp, null);
            }
            catch (Exception) { }
        });
        // Resolve before preloading so preloaded assemblies are indexed and watched.
        host.Services.GetRequiredService<IndexingService>();
        host.Services.GetRequiredService<NativeCodeService>();
        // PDBs are read during index builds, --prewarm analyzes preloaded images, and journals of earlier sessions are offered.
        host.Services.GetRequiredService<PdbService>();
        host.Services.GetRequiredService<NativeEngineService>();
        host.Services.GetRequiredService<EditJournal>();
        var subscriptions = host.Services.GetRequiredService<ResourceSubscriptions>();
        host.Services.GetRequiredService<FileWatchService>().Changed += _ => subscriptions.Check();
        return host;
    }

    /// <summary>Registers the services the tools use; the server and a <c>corvus worker</c> share this list.</summary>
    internal static IServiceCollection AddServices(IServiceCollection services, ServerOptions options)
    {
        services
            .AddSingleton(options)
            .AddSingleton<AssemblyWorkspace>()
            .AddSingleton<OutputPager>()
            .AddSingleton<ResultStore>()
            .AddSingleton<RecentCalls>()
            .AddSingleton<CallActivity>()
            .AddSingleton<DecompilerService>()
            .AddSingleton<SearchService>()
            .AddSingleton<ReferenceService>()
            .AddSingleton<AotMetadataService>()
            .AddSingleton<AotStringService>()
            .AddSingleton<AotNavigator>()
            .AddSingleton<AotBuildLoader>()
            .AddSingleton<ResourceService>()
            .AddSingleton<AssemblyReport>()
            .AddSingleton<IlAssembler>()
            .AddSingleton<CSharpPatcher>()
            .AddSingleton<EditService>()
            .AddSingleton<EditHistoryService>()
            .AddSingleton<AssemblyComparer>()
            .AddSingleton<CallGraphService>()
            .AddSingleton<AotExporter>()
            .AddSingleton<CppBindingGenerator>()
            .AddSingleton<IndexingService>()
            .AddSingleton<FileWatchService>()
            .AddSingleton<UnpackService>()
            .AddSingleton<InspectionService>()
            // The file tools' workers end with the host that started them.
            .AddSingleton(_ => new Native.Providers.Worker.WorkerPool())
            .AddSingleton<Services.Analysis.FolderCompare>()
            .AddSingleton<NativeEngineService>()
            .AddSingleton<Corvus.Native.Annotations.AnnotationStore>()
            .AddSingleton<NativeCodeService>()
            .AddSingleton<NativeLinkService>()
            .AddSingleton<NativeEditJournal>()
            .AddSingleton<NativeEditService>()
            .AddSingleton<LiveSessionService>()
            .AddSingleton<AotNativeNames>()
            .AddSingleton<NativeNamePush>()
            .AddSingleton<NativeTypePush>()
            .AddSingleton<NativeUserTypePush>()
            .AddSingleton<ReadyToRunService>()
            .AddSingleton<PdbService>()
            .AddSingleton<MinidumpService>()
            .AddSingleton<NotesService>()
            .AddSingleton<EditJournal>()
            .AddSingleton<SessionService>()
            .AddSingleton<StackTextService>()
            .AddSingleton<LiveProcessService>()
            .AddSingleton<Services.Mobile.JavaDotNetMap>()
            .AddSingleton<Services.Mobile.DeviceService>()
            .AddSingleton<Services.Mobile.AndroidPackageService>()
            .AddSingleton<Services.Mobile.DexService>()
            .AddSingleton<Services.Mobile.JniBindings>()
            .AddSingleton<Services.Mobile.AppGraph>()
            .AddSingleton<Services.Mobile.AndroidProjectExport>()
            .AddSingleton<Services.Mobile.JavaDecompilerService>()
            .AddSingleton<ResourceSubscriptions>();
        return services;
    }

    private static bool IsZip(string path)
    {
        Span<byte> head = stackalloc byte[4];
        using var file = File.OpenRead(path);
        return file.Read(head) == 4 && head.SequenceEqual("PK\x03\x04"u8);
    }

    // A failed or cancelled preload has already left its notices; the request runs on what loaded.
    private static McpRequestHandler<TParams, TResult> AfterPreload<TParams, TResult>(McpRequestHandler<TParams, TResult> next) => async (context, ct) =>
    {
        try { await context.Services!.GetRequiredService<PreloadRun>().Completed.WaitAsync(ct); }
        catch (Exception) when (!ct.IsCancellationRequested) { }
        return await next(context, ct);
    };

    /// <summary>The background load of --load paths; <see cref="Completed"/> ends when every path has been tried.</summary>
    internal sealed class PreloadRun
    {
        /// <summary>The running load; already complete when nothing is preloaded.</summary>
        public Task Completed { get; internal set; } = Task.CompletedTask;
    }

    private sealed class PreloadStarter(PreloadRun run, AssemblyWorkspace workspace, ILogger log, ServerOptions options) : IHostedService
    {
        private readonly CancellationTokenSource _stop = new();

        public Task StartAsync(CancellationToken cancellationToken)
        {
            run.Completed = Task.Run(() => Preload(workspace, log, options, _stop.Token), CancellationToken.None);
            return Task.CompletedTask;
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            _stop.Cancel();
            try { await run.Completed.WaitAsync(cancellationToken); }
            catch (OperationCanceledException) { /* the host is not waiting longer */ }
        }
    }

    /// <summary>
    /// Loads each --load path and logs the result; a failed, partial or cancelled load queues a notice
    /// for the next tool result, a complete one stays silent.
    /// </summary>
    internal static void Preload(AssemblyWorkspace workspace, ILogger log, ServerOptions options, CancellationToken ct = default)
    {
        foreach (var path in options.Preload)
        {
            try
            {
                ct.ThrowIfCancellationRequested();
                if (Directory.Exists(path))
                {
                    var report = workspace.LoadDirectory(path, recursive: false, (_, _, _) => ct.ThrowIfCancellationRequested());
                    log.LogInformation("Preloaded {Count} assemblies from {Dir} ({Skipped} skipped)", report.Loaded.Count, path, report.Skipped.Count);
                    if (report.Skipped.Count > 0)
                        workspace.Notify($"Preloaded {report.Loaded.Count} assemblies from {path}, skipped {report.Skipped.Count}. Next: load_assembly path=\"{path}\" to see why.");
                }
                else
                {
                    try { workspace.LoadAny(path, null); } // a native PE, ELF or Mach-O loads as a native image, as with load_assembly
                    catch (ToolError) when (IsZip(path))
                    {
                        // A zip-family container (.vsix, .nupkg, .zip): its assemblies, as unpack_container loads them.
                        var report = new UnpackService(workspace).Unpack(path, null, load: true, AnalysisLimits.Default, ct);
                        log.LogInformation("Preloaded {Count} assemblies from {Container} ({Kind})", report.Files.Count(f => f.LoadedAs != null), path, report.Container);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                log.LogWarning("Preload of {Path} was cancelled", path);
                workspace.Notify($"Preload of {path} was cancelled. Next: load_assembly path=\"{path}\".");
            }
            catch (Exception ex)
            {
                log.LogWarning("Could not preload {Path}: {Message}", path, ex.Message);
                workspace.Notify($"Could not preload {path}: {ex.Message.TrimEnd('.')}. Next: load_assembly path=\"{path}\" after checking the path.");
            }
        }
    }
}
