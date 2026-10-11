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
            .AddSingleton<Corvus.Native.Annotations.AnnotationStore>()
            .AddSingleton<NativeCodeService>()
            .AddSingleton<NativeLinkService>()
            .AddSingleton<NativeEditService>()
            .AddSingleton<Il2CppNativeNames>()
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
            .AddSingleton<Services.Mobile.AndroidProjectExport>()
            .AddSingleton<Services.Mobile.JavaDecompilerService>()
            .AddSingleton<ResourceSubscriptions>();

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
            .WithRequestFilters(filters => filters.AddCallToolFilter(CallFilter.Wrap));

        var host = builder.Build();
        // Resolve before preloading so preloaded assemblies are indexed and watched.
        host.Services.GetRequiredService<IndexingService>();
        host.Services.GetRequiredService<NativeCodeService>();
        host.Services.GetRequiredService<PdbService>(); // reads matching local PDBs during index builds
        host.Services.GetRequiredService<NativeEngineService>(); // with --prewarm, analyzes preloaded native images in the background
        host.Services.GetRequiredService<EditJournal>(); // offers journals of earlier sessions for preloaded files
        var subscriptions = host.Services.GetRequiredService<ResourceSubscriptions>();
        host.Services.GetRequiredService<FileWatchService>().Changed += _ => subscriptions.Check();
        Preload(host.Services.GetRequiredService<AssemblyWorkspace>(), host.Services.GetRequiredService<ILogger<AssemblyWorkspace>>(), options);
        return host;
    }

    internal static void Preload(AssemblyWorkspace workspace, ILogger log, ServerOptions options)
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
                    workspace.LoadAny(path, null); // a native PE, ELF or Mach-O loads as a native image, as with load_assembly
                }
            }
            catch (Exception ex)
            {
                log.LogWarning("Could not preload {Path}: {Message}", path, ex.Message);
            }
        }
    }
}
