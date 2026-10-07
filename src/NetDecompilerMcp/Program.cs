using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using NetDecompilerMcp;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Services.Analysis;

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

// The host must not parse our arguments, and stdout belongs to the MCP protocol: all logging goes to stderr.
var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { Args = [] });
builder.Logging.ClearProviders();
builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);
builder.Logging.SetMinimumLevel(LogLevel.Information);

builder.Services
    .AddSingleton(options)
    .AddSingleton<AssemblyWorkspace>()
    .AddSingleton<OutputPager>()
    .AddSingleton<DecompilerService>()
    .AddSingleton<SearchService>()
    .AddSingleton<ReferenceService>()
    .AddSingleton<Il2CppService>()
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
    .AddSingleton<InspectionService>();

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
    // Structured results: write null properties instead of omitting them. The generated output schemas list every
    // property as required (nullable ones as "type or null"), so an omitted null fails schema validation in clients.
    .WithToolsFromAssembly(serializerOptions: new System.Text.Json.JsonSerializerOptions(McpJsonUtilities.DefaultOptions)
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never,
    })
    .WithResourcesFromAssembly()
    .WithPromptsFromAssembly()
    .WithCompleteHandler((context, _) =>
        ValueTask.FromResult(Completions.Complete(context.Services!.GetRequiredService<AssemblyWorkspace>(), context.Params!)))
    .WithRequestFilters(filters => filters.AddCallToolFilter(next => async (context, cancellationToken) =>
    {
        try
        {
            var result = await next(context, cancellationToken);
            // Workspace events since the last call (files reloaded from disk...) ride along with the next result.
            var notices = context.Services?.GetService<AssemblyWorkspace>()?.DrainNotices();
            if (notices is { Count: > 0 })
                result.Content.Insert(0, new TextContentBlock { Text = string.Join("\n", notices.Select(n => "[workspace] " + n)) });
            return result;
        }
        catch (Exception ex) when (ex is not McpException && ex is not OperationCanceledException)
        {
            // Unexpected failure: tell the model what happened (instead of a generic error) and keep serving.
            context.Services?.GetService<ILogger<AssemblyWorkspace>>()?.LogError(ex, "Tool {Tool} failed", context.Params?.Name);
            return new CallToolResult
            {
                IsError = true,
                Content = [new TextContentBlock { Text = $"Internal error in {context.Params?.Name}: {ex.GetType().Name}: {ex.Message}" }],
            };
        }
    }));

var host = builder.Build();
// Created before preloading so the preloaded assemblies are indexed and watched too.
host.Services.GetRequiredService<IndexingService>();
host.Services.GetRequiredService<FileWatchService>().Changed += _ => NotifyResourcesChanged(host.Services);
Preload(host.Services.GetRequiredService<AssemblyWorkspace>(), host.Services.GetRequiredService<ILogger<AssemblyWorkspace>>(), options);
await host.RunAsync();
return 0;

// Best effort: tell the client that the resource list changed. The notice text itself rides along with the next tool
// result, which works with every client.
static void NotifyResourcesChanged(IServiceProvider services)
{
    if (services.GetService<ModelContextProtocol.Server.McpServer>() is not { } server) return;
    _ = Task.Run(async () =>
    {
        try
        {
            await server.SendNotificationAsync(NotificationMethods.ResourceListChangedNotification);
        }
        catch
        {
            // the client may not support notifications
        }
    });
}

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
