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
builder.Logging.SetMinimumLevel(LogLevel.Information);

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
    .AddSingleton<PdbService>();

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
    // Serialize nulls explicitly: generated output schemas mark every property required, so omitted nulls fail validation.
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
            if (context.MatchedPrimitive is ModelContextProtocol.Server.McpServerTool tool)
                ArgumentCheck.Apply(tool.ProtocolTool.InputSchema, context.Params?.Arguments);
            var result = await next(context, cancellationToken);
            // Transformed names made of zero-width and bidi characters would print as nothing or scramble the line.
            foreach (var block in result.Content.OfType<TextContentBlock>())
                block.Text = NetDecompilerMcp.Core.Format.EscapeInvisible(block.Text);
            if (context.Services is { } services)
                result = ResponseBudget.Enforce(result, context.Params?.Name, services.GetRequiredService<ServerOptions>(),
                    services.GetRequiredService<ResultStore>(), context.Params);
            // Prepend pending workspace notices; trailing blank line because clients join content blocks without a separator.
            var notices = context.Services?.GetService<AssemblyWorkspace>()?.DrainNotices();
            if (notices is { Count: > 0 })
                result.Content.Insert(0, new TextContentBlock { Text = string.Join("\n", notices.Select(n => "[workspace] " + n)) + "\n\n" });
            return result;
        }
        catch (NetDecompilerMcp.Core.ToolError ex)
        {
            // Code, message and next step, with names made of invisible characters escaped as in results.
            return new CallToolResult
            {
                IsError = true,
                Content = [new TextContentBlock { Text = NetDecompilerMcp.Core.Format.EscapeInvisible(ex.Render(context.Params?.Name)) }],
            };
        }
        catch (ArgumentException ex) when (ex.ParamName == "arguments" && System.Text.RegularExpressions.Regex.Match(ex.Message, "required parameter '([^']+)'") is { Success: true } m)
        {
            // Argument binding: a required parameter is missing.
            return new CallToolResult
            {
                IsError = true,
                Content = [new TextContentBlock { Text = new NetDecompilerMcp.Core.ToolError(NetDecompilerMcp.Core.ErrorCode.InvalidArgument,
                    $"missing required parameter '{m.Groups[1].Value}'.").Render(context.Params?.Name) }],
            };
        }
        catch (Exception ex) when (ArgumentCheck.FileSystemError(ex) is { } error)
        {
            // A path argument System.IO rejected or could not reach.
            return new CallToolResult
            {
                IsError = true,
                Content = [new TextContentBlock { Text = NetDecompilerMcp.Core.Format.EscapeInvisible(error.Render(context.Params?.Name)) }],
            };
        }
        catch (Exception ex) when (ex is not McpException && ex is not OperationCanceledException)
        {
            // Return unexpected exceptions as a descriptive tool error instead of a generic protocol error.
            context.Services?.GetService<ILogger<AssemblyWorkspace>>()?.LogError(ex, "Tool {Tool} failed", context.Params?.Name);
            return new CallToolResult
            {
                IsError = true,
                Content = [new TextContentBlock { Text = $"Error (internal) in {context.Params?.Name}: {ex.GetType().Name}: {ex.Message}" }],
            };
        }
    }));

var host = builder.Build();
// Resolve before preloading so preloaded assemblies are indexed and watched.
host.Services.GetRequiredService<IndexingService>();
host.Services.GetRequiredService<NativeCodeService>();
host.Services.GetRequiredService<PdbService>(); // reads matching local PDBs during index builds
host.Services.GetRequiredService<NativeEngineService>(); // with --ida-prewarm, analyzes preloaded native images in the background
host.Services.GetRequiredService<FileWatchService>().Changed += _ => NotifyResourcesChanged(host.Services);
Preload(host.Services.GetRequiredService<AssemblyWorkspace>(), host.Services.GetRequiredService<ILogger<AssemblyWorkspace>>(), options);
await host.RunAsync();
return 0;

// Best effort; not all clients support notifications, so notices are also attached to the next tool result.
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
