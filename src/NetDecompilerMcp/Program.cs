using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using NetDecompilerMcp;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Services;

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
    .AddSingleton<EditService>();

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
    .WithToolsFromAssembly()
    .WithResourcesFromAssembly()
    .WithPromptsFromAssembly()
    .WithCompleteHandler((context, _) =>
        ValueTask.FromResult(Completions.Complete(context.Services!.GetRequiredService<AssemblyWorkspace>(), context.Params!)))
    .WithRequestFilters(filters => filters.AddCallToolFilter(next => async (context, cancellationToken) =>
    {
        try
        {
            return await next(context, cancellationToken);
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
