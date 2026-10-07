using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using NetDecompilerMcp;
using NetDecompilerMcp.Core;
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

// Don't let the host parse our arguments; stdout belongs to the MCP protocol, so all logs go to stderr.
var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { Args = [] });
builder.Logging.ClearProviders();
builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);
builder.Logging.SetMinimumLevel(LogLevel.Information);

builder.Services.AddSingleton(options);
builder.Services.AddSingleton<AssemblyWorkspace>();
builder.Services.AddSingleton<OutputPager>();
builder.Services.AddSingleton<DecompilerService>();
builder.Services.AddSingleton<AnalysisService>();
builder.Services.AddSingleton<Il2CppService>();
builder.Services.AddSingleton<ResourceService>();
builder.Services.AddSingleton<IlAssembler>();
builder.Services.AddSingleton<EditService>();

builder.Services
    .AddMcpServer(o =>
    {
        o.ServerInfo = new Implementation { Name = "net-decompiler", Version = typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "1.0.0" };
        o.ServerInstructions = ServerInstructions.Text;
    })
    .WithStdioServerTransport()
    .WithToolsFromAssembly()
    .WithRequestFilters(filters => filters.AddCallToolFilter(next => async (context, cancellationToken) =>
    {
        try
        {
            return await next(context, cancellationToken);
        }
        catch (Exception ex) when (ex is not McpException && ex is not OperationCanceledException)
        {
            // Unexpected failure: report it to the model instead of a generic error, and keep the server alive.
            context.Services?.GetService<ILogger<AssemblyWorkspace>>()?.LogError(ex, "Tool {Tool} failed", context.Params?.Name);
            return new CallToolResult
            {
                IsError = true,
                Content = [new TextContentBlock { Text = $"Internal error in {context.Params?.Name}: {ex.GetType().Name}: {ex.Message}" }],
            };
        }
    }));

var host = builder.Build();

var workspace = host.Services.GetRequiredService<AssemblyWorkspace>();
var log = host.Services.GetRequiredService<ILogger<AssemblyWorkspace>>();
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

await host.RunAsync();
return 0;
