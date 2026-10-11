using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NetDecompilerMcp;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;

if (NetDecompilerMcp.Relay.RelayCli.TryRun(args) is { } relayExitCode) return relayExitCode;
if (NetDecompilerMcp.Setup.ToolCli.TryRun(args) is { } toolExitCode) return toolExitCode;
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

using var host = ServerHost.Build(options, ServerInstructions.Text, server => server.WithStdioServerTransport());
await host.RunAsync();
return 0;
