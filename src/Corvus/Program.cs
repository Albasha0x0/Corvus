using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Corvus;
using Corvus.Core;
using Corvus.Mcp;

if (Corvus.Native.Providers.Worker.WorkerHost.TryRun(args) is { } workerExitCode) return workerExitCode;
if (Corvus.Native.Providers.Live.Inspector.InspectorWorker.TryRun(args) is { } inspectorExitCode) return inspectorExitCode;
if (Corvus.Native.Providers.Live.Jdwp.JdwpWorker.TryRun(args) is { } jdwpExitCode) return jdwpExitCode;
if (Corvus.Native.Providers.Live.Ttd.TtdWorker.TryRun(args) is { } ttdExitCode) return ttdExitCode;
if (Corvus.Native.Providers.DataFolder.MigratesOnStart(args)) Corvus.Native.Providers.DataFolder.MigrateDefault(Console.Error);
// After the move of an older data folder, which may hold the file; workers inherit what it sets.
ConfigFile.Apply(Console.Error);
if (Corvus.Relay.RelayCli.TryRun(args) is { } relayExitCode) return relayExitCode;
if (Corvus.Setup.ToolCli.TryRun(args) is { } toolExitCode) return toolExitCode;
if (Corvus.Setup.SetupCli.TryRun(args) is { } setupExitCode) return setupExitCode;

ServerOptions options;
try
{
    options = ServerOptions.Parse(args);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"corvus: {ex.Message}");
    return 2;
}

// Parallel decompilation (export_project, comparisons) occupies a pool thread per core; spare threads let the transport
// read a cancellation or the next request at once instead of after the pool grows, which takes seconds.
ThreadPool.GetMinThreads(out var minWorkers, out var minIo);
ThreadPool.SetMinThreads(Math.Max(minWorkers, Environment.ProcessorCount * 2 + 8), minIo);

using var host = ServerHost.Build(options, ServerInstructions.Text, server => server.WithStdioServerTransport());
await host.RunAsync();
return 0;
