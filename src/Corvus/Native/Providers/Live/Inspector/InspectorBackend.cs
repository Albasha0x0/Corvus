using Corvus.Core;
using Corvus.Native.Providers.Worker;

namespace Corvus.Native.Providers.Live.Inspector;

/// <summary>Sessions on a Node or Electron program through its V8 inspector, served by this program's <c>inspector-worker</c> command; nothing else is installed.</summary>
public sealed class InspectorBackend : ILiveBackend
{
    public string Name => "inspector";

    public (string Reason, string Remediation)? Unavailable() => null;

    public WorkerConnection Start()
    {
        var start = WorkerPool.OwnCommand(InspectorWorker.Command);
        try { return WorkerConnection.Start("inspector worker", start); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.ProviderUnavailable, $"The inspector worker could not be started with {start.FileName}: {ex.Message}", "check the Corvus install");
        }
    }
}
