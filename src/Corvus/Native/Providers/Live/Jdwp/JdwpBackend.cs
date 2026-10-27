using Corvus.Core;
using Corvus.Native.Providers.Worker;

namespace Corvus.Native.Providers.Live.Jdwp;

/// <summary>Sessions on a JVM through its JDWP agent (<c>jdwp:PORT</c>), served by this program's <c>jdwp-worker</c> command; nothing else is installed.</summary>
public sealed class JdwpBackend : ILiveBackend
{
    public string Name => "jdwp";

    public (string Reason, string Remediation)? Unavailable() => null;

    public WorkerConnection Start()
    {
        var start = WorkerPool.OwnCommand(JdwpWorker.Command);
        try { return WorkerConnection.Start("JDWP worker", start); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.ProviderUnavailable, $"The JDWP worker could not be started with {start.FileName}: {ex.Message}", "check the Corvus install");
        }
    }
}
