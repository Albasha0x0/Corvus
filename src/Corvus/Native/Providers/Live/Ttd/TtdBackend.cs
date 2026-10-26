using Corvus.Core;
using Corvus.Native.Providers.Worker;

namespace Corvus.Native.Providers.Live.Ttd;

/// <summary>
/// Sessions on a TTD recording (<c>ttd:PATH</c>), replayed by this program's own <c>ttd-worker</c> with the TTD Replay API
/// (CORVUS_TTD names the folder holding TTDReplay.dll).
/// </summary>
public sealed class TtdBackend : ILiveBackend
{
    public string Name => "ttd";

    public (string Reason, string Remediation)? Unavailable() =>
        !OperatingSystem.IsWindows() || System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture != System.Runtime.InteropServices.Architecture.X64
            ? ("Recordings are replayed with the TTD Replay API, which runs on Windows x64 only.", "open the recording on a Windows x64 machine")
            : TtdWorker.Folder() == null ? ("CORVUS_TTD is not set.", TtdReplay.Remedy) : null;

    public WorkerConnection Start()
    {
        var start = WorkerPool.OwnCommand(TtdWorker.Command);
        try { return WorkerConnection.Start("TTD worker", start); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.ProviderUnavailable, $"The TTD worker could not be started with {start.FileName}: {ex.Message}", "check the Corvus install");
        }
    }
}
