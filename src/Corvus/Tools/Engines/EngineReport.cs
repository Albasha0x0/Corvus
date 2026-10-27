using Corvus.Core;
using ModelContextProtocol;
using Corvus.Mcp;
using Corvus.Native.Providers;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>Engine provenance of a result: engine and reason in the result; details that vary between calls in _meta only.</summary>
internal static class EngineReport
{
    /// <summary>Records that <paramref name="choice"/> answered, from <paramref name="session"/> when one was opened.</summary>
    public static void Answered(EngineChoice choice, NativeEngineService? engines, INativeDecompilerSession? session = null)
    {
        ToolOutput.Engine(choice.Engine, choice.Note);
        if (!choice.External) return;
        EngineUse.Note(choice.Engine);
        if (OutputCall.Current is not { } call || engines == null) return;
        var id = engines.Identity(choice.Engine);
        var meta = call.EngineMeta;
        meta["engineVersion"] = id.Version;
        meta["engineBuild"] = id.Build;
        meta["engineProfile"] = id.Profile;
        // A saved database that failed to open was analyzed again; only the call that opened it says so.
        if (session is WorkerSessionBase { Rebuilt: { } rebuilt } w)
        {
            ToolOutput.Warn(rebuilt);
            w.Rebuilt = null;
        }
        if (session != null)
        {
            meta["analysis"] = session.AnalysisComplete ? "complete" : "partial";
            meta["savedAnalysis"] = session.ReusedDatabase;
            meta["openSeconds"] = Math.Round(session.OpenTime.TotalSeconds, 1);
            if (session is WorkerSessionBase { Overrides: { } overrides }) meta["importOverrides"] = overrides.Text;
        }
        if (id.Profile == "standard") Limit(Limitations.Id(Limitation.EngineProfileStandard));
        if (session is { AnalysisComplete: false }) Limit(Limitations.Id(Limitation.AnalysisPartial));
    }

    /// <summary>A push into the engine database before the answer (names, types, PDB, marks): _meta only.</summary>
    public static void Pushed(string? line)
    {
        if (line == null || OutputCall.Current is not { } call) return;
        if (call.EngineMeta.GetValueOrDefault("pushed") is not List<string> list) call.EngineMeta["pushed"] = list = [];
        list.Add(line);
    }

    /// <summary>How much of the answer the persistent engine output cache served.</summary>
    public static void Cached(int hits, int misses)
    {
        if (OutputCall.Current is not { } call) return;
        call.EngineMeta["outputCache"] = new { hits, misses };
    }

    /// <summary>A digest of everything pushed into the engine before an answer; equal digests let another process reuse a stored answer.</summary>
    public static string SetupDigest(LoadedNative native, NativeCodeService? code, params object?[] tool)
    {
        var user = code?.Annotations(native);
        var layers = Native.Code.NativeNameLayers.OfOrNull(native)?.Layers ?? [];
        var pdb = PdbService.PathForEngines(native) ?? PdbService.StateOf(native)?.Path;
        var pdbFile = pdb != null && new FileInfo(pdb) is { Exists: true } f ? $"{pdb}|{f.Length}|{f.LastWriteTimeUtc.Ticks}" : "";
        return EngineOutputCache.Key(["setup", NativeNamePush.StampOf(NativeNamePush.Effective(user, layers, native.Image)),
            NativeNamePush.StampOf(NativeNamePush.Effective(user, layers, native.Image, withPdb: true)), user?.UserTypes.Stamp, pdbFile,
            AotNativeNames.Of(native) != null, .. tool]);
    }

    /// <summary>While an engine works on one request: a progress notification every few seconds naming it and the time so far (S9.2).</summary>
    public static IDisposable Heartbeat(IProgress<ProgressNotificationValue> progress, string what)
    {
        var clock = System.Diagnostics.Stopwatch.StartNew();
        return new Timer(_ => progress.Report(new ProgressNotificationValue
            { Progress = (float)clock.Elapsed.TotalSeconds, Message = $"{what} ({clock.Elapsed.TotalSeconds:0} s)" }), null, HeartbeatEvery, HeartbeatEvery);
    }

    /// <summary>Under the 5 s the progress contract allows between notifications.</summary>
    internal static readonly TimeSpan HeartbeatEvery = TimeSpan.FromSeconds(4);

    private static void Limit(string id)
    {
        if (OutputCall.Current is not { } call) return;
        if (call.EngineMeta.GetValueOrDefault("limitations") is not List<string> list) call.EngineMeta["limitations"] = list = [];
        if (!list.Contains(id)) list.Add(id);
    }
}
