using Corvus.Core;
using ModelContextProtocol;
using Corvus.Mcp;
using Corvus.Native.Providers;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>
/// Engine provenance of a result (EL-2b): the engine and why it was chosen in both parts (engine, engineNote), and its
/// version, build, profile, analysis state and what was pushed or served from the output cache in _meta, which is the
/// only place for details that differ between calls of the same question.
/// </summary>
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
        // a saved database that could not be opened was analyzed again: said once, by the call that opened it
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

    /// <summary>
    /// Everything the server pushes into an engine database before a tool's answer (names and comments in effect, user types,
    /// the PDB, the tool's own pushes such as notes, Il2Cpp names): equal digests mean equal pushes, so an answer stored after
    /// them holds for another process that has not opened the engine.
    /// </summary>
    public static string SetupDigest(LoadedNative native, NativeCodeService? code, params object?[] tool)
    {
        var user = code?.Annotations(native);
        var layers = Native.Code.NativeNameLayers.OfOrNull(native)?.Layers ?? [];
        var pdb = PdbService.PathForEngines(native);
        var pdbFile = pdb != null && new FileInfo(pdb) is { Exists: true } f ? $"{pdb}|{f.Length}|{f.LastWriteTimeUtc.Ticks}" : "";
        return EngineOutputCache.Key(["setup", NativeNamePush.StampOf(NativeNamePush.Effective(user, layers, native.Image)),
            NativeNamePush.StampOf(NativeNamePush.Effective(user, layers, native.Image, withPdb: true)), user?.UserTypes.Stamp, pdbFile,
            Il2CppNativeNames.Of(native) != null, .. tool]);
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
