using Corvus.Core;
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

    private static void Limit(string id)
    {
        if (OutputCall.Current is not { } call) return;
        if (call.EngineMeta.GetValueOrDefault("limitations") is not List<string> list) call.EngineMeta["limitations"] = list = [];
        if (!list.Contains(id)) list.Add(id);
    }
}
