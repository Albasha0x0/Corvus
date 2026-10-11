using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Providers.Ghidra;
using NetDecompilerMcp.Native.Providers.Ida;

namespace NetDecompilerMcp.Native.Providers;

/// <summary>An analysis setting of an engine: its name, value type, current value and description.</summary>
public sealed record NativeAnalyzerOption(string Name, string Type, string Value, string? Description);

/// <summary>
/// What a reanalysis did: whether the engine's analysis queue ran empty within the budget (false: the rest runs on the next
/// reanalysis or open), the function counts before and after, and the engine's warnings (options it did not take).
/// </summary>
public sealed record NativeReanalysis(bool Complete, int FunctionsBefore, int FunctionsAfter, TimeSpan Elapsed, IReadOnlyList<string> Warnings);

/// <summary>
/// Code that is in no function: instructions [<see cref="Start"/>, <see cref="End"/>) in a run, with the call, jump and
/// data references to its start.
/// </summary>
public sealed record NativeFunctionCandidate(uint Start, uint End, int Instructions, int Calls, int Jumps, int DataRefs);

/// <summary>Function candidates in address order; <see cref="Truncated"/> when the scan budget ended first.</summary>
public sealed record NativeCandidateScan(IReadOnlyList<NativeFunctionCandidate> Items, int Scanned, bool Truncated);

/// <summary>A marker the engine shows at an address: a Ghidra bookmark (category NDM), an IDA marked position.</summary>
public sealed record NativeMark(uint Rva, string Text);

/// <summary>Marks the engine holds now (<see cref="Set"/>), earlier ones removed, and those it could not take.</summary>
public sealed record NativeMarkResult(int Set, int Removed, int Failed, IReadOnlyList<string> Failures);

/// <summary>Engine requests beyond <see cref="INativeDecompilerSession"/>: analysis control, function candidates, marks.</summary>
public interface INativeEngineControl
{
    /// <summary>Functions one batch request decompiles at once (Ghidra's decompiler pool; IDA one).</summary>
    int DecompileLanes => 1;

    Task<IReadOnlyList<NativeAnalyzerOption>> AnalyzersAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Runs auto-analysis again over the image, or over [start, end), within <paramref name="seconds"/>; <paramref name="options"/>
    /// apply to this run only. The database is saved afterwards.
    /// </summary>
    Task<NativeReanalysis> ReanalyzeAsync(IReadOnlyList<KeyValuePair<string, string>> options, uint? start, uint? end, double seconds,
        CancellationToken cancellationToken = default);

    /// <summary>Runs of instructions outside every function, scanning at most <paramref name="maxInstructions"/>.</summary>
    Task<NativeCandidateScan> FunctionCandidatesAsync(int maxInstructions, CancellationToken cancellationToken = default);

    /// <summary>Replaces the server's marks in the database with <paramref name="marks"/> and records <paramref name="stamp"/>.</summary>
    Task<NativeMarkResult> SetMarksAsync(IReadOnlyList<NativeMark> marks, string stamp, CancellationToken cancellationToken = default);
}

/// <summary>The engine control of a session, and a per-session analysis generation that reanalysis advances (for caches of engine output).</summary>
public static class EngineControl
{
    /// <summary>Stamp key of the marks pushed into a database.</summary>
    public const string MarksStampKey = "ndm_marks";

    private static readonly ConditionalWeakTable<INativeDecompilerSession, StrongBox<int>> Generations = new();

    public static INativeEngineControl? Of(INativeDecompilerSession session) => session switch
    {
        INativeEngineControl c => c,
        IdaSession ida => new IdaControl(ida),
        GhidraSession ghidra => new GhidraControl(ghidra),
        _ => null,
    };

    public static INativeEngineControl Require(INativeDecompilerSession session, string what) =>
        Of(session) ?? throw new ToolError(ErrorCode.Unsupported, $"The {session.ProviderId} engine does not support {what}.", "use engine=ida or engine=ghidra");

    /// <summary>Changes when the engine's analysis was run again; part of the keys of cached pseudocode.</summary>
    public static int Generation(INativeDecompilerSession session) => Generations.TryGetValue(session, out var g) ? Volatile.Read(ref g.Value) : 0;

    public static void Advance(INativeDecompilerSession session) => Interlocked.Increment(ref Generations.GetOrCreateValue(session).Value);

    internal static JsonArray Pairs(IEnumerable<KeyValuePair<string, string>> pairs) => new(pairs.Select(p => (JsonNode)new JsonArray(p.Key, p.Value)).ToArray());

    internal static IReadOnlyList<NativeAnalyzerOption> Analyzers(JsonElement r) =>
        r.GetProperty("options").EnumerateArray().Select(x => new NativeAnalyzerOption(x[0].GetString() ?? "", x[1].GetString() ?? "", x[2].GetString() ?? "",
            x.GetArrayLength() > 3 && x[3].ValueKind == JsonValueKind.String ? x[3].GetString() : null)).ToList();

    internal static NativeReanalysis Reanalysis(JsonElement r) =>
        new(r.GetProperty("complete").GetBoolean(), r.GetProperty("before").GetInt32(), r.GetProperty("after").GetInt32(),
            TimeSpan.FromSeconds(r.GetProperty("seconds").GetDouble()), r.GetProperty("warnings").EnumerateArray().Select(w => w.GetString() ?? "").ToList());

    internal static NativeCandidateScan Candidates(JsonElement r) =>
        new(r.GetProperty("rows").EnumerateArray().Select(x => new NativeFunctionCandidate(x[0].GetUInt32(), x[1].GetUInt32(), x[2].GetInt32(), x[3].GetInt32(),
            x[4].GetInt32(), x[5].GetInt32())).ToList(), r.GetProperty("scanned").GetInt32(), r.GetProperty("truncated").GetBoolean());

    internal static NativeMarkResult Marks(JsonElement r) =>
        new(r.GetProperty("set").GetInt32(), r.GetProperty("removed").GetInt32(), r.GetProperty("failed").GetInt32(),
            r.GetProperty("failures").EnumerateArray().Select(f => f.GetString() ?? "").ToList());

    internal static JsonObject MarkArgs(IReadOnlyList<NativeMark> marks, string stamp) => WorkerRows.Args(
        ("items", new JsonArray(marks.Select(m => (JsonNode)new JsonArray(m.Rva, m.Text)).ToArray())), ("stamp_key", MarksStampKey), ("stamp", stamp));

    /// <summary>A reanalysis may take the whole budget plus the save.</summary>
    internal static TimeSpan ReanalysisTimeout(double seconds) => TimeSpan.FromSeconds(seconds + 300);

    private sealed class IdaControl(IdaSession session) : INativeEngineControl
    {
        public async Task<IReadOnlyList<NativeAnalyzerOption>> AnalyzersAsync(CancellationToken cancellationToken = default) =>
            Analyzers(await session.CallAsync("analyzers", new JsonObject(), cancellationToken).ConfigureAwait(false));

        public async Task<NativeReanalysis> ReanalyzeAsync(IReadOnlyList<KeyValuePair<string, string>> options, uint? start, uint? end, double seconds,
            CancellationToken cancellationToken = default)
        {
            var args = WorkerRows.Args(("options", Pairs(options)), ("start", start), ("end", end), ("budget_seconds", seconds));
            var result = Reanalysis(await session.CallAsync("reanalyze", args, cancellationToken, saves: true, timeout: ReanalysisTimeout(seconds)).ConfigureAwait(false));
            return result;
        }

        public async Task<NativeCandidateScan> FunctionCandidatesAsync(int maxInstructions, CancellationToken cancellationToken = default) =>
            Candidates(await session.CallAsync("function_candidates", WorkerRows.Args(("max_scan", maxInstructions)), cancellationToken).ConfigureAwait(false));

        public async Task<NativeMarkResult> SetMarksAsync(IReadOnlyList<NativeMark> marks, string stamp, CancellationToken cancellationToken = default) =>
            Marks(await session.CallAsync("set_marks", MarkArgs(marks, stamp), cancellationToken, journal: true).ConfigureAwait(false));
    }

    private sealed class GhidraControl(GhidraSession session) : INativeEngineControl
    {
        public int DecompileLanes => session.DecompilerPool;

        public async Task<IReadOnlyList<NativeAnalyzerOption>> AnalyzersAsync(CancellationToken cancellationToken = default) =>
            Analyzers(await session.CallAsync("analyzers", new JsonObject(), cancellationToken).ConfigureAwait(false));

        public async Task<NativeReanalysis> ReanalyzeAsync(IReadOnlyList<KeyValuePair<string, string>> options, uint? start, uint? end, double seconds,
            CancellationToken cancellationToken = default)
        {
            var args = WorkerRows.Args(("options", Pairs(options)), ("start", start), ("end", end), ("budget_seconds", seconds));
            var r = await session.CallAsync("reanalyze", args, cancellationToken, saves: true, timeout: ReanalysisTimeout(seconds)).ConfigureAwait(false);
            var result = Reanalysis(r);
            session.Reanalyzed(r.GetProperty("analysis_complete").GetBoolean(), result.FunctionsAfter);
            return result;
        }

        public async Task<NativeCandidateScan> FunctionCandidatesAsync(int maxInstructions, CancellationToken cancellationToken = default) =>
            Candidates(await session.CallAsync("function_candidates", WorkerRows.Args(("max_scan", maxInstructions)), cancellationToken).ConfigureAwait(false));

        public async Task<NativeMarkResult> SetMarksAsync(IReadOnlyList<NativeMark> marks, string stamp, CancellationToken cancellationToken = default) =>
            Marks(await session.CallAsync("set_marks", MarkArgs(marks, stamp), cancellationToken, journal: true).ConfigureAwait(false));
    }
}
