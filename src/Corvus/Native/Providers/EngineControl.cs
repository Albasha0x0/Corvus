using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native.Providers.Ghidra;
using Corvus.Native.Providers.Ida;

namespace Corvus.Native.Providers;

/// <summary>An analysis setting of an engine: its name, value type, current value and description.</summary>
public sealed record NativeAnalyzerOption(string Name, string Type, string Value, string? Description);

/// <summary>A reanalysis result: whether the queue emptied within budget (else the rest runs on the next reanalysis or open), function counts before and after, and rejected options.</summary>
public sealed record NativeReanalysis(bool Complete, int FunctionsBefore, int FunctionsAfter, TimeSpan Elapsed, IReadOnlyList<string> Warnings);

/// <summary>A run of code in no function, [<see cref="Start"/>, <see cref="End"/>), with the references to its start.</summary>
public sealed record NativeFunctionCandidate(uint Start, uint End, int Instructions, int Calls, int Jumps, int DataRefs);

/// <summary>Function candidates in address order; <see cref="Truncated"/> when the scan budget ended first.</summary>
public sealed record NativeCandidateScan(IReadOnlyList<NativeFunctionCandidate> Items, int Scanned, bool Truncated);

/// <summary>A marker the engine shows at an address: a Ghidra bookmark (category Corvus), an IDA marked position.</summary>
public sealed record NativeMark(uint Rva, string Text);

/// <summary>Marks the engine holds now (<see cref="Set"/>), earlier ones removed, and those it could not take.</summary>
public sealed record NativeMarkResult(int Set, int Removed, int Failed, IReadOnlyList<string> Failures);

/// <summary>Bytes the engine has loaded at <see cref="Rva"/> (relocations and loader fixups applied).</summary>
public sealed record NativeMemoryRun(uint Rva, byte[] Bytes);

/// <summary>An initialized page of engine memory; <see cref="Hash"/> is the first 8 bytes of its SHA-256 as lowercase hex.</summary>
public sealed record NativeMemoryPage(uint Rva, int Length, string Hash)
{
    /// <summary>The digest of <paramref name="bytes"/> in the form <see cref="Hash"/> has.</summary>
    public static string Digest(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes).AsSpan(0, 8));
}

/// <summary>Bytes the engine's loader wrote, with the engine's fixup type and target symbol (null when none).</summary>
public sealed record EngineFixup(uint Rva, int Size, string Type, string? Target);

/// <summary>Fixups in address order and patched bytes with originals (null when the engine keeps none); <see cref="Truncated"/> at the maximum.</summary>
public sealed record EngineFixupList(IReadOnlyList<EngineFixup> Fixups, IReadOnlyList<NativeByteRange>? Patched, bool Truncated);

/// <summary>Engine requests beyond <see cref="INativeDecompilerSession"/>: analysis control, function candidates, marks, memory.</summary>
public interface INativeEngineControl
{
    /// <summary>Functions one batch request decompiles at once (Ghidra's decompiler pool; IDA one).</summary>
    int DecompileLanes => 1;

    Task<IReadOnlyList<NativeAnalyzerOption>> AnalyzersAsync(CancellationToken cancellationToken = default);

    /// <summary>Reruns auto-analysis over the image or [start, end) within <paramref name="seconds"/>, with one-run <paramref name="options"/>, then saves.</summary>
    Task<NativeReanalysis> ReanalyzeAsync(IReadOnlyList<KeyValuePair<string, string>> options, uint? start, uint? end, double seconds,
        CancellationToken cancellationToken = default);

    /// <summary>Runs of instructions outside every function, scanning at most <paramref name="maxInstructions"/>.</summary>
    Task<NativeCandidateScan> FunctionCandidatesAsync(int maxInstructions, CancellationToken cancellationToken = default);

    /// <summary>Replaces the server's marks in the database with <paramref name="marks"/> and records <paramref name="stamp"/>.</summary>
    Task<NativeMarkResult> SetMarksAsync(IReadOnlyList<NativeMark> marks, string stamp, CancellationToken cancellationToken = default);

    /// <summary>The initialized bytes of [rva, rva + length) as the engine holds them, in address order; gaps are not loaded.</summary>
    Task<IReadOnlyList<NativeMemoryRun>> MemoryAsync(uint rva, uint length, CancellationToken cancellationToken = default) =>
        throw new ToolError(ErrorCode.Unsupported, "This engine does not read its memory.", "use memory=file");

    /// <summary>Digests of the initialized <paramref name="page"/>-aligned pages of [rva, rva + length), in address order.</summary>
    async Task<IReadOnlyList<NativeMemoryPage>> MemoryPagesAsync(uint rva, uint length, int page, CancellationToken cancellationToken = default) =>
        EngineControl.Digest(await MemoryAsync(rva, length, cancellationToken).ConfigureAwait(false), page);

    /// <summary>The engine's relocations and loader fixups, at most <paramref name="max"/>; Unsupported when the engine cannot list them.</summary>
    Task<EngineFixupList> FixupsAsync(int max, CancellationToken cancellationToken = default) =>
        throw new ToolError(ErrorCode.Unsupported, "This engine does not list its fixups.");
}

/// <summary>The engine control of a session, and a per-session analysis generation that reanalysis advances (for caches of engine output).</summary>
public static class EngineControl
{
    /// <summary>Stamp key of the marks pushed into a database.</summary>
    public const string MarksStampKey = "marks";

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

    internal static IReadOnlyList<NativeMemoryRun> Memory(JsonElement r) =>
        r.GetProperty("runs").EnumerateArray().Select(x => new NativeMemoryRun(x[0].GetUInt32(), Convert.FromBase64String(x[1].GetString() ?? ""))).ToList();

    internal static JsonObject MemoryArgs(uint rva, uint length) => WorkerRows.Args(("rva", rva), ("size", length));

    /// <summary>Runs cut at multiples of <paramref name="page"/> and digested.</summary>
    internal static IReadOnlyList<NativeMemoryPage> Digest(IReadOnlyList<NativeMemoryRun> runs, int page)
    {
        var pages = new List<NativeMemoryPage>();
        foreach (var run in runs)
            for (long at = run.Rva, end = run.Rva + (long)run.Bytes.Length; at < end;)
            {
                long next = Math.Min(end, (at / page + 1) * page);
                pages.Add(new NativeMemoryPage((uint)at, (int)(next - at), NativeMemoryPage.Digest(run.Bytes.AsSpan((int)(at - run.Rva), (int)(next - at)))));
                at = next;
            }
        return pages;
    }

    /// <summary>A memory reply with page digests; a worker that ignores the page argument returns runs, digested here.</summary>
    internal static IReadOnlyList<NativeMemoryPage> Pages(JsonElement r, int page) =>
        r.TryGetProperty("pages", out var pages)
            ? pages.EnumerateArray().Select(x => new NativeMemoryPage(x[0].GetUInt32(), x[1].GetInt32(), x[2].GetString() ?? "")).ToList()
            : Digest(Memory(r), page);

    internal static JsonObject PageArgs(uint rva, uint length, int page) => WorkerRows.Args(("rva", rva), ("size", length), ("page", page));

    internal static EngineFixupList Fixups(JsonElement r) =>
        new(r.GetProperty("fixups").EnumerateArray().Select(x => new EngineFixup(x[0].GetUInt32(), x[1].GetInt32(), x[2].GetString() ?? "",
                x[3].ValueKind == JsonValueKind.String ? x[3].GetString() : null)).ToList(),
            r.TryGetProperty("patched", out var p) && p.ValueKind == JsonValueKind.Array
                ? p.EnumerateArray().Select(x => new NativeByteRange(x[0].GetUInt32(), Convert.FromBase64String(x[1].GetString() ?? ""))).ToList()
                : null,
            r.GetProperty("truncated").GetBoolean());

    /// <summary>The fixup list of a session; a worker without the request reports Unsupported.</summary>
    internal static async Task<EngineFixupList> FixupsAsync(WorkerSessionBase session, string engine, int max, CancellationToken cancellationToken)
    {
        try { return Fixups(await session.CallAsync("fixups", WorkerRows.Args(("max", max)), cancellationToken).ConfigureAwait(false)); }
        catch (ToolError e) when (e.Message.Contains("unknown op", StringComparison.Ordinal))
        {
            throw new ToolError(ErrorCode.Unsupported, $"This {engine} worker does not list its fixups.");
        }
    }

    /// <summary>A reanalysis may take the whole budget plus the save.</summary>
    internal static TimeSpan ReanalysisTimeout(double seconds) => TimeSpan.FromSeconds(seconds + 300);

    /// <summary>The verbs both engine workers answer the same way, keyed by the engine's name in errors.</summary>
    private abstract class WorkerControl(WorkerSessionBase session, string engine) : INativeEngineControl
    {
        public async Task<IReadOnlyList<NativeAnalyzerOption>> AnalyzersAsync(CancellationToken cancellationToken = default) =>
            Analyzers(await session.CallAsync("analyzers", new JsonObject(), cancellationToken).ConfigureAwait(false));

        public abstract Task<NativeReanalysis> ReanalyzeAsync(IReadOnlyList<KeyValuePair<string, string>> options, uint? start, uint? end, double seconds,
            CancellationToken cancellationToken = default);

        public async Task<NativeCandidateScan> FunctionCandidatesAsync(int maxInstructions, CancellationToken cancellationToken = default) =>
            Candidates(await session.CallAsync("function_candidates", WorkerRows.Args(("max_scan", maxInstructions)), cancellationToken).ConfigureAwait(false));

        public async Task<NativeMarkResult> SetMarksAsync(IReadOnlyList<NativeMark> marks, string stamp, CancellationToken cancellationToken = default) =>
            Marks(await session.CallAsync("set_marks", MarkArgs(marks, stamp), cancellationToken, journal: true).ConfigureAwait(false));

        public async Task<IReadOnlyList<NativeMemoryRun>> MemoryAsync(uint rva, uint length, CancellationToken cancellationToken = default) =>
            Memory(await session.CallAsync("memory", MemoryArgs(rva, length), cancellationToken).ConfigureAwait(false));

        public async Task<IReadOnlyList<NativeMemoryPage>> MemoryPagesAsync(uint rva, uint length, int page, CancellationToken cancellationToken = default) =>
            Pages(await session.CallAsync("memory", PageArgs(rva, length, page), cancellationToken).ConfigureAwait(false), page);

        public Task<EngineFixupList> FixupsAsync(int max, CancellationToken cancellationToken = default) => EngineControl.FixupsAsync(session, engine, max, cancellationToken);
    }

    private sealed class IdaControl(IdaSession session) : WorkerControl(session, "IDA")
    {
        public override async Task<NativeReanalysis> ReanalyzeAsync(IReadOnlyList<KeyValuePair<string, string>> options, uint? start, uint? end, double seconds,
            CancellationToken cancellationToken = default)
        {
            var args = WorkerRows.Args(("options", Pairs(options)), ("start", start), ("end", end), ("budget_seconds", seconds));
            var result = Reanalysis(await session.CallAsync("reanalyze", args, cancellationToken, saves: true, timeout: ReanalysisTimeout(seconds)).ConfigureAwait(false));
            session.Reanalyzed(result.Complete);
            return result;
        }
    }

    // Listed again so its DecompileLanes replaces the interface default.
    private sealed class GhidraControl(GhidraSession session) : WorkerControl(session, "Ghidra"), INativeEngineControl
    {
        public int DecompileLanes => session.DecompilerPool;

        public override async Task<NativeReanalysis> ReanalyzeAsync(IReadOnlyList<KeyValuePair<string, string>> options, uint? start, uint? end, double seconds,
            CancellationToken cancellationToken = default)
        {
            var args = WorkerRows.Args(("options", Pairs(options)), ("start", start), ("end", end), ("budget_seconds", seconds));
            var r = await session.CallAsync("reanalyze", args, cancellationToken, saves: true, timeout: ReanalysisTimeout(seconds)).ConfigureAwait(false);
            var result = Reanalysis(r);
            session.Reanalyzed(r.GetProperty("analysis_complete").GetBoolean(), result.FunctionsAfter);
            return result;
        }
    }
}
