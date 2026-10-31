using System.Text.Json;
using ModelContextProtocol.Protocol;

namespace Corvus.Setup;

internal static partial class ToolCli
{
    private const string AnalyzeTool = "reanalyze_native";

    private const int StatusWaitSeconds = 30;

    // Polls of an unchanged running analysis, 2 s apart, before the outcome is unknown.
    private const int StallPolls = 150;

    /// <summary>
    /// One tool call against the in-process server or a routed session; null
    /// after a protocol error.
    /// </summary>
    internal delegate Task<CallToolResult?> ToolCall(string tool, Dictionary<string, object?> arguments, CancellationToken cancellationToken);

    // Runs reanalyze_native; --wait blocks until the first analysis or
    // reanalysis ends.
    private static async Task<int> AnalyzeAsync(CliArgs a, CliIo io, CancellationToken cancellationToken)
    {
        if (a.Positionals.Count != 1) throw new UsageException("analyze takes one image.");
        var image = a.Positionals[0];
        var tool = RequireTool(AnalyzeTool);
        var arguments = a.ToolArguments(tool["inputSchema"], io.In);
        if (arguments.ContainsKey("image")) throw new UsageException("analyze takes the image as an argument, not image=.");
        arguments["image"] = image;
        if (a.Wait)
        {
            if (arguments.TryGetValue("background", out var b) && !Equals(b, true) && b?.ToString() != "true")
                throw new UsageException("--wait runs the job in the background; remove background=.");
            arguments["background"] = true;
        }
        var routed = RoutedSession(a, io);
        await using var session = routed == null ? await ToolSession.StartAsync(a.Server(oneShot: true), cancellationToken) : null;
        ToolCall call = (name, args, ct) => routed == null ? Invoke(session!, name, args, io, ct) : InvokeRemote(routed, name, args, io, ct);
        if (!a.Wait)
        {
            var result = await call(AnalyzeTool, arguments, cancellationToken);
            return result is null ? Exit.Usage : Print(AnalyzeTool, result, a, io, oneShot: routed == null);
        }
        return await AnalyzeWaitAsync(call, image, arguments, a, io, cancellationToken);
    }

    /// <summary>
    /// Waits for an image's analysis to end and returns its exit code. An open
    /// that ran the analysis is the outcome; an open that loaded a saved
    /// database is followed by one background reanalysis.
    /// </summary>
    internal static async Task<int> AnalyzeWaitAsync(ToolCall call, string image, Dictionary<string, object?> arguments, CliArgs a, CliIo io,
        CancellationToken cancellationToken, TimeSpan? pollEvery = null, int stallPolls = StallPolls)
    {
        var poll = pollEvery ?? TimeSpan.FromSeconds(2);
        var stalled = 0;
        var engine = arguments.TryGetValue("engine", out var e) ? e?.ToString() : null;
        // Open the engine; its early answer is not an end.
        var open = new Dictionary<string, object?> { ["image"] = image, ["analyzers"] = true };
        if (engine != null) open["engine"] = engine;
        var started = await call(AnalyzeTool, open, cancellationToken);
        if (started is null) return Exit.Usage;
        if (started.IsError == true && !IsStillRunning(Split(started).Error)) return Print(AnalyzeTool, started, a, io);

        var reanalyzing = false;
        while (true)
        {
            var query = new Dictionary<string, object?> { ["image"] = image, ["waitSeconds"] = StatusWaitSeconds };
            if (engine != null) query["engine"] = engine;
            var reply = await call("get_engine_status", query, cancellationToken);
            if (reply is null || reply.IsError == true) return reply is null ? Exit.Usage : Print("get_engine_status", reply, a, io);
            var state = EngineJobState(reply.StructuredContent, engine);
            if (state is null)
            {
                io.Error.WriteLine($"Analysis of {image}: no engine session is reported.");
                return Exit.ToolError;
            }
            if (state.State == "opening" || state.JobRunning) continue;
            if (state.State == "open" && !reanalyzing && !state.Reused && state.Analysis == "running")
            {
                // The analysis reports no progress unit; an unchanged state for stallPolls polls ends the wait.
                if (++stalled >= stallPolls)
                {
                    io.Error.WriteLine($"Analysis of {image}: {state.Engine} still reports analysis running after {stalled} polls; the outcome is unknown. Next: get_engine_status image={image} waitSeconds={StatusWaitSeconds}.");
                    return Exit.Unknown;
                }
                await Task.Delay(poll, cancellationToken);
                continue;
            }
            if (state.State == "open" && !reanalyzing && state.Reused)
            {
                var run = await call(AnalyzeTool, arguments, cancellationToken);
                if (run is null) return Exit.Usage;
                if (run.IsError == true) return Print(AnalyzeTool, run, a, io);
                reanalyzing = true;
                continue;
            }
            var result = state.State switch
            {
                "open" when reanalyzing => state.JobResult,
                "open" => state.Analysis,
                "failed" => state.JobResult ?? "failed",
                _ => "failed",
            };
            if (result is null or "running")
            {
                io.Error.WriteLine($"Analysis of {image}: {state.Engine} reports no result (state {state.State}); the outcome is unknown. Next: get_engine_status image={image}.");
                return Exit.Unknown;
            }
            io.Error.WriteLine($"Analysis of {image}: {state.Engine} {state.JobOutcome ?? result}");
            return ResultExit(result);
        }
    }

    /// <summary>
    /// Maps an analysis result to an exit code: complete 0, partial 4, cancelled
    /// 6, anything else (failed) 1. Unknown (7) is decided by the caller.
    /// </summary>
    internal static int ResultExit(string? result) => result switch
    {
        "complete" => Exit.Ok,
        "partial" => Exit.Partial,
        "cancelled" => Exit.JobCancelled,
        _ => Exit.ToolError,
    };

    /// <summary>
    /// What an engine entry of get_engine_status says about the analysis: the
    /// session state, whether an open loaded a saved database, its analysis
    /// (complete or partial), and the job's state, result and outcome text.
    /// </summary>
    internal sealed record EngineJobView(string Engine, string State, bool Reused, string? Analysis, bool JobRunning, string? JobResult, string? JobOutcome);

    /// <summary>
    /// Reads the entry of the named engine, or the first engine with a session
    /// when null; null when the report holds none.
    /// </summary>
    internal static EngineJobView? EngineJobState(JsonElement? structured, string? engineName)
    {
        if (structured is not { ValueKind: JsonValueKind.Object } root
            || !root.TryGetProperty("engines", out var engines)
            || engines.ValueKind != JsonValueKind.Array) return null;
        foreach (var entry in engines.EnumerateArray())
        {
            var name = Text(entry, "engine") ?? "";
            var state = Text(entry, "state") ?? "";
            if (engineName != null ? !string.Equals(name, engineName, StringComparison.OrdinalIgnoreCase) : state == "not_started") continue;
            entry.TryGetProperty("job", out var job);
            var hasJob = job.ValueKind == JsonValueKind.Object;
            return new EngineJobView(name, state,
                entry.TryGetProperty("reusedDatabase", out var reused) && reused.ValueKind == JsonValueKind.True,
                Text(entry, "analysis"),
                hasJob && Text(job, "state") == "running",
                hasJob ? Text(job, "result") : null,
                hasJob ? Text(job, "outcome") : null);
        }
        return null;
    }

    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
