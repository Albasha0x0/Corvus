using System.Text.Json;
using System.Text.RegularExpressions;
using ModelContextProtocol.Protocol;

namespace Corvus.Setup;

internal static partial class ToolCli
{
    private const string AnalyzeTool = "reanalyze_native";

    private static readonly TimeSpan AnalyzePoll = TimeSpan.FromSeconds(2);

    private static readonly TimeSpan AnalyzeGrace = TimeSpan.FromSeconds(60);

    private static readonly TimeSpan AnalyzeDefaultBudget = TimeSpan.FromHours(1);

    // Runs reanalyze_native; --wait runs it as a background job and waits.
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
        await using var session = await ToolSession.StartAsync(a.Server(oneShot: true), cancellationToken);
        var result = await Invoke(session, AnalyzeTool, arguments, io, cancellationToken);
        if (result is null) return Exit.Usage;
        var code = Print(AnalyzeTool, result, a, io);
        if (code != Exit.Ok || !a.Wait) return code;

        var engine = arguments.TryGetValue("engine", out var e) ? e?.ToString() : null;
        var started = DateTime.UtcNow;
        var budget = AnalyzeDefaultBudget;
        while (true)
        {
            await Task.Delay(AnalyzePoll, cancellationToken);
            var status = new Dictionary<string, object?> { ["image"] = image };
            if (engine != null) status["engine"] = engine;
            var reply = await Invoke(session, "get_engine_status", status, io, cancellationToken);
            if (reply is null || reply.IsError == true) return Exit.ToolError;
            var state = BackgroundState(reply.StructuredContent, engine);
            if (state.Outcome is { } outcome)
            {
                io.Error.WriteLine($"Analysis of {image}: {outcome}");
                return OutcomeExit(outcome);
            }
            if (!state.Running)
            {
                io.Error.WriteLine($"Analysis of {image}: the background job is no longer reported.");
                return Exit.ToolError;
            }
            if (state.Budget is { } seconds) budget = TimeSpan.FromSeconds(seconds) + AnalyzeGrace;
            if (DateTime.UtcNow - started > budget)
            {
                io.Error.WriteLine($"Analysis of {image}: still running after {budget.TotalSeconds:0} s.");
                return Exit.Timeout;
            }
        }
    }

    /// <summary>
    /// Maps a background outcome to an exit code: a failed job is
    /// <see cref="Exit.ToolError"/>, any other outcome is <see cref="Exit.Ok"/>.
    /// </summary>
    internal static int OutcomeExit(string outcome) =>
        outcome.Contains(" failed after ", StringComparison.Ordinal) ? Exit.ToolError : Exit.Ok;

    /// <summary>
    /// Reads the background job of an engine status report, for the named
    /// engine or any engine when null. Outcome is the ended job's text; Running
    /// is true while it runs, with its budget in seconds when stated. All are
    /// empty when no background stage is reported.
    /// </summary>
    internal static (string? Outcome, bool Running, int? Budget) BackgroundState(JsonElement? structured, string? engineName)
    {
        if (structured is not { ValueKind: JsonValueKind.Object } root
            || !root.TryGetProperty("engines", out var engines)
            || engines.ValueKind != JsonValueKind.Array) return (null, false, null);
        foreach (var engine in engines.EnumerateArray())
        {
            if (engineName != null
                && !(engine.TryGetProperty("engine", out var name)
                    && string.Equals(name.GetString(), engineName, StringComparison.OrdinalIgnoreCase)))
                continue;
            if (!engine.TryGetProperty("stage", out var stage) || stage.GetString() is not { } text) continue;
            if (!text.StartsWith("background ", StringComparison.Ordinal)) continue;
            if (!text.Contains(": running ", StringComparison.Ordinal))
                return (text["background ".Length..], false, null);
            var match = Regex.Match(text, @" of (\d+) s");
            return (null, true, match.Success ? int.Parse(match.Groups[1].Value) : null);
        }
        return (null, false, null);
    }
}
