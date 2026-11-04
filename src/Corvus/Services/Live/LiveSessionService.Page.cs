using System.Globalization;
using System.Text.Json.Nodes;
using Corvus.Core;

namespace Corvus.Services;

public sealed partial class LiveSessionService
{
    // A walk of up to 2,000 elements sends two commands each.
    private static readonly TimeSpan WalkTimeout = TimeSpan.FromMinutes(5);

    /// <summary>Starts, reads or stops function coverage in a script session (mode start, take or stop); returns the report lines; refuses JVM and native sessions.</summary>
    public async Task<IReadOnlyList<string>> CoverageAsync(LiveSession session, string? mode, CancellationToken ct)
    {
        Live(session);
        var m = (mode ?? "take").Trim().ToLowerInvariant();
        RequireScripts(session, "coverage");
        var r = await session.Worker.RequestAsync("coverage", new JsonObject { ["mode"] = m }, RequestTimeout, ct).ConfigureAwait(false);
        if (m == "start") return ["coverage started: functions called from now on are counted"];
        if (m == "stop") return [r.GetProperty("stopped").GetBoolean() ? "coverage stopped" : "no coverage was running"];
        var lines = new List<string>();
        var rows = r.GetProperty("rows");
        lines.Add($"{rows.GetArrayLength()} function(s) called since start (script, function, line, count)");
        foreach (var row in rows.EnumerateArray().OrderByDescending(x => x.GetProperty("count").GetInt32()).ThenBy(x => x.GetProperty("script").GetString(), StringComparer.Ordinal))
        {
            var line = row.GetProperty("line").GetInt32();
            var name = row.GetProperty("function").GetString() is { Length: > 0 } n ? n : "(anonymous)";
            lines.Add($"  {row.GetProperty("script").GetString()}:{(line > 0 ? line.ToString(CultureInfo.InvariantCulture) : "unknown")} {name} x{row.GetProperty("count").GetInt32()}");
        }
        if (r.GetProperty("cut").GetBoolean()) lines.Add($"Rows cut at {r.GetProperty("limit").GetInt32()}: more functions were called.");
        return lines;
    }

    /// <summary>Lists the event listeners of a page's elements with their handler positions; refuses sessions without a document.</summary>
    public async Task<IReadOnlyList<string>> ListenersAsync(LiveSession session, CancellationToken ct)
    {
        Live(session);
        RequireScripts(session, "listeners");
        var r = await session.Worker.RequestAsync("listeners", null, WalkTimeout, ct).ConfigureAwait(false);
        var rows = r.GetProperty("rows");
        var lines = new List<string>
        {
            $"{rows.GetArrayLength()} listener(s) on {r.GetProperty("elements").GetInt32()} element(s) (event, element, handler script:line, capture, once)",
        };
        if (!r.GetProperty("body").GetBoolean()) lines.Add("The document has no body: no element was read.");
        foreach (var row in rows.EnumerateArray())
        {
            var line = row.GetProperty("line").GetInt32();
            lines.Add($"  {row.GetProperty("type").GetString()} {row.GetProperty("element").GetString()} {row.GetProperty("script").GetString()}:{(line > 0 ? line.ToString(CultureInfo.InvariantCulture) : "unknown")}"
                + (row.GetProperty("capture").GetBoolean() ? " capture" : "") + (row.GetProperty("once").GetBoolean() ? " once" : ""));
        }
        if (r.GetProperty("cut").GetBoolean()) lines.Add($"Walk cut at {r.GetProperty("limit").GetInt32()} elements: later elements were not read.");
        return lines;
    }

    private static void RequireScripts(LiveSession session, string what)
    {
        if (session.ScriptRuntime is not { Jvm: false })
            throw new ToolError(ErrorCode.Unsupported, $"{session.Id} is not a V8 inspector or browser page session: {what} is read from a page or a Node or Electron program.",
                "live_session action=attach program=cdp:PORT or inspector:PORT");
    }
}
