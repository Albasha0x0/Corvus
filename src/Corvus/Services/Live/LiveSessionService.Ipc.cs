using System.Text.Json;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Services;

/// <summary>
/// An IPC channel as recorded in an Electron main process, joined to the app's code: direction (renderer-to-main or
/// main-to-renderer), kind (send, sendSync, invoke, invoke-result, invoke-error), value shape, messages counted (0 for a
/// channel the code names that was not seen) and the code sites on both sides.
/// </summary>
public sealed record LiveIpcRow(string Channel, string Direction, string Kind, string Shape, int Count, string Code);

/// <summary>A session's IPC ledger: the app path the code was read from, its rows, and keys dropped past the recorder's limit.</summary>
public sealed record LiveIpcLedger(string? App, IReadOnlyList<LiveIpcRow> Rows, int Dropped, int CodeRows);

public sealed partial class LiveSessionService
{
    /// <summary>
    /// Records IPC in the Electron main process of an inspector session (installed on the first call) and returns the
    /// messages seen so far, each joined to the static IPC rows of the app at app.getAppPath(). Refuses other sessions.
    /// </summary>
    public async Task<LiveIpcLedger> IpcAsync(LiveSession session, CancellationToken ct)
    {
        Live(session);
        if (session.ScriptRuntime is not { Jvm: false } js)
            throw new ToolError(ErrorCode.Unsupported, $"{session.Id} is not a V8 inspector session: IPC is recorded in an Electron main process.",
                "live_session action=attach program=inspector:PORT (electron --inspect=PORT)");
        var r = await session.Worker.RequestAsync("ipc", null, RequestTimeout, ct).ConfigureAwait(false);
        var app = r.TryGetProperty("app", out var a) && a.ValueKind == JsonValueKind.String ? a.GetString() : null;
        if (js.IpcCode == null || js.IpcCode.Value.App != app)
            js.IpcCode = (app, app != null ? ElectronInspector.AppSurface(app, ct).Where(x => x.Role != null).ToList() : []);
        var code = js.IpcCode.Value.Rows;
        var rows = new List<LiveIpcRow>();
        foreach (var m in r.GetProperty("rows").EnumerateArray())
        {
            var (d, k, c) = (m.GetProperty("d").GetString()!, m.GetProperty("k").GetString()!, m.GetProperty("c").GetString()!);
            rows.Add(new LiveIpcRow(c, d, k, m.GetProperty("s").GetString()!, m.GetProperty("n").GetInt32(), Sites(code, c, d == "renderer-to-main" || k.StartsWith("invoke-", StringComparison.Ordinal))));
        }
        // Channels the code names on one side that no message used.
        foreach (var g in code.GroupBy(x => (x.Value, Main: x.Role is "send-main" or "listen-main")))
            if (!rows.Any(x => x.Channel == g.Key.Value && (x.Direction == "renderer-to-main" || x.Kind.StartsWith("invoke-", StringComparison.Ordinal)) == g.Key.Main))
                rows.Add(new LiveIpcRow(g.Key.Value, g.Key.Main ? "renderer-to-main" : "main-to-renderer", "", "", 0, Sites(code, g.Key.Value, g.Key.Main)));
        return new LiveIpcLedger(app, [.. rows.OrderByDescending(x => x.Count > 0).ThenBy(x => x.Channel, StringComparer.Ordinal).ThenBy(x => x.Direction, StringComparer.Ordinal)],
            r.GetProperty("dropped").GetInt32(), code.Count);
    }

    // The sites of a channel on one route: renderer-to-main (sender in a renderer, listener in main) or main-to-renderer.
    private static string Sites(IReadOnlyList<ElectronRow> code, string channel, bool toMain)
    {
        string Side(string role, string label) =>
            code.Where(x => x.Value == channel && x.Role == role).Take(3).Select(x => $"{label} {x.Site} ({x.Call})").ToList() is { Count: > 0 } s ? string.Join("; ", s) : $"no {label} read";
        return toMain ? Side("listen-main", "main listener") + "; " + Side("send-main", "renderer sender")
            : Side("send-renderer", "main sender") + "; " + Side("listen-renderer", "renderer listener");
    }
}
