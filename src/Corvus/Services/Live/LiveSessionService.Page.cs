using System.Globalization;
using System.Text.Json;
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

    /// <summary>Writes a PNG of the page to <paramref name="path"/> and returns its path, size and SHA-256; refuses links, remote paths and an existing file without overwrite.</summary>
    public async Task<IReadOnlyList<string>> ScreenshotAsync(LiveSession session, string? path, bool overwrite, CancellationToken ct)
    {
        Live(session);
        RequireScripts(session, "screenshot");
        if (string.IsNullOrWhiteSpace(path))
            throw new ToolError(ErrorCode.InvalidArgument, "A screenshot needs a file to write.", "pass outputPath, e.g. page.png");
        // The path is checked before the page is asked for the image.
        SafeFile.Output(path);
        var r = await session.Worker.RequestAsync("screenshot", null, RequestTimeout, ct).ConfigureAwait(false);
        if (r.GetProperty("data").GetString() is not { Length: > 0 } data)
            throw new ToolError(ErrorCode.Unsupported, "The page returned no image.", "live_session action=status shows whether the page is still open");
        var bytes = Convert.FromBase64String(data);
        var full = SafeFile.WriteAllBytes(path, bytes, overwrite);
        return [$"saved: {full}", $"size: {bytes.Length} bytes", $"sha256: {Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes))}"];
    }

    /// <summary>Lists the tools a page registers for agents as name, description and schema size; reads "not offered" or "unknown" with the reason when it lists none.</summary>
    public async Task<IReadOnlyList<string>> PageToolsAsync(LiveSession session, CancellationToken ct)
    {
        Live(session);
        RequireScripts(session, "page tools");
        var r = await session.Worker.RequestAsync("page_tools", null, RequestTimeout, ct).ConfigureAwait(false);
        return PageToolRows(r);
    }

    private static List<string> PageToolRows(JsonElement r)
    {
        var state = r.GetProperty("state").GetString();
        if (state == "unknown") return [$"tools unknown: {(r.TryGetProperty("message", out var m) ? m.GetString() : "no reason given")}"];
        if (state != "offered") return ["tools not offered"];
        var rows = r.GetProperty("rows");
        var lines = new List<string> { $"{rows.GetArrayLength()} tool(s) (name, description, input schema size in characters)" };
        foreach (var t in rows.EnumerateArray())
            lines.Add($"  tool {t.GetProperty("name").GetString()} | {t.GetProperty("description").GetString()?.ReplaceLineEndings(" ")} | schema {t.GetProperty("schema").GetInt32()}");
        return lines;
    }

    /// <summary>The page's script urls with hashes, listener rows and page tools as lines that <see cref="PageDiff"/> compares.</summary>
    public async Task<string> PageStateAsync(LiveSession session, CancellationToken ct)
    {
        Live(session);
        RequireScripts(session, "page state");
        var lines = new List<string>();
        var scripts = await session.Worker.RequestAsync("scripts", null, RequestTimeout, ct).ConfigureAwait(false);
        foreach (var s in scripts.EnumerateArray().OrderBy(x => x.GetProperty("url").GetString(), StringComparer.Ordinal))
            if (s.GetProperty("url").GetString() is { Length: > 0 } url) lines.Add($"script {url} {s.GetProperty("hash").GetString()}");
        lines.AddRange((await ListenersAsync(session, ct).ConfigureAwait(false)).Where(l => l.StartsWith("  ", StringComparison.Ordinal)).Select(l => "listener" + l[1..]));
        lines.AddRange(PageToolRows(await session.Worker.RequestAsync("page_tools", null, RequestTimeout, ct).ConfigureAwait(false)).Where(l => !l.EndsWith("input schema size in characters)", StringComparison.Ordinal)).Select(l => l.TrimStart()));
        return string.Join('\n', lines) + "\n";
    }

    /// <summary>Compares two page states: scripts by url and hash, listener rows and tools by name; returns the added, removed and changed rows.</summary>
    public static IReadOnlyList<string> PageDiff(string oldState, string newState)
    {
        static Dictionary<string, string> Rows(string text)
        {
            var map = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = line.Split(' ', 3);
                if (parts[0] == "script" && parts.Length == 3) map["script " + parts[1]] = parts[2];
                else if (parts[0] == "tool" && line.Contains(" | ", StringComparison.Ordinal))
                    map["tool " + line[5..line.IndexOf(" | ", StringComparison.Ordinal)]] = line[line.IndexOf(" | ", StringComparison.Ordinal)..];
                else map[line] = "";
            }
            return map;
        }
        var (a, b) = (Rows(oldState), Rows(newState));
        var lines = new List<string>();
        foreach (var k in b.Keys.Where(k => !a.ContainsKey(k)).Order(StringComparer.Ordinal)) lines.Add($"  added {k} {b[k]}".TrimEnd());
        foreach (var k in a.Keys.Where(k => !b.ContainsKey(k)).Order(StringComparer.Ordinal)) lines.Add($"  removed {k} {a[k]}".TrimEnd());
        foreach (var k in a.Keys.Where(k => b.TryGetValue(k, out var v) && v != a[k]).Order(StringComparer.Ordinal)) lines.Add($"  changed {k}: {a[k].Trim()} -> {b[k].Trim()}");
        lines.Insert(0, lines.Count == 0 ? "no difference" : $"{lines.Count} difference(s)");
        return lines;
    }

    private static void RequireScripts(LiveSession session, string what)
    {
        if (session.ScriptRuntime is not { Jvm: false })
            throw new ToolError(ErrorCode.Unsupported, $"{session.Id} is not a V8 inspector or browser page session: {what} is read from a page or a Node or Electron program.",
                "live_session action=attach program=cdp:PORT or inspector:PORT");
    }
}
