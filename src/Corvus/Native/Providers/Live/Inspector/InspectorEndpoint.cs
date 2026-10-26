using System.Net;
using System.Text.Json;
using Corvus.Core;

namespace Corvus.Native.Providers.Live.Inspector;

/// <summary>
/// A V8 inspector a session connects to, named as <c>inspector:PORT</c>, <c>inspector:HOST:PORT</c> or
/// <c>inspector:ws://HOST:PORT/ID</c>, with an optional <c>#TARGET</c> (id, type or part of the title). Node opens one with
/// --inspect, an Electron main process with --inspect, its pages with --remote-debugging-port. Only loopback hosts are
/// accepted: the inspector runs any code it is sent.
/// </summary>
public static class InspectorEndpoint
{
    public const string Prefix = "inspector:";

    /// <summary>True when <paramref name="program"/> names an inspector rather than a process.</summary>
    public static bool Is(string? program) => program?.TrimStart().StartsWith(Prefix, StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>One debuggable target of an inspector: what /json/list reports for it.</summary>
    public sealed record Target(string Id, string Type, string Title, string Url, Uri WebSocket);

    /// <summary>The target <paramref name="program"/> names: a WebSocket URL as given, else the first match in the inspector's list (node targets first).</summary>
    public static async Task<Target> ResolveAsync(string program, CancellationToken ct)
    {
        var text = program.Trim()[Prefix.Length..];
        string? select = null;
        if (text.IndexOf('#') is var hash and >= 0) (text, select) = (text[..hash], text[(hash + 1)..]);
        if (text.StartsWith("ws://", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(text, UriKind.Absolute, out var ws)) throw Bad(program, "the WebSocket URL does not parse");
            RequireLoopback(ws.Host, program);
            return new Target(ws.AbsolutePath.Trim('/'), "?", "", "", ws);
        }
        var (host, port) = text.LastIndexOf(':') is var colon and > 0 ? (text[..colon], text[(colon + 1)..]) : ("127.0.0.1", text);
        if (!int.TryParse(port, out var number) || number is < 1 or > 65535) throw Bad(program, $"'{port}' is not a port");
        RequireLoopback(host, program);
        var list = await ListAsync(new Uri($"http://{(host.Contains(':') ? $"[{host.Trim('[', ']')}]" : host)}:{number}/json/list"), ct).ConfigureAwait(false);
        var match = list.Where(t => select == null || t.Id == select || t.Type.Equals(select, StringComparison.OrdinalIgnoreCase)
                || t.Title.Contains(select, StringComparison.OrdinalIgnoreCase))
            .OrderBy(t => t.Type == "node" ? 0 : t.Type == "page" ? 1 : 2).FirstOrDefault();
        return match ?? throw new ToolError(ErrorCode.NotFound,
            $"The inspector at {host}:{number} lists {list.Count} target(s){(select != null ? $", none matching '{select}'" : "")}: {string.Join(", ", list.Select(t => $"{t.Type} {t.Id} \"{t.Title}\""))}.",
            "program=inspector:PORT#TARGET names one by id, type or title");
    }

    private static async Task<List<Target>> ListAsync(Uri list, CancellationToken ct)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        string json;
        try { json = await http.GetStringAsync(list, ct).ConfigureAwait(false); }
        catch (HttpRequestException ex)
        {
            throw new ToolError(ErrorCode.NotFound, $"No inspector answers at {list.Authority}: {ex.Message}",
                "start the program with --inspect=PORT (Node, Electron main) or --remote-debugging-port=PORT (Electron pages)");
        }
        var targets = new List<Target>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) throw new JsonException("not a list");
            foreach (var t in doc.RootElement.EnumerateArray())
            {
                string? Get(string k) => t.ValueKind == JsonValueKind.Object && t.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
                // A target another client holds has no WebSocket URL.
                if (Get("webSocketDebuggerUrl") is not { } ws || !Uri.TryCreate(ws, UriKind.Absolute, out var uri)) continue;
                RequireLoopback(uri.Host, list.ToString());
                targets.Add(new Target(Get("id") ?? "", Get("type") ?? "", Get("title") ?? "", Get("url") ?? "", uri));
            }
        }
        catch (JsonException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{list} did not answer with a target list: {ex.Message}"); }
        return targets;
    }

    /// <summary>Returns when <paramref name="host"/> is localhost or a loopback address; else refuses <paramref name="program"/>, naming <paramref name="what"/> it connects to.</summary>
    internal static void RequireLoopback(string host, string program, string what = "an inspector")
    {
        var name = host.Trim('[', ']');
        if (name.Equals("localhost", StringComparison.OrdinalIgnoreCase) || (IPAddress.TryParse(name, out var ip) && IPAddress.IsLoopback(ip))) return;
        throw new ToolError(ErrorCode.Unsupported, $"{program}: {host} is not a loopback address; sessions connect only to {what} on this machine.",
            "forward the port to 127.0.0.1 (ssh -L, adb forward) and name that");
    }

    private static ToolError Bad(string program, string why) =>
        new(ErrorCode.InvalidArgument, $"{program}: {why}.", "program=inspector:PORT, inspector:HOST:PORT or inspector:ws://HOST:PORT/ID");
}
