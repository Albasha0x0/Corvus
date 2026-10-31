using System.Globalization;
using System.Text.Json;

namespace Corvus.Core;

/// <summary>A recorded gateway response; Body is null when not recorded.</summary>
public sealed record GatewayResponse(int Sequence, string Url, byte[]? Body);

/// <summary>A recorded Network.Connect call; a null Host or Port is unknown.</summary>
public sealed record ConnectCall(int Sequence, string? Host, int? Port);

/// <summary>A response's host and port pair joined to the later connect that used it.</summary>
public sealed record ConnectionJoin(
    int ResponseSequence, string ResponseUrl, string SourceHostField, string SourcePortField,
    int ConnectSequence, string DestinationHostField, string DestinationPortField, string Host, int Port);

/// <summary>An entry that joined nothing; Side is "response" or "connect".</summary>
public sealed record UnresolvedJoin(string Side, int Sequence, string Reason);

/// <summary>The joins of one recording; each unresolved entry is unknown, not absent.</summary>
public sealed record ConnectionFlowReport(IReadOnlyList<ConnectionJoin> Joins, IReadOnlyList<UnresolvedJoin> Unresolved);

/// <summary>Joins host and port pairs in responses to later connect calls.</summary>
public static class ConnectionFlow
{
    /// <summary>The destination field that receives the joined host.</summary>
    public const string DestinationHostField = "Network.Connect.host";

    /// <summary>The destination field that receives the joined port.</summary>
    public const string DestinationPortField = "Network.Connect.port";

    /// <summary>The reason given to a response whose JSON holds no host and port pair.</summary>
    public const string NoPairReason = "no host and port field pair";

    private const int MaxDepth = 64;

    private static readonly string[] HostNames = ["host", "hostname", "address", "ip", "server"];
    private static readonly string[] PortNames = ["port", "tcpPort"];

    private sealed record Candidate(string HostField, string PortField, string Host, int Port);

    /// <summary>
    /// Joins each host and port pair to the first later unused connect with the
    /// same pair; unmatched entries and unreadable bodies are reported.
    /// </summary>
    public static ConnectionFlowReport Join(IEnumerable<GatewayResponse> responses, IEnumerable<ConnectCall> connects)
    {
        var calls = connects.OrderBy(c => c.Sequence).ToList();
        var byPair = new Dictionary<(string, int), List<int>>();
        for (int i = 0; i < calls.Count; i++)
        {
            if (calls[i].Host is { } h && calls[i].Port is { } p)
            {
                var key = (h.ToUpperInvariant(), p);
                if (!byPair.TryGetValue(key, out var ix)) byPair[key] = ix = [];
                ix.Add(i);
            }
        }
        var used = new HashSet<int>();
        var joins = new List<ConnectionJoin>();
        var unresolved = new List<UnresolvedJoin>();
        var seen = new List<(int Sequence, string Host, int Port)>();

        foreach (var r in responses.OrderBy(r => r.Sequence))
        {
            var found = Candidates(r, out var notes);
            foreach (var n in notes) unresolved.Add(new("response", r.Sequence, n));
            foreach (var c in found)
            {
                seen.Add((r.Sequence, c.Host, c.Port));
                // A connect joins one pair, and only a response that precedes it.
                int hit = byPair.TryGetValue((c.Host.ToUpperInvariant(), c.Port), out var ix)
                    ? ix.FirstOrDefault(i => calls[i].Sequence > r.Sequence && !used.Contains(i), -1)
                    : -1;
                if (hit >= 0)
                {
                    used.Add(hit);
                    joins.Add(new(r.Sequence, r.Url, c.HostField, c.PortField, calls[hit].Sequence,
                        DestinationHostField, DestinationPortField, c.Host, c.Port));
                    continue;
                }
                bool portDiffers = calls.Any(k => k.Sequence > r.Sequence && k.Port != c.Port && string.Equals(k.Host, c.Host, StringComparison.OrdinalIgnoreCase));
                unresolved.Add(new("response", r.Sequence, portDiffers
                    ? $"a later connect names {c.Host} with another port"
                    : $"no later connect names {c.Host}:{c.Port}"));
            }
        }

        for (int i = 0; i < calls.Count; i++)
        {
            if (used.Contains(i)) continue;
            var k = calls[i];
            unresolved.Add(new("connect", k.Sequence, k.Host is null || k.Port is null
                ? "host or port not recorded"
                : seen.Any(s => s.Sequence < k.Sequence && Same(k, s.Host, s.Port))
                    ? "every earlier host and port pair naming it is joined to another connect"
                    : $"no earlier response names {k.Host}:{k.Port}"));
        }
        return new(joins, unresolved.OrderBy(u => u.Sequence).ToList());
    }

    private static bool Same(ConnectCall k, string host, int port) =>
        k.Port == port && string.Equals(k.Host, host, StringComparison.OrdinalIgnoreCase);

    private static List<Candidate> Candidates(GatewayResponse r, out List<string> notes)
    {
        var list = new List<Candidate>();
        notes = [];
        if (r.Body is null) { notes.Add("body not recorded"); return list; }
        if (r.Body.Length == 0) { notes.Add("body is empty"); return list; }
        try
        {
            using var doc = JsonDocument.Parse(r.Body, new JsonDocumentOptions { MaxDepth = MaxDepth });
            Walk(doc.RootElement, "$", list, notes);
        }
        catch (JsonException)
        {
            list.Clear();
            notes.Clear();
            notes.Add($"body is not JSON or is nested deeper than {MaxDepth} levels");
            return list;
        }
        if (list.Count == 0 && notes.Count == 0) notes.Add(NoPairReason);
        return list;
    }

    // Reads the first host-named and first port-named field of each object; later ones are noted.
    private static void Walk(JsonElement e, string path, List<Candidate> list, List<string> notes)
    {
        if (e.ValueKind == JsonValueKind.Array)
        {
            int i = 0;
            foreach (var item in e.EnumerateArray()) Walk(item, $"{path}[{i++}]", list, notes);
        }
        else if (e.ValueKind == JsonValueKind.Object)
        {
            var props = e.EnumerateObject().ToList();
            var hosts = props.Where(p => p.Value.ValueKind == JsonValueKind.String
                && HostNames.Contains(p.Name, StringComparer.OrdinalIgnoreCase)).ToList();
            var ports = props.Where(p => PortNames.Contains(p.Name, StringComparer.OrdinalIgnoreCase)).ToList();
            if (hosts.Count > 0 && ports.Count > 0)
            {
                var hp = hosts[0];
                var pp = ports[0];
                string host = hp.Value.GetString() ?? "";
                int? port = PortOf(pp.Value);
                if (host.Length == 0) notes.Add($"host field {path}.{hp.Name} is empty");
                else if (port is null) notes.Add($"port field {path}.{pp.Name} is not a port from 1 to 65535");
                else list.Add(new($"{path}.{hp.Name}", $"{path}.{pp.Name}", host, port.Value));
                if (hosts.Count > 1 || ports.Count > 1)
                    notes.Add($"{path} has more than one host or port field; only {hp.Name} and {pp.Name} were read");
            }
            foreach (var p in props) Walk(p.Value, $"{path}.{p.Name}", list, notes);
        }
    }

    private static int? PortOf(JsonElement v) => v.ValueKind switch
    {
        JsonValueKind.Number when v.TryGetInt32(out int n) && n is > 0 and <= 65535 => n,
        JsonValueKind.String when int.TryParse(v.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out int n) && n is > 0 and <= 65535 => n,
        _ => null,
    };
}
