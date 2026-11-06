using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Corvus.Services.Analysis.Hunts;

/// <summary>Microsoft Graph v1.0 detectionRule bodies for hunting queries; a rule is created disabled, so nothing runs until a person enables it.</summary>
public static class HuntRules
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web) { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull };

    /// <summary>The ISO 8601 run interval of every rule: once a day.</summary>
    public const string Frequency = "P1D";

    /// <summary>The hunts that become detection rules: every query except a signer query, which matches every file the publisher signs, a <see cref="Hunt.HuntingOnly"/> query and a query the proof dropped.</summary>
    public static IReadOnlyList<Hunt> Rules(HuntSet set) => [.. set.Hunts.Where(h => h.Table != "DeviceFileCertificateInfo" && !h.HuntingOnly && h.Proof?.Verdict != "drop")];

    /// <summary>The detectionRule body of <paramref name="hunt"/>: id, names, query, schedule, status disabled and an alert template that maps the columns its query returns.</summary>
    public static JsonObject Rule(Hunt hunt)
    {
        var description = "Created from " + string.Join(", ", hunt.Facts.Select(f => f.Length > 200 ? f[..200] : f)) + ".";
        return new JsonObject
        {
            ["@odata.type"] = "#microsoft.graph.security.detectionRule",
            ["id"] = hunt.Id,
            ["displayName"] = hunt.Title,
            ["description"] = description,
            ["status"] = "disabled",
            ["queryCondition"] = new JsonObject { ["queryText"] = hunt.Kql },
            ["schedule"] = new JsonObject { ["frequency"] = Frequency },
            ["detectionAction"] = new JsonObject
            {
                ["alertTemplate"] = new JsonObject
                {
                    ["title"] = hunt.Title,
                    ["description"] = description,
                    ["severity"] = hunt.Severity,
                    ["entityMappings"] = Mappings(hunt),
                },
            },
        };
    }

    // An Event table query returns Computer and no file hash.
    private static JsonObject Mappings(Hunt hunt) => hunt.Table == "Event"
        ? new JsonObject { ["hosts"] = new JsonArray(new JsonObject { ["nameColumn"] = "Computer" }) }
        : new JsonObject
        {
            ["hosts"] = new JsonArray(new JsonObject { ["deviceIdColumn"] = "DeviceId", ["nameColumn"] = "DeviceName" }),
            ["files"] = new JsonArray(new JsonObject { ["sha1Column"] = "SHA1" }),
        };

    /// <summary>The note naming how many queries and rules <see cref="Write"/> saved to a path.</summary>
    public static string Written(HuntSet set, string path)
    {
        int queries = set.Hunts.Count, rules = Rules(set).Count;
        int dropped = set.Hunts.Count(h => h.Proof?.Verdict == "drop");
        var tail = dropped > 0 ? $"; {dropped} dropped by the proof, no rule" : "";
        return $"{queries} hunting {(queries == 1 ? "query" : "queries")} and {rules} detection {(rules == 1 ? "rule" : "rules")} (disabled) written to {path}{tail}.";
    }

    /// <summary>
    /// The hunt set of a file <see cref="Write"/> saved; null when the bytes are not one. A query with no rule and no
    /// drop verdict is a hunting-only query.
    /// </summary>
    public static HuntSet? Read(ReadOnlySpan<byte> bytes)
    {
        // Only a small file that starts like a JSON object is parsed.
        int at = 0;
        while (at < bytes.Length && bytes[at] is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n') at++;
        if (bytes.Length > 16 << 20 || at == bytes.Length || bytes[at] != (byte)'{' && bytes[at] != 0xEF) return null;
        try
        {
            if (JsonNode.Parse(bytes) is not JsonObject { } root || root["hunts"] is not JsonArray queries) return null;
            var ruleIds = (root["detectionRules"] as JsonArray ?? []).Select(r => (string?)r?["id"]).ToHashSet();
            var hunts = new List<Hunt>();
            foreach (var q in queries)
            {
                if (q is not JsonObject o || (string?)o["id"] is not { } id || (string?)o["kql"] is not { } kql || o["facts"] is not JsonArray facts) return null;
                var table = (string?)o["table"] ?? "";
                bool dropped = (string?)o["proof"]?["verdict"] == "drop";
                hunts.Add(new Hunt(id, (string?)o["title"] ?? id, table, kql, [.. facts.Select(x => x?.GetValue<string>() ?? "")], (string?)o["evidence"] ?? "")
                {
                    Severity = (string?)o["severity"] ?? "informational",
                    HuntingOnly = !ruleIds.Contains(id) && !dropped && table != "DeviceFileCertificateInfo",
                });
            }
            return new HuntSet(hunts, [.. (root["notes"] as JsonArray ?? []).Select(n => n?.GetValue<string>() ?? "")]);
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or FormatException) { return null; }
    }

    /// <summary>The JSON file of a hunt set: the queries, one disabled detectionRule body per query, and the notes.</summary>
    public static byte[] Write(HuntSet set)
    {
        var rules = Rules(set);
        var notes = set.Notes.ToList();
        if (set.Hunts.Any(h => h.Table == "DeviceFileCertificateInfo" || h.HuntingOnly)) notes.Add("Signer and DNS or TLS name queries are hunting queries only: they match every file the publisher signs or name no file, so no detection rule is written for them.");
        if (set.Hunts.Any(h => h.Proof?.Verdict == "drop")) notes.Add("A query the proof dropped keeps its verdict and gets no detection rule.");
        var root = new JsonObject
        {
            ["hunts"] = new JsonArray([.. set.Hunts.Select(h => (JsonNode)new JsonObject
            {
                ["id"] = h.Id,
                ["title"] = h.Title,
                ["table"] = h.Table,
                ["kql"] = h.Kql,
                ["facts"] = new JsonArray([.. h.Facts.Select(f => (JsonNode)JsonValue.Create(f)!)]),
                ["evidence"] = h.Evidence,
                ["severity"] = h.Severity,
            })]),
            ["detectionRules"] = new JsonArray([.. rules.Select(h => (JsonNode)Rule(h))]),
            ["notes"] = new JsonArray([.. notes.Select(n => (JsonNode)JsonValue.Create(n)!)]),
        };
        if (set.Proof != null) root["proof"] = JsonSerializer.SerializeToNode(set.Proof, Options);
        var queries = (JsonArray)root["hunts"]!;
        for (int i = 0; i < set.Hunts.Count; i++)
            if (set.Hunts[i].Proof is { } proof) ((JsonObject)queries[i]!)["proof"] = JsonSerializer.SerializeToNode(proof, Options);
        return Encoding.UTF8.GetBytes(root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }
}
