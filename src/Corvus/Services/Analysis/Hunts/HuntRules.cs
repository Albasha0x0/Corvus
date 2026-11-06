using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Corvus.Services.Analysis.Hunts;

/// <summary>Microsoft Graph v1.0 detectionRule bodies for hunting queries; a rule is created disabled, so nothing runs until a person enables it.</summary>
public static class HuntRules
{
    /// <summary>The ISO 8601 run interval of every rule: once a day.</summary>
    public const string Frequency = "P1D";

    /// <summary>The hunts that become detection rules: every query except a signer query, which matches every file the publisher signs, and a <see cref="Hunt.HuntingOnly"/> query.</summary>
    public static IReadOnlyList<Hunt> Rules(HuntSet set) => [.. set.Hunts.Where(h => h.Table != "DeviceFileCertificateInfo" && !h.HuntingOnly)];

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
        return $"{queries} hunting {(queries == 1 ? "query" : "queries")} and {rules} detection {(rules == 1 ? "rule" : "rules")} (disabled) written to {path}.";
    }

    /// <summary>The JSON file of a hunt set: the queries, one disabled detectionRule body per query, and the notes.</summary>
    public static byte[] Write(HuntSet set)
    {
        var rules = Rules(set);
        var notes = set.Notes.ToList();
        if (rules.Count < set.Hunts.Count) notes.Add("Signer and DNS or TLS name queries are hunting queries only: they match every file the publisher signs or name no file, so no detection rule is written for them.");
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
        return Encoding.UTF8.GetBytes(root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }
}
