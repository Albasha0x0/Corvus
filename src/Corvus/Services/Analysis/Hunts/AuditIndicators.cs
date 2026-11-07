using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Corvus.Services.Analysis.Hunts;

/// <summary>Writes Defender for Endpoint indicator bodies from the facts a proof kept; every body has action Audit and generateAlert true.</summary>
public static class AuditIndicators
{
    /// <summary>The only action of a written body: a match raises an alert and nothing is blocked.</summary>
    public const string Action = "Audit";

    /// <summary>The service limits named in the file: indicators per tenant, calls per minute and calls per hour.</summary>
    public const int TenantLimit = 15_000, PerMinute = 100, PerHour = 1_500;

    private static readonly string[] Notes =
    [
        "Each entry of indicators is a request body for POST https://api.security.microsoft.com/api/indicators; Corvus makes no call.",
        "Every action is Audit with generateAlert true: a match raises an alert and nothing is blocked.",
        $"Limits: {TenantLimit:N0} active indicators per tenant, {PerMinute} calls per minute, {PerHour:N0} calls per hour.",
        "File indicators need Defender Antivirus in active mode with file hash computation on; no expirationTime is set.",
        "No certificate indicator is written: it takes a leaf certificate thumbprint, which Corvus does not read.",
    ];

    /// <summary>
    /// The indicator file of <paramref name="set"/>, the number of indicators in it and the number of facts withheld: one FileSha1 and one FileSha256 body
    /// for a kept file hash, and a DomainName, Url or IpAddress body for each kept network value. Throws InvalidArgument for a set with no proof.
    /// </summary>
    public static (byte[] Json, int Count, int Withheld) Write(HuntSet set)
    {
        var (kept, withheld) = AuditFacts.Of(set);
        var sha1 = set.Image?.Sha1 ?? RuleProof.Sha1Of(set);
        var origin = sha1.Length >= 12 ? $"the file with SHA-1 {sha1[..12]}" : "a file";
        var bodies = new List<JsonObject>();
        foreach (var fact in kept)
        {
            var severity = char.ToUpperInvariant(fact.Severity[0]) + fact.Severity[1..];
            switch (fact.Kind)
            {
                case HuntKind.Sha1:
                    bodies.Add(Body(fact.Value, "FileSha1", $"Audit: file SHA-1 {fact.Value[..12]}", severity, origin));
                    if (set.Image is { } image && image.Sha1 == fact.Value) bodies.Add(Body(image.Sha256, "FileSha256", $"Audit: file SHA-256 {image.Sha256[..12]}", severity, origin));
                    else withheld.Add(new($"sha256 of {fact.Kind}:{fact.Value}", "unknown: the input is a saved set of queries, not the file"));
                    break;
                case HuntKind.Domain:
                    bodies.Add(Body(fact.Value, "DomainName", $"Audit: connection to {Short(fact.Value)}", severity, origin));
                    break;
                case HuntKind.Url:
                    bodies.Add(Body(fact.Value, "Url", $"Audit: connection to {Short(fact.Value)}", severity, origin));
                    break;
                default:
                    bodies.Add(Body(fact.Value, "IpAddress", $"Audit: connection to {fact.Value}", severity, origin));
                    break;
            }
        }
        var root = new JsonObject
        {
            ["indicators"] = new JsonArray([.. bodies.Select(b => (JsonNode)b)]),
            ["withheld"] = new JsonArray([.. withheld.Select(w => (JsonNode)new JsonObject { ["fact"] = w.Fact, ["reason"] = w.Reason })]),
            ["notes"] = new JsonArray([.. Notes.Select(n => (JsonNode)JsonValue.Create(n)!)]),
        };
        return (Encoding.UTF8.GetBytes(root.ToJsonString(new JsonSerializerOptions { WriteIndented = true })), bodies.Count, withheld.Count);
    }

    /// <summary>The note naming how many indicators and withheld facts <see cref="Write"/> saved to <paramref name="path"/>.</summary>
    public static string Written(int count, int withheld, string path)
        => $"{count} audit {(count == 1 ? "indicator" : "indicators")} written to {path}; {withheld} {(withheld == 1 ? "fact" : "facts")} withheld, each with its reason.";

    private static JsonObject Body(string value, string type, string title, string severity, string origin) => new()
    {
        ["indicatorValue"] = value,
        ["indicatorType"] = type,
        ["action"] = Action,
        ["title"] = title,
        ["description"] = $"Audit only. Kept by the clean-file proof of {origin}.",
        ["severity"] = severity,
        ["generateAlert"] = true,
    };

    // A cut never splits a surrogate pair.
    private static string Short(string value) => value.Length <= 60 ? value : value[..(char.IsHighSurrogate(value[56]) ? 56 : 57)] + "...";
}
