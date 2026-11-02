using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Corvus.Core;

/// <summary>Canonical JSON and the result hashes of this process's recent calls (provenance resultSha256, note evidence).</summary>
public static class ResultHashes
{
    private const int MaxRecent = 1_000;

    // Calls with larger arguments, such as patch bodies, are not remembered.
    private const int MaxArgsChars = 16_384;

    // Arguments that only size or page a result; a call may carry them beyond the evidence.
    private static readonly HashSet<string> SizeArgs = new(StringComparer.Ordinal)
    {
        "limit", "offset", "maxTokens", "maxInstructions", "maxResults", "maxBytes", "maxDepth", "waitSeconds",
    };

    private static readonly List<(string Tool, string Canonical, Dictionary<string, string> Members, string Result)> Recent = [];

    private static readonly JsonSerializerOptions Compact = new() { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    /// <summary>JSON with object members in ordinal order and no insignificant white space.</summary>
    public static string Canonical(JsonNode? node, JsonSerializerOptions? options = null) => Sorted(node)?.ToJsonString(options ?? Compact) ?? "null";

    private static JsonNode? Sorted(JsonNode? node) => node switch
    {
        JsonObject o => new JsonObject(o.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => KeyValuePair.Create(p.Key, Sorted(p.Value)))),
        JsonArray a => new JsonArray(a.Select(Sorted).ToArray()),
        null => null,
        _ => node.DeepClone(),
    };

    public static string Sha256(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    /// <summary>Records a successful call with its arguments and result hash; arguments over 16,384 characters are not kept.</summary>
    public static void Remember(string tool, JsonNode? args, string resultSha256)
    {
        var call = args as JsonObject ?? new JsonObject();
        var canonical = Canonical(call);
        if (canonical.Length > MaxArgsChars) return;
        var members = Members(call);
        lock (Recent)
        {
            // A bounded memory of this process's calls, not a cache that must hold everything.
            if (Recent.Count >= MaxRecent) Recent.RemoveRange(0, MaxRecent / 2);
            Recent.Add((tool, canonical, members, resultSha256));
        }
    }

    /// <summary>
    /// The resultSha256 of this process's newest successful call of <paramref name="tool"/> with arguments identical to
    /// <paramref name="args"/>, else the newest whose extra arguments are only size or paging ones (limit, offset,
    /// maxTokens, maxInstructions and the like); null when none. Empty arguments match only a call without arguments.
    /// </summary>
    public static string? Latest(string tool, JsonNode? args)
    {
        var wanted = args as JsonObject ?? new JsonObject();
        var exact = Canonical(wanted);
        var wantedMembers = Members(wanted);
        lock (Recent)
        {
            for (int i = Recent.Count - 1; i >= 0; i--)
                if (Recent[i].Tool == tool && Recent[i].Canonical == exact) return Recent[i].Result;
            if (wantedMembers.Count == 0) return null;
            for (int i = Recent.Count - 1; i >= 0; i--)
            {
                var call = Recent[i].Members;
                if (Recent[i].Tool != tool) continue;
                if (wantedMembers.All(w => call.TryGetValue(w.Key, out var v) && v == w.Value)
                    && call.Keys.All(k => wantedMembers.ContainsKey(k) || SizeArgs.Contains(k)))
                    return Recent[i].Result;
            }
        }
        return null;
    }

    private static Dictionary<string, string> Members(JsonObject args) => args.ToDictionary(p => p.Key, p => Canonical(p.Value), StringComparer.Ordinal);
}
