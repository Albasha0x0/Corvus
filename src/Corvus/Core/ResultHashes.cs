using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Corvus.Core;

/// <summary>Canonical JSON and the result hashes of this process's recent calls (provenance resultSha256, note evidence).</summary>
public static class ResultHashes
{
    private const int MaxRecent = 1_000;

    private static readonly ConcurrentDictionary<(string Tool, string Args), string> Recent = new();

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

    /// <summary>Records a successful call: <paramref name="argsSha256"/> is the SHA-256 of its canonical arguments.</summary>
    public static void Remember(string tool, string argsSha256, string resultSha256)
    {
        if (Recent.Count >= MaxRecent) Recent.Clear(); // a bounded memory of this process's calls, not a cache that must hold everything
        Recent[(tool, argsSha256)] = resultSha256;
    }

    /// <summary>The resultSha256 of this process's latest successful call of <paramref name="tool"/> with these arguments, or null.</summary>
    public static string? Latest(string tool, JsonNode? args) => Recent.GetValueOrDefault((tool, Sha256(Canonical(args ?? new JsonObject()))));
}
