using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ModelContextProtocol;
using ModelContextProtocol.Server;

namespace NetDecompilerMcp.Mcp;

/// <summary>
/// The server's catalog (tools, resources, prompts) as registered, and its digest: one value that changes when a tool's
/// name, title, description, input or output schema, annotations or _meta change, or a prompt's name, title, description
/// or arguments. Computed from the protocol JSON, so a client's tools/list and prompts/list give the same digest.
/// Format: "t{tools}-{12 hex}.p{prompts}-{8 hex}", so a mismatch tells whether tools or prompts differ and by how many.
/// </summary>
public static partial class Catalog
{
    /// <summary>Nulls serialized explicitly: generated output schemas mark every property required, so omitted nulls fail validation.</summary>
    public static readonly JsonSerializerOptions ToolSerializerOptions = new(McpJsonUtilities.DefaultOptions)
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never,
    };

    private static readonly string[] ToolFields = ["name", "title", "description", "inputSchema", "outputSchema", "annotations", "_meta"];
    private static readonly string[] PromptFields = ["name", "title", "description", "arguments"];

    /// <summary>Registers this build's tools, resources and prompts, with annotations from <see cref="ToolEffects"/>.</summary>
    public static IMcpServerBuilder WithCatalog(this IMcpServerBuilder builder)
    {
        var assembly = typeof(Catalog).Assembly;
        builder.WithToolsFromAssembly(assembly, ToolSerializerOptions).WithResourcesFromAssembly(assembly).WithPromptsFromAssembly(assembly);
        // Applied once the tool collection is complete.
        builder.Services.PostConfigure<McpServerOptions>(o =>
        {
            if (o.ToolCollection is { } tools) ToolEffects.Apply(tools);
        });
        return builder;
    }

    /// <summary>This build's catalog, registered in process the way the server registers it.</summary>
    public static (List<JsonNode> Tools, List<JsonNode> Prompts) OfThisBuild()
    {
        var services = new ServiceCollection();
        services.AddMcpServer().WithCatalog();
        using var provider = services.BuildServiceProvider();
        return Of(provider.GetRequiredService<IOptions<McpServerOptions>>().Value);
    }

    /// <summary>The protocol JSON of a server's tools and prompts.</summary>
    public static (List<JsonNode> Tools, List<JsonNode> Prompts) Of(McpServerOptions options) =>
        ((options.ToolCollection ?? []).Select(t => JsonSerializer.SerializeToNode(t.ProtocolTool, McpJsonUtilities.DefaultOptions)!).ToList(),
         (options.PromptCollection ?? []).Select(p => JsonSerializer.SerializeToNode(p.ProtocolPrompt, McpJsonUtilities.DefaultOptions)!).ToList());

    public static string Digest(IEnumerable<JsonNode?> tools, IEnumerable<JsonNode?> prompts)
    {
        var t = Hashes(tools, ToolFields);
        var p = Hashes(prompts, PromptFields);
        return $"t{t.Count}-{Combine(t)[..12]}.p{p.Count}-{Combine(p)[..8]}";
    }

    /// <summary>Each tool's hash by name (what tools/list says about it).</summary>
    public static SortedDictionary<string, string> ToolHashes(IEnumerable<JsonNode?> tools) => Hashes(tools, ToolFields);

    public static SortedDictionary<string, string> PromptHashes(IEnumerable<JsonNode?> prompts) => Hashes(prompts, PromptFields);

    /// <summary>Null when <paramref name="expected"/> equals <paramref name="actual"/>; else what differs, as far as the digests tell.</summary>
    public static string? Difference(string expected, string actual)
    {
        expected = expected.Trim();
        if (string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase)) return null;
        if (DigestPattern().Match(expected) is not { Success: true } e || DigestPattern().Match(actual) is not { Success: true } a)
            return $"'{expected}' is not a catalog digest of this form: {actual}.";
        var parts = new List<string>();
        int et = int.Parse(e.Groups[1].Value), at = int.Parse(a.Groups[1].Value), ep = int.Parse(e.Groups[3].Value), ap = int.Parse(a.Groups[3].Value);
        if (et != at) parts.Add($"tools: {et} expected, this server has {at} ({(at > et ? "added" : "removed")} {Math.Abs(at - et)} or more)");
        else if (!e.Groups[2].Value.Equals(a.Groups[2].Value, StringComparison.OrdinalIgnoreCase))
            parts.Add($"tools: the same number ({at}), but names, schemas, descriptions or annotations differ");
        if (ep != ap) parts.Add($"prompts: {ep} expected, this server has {ap}");
        else if (!e.Groups[4].Value.Equals(a.Groups[4].Value, StringComparison.OrdinalIgnoreCase))
            parts.Add($"prompts: the same number ({ap}), but names, descriptions or arguments differ");
        return string.Join("; ", parts);
    }

    [GeneratedRegex(@"^t(\d+)-([0-9a-f]{12})\.p(\d+)-([0-9a-f]{8})$", RegexOptions.IgnoreCase)]
    private static partial Regex DigestPattern();

    private static SortedDictionary<string, string> Hashes(IEnumerable<JsonNode?> items, string[] fields)
    {
        var result = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var item in items)
        {
            if (item is not JsonObject o || o["name"]?.GetValue<string>() is not { } name) continue;
            var picked = new JsonObject();
            foreach (var f in fields)
                if (o[f] is { } v) picked[f] = Canonical(v);
            result[name] = Hex(picked.ToJsonString());
        }
        return result;
    }

    private static string Combine(SortedDictionary<string, string> hashes) =>
        Hex(string.Concat(hashes.Select(h => h.Key + "\n" + h.Value + "\n")));

    /// <summary>A copy with object members in ordinal order, so equal JSON hashes equally whatever the member order.</summary>
    private static JsonNode? Canonical(JsonNode? node) => node switch
    {
        JsonObject o => new JsonObject(o.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => KeyValuePair.Create(p.Key, Canonical(p.Value)))),
        JsonArray a => new JsonArray(a.Select(Canonical).ToArray()),
        null => null,
        _ => JsonNode.Parse(node.ToJsonString()),
    };

    private static string Hex(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
}
