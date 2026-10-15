using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ModelContextProtocol;
using ModelContextProtocol.Server;
using Corvus.Core;

namespace Corvus.Mcp;

/// <summary>
/// The server's catalog (tools, resources, prompts) as registered, and its digest: one value that changes when a tool's
/// name, title, description, input or output schema, annotations or _meta change, or a prompt's name, title, description
/// or arguments. Computed from the protocol JSON, so a client's tools/list and prompts/list give the same digest.
/// Format: "t{tools}-{12 hex}.p{prompts}-{8 hex}", so a mismatch tells whether tools or prompts differ and by how many.
/// </summary>
public static partial class Catalog
{
    /// <summary>
    /// Serializes tool results (record text and structured content). Nulls are left out: <see cref="OutputSchemas"/> makes
    /// every nullable property optional. Relaxed escaping keeps generic names (List`1, &lt;Module&gt;) readable.
    /// </summary>
    public static readonly JsonSerializerOptions ToolSerializerOptions = new(McpJsonUtilities.DefaultOptions)
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private static readonly string[] ToolFields = ["name", "title", "description", "inputSchema", "outputSchema", "annotations", "_meta"];
    private static readonly string[] PromptFields = ["name", "title", "description", "arguments"];

    /// <summary>
    /// Registers this build's tools of the enabled <see cref="Toolsets"/> (from the registered <see cref="ServerOptions"/>, else the
    /// default set), resources and prompts, with annotations from <see cref="ToolEffects"/> and value sets from <see cref="ParameterDomains"/>.
    /// </summary>
    public static IMcpServerBuilder WithCatalog(this IMcpServerBuilder builder)
    {
        var assembly = typeof(Catalog).Assembly;
        builder.WithToolsInParallel(assembly, ToolSerializerOptions).WithResourcesFromAssembly(assembly).WithPromptsFromAssembly(assembly)
            .WithMessageFilters(filters => filters.AddIncomingFilter(ToolListCache.Filter));
        // Applied once the tool collection is complete.
        builder.Services.AddOptions<McpServerOptions>().PostConfigure<IServiceProvider>((o, services) =>
        {
            if (o.ToolCollection is not { } tools) return;
            var serverOptions = services.GetService<ServerOptions>();
            var enabled = serverOptions?.Toolsets ?? Toolsets.Default;
            foreach (var tool in tools.Where(t => !Profiles.Registers(enabled, serverOptions?.ToolAllowList, t.ProtocolTool.Name)).ToList()) tools.Remove(tool);
            ToolEffects.Apply(tools);
            ParameterDomains.Apply(tools);
            DropNullDefaults(tools);
            DropNullableInputs(tools);
            DropImpliedDefaults(tools);
            DropPagingDescriptions(tools);
            ToolOutput.ApplyEnvelope(tools);
            foreach (var tool in tools)
                if (tool.ProtocolTool.OutputSchema is { } output)
                {
                    GeneratedSchemas[tool.ProtocolTool.Name] = output;
                    tool.ProtocolTool.OutputSchema = OutputSchemas.Compact(output);
                }
        });
        return builder;
    }

    /// <summary>Every tool of <see cref="WithToolsInParallel"/>, made on first use.</summary>
    internal sealed class ToolSet(McpServerTool[] tools)
    {
        public McpServerTool[] Tools { get; } = tools;
    }

    /// <summary>
    /// WithToolsFromAssembly with the tools made on all cores: building each tool's schemas from its method took about 0.7 s
    /// one by one, before the server could answer initialize. Same tools, same order.
    /// </summary>
    private static readonly Lock BuildGate = new();

    internal static IMcpServerBuilder WithToolsInParallel(this IMcpServerBuilder builder, System.Reflection.Assembly assembly, JsonSerializerOptions serializerOptions)
    {
        const System.Reflection.BindingFlags all = System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Static
            | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic;
        var methods = assembly.GetTypes()
            .Where(t => System.Reflection.CustomAttributeExtensions.GetCustomAttribute<McpServerToolTypeAttribute>(t) != null)
            .SelectMany(t => t.GetMethods(all).Where(m => System.Reflection.CustomAttributeExtensions.GetCustomAttribute<McpServerToolAttribute>(m) != null)
                .Select(m => (Type: t, Method: m)))
            .ToArray();
        builder.Services.AddSingleton(services =>
        {
            var tools = new McpServerTool[methods.Length];
            // One catalog build at a time: two builds making the same tool at once race in the SDK and leak a RequestContext
            // parameter into its schema (servers in one process: tests).
            lock (BuildGate)
                Parallel.For(0, methods.Length, i =>
                {
                    var (type, method) = methods[i];
                    var options = new McpServerToolCreateOptions { Services = services, SerializerOptions = serializerOptions };
                    tools[i] = method.IsStatic ? McpServerTool.Create(method, (object?)null, options)
                        : McpServerTool.Create(method, r => r.Services is { } s ? ActivatorUtilities.CreateInstance(s, type) : Activator.CreateInstance(type)!, options);
                });
            return new ToolSet(tools);
        });
        for (int i = 0; i < methods.Length; i++)
        {
            int k = i;
            builder.Services.AddSingleton(services => services.GetRequiredService<ToolSet>().Tools[k]);
        }
        return builder;
    }

    // The generated schemas, for docs/schemas; the described form is made only when asked for.
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, JsonElement> GeneratedSchemas = new(StringComparer.Ordinal);

    /// <summary>Each structured tool's output schema with its descriptions and full depth (docs/schemas), by tool name.</summary>
    public static SortedDictionary<string, JsonElement> DescribedOutputSchemas()
    {
        _ = Built.Value;
        return new(GeneratedSchemas.ToDictionary(s => s.Key, s => OutputSchemas.Described(s.Value)), StringComparer.Ordinal);
    }

    /// <summary>Removes "default": null from input and output schemas; an optional property without a default says the same in fewer bytes.</summary>
    private static void DropNullDefaults(IEnumerable<McpServerTool> tools)
    {
        foreach (var tool in tools)
        {
            var t = tool.ProtocolTool;
            if (Without(t.InputSchema) is { } input) t.InputSchema = input;
            if (t.OutputSchema is { } output && Without(output) is { } trimmed) t.OutputSchema = trimmed;
        }

        static JsonElement? Without(JsonElement schema)
        {
            var node = JsonNode.Parse(schema.GetRawText());
            return Drop(node) ? JsonSerializer.SerializeToElement(node) : null;
        }

        static bool Drop(JsonNode? node)
        {
            bool changed = false;
            if (node is JsonObject o)
            {
                if (o.TryGetPropertyValue("default", out var d) && d is null) changed = o.Remove("default");
                foreach (var (_, child) in o) changed |= Drop(child);
            }
            else if (node is JsonArray a)
                foreach (var child in a) changed |= Drop(child);
            return changed;
        }
    }

    /// <summary>
    /// Removes "null" from input parameter types and enums (C# nullables): an optional parameter is left out, not sent as
    /// null, and the union cost about 6 KB of the model-facing catalog. A null sent anyway still binds as omitted. Open
    /// array items get a type.
    /// </summary>
    private static void DropNullableInputs(IEnumerable<McpServerTool> tools)
    {
        foreach (var tool in tools)
        {
            var t = tool.ProtocolTool;
            var schema = JsonNode.Parse(t.InputSchema.GetRawText());
            if (Drop(schema)) t.InputSchema = JsonSerializer.SerializeToElement(schema);
        }

        static bool Drop(JsonNode? node)
        {
            bool changed = false;
            if (node is JsonObject o)
            {
                if (o["type"] is JsonArray types && types.Any(x => (string?)x == "null"))
                {
                    var kept = types.Select(x => (string)x!).Where(x => x != "null").ToList();
                    o["type"] = kept.Count == 1 ? JsonValue.Create(kept[0]) : new JsonArray([.. kept.Select(k => (JsonNode)JsonValue.Create(k)!)]);
                    changed = true;
                }
                if (o["enum"] is JsonArray values)
                    for (int i = values.Count - 1; i >= 0; i--)
                        if (values[i] is null) { values.RemoveAt(i); changed = true; }
                // An open item ({}, a converter-read type such as note evidence) is rejected by strict gateways (SchemaGate);
                // the items are objects, and a string a converter also takes still binds.
                if (o["items"] is JsonObject { Count: 0 }) { o["items"] = new JsonObject { ["type"] = "object" }; changed = true; }
                foreach (var (_, child) in o) changed |= Drop(child);
            }
            else if (node is JsonArray a)
                foreach (var child in a) changed |= Drop(child);
            return changed;
        }
    }

    /// <summary>Removes the defaults the conventions imply: a boolean without one is false (S7.2), an offset 0 (S2.1).</summary>
    private static void DropImpliedDefaults(IEnumerable<McpServerTool> tools)
    {
        foreach (var tool in tools)
        {
            var t = tool.ProtocolTool;
            if (JsonNode.Parse(t.InputSchema.GetRawText()) is not JsonObject schema || schema["properties"] is not JsonObject properties) continue;
            bool changed = false;
            foreach (var (name, property) in properties)
                if (property is JsonObject p && p["default"] is JsonValue d
                    && ((string?)p["type"] == "boolean" && d.GetValueKind() == JsonValueKind.False
                        || name == "offset" && d.GetValueKind() == JsonValueKind.Number && d.GetValue<long>() == 0))
                    changed |= p.Remove("default");
            if (changed) t.InputSchema = JsonSerializer.SerializeToElement(schema);
        }
    }

    /// <summary>
    /// Removes the paging parameters' generic descriptions (offset, limit, maxTokens): the server instructions explain them
    /// once (about 6.6 KB of the model-facing catalog). A parameter whose text says more, such as its maximum, keeps it.
    /// </summary>
    private static void DropPagingDescriptions(IEnumerable<McpServerTool> tools)
    {
        foreach (var tool in tools)
        {
            var t = tool.ProtocolTool;
            if (JsonNode.Parse(t.InputSchema.GetRawText()) is not JsonObject schema || schema["properties"] is not JsonObject properties) continue;
            bool changed = false;
            foreach (var (name, property) in properties)
                if (property is JsonObject p && PagingParameters.TryGetValue(name, out var generic) && p["description"] is JsonValue d && generic.Contains((string?)d))
                    changed |= p.Remove("description");
            if (changed) t.InputSchema = JsonSerializer.SerializeToElement(schema);
        }
    }

    /// <summary>The paging parameters and the generic descriptions the server instructions stand in for.</summary>
    public static readonly IReadOnlyDictionary<string, string[]> PagingParameters = new Dictionary<string, string[]>(StringComparer.Ordinal)
    {
        ["offset"] = [Corvus.Tools.ToolSupport.RowOffsetDescription, Corvus.Tools.ToolSupport.CharOffsetDescription],
        ["limit"] = [Corvus.Tools.ToolSupport.LimitDescription],
        ["maxTokens"] = [Corvus.Tools.ToolSupport.MaxTokensDescription],
    };

    /// <summary>This build's catalog as a server started without --toolsets lists it (what a client's default registration sees).</summary>
    public static (List<JsonNode> Tools, List<JsonNode> Prompts) OfThisBuild() => OfThisBuild(Toolsets.Default);

    /// <summary>This build's catalog with <paramref name="toolsets"/> enabled (<see cref="Toolsets.All"/>: every tool).</summary>
    public static (List<JsonNode> Tools, List<JsonNode> Prompts) OfThisBuild(IReadOnlySet<string> toolsets)
    {
        var (tools, prompts) = Built.Value;
        return (tools.Where(t => Profiles.Registers(toolsets, (string)t["name"]!)).Select(t => t.DeepClone()).ToList(), prompts.Select(p => p.DeepClone()).ToList());
    }

    // Built once, with every toolset: concurrent registrations in one process race in the SDK's schema generation (a RequestContext parameter leaks into the schema).
    private static readonly Lazy<(List<JsonNode> Tools, List<JsonNode> Prompts)> Built = new(() =>
    {
        var services = new ServiceCollection();
        services.AddSingleton(new ServerOptions { Toolsets = Toolsets.All });
        services.AddMcpServer().WithCatalog();
        using var provider = services.BuildServiceProvider();
        return Of(provider.GetRequiredService<IOptions<McpServerOptions>>().Value);
    });

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
