using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol.Protocol;
using Corvus.Core;

namespace Corvus.Mcp;

public static partial class ToolOutput
{
    public const string ProvenanceKey = "corvus/provenance";

    /// <summary>Parameters that name an input file or a loaded target.</summary>
    private static readonly string[] InputParameters = ["assembly", "image", "path", "oldAssembly", "newAssembly", "oldImage", "newImage", "oldPath", "newPath"];

    private const int MaxInputs = 4;

    private static readonly ConcurrentDictionary<(string Path, long Length, long Ticks), string> FileHashes = new();

    /// <summary>A result's provenance for _meta: inputs with SHA-256, tool, argument hash, engine, version and, on success, result hash and coverage; about 1 KB at most.</summary>
    internal static JsonObject Provenance(string tool, IDictionary<string, JsonElement>? args, AssemblyWorkspace? workspace, string? engine,
        CallToolResult result, OutputCall call, string? resultSha256 = null)
    {
        var inputs = new JsonArray();
        void Collect()
        {
            foreach (var name in InputParameters)
                if (args != null && args.TryGetValue(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } value
                    && inputs.Count < MaxInputs && Input(value, workspace) is { } input && !inputs.Any(i => (string?)i!["sha256"] == (string?)input["sha256"]))
                    inputs.Add(input);
        }
        Collect();
        var p = new JsonObject
        {
            ["input"] = inputs,
            ["tool"] = tool,
            ["args"] = Sha256(Canonical(args == null ? new JsonObject() : JsonSerializer.SerializeToNode(args))),
        };
        if (engine != null) p["engine"] = engine;
        foreach (var (key, value) in call.EngineMeta) p[key] = value is null ? null : Serialize(value);
        p["corvus"] = ServerIdentity.InformationalVersion;
        if (ToolContract.Of(tool).UntrustedContent)
        {
            p["untrustedContent"] = true;
            p["source"] = "analysis_target";
        }
        // An error is no result to verify: what was asked of which inputs is its provenance.
        if (result.IsError == true) return p;
        p["resultSha256"] = resultSha256 ?? ResultSha256(result);
        ResultHashes.Remember(tool, ResultHashes.Sha256(ResultHashes.Canonical(args == null ? new JsonObject() : JsonSerializer.SerializeToNode(args))), (string)p["resultSha256"]!);
        p["coverage"] = call.Coverage?.Status ?? "complete";
        if (call.Facets is { Count: > 0 } facets) p["facets"] = Facets(facets);
        if (call.Coverage is { Limitations.Count: > 0 } c)
            p["limitations"] = new JsonArray(c.Limitations.Concat(p["limitations"] is JsonArray stated ? stated.Select(l => (string)l!) : [])
                .Distinct().Take(8).Select(l => (JsonNode)JsonValue.Create(l)!).ToArray());
        return p;
    }

    /// <summary>SHA-256 of the canonical structured JSON, else of the text, without workspace notices.</summary>
    // Without notices the hash equals the one earlier versions gave.
    public static string ResultSha256(CallToolResult result)
    {
        if (result.StructuredContent is { } s)
        {
            var record = JsonNode.Parse(s.GetRawText());
            if (record is JsonObject o) o.Remove("notices");
            return Sha256(Canonical(record));
        }
        var blocks = result.Content.OfType<TextContentBlock>().ToList();
        if (blocks.Count > 0 && blocks[^1].Text.StartsWith(NoticePrefix, StringComparison.Ordinal)) blocks.RemoveAt(blocks.Count - 1);
        return Sha256(string.Concat(blocks.Select(b => b.Text)));
    }

    /// <summary>The prefix of the text block that carries a call's workspace notices.</summary>
    public const string NoticePrefix = "[workspace] ";

    /// <summary>JSON with object members in ordinal order and no insignificant white space.</summary>
    public static string Canonical(JsonNode? node) => Sorted(node)?.ToJsonString(Json) ?? "null";

    private static JsonNode? Sorted(JsonNode? node) => node switch
    {
        JsonObject o => new JsonObject(o.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => KeyValuePair.Create(p.Key, Sorted(p.Value)))),
        JsonArray a => new JsonArray(a.Select(Sorted).ToArray()),
        null => null,
        _ => node.DeepClone(),
    };

    private static string Sha256(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    /// <summary>A loaded target by id, name, file name or path; else an existing file, hashed once per version.</summary>
    /// <summary>The inputs a call names, by the argument as given and the SHA-256 it resolves to now.</summary>
    internal static IReadOnlyList<KeptInput> Inputs(IDictionary<string, JsonElement>? args, AssemblyWorkspace? workspace) =>
        args == null ? [] : [.. InputParameters
            .Select(name => args.TryGetValue(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } value ? value : null)
            .OfType<string>().Distinct().Take(MaxInputs)
            .Select(value => (value, sha: (string?)Input(value, workspace)?["sha256"])).Where(x => x.sha != null).Select(x => new KeptInput(x.value, x.sha!))];

    internal static JsonObject? Input(string value, AssemblyWorkspace? workspace)
    {
        try
        {
            return Find(value, workspace);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    private static JsonObject? Find(string value, AssemblyWorkspace? workspace)
    {
        // The published entries, not the lock: this runs after the call, outside its cancellation scope.
        foreach (var t in workspace?.Published.Entries ?? [])
            if (Names(value, t.Id, t.AssemblyName, t.FilePath))
            {
                var o = new JsonObject { ["id"] = t.Id, ["sha256"] = t.Sha256 };
                if (t.Mvid is { } mvid) o["mvid"] = mvid.ToString();
                return o;
            }
        if (!Path.IsPathFullyQualified(value) || new FileInfo(value) is not { Exists: true } info) return null;
        var hash = FileHashes.GetOrAdd((info.FullName, info.Length, info.LastWriteTimeUtc.Ticks), key =>
        {
            using var stream = File.OpenRead(key.Path);
            return Convert.ToHexStringLower(SHA256.HashData(stream));
        });
        return new JsonObject { ["id"] = info.Name, ["sha256"] = hash };
    }

    private static bool Names(string value, string id, string? name, string path) =>
        value.Equals(id, StringComparison.OrdinalIgnoreCase) || name != null && value.Equals(name, StringComparison.OrdinalIgnoreCase)
        || value.Equals(Path.GetFileName(path), StringComparison.OrdinalIgnoreCase)
        || Path.IsPathFullyQualified(value) && string.Equals(Path.GetFullPath(value), Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase);
}
