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

    /// <summary>
    /// The provenance of a result (S5.1), for _meta: inputs with SHA-256 (and MVID), tool, a hash of the arguments, engine,
    /// version and, on a success, a hash of the result and its coverage. Costs the model nothing; at most about 1 KB.
    /// </summary>
    internal static JsonObject Provenance(string tool, IDictionary<string, JsonElement>? args, AssemblyWorkspace? workspace, string? engine,
        CallToolResult result, OutputCall call)
    {
        var inputs = new JsonArray();
        void Collect()
        {
            foreach (var name in InputParameters)
                if (args != null && args.TryGetValue(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } value
                    && inputs.Count < MaxInputs && Input(value, workspace) is { } input && !inputs.Any(i => (string?)i!["sha256"] == (string?)input["sha256"]))
                    inputs.Add(input);
        }
        // under the lock: a call nested in another (read_result format=verify) still counts as inside a call
        if (workspace != null) workspace.Read(() => { Collect(); return 0; });
        else Collect();
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
        p["resultSha256"] = ResultSha256(result);
        ResultHashes.Remember(tool, ResultHashes.Sha256(ResultHashes.Canonical(args == null ? new JsonObject() : JsonSerializer.SerializeToNode(args))), (string)p["resultSha256"]!);
        p["coverage"] = call.Coverage?.Status ?? "complete";
        if (call.Coverage is { Limitations.Count: > 0 } c)
            p["limitations"] = new JsonArray(c.Limitations.Concat(p["limitations"] is JsonArray stated ? stated.Select(l => (string)l!) : [])
                .Distinct().Take(8).Select(l => (JsonNode)JsonValue.Create(l)!).ToArray());
        return p;
    }

    /// <summary>SHA-256 of the canonical structured JSON (sorted keys, compact), else of the text blocks.</summary>
    public static string ResultSha256(CallToolResult result) =>
        result.StructuredContent is { } s
            ? Sha256(Canonical(JsonNode.Parse(s.GetRawText())))
            : Sha256(string.Concat(result.Content.OfType<TextContentBlock>().Select(b => b.Text)));

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
        if (workspace != null)
        {
            foreach (var a in workspace.Assemblies)
                if (Names(value, a.Id, a.AssemblyName, a.FilePath))
                {
                    var o = new JsonObject { ["id"] = a.Id, ["sha256"] = a.OriginalSha256 };
                    if (a.Module.Mvid is { } mvid) o["mvid"] = mvid.ToString();
                    return o;
                }
            foreach (var n in workspace.Natives)
                if (Names(value, n.Id, null, n.FilePath))
                    return new JsonObject { ["id"] = n.Id, ["sha256"] = n.OriginalSha256 };
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
