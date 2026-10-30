using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Corvus.Setup;

/// <summary>batch --sarif: a batch document as one SARIF 2.1.0 run, within the code scanning upload limits.</summary>
internal static class SarifLog
{
    internal const int MaxResults = 25_000;
    internal const int MaxGzipBytes = 10 * 1024 * 1024;

    /// <summary>The SARIF log of a single-file or records document; paths become uris relative to <paramref name="baseDir"/>.</summary>
    internal static JsonObject Build(JsonObject document, string baseDir, int maxResults = MaxResults, int maxGzipBytes = MaxGzipBytes)
    {
        // Strongest first, so a cut drops the weakest findings.
        var results = Results(document, baseDir).OrderByDescending(r => ToolCli.BatchLevel.Rank(r.Level)).Select(r => r.Node).ToList();
        int total = results.Count;
        var kept = Math.Min(total, maxResults);
        while (true)
        {
            var log = Wrap(document, new JsonArray([.. results.Take(kept).Select(r => r.DeepClone())]), total, kept);
            if (kept == 0 || Gzip(log) <= maxGzipBytes) return log;
            kept = (int)(kept * 0.75);
        }
    }

    /// <summary>The size of <paramref name="log"/> gzip-compressed.</summary>
    internal static long Gzip(JsonObject log)
    {
        using var counter = new CountingStream();
        using (var gzip = new GZipStream(counter, CompressionLevel.Optimal, leaveOpen: true))
        using (var writer = new Utf8JsonWriter(gzip))
            log.WriteTo(writer);
        return counter.Length;
    }

    private sealed class CountingStream : Stream
    {
        private long _length;
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => _length;
        public override long Position { get => _length; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => _length += count;
    }

    private static JsonObject Wrap(JsonObject document, JsonArray results, int total, int kept)
    {
        // The driver lists the rules the results name, at the strongest level seen.
        var strongest = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var result in results)
        {
            var id = (string)result!["ruleId"]!;
            var level = (string)result["level"]!;
            if (!strongest.TryGetValue(id, out var seen) || Rank(level) > Rank(seen)) strongest[id] = level;
            result["ruleIndex"] = strongest.Keys.ToList().IndexOf(id);
        }
        var rules = new JsonArray([.. strongest.Select(r => (JsonNode?)new JsonObject
        {
            ["id"] = r.Key,
            ["defaultConfiguration"] = new JsonObject { ["level"] = r.Value },
        })]);
        var properties = new JsonObject
        {
            ["complete"] = (bool?)document["complete"] == true,
            ["ruleTable"] = (string?)document["ruleTable"] ?? "unknown",
        };
        if (kept < total)
            properties["cut"] = $"Results cut from {total} to {kept}, weakest levels first, for the upload limits of {MaxResults} results per run and {MaxGzipBytes / (1024 * 1024)} MB gzip.";
        return new JsonObject
        {
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json",
            ["version"] = "2.1.0",
            ["runs"] = new JsonArray(new JsonObject
            {
                ["tool"] = new JsonObject
                {
                    ["driver"] = new JsonObject { ["name"] = "Corvus", ["version"] = Installation.Version, ["rules"] = rules },
                },
                ["results"] = results,
                ["properties"] = properties,
            }),
        };
    }

    private static int Rank(string level) => ToolCli.BatchLevel.Rank(level switch { "error" => ToolCli.BatchLevel.Noteworthy, "warning" => ToolCli.BatchLevel.Review, _ => ToolCli.BatchLevel.Info });

    /// <summary>The SARIF level of a finding level: error for noteworthy, warning for review, note for the rest.</summary>
    internal static string SarifLevel(string? level) => level switch
    {
        ToolCli.BatchLevel.Noteworthy => "error",
        ToolCli.BatchLevel.Review => "warning",
        _ => "note",
    };

    private static List<(string Level, JsonNode Node)> Results(JsonObject document, string baseDir)
    {
        var list = new List<(string, JsonNode)>();
        var records = document["records"] is JsonArray all ? all.Select(r => r!.AsObject()).ToList() : [ToolCli.RecordOf(document)];
        var root = (string?)document["file"]?["path"];
        var isRecords = document["records"] != null;
        foreach (var record in records)
        {
            var shown = (isRecords ? (record["file"]?["paths"] as JsonArray)?.FirstOrDefault()?.ToString() : null) ?? root ?? "unknown";
            // A member path is "container!/inner": the container is the artifact.
            var bang = shown.IndexOf("!/", StringComparison.Ordinal);
            var inner = bang >= 0 ? shown[(bang + 2)..] : null;
            var outer = bang >= 0 ? shown[..bang] : shown;
            var uri = Uri(baseDir, isRecords && root != null ? Path.Combine(root, outer) : outer);
            foreach (var finding in record["findings"] as JsonArray ?? [])
            {
                if (finding is not JsonObject f) continue;
                var rule = (string?)f["rule"] ?? "unknown";
                var level = (string?)f["level"] ?? ToolCli.BatchLevel.Info;
                var text = (string?)f["evidence"] ?? rule;
                if (inner != null) text += $" (in {inner})";
                var result = new JsonObject { ["ruleId"] = rule };
                result["level"] = SarifLevel(level);
                result["message"] = new JsonObject { ["text"] = text };
                result["locations"] = new JsonArray(new JsonObject
                {
                    ["physicalLocation"] = new JsonObject
                    {
                        ["artifactLocation"] = new JsonObject { ["uri"] = uri, ["uriBaseId"] = "%SRCROOT%" },
                    },
                });
                result["partialFingerprints"] = new JsonObject { ["corvusFinding/v1"] = (string?)f["key"] ?? rule };
                list.Add((level, result));
            }
        }
        return list;
    }

    /// <summary>A repository-relative uri for <paramref name="path"/>; the file name alone when it lies outside <paramref name="baseDir"/>.</summary>
    internal static string Uri(string baseDir, string path)
    {
        var relative = Path.GetRelativePath(baseDir, Path.GetFullPath(path)).Replace('\\', '/');
        if (relative.StartsWith("../", StringComparison.Ordinal) || relative == ".." || Path.IsPathRooted(relative)) relative = Path.GetFileName(path);
        return string.Join('/', relative.Split('/').Select(System.Uri.EscapeDataString));
    }
}
