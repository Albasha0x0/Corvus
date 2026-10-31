using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Corvus.Setup;

/// <summary>batch --sarif: a batch document as one SARIF 2.1.0 run, within the code scanning upload limits.</summary>
internal static class SarifLog
{
    internal const int MaxResults = 25_000;
    internal const int MaxGzipBytes = 10 * 1024 * 1024;

    /// <summary>The SARIF log of a single-file or records document; paths become uris relative to <paramref name="baseDir"/>.</summary>
    internal static JsonObject Build(JsonObject document, string baseDir, int maxResults = MaxResults, int maxGzipBytes = MaxGzipBytes) =>
        Cut(document, Results(document, baseDir), maxResults, maxGzipBytes);

    /// <summary>
    /// The SARIF log of compare_folders results: the findings new in each, located on the new side. Removed rows and rows
    /// that are not findings give no result.
    /// </summary>
    internal static JsonObject BuildDiff(IEnumerable<JsonObject> comparisons, string baseDir, int maxResults = MaxResults, int maxGzipBytes = MaxGzipBytes)
    {
        var list = comparisons.ToList();
        var document = new JsonObject { ["complete"] = list.All(c => (bool?)c["old"]?["complete"] != false && (bool?)c["new"]?["complete"] != false) };
        return Cut(document, list.SelectMany(c => DiffResults(c, baseDir)).ToList(), maxResults, maxGzipBytes);
    }

    private static JsonObject Cut(JsonObject document, List<(string Level, JsonNode Node)> found, int maxResults, int maxGzipBytes)
    {
        // Strongest first, so a cut drops the weakest findings.
        var results = found.OrderByDescending(r => ToolCli.BatchLevel.Rank(r.Level)).Select(r => r.Node).ToList();
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
        var run = new JsonObject
        {
            ["tool"] = new JsonObject
            {
                ["driver"] = new JsonObject { ["name"] = "Corvus", ["version"] = Installation.Version, ["rules"] = rules },
            },
            ["results"] = results,
            ["properties"] = properties,
        };
        if (kept < total)
        {
            var cut = $"Results cut from {total} to {kept}, weakest levels first, for the upload limits of {MaxResults} results per run and {MaxGzipBytes / (1024 * 1024)} MB gzip.";
            properties["cut"] = cut;
            // A run-level notification names the cut in SARIF's own terms.
            run["invocations"] = new JsonArray(new JsonObject
            {
                ["executionSuccessful"] = true,
                ["toolExecutionNotifications"] = new JsonArray(new JsonObject
                {
                    ["level"] = "warning",
                    ["message"] = new JsonObject { ["text"] = $"{total - kept} results left out. {cut}" },
                }),
            });
        }
        return new JsonObject
        {
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json",
            ["version"] = "2.1.0",
            ["runs"] = new JsonArray(run),
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

    // A package finding row reads "level" or "level at path:line".
    private static readonly Regex Located = new(@"^(?:noteworthy|review|info)(?: at (?<path>.+?)(?::(?<line>[0-9]+))?)?$", RegexOptions.NonBacktracking);

    private static List<(string Level, JsonNode Node)> DiffResults(JsonObject comparison, string baseDir)
    {
        var list = new List<(string, JsonNode)>();
        var newPath = (string?)comparison["new"]?["path"] ?? "unknown";
        var folder = (string?)comparison["new"]?["kind"] == "folder";
        foreach (var row in comparison["changes"] as JsonArray ?? [])
        {
            if (row is not JsonObject r || (string?)r["rule"] is not { } rule || (string?)r["kind"] is not ("added" or "changed")) continue;
            var key = (string?)r["key"] ?? rule;
            var detail = (string?)r["new"] ?? "";
            var level = RowLevel(detail);
            string? path = null;
            int? line = null;
            if (rule.StartsWith("malcontent/", StringComparison.Ordinal))
            {
                if (key.LastIndexOf(" at ", StringComparison.Ordinal) is > 0 and var at) path = key[(at + 4)..];
            }
            else if (Located.Match(detail) is { Success: true } m)
            {
                if (m.Groups["path"].Success) path = m.Groups["path"].Value;
                if (m.Groups["line"].Success) line = int.Parse(m.Groups["line"].Value, System.Globalization.CultureInfo.InvariantCulture);
            }
            // A lockfile row is keyed "path: name@version".
            else if (key.IndexOf(": ", StringComparison.Ordinal) is > 0 and var colon) path = key[..colon];
            var text = $"{(string?)r["kind"]} {key}" + (detail.Length > 0 ? $": {detail}" : "");
            var artifact = folder && path != null ? InRoot(baseDir, newPath, path) : Uri(baseDir, newPath);
            if (!folder && path != null) text += $" (in {path})";
            var physical = new JsonObject { ["artifactLocation"] = new JsonObject { ["uri"] = artifact, ["uriBaseId"] = "%SRCROOT%" } };
            if (folder && line != null) physical["region"] = new JsonObject { ["startLine"] = line };
            var result = new JsonObject { ["ruleId"] = rule, ["level"] = SarifLevel(level) };
            result["message"] = new JsonObject { ["text"] = text };
            result["locations"] = new JsonArray(new JsonObject { ["physicalLocation"] = physical });
            // Rule, path in the scanned root and key only, so the folder it runs from does not change it.
            var print = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join((char)10, rule, path?.Replace('\\', '/') ?? artifact, key))));
            result["partialFingerprints"] = new JsonObject { ["corvusDiff/v1"] = print };
            list.Add((level, result));
        }
        return list;
    }

    // Relative to the current folder, else to the scanned root, which a uri cannot leave.
    private static string InRoot(string baseDir, string root, string path)
    {
        var relative = Path.GetRelativePath(baseDir, Path.GetFullPath(Path.Combine(root, path))).Replace('\\', '/');
        if (relative.StartsWith("../", StringComparison.Ordinal) || Path.IsPathRooted(relative)) relative = path.Replace('\\', '/');
        return string.Join('/', relative.Split('/').Select(System.Uri.EscapeDataString));
    }

    // The leading level word of a row's new text; rows without one (lockfile rows) are review.
    private static string RowLevel(string detail)
    {
        var word = detail.Split([' ', ':'], 2)[0];
        return ToolCli.BatchLevel.Rank(word) > 0 ? word : ToolCli.BatchLevel.Review;
    }

    /// <summary>A repository-relative uri for <paramref name="path"/>; the file name alone when it lies outside <paramref name="baseDir"/>.</summary>
    internal static string Uri(string baseDir, string path)
    {
        var relative = Path.GetRelativePath(baseDir, Path.GetFullPath(path)).Replace('\\', '/');
        if (relative.StartsWith("../", StringComparison.Ordinal) || relative == ".." || Path.IsPathRooted(relative)) relative = Path.GetFileName(path);
        return string.Join('/', relative.Split('/').Select(System.Uri.EscapeDataString));
    }
}
