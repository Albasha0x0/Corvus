using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Services.Analysis;

namespace Corvus.Setup;

/// <summary>batch --file --baseline: known findings dropped by key, each entry with a reason, an owner and an expiry date.</summary>
internal static partial class ToolCli
{
    /// <summary>The baseline file's schema.</summary>
    public const string BaselineSchema = "corvus.baseline/1";

    /// <summary>A known finding; an entry from an earlier result has no owner and never expires.</summary>
    internal sealed record BaselineEntry(string Key, string Reason, string? Owner, DateOnly? Expires);

    /// <summary>Known findings by key, as of one day; Used holds the keys the run matched.</summary>
    internal sealed class Baseline(IReadOnlyDictionary<string, BaselineEntry> entries, DateOnly today)
    {
        public IReadOnlyDictionary<string, BaselineEntry> Entries { get; } = entries;
        public DateOnly Today { get; } = today;
        public HashSet<string> Used { get; } = new(StringComparer.Ordinal);
        public int Suppressed { get; set; }
        public int Expired { get; set; }
        public int Rose { get; set; }

        /// <summary>The run's baseline record: entries, findings suppressed, expired and risen, and entries no finding matched.</summary>
        public JsonObject Record(string path) => new()
        {
            ["path"] = path,
            ["entries"] = Entries.Count,
            ["suppressed"] = Suppressed,
            ["expired"] = Expired,
            ["rose"] = Rose,
            ["unused"] = Entries.Count - Used.Count,
        };
    }

    /// <summary>Reads a corvus.baseline/1 file; an unreadable file or an incomplete entry is a usage error.</summary>
    internal static Baseline ReadBaseline(string path, DateOnly today)
    {
        JsonNode? root;
        try { root = JsonNode.Parse(File.ReadAllText(path)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { throw new UsageException($"Cannot read baseline {path}: {ex.Message}"); }
        var byKey = new Dictionary<string, BaselineEntry>(StringComparer.Ordinal);
        if ((string?)root?["schema"] == FileBatchSchema)
        {
            var reason = $"from {Path.GetFileName(path)}";
            IEnumerable<JsonNode> records = root["records"] is JsonArray all ? all.Select(r => r!) : [root];
            foreach (var record in records)
                foreach (var finding in (record["findings"] as JsonArray ?? []).Concat(record["suppressed"] as JsonArray ?? []))
                    if ((string?)finding?["key"] is { Length: > 0 } key)
                        byKey[key] = new BaselineEntry(key, reason, null, null);
            return new Baseline(byKey, today);
        }
        if ((string?)root?["schema"] != BaselineSchema || root["entries"] is not JsonArray entries)
            throw new UsageException($"The baseline needs schema {BaselineSchema} and an entries array, or a {FileBatchSchema} result.");
        for (int i = 0; i < entries.Count; i++)
        {
            string Field(string name) => (string?)entries[i]?[name] is { Length: > 0 } value ? value : throw new UsageException($"Baseline entry {i + 1} has no {name}.");
            var expires = DateOnly.TryParseExact(Field("expires"), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var date)
                ? date : throw new UsageException($"Baseline entry {i + 1}: expires takes a date as yyyy-MM-dd.");
            byKey[Field("key")] = new BaselineEntry(Field("key"), Field("reason"), Field("owner"), expires);
        }
        return new Baseline(byKey, today);
    }

    /// <summary>Splits findings into kept and suppressed; an expired or lower-level entry keeps its finding, marked.</summary>
    internal static (JsonArray Kept, JsonArray Suppressed) ApplyBaseline(JsonArray findings, string? sha256, Baseline? baseline)
    {
        if (baseline == null) return (findings, []);
        var kept = new JsonArray();
        var suppressed = new JsonArray();
        foreach (var node in findings.ToArray())
        {
            var finding = node!.DeepClone().AsObject();
            var level = (string?)finding["level"];
            if (baseline.Entries.TryGetValue((string?)finding["key"] ?? "", out var entry))
            {
                baseline.Used.Add(entry.Key);
                // The expiry date is the last day the entry applies.
                if (entry.Expires is not { } expires || expires >= baseline.Today)
                {
                    finding["baseline"] = Note(entry);
                    suppressed.Add(finding);
                    baseline.Suppressed++;
                    continue;
                }
                finding["baseline"] = Note(entry, "expired", expires.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
                baseline.Expired++;
            }
            else
            {
                // A level rise changes the key, so the entry for a lower level is
                // named, never applied.
                foreach (var lower in new[] { FindingLevel.Review, FindingLevel.Info }.Where(l => FindingLevel.Rank(l) < FindingLevel.Rank(level)))
                {
                    var key = FindingKey(sha256, (string?)finding["rule"], lower, (string?)finding["evidence"], (string?)finding["location"]);
                    if (!baseline.Entries.TryGetValue(key, out var earlier)) continue;
                    baseline.Used.Add(earlier.Key);
                    finding["baseline"] = Note(earlier, "rose", lower);
                    baseline.Rose++;
                    break;
                }
            }
            kept.Add(finding);
        }
        return (kept, suppressed);
    }

    private static JsonObject Note(BaselineEntry entry, string? state = null, string? value = null)
    {
        var note = new JsonObject
        {
            ["reason"] = entry.Reason,
            ["owner"] = entry.Owner,
            ["expires"] = entry.Expires?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
        };
        if (state != null) note[state] = value;
        return note;
    }

    /// <summary>The verdict over the findings left after the baseline; the summary's own verdict when nothing was suppressed.</summary>
    internal static JsonObject Verdict(JsonNode? summary, JsonArray kept, JsonArray suppressed)
    {
        if (summary == null || suppressed.Count == 0) return Verdict(summary);
        var level = FindingLevel.Strongest(kept.Select(f => (string?)f!["level"] ?? ""));
        var verdict = new JsonObject
        {
            ["level"] = level,
            ["reasons"] = new JsonArray([.. kept.Where(f => (string?)f!["level"] == level).Select(f => f!.DeepClone())]),
        };
        if (summary["findingTotal"] is { } total) verdict["findingTotal"] = total.DeepClone();
        return verdict;
    }
}
