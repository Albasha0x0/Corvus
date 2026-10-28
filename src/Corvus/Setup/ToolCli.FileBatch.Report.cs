using System.Text;
using System.Text.Json.Nodes;
using Corvus.Core;

namespace Corvus.Setup;

/// <summary>batch --file --report: the document as Markdown, one section per record in gate order, every read value escaped.</summary>
internal static partial class ToolCli
{
    private static readonly HashSet<string> IndicatorTypes = new(StringComparer.Ordinal) { "url", "domain", "ipv4", "ipv6", "email" };

    /// <summary>The Markdown report of a batch document; a single-file document is one record.</summary>
    internal static string Report(JsonObject document)
    {
        var md = new StringBuilder();
        static string T(JsonNode? value) => Format.EscapeMarkdown(value?.ToString() ?? "unknown");
        var summary = document["summary"];
        md.Append("# Batch report\n\n");
        md.Append("- Input: ").Append(T(document["file"]?["path"])).Append('\n');
        md.Append("- Level: ").Append(T(summary?["level"])).Append('\n');
        if (summary?["records"] != null)
            md.Append($"- Records: {T(summary["records"])} (files {T(summary["files"])}, members {T(summary["members"])})\n");
        md.Append("- Complete: ").Append((bool?)document["complete"] == true ? "yes" : "no").Append('\n');
        md.Append("- Rule table: ").Append(T(document["ruleTable"])).Append('\n');
        if (document["gate"] is { } gate)
        {
            md.Append($"- Gate: {((bool?)gate["failed"] == true ? "failed" : "passed")} at {T(gate["failOn"])}\n");
            foreach (var reason in gate["reasons"] as JsonArray ?? []) md.Append("  - ").Append(T(reason)).Append('\n');
        }
        foreach (var entry in document["unread"] as JsonArray ?? []) md.Append("- Not read: ").Append(T(entry)).Append('\n');

        var records = document["records"] is JsonArray all ? all.Select(r => r!.AsObject()).ToList() : [RecordOf(document)];
        for (int i = 0; i < records.Count; i++)
        {
            var record = records[i];
            var file = record["file"];
            var paths = file?["paths"] as JsonArray ?? new JsonArray(file?["path"]?.DeepClone());
            var level = record["summary"]?["level"];
            md.Append($"\n## {i + 1}. {T(level)}: {T(paths.FirstOrDefault())}\n\n");
            var counts = record["counts"];
            md.Append($"- Level: {T(level)}; findings {T(counts?[BatchLevel.Noteworthy])} noteworthy, {T(counts?[BatchLevel.Review])} review, {T(counts?[BatchLevel.Info])} info\n");
            md.Append("- SHA-256: ").Append(T(file?["sha256"])).Append('\n');
            md.Append("- Type: ").Append(T(file?["type"])).Append('\n');
            var gaps = (record["sections"] as JsonArray ?? [])
                .Where(s => (string?)s!["status"] is not (SectionStatus.Complete or SectionStatus.NotApplicable))
                .Select(s => $"{T(s!["name"])} {T(s["status"])}").ToList();
            md.Append("- Complete: ").Append(gaps.Count == 0 && (bool?)record["complete"] != false ? "yes" : $"no ({string.Join(", ", gaps.DefaultIfEmpty("members not read"))})").Append('\n');
            md.Append("- Paths:\n");
            foreach (var path in paths) md.Append("  - ").Append(T(path)).Append('\n');
            var findings = record["findings"] as JsonArray ?? [];
            Findings(md, "Reasons", findings.Where(f => (string?)f!["level"] == (string?)level));
            Findings(md, "Other findings", findings.Where(f => (string?)f!["level"] != (string?)level));
            Findings(md, "Suppressed by the baseline", record["suppressed"] as JsonArray ?? []);
            var indicators = Indicators(record);
            if (indicators.Count > 0)
            {
                md.Append("- Indicators:\n");
                foreach (var (type, value) in indicators) md.Append($"  - {T(type)}: {T(value)}\n");
            }
            foreach (var entry in record["unread"] as JsonArray ?? []) md.Append("- Not read: ").Append(T(entry)).Append('\n');
        }
        return md.ToString();

        static void Findings(StringBuilder md, string heading, IEnumerable<JsonNode?> rows)
        {
            var list = rows.ToList();
            if (list.Count == 0) return;
            md.Append($"- {heading}:\n");
            foreach (var f in list)
            {
                md.Append($"  - {T(f!["level"])} {T(f["rule"])} ({T(f["category"])}, {T(f["source"])}): {T(f["evidence"])}");
                if (f["location"] != null) md.Append(" at ").Append(T(f["location"]));
                md.Append('\n');
            }
        }
    }

    /// <summary>The views' indicator findings and network strings, then payload hashes; distinct, in order.</summary>
    private static List<(string Type, string Value)> Indicators(JsonObject record)
    {
        var found = new List<(string, string)>();
        // The views name an indicator finding by an "/ioc" rule; its evidence
        // is the value.
        foreach (var finding in record["findings"] as JsonArray ?? [])
            if (((string?)finding!["rule"])?.EndsWith("/ioc", StringComparison.Ordinal) == true && (string?)finding["evidence"] is { Length: > 0 } evidence)
                found.Add((Uri.TryCreate(evidence, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https" or "ftp" ? "url" : "value", evidence));
        var strings = (record["sections"] as JsonArray ?? []).FirstOrDefault(s => (string?)s!["name"] == "strings");
        foreach (var item in strings?["result"]?["items"] as JsonArray ?? [])
            if ((string?)item?["type"] is { } type && IndicatorTypes.Contains(type) && (string?)item["value"] is { } value)
                found.Add((type, value));
        var distinct = found.Distinct().OrderBy(v => v.Item1, StringComparer.Ordinal).ThenBy(v => v.Item2, StringComparer.Ordinal).ToList();
        foreach (var payload in record["extracted"] as JsonArray ?? [])
            if ((string?)payload?["sha256"] is { } sha) distinct.Add(("sha256", $"{sha} ({(string?)payload["path"]})"));
        return distinct;
    }

    /// <summary>The record of a single-file document: its file, completeness, verdict, counts, findings and sections.</summary>
    internal static JsonObject RecordOf(JsonObject document)
    {
        var findings = document["findings"] as JsonArray ?? [];
        var record = new JsonObject
        {
            ["file"] = document["file"]?.DeepClone(),
            ["complete"] = document["complete"]?.DeepClone(),
            ["summary"] = document["summary"]?.DeepClone(),
            ["counts"] = Counts(findings),
            ["findings"] = findings.DeepClone(),
            ["sections"] = document["sections"]?.DeepClone(),
        };
        foreach (var key in new[] { "suppressed", "extracted" })
            if (document[key] is { } value) record[key] = value.DeepClone();
        return record;
    }
}
