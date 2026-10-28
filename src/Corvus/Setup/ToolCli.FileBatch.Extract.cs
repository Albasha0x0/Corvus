using System.Text;
using System.Text.Json.Nodes;

namespace Corvus.Setup;

/// <summary>batch --file --extract: decoded payloads and peeled script text written under one folder per SHA-256, with their chain.</summary>
internal static partial class ToolCli
{
    private static readonly FileBatchStep EmbeddedStep = new("embedded", "extract_embedded", "embeddedItems");
    private static readonly FileBatchStep ScriptStep = new("script", "summarize_file", null);

    /// <summary>Writes a file's payloads under its SHA-256, adds two sections, returns what was written; null without --extract.</summary>
    private static async Task<JsonArray?> Extract(FileBatchRun run, string path, string? sha256, JsonNode? summary, JsonArray sections, IReadOnlyList<string> paths)
    {
        if (run.Extract == null) return null;
        var extracted = new JsonArray();
        var folder = Path.Combine(run.Extract, sha256 ?? $"unknown-{run.Index.Count}");
        foreach (var step in new[] { EmbeddedStep, ScriptStep })
        {
            if (run.TimedOut)
            {
                sections.Add(Section(step, SectionStatus.Timeout, "The time limit ended the run before this step."));
                continue;
            }
            if (summary == null)
            {
                sections.Add(Section(step, SectionStatus.Error, "The summary failed, so whether this step applies is unknown."));
                continue;
            }
            try
            {
                sections.Add(step == EmbeddedStep
                    ? await ExtractEmbedded(run, path, summary, folder, extracted)
                    : await ExtractScript(run, path, summary, folder, extracted));
            }
            catch (OperationCanceledException) when (!run.Cancellation.IsCancellationRequested)
            {
                run.TimedOut = true;
                sections.Add(Section(step, SectionStatus.Timeout, "The time limit ended this step."));
            }
        }
        run.Index.Add(new JsonObject
        {
            ["sha256"] = sha256 ?? "unknown",
            ["paths"] = new JsonArray([.. paths.Select(p => (JsonNode?)p)]),
            ["extracted"] = extracted.DeepClone(),
        });
        return extracted;
    }

    private static async Task<JsonObject> ExtractEmbedded(FileBatchRun run, string path, JsonNode summary, string folder, JsonArray extracted)
    {
        if (!HoldsManagedCode(path, summary))
            return Section(EmbeddedStep, SectionStatus.NotApplicable, "Embedded content is read from .NET assemblies and files that hold them.");
        var arguments = new Dictionary<string, object?>
        {
            ["path"] = path, ["save"] = true, ["outputDirectory"] = Path.Combine(folder, "embedded"), ["limit"] = (int)run.Limits["embeddedItems"],
        };
        var (section, timedOut) = await Step(run.Session!, EmbeddedStep, arguments, run.Io, run.Deadline, run.Cancellation);
        run.TimedOut |= timedOut;
        foreach (var item in section["result"]?["items"] as JsonArray ?? [])
        {
            if ((string?)item?["savedTo"] is not { } saved) continue;
            extracted.Add(new JsonObject
            {
                ["path"] = Path.GetRelativePath(run.Extract!, saved).Replace('\\', '/'),
                ["sha256"] = item["sha256"]?.DeepClone(),
                ["kind"] = item["kind"]?.DeepClone(),
                ["source"] = item["source"]?.DeepClone(),
                ["chain"] = item["encoding"]?.DeepClone() ?? new JsonArray(),
            });
        }
        return section;
    }

    /// <summary>Pages the script view's plain text into script.txt; the chain is each peeled layer as "language via how".</summary>
    private static async Task<JsonObject> ExtractScript(FileBatchRun run, string path, JsonNode summary, string folder, JsonArray extracted)
    {
        if (summary["views"] is not JsonArray views || !views.Any(v => (string?)v == "script"))
            return Section(ScriptStep, SectionStatus.NotApplicable, "The file has no script view.");
        var plain = new StringBuilder();
        JsonObject? first = null;
        long offset = 0;
        while (true)
        {
            var result = await Invoke(run.Session!, ScriptStep.Tool, new() { ["path"] = path, ["view"] = "script", ["offset"] = offset }, run.Io, run.Deadline);
            if (result == null || result.IsError == true) return Section(ScriptStep, result);
            var detail = Structured(result)?["detail"] as JsonObject;
            first ??= detail;
            plain.Append((string?)detail?["plain"]);
            if ((long?)detail?["next"] is not { } next || next <= offset) break;
            offset = next;
        }
        var layers = first?["layers"] as JsonArray ?? [];
        var section = new JsonObject { ["name"] = ScriptStep.Name, ["tool"] = ScriptStep.Tool, ["status"] = SectionStatus.Complete };
        if ((bool?)first?["complete"] == false)
        {
            section["status"] = SectionStatus.Partial;
            section["reason"] = string.Join("; ", (first?["notes"] as JsonArray ?? []).Select(n => (string?)n)) is { Length: > 0 } notes ? notes : "the script was not read to its end";
        }
        // Text with nothing peeled, undone or folded is the file itself.
        if (layers.Count == 0 && first?["recovered"] == null && (int?)first?["folded"] is null or 0) return section;
        Directory.CreateDirectory(folder);
        var file = Path.Combine(folder, "script.txt");
        await File.WriteAllTextAsync(file, plain.ToString(), run.Cancellation);
        var chain = new JsonArray([.. layers.Select(l => (JsonNode?)$"{(string?)l!["language"]} via {(string?)l["via"]}")]);
        foreach (var recovered in first?["recovered"] as JsonArray ?? []) chain.Add((string?)recovered);
        extracted.Add(new JsonObject
        {
            ["path"] = Path.GetRelativePath(run.Extract!, file).Replace('\\', '/'),
            ["kind"] = "script",
            ["source"] = $"{(string?)first?["language"]} plain text, {(int?)first?["folded"] ?? 0} constant expression(s) folded",
            ["chain"] = chain,
        });
        section["result"] = new JsonObject { ["language"] = first?["language"]?.DeepClone(), ["layers"] = layers.Count, ["chars"] = plain.Length };
        return section;
    }

    /// <summary>Writes index.json under the extract folder: each file's SHA-256, paths and payloads with their chain.</summary>
    private static void WriteExtractIndex(FileBatchRun run)
    {
        if (run.Extract == null) return;
        File.WriteAllText(Path.Combine(run.Extract, "index.json"), run.Index.ToJsonString(Compact));
    }
}
