using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Corvus.Services.Analysis;

namespace Corvus.Setup;

/// <summary>batch --file --recurse: one record per SHA-256 with every path it was seen at, strongest first.</summary>
internal static partial class ToolCli
{
    /// <summary>The records document: run fields, the root, the folders not read and one record per distinct file.</summary>
    private static async Task<JsonObject> RecordsDocument(FileBatchRun run, string root)
    {
        var unread = new List<string>();
        var members = Members(root, (int)run.Limits["members"], unread);
        var groups = new List<(string? Sha256, List<string> Paths)>();
        var bySha = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var member in members)
        {
            var sha = run.TimedOut ? null : Sha256(member, run);
            if (sha != null && bySha.TryGetValue(sha, out var index)) groups[index].Paths.Add(member);
            else
            {
                if (sha != null) bySha[sha] = groups.Count;
                groups.Add((sha, [member]));
            }
        }

        var records = new List<JsonObject>();
        string? ruleTable = null;
        foreach (var (hashed, paths) in groups)
        {
            var (sections, summary) = await Steps(run, paths[0]);
            ruleTable ??= (string?)summary?["ruleTable"];
            var sha = hashed ?? (string?)summary?["sha256"];
            var (findings, suppressed) = ApplyBaseline(KeyedFindings(sha, summary), sha, run.Baseline);
            var relative = paths.Select(p => Relative(root, p)).ToList();
            var extracted = await Extract(run, paths[0], sha, summary, sections, relative);
            var file = new JsonObject
            {
                ["sha256"] = sha ?? "unknown",
                ["size"] = summary?["size"]?.DeepClone(),
                ["type"] = summary?["type"]?.DeepClone(),
                ["paths"] = new JsonArray([.. relative.Select(p => (JsonNode?)p)]),
            };
            var record = new JsonObject
            {
                ["file"] = file,
                ["complete"] = Complete(sections),
                ["summary"] = Verdict(summary, findings, suppressed),
                ["counts"] = Counts(findings),
                ["findings"] = findings,
                ["sections"] = sections,
            };
            if (run.Baseline != null) record["suppressed"] = suppressed;
            if (extracted != null) record["extracted"] = extracted;
            records.Add(record);
        }
        // Noteworthy count first, then review count; the first path breaks ties
        // so the order is stable.
        var ordered = records
            .OrderByDescending(r => (int)r["counts"]![FindingLevel.Noteworthy]!)
            .ThenByDescending(r => (int)r["counts"]![FindingLevel.Review]!)
            .ThenBy(r => (string?)r["file"]!["paths"]![0], StringComparer.Ordinal)
            .ToList();

        var document = RunFields(run, ruleTable);
        document["file"] = new JsonObject { ["path"] = root };
        document["complete"] = unread.Count == 0 && ordered.All(r => (bool)r["complete"]!);
        var levels = ordered.Select(r => (string)r["summary"]!["level"]!).ToList();
        var strongest = FindingLevel.Strongest(levels);
        document["summary"] = new JsonObject
        {
            // A record of unknown level may hold anything below noteworthy.
            ["level"] = levels.Contains("unknown") && strongest != FindingLevel.Noteworthy ? "unknown" : strongest,
            ["records"] = ordered.Count,
            ["files"] = members.Count,
            ["byLevel"] = new JsonObject([.. levels.GroupBy(l => l).OrderBy(g => g.Key, StringComparer.Ordinal).Select(g => KeyValuePair.Create(g.Key, (JsonNode?)g.Count()))]),
        };
        if (unread.Count > 0) document["unread"] = new JsonArray([.. unread.Select(u => (JsonNode?)u)]);
        document["records"] = new JsonArray([.. ordered]);
        return document;
    }

    /// <summary>The files under a folder in ordinal order, or a file root alone; what was not read goes to unread.</summary>
    internal static List<string> Members(string root, int limit, List<string> unread)
    {
        if (File.Exists(root)) return [root];
        var files = new List<string>();
        var folders = new Stack<string>([root]);
        while (folders.Count > 0)
        {
            var folder = folders.Pop();
            string[] entries;
            try { entries = Directory.GetFileSystemEntries(folder); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                unread.Add($"{folder}: {ex.Message}");
                continue;
            }
            Array.Sort(entries, StringComparer.Ordinal);
            foreach (var entry in entries.Reverse())
            {
                FileAttributes attributes;
                try { attributes = File.GetAttributes(entry); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    unread.Add($"{entry}: {ex.Message}");
                    continue;
                }
                // A link can point back up the tree or off the volume.
                if (attributes.HasFlag(FileAttributes.ReparsePoint)) unread.Add($"{entry}: a link, not followed");
                else if (attributes.HasFlag(FileAttributes.Directory)) folders.Push(entry);
                else files.Add(entry);
            }
        }
        files.Sort(StringComparer.Ordinal);
        if (files.Count > limit)
        {
            unread.Add($"Files past the members limit of {limit}: {files.Count - limit}, from {files[limit]}");
            files.RemoveRange(limit, files.Count - limit);
        }
        return files;
    }

    /// <summary>The file's lower-case SHA-256; null when the file could not be read or the deadline passed.</summary>
    private static string? Sha256(string path, FileBatchRun run)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16);
            return Convert.ToHexStringLower(SHA256.HashData(stream));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
        finally
        {
            if (run.Deadline.IsCancellationRequested && !run.Cancellation.IsCancellationRequested) run.TimedOut = true;
        }
    }

    private static string Relative(string root, string path) =>
        path == root ? Path.GetFileName(path) : Path.GetRelativePath(root, path).Replace('\\', '/');

    /// <summary>The summary's findings, each with its key; empty when the summary gave none.</summary>
    internal static JsonArray KeyedFindings(string? sha256, JsonNode? summary)
    {
        var findings = new JsonArray();
        foreach (var finding in summary?["findings"] as JsonArray ?? [])
        {
            if (finding?.DeepClone() is not JsonObject copy) continue;
            copy["key"] = FindingKey(sha256, (string?)copy["rule"], (string?)copy["level"], (string?)copy["evidence"], (string?)copy["location"]);
            findings.Add(copy);
        }
        return findings;
    }

    /// <summary>A finding's key: file SHA-256, rule, level and a 16-digit SHA-256 prefix of evidence and location.</summary>
    internal static string FindingKey(string? sha256, string? rule, string? level, string? evidence, string? location)
    {
        var span = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"{evidence}\n{location}")))[..16];
        return $"{sha256 ?? "unknown"}|{rule}|{level}|{span}";
    }

    private static JsonObject Counts(JsonArray findings) => new()
    {
        [FindingLevel.Noteworthy] = findings.Count(f => (string?)f!["level"] == FindingLevel.Noteworthy),
        [FindingLevel.Review] = findings.Count(f => (string?)f!["level"] == FindingLevel.Review),
        [FindingLevel.Info] = findings.Count(f => (string?)f!["level"] == FindingLevel.Info),
    };
}
