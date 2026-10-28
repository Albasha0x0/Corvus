using System.Globalization;
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
        var groups = new List<RecordGroup>();
        var bySha = new Dictionary<string, RecordGroup>(StringComparer.Ordinal);
        void Add(string? sha, string local, string shown, bool member)
        {
            if (sha != null && bySha.TryGetValue(sha, out var known)) known.Paths.Add(shown);
            else
            {
                var group = new RecordGroup(sha, local, [shown], member);
                if (sha != null) bySha[sha] = group;
                groups.Add(group);
            }
        }
        foreach (var path in members) Add(run.TimedOut ? null : Sha256(path, run), path, Relative(root, path), member: false);

        var records = new List<JsonObject>();
        string? ruleTable = null;
        var unpacked = Path.Combine(Path.GetTempPath(), $"corvus-batch-{Guid.NewGuid():N}");
        try
        {
            // Members found in a container join the list and are read in turn.
            for (int i = 0; i < groups.Count; i++)
            {
                var group = groups[i];
                var (sections, summary) = await Steps(run, group.Local);
                ruleTable ??= (string?)summary?["ruleTable"];
                var sha = group.Sha256 ?? (string?)summary?["sha256"];
                var notRead = new List<string>();
                // The unpack walk already opens nested containers, so a member is
                // not unpacked again.
                if (!group.Member && summary != null && (string?)summary["container"] is { } container && !container.StartsWith("none", StringComparison.Ordinal))
                    foreach (var (memberSha, local, inner) in await Unpack(run, group.Local, Path.Combine(unpacked, i.ToString(CultureInfo.InvariantCulture)), sections, notRead))
                        Add(memberSha, local, $"{group.Paths[0]}!/{inner}", member: true);
                var (findings, suppressed) = ApplyBaseline(KeyedFindings(sha, summary), sha, run.Baseline);
                var extracted = await Extract(run, group.Local, sha, summary, sections, group.Paths);
                var record = new JsonObject
                {
                    ["file"] = new JsonObject
                    {
                        ["sha256"] = sha ?? "unknown",
                        ["size"] = summary?["size"]?.DeepClone(),
                        ["type"] = summary?["type"]?.DeepClone(),
                        ["paths"] = new JsonArray(),
                    },
                    ["complete"] = Complete(sections) && notRead.Count == 0,
                    ["summary"] = Verdict(summary, findings, suppressed),
                    ["counts"] = Counts(findings),
                    ["findings"] = findings,
                    ["sections"] = sections,
                };
                if (notRead.Count > 0) record["unread"] = new JsonArray([.. notRead.Select(n => (JsonNode?)n)]);
                if (run.Baseline != null) record["suppressed"] = suppressed;
                if (extracted != null) record["extracted"] = extracted;
                records.Add(record);
            }
        }
        finally
        {
            try { if (Directory.Exists(unpacked)) Directory.Delete(unpacked, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { run.Io.Error.WriteLine($"Could not remove {unpacked}: {ex.Message}"); }
        }
        // A path seen after its record was written still belongs to it.
        for (int i = 0; i < groups.Count; i++)
        {
            records[i]["file"]!["paths"] = new JsonArray([.. groups[i].Paths.Select(p => (JsonNode?)p)]);
            if (run.Extract != null) run.Index[i]!["paths"] = records[i]["file"]!["paths"]!.DeepClone();
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
            ["members"] = groups.Sum(g => g.Paths.Count) - members.Count,
            ["byLevel"] = new JsonObject([.. levels.GroupBy(l => l).OrderBy(g => g.Key, StringComparer.Ordinal).Select(g => KeyValuePair.Create(g.Key, (JsonNode?)g.Count()))]),
        };
        if (unread.Count > 0) document["unread"] = new JsonArray([.. unread.Select(u => (JsonNode?)u)]);
        document["records"] = new JsonArray([.. ordered]);
        return document;
    }

    /// <summary>One record's input: SHA-256, the copy the steps read, every path seen, and whether a container held it.</summary>
    private sealed record RecordGroup(string? Sha256, string Local, List<string> Paths, bool Member);

    private static readonly FileBatchStep MembersStep = new("members", "unpack_container", "containerFiles");

    /// <summary>Extracts a container's members, adds their section and names what was not read; empty when none was extracted.</summary>
    private static async Task<List<(string? Sha256, string Local, string Inner)>> Unpack(FileBatchRun run, string path, string output, JsonArray sections,
        List<string> notRead)
    {
        if (run.TimedOut)
        {
            sections.Add(Section(MembersStep, SectionStatus.Timeout, "The time limit ended the run before this step."));
            notRead.Add("The members were not read: the time limit ended the run.");
            return [];
        }
        var arguments = new Dictionary<string, object?>
        {
            ["path"] = path, ["outputDirectory"] = output, ["extractOnly"] = true, ["limit"] = (int)run.Limits["containerFiles"],
        };
        JsonObject section;
        try
        {
            (section, var timedOut) = await Step(run.Session!, MembersStep, arguments, run.Io, run.Deadline, run.Cancellation);
            run.TimedOut |= timedOut;
        }
        catch (OperationCanceledException) when (!run.Cancellation.IsCancellationRequested)
        {
            run.TimedOut = true;
            section = Section(MembersStep, SectionStatus.Timeout, "The time limit ended this step.");
        }
        var result = section["result"];
        var members = new List<(string?, string, string)>();
        foreach (var item in result?["items"] as JsonArray ?? [])
        {
            // The host itself is listed where it already is.
            if ((bool?)item?["extracted"] == false || (string?)item?["path"] is not { } inner) continue;
            var local = Path.GetFullPath(inner, output);
            // The views choose a reader by extension, so a member gets its archive
            // name back. The folder is the run's private temp folder: nothing in
            // it runs, and it is removed after the run. A failed rename keeps the
            // .bin name.
            if (Core.Blob.WithoutRunnableSuffix(inner) is { } original && !File.Exists(Path.GetFullPath(original, output)))
            {
                try
                {
                    File.Move(local, Path.GetFullPath(original, output));
                    (local, inner) = (Path.GetFullPath(original, output), original);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
            members.Add(((string?)item["sha256"], local, inner.Replace('\\', '/')));
        }
        // Limit notes name the members the walk did not reach.
        foreach (var note in result?["notes"] as JsonArray ?? [])
            if ((string?)note is { } text && (text.Contains("limit", StringComparison.Ordinal) || text.StartsWith("Could not write", StringComparison.Ordinal)))
                notRead.Add(text);
        if ((string?)section["status"] is not (SectionStatus.Complete or SectionStatus.NotApplicable))
            notRead.Add($"Members not read: {(string?)section["reason"] ?? (string?)section["error"]?["message"] ?? (string?)section["status"]}.");
        // The member list repeats the records; the section keeps the counts.
        if (result is JsonObject kept)
            section["result"] = new JsonObject { ["container"] = kept["container"]?.DeepClone(), ["total"] = kept["total"]?.DeepClone(), ["extracted"] = members.Count };
        sections.Add(section);
        return members;
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
