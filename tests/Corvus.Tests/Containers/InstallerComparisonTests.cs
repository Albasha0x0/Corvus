using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native.Providers;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Real installers listed by each reader against a reference tool, by file name and size. Opt-in: CORVUS_INSTALLERS names a
/// folder with nsis, inno, msi and burn subfolders; each reference tool's variable names its program, and a format whose
/// tool is not set is skipped.
/// </summary>
[Trait("Speed", "Slow")]
public sealed class InstallerComparisonTests(ITestOutputHelper output)
{
    /// <summary>A reference tool for the reader of one kind: its variable, native arguments ({input}, {output}, {work}: an existing scratch folder), and how its output becomes (name, size) rows.</summary>
    private sealed record Reference(string Format, string Variable, string[] Arguments, Func<string, string, IEnumerable<(string Name, long Size)>> Rows);

    private static readonly Reference[] References =
    [
        new("nsis", "CORVUS_ARCHIVE_LISTER", ["l", "-slt", "-sccUTF-8", "-tNsis", "{input}"], (text, _) => SlTechnical(text)),
        new("inno", "CORVUS_SETUP_LISTER", ["-v", "{input}"], (text, _) => SetupListing(text)),
        new("msi", "CORVUS_MSI_LISTER", ["l", "-t", "File", "{input}"], (text, _) => FileTable(text)),
        new("burn", "CORVUS_BUNDLE_EXTRACTOR", ["burn", "extract", "{input}", "-o", "{output}/payloads", "-oba", "{output}/ba", "-intermediateFolder", "{work}"], (_, folder) => BundleFiles(folder)),
    ];

    /// <summary>Per installer, at least this share of the reference rows is found among ours.</summary>
    private const double Floor = 0.99;

    [Fact]
    public void Real_installers_list_the_files_their_reference_tools_list()
    {
        if (Environment.GetEnvironmentVariable("CORVUS_INSTALLERS") is not { Length: > 0 } root || !Directory.Exists(root)) return;
        var failures = new List<string>();
        foreach (var reference in References)
        {
            var folder = Path.Combine(root, reference.Format);
            if (Environment.GetEnvironmentVariable(reference.Variable) is not { Length: > 0 } tool || !Directory.Exists(folder)) continue;
            foreach (var installer in Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories)
                         .Where(f => f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".msi", StringComparison.OrdinalIgnoreCase)).Order())
            {
                var (kind, files) = Ours(installer);
                if (kind != reference.Format)
                {
                    output.WriteLine($"{reference.Format} {Path.GetFileName(installer)}: skipped, read as {kind ?? "nothing"}");
                    continue;
                }
                using var work = new TempDir();
                var args = reference.Arguments.Select(a => a.Replace("{input}", installer).Replace("{output}", work.File("out")).Replace("{work}", work.Path)).ToList();
                var run = ExternalTools.Run(tool, args, TimeSpan.FromMinutes(10), 256L << 20, default, workingDirectory: work.Path);
                Assert.True(run.StartError == null && !run.TimedOut && !run.Truncated, $"{reference.Variable}: {run.StartError ?? run.Stderr}");
                var (total, found, missing) = Match(reference.Rows(run.Text, work.File("out")), files);
                var line = $"{Path.GetFileName(installer)}: {found:N0} of {total:N0}{(missing.Count > 0 ? "; missing: " + string.Join(", ", missing) : "")}";
                output.WriteLine($"{reference.Format} {line}");
                if (total == 0 || found < total * Floor) failures.Add(line);
            }
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    /// <summary>The reader's kind and every file it names, extracted or only listed; embedded cabinets are read one level down.</summary>
    private static (string? Kind, List<(string Name, long Size)> Files) Ours(string installer)
    {
        // the whole file picks the reader: an MSI's tables can lie past the first megabyte
        var name = Path.GetFileName(installer);
        if (Containers.ReaderFor(File.ReadAllBytes(installer), name) is not { } reader) return (null, []);
        using var stream = File.OpenRead(installer);
        var c = reader.Open(stream, name, false, AnalysisLimits.Default, default) ?? reader.Open(File.ReadAllBytes(installer), name, false, AnalysisLimits.Default, default);
        var files = Files(c);
        foreach (var item in c.Items)
            if (Containers.ReaderFor(item.Bytes, item.Name) is { Kind: "cab" } cab)
                files.AddRange(Files(cab.Open(item.Bytes, item.Name, false, AnalysisLimits.Default, default)));
        return (reader.Kind, files);
    }

    /// <summary>Entries as listed (a path may repeat), plus items the entries leave out.</summary>
    private static List<(string Name, long Size)> Files(ContainerContents c)
    {
        var files = (c.Entries ?? []).Select(e => (e.Path, e.Size)).ToList();
        var listed = files.Select(f => f.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
        files.AddRange(c.Items.Where(i => !listed.Contains(i.Name)).Select(i => (i.Name, (long)i.Bytes.Length)));
        return files;
    }

    /// <summary>A size the reference tool leaves blank (7-Zip, for a file of a non-solid NSIS installer): matched by name alone.</summary>
    private const long Unknown = -1;

    /// <summary>Reference rows found among ours by file name and size; empty files are left out (uninstallers are written at install time).</summary>
    private static (long Total, long Found, List<string> Missing) Match(IEnumerable<(string Name, long Size)> expected, List<(string Name, long Size)> ours)
    {
        var bySize = ours.GroupBy(r => (BaseName(r.Name), r.Size)).ToDictionary(g => g.Key, g => g.Count());
        var byName = ours.GroupBy(r => BaseName(r.Name)).ToDictionary(g => g.Key, g => g.Count());
        long total = 0, found = 0;
        var missing = new List<string>();
        foreach (var (path, size) in expected)
        {
            if (size == 0) continue;
            total++;
            var name = BaseName(path);
            bool hit = size == Unknown ? Take(byName, name) : Take(bySize, (name, size));
            if (hit) found++;
            else if (missing.Count < 5) missing.Add($"{name} ({size})");
        }
        return (total, found, missing);
    }

    private static bool Take<TKey>(Dictionary<TKey, int> counts, TKey key) where TKey : notnull
    {
        if (counts.GetValueOrDefault(key) == 0) return false;
        counts[key]--;
        return true;
    }

    // the Inno Setup unpacker writes ':' (from {code:...} names) as '_'
    private static string BaseName(string path) => path.Replace('\\', '/').Split('/')[^1].Replace(':', '_').ToLowerInvariant();

    /// <summary>7-Zip's technical listing: Path and Size (blank for some) of each entry that is not a folder.</summary>
    private static IEnumerable<(string, long)> SlTechnical(string text)
    {
        var record = new Dictionary<string, string>();
        foreach (var line in text[(text.IndexOf("----------", StringComparison.Ordinal) + 10)..].Split('\n').Select(l => l.TrimEnd('\r')).Append(""))
        {
            if (line.Length == 0)
            {
                if (record.TryGetValue("Path", out var path) && record.GetValueOrDefault("Folder") != "+" && record.TryGetValue("Size", out var size))
                    yield return (path, long.TryParse(size, out var bytes) ? bytes : Unknown);
                record.Clear();
            }
            else if (line.IndexOf(" = ", StringComparison.Ordinal) is > 0 and var at) record[line[..at]] = line[(at + 3)..];
        }
    }

    /// <summary>An Inno Setup unpacker's listing: size, date, time, name (a repeated name gets ",N" before its extension).</summary>
    private static IEnumerable<(string, long)> SetupListing(string text)
    {
        foreach (Match m in Regex.Matches(text, @"^\s*(\d+)\s+\d{4}-\d\d-\d\d \d\d:\d\d\s+(.+?)\r?$", RegexOptions.Multiline))
            if (m.Groups[2].Value != "install_script.iss")
                yield return (Regex.Replace(m.Groups[2].Value, @",\d+(\.[^.\\]*)?$", x => x.Groups[1].Value), long.Parse(m.Groups[1].Value));
    }

    /// <summary>The File table as CSV: FileName ("SHORT|long name") and FileSize columns.</summary>
    private static IEnumerable<(string, long)> FileTable(string text)
    {
        var lines = text.Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.Length > 0).ToList();
        if (lines.Count == 0) yield break;
        var header = Csv(lines[0]);
        int name = header.IndexOf("FileName"), size = header.IndexOf("FileSize");
        foreach (var line in lines.Skip(1))
            if (Csv(line) is var f && f.Count > Math.Max(name, size) && long.TryParse(f[size], out var bytes))
                yield return (f[name].Split('|')[^1], bytes);
    }

    private static List<string> Csv(string line)
    {
        var fields = new List<string>();
        var field = new System.Text.StringBuilder();
        bool quoted = false;
        for (int i = 0; i < line.Length; i++)
        {
            char ch = line[i];
            if (quoted && ch == '"' && i + 1 < line.Length && line[i + 1] == '"') { field.Append('"'); i++; }
            else if (ch == '"') quoted = !quoted;
            else if (ch == ',' && !quoted) { fields.Add(field.ToString()); field.Clear(); }
            else field.Append(ch);
        }
        fields.Add(field.ToString());
        return fields;
    }

    /// <summary>A bundle extracted: bootstrapper files by name, payloads by source id renamed from the manifest's Payload entries.</summary>
    private static IEnumerable<(string, long)> BundleFiles(string folder)
    {
        var ba = Path.Combine(folder, "ba");
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (File.Exists(Path.Combine(ba, "manifest.xml")))
            foreach (var p in System.Xml.Linq.XDocument.Load(Path.Combine(ba, "manifest.xml")).Descendants().Where(e => e.Name.LocalName == "Payload"))
                if (p.Attribute("SourcePath")?.Value is { } source && p.Attribute("FilePath")?.Value is { } file) names[source] = file;
        foreach (var dir in new[] { ba, Path.Combine(folder, "payloads") }.Where(Directory.Exists))
            foreach (var f in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                yield return (names.GetValueOrDefault(Path.GetRelativePath(dir, f).Replace('\\', '/'), f), new FileInfo(f).Length);
    }
}
