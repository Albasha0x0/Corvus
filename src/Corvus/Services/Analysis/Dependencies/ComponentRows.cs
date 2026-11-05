using System.Text;
using System.Text.Json;
using Corvus.Native;

namespace Corvus.Services.Analysis.Dependencies;

/// <summary>Components of an image as JSON lines for a Log Analytics custom table, one row per component.</summary>
public static class ComponentRows
{
    /// <summary>The most images a folder walk summarizes; further images are named as not read.</summary>
    public const int MaxImages = 500;

    private const int HeaderBytes = 4096;

    /// <summary>The row columns and their Log Analytics types, in row order.</summary>
    public static IReadOnlyList<(string Name, string Type)> Columns { get; } =
    [
        ("TimeGenerated", "datetime"), ("ImageSHA1", "string"), ("ImageSHA256", "string"), ("ImageName", "string"),
        ("Component", "string"), ("Version", "string"), ("Ecosystem", "string"), ("Purl", "string"), ("Cpe", "string"),
        ("Evidence", "string"), ("Advisories", "dynamic"), ("AdvisoryState", "string"),
    ];

    // Vendor and product names of the NVD CPE dictionary, by the library name the version-string rules use.
    private static readonly Dictionary<string, string> CpeNames = new(StringComparer.Ordinal)
    {
        ["zlib"] = "zlib:zlib",
        ["OpenSSL"] = "openssl:openssl",
        ["Mbed TLS"] = "trustedfirmware:mbed_tls",
        ["wolfSSL"] = "wolfssl:wolfssl",
    };

    /// <summary>The CPE 2.3 name of a native library version, or empty when the dictionary has no entry confirmed for the name or no version was read.</summary>
    public static string Cpe(string name, string? version) =>
        version is { Length: > 0 } && CpeNames.TryGetValue(name, out var product) && version.All(IsCpeVersionChar)
            ? $"cpe:2.3:a:{product}:{version}:*:*:*:*:*:*:*"
            : "";

    private static bool IsCpeVersionChar(char c) => char.IsAsciiLetterOrDigit(c) || c == '.';

    /// <summary>The rows of one image: nothing for a subject or a component the build does not load.</summary>
    public static IEnumerable<string> Lines(DateTimeOffset generated, string imageName, string sha1, string sha256, DependencyFacts facts)
    {
        var time = generated.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", System.Globalization.CultureInfo.InvariantCulture);
        foreach (var c in facts.All.Where(c => c.Scope != "excluded"))
        {
            var (ids, state) = Advisory(facts.Advisories, c);
            var native = c.Ecosystem == "native";
            yield return JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["TimeGenerated"] = time, ["ImageSHA1"] = sha1, ["ImageSHA256"] = sha256, ["ImageName"] = imageName,
                ["Component"] = c.Name, ["Version"] = c.Version ?? "", ["Ecosystem"] = c.Ecosystem, ["Purl"] = c.Purl ?? "",
                ["Cpe"] = native ? Cpe(c.Name, c.Version) : "", ["Evidence"] = c.Source, ["Advisories"] = ids, ["AdvisoryState"] = state,
            });
        }
    }

    // Unknown is not none: a component the check did not match says why.
    private static (string[] Ids, string State) Advisory(DependencyAdvisories? advisories, DependencyComponent c)
    {
        if (advisories == null) return ([], "unknown: the advisory check did not run");
        var ids = advisories.Findings.Where(f => f.Component == c.Ref).SelectMany(f => f.Aliases.Prepend(f.Id)).Distinct().ToArray();
        if (ids.Length > 0) return (ids, "matched");
        return advisories.Unmatched.TryGetValue(c.Ref, out var why) ? ([], $"unknown: {why}") : ([], "none");
    }

    /// <summary>
    /// The rows of every native or managed image under <paramref name="folder"/>, read through <paramref name="summarize"/>;
    /// a skipped image is a note, and the walk stops at <see cref="MaxImages"/>.
    /// </summary>
    public static (List<string> Lines, int Images, List<string> Notes) OfFolder(string folder, DateTimeOffset generated,
        Func<string, InspectionService.FileSummary> summarize, CancellationToken ct)
    {
        var lines = new List<string>();
        var notes = new List<string>();
        int images = 0, unread = 0;
        foreach (var file in Directory.EnumerateFiles(folder, "*", new EnumerationOptions
                     {
                         RecurseSubdirectories = true, IgnoreInaccessible = true,
                         // A link is not followed, so a cycle cannot widen the walk.
                         AttributesToSkip = FileAttributes.ReparsePoint,
                     })
                     .Order(StringComparer.Ordinal))
        {
            ct.ThrowIfCancellationRequested();
            if (!IsImage(file)) continue;
            if (images >= MaxImages) { unread++; continue; }
            images++;
            var name = Path.GetRelativePath(folder, file).Replace('\\', '/');
            try { lines.AddRange(OfSummary(summarize(file), name, generated)); }
            catch (Exception ex) when (ex is Core.ToolError or IOException or UnauthorizedAccessException) { notes.Add($"{name}: not read, so its components are unknown ({ex.Message})"); }
        }
        if (unread > 0) notes.Add($"{unread} more images past the limit of {MaxImages} were not read; their components are unknown.");
        return (lines, images, notes);
    }

    /// <summary>The rows of a summary's dependencies view under the image name; empty when the view lists no component.</summary>
    public static IEnumerable<string> OfSummary(InspectionService.FileSummary summary, string imageName, DateTimeOffset generated) =>
        summary.Views.GetValueOrDefault("dependencies")?.Detail is DependencyFacts facts
            ? Lines(generated, imageName, summary.File.Sha1, summary.File.Sha256, facts)
            : [];

    private static bool IsImage(string file)
    {
        try
        {
            using var stream = File.OpenRead(file);
            var head = new byte[HeaderBytes];
            int read = stream.Read(head, 0, head.Length);
            return NativeImageLoader.Detect(head.AsSpan(0, read)) != NativeFileKind.Unknown;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    /// <summary>The JSON lines as UTF-8 with a line feed after each.</summary>
    public static byte[] Encode(IEnumerable<string> lines) => Encoding.UTF8.GetBytes(string.Concat(lines.Select(l => l + "\n")));
}
