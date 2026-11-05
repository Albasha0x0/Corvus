using System.Text;
using System.Text.Json;
using Corvus.Native;

namespace Corvus.Services.Analysis.Dependencies;

/// <summary>Components of an image as JSON lines for a Log Analytics custom table, one row per component.</summary>
public static class ComponentRows
{
    /// <summary>The most images a folder walk summarizes; further images are named as not read.</summary>
    public const int MaxImages = 500;

    /// <summary>The most characters a text column keeps; a longer value is cut and ends with <see cref="Cut"/>.</summary>
    public const int MaxFieldChars = 1024;

    /// <summary>The marker that ends a value cut at <see cref="MaxFieldChars"/>.</summary>
    public const string Cut = "...[truncated]";

    private const int HeaderBytes = 4096;
    private const int MaxCpeVersionChars = 64;

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
        ["LibreSSL"] = "openbsd:libressl",
        ["Mbed TLS"] = "trustedfirmware:mbed_tls",
        ["wolfSSL"] = "wolfssl:wolfssl",
    };

    /// <summary>The CPE 2.3 name of a native library version, or empty when the dictionary has no entry confirmed for the name or no version was read.</summary>
    public static string Cpe(string name, string? version) =>
        version is { Length: > 0 } && CpeNames.TryGetValue(name, out var product) && version.Length <= MaxCpeVersionChars && version.All(IsCpeVersionChar)
            ? $"cpe:2.3:a:{product}:{version}:*:*:*:*:*:*:*"
            : "";

    // Values come from the analyzed file; a column holds at most MaxFieldChars.
    private static string Clip(string? value) =>
        value is null || value.Length <= MaxFieldChars ? value ?? "" : string.Concat(value.AsSpan(0, MaxFieldChars - Cut.Length), Cut);

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
                ["TimeGenerated"] = time, ["ImageSHA1"] = sha1, ["ImageSHA256"] = sha256, ["ImageName"] = Clip(imageName),
                ["Component"] = Clip(c.Name), ["Version"] = Clip(c.Version), ["Ecosystem"] = c.Ecosystem, ["Purl"] = Clip(c.Purl),
                ["Cpe"] = native ? Cpe(c.Name, c.Version) : "", ["Evidence"] = Clip(c.Source), ["Advisories"] = ids, ["AdvisoryState"] = state,
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
        int images = 0, unread = 0, other = 0;
        foreach (var file in Directory.EnumerateFiles(folder, "*", new EnumerationOptions
                     {
                         RecurseSubdirectories = true, IgnoreInaccessible = true,
                         // A link is not followed, so a cycle cannot widen the walk.
                         AttributesToSkip = FileAttributes.ReparsePoint,
                     })
                     .Order(StringComparer.Ordinal))
        {
            ct.ThrowIfCancellationRequested();
            var kind = IsImage(file);
            var rel = Path.GetRelativePath(folder, file).Replace('\\', '/');
            if (kind == null) { notes.Add($"{rel}: could not be opened, so its components are unknown"); continue; }
            if (kind == false) { other++; continue; }
            if (images >= MaxImages) { unread++; continue; }
            images++;
            // A reader fault on one image is a note; the other images still write.
            try { lines.AddRange(OfSummary(summarize(file), rel, generated)); }
            catch (Exception ex) when (ex is not OperationCanceledException) { notes.Add($"{rel}: not read, so its components are unknown ({ex.Message})"); }
        }
        if (other > 0) notes.Add($"{other} files are not native or managed images and were not read; any components inside them are unknown");
        if (unread > 0) notes.Add($"{unread} more images past the limit of {MaxImages} were not read; their components are unknown.");
        return (lines, images, notes);
    }

    /// <summary>The rows of a summary's dependencies view under the image name; empty when the view lists no component.</summary>
    public static IEnumerable<string> OfSummary(InspectionService.FileSummary summary, string imageName, DateTimeOffset generated) =>
        summary.Views.GetValueOrDefault("dependencies")?.Detail is DependencyFacts facts
            ? Lines(generated, imageName, summary.File.Sha1, summary.File.Sha256, facts)
            : [];

    // Null when the file could not be opened: unknown, not a non-image.
    private static bool? IsImage(string file)
    {
        try
        {
            using var stream = File.OpenRead(file);
            var head = new byte[HeaderBytes];
            int read = stream.Read(head, 0, head.Length);
            return NativeImageLoader.Detect(head.AsSpan(0, read)) != NativeFileKind.Unknown;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>The JSON lines as UTF-8 with a line feed after each.</summary>
    public static byte[] Encode(IEnumerable<string> lines) => Encoding.UTF8.GetBytes(string.Concat(lines.Select(l => l + "\n")));
}
