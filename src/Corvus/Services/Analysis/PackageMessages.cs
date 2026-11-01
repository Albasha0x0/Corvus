using System.IO.Compression;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Core.Archives;
using Corvus.Core.Protobuf;
using Corvus.Services.Analysis.Endpoints;

namespace Corvus.Services.Analysis;

/// <summary>Message ids that scripts of a package name, and the descriptors its .pb and .pbe entries hold.</summary>
internal static class PackageMessages
{
    /// <summary>A message id a script names: the id, the message name, the entry that names it and whether it is a bare assignment.</summary>
    public sealed record Id(int Number, string Name, string Source, bool Bare = false);

    /// <summary>What a package read found; Unreadable entries leave their ids and descriptors unknown, not absent.</summary>
    public sealed record Package(IReadOnlyList<FoundDescriptor> Descriptors, IReadOnlyList<Id> Ids, IReadOnlyList<string> Unreadable, int Scanned, int Total);

    private const RegexOptions Options = RegexOptions.NonBacktracking | RegexOptions.Multiline | RegexOptions.CultureInvariant;

    // Matches ids written as [1001] = "pkg.Message".
    private static readonly Regex ByNumber = new(@"^\s*\[\s*(\d{1,9})\s*\]\s*=\s*[""']([A-Za-z_][\w.]*)[""']", Options);

    // Matches ids written as Message = 1001.
    private static readonly Regex ByName = new(@"^\s*([A-Za-z_][\w.]*)\s*=\s*(\d{1,9})\s*[,;]?\s*(?:--.*)?$", Options);

    private static bool IsScript(string name) => name.EndsWith(".lua", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".luae", StringComparison.OrdinalIgnoreCase);

    private static bool IsDescriptor(string name) => name.EndsWith(".pb", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".pbe", StringComparison.OrdinalIgnoreCase);

    /// <summary>True when the archive holds a script or descriptor entry this reader reads.</summary>
    public static bool Any(string path)
    {
        using var zip = ApiSurface.OpenZip(path);
        return ApiSurface.Entries(zip, path).Any(e => IsScript(e.FullName) || IsDescriptor(e.FullName));
    }

    /// <summary>Ids named by the script text, one per matching line.</summary>
    public static List<Id> ParseIds(string text, string source)
    {
        var ids = new List<Id>();
        foreach (Match m in ByNumber.Matches(text)) ids.Add(new Id(int.Parse(m.Groups[1].Value), m.Groups[2].Value, source));
        foreach (Match m in ByName.Matches(text)) ids.Add(new Id(int.Parse(m.Groups[2].Value), m.Groups[1].Value, source, Bare: true));
        return ids;
    }

    /// <summary>Reads the scripts and descriptor entries of a zip; an entry over <paramref name="limits"/> or with a transformed payload is listed as unreadable.</summary>
    public static Package Read(string path, AnalysisLimits limits, CancellationToken ct)
    {
        var ids = new List<Id>();
        var descriptors = new List<FoundDescriptor>();
        var unreadable = new List<string>();
        int scanned = 0, total = 0;
        var container = new TransformedBlockContainerReader();
        using var zip = ApiSurface.OpenZip(path);
        foreach (var e in ApiSurface.Entries(zip, path).Where(e => IsScript(e.FullName) || IsDescriptor(e.FullName)).OrderBy(e => e.FullName, StringComparer.Ordinal))
        {
            ct.ThrowIfCancellationRequested();
            total++;
            byte[]? bytes = null;
            try { using var s = e.Open(); bytes = e.Length <= limits.MaxItemBytes ? Blob.ReadBounded(s, limits.MaxItemBytes) : null; }
            catch (Exception ex) when (ex is InvalidDataException or IOException) { unreadable.Add($"{e.FullName} (corrupt entry)"); continue; }
            if (bytes is null) { unreadable.Add($"{e.FullName} (over the item limit)"); continue; }
            long baseOffset = 0;
            if (container.Accepts(bytes, e.FullName))
            {
                ExtractedItem? payload;
                try { payload = container.Open(bytes, e.FullName, false, limits, ct).Items.FirstOrDefault(); }
                catch (Exception ex) when (ex is InvalidDataException or IOException or ToolError) { unreadable.Add($"{e.FullName} (corrupt container)"); continue; }
                if (payload is null || !IsDescriptor(e.FullName)) { unreadable.Add($"{e.FullName} (transformed payload)"); continue; }
                bytes = payload.Bytes;
                baseOffset = 8;
            }
            scanned++;
            if (IsScript(e.FullName))
            {
                ids.AddRange(ParseIds(System.Text.Encoding.UTF8.GetString(bytes), e.FullName));
                continue;
            }
            var found = ProtoScan.Raw(bytes, ct);
            // A .pb entry without a descriptor is plain data, read and not a descriptor.
            if (found.Count == 0)
            {
                if (!e.FullName.EndsWith(".pb", StringComparison.OrdinalIgnoreCase)) { unreadable.Add($"{e.FullName} (no readable descriptor)"); scanned--; }
                continue;
            }
            foreach (var (offset, file) in found) descriptors.Add(new FoundDescriptor(file, e.FullName, "raw bytes", baseOffset + offset));
        }
        return new Package(descriptors, ids, unreadable, scanned, total);
    }

    /// <summary>Message full names ("pkg.Outer.Inner") of a descriptor, nested messages included.</summary>
    public static IEnumerable<(string Full, ProtoMessage Message)> Messages(ProtoFile file)
    {
        var prefix = file.Package is { Length: > 0 } p ? p + "." : "";
        var stack = new Stack<(string, ProtoMessage)>(file.Messages.AsEnumerable().Reverse().Select(m => (prefix + m.Name, m)));
        while (stack.Count > 0)
        {
            var (full, m) = stack.Pop();
            yield return (full, m);
            foreach (var n in Enumerable.Reverse(m.Nested)) stack.Push((full + "." + n.Name, n));
        }
    }
}
