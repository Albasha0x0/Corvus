using System.Net;
using System.Text.RegularExpressions;

namespace Corvus.Services.Analysis;

/// <summary>Targets whose scheme or form starts a local handler or reaches a network share: the rule link/local-handler.</summary>
internal static partial class LocalHandlerTargets
{
    // Sources: Microsoft "Office URI Schemes", Microsoft Learn "search-ms
    // protocol", and Microsoft guidance for the MSDT protocol handler.
    private static readonly string[] Schemes =
    [
        "ms-word", "ms-excel", "ms-powerpoint", "ms-access", "ms-visio", "ms-project", "ms-publisher", "ms-spd", "ms-infopath",
        "ms-officecmd", "ms-msdt", "search-ms", "search",
    ];

    private const int MaxHtmlTargets = 200;

    /// <summary>Names the handler a target starts: a scheme, file:// or a UNC path; null for any other target, https and mailto included.</summary>
    public static string? Match(string? target)
    {
        if (string.IsNullOrWhiteSpace(target)) return null;
        var t = target.Trim();
        if (t.StartsWith(@"\\", StringComparison.Ordinal) && t.Length > 2 && t[2] is not ('?' or '.' or '\\'))
            return IsWebDav(t) ? "UNC path to a WebDAV share" : "UNC path";
        if (t.StartsWith("file://", StringComparison.OrdinalIgnoreCase)) return "file:// target";
        int colon = t.IndexOf(':');
        if (colon <= 0) return null;
        var scheme = t[..colon];
        return Array.Exists(Schemes, s => s.Equals(scheme, StringComparison.OrdinalIgnoreCase)) ? scheme.ToLowerInvariant() + ": protocol handler" : null;
    }

    /// <summary>True for a UNC host written for the WebDAV client: a host with @SSL or @port, or a DavWWWRoot segment.</summary>
    public static bool IsWebDav(string unc)
    {
        var host = unc.TrimStart('\\');
        int end = host.IndexOf('\\');
        var name = end < 0 ? host : host[..end];
        return name.Contains('@') || unc.Contains(@"\DavWWWRoot", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>One finding per target that <see cref="Match"/> names; empty when none. Location says where the target was read.</summary>
    public static IReadOnlyList<Finding> Scan(IEnumerable<(string Target, string Location)> targets, string source)
    {
        var found = new List<Finding>();
        foreach (var (target, location) in targets)
            if (Match(target) is { } what)
                found.Add(new Finding(FindingRules.Check("link/local-handler", FindingLevel.Review), "link/local-handler", "link",
                    $"{what}: {(target.Length > 200 ? target[..200] + "..." : target)}", location, source));
        return found;
    }

    /// <summary>The href, src, action and formaction values of an HTML text, entity-decoded, as target and attribute name; at most 200.</summary>
    public static IReadOnlyList<(string Target, string Location)> FromHtml(string html)
    {
        var list = new List<(string, string)>();
        foreach (Match m in Reference().Matches(html))
        {
            var value = m.Groups[2].Success ? m.Groups[2].Value : m.Groups[3].Success ? m.Groups[3].Value : m.Groups[4].Value;
            list.Add((WebUtility.HtmlDecode(value), m.Groups[1].Value.ToLowerInvariant() + " attribute"));
            if (list.Count >= MaxHtmlTargets) break;
        }
        return list;
    }

    [GeneratedRegex(@"(?:^|[\s""'/])(href|src|action|formaction)\s*=\s*(?:""([^""]*)""|'([^']*)'|([^\s>""']+))", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)]
    private static partial Regex Reference();
}
