using System.Net;
using System.Text.RegularExpressions;

namespace Corvus.Core.Documents;

/// <summary>Scheme, UNC and HTML-reference matching for targets that start a local handler or reach a network share.</summary>
internal static partial class HandlerTargets
{
    // Sources: Microsoft "Office URI Schemes", Microsoft Learn "search-ms
    // protocol", and Microsoft guidance for the MSDT protocol handler.
    internal static readonly string[] Schemes =
    [
        "ms-word", "ms-excel", "ms-powerpoint", "ms-access", "ms-visio", "ms-project", "ms-publisher", "ms-spd", "ms-infopath",
        "ms-officecmd", "ms-msdt", "search-ms", "search", "ms-appinstaller",
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
        if (!Array.Exists(Schemes, s => s.Equals(scheme, StringComparison.OrdinalIgnoreCase))) return null;
        var name = scheme.ToLowerInvariant();
        // Parameters of ms-officecmd have no public specification.
        return name == "ms-officecmd" ? name + ": protocol handler, parameters unspecified" : name + ": protocol handler";
    }

    /// <summary>True for a UNC host written for the WebDAV client: a host with @SSL or @port, or a DavWWWRoot segment.</summary>
    public static bool IsWebDav(string unc)
    {
        var host = unc.TrimStart('\\');
        int end = host.IndexOf('\\');
        var name = end < 0 ? host : host[..end];
        return name.Contains('@') || unc.Contains(@"\DavWWWRoot", StringComparison.OrdinalIgnoreCase);
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
