using System.Text;
using System.Text.RegularExpressions;

namespace Corvus.Services.Analysis.Endpoints;

/// <summary>
/// An endpoint the code names: the HTTP method (<c>*</c> when the code does not say), the URL or path template (values the
/// code computes as {name} or {}), the client that sends it (retrofit, okhttp, ktor, refit, httpclient, grpc, nsurl, url),
/// the file, and the method (DEX id, .NET member or native function) and location that build it.
/// </summary>
public sealed record CodeEndpoint(string Verb, string Url, string Client, string File, string? Member, string? Location)
{
    /// <summary>The base URL joined to a relative path, when the code sets one.</summary>
    public string? Base { get; init; }

    public string Text => $"{Verb} {Url}";
}

/// <summary>Template helpers shared by the code readers: placeholders, base joins and the key a capture template is matched on.</summary>
public static partial class EndpointTemplates
{
    /// <summary>A literal that is a URL with an http(s) or ws(s) scheme and a host.</summary>
    public static bool IsAbsoluteUrl(string s) => AbsoluteUrl().IsMatch(s);

    /// <summary>An absolute URL that is not an XML namespace or parser feature name (w3.org, schemas.android.com, ...).</summary>
    public static bool IsLinkUrl(string s) => IsAbsoluteUrl(s) && (Key(s).Host is not { } host || !NamespaceHosts.Contains(host));

    private static readonly HashSet<string> NamespaceHosts = new(StringComparer.Ordinal)
    {
        "www.w3.org", "w3.org", "schemas.android.com", "xml.org", "xmlpull.org", "ns.adobe.com", "schemas.microsoft.com", "schemas.openxmlformats.org",
        "purl.org", "schemas.xmlsoap.org", "java.sun.com", "xml.apache.org", "apache.org", "www.apple.com", "json-schema.org",
    };

    /// <summary>
    /// Joins a base URL and a relative path as Retrofit and System.Uri resolve them: an absolute path keeps only the base's
    /// origin, a relative one is appended after the base's last '/'.
    /// </summary>
    public static string Join(string baseUrl, string path)
    {
        if (path.Length == 0) return baseUrl;
        if (IsAbsoluteUrl(path) || path.StartsWith('{') && path.Contains("://", StringComparison.Ordinal)) return path;
        int scheme = baseUrl.IndexOf("://", StringComparison.Ordinal);
        int pathStart = scheme < 0 ? -1 : baseUrl.IndexOf('/', scheme + 3);
        if (path.StartsWith('/')) return (pathStart < 0 ? baseUrl.TrimEnd('/') : baseUrl[..pathStart]) + path;
        if (pathStart < 0) return baseUrl.TrimEnd('/') + "/" + path;
        return baseUrl[..(baseUrl.LastIndexOf('/') + 1)] + path;
    }

    /// <summary>A path the code leaves relative (no base known), written from the root.</summary>
    public static string Rooted(string path) => IsAbsoluteUrl(path) || path.StartsWith('/') || path.StartsWith('{') ? path : "/" + path;

    /// <summary>printf and NSString formats (%@, %d, %s, %lu, %.2f) as {}.</summary>
    public static string FoldFormat(string s) => FormatSpec().Replace(s, m => m.Value == "%%" ? "%" : "{}");

    /// <summary>
    /// What a code template and a capture template are matched on: host (empty when the code leaves it open), path segments
    /// with every {…} segment open, the query left out. A capture's {n} / {id} segments are concrete-value folds and only an
    /// open code segment matches them.
    /// </summary>
    public static (string Verb, string? Host, string[] Segments) Key(string text)
    {
        int space = text.IndexOf(' ');
        var verb = space < 0 ? "*" : text[..space];
        var url = space < 0 ? text : text[(space + 1)..];
        int q = url.IndexOfAny(['?', '#']);
        if (q >= 0) url = url[..q];
        string? host = null;
        int scheme = url.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0)
        {
            int slash = url.IndexOf('/', scheme + 3);
            var authority = slash < 0 ? url[(scheme + 3)..] : url[(scheme + 3)..slash];
            url = slash < 0 ? "/" : url[slash..];
            int colon = authority.LastIndexOf(':');
            if (colon > 0 && authority[(colon + 1)..].All(char.IsAsciiDigit)) authority = authority[..colon];
            host = authority.Contains('{', StringComparison.Ordinal) ? null : authority.ToLowerInvariant();
        }
        else if (url.StartsWith('{'))
        {
            int slash = url.IndexOf('/');
            url = slash < 0 ? "/" : url[slash..]; // {base}/path: the host is open
        }
        var segments = url.Split('/', StringSplitOptions.RemoveEmptyEntries);
        return (verb, host, segments);
    }

    /// <summary>True when a capture request template is an instance of the code template.</summary>
    public static bool Matches(string codeText, string captureText)
    {
        var code = Key(codeText);
        var seen = Key(captureText);
        if (code.Verb != "*" && seen.Verb != "*" && !code.Verb.Equals(seen.Verb, StringComparison.OrdinalIgnoreCase)) return false;
        if (code.Host != null && seen.Host != null && code.Host != seen.Host) return false;
        if (code.Segments.Length != seen.Segments.Length) return false;
        for (int i = 0; i < code.Segments.Length; i++)
        {
            var c = code.Segments[i];
            if (c.Contains('{', StringComparison.Ordinal))
            {
                if (!SegmentMatches(c, seen.Segments[i])) return false;
            }
            else if (!c.Equals(seen.Segments[i], StringComparison.Ordinal)) return false;
        }
        return true;
    }

    /// <summary>Whether <paramref name="text"/> fits a segment with placeholders ("v{n}.json"): its literal parts in order, each {…} any text.</summary>
    internal static bool SegmentMatches(string segment, string text)
    {
        var parts = Placeholder().Split(segment);
        if (parts.Length == 1) return segment.Equals(text, StringComparison.Ordinal);
        // Each literal part taken at its first place after the previous one: a
        // linear match, where a regex of lazy wildcards backtracks polynomially.
        if (!text.StartsWith(parts[0], StringComparison.Ordinal)) return false;
        int at = parts[0].Length;
        for (int i = 1; i < parts.Length - 1; i++)
        {
            int found = text.IndexOf(parts[i], at, StringComparison.Ordinal);
            if (found < 0) return false;
            at = found + parts[i].Length;
        }
        return text.Length - at >= parts[^1].Length && text.EndsWith(parts[^1], StringComparison.Ordinal);
    }

    [GeneratedRegex(@"^(https?|wss?)://[A-Za-z0-9{][^\s""'<>]*$", RegexOptions.IgnoreCase)]
    private static partial Regex AbsoluteUrl();

    [GeneratedRegex(@"%%|%[-+ #0]*[0-9]*(\.[0-9]+)?(hh|h|ll|l|q|z|t|j|L)?[@dDiuUxXoOfFeEgGsScCp]")]
    private static partial Regex FormatSpec();

    [GeneratedRegex(@"\{[^}]*\}")]
    private static partial Regex Placeholder();
}
