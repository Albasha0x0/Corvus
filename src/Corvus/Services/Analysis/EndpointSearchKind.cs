using System.Text.RegularExpressions;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>
/// search_container kind=endpoint on a HAR or mitmproxy capture: each request template once (method, host, path with
/// numeric and id segments as {n} / {id}, query names), with its request count and statuses. Values are never shown.
/// </summary>
internal sealed partial class EndpointSearchKind : IContainerSearchKind
{
    public IReadOnlyList<string> Kinds => ["endpoint"];

    public IEnumerable<ContainerMatch> Search(ContainerScope scope, string kind, Func<string, bool> matches, CancellationToken ct)
    {
        byte[] data;
        try
        {
            if (!File.Exists(scope.Source) || new FileInfo(scope.Source).Length > AnalysisLimits.Default.MaxItemBytes) yield break;
            data = File.ReadAllBytes(scope.Source);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { yield break; }
        List<CapturedResponse>? requests = Captures.LooksLikeHar(data) ? Captures.ReadHar(data)
            : Captures.LooksLikeFlows(data) ? Captures.ReadFlows(data, [], ct) : null;
        if (requests == null) yield break;
        var groups = requests.GroupBy(r => Template(r.Method, r.Url)).OrderBy(g => g.Key.Host, StringComparer.Ordinal).ThenBy(g => g.Key.Text, StringComparer.Ordinal);
        foreach (var g in groups)
        {
            ct.ThrowIfCancellationRequested();
            if (!matches(g.Key.Text) && !matches(g.Key.Host)) continue;
            var statuses = string.Join(", ", g.Select(r => r.Status).Where(s => s != 0).Distinct().Order());
            yield return new ContainerMatch(g.Key.Host, g.Key.Text, "endpoint")
            {
                Detail = $"{g.Count()} request(s)" + (statuses.Length > 0 ? $", status {statuses}" : ""),
            };
        }
    }

    internal static (string Host, string Text) Template(string method, string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return ("", $"{method} {url}");
        var segments = uri.AbsolutePath.Split('/').Select(s => s.Length == 0 ? s : Numeric().IsMatch(s) ? "{n}" : Id().IsMatch(s) ? "{id}" : s);
        var names = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries).Select(p => p.Split('=')[0]).Distinct().Order(StringComparer.Ordinal);
        var query = string.Join("&", names.Select(n => n + "=…"));
        return (uri.Host, $"{method} {uri.Scheme}://{uri.Authority}{string.Join("/", segments)}{(query.Length > 0 ? "?" + query : "")}");
    }

    [GeneratedRegex("^[0-9]+$")]
    private static partial Regex Numeric();

    // GUIDs and long hex or base64url tokens
    [GeneratedRegex("^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,}|[A-Za-z0-9_-]{24,})$")]
    private static partial Regex Id();
}
