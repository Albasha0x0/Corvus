using Corvus.Core.Documents;

namespace Corvus.Services.Analysis;

/// <summary>Targets whose scheme or form starts a local handler or reaches a network share: the rule link/local-handler.</summary>
internal static class LocalHandlerTargets
{
    /// <summary>Names the handler a target starts: a scheme, file:// or a UNC path; null for any other target, https and mailto included.</summary>
    public static string? Match(string? target) => HandlerTargets.Match(target);

    /// <summary>True for a UNC host written for the WebDAV client: a host with @SSL or @port, or a DavWWWRoot segment.</summary>
    public static bool IsWebDav(string unc) => HandlerTargets.IsWebDav(unc);

    /// <summary>The href, src, action and formaction values of an HTML text, entity-decoded, as target and attribute name; at most 200.</summary>
    public static IReadOnlyList<(string Target, string Location)> FromHtml(string html) => HandlerTargets.FromHtml(html);

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
}
