using System.Net.Http.Headers;
using Corvus.Core;

namespace Corvus.Setup;

/// <summary>HTTP for the GitHub API; the token goes only to GitHub's own hosts, never to asset download URLs.</summary>
// The policy follows redirects and drops Authorization on each hop; this
// handler adds it back for GitHub's hosts, so a moved private repository
// still answers.
internal sealed class GitHubHttp(HttpMessageHandler inner, string? token) : DelegatingHandler(inner)
{
    private static readonly string[] TokenHosts = ["api.github.com", "github.com"];

    public static HttpClient Create(string userAgent, string? token, HttpMessageHandler? inner = null) =>
        NetworkPolicy.Client(NetworkServers.GitHub, TimeSpan.FromMinutes(5), new GitHubHttp(inner ?? NetworkPolicy.Sockets(NetworkServers.GitHub), token), userAgent,
            disposeInner: inner == null);

    public static bool SendsToken(Uri uri) => uri.Scheme == Uri.UriSchemeHttps && TokenHosts.Contains(uri.Host, StringComparer.OrdinalIgnoreCase);

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        request.Headers.Authorization = !string.IsNullOrEmpty(token) && SendsToken(request.RequestUri!) ? new AuthenticationHeaderValue("Bearer", token) : null;
        return base.SendAsync(request, ct);
    }

    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken ct) => SendAsync(request, ct).GetAwaiter().GetResult();
}
