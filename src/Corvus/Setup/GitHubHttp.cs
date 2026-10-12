using System.Net;
using System.Net.Http.Headers;

namespace Corvus.Setup;

/// <summary>
/// HTTP for the GitHub API. Redirects are followed here: .NET drops the Authorization header on every redirect, so a
/// renamed or moved private repository (301 to api.github.com/repositories/ID) would answer 404. The token goes only
/// to GitHub's own hosts, never to the signed download URLs assets redirect to.
/// </summary>
internal sealed class GitHubHttp(HttpMessageHandler inner, string? token) : DelegatingHandler(inner)
{
    private const int MaxRedirects = 10;
    private static readonly string[] TokenHosts = ["api.github.com", "github.com"];

    public static HttpClient Create(string userAgent, string? token, HttpMessageHandler? inner = null)
    {
        var http = new HttpClient(new GitHubHttp(inner ?? new SocketsHttpHandler { AllowAutoRedirect = false }, token)) { Timeout = TimeSpan.FromMinutes(5) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd(userAgent);
        return http;
    }

    public static bool SendsToken(Uri uri) => uri.Scheme == Uri.UriSchemeHttps && TokenHosts.Contains(uri.Host, StringComparer.OrdinalIgnoreCase);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        Authorize(request);
        var response = await base.SendAsync(request, ct).ConfigureAwait(false);
        for (int hop = 0; hop < MaxRedirects && IsRedirect(response.StatusCode) && response.Headers.Location is { } location; hop++)
        {
            var next = new HttpRequestMessage(HttpMethod.Get, location.IsAbsoluteUri ? location : new Uri(request.RequestUri!, location));
            foreach (var header in request.Headers.Where(h => h.Key != "Authorization")) next.Headers.TryAddWithoutValidation(header.Key, header.Value);
            response.Dispose();
            request = next;
            Authorize(request);
            response = await base.SendAsync(request, ct).ConfigureAwait(false);
        }
        return response;
    }

    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken ct) => SendAsync(request, ct).GetAwaiter().GetResult();

    private void Authorize(HttpRequestMessage request)
    {
        request.Headers.Authorization = !string.IsNullOrEmpty(token) && SendsToken(request.RequestUri!) ? new AuthenticationHeaderValue("Bearer", token) : null;
    }

    private static bool IsRedirect(HttpStatusCode code) => code is HttpStatusCode.MovedPermanently or HttpStatusCode.Found or HttpStatusCode.SeeOther
        or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect;
}
