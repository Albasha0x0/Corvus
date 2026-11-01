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
        NetworkPolicy.Client(NetworkServers.GitHub, Timeout.InfiniteTimeSpan, new GitHubHttp(inner ?? NetworkPolicy.Sockets(NetworkServers.GitHub), token), userAgent,
            disposeInner: inner == null);

    /// <summary>
    /// Reads <paramref name="url"/> into memory; throws <see cref="TimeoutException"/>,
    /// naming the last progress, when no byte arrives for the <paramref name="rule"/> window.
    /// </summary>
    public static async Task<byte[]> DownloadAsync(HttpClient http, string url, StallRule rule, TimeProvider time, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Accept.ParseAdd("application/octet-stream");
        using var stalled = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var tick = rule.Window / 4;
        using var watch = time.CreateTimer(_ => { if (rule.Stalled(null)) stalled.Cancel(); }, null, tick, tick);
        try
        {
            rule.Progress("waiting for the response");
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, stalled.Token);
            response.EnsureSuccessStatusCode();
            var total = response.Content.Headers.ContentLength?.ToString() ?? "unknown";
            await using var body = await response.Content.ReadAsStreamAsync(stalled.Token);
            var data = new MemoryStream();
            var chunk = new byte[81920];
            for (int n; (n = await body.ReadAsync(chunk, stalled.Token)) > 0;)
            {
                data.Write(chunk, 0, n);
                rule.Progress($"{data.Length} of {total} bytes");
            }
            return data.ToArray();
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException($"no data for {rule.Window.TotalSeconds:0} s ({rule.LastUnitText}).");
        }
    }

    public static bool SendsToken(Uri uri) => uri.Scheme == Uri.UriSchemeHttps && TokenHosts.Contains(uri.Host, StringComparer.OrdinalIgnoreCase);

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        request.Headers.Authorization = !string.IsNullOrEmpty(token) && SendsToken(request.RequestUri!) ? new AuthenticationHeaderValue("Bearer", token) : null;
        return base.SendAsync(request, ct);
    }

    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken ct) => SendAsync(request, ct).GetAwaiter().GetResult();
}
