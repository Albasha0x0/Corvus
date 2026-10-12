using System.Net;
using Corvus.Setup;

namespace Corvus.Tests;

public sealed class GitHubHttpTests
{
    private sealed class Stub(Func<HttpRequestMessage, HttpResponseMessage> answer) : HttpMessageHandler
    {
        public readonly List<(Uri Uri, string? Auth)> Seen = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Seen.Add((request.RequestUri!, request.Headers.Authorization?.ToString()));
            return Task.FromResult(answer(request));
        }
    }

    private static HttpResponseMessage Redirect(string to) => new(HttpStatusCode.MovedPermanently) { Headers = { Location = new Uri(to) } };

    [Fact]
    public async Task A_renamed_private_repository_is_followed_with_the_token()
    {
        var stub = new Stub(r => r.RequestUri!.AbsolutePath switch
        {
            "/repos/old/name/releases/latest" => Redirect("https://api.github.com/repositories/42/releases/latest"),
            _ when r.Headers.Authorization == null => new HttpResponseMessage(HttpStatusCode.NotFound),
            _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") },
        });
        using var http = GitHubHttp.Create("test", "secret", stub);
        Assert.Equal("{}", await http.GetStringAsync("https://api.github.com/repos/old/name/releases/latest"));
        Assert.Equal(["Bearer secret", "Bearer secret"], stub.Seen.Select(s => s.Auth));
    }

    [Fact]
    public async Task An_asset_download_keeps_the_token_off_the_storage_host()
    {
        var stub = new Stub(r => r.RequestUri!.Host == "api.github.com"
            ? new HttpResponseMessage(HttpStatusCode.Found) { Headers = { Location = new Uri("https://objects.githubusercontent.com/x?sig=1") } }
            : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent([1, 2]) });
        using var http = GitHubHttp.Create("test", "secret", stub);
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/repos/a/b/releases/assets/7");
        request.Headers.Accept.ParseAdd("application/octet-stream");
        using var response = http.Send(request);
        Assert.Equal([1, 2], await response.Content.ReadAsByteArrayAsync());
        Assert.Equal([("api.github.com", "Bearer secret"), ("objects.githubusercontent.com", (string?)null)], stub.Seen.Select(s => (s.Uri.Host, s.Auth)));
    }

    [Theory]
    [InlineData("https://api.github.com/x", true)]
    [InlineData("https://github.com/x", true)]
    [InlineData("http://api.github.com/x", false)]
    [InlineData("https://objects.githubusercontent.com/x", false)]
    [InlineData("https://api.github.com.evil.example/x", false)]
    public void The_token_goes_only_to_github_hosts_over_https(string url, bool sent) => Assert.Equal(sent, GitHubHttp.SendsToken(new Uri(url)));
}
