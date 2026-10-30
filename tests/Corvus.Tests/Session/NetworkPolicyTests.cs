using System.Net;
using System.Net.Sockets;
using Corvus.Core;
using Corvus.Native.Providers.Ida;

namespace Corvus.Tests;

/// <summary>
/// The download client's checks, each observed on a loopback listener that
/// records connections, or on a stub handler.
/// </summary>
public sealed class NetworkPolicyTests
{
    private sealed class Stub(Func<HttpRequestMessage, HttpResponseMessage> answer) : HttpMessageHandler
    {
        public readonly List<Uri> Seen = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Seen.Add(request.RequestUri!);
            return Task.FromResult(answer(request));
        }
    }

    private static TcpListener Listen()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return listener;
    }

    private static int Port(TcpListener listener) => ((IPEndPoint)listener.LocalEndpoint).Port;

    [Fact]
    public async Task An_unlisted_server_is_refused_before_a_connection()
    {
        var listener = Listen();
        try
        {
            using var http = NetworkPolicy.Client(new NetworkServers(["https://sym.example"]), TimeSpan.FromSeconds(5), offline: false);
            var e = await Assert.ThrowsAnyAsync<HttpRequestException>(() => http.GetAsync($"https://127.0.0.1:{Port(listener)}/x"));
            Assert.Contains("not a listed server", NetworkPolicy.Refusal(e)!.Message);
            Assert.False(listener.Pending());
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public async Task A_listed_name_that_resolves_to_loopback_connects_only_when_configured()
    {
        var listener = Listen();
        try
        {
            var servers = new[] { $"https://localhost:{Port(listener)}" };
            using (var http = NetworkPolicy.Client(new NetworkServers(servers), TimeSpan.FromSeconds(5), offline: false))
            {
                var e = await Assert.ThrowsAnyAsync<HttpRequestException>(() => http.GetAsync(servers[0] + "/x"));
                Assert.Contains("private, loopback or link-local", NetworkPolicy.Refusal(e)!.Message);
                Assert.False(listener.Pending());
            }
            using (var http = NetworkPolicy.Client(new NetworkServers(servers, Configured: true), TimeSpan.FromSeconds(5), offline: false))
            {
                var accepted = listener.AcceptTcpClientAsync();
                var request = http.GetAsync(servers[0] + "/x");
                (await accepted).Dispose();
                await Assert.ThrowsAnyAsync<Exception>(() => request);
            }
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public async Task A_redirect_from_https_to_http_is_refused()
    {
        var stub = new Stub(_ => new HttpResponseMessage(HttpStatusCode.Found) { Headers = { Location = new Uri("http://sym.example/x") } });
        using var http = NetworkPolicy.Client(new NetworkServers(["https://sym.example"]), TimeSpan.FromSeconds(5), stub, offline: false);
        var e = await Assert.ThrowsAnyAsync<HttpRequestException>(() => http.GetAsync("https://sym.example/x"));
        Assert.Contains("redirect from https", NetworkPolicy.Refusal(e)!.Message);
        Assert.Equal([new Uri("https://sym.example/x")], stub.Seen);
    }

    [Fact]
    public async Task A_redirect_to_an_unlisted_host_is_refused_before_a_connection()
    {
        var stub = new Stub(_ => new HttpResponseMessage(HttpStatusCode.Found) { Headers = { Location = new Uri("https://elsewhere.example/x") } });
        var servers = new NetworkServers(["https://sym.example"], RedirectHosts: ["*.blob.example"]);
        using var http = NetworkPolicy.Client(servers, TimeSpan.FromSeconds(5), stub, offline: false);
        var e = await Assert.ThrowsAnyAsync<HttpRequestException>(() => http.GetAsync("https://sym.example/x"));
        Assert.Contains("to elsewhere.example is refused", NetworkPolicy.Refusal(e)!.Message);
        Assert.Equal([new Uri("https://sym.example/x")], stub.Seen);
    }

    [Fact]
    public async Task A_redirect_to_a_known_redirect_host_is_followed()
    {
        var stub = new Stub(r => r.RequestUri!.Host == "sym.example"
            ? new HttpResponseMessage(HttpStatusCode.Found) { Headers = { Location = new Uri("https://store1.blob.example/x") } }
            : new HttpResponseMessage(HttpStatusCode.OK));
        var servers = new NetworkServers(["https://sym.example"], RedirectHosts: ["*.blob.example"]);
        using var http = NetworkPolicy.Client(servers, TimeSpan.FromSeconds(5), stub, offline: false);
        using var response = await http.GetAsync("https://sym.example/x");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("store1.blob.example", stub.Seen[^1].Host);
    }

    [Fact]
    public async Task An_http_server_connects_only_when_named_in_CORVUS_HTTP_SERVERS()
    {
        var listener = Listen();
        try
        {
            var server = $"http://localhost:{Port(listener)}";
            var servers = new NetworkServers([server], Configured: true);
            using (var http = NetworkPolicy.Client(servers, TimeSpan.FromSeconds(5), offline: false, httpServers: "other.example"))
            {
                var e = await Assert.ThrowsAnyAsync<HttpRequestException>(() => http.GetAsync(server + "/x"));
                Assert.Contains(NetworkPolicy.HttpServersVariable, NetworkPolicy.Refusal(e)!.Message);
                Assert.False(listener.Pending());
            }
            // The allowed request ran past 5 s on a macOS runner (release run 41002381249).
            using (var http = NetworkPolicy.Client(servers, TimeSpan.FromSeconds(30), offline: false, httpServers: $"other.example, localhost:{Port(listener)}"))
            {
                var accepted = listener.AcceptTcpClientAsync();
                var request = http.GetAsync(server + "/x");
                using (var client = await accepted)
                {
                    var stream = client.GetStream();
                    var buffer = new byte[4096];
                    _ = await stream.ReadAsync(buffer);
                    await stream.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray());
                }
                using var response = await request;
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            }
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public async Task Offline_sends_nothing_through_a_proxy()
    {
        var proxy = Listen();
        try
        {
            using var handler = new SocketsHttpHandler { Proxy = new WebProxy($"http://127.0.0.1:{Port(proxy)}"), UseProxy = true };
            using var http = NetworkPolicy.Client(new NetworkServers(["https://sym.example"]), TimeSpan.FromSeconds(5), handler, offline: true);
            var e = await Assert.ThrowsAnyAsync<HttpRequestException>(() => http.GetAsync("https://sym.example/x"));
            Assert.StartsWith("CORVUS_OFFLINE is set", NetworkPolicy.Refusal(e)!.Message);
            Assert.False(proxy.Pending());
        }
        finally { proxy.Stop(); }
    }

    [Theory]
    [InlineData("127.0.0.1", false)]
    [InlineData("10.1.2.3", false)]
    [InlineData("172.20.0.1", false)]
    [InlineData("192.168.1.1", false)]
    [InlineData("169.254.169.254", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("::1", false)]
    [InlineData("fe80::1", false)]
    [InlineData("fd00::1", false)]
    [InlineData("::ffff:10.0.0.1", false)]
    [InlineData("93.184.216.34", true)]
    [InlineData("2606:4700::1111", true)]
    public void Private_loopback_and_link_local_addresses_are_not_public(string address, bool isPublic) =>
        Assert.Equal(isPublic, NetworkPolicy.IsPublic(IPAddress.Parse(address)));

    [Fact]
    public void Offline_the_IDA_worker_symbol_path_names_no_server()
    {
        var pdb = Path.Combine(Path.GetTempPath(), "symbols", "app.pdb");
        foreach (var path in new[] { null, pdb })
        {
            var env = IdaProvider.WorkerEnvironment(Path.Combine(Path.GetTempPath(), "no-ida"), path, offline: true);
            Assert.DoesNotContain("://", Assert.Contains("_NT_SYMBOL_PATH", env)!, StringComparison.Ordinal);
        }
        Assert.DoesNotContain("_NT_SYMBOL_PATH", IdaProvider.WorkerEnvironment(Path.Combine(Path.GetTempPath(), "no-ida"), null, offline: false).Keys);
    }
}
