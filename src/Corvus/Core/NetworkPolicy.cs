using System.Net;
using System.Net.Sockets;

namespace Corvus.Core;

/// <summary>
/// The servers a client may request: <paramref name="Listed"/> base URLs, and
/// with <paramref name="Configured"/> set, servers the user set up, which may
/// sit on private, loopback or link-local addresses. A redirect may lead to a
/// listed server or to one of <paramref name="RedirectHosts"/> (a host, or
/// "*.suffix").
/// </summary>
public sealed record NetworkServers(IReadOnlyList<string> Listed, bool Configured = false, IReadOnlyList<string>? RedirectHosts = null)
{
    /// <summary>
    /// GitHub's API and site, with the hosts its release assets and source
    /// archives redirect to.
    /// </summary>
    public static readonly NetworkServers GitHub = new(["https://api.github.com", "https://github.com"],
        RedirectHosts: ["objects.githubusercontent.com", "release-assets.githubusercontent.com", "codeload.github.com"]);
}

/// <summary>
/// A request the network policy refused before connecting; the message names
/// the URL and why.
/// </summary>
public sealed class NetworkRefusedException(string message) : HttpRequestException(message);

/// <summary>
/// The one HTTP client of every download: nothing under CORVUS_OFFLINE, https
/// only (plain http for CORVUS_HTTP_SERVERS), listed servers and their known
/// redirect hosts only, private addresses only for configured servers, each
/// redirect hop checked again.
/// </summary>
public static class NetworkPolicy
{
    public const int MaxRedirects = 10;

    /// <summary>
    /// Comma-separated server URLs or hosts (host:port) that may be requested
    /// over plain http.
    /// </summary>
    public const string HttpServersVariable = "CORVUS_HTTP_SERVERS";

    /// <summary>
    /// A client for <paramref name="servers"/>. <paramref name="inner"/> replaces
    /// the socket handler, its connections then not address-checked, and is
    /// disposed with the client only when <paramref name="disposeInner"/> is set.
    /// <paramref name="offline"/> defaults to CORVUS_OFFLINE and
    /// <paramref name="httpServers"/> to CORVUS_HTTP_SERVERS.
    /// </summary>
    public static HttpClient Client(NetworkServers servers, TimeSpan timeout, HttpMessageHandler? inner = null, string? userAgent = null,
        bool? offline = null, TimeSpan? connectTimeout = null, bool disposeInner = false, string? httpServers = null)
    {
        var policy = new PolicyHandler(inner ?? Sockets(servers, connectTimeout), ownsInner: inner == null || disposeInner, servers, offline ?? ReferencePacks.Offline,
            httpServers ?? HttpServers);
        var http = new HttpClient(policy) { Timeout = timeout };
        if (userAgent != null) http.DefaultRequestHeaders.UserAgent.ParseAdd(userAgent);
        return http;
    }

    /// <summary>
    /// A client for http endpoints on this machine (a debugger's inspector
    /// port); a host other than a loopback address is refused.
    /// </summary>
    public static HttpClient Loopback(TimeSpan timeout) => new(new LoopbackHandler()) { Timeout = timeout };

    /// <summary>
    /// The socket handler of <paramref name="servers"/>: no redirects, each
    /// address resolved and checked before connecting.
    /// </summary>
    internal static SocketsHttpHandler Sockets(NetworkServers servers, TimeSpan? connectTimeout = null) => new()
    {
        AllowAutoRedirect = false,
        ConnectTimeout = connectTimeout ?? TimeSpan.FromSeconds(30),
        ConnectCallback = (context, ct) => ConnectAsync(context, servers, ct),
    };

    /// <summary>
    /// The refusal behind <paramref name="ex"/>, through wrapping request
    /// exceptions; null when it is none.
    /// </summary>
    public static NetworkRefusedException? Refusal(Exception? ex)
    {
        for (; ex != null; ex = ex.InnerException)
            if (ex is NetworkRefusedException refused) return refused;
        return null;
    }

    /// <summary>
    /// False for loopback, private (RFC 1918, unique local), link-local, shared
    /// (100.64/10), unspecified and multicast addresses.
    /// </summary>
    public static bool IsPublic(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address)) return false;
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return !(b[0] is 0 or 10 or >= 224
                     || (b[0] == 100 && (b[1] & 0xC0) == 64)
                     || (b[0] == 169 && b[1] == 254)
                     || (b[0] == 172 && (b[1] & 0xF0) == 16)
                     || (b[0] == 192 && b[1] == 168));
        }
        if (address.AddressFamily != AddressFamily.InterNetworkV6) return false;
        var v6 = address.GetAddressBytes();
        return !(address.Equals(IPAddress.IPv6None) || address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast
                 || (v6[0] & 0xFE) == 0xFC);
    }

    private static string? HttpServers => Corvus.Native.Providers.ExternalTools.ReadVariable(HttpServersVariable);

    /// <summary>
    /// True when <paramref name="uri"/>'s server is named in
    /// <paramref name="httpServers"/> (default CORVUS_HTTP_SERVERS), by URL or
    /// by host; a host without a port matches any port.
    /// </summary>
    public static bool PlainHttpAllowed(Uri uri, string? httpServers = null) => (httpServers ?? HttpServers ?? "")
        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Any(entry => Uri.TryCreate(entry.Contains("://", StringComparison.Ordinal) ? entry : "http://" + entry, UriKind.Absolute, out var named)
                      && string.Equals(named.Host, uri.Host, StringComparison.OrdinalIgnoreCase)
                      && (named.Port == uri.Port || (!entry.Contains("://", StringComparison.Ordinal) && !entry.Contains(':'))));

    private static bool RedirectHost(NetworkServers servers, Uri uri) => (servers.RedirectHosts ?? []).Any(h =>
        h.StartsWith("*.", StringComparison.Ordinal) ? uri.Host.EndsWith(h[1..], StringComparison.OrdinalIgnoreCase)
            : string.Equals(h, uri.Host, StringComparison.OrdinalIgnoreCase));

    private static bool Listed(NetworkServers servers, Uri uri) => servers.Listed.Any(s =>
        Uri.TryCreate(s, UriKind.Absolute, out var listed) && string.Equals(listed.Host, uri.Host, StringComparison.OrdinalIgnoreCase) && listed.Port == uri.Port);

    private static bool MayBePrivate(NetworkServers servers, string host) => servers.Configured && servers.Listed.Any(s =>
        Uri.TryCreate(s, UriKind.Absolute, out var listed) && string.Equals(listed.Host, host, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Throws when <paramref name="uri"/> may not be requested;
    /// <paramref name="from"/> is the request redirected to it, null for the
    /// request itself.
    /// </summary>
    private static void Check(Uri uri, NetworkServers servers, bool offline, string? httpServers, Uri? from)
    {
        if (offline) throw new NetworkRefusedException($"CORVUS_OFFLINE is set: {uri} is not requested.");
        if (uri.Scheme != Uri.UriSchemeHttps)
        {
            if (from?.Scheme == Uri.UriSchemeHttps) throw new NetworkRefusedException($"A redirect from https to {uri} is refused.");
            if (uri.Scheme != Uri.UriSchemeHttp || !PlainHttpAllowed(uri, httpServers))
                throw new NetworkRefusedException($"{uri} is not https, and its server is not in {HttpServersVariable}.");
        }
        if (from == null && !Listed(servers, uri))
            throw new NetworkRefusedException($"{uri.Authority} is not a listed server (listed: {string.Join(", ", servers.Listed)}).");
        if (from != null && !Listed(servers, uri) && !RedirectHost(servers, uri))
            throw new NetworkRefusedException($"A redirect from {from.Host} to {uri.Host} is refused: not a server or redirect host listed for this download " +
                                              $"(listed: {string.Join(", ", servers.Listed.Concat(servers.RedirectHosts ?? []))}).");
        if (IPAddress.TryParse(uri.IdnHost, out var literal) && !IsPublic(literal) && !MayBePrivate(servers, uri.IdnHost))
            throw new NetworkRefusedException($"{uri.Authority} is a private, loopback or link-local address and not a configured server.");
    }

    // A connection through a proxy goes to the proxy the user set up; the
    // target's own address is then the proxy's to resolve.
    private static async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, NetworkServers servers, CancellationToken ct)
    {
        var host = context.DnsEndPoint.Host;
        bool proxied = context.InitialRequestMessage.RequestUri is { } target && !string.Equals(target.IdnHost, host, StringComparison.OrdinalIgnoreCase);
        var addresses = IPAddress.TryParse(host, out var literal) ? [literal] : await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
        var allowed = proxied || MayBePrivate(servers, host) ? addresses : addresses.Where(IsPublic).ToArray();
        if (allowed.Length == 0)
            throw new NetworkRefusedException($"{host} resolves only to private, loopback or link-local addresses ({string.Join(", ", addresses.Select(a => a.ToString()))}) and is not a configured server.");
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(allowed, context.DnsEndPoint.Port, ct).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private static bool IsRedirect(HttpStatusCode code) => code is HttpStatusCode.MovedPermanently or HttpStatusCode.Found or HttpStatusCode.SeeOther
        or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect;

    // Redirects are followed here so each hop is checked; the next request
    // drops Authorization, which an inner handler adds back for its own hosts.
    private sealed class PolicyHandler(HttpMessageHandler inner, bool ownsInner, NetworkServers servers, bool offline, string? httpServers) : HttpMessageHandler
    {
        private readonly HttpMessageInvoker _inner = new(inner, ownsInner);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Check(request.RequestUri!, servers, offline, httpServers, null);
            var response = await _inner.SendAsync(request, ct).ConfigureAwait(false);
            for (int hop = 1; hop <= MaxRedirects && IsRedirect(response.StatusCode) && response.Headers.Location is { } location; hop++)
            {
                var next = new HttpRequestMessage(HttpMethod.Get, location.IsAbsoluteUri ? location : new Uri(request.RequestUri!, location));
                Check(next.RequestUri!, servers, offline, httpServers, request.RequestUri);
                foreach (var header in request.Headers.Where(h => h.Key != "Authorization")) next.Headers.TryAddWithoutValidation(header.Key, header.Value);
                response.Dispose();
                request = next;
                response = await _inner.SendAsync(request, ct).ConfigureAwait(false);
            }
            return response;
        }

        protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken ct) => SendAsync(request, ct).GetAwaiter().GetResult();

        protected override void Dispose(bool disposing)
        {
            if (disposing) _inner.Dispose();
            base.Dispose(disposing);
        }
    }

    private sealed class LoopbackHandler() : DelegatingHandler(new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = false })
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var uri = request.RequestUri!;
            bool loopback = IPAddress.TryParse(uri.IdnHost, out var a) ? IPAddress.IsLoopback(a) : uri.IdnHost == "localhost";
            if (!loopback || uri.Scheme is not ("http" or "https")) throw new NetworkRefusedException($"{uri} is not an endpoint on this machine.");
            return base.SendAsync(request, ct);
        }
    }
}
