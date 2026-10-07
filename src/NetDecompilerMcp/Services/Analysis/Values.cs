using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services.Analysis;

/// <summary>One extracted value: its type, the value, the number of occurrences, up to 5 locations, up to 5 APIs it is passed to, and an optional detail (e.g. key size).</summary>
public sealed record ExtractedValue(string Type, string Value, int Count, IReadOnlyList<string> Locations, IReadOnlyList<string> PassedTo, string? Detail = null);

/// <summary>
/// Extracts typed values from string literals, string constants, resource text (up to 4 MB) and the text items found by
/// <see cref="Embedded"/> (decoded base64 / hex / compressed text): URLs, domains, IPv4 / IPv6 addresses, email
/// addresses, file paths, named pipes, registry keys, mutex names, user agents and crypto keys. Mutex names, user agents
/// and crypto keys are recognized by the APIs a string is passed to and the APIs of the method containing it. Excluded:
/// URLs and domains whose host is an XML / schema namespace host, IPv4-like version numbers (first octet 0, or first
/// octet below 10 with the last two 0), and bare domains whose last label is not in a fixed TLD list (TLDs that are
/// also file extensions are not in it). Each text is scanned up to 1 MB; values over 2,048 characters are dropped;
/// regexes time out after 1 s.
/// </summary>
public static class Values
{
    public static readonly IReadOnlyList<string> Types =
        ["url", "domain", "ipv4", "ipv6", "email", "file_path", "named_pipe", "registry_key", "mutex", "user_agent", "crypto_key"];

    private const int MaxLocations = 5;
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1);

    private static Regex R(string pattern) => new(pattern, RegexOptions.CultureInvariant | RegexOptions.Compiled, RegexTimeout);

    private static readonly Regex Url = R(@"\b(?:https?|ftps?|wss?|tcp|udp)://[^\s""'<>\\^`{|}]+");
    private static readonly Regex Email = R(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b");
    private static readonly Regex Ipv4 = R(@"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])");
    private static readonly Regex Ipv6Candidate = R(@"(?<![\w:.])[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*(?![\w:])");
    private static readonly Regex Hostname = R(@"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})$");
    // a path ends at a quote, ';' or '`' too: in a command line those close the argument ("'C:\x\a.exe' -Arg ...; ...")
    private static readonly Regex WindowsPath = R(@"(?:\b[A-Za-z]:\\|%[A-Za-z_][A-Za-z0-9_]*%\\)[^\r\n""'`;*?<>|]*[^\r\n""'`;*?<>|\s.,:)]");
    private static readonly Regex UncPath = R(@"\\\\(?!\.\\pipe\\)[A-Za-z0-9._$-]+\\[^\r\n""'`;*?<>|]*[^\r\n""'`;*?<>|\s.,:)]");
    private static readonly Regex UnixPath = R(@"(?<![\w/])/(?:etc|tmp|var|usr|bin|sbin|home|dev|proc|opt|root|Library|Users|Applications|System)/[^\s""'<>|;]*[^\s""'<>|;.,)]");
    private static readonly Regex Pipe = R(@"\\\\\.\\pipe\\[^\s""'<>|]+");
    private static readonly Regex Registry = R(@"\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU)(?:\\[^\r\n""]*[^\r\n""\s\\])?(?![\w])");
    private static readonly Regex RelativeRegistry = R(@"^(?:SOFTWARE|Software|SYSTEM\\CurrentControlSet|System\\CurrentControlSet)\\[^\r\n""]+$");

    /// <summary>Hosts of XML / schema namespace URIs: URLs with these hosts, and these hosts as domains, are excluded.</summary>
    private static readonly HashSet<string> NamespaceHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "schemas.microsoft.com", "www.w3.org", "w3.org", "schemas.xmlsoap.org", "schemas.openxmlformats.org", "purl.org",
        "ns.adobe.com", "json-schema.org", "docs.oasis-open.org", "www.xml.org", "xml.org", "tempuri.org", "schema.org",
    };

    /// <summary>Top-level domains accepted for bare domain names (TLDs that are also file extensions are left out).</summary>
    private static readonly HashSet<string> Tlds = new(StringComparer.Ordinal)
    {
        "com", "net", "org", "info", "biz", "io", "co", "me", "tv", "cc", "us", "uk", "de", "ru", "cn", "jp", "fr", "it", "nl", "es",
        "br", "in", "au", "ca", "ch", "se", "no", "fi", "dk", "be", "at", "cz", "sk", "hu", "ro", "bg", "gr", "pt", "ie", "kr", "tw",
        "hk", "sg", "my", "id", "th", "vn", "ph", "tr", "ua", "by", "kz", "ir", "il", "sa", "ae", "eg", "za", "ng", "ke", "ar", "mx",
        "cl", "pe", "ve", "eu", "xyz", "top", "online", "site", "club", "live", "shop", "store", "tech", "cloud", "space", "fun",
        "icu", "pw", "su", "ws", "to", "ly", "gg", "link", "click", "download", "stream", "win", "bid", "loan", "work", "email",
        "onion", "today", "world", "one", "life", "page", "host", "website", "trade", "cyber", "gov", "edu", "mil", "int",
    };

    private static readonly string[] CryptoApis =
    [
        "::set_Key", "::set_IV", "::CreateDecryptor", "::CreateEncryptor", "System.Security.Cryptography.Rfc2898DeriveBytes::",
        "System.Security.Cryptography.PasswordDeriveBytes::", "System.Security.Cryptography.HMAC", "System.Security.Cryptography.AesGcm::.ctor",
        "System.Security.Cryptography.AesCcm::.ctor", "System.Security.Cryptography.ChaCha20Poly1305::.ctor", "::DecryptCbc", "::EncryptCbc",
        "::DecryptEcb", "::EncryptEcb",
    ];

    private static bool IsCryptoApi(string api) => CryptoApis.Any(c => api.Contains(c, StringComparison.Ordinal));

    private sealed class Builder
    {
        public readonly Dictionary<(string Type, string Value), (int Count, List<string> Locations, HashSet<string> PassedTo, string? Detail)> Items = [];

        public void Add(string type, string value, Location where, IEnumerable<string>? passedTo = null, string? detail = null)
        {
            value = value.Trim();
            if (value.Length == 0 || value.Length > 2048) return;
            var key = (type, value);
            if (!Items.TryGetValue(key, out var item)) item = (0, [], new HashSet<string>(StringComparer.Ordinal), detail);
            item.Count++;
            if (item.Locations.Count < MaxLocations && !item.Locations.Contains(where.Where)) item.Locations.Add(where.Where);
            foreach (var api in passedTo ?? []) if (item.PassedTo.Count < 5) item.PassedTo.Add(api);
            Items[key] = (item.Count, item.Locations, item.PassedTo, item.Detail ?? detail);
        }
    }

    /// <summary>Values in a scanned module and in the text items of <paramref name="embedded"/> decoded from it.</summary>
    public static List<ExtractedValue> Find(ModuleScan scan, IReadOnlyList<EmbeddedContent> embedded, CancellationToken ct)
    {
        var b = new Builder();
        foreach (var s in scan.Strings)
        {
            ct.ThrowIfCancellationRequested();
            FromText(b, s.Value, s.Location, s.Consumers);
            FromContext(b, s, scan);
        }
        foreach (var r in scan.Resources)
        {
            ct.ThrowIfCancellationRequested();
            var text = r.Text ?? (r.Bytes is { Length: > 0 and <= 4 * 1024 * 1024 } bytes && Blob.LooksLikeText(bytes) ? Encoding.UTF8.GetString(bytes) : null);
            if (text != null) FromText(b, text, new Location($"resource '{r.Name}'"), []);
        }
        foreach (var p in embedded.Where(p => p.Kind == "text"))
            FromText(b, Encoding.UTF8.GetString(p.Bytes), new Location($"{p.Source} (decoded: {string.Join(" > ", p.Encoding)})"), []);
        CryptoArrays(b, scan);

        return [.. b.Items.Select(kv => new ExtractedValue(kv.Key.Type, kv.Key.Value, kv.Value.Count, kv.Value.Locations, [.. kv.Value.PassedTo], kv.Value.Detail))
            .OrderBy(i => Array.IndexOf([.. Types], i.Type)).ThenByDescending(i => i.Count).ThenBy(i => i.Value, StringComparer.Ordinal)];
    }

    private static IEnumerable<string> Matches(Regex regex, string text)
    {
        MatchCollection matches;
        try { matches = regex.Matches(text); _ = matches.Count; }
        catch (RegexMatchTimeoutException) { yield break; }
        foreach (Match m in matches) yield return m.Value;
    }

    private static void FromText(Builder b, string text, Location where, IReadOnlyList<string> passedTo)
    {
        if (text.Length > 1024 * 1024) text = text[..(1024 * 1024)];
        var hosts = new List<string>();
        foreach (var url in Matches(Url, text))
        {
            var clean = url.TrimEnd('.', ',', ';', ')', ']', '\'');
            if (!Uri.TryCreate(clean, UriKind.Absolute, out var uri) || NamespaceHosts.Contains(uri.Host)) continue;
            b.Add("url", clean, where, passedTo);
            hosts.Add(uri.Host);
        }
        foreach (var email in Matches(Email, text))
        {
            b.Add("email", email, where, passedTo);
            hosts.Add(email[(email.IndexOf('@') + 1)..]);
        }
        foreach (var host in hosts)
        {
            if (IPAddress.TryParse(host.Trim('[', ']'), out var ip)) b.Add(ip.AddressFamily == AddressFamily.InterNetworkV6 ? "ipv6" : "ipv4", ip.ToString(), where, passedTo);
            else if (IsDomain(host.ToLowerInvariant(), requireKnownTld: false)) b.Add("domain", host.ToLowerInvariant(), where, passedTo);
        }
        // bare domains: whole whitespace-separated tokens only, all lowercase, known TLD
        foreach (var token in text.Split([' ', '\t', '\r', '\n', '"', '\'', ',', ';', '(', ')', '<', '>', '[', ']', '='], StringSplitOptions.RemoveEmptyEntries))
        {
            var t = token.TrimEnd('.', ':');
            if (t.Contains("://") || t.Contains('@')) continue;
            var host = t.Contains(':') && !t.Contains("::") ? t[..t.IndexOf(':')] : t;
            if (IsDomain(host, requireKnownTld: true)) b.Add("domain", host, where, passedTo);
        }
        foreach (var m in MatchesAt(Ipv4, text))
            if (IsPlausibleIpv4(m.Value) && !IsVersionContext(text, m.Index)
                && !text.Contains("Version=" + m.Value, StringComparison.OrdinalIgnoreCase)) // the same number given as a version elsewhere in the text
                b.Add("ipv4", m.Value, where, passedTo);
        foreach (var candidate in Matches(Ipv6Candidate, text))
            if (candidate.Count(c => c == ':') >= 2 && IPAddress.TryParse(candidate, out var v6) && v6.AddressFamily == AddressFamily.InterNetworkV6
                && candidate.Any(char.IsAsciiHexDigit))
                b.Add("ipv6", v6.ToString(), where, passedTo);
        foreach (var pipe in Matches(Pipe, text))
            b.Add("named_pipe", pipe, where, passedTo);
        foreach (var path in Matches(WindowsPath, text).Concat(Matches(UncPath, text)).Concat(Matches(UnixPath, text)))
            b.Add("file_path", path, where, passedTo);
        foreach (var key in Matches(Registry, text))
            b.Add("registry_key", key, where, passedTo);
        if (RelativeRegistry.IsMatch(text.Trim()) || passedTo.Any(a => a.StartsWith("Microsoft.Win32.RegistryKey::", StringComparison.Ordinal) && a.Contains("SubKey")))
            if (text.Contains('\\') && text.Length < 512) b.Add("registry_key", text.Trim(), where, passedTo);
    }

    /// <summary>Types recognized by where the string goes: mutex names, user agents, crypto keys and key-derivation passwords.</summary>
    private static void FromContext(Builder b, ModuleScan.CodeString s, ModuleScan scan)
    {
        var value = s.Value;
        if (s.Consumers.Any(a => a.StartsWith("System.Threading.Mutex::", StringComparison.Ordinal) || Regex.IsMatch(a, @"::(?:Create|Open)Mutex", RegexOptions.None, RegexTimeout)))
            b.Add("mutex", value, s.Location, s.Consumers);
        if (value.StartsWith("Mozilla/", StringComparison.Ordinal)
            || value.Length is >= 4 and < 512 && s.Consumers.Any(a => a.EndsWith("::set_UserAgent", StringComparison.Ordinal)
                || a.Contains("ProductInfoHeaderValue::", StringComparison.Ordinal) || a.EndsWith("HttpHeaderValueCollection`1::ParseAdd", StringComparison.Ordinal)
                || a.EndsWith("HttpHeaderValueCollection`1::TryParseAdd", StringComparison.Ordinal)))
            b.Add("user_agent", value, s.Location, s.Consumers);

        bool cryptoHere = s.Method != null && scan.ApisByMethod.TryGetValue(s.Method, out var apis) && apis.Any(IsCryptoApi);
        if (!cryptoHere && !s.Consumers.Any(IsCryptoApi)) return;
        if (s.Consumers.Any(a => a.Contains("DeriveBytes::", StringComparison.Ordinal)))
        {
            b.Add("crypto_key", value, s.Location, s.Consumers, "password for key derivation");
            return;
        }
        var limits = AnalysisLimits.Default;
        var decoded = Embedded.TryHex(value, limits) is { } hex ? (Bytes: hex, Encoding: "hex") // hex first: it is also valid base64
            : Embedded.TryBase64(value, limits) is { } b64 ? (Bytes: b64, Encoding: "base64")
            : s.Consumers.Any(a => a.EndsWith(".Encoding::GetBytes", StringComparison.Ordinal)) ? (Bytes: Encoding.UTF8.GetBytes(value), Encoding: "text")
            : (Bytes: (byte[]?)null, Encoding: "");
        if (decoded.Bytes is { Length: 8 or 16 or 24 or 32 or 64 } key)
            b.Add("crypto_key", value, s.Location, s.Consumers, $"{key.Length * 8}-bit key or IV ({decoded.Encoding})");
    }

    /// <summary>Static byte arrays of key / IV size used in a method that does symmetric crypto.</summary>
    private static void CryptoArrays(Builder b, ModuleScan scan)
    {
        foreach (var d in scan.Data)
        {
            if (d.Data.Length is not (8 or 16 or 24 or 32 or 64)) continue;
            var user = d.UsedIn.FirstOrDefault(m => scan.ApisByMethod.TryGetValue(m, out var apis) && apis.Any(IsCryptoApi));
            if (user != null)
                b.Add("crypto_key", Convert.ToHexStringLower(d.Data), new Location($"static data {Format.MemberLabel(d.Field)} used in {Format.MemberLabel(user)}"),
                    null, $"{d.Data.Length * 8}-bit key or IV (byte array)");
        }
    }

    private static bool IsDomain(string host, bool requireKnownTld)
    {
        if (host.Length is < 4 or > 253 || NamespaceHosts.Contains(host)) return false;
        var m = Hostname.Match(host);
        if (!m.Success) return false;
        if (host.Split('.').All(p => p.All(char.IsAsciiDigit) || p.Length == 0)) return false;
        return !requireKnownTld || Tlds.Contains(m.Groups[1].Value);
    }

    /// <summary>Drops assembly-version-like values ("4.0.0.0") and "0.x.x.x"; keeps everything else, private ranges included.</summary>
    /// <summary>"Version=4.0.3.0", "version 1.2.3.4", "v2.0.0.1": a version number written like an address.</summary>
    private static bool IsVersionContext(string text, int index)
    {
        var before = text.AsSpan(Math.Max(0, index - 12), index - Math.Max(0, index - 12)).TrimEnd(" =:\t".AsSpan());
        return before.EndsWith("version", StringComparison.OrdinalIgnoreCase) || before.EndsWith("ver", StringComparison.OrdinalIgnoreCase)
               || (before.Length > 0 && (before[^1] is 'v' or 'V') && (before.Length == 1 || !char.IsLetterOrDigit(before[^2])));
    }

    private static IEnumerable<Match> MatchesAt(Regex regex, string text)
    {
        MatchCollection matches;
        try { matches = regex.Matches(text); _ = matches.Count; }
        catch (RegexMatchTimeoutException) { yield break; }
        foreach (Match m in matches) yield return m;
    }

    private static bool IsPlausibleIpv4(string ip)
    {
        var o = ip.Split('.').Select(int.Parse).ToArray();
        if (o[0] == 0) return false;
        if (o[0] < 10 && o[2] == 0 && o[3] == 0) return false;
        return true;
    }

    // ------------------------------------------------------------------ export

    public static string ToCsv(IEnumerable<ExtractedValue> values)
    {
        static string Q(string? s) => s == null ? "" : s.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
        var sb = new StringBuilder("type,value,count,detail,first_location,passed_to\n");
        foreach (var i in values)
            sb.Append(Q(i.Type)).Append(',').Append(Q(i.Value)).Append(',').Append(i.Count).Append(',').Append(Q(i.Detail)).Append(',')
              .Append(Q(i.Locations.FirstOrDefault())).Append(',').Append(Q(string.Join(" | ", i.PassedTo))).Append('\n');
        return sb.ToString();
    }

    public static string ToJson(IEnumerable<ExtractedValue> values) =>
        JsonSerializer.Serialize(values, new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
}
