using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>An extracted value with up to 5 locations, up to 5 consuming APIs, and an optional detail (e.g. key size).</summary>
public sealed record ExtractedValue(string Type, string Value, int Count, IReadOnlyList<string> Locations, IReadOnlyList<string> PassedTo, string? Detail = null);

/// <summary>
/// Extracts typed values (network indicators, paths, registry keys, mutexes, user agents, crypto keys) from strings,
/// resource text and decoded embedded text. Mutexes, user agents and keys are recognized by the APIs that consume them.
/// </summary>
public static partial class Values
{
    public static readonly IReadOnlyList<string> Types =
        ["url", "domain", "ipv4", "ipv6", "email", "file_path", "named_pipe", "registry_key", "mutex", "user_agent", "crypto_key"];

    private const int MaxLocations = 5;

    // Texts run to 1 MB: NonBacktracking matches in linear time, so no match
    // timeout. Patterns that need lookarounds are generated regexes whose tails
    // fail only where no later match can start, or code.
    private static Regex R(string pattern) => new(pattern, RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    private static readonly Regex Url = R(@"\b(?:https?|ftps?|wss?|tcp|udp)://[^\s""'<>\\^`{|}]+");
    private static readonly Regex Email = R(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b");
    [GeneratedRegex(@"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])", RegexOptions.CultureInvariant)]
    private static partial Regex Ipv4();
    private static readonly Regex Ipv6Run = R(@"[0-9A-Fa-f:.]+");
    private static readonly Regex WordChar = R(@"\w");
    private static readonly Regex Hostname = R(@"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})$");
    // Paths also end at a quote, ';' or '`', which terminate command-line arguments.
    private static readonly Regex WindowsPath = R(@"(?:\b[A-Za-z]:\\|%[A-Za-z_][A-Za-z0-9_]*%\\)[^\r\n""'`;*?<>|]*[^\r\n""'`;*?<>|\s.,:)]");
    [GeneratedRegex(@"\\\\(?!\.\\pipe\\)[A-Za-z0-9._$-]+\\[^\r\n""'`;*?<>|]*[^\r\n""'`;*?<>|\s.,:)]", RegexOptions.CultureInvariant)]
    private static partial Regex UncPath();
    [GeneratedRegex(@"(?<![\w/])/(?:etc|tmp|var|usr|bin|sbin|home|dev|proc|opt|root|Library|Users|Applications|System)/[^\s""'<>|;]*[^\s""'<>|;.,)]", RegexOptions.CultureInvariant)]
    private static partial Regex UnixPath();
    private static readonly Regex Pipe = R(@"\\\\\.\\pipe\\[^\s""'<>|]+");
    [GeneratedRegex(@"\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU)(?:\\[^\r\n""]*[^\r\n""\s\\])?(?![\w])", RegexOptions.CultureInvariant)]
    private static partial Regex Registry();
    private static readonly Regex RelativeRegistry = R(@"^(?:SOFTWARE|Software|SYSTEM\\CurrentControlSet|System\\CurrentControlSet)\\[^\r\n""]+$");

    /// <summary>XML / schema namespace hosts, excluded from URLs and domains.</summary>
    private static readonly HashSet<string> NamespaceHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "schemas.microsoft.com", "www.w3.org", "w3.org", "schemas.xmlsoap.org", "schemas.openxmlformats.org", "purl.org",
        "ns.adobe.com", "json-schema.org", "docs.oasis-open.org", "www.xml.org", "xml.org", "tempuri.org", "schema.org",
    };

    /// <summary>TLDs accepted for bare domains; TLDs that double as file extensions are omitted.</summary>
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

    /// <param name="embedded">Decoded embedded content; its text items are scanned too.</param>
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

    private static IEnumerable<string> Matches(Regex regex, string text) => regex.Matches(text).Select(m => m.Value);

    /// <summary>
    /// IPv6 candidates: runs of hex digits, colons and dots outside a word, with two colons before any dot, ending
    /// before a non-word character or at the run's last dot.
    /// </summary>
    private static IEnumerable<string> Ipv6Candidates(string text)
    {
        // A scan of whole runs: one regex of three overlapping classes
        // backtracks cubically over a long run that ends inside a word.
        foreach (Match run in Ipv6Run.Matches(text))
        {
            int start = run.Index, end = run.Index + run.Length;
            if (text[start] == '.' || start > 0 && WordChar.IsMatch(text.AsSpan(start - 1, 1))) continue;
            int dot = run.Value.IndexOf('.');
            if (run.Value.AsSpan(0, dot < 0 ? run.Length : dot).Count(':') < 2) continue;
            if (end < text.Length && WordChar.IsMatch(text.AsSpan(end, 1)))
            {
                if (dot < 0) continue;
                end = start + run.Value.LastIndexOf('.');
            }
            yield return text[start..end];
        }
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
        // Bare domains: whole tokens only, lowercase, known TLD.
        foreach (var token in text.Split([' ', '\t', '\r', '\n', '"', '\'', ',', ';', '(', ')', '<', '>', '[', ']', '='], StringSplitOptions.RemoveEmptyEntries))
        {
            var t = token.TrimEnd('.', ':');
            if (t.Contains("://") || t.Contains('@')) continue;
            var host = t.Contains(':') && !t.Contains("::") ? t[..t.IndexOf(':')] : t;
            if (IsDomain(host, requireKnownTld: true)) b.Add("domain", host, where, passedTo);
        }
        foreach (Match m in Ipv4().Matches(text))
            if (IsPlausibleIpv4(m.Value) && !IsVersionContext(text, m.Index)
                && !text.Contains("Version=" + m.Value, StringComparison.OrdinalIgnoreCase)) // same number used as a version elsewhere
                b.Add("ipv4", m.Value, where, passedTo);
        foreach (var candidate in Ipv6Candidates(text))
            if (candidate.Count(c => c == ':') >= 2 && IPAddress.TryParse(candidate, out var v6) && v6.AddressFamily == AddressFamily.InterNetworkV6
                && candidate.Any(char.IsAsciiHexDigit))
                b.Add("ipv6", v6.ToString(), where, passedTo);
        foreach (var pipe in Matches(Pipe, text))
            b.Add("named_pipe", pipe, where, passedTo);
        foreach (var path in Matches(WindowsPath, text).Concat(Matches(UncPath(), text)).Concat(Matches(UnixPath(), text)))
            b.Add("file_path", path, where, passedTo);
        foreach (var key in Matches(Registry(), text))
            b.Add("registry_key", key, where, passedTo);
        if (RelativeRegistry.IsMatch(text.Trim()) || passedTo.Any(a => a.StartsWith("Microsoft.Win32.RegistryKey::", StringComparison.Ordinal) && a.Contains("SubKey")))
            if (text.Contains('\\') && text.Length < 512) b.Add("registry_key", text.Trim(), where, passedTo);
    }

    /// <summary>Mutex names, user agents, crypto keys and KDF passwords, recognized by consuming APIs.</summary>
    private static void FromContext(Builder b, ModuleScan.CodeString s, ModuleScan scan)
    {
        var value = s.Value;
        if (s.Consumers.Any(a => a.StartsWith("System.Threading.Mutex::", StringComparison.Ordinal) || a.Contains("::CreateMutex", StringComparison.Ordinal) || a.Contains("::OpenMutex", StringComparison.Ordinal)))
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
        var decoded = Embedded.TryHex(value, limits) is { } hex ? (Bytes: hex, Encoding: "hex") // hex first: hex is also valid base64
            : Embedded.TryBase64(value, limits) is { } b64 ? (Bytes: b64, Encoding: "base64")
            : s.Consumers.Any(a => a.EndsWith(".Encoding::GetBytes", StringComparison.Ordinal)) ? (Bytes: Encoding.UTF8.GetBytes(value), Encoding: "text")
            : (Bytes: (byte[]?)null, Encoding: "");
        if (decoded.Bytes is { Length: 8 or 16 or 24 or 32 or 64 } key)
            b.Add("crypto_key", value, s.Location, s.Consumers, $"{key.Length * 8}-bit key or IV ({decoded.Encoding})");
    }

    /// <summary>Static byte arrays of key / IV size used in a method that calls crypto APIs.</summary>
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

    /// <summary>True when preceded by "version", "ver" or "v" (e.g. "Version=4.0.3.0").</summary>
    private static bool IsVersionContext(string text, int index)
    {
        var before = text.AsSpan(Math.Max(0, index - 12), index - Math.Max(0, index - 12)).TrimEnd(" =:\t".AsSpan());
        return before.EndsWith("version", StringComparison.OrdinalIgnoreCase) || before.EndsWith("ver", StringComparison.OrdinalIgnoreCase)
               || (before.Length > 0 && (before[^1] is 'v' or 'V') && (before.Length == 1 || !char.IsLetterOrDigit(before[^2])));
    }

    /// <summary>Rejects "0.x.x.x" and version-like "N.x.0.0" with N below 10; private ranges are kept.</summary>
    private static bool IsPlausibleIpv4(string ip)
    {
        var o = ip.Split('.').Select(int.Parse).ToArray();
        if (o[0] == 0) return false;
        if (o[0] < 10 && o[2] == 0 && o[3] == 0) return false;
        return true;
    }

    public static string ToCsv(IEnumerable<ExtractedValue> values)
    {
        static string Q(string? s) => s == null ? "" : s.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
        var sb = new StringBuilder("type,value,count,detail,first_location,passed_to\n");
        foreach (var i in values)
            sb.Append(Q(i.Type)).Append(',').Append(Q(i.Value)).Append(',').Append(i.Count).Append(',').Append(Q(i.Detail)).Append(',')
              .Append(Q(i.Locations.FirstOrDefault())).Append(',').Append(Q(string.Join(" | ", i.PassedTo))).Append('\n');
        return sb.ToString();
    }
}
