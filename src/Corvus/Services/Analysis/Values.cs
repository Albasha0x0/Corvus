using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>An extracted value with up to 5 locations, up to 5 consuming APIs, and an optional detail (e.g. key size).</summary>
public sealed record ExtractedValue(string Type, string Value, int Count, IReadOnlyList<string> Locations, IReadOnlyList<string> PassedTo, string? Detail = null);

/// <summary>Extracts typed values (network indicators, paths, registry keys, mutexes, keys) from strings, resources and decoded text.</summary>
public static partial class Values
{
    public static readonly IReadOnlyList<string> Types =
        ["url", "domain", "ipv4", "ipv6", "email", "file_path", "named_pipe", "registry_key", "mutex", "user_agent", "crypto_key", "encoded"];

    /// <summary>Encoded rows kept per call of <see cref="Find"/> or <see cref="FromFields"/>; the rest are counted.</summary>
    public const int MaxEncoded = 100;

    // Shorter base64 runs are mostly identifiers and resource names.
    private const int MinEncodedChars = 24;
    // An encoded row shows this much of a longer value; its detail keeps the whole length.
    private const int MaxEncodedShown = 256;

    private const int MaxLocations = 5, MaxPassedTo = 5;

    // NonBacktracking matches 1 MB texts in linear time, so no match timeout; lookaround patterns are bounded generated regexes.
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
            foreach (var api in passedTo ?? []) if (item.PassedTo.Count < MaxPassedTo) item.PassedTo.Add(api);
            Items[key] = (item.Count, item.Locations, item.PassedTo, item.Detail ?? detail);
        }
    }

    /// <summary>The typed values of the other overload, without the count of encoded values past the cap.</summary>
    public static List<ExtractedValue> Find(ModuleScan scan, IReadOnlyList<EmbeddedContent> embedded, CancellationToken ct) => Find(scan, embedded, out _, ct);

    /// <summary>Typed values of an assembly, with whole base64 or hex literals as encoded rows; <paramref name="encodedDropped"/> counts those past the cap.</summary>
    /// <param name="embedded">Decoded embedded content; its text items are scanned too.</param>
    public static List<ExtractedValue> Find(ModuleScan scan, IReadOnlyList<EmbeddedContent> embedded, out int encodedDropped, CancellationToken ct)
    {
        var b = new Builder();
        var limits = AnalysisLimits.Default;
        var encoded = new HashSet<string>(StringComparer.Ordinal);
        encodedDropped = 0;
        foreach (var s in scan.Strings)
        {
            ct.ThrowIfCancellationRequested();
            FromText(b, s.Value, s.Location, s.Consumers);
            FromContext(b, s, scan);
            // Embedded content already decodes literals, so the decoded text is not scanned again here.
            AddEncoded(b, encoded, s.Value, s.Location, s.Consumers, ref encodedDropped, limits);
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

        return Order(b.Items.Select(kv => new ExtractedValue(kv.Key.Type, kv.Key.Value, kv.Value.Count, kv.Value.Locations, [.. kv.Value.PassedTo], kv.Value.Detail)));
    }

    /// <summary>Typed values of asset field texts, encoded values decoded and scanned once; nothing is decrypted; empty for no values.</summary>
    public static List<ExtractedValue> FromFields(IEnumerable<(string Text, string Location)> fields, out int encodedDropped, CancellationToken ct)
    {
        var b = new Builder();
        var limits = AnalysisLimits.Default;
        var encoded = new HashSet<string>(StringComparer.Ordinal);
        encodedDropped = 0;
        foreach (var (text, location) in fields)
        {
            ct.ThrowIfCancellationRequested();
            var where = new Location(location);
            FromText(b, text, where, []);
            // Asset GUIDs (32 hex digits) name other assets; a field named for one holds no encoded value.
            if (location.AsSpan(location.LastIndexOf('.') + 1).Contains("guid", StringComparison.OrdinalIgnoreCase)) continue;
            if (AddEncoded(b, encoded, text, where, null, ref encodedDropped, limits) is { } e && Blob.LooksLikeText(e.Bytes))
                FromText(b, Encoding.UTF8.GetString(e.Bytes), new Location($"{location} (decoded: {e.Encoding})"), []);
        }
        return Order(b.Items.Select(kv => new ExtractedValue(kv.Key.Type, kv.Key.Value, kv.Value.Count, kv.Value.Locations, [.. kv.Value.PassedTo], kv.Value.Detail)));
    }

    /// <summary>Adds a whole hex or base64 value as an encoded row under the cap, else counts it; returns the decoding added, or null.</summary>
    private static (string Encoding, byte[] Bytes)? AddEncoded(Builder b, HashSet<string> seen, string text, Location where, IReadOnlyList<string>? passedTo,
        ref int dropped, AnalysisLimits limits)
    {
        if (Encoded(text.Trim(), limits) is not { } e) return null;
        var shown = e.Text.Length <= MaxEncodedShown ? e.Text : e.Text[..MaxEncodedShown] + "...";
        if (!seen.Contains(shown) && seen.Count >= MaxEncoded)
        {
            dropped++;
            return null;
        }
        seen.Add(shown);
        b.Add("encoded", shown, where, passedTo, $"{e.Encoding}, {e.Bytes.Length:N0} bytes" + (e.Text.Length > MaxEncodedShown ? $", {e.Text.Length:N0} characters" : ""));
        return (e.Encoding, e.Bytes);
    }

    /// <summary>The encoding and bytes of a whole hex value of 32 digits or more, or base64 of 24 characters or more; null for any other text.</summary>
    private static (string Text, string Encoding, byte[] Bytes)? Encoded(string text, AnalysisLimits limits)
    {
        if (text.Length < MinEncodedChars) return null;
        // Hex first: hex is also valid base64.
        if (text.All(char.IsAsciiHexDigit)) return Embedded.TryHex(text, limits) is { } hex ? (text, "hex", hex) : null;
        if (text.Length % 4 != 0 || !text.All(c => char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '=')) return null;
        if (!text.EndsWith('=') && !(text.Any(char.IsAsciiDigit) && text.Any(char.IsAsciiLetterUpper) && text.Any(char.IsAsciiLetterLower))) return null;
        return Embedded.TryBase64(text, limits) is { } bytes ? (text, "base64", bytes) : null;
    }

    /// <summary>The values of several assemblies merged by type and value, locations prefixed with the assembly path; empty for no values.</summary>
    public static List<ExtractedValue> Join(IEnumerable<(string Assembly, IReadOnlyList<ExtractedValue> Values)> parts)
    {
        var rows = new Dictionary<(string Type, string Value), ExtractedValue>();
        foreach (var (assembly, values) in parts)
            foreach (var v in values)
            {
                var located = v.Locations.Select(l => $"{assembly}: {l}");
                rows[(v.Type, v.Value)] = rows.TryGetValue((v.Type, v.Value), out var seen)
                    ? seen with
                    {
                        Count = seen.Count + v.Count,
                        Locations = [.. seen.Locations.Concat(located).Take(MaxLocations)],
                        PassedTo = [.. seen.PassedTo.Union(v.PassedTo, StringComparer.Ordinal).Take(MaxPassedTo)],
                        Detail = seen.Detail ?? v.Detail,
                    }
                    : v with { Locations = [.. located] };
            }
        return Order(rows.Values);
    }

    private static List<ExtractedValue> Order(IEnumerable<ExtractedValue> values) =>
        [.. values.OrderBy(i => Array.IndexOf([.. Types], i.Type)).ThenByDescending(i => i.Count).ThenBy(i => i.Value, StringComparer.Ordinal)];

    private static IEnumerable<string> Matches(Regex regex, string text) => regex.Matches(text).Select(m => m.Value);

    /// <summary>IPv6 candidates: runs of hex digits, colons and dots outside a word with two colons before any dot.</summary>
    private static IEnumerable<string> Ipv6Candidates(string text)
    {
        // Scans whole runs: one regex of three overlapping classes backtracks cubically on a run ending inside a word.
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
        // A number also used as Version= elsewhere in the text is a version.
        foreach (Match m in Ipv4().Matches(text))
            if (IsPlausibleIpv4(m.Value) && !IsVersionContext(text, m.Index)
                && !text.Contains("Version=" + m.Value, StringComparison.OrdinalIgnoreCase))
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
        // Hex first: hex is also valid base64.
        var decoded = Embedded.TryHex(value, limits) is { } hex ? (Bytes: hex, Encoding: "hex")
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
