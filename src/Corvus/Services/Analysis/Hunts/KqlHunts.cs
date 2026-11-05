using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Corvus.Services.Analysis.Hunts;

/// <summary>A recovered fact: its <see cref="HuntKind"/>, value and <see cref="IndicatorEvidence"/> class.</summary>
public sealed record HuntFact(string Kind, string Value, string Evidence);

/// <summary>An advanced hunting query with the table it reads, the facts it came from and their strongest evidence class.</summary>
public sealed record Hunt(string Id, string Title, string Table, string Kql, IReadOnlyList<string> Facts, string Evidence)
{
    /// <summary>The alert severity a rule built from the query carries: informational, low, medium or high.</summary>
    public string Severity { get; init; } = "informational";
}

/// <summary>The queries written for a fact list, and the notes naming each fact that got none.</summary>
public sealed record HuntSet(IReadOnlyList<Hunt> Hunts, IReadOnlyList<string> Notes);

/// <summary>The fact kinds <see cref="KqlHunts"/> writes queries for.</summary>
public static class HuntKind
{
    /// <summary>A file SHA-1, 40 hex digits.</summary>
    public const string Sha1 = "sha1";

    /// <summary>The signer name of a signed file.</summary>
    public const string Signer = "signer";

    /// <summary>The OriginalFilename of the version resource.</summary>
    public const string OriginalFileName = "original_file_name";

    /// <summary>A DLL name the image loads without a path.</summary>
    public const string DllName = "dll_name";

    /// <summary>A host name.</summary>
    public const string Domain = "domain";

    /// <summary>A URL.</summary>
    public const string Url = "url";

    /// <summary>An IPv4 address.</summary>
    public const string Ipv4 = "ipv4";

    /// <summary>An IPv6 address.</summary>
    public const string Ipv6 = "ipv6";

    /// <summary>A named pipe, with or without the \\.\pipe\ prefix.</summary>
    public const string NamedPipe = "named_pipe";

    /// <summary>A path of a file the program writes.</summary>
    public const string FilePath = "file_path";

    /// <summary>A mutex name; Defender XDR has no action type for it.</summary>
    public const string Mutex = "mutex";

    /// <summary>Every kind, in the order the queries are written.</summary>
    public static readonly IReadOnlyList<string> All =
        [Sha1, Signer, OriginalFileName, DllName, Domain, Url, Ipv4, Ipv6, NamedPipe, FilePath, Mutex];
}

/// <summary>Writes Defender XDR advanced hunting queries from a plain fact list; every query passes <see cref="KqlCheck"/> before it is returned.</summary>
public static class KqlHunts
{
    /// <summary>Queries written per kind; the rest are counted in a note.</summary>
    public const int MaxPerKind = 50;

    /// <summary>The longest fact value a query carries, in characters.</summary>
    public const int MaxValueChars = 1_000;

    private const string Base = "Timestamp, DeviceId, DeviceName, ReportId";

    /// <summary>A KQL single-quoted string literal of <paramref name="value"/>: quote and backslash escaped, control characters written as escapes.</summary>
    public static string Literal(string value)
    {
        var sb = new StringBuilder("'");
        for (int i = 0; i < value.Length; i++)
        {
            var c = value[i];
            if (char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
            {
                sb.Append(c).Append(value[++i]);
                continue;
            }
            if (char.IsSurrogate(c)) { sb.Append("\\ufffd"); continue; }
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '\'': sb.Append("\\'"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case < ' ' or '\u007f' or '\u2028' or '\u2029':
                    sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    break;
                default: sb.Append(c); break;
            }
        }
        return sb.Append('\'').ToString();
    }

    /// <summary>
    /// One query per fact and table. Network kinds need evidence of <see cref="IndicatorEvidence.Reference"/> or stronger.
    /// A fact with no query, and a query that fails the check, is named in the notes.
    /// </summary>
    public static HuntSet Write(IEnumerable<HuntFact> facts)
    {
        var notes = new List<string>();
        var merged = new Dictionary<(string Kind, string Value), string>();
        foreach (var f in facts)
        {
            if (string.IsNullOrWhiteSpace(f.Value)) continue;
            var clean = CleanText(f.Value).Trim();
            var key = (f.Kind, f.Kind == HuntKind.Sha1 ? clean.ToLowerInvariant() : clean);
            merged[key] = merged.TryGetValue(key, out var seen) ? IndicatorEvidence.Stronger(seen, f.Evidence) : f.Evidence;
        }
        var ordered = merged.OrderBy(m => HuntKind.All.ToList().IndexOf(m.Key.Kind)).ThenBy(m => m.Key.Value, StringComparer.Ordinal).ToList();
        string? sha1 = ordered.FirstOrDefault(m => m.Key.Kind == HuntKind.Sha1 && IsSha1(m.Key.Value)).Key.Value;
        var hunts = new List<Hunt>();
        foreach (var group in ordered.GroupBy(m => m.Key.Kind))
        {
            if (!HuntKind.All.Contains(group.Key)) { notes.Add($"{group.Count()} '{group.Key}' fact(s) have no query: the kind is not supported."); continue; }
            if (group.Key == HuntKind.Mutex)
            {
                notes.Add($"{group.Count()} mutex name(s) have no query: Defender XDR documents no mutex action type.");
                continue;
            }
            int skippedWeak = 0, written = 0, over = 0, tooLong = 0, unqueried = 0, local = 0;
            foreach (var ((kind, value), evidence) in group)
            {
                if (value.Length > MaxValueChars) { tooLong++; continue; }
                if (IsNetwork(kind) && Rank(evidence) < Rank(IndicatorEvidence.Reference)) { skippedWeak++; continue; }
                if (written >= MaxPerKind) { over++; continue; }
                if (IsNetwork(kind) && !Routable(kind, value)) { local++; continue; }
                var made = Queries(kind, value, evidence, sha1, ref unqueried);
                foreach (var h in made)
                {
                    var problems = KqlCheck.Diagnostics(h.Kql);
                    if (problems.Count > 0) notes.Add($"Query {h.Id} was dropped: {problems[0]}");
                    else hunts.Add(h);
                }
                if (made.Count > 0) written++;
            }
            if (tooLong > 0) notes.Add($"{tooLong} {group.Key} fact(s) over {MaxValueChars:N0} characters have no query.");
            if (unqueried > 0) notes.Add($"{unqueried} {group.Key} fact(s) have no query: {UnqueriedReason(group.Key)}.");
            if (local > 0) notes.Add($"{local} {group.Key} fact(s) name a loopback, unspecified, private or link-local address and have no network query.");
            if (group.Key == HuntKind.NamedPipe && written > 0)
                notes.Add("Named pipe queries read ActionType NamedPipeEvent and AdditionalFields.PipeName; no Learn page lists them, so no result does not show the pipe is absent.");
            if (skippedWeak > 0)
                notes.Add($"{skippedWeak} {group.Key} fact(s) found only as strings have no network query; view=indicators lists them with their evidence.");
            if (over > 0) notes.Add($"{over} {group.Key} fact(s) past the first {MaxPerKind} have no query.");
        }
        return new HuntSet(hunts, notes);
    }

    private static string UnqueriedReason(string kind) => kind switch
    {
        HuntKind.Sha1 => "the value is not 40 hex digits",
        HuntKind.DllName => "they need the SHA-1 of the loading file",
        HuntKind.Ipv4 or HuntKind.Ipv6 => "the value is not an address",
        HuntKind.NamedPipe => "the pipe name is empty",
        HuntKind.FilePath => "the path names no file",
        _ => "no query applies",
    };

    private static bool Routable(string kind, string value) =>
        kind is not (HuntKind.Ipv4 or HuntKind.Ipv6) || !IPAddress.TryParse(value, out var ip) || IsRoutable(ip);

    // Loopback, unspecified, private and link-local addresses match local traffic of every device.
    private static bool IsRoutable(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return false;
        if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast) return false;
        var b = ip.GetAddressBytes();
        if (b.Length == 4)
            return !(b[0] is 10 or 0 || b[0] == 172 && b[1] is >= 16 and <= 31 || b[0] == 192 && b[1] == 168
                || b[0] == 169 && b[1] == 254 || b[0] == 100 && b[1] is >= 64 and <= 127);
        return (b[0] & 0xFE) != 0xFC;
    }

    private static int Rank(string evidence) => Math.Max(0, Array.IndexOf(IndicatorEvidence.Classes, evidence));

    private static bool IsNetwork(string kind) => kind is HuntKind.Domain or HuntKind.Url or HuntKind.Ipv4 or HuntKind.Ipv6;

    private static bool IsSha1(string value) => value.Length == 40 && value.All(char.IsAsciiHexDigit);

    private static string Id(string kind, string value, string suffix)
    {
        var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(kind + "\0" + value)))[..8];
        return $"{kind.Replace('_', '-')}-{hash}{suffix}";
    }

    // Unpaired surrogates become U+FFFD so the JSON writer accepts the text.
    private static string CleanText(string value)
    {
        StringBuilder? sb = null;
        for (int i = 0; i < value.Length; i++)
        {
            var c = value[i];
            bool pair = char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]);
            if (pair) { sb?.Append(c).Append(value[i + 1]); i++; continue; }
            if (char.IsSurrogate(c)) { sb ??= new StringBuilder(value[..i]); sb.Append('\ufffd'); continue; }
            sb?.Append(c);
        }
        return sb?.ToString() ?? value;
    }

    // A value in a title is cut and stripped of control characters.
    private static string Short(string value)
    {
        var clean = new string([.. CleanText(value).Select(c => char.IsControl(c) ? ' ' : c)]);
        return clean.Length > 60 ? clean[..57] + "..." : clean;
    }

    private static Hunt Make(string kind, string value, string evidence, string suffix, string title, string table, string severity, params string[] lines) =>
        new(Id(kind, value, suffix), title, table, string.Join('\n', lines), [$"{kind}:{value}"], evidence) { Severity = severity };

    private static List<Hunt> Queries(string kind, string value, string evidence, string? sha1, ref int unqueried)
    {
        switch (kind)
        {
            case HuntKind.Sha1:
                if (!IsSha1(value)) { unqueried++; return []; }
                var hash = Literal(value);
                return
                [
                    Make(kind, value, evidence, "-files", $"Files with SHA-1 {Short(value)}", "DeviceFileEvents", "medium",
                        "DeviceFileEvents", $"| where SHA1 == {hash}",
                        $"| project {Base}, ActionType, FileName, FolderPath, SHA1, InitiatingProcessFileName"),
                    Make(kind, value, evidence, "-processes", $"Processes started from SHA-1 {Short(value)}", "DeviceProcessEvents", "medium",
                        "DeviceProcessEvents", $"| where SHA1 == {hash}",
                        $"| project {Base}, FileName, FolderPath, ProcessCommandLine, SHA1, InitiatingProcessFileName"),
                    Make(kind, value, evidence, "-images", $"Image loads of SHA-1 {Short(value)}", "DeviceImageLoadEvents", "medium",
                        "DeviceImageLoadEvents", $"| where SHA1 == {hash}",
                        $"| project {Base}, FileName, FolderPath, SHA1, InitiatingProcessFileName"),
                ];
            case HuntKind.Signer:
                var name = SignerName(value);
                return
                [
                    Make(kind, value, evidence, "", $"Files signed by {Short(name)}", "DeviceFileCertificateInfo", "low",
                        "DeviceFileCertificateInfo", $"| where Signer has {Literal(name)}",
                        "| project Timestamp, DeviceId, DeviceName, ReportId, SHA1, Signer, Issuer, IsTrusted"),
                ];
            case HuntKind.OriginalFileName:
                return
                [
                    Make(kind, value, evidence, "", $"Copies of {Short(value)} under another name", "DeviceProcessEvents", "medium",
                        "DeviceProcessEvents",
                        $"| where ProcessVersionInfoOriginalFileName =~ {Literal(value)} and FileName !~ {Literal(value)}",
                        $"| project {Base}, FileName, FolderPath, ProcessVersionInfoOriginalFileName, SHA1"),
                ];
            case HuntKind.DllName:
                if (sha1 == null) { unqueried++; return []; }
                return
                [
                    Make(kind, value, evidence, "", $"{Short(value)} loaded from the folder of the file", "DeviceImageLoadEvents", "medium",
                        "DeviceImageLoadEvents", $"| where InitiatingProcessSHA1 == {Literal(sha1)}",
                        $"| where FileName =~ {Literal(value)}",
                        "| where isnotempty(InitiatingProcessFolderPath)",
                        "| extend LoaderDir = tolower(replace_string(InitiatingProcessFolderPath, InitiatingProcessFileName, ''))",
                        "| extend DllDir = tolower(replace_string(FolderPath, FileName, ''))",
                        "| where DllDir == LoaderDir",
                        $"| project {Base}, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessFolderPath"),
                ];
            case HuntKind.Domain:
                return [Network(kind, value, evidence, $"Connections to {Short(value)}", $"RemoteUrl has {Literal(value)}")];
            case HuntKind.Url:
                var host = Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.HostNameType == UriHostNameType.Dns ? uri.Host : null;
                var filter = $"RemoteUrl =~ {Literal(value)}" + (host != null ? $" or RemoteUrl =~ {Literal(host)}" : "");
                if (uri != null && uri.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6
                    && IPAddress.TryParse(uri.Host.Trim('[', ']'), out var urlIp) && IsRoutable(urlIp))
                    filter += $" or RemoteIP == {Literal(urlIp.ToString())}";
                return [Network(kind, value, evidence, $"Connections to {Short(value)}", filter)];
            case HuntKind.Ipv4 or HuntKind.Ipv6:
                if (!IPAddress.TryParse(value, out var ip)) { unqueried++; return []; }
                return [Network(kind, value, evidence, $"Connections to {ip}", $"RemoteIP == {Literal(ip.ToString())}")];
            case HuntKind.NamedPipe:
                var pipe = PipeName(value);
                if (pipe.Length == 0) { unqueried++; return []; }
                return
                [
                    Make(kind, value, evidence, "", $"Opens of named pipe {Short(pipe)}", "DeviceEvents", "low",
                        "DeviceEvents", "| where ActionType == 'NamedPipeEvent'",
                        "| extend PipeName = tostring(parse_json(AdditionalFields).PipeName)",
                        $"| where PipeName endswith {Literal("\\" + pipe)}",
                        $"| project {Base}, FileName, PipeName, InitiatingProcessFileName, SHA1 = InitiatingProcessSHA1"),
                ];
            case HuntKind.FilePath:
                var leaf = value[(value.LastIndexOfAny(['\\', '/']) + 1)..];
                if (leaf.Length == 0) { unqueried++; return []; }
                var folder = value[..Math.Max(0, value.Length - leaf.Length - 1)];
                var rooted = value.Length > 2 && (char.IsAsciiLetter(value[0]) && value[1] == ':' || value.StartsWith(@"\\", StringComparison.Ordinal));
                return
                [
                    Make(kind, value, evidence, "", $"Writes of {Short(leaf)}", "DeviceFileEvents", "low",
                        "DeviceFileEvents", rooted ? $"| where (FolderPath =~ {Literal(folder)} or FolderPath =~ {Literal(value)}) and FileName =~ {Literal(leaf)}" : $"| where FileName =~ {Literal(leaf)}",
                        $"| project {Base}, ActionType, FileName, FolderPath, SHA1, InitiatingProcessFileName"),
                ];
            default:
                return [];
        }
    }

    private static Hunt Network(string kind, string value, string evidence, string title, string filter) =>
        Make(kind, value, evidence, "", title, "DeviceNetworkEvents", "low",
            "DeviceNetworkEvents", $"| where {filter}",
            $"| project {Base}, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, SHA1 = InitiatingProcessSHA1");

    // The CN of a distinguished name, else the value.
    private static string SignerName(string value)
    {
        int at = value.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
        if (at < 0) return value;
        var rest = value[(at + 3)..];
        int comma = rest.IndexOf(',');
        return (comma < 0 ? rest : rest[..comma]).Trim().Trim('"');
    }

    private static string PipeName(string value)
    {
        var v = value.Trim();
        int at = v.IndexOf(@"pipe\", StringComparison.OrdinalIgnoreCase);
        return (at >= 0 ? v[(at + 5)..] : v).Trim('\\');
    }
}
