using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace Corvus.Services.Analysis.Hunts;

/// <summary>A recovered fact: its <see cref="HuntKind"/>, value and <see cref="IndicatorEvidence"/> class.</summary>
public sealed record HuntFact(string Kind, string Value, string Evidence);

/// <summary>An advanced hunting query with the table it reads, the facts it came from and their strongest evidence class.</summary>
public sealed record Hunt(string Id, string Title, string Table, string Kql, IReadOnlyList<string> Facts, string Evidence)
{
    /// <summary>The alert severity a rule built from the query carries: informational, low, medium or high.</summary>
    public string Severity { get; init; } = "informational";

    /// <summary>True for a query that gets no detection rule, since its rows name no file.</summary>
    [JsonIgnore]
    public bool HuntingOnly { get; init; }

    /// <summary>The check against clean files and prior builds; null when none was asked for.</summary>
    public HuntProof? Proof { get; init; }
}

/// <summary>The queries written for a fact list, and the notes naming each fact that got none.</summary>
public sealed record HuntSet(IReadOnlyList<Hunt> Hunts, IReadOnlyList<string> Notes)
{
    /// <summary>Every fact read from the file, with or without a query; empty for a set written from a fact list.</summary>
    [JsonIgnore]
    public IReadOnlyList<HuntFact> Facts { get; init; } = [];

    /// <summary>The kinds the file could not show; a fact of such a kind absent from it is unknown, not a miss.</summary>
    [JsonIgnore]
    public IReadOnlySet<string> UnknownKinds { get; init; } = new HashSet<string>();

    /// <summary>What the clean-file and prior-build scans read; null when none was asked for.</summary>
    public ProofScan? Proof { get; init; }
}

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

    /// <summary>A registry key path, with or without its hive.</summary>
    public const string RegistryKey = "registry_key";

    /// <summary>A mutex name; Defender XDR has no action type for it.</summary>
    public const string Mutex = "mutex";

    /// <summary>Every kind, in the order the queries are written.</summary>
    public static readonly IReadOnlyList<string> All =
        [Sha1, Signer, OriginalFileName, DllName, Domain, Url, Ipv4, Ipv6, NamedPipe, FilePath, RegistryKey, Mutex];
}

/// <summary>Writes Defender XDR advanced hunting queries from a plain fact list; every query passes <see cref="KqlCheck"/> before it is returned.</summary>
public static class KqlHunts
{
    /// <summary>Queries written per kind; the rest are counted in a note.</summary>
    public const int MaxPerKind = 50;

    /// <summary>The longest fact value a query carries, in characters.</summary>
    public const int MaxValueChars = 1_000;

    /// <summary>The longest library name list of one query, in characters; more names go to further queries.</summary>
    public const int MaxLibraryListChars = 4_000;

    private const string Base = "Timestamp, DeviceId, DeviceName, ReportId";

    private const string EmptyUrlNote = "RemoteUrl is empty on some connections, so no result does not show no connection; the DNS and TLS name queries read rows on any device that name no process, so a row does not show this file made the connection.";

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
    /// One query per fact and table; facts that read the same rows share a query. A network fact weaker than
    /// <see cref="IndicatorEvidence.Reference"/> reads this file's connections alone, and without a known executable file it gets no query.
    /// A fact with no query, and a query that fails the check, is named in the notes. With <paramref name="scopeSha1"/>
    /// every query is limited to the file with that SHA-1 as the initiating process, and a malformed SHA-1 throws.
    /// A file that is not <paramref name="executable"/> gets the file event query of its SHA-1 only.
    /// </summary>
    public static HuntSet Write(IEnumerable<HuntFact> facts, string? scopeSha1 = null, bool executable = true)
    {
        if (scopeSha1 != null && !IsSha1(scopeSha1)) throw new ArgumentException("The scope is not 40 hex digits.", nameof(scopeSha1));
        scopeSha1 = scopeSha1?.ToLowerInvariant();
        var notes = new List<string>();
        var merged = new Dictionary<(string Kind, string Value), string>(new FactKeyComparer());
        foreach (var f in facts)
        {
            if (string.IsNullOrWhiteSpace(f.Value)) continue;
            var clean = CleanText(f.Value).Trim();
            // The first spelling is kept.
            var key = (f.Kind, f.Kind == HuntKind.Sha1 ? clean.ToLowerInvariant() : clean);
            merged[key] = merged.TryGetValue(key, out var seen) ? IndicatorEvidence.Stronger(seen, f.Evidence) : f.Evidence;
        }
        var ordered = merged.OrderBy(m => HuntKind.All.ToList().IndexOf(m.Key.Kind)).ThenBy(m => m.Key.Value, StringComparer.Ordinal).ToList();
        string? sha1 = scopeSha1 ?? ordered.FirstOrDefault(m => m.Key.Kind == HuntKind.Sha1 && IsSha1(m.Key.Value)).Key.Value;
        bool scoped = scopeSha1 != null;
        var hunts = new List<Hunt>();
        foreach (var group in ordered.GroupBy(m => m.Key.Kind))
        {
            if (!HuntKind.All.Contains(group.Key)) { notes.Add($"{group.Count()} '{group.Key}' fact(s) have no query: the kind is not supported."); continue; }
            if (group.Key == HuntKind.Mutex)
            {
                notes.Add($"{group.Count()} mutex name(s) have no query: Defender XDR documents no mutex action type.");
                continue;
            }
            int skippedWeak = 0, written = 0, over = 0, tooLong = 0, unqueried = 0, local = 0, implausible = 0;
            if (group.Key == HuntKind.DllName)
            {
                var libraries = group.Where(m => m.Key.Value.Length <= MaxValueChars).ToList();
                tooLong = group.Count() - libraries.Count;
                if (libraries.Count > 0 && sha1 == null) unqueried = libraries.Count;
                else
                    foreach (var h in LibraryQueries(libraries, sha1, scoped, ref over))
                    {
                        var problems = KqlCheck.Diagnostics(h.Kql);
                        if (problems.Count > 0) notes.Add($"Query {h.Id} was dropped: {problems[0]}");
                        else hunts.Add(h);
                    }
            }
            foreach (var ((kind, value), evidence) in group.Where(_ => group.Key != HuntKind.DllName))
            {
                if (value.Length > MaxValueChars) { tooLong++; continue; }
                // A string is not shown to be contacted, and only an executable file starts a process to filter on.
                if (IsNetwork(kind) && !scoped && Rank(evidence) < Rank(IndicatorEvidence.Reference) && (sha1 == null || !executable)) { skippedWeak++; continue; }
                if (written >= MaxPerKind) { over++; continue; }
                if (IsNetwork(kind) && !Routable(kind, value)) { local++; continue; }
                if (evidence == IndicatorEvidence.String && !Plausible(kind, value)) { implausible++; continue; }
                var made = Queries(kind, value, evidence, sha1, scoped, executable, ref unqueried);
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
            if (local > 0) notes.Add($"{local} {group.Key} fact(s) name a loopback, unspecified, private, link-local or broadcast address and have no network query.");
            if (implausible > 0) notes.Add($"{implausible} {group.Key} string(s) read as an object identifier, a fragment or a name with no domain and have no network query.");
            if (group.Key == HuntKind.NamedPipe && written > 0)
                notes.Add("Named pipe queries read ActionType NamedPipeEvent and AdditionalFields.PipeName; no Learn page lists them, so no result does not show the pipe is absent.");
            if (group.Key == HuntKind.Url && written > 0)
                notes.Add("URL queries match the host where it is a name, since RemoteUrl can omit the path.");
            if (group.Key is HuntKind.Domain or HuntKind.Url && written > 0 && !notes.Contains(EmptyUrlNote))
                notes.Add(EmptyUrlNote);
            if (group.Key == HuntKind.RegistryKey && written > 0)
                notes.Add("Registry queries match the path as written, so a key under WOW6432Node or a numbered control set gives no result.");
            if (group.Key == HuntKind.FilePath && written > 0)
                notes.Add("DeviceFileEvents does not record every write, so no result does not show the file was not written.");
            if (skippedWeak > 0)
                notes.Add($"{skippedWeak} {group.Key} fact(s) found only as strings have no network query; view=indicators lists them with their evidence.");
            if (over > 0) notes.Add($"{over} {group.Key} fact(s) past the first {MaxPerKind} have no query.");
        }
        // A URL and its host read the same rows.
        var unique = hunts.GroupBy(h => h.Kql).Select(g => g.First() with
        {
            Facts = [.. g.SelectMany(h => h.Facts).Distinct()],
            Evidence = g.Select(h => h.Evidence).Aggregate(IndicatorEvidence.Stronger),
        }).ToList();
        return new HuntSet(unique, notes);
    }

    /// <summary>Range clauses in one crash query; the rest are counted in a note.</summary>
    public const int MaxCrashRanges = 200;

    /// <summary>
    /// One Microsoft Sentinel Event table query for Application Error events (event 1000) in <paramref name="module"/> with
    /// <paramref name="timeDateStamp"/> whose faulting offset lies in a half-open RVA range. No ranges give no query.
    /// Ranges whose gap holds none of <paramref name="functionStarts"/> and is shorter than <see cref="MaxPaddingGap"/> share a clause.
    /// </summary>
    public static HuntSet WriteCrash(string module, uint timeDateStamp, IEnumerable<(uint Start, uint End)> ranges, IReadOnlyCollection<uint>? functionStarts = null)
    {
        var sorted = Merge(ranges.Where(r => r.End > r.Start).Distinct().OrderBy(r => r.Start), functionStarts ?? []);
        if (sorted.Count == 0 || string.IsNullOrWhiteSpace(module)) return new HuntSet([], ["No function range is known, so no crash query was written."]);
        var notes = new List<string>();
        if (sorted.Count > MaxCrashRanges)
            notes.Add($"{sorted.Count - MaxCrashRanges} changed range(s) past the first {MaxCrashRanges} have no clause in the crash query.");
        // Offsets are compared as 16-digit lower case hex text, which orders like the numbers.
        static string Hex(uint v) => Literal(v.ToString("x16", CultureInfo.InvariantCulture));
        var clauses = sorted.Take(MaxCrashRanges).Select(r => $"(strcmp(Offset, {Hex(r.Start)}) >= 0 and strcmp(Offset, {Hex(r.End)}) < 0)").ToList();
        static string Field(string name) => $"extract({Literal($"Name=\"{name}\">([^<]*)<")}, 1, EventData)";
        var stamp = timeDateStamp.ToString("x8", CultureInfo.InvariantCulture);
        var lines = new List<string>
        {
            "Event",
            "| where EventLog =~ 'Application' and Source =~ 'Application Error' and EventID == 1000",
            $"| extend AppName = {Field("AppName")}",
            $"| extend ModuleName = {Field("ModuleName")}",
            $"| extend ModuleTimeStamp = {Field("ModuleTimeStamp")}",
            $"| extend FaultingOffset = {Field("FaultingOffset")}",
            $"| where ModuleName =~ {Literal(module)} and ModuleTimeStamp =~ {Literal(stamp)} and isnotempty(FaultingOffset)",
            "| extend Offset = substring(strcat('0000000000000000', tolower(FaultingOffset)), strlen(FaultingOffset), 16)",
            "| where " + string.Join("\n    or ", clauses),
            "| project TimeGenerated, Computer, AppName, ModuleName, ModuleTimeStamp, FaultingOffset",
        };
        var hunt = new Hunt(Id("crash", $"{module}\0{stamp}", ""), $"Crashes in changed code of {Short(module)}", "Event", string.Join('\n', lines),
            [$"crash:{module}:{stamp}"], IndicatorEvidence.Decoded);
        var problems = KqlCheck.Diagnostics(hunt.Kql);
        if (problems.Count > 0) return new HuntSet([], [.. notes, $"Query {hunt.Id} was dropped: {problems[0]}"]);
        return new HuntSet([hunt], notes);
    }

    /// <summary>Longest gap between two changed functions taken for alignment padding, in bytes.</summary>
    public const uint MaxPaddingGap = 16;

    // A gap with no function start that is shorter than the alignment is
    // padding, so a fault there is in neither function and the clause may
    // cover it.
    private static List<(uint Start, uint End)> Merge(IEnumerable<(uint Start, uint End)> sorted, IReadOnlyCollection<uint> starts)
    {
        var ordered = starts.Order().ToArray();
        var merged = new List<(uint Start, uint End)>();
        foreach (var r in sorted)
        {
            if (merged.Count > 0 && merged[^1] is var last && r.Start >= last.End && r.Start - last.End < MaxPaddingGap && !StartsIn(ordered, last.End, r.Start))
                merged[^1] = (last.Start, Math.Max(last.End, r.End));
            else if (merged.Count > 0 && r.Start < merged[^1].End)
                merged[^1] = (merged[^1].Start, Math.Max(merged[^1].End, r.End));
            else merged.Add(r);
        }
        return merged;
    }

    // Whether a function starts in [from, to).
    private static bool StartsIn(uint[] starts, uint from, uint to)
    {
        int i = Array.BinarySearch(starts, from);
        if (i < 0) i = ~i;
        return i < starts.Length && starts[i] < to;
    }

    private static string UnqueriedReason(string kind) => kind switch
    {
        HuntKind.Sha1 => "the value is not 40 hex digits",
        HuntKind.DllName => "they need the SHA-1 of the loading file",
        HuntKind.RegistryKey => "they need the SHA-1 of the file that changes the key",
        HuntKind.Ipv4 or HuntKind.Ipv6 => "the value is not an address",
        HuntKind.NamedPipe => "the pipe name is empty, or it is only a string and the file SHA-1 is unknown",
        HuntKind.FilePath => "the path names no file, or it is only a string and the file SHA-1 is unknown",
        _ => "no query applies",
    };

    private static bool Routable(string kind, string value) =>
        kind is not (HuntKind.Ipv4 or HuntKind.Ipv6) || !IPAddress.TryParse(value, out var ip) || IsRoutable(ip);

    // A string can have the form of an address or host without being one. A
    // reference is kept as read.
    private static bool Plausible(string kind, string value)
    {
        switch (kind)
        {
            case HuntKind.Domain:
                return value.Contains('.');
            case HuntKind.Url:
                return !Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.HostNameType != UriHostNameType.Dns || uri.Host.Contains('.');
            case HuntKind.Ipv4:
                // RFC 5280 attribute and extension identifiers.
                return !value.StartsWith("2.5.4.", StringComparison.Ordinal) && !value.StartsWith("2.5.29.", StringComparison.Ordinal);
            case HuntKind.Ipv6:
                if (!IPAddress.TryParse(value, out var ip)) return true;
                var b = ip.GetAddressBytes();
                // Every group under 0x1000 reads as a text fragment such as 6:86::.
                return Enumerable.Range(0, 8).Any(i => b[2 * i] >= 0x10);
            default:
                return true;
        }
    }

    // Loopback, unspecified, private, link-local and broadcast addresses match local traffic of every device.
    private static bool IsRoutable(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return false;
        if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast) return false;
        var b = ip.GetAddressBytes();
        if (b.Length == 4)
            return !(b[0] is 10 or 0 or 255 || b[0] == 172 && b[1] is >= 16 and <= 31 || b[0] == 192 && b[1] == 168
                || b[0] == 169 && b[1] == 254 || b[0] == 100 && b[1] is >= 64 and <= 127);
        return (b[0] & 0xFE) != 0xFC;
    }

    private static int Rank(string evidence) => Math.Max(0, Array.IndexOf(IndicatorEvidence.Classes, evidence));

    private static bool IsNetwork(string kind) => kind is HuntKind.Domain or HuntKind.Url or HuntKind.Ipv4 or HuntKind.Ipv6;

    private static bool IsSha1(string value) => value.Length == 40 && value.All(char.IsAsciiHexDigit);

    // A query filtered on one file's SHA-1 hashes it too, so two files'
    // queries for one value get distinct ids.
    private static string Id(string kind, string value, string suffix, string? file = null)
    {
        var key = file == null ? kind + "\0" + value : kind + "\0" + value + "\0" + file;
        var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(key)))[..8];
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

    private static Hunt Make(string kind, string value, string evidence, string suffix, string? file, string title, string table, string severity, params string?[] lines) =>
        new(Id(kind, value, suffix, file), title, table, string.Join('\n', lines.Where(l => l != null)), [$"{kind}:{value}"], evidence) { Severity = severity };

    private static List<Hunt> Queries(string kind, string value, string evidence, string? sha1, bool scoped, bool executable, ref int unqueried)
    {
        // A query limited to one build gets its own id and a filter on the initiating file.
        var tag = scoped ? "-new" : "";
        // A network string is not shown to be contacted, so the query reads
        // connections of this file alone.
        bool netByFile = IsNetwork(kind) && (scoped || Rank(evidence) < Rank(IndicatorEvidence.Reference));
        var only = netByFile ? $"| where InitiatingProcessSHA1 == {Literal(sha1!)}" : null;
        var netFile = netByFile ? sha1 : null;
        var byThis = netByFile ? " by this file" : "";
        switch (kind)
        {
            case HuntKind.Sha1:
                if (!IsSha1(value)) { unqueried++; return []; }
                var hash = Literal(value);
                var files = Make(kind, value, evidence, "-files", null, $"Files with SHA-1 {Short(value)}", "DeviceFileEvents", "medium",
                    "DeviceFileEvents", $"| where SHA1 == {hash}",
                    $"| project {Base}, ActionType, FileName, FolderPath, SHA1, InitiatingProcessFileName");
                if (!executable) return [files];
                return
                [
                    files,
                    Make(kind, value, evidence, "-processes", null, $"Processes started from SHA-1 {Short(value)}", "DeviceProcessEvents", "medium",
                        "DeviceProcessEvents", $"| where SHA1 == {hash}",
                        $"| project {Base}, FileName, FolderPath, ProcessCommandLine, SHA1, InitiatingProcessFileName"),
                    Make(kind, value, evidence, "-images", null, $"Image loads of SHA-1 {Short(value)}", "DeviceImageLoadEvents", "medium",
                        "DeviceImageLoadEvents", $"| where SHA1 == {hash}",
                        $"| project {Base}, FileName, FolderPath, SHA1, InitiatingProcessFileName"),
                ];
            case HuntKind.Signer:
                var name = SignerName(value);
                return
                [
                    Make(kind, value, evidence, "", null, $"Files signed by {Short(name)}", "DeviceFileCertificateInfo", "low",
                        "DeviceFileCertificateInfo", $"| where Signer has {Literal(name)}",
                        "| project Timestamp, DeviceId, DeviceName, ReportId, SHA1, Signer, Issuer, IsTrusted"),
                ];
            case HuntKind.OriginalFileName:
                return
                [
                    Make(kind, value, evidence, "", null, $"Copies of {Short(value)} under another name", "DeviceProcessEvents", "medium",
                        "DeviceProcessEvents",
                        $"| where ProcessVersionInfoOriginalFileName =~ {Literal(value)} and FileName !~ {Literal(value)}",
                        $"| project {Base}, FileName, FolderPath, ProcessVersionInfoOriginalFileName, SHA1"),
                ];
            case HuntKind.Domain:
                return [Network(kind, value, evidence, tag, only, netFile, $"Connections to {Short(value)}{byThis}", $"RemoteUrl has {Literal(value)}"), Lookups(kind, value, evidence, value)];
            case HuntKind.Url:
                var host = Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.HostNameType == UriHostNameType.Dns ? uri.Host : null;
                var filter = host != null ? $"RemoteUrl has {Literal(host)}" : $"RemoteUrl =~ {Literal(value)}";
                if (uri != null && uri.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6
                    && IPAddress.TryParse(uri.Host.Trim('[', ']'), out var urlIp) && IsRoutable(urlIp))
                    filter += $" or RemoteIP == {Literal(urlIp.ToString())}";
                var connections = Network(kind, value, evidence, tag, only, netFile, $"Connections to {Short(host ?? value)}{byThis}", filter);
                return host != null ? [connections, Lookups(kind, value, evidence, host)] : [connections];
            case HuntKind.Ipv4 or HuntKind.Ipv6:
                if (!IPAddress.TryParse(value, out var ip)) { unqueried++; return []; }
                return [Network(kind, value, evidence, tag, only, netFile, $"Connections to {ip}{byThis}", $"RemoteIP == {Literal(ip.ToString())}")];
            case HuntKind.NamedPipe:
                var pipe = PipeName(value);
                if (pipe.Length == 0) { unqueried++; return []; }
                // A pipe seen only as a string is not shown to be opened, so
                // the query reads opens by this file alone.
                bool pipeByFile = scoped || Rank(evidence) < Rank(IndicatorEvidence.Reference);
                if (pipeByFile && sha1 == null) { unqueried++; return []; }
                return
                [
                    Make(kind, value, evidence, tag, pipeByFile ? sha1 : null, pipeByFile ? $"Opens of named pipe {Short(pipe)} by this file" : $"Opens of named pipe {Short(pipe)}", "DeviceEvents", "low",
                        "DeviceEvents", "| where ActionType == 'NamedPipeEvent'", pipeByFile ? $"| where InitiatingProcessSHA1 == {Literal(sha1!)}" : null,
                        "| extend PipeName = tostring(parse_json(AdditionalFields).PipeName)",
                        $"| where PipeName endswith {Literal("\\" + pipe)}",
                        $"| project {Base}, FileName, PipeName, InitiatingProcessFileName, SHA1 = InitiatingProcessSHA1"),
                ];
            case HuntKind.FilePath:
                var (leaf, folder, rooted) = FilePathParts(value);
                if (leaf.Length == 0) { unqueried++; return []; }
                // A path seen only as a string is not shown to be written, so
                // the query reads writes by this file alone.
                bool byFile = scoped || Rank(evidence) < Rank(IndicatorEvidence.Reference);
                if (byFile && sha1 == null) { unqueried++; return []; }
                List<string> lines = ["DeviceFileEvents",
                    rooted ? $"| where (FolderPath =~ {Literal(folder)} or FolderPath =~ {Literal(value)}) and FileName =~ {Literal(leaf)}" : $"| where FileName =~ {Literal(leaf)}"];
                if (byFile) lines.Add($"| where InitiatingProcessSHA1 == {Literal(sha1!)}");
                lines.Add($"| project {Base}, ActionType, FileName, FolderPath, SHA1, InitiatingProcessFileName");
                return [Make(kind, value, evidence, tag, byFile ? sha1 : null, byFile ? $"Writes of {Short(leaf)} by this file" : $"Writes of {Short(leaf)}", "DeviceFileEvents", "low", [.. lines])];
            case HuntKind.RegistryKey:
                var subkey = SubKey(value);
                if (subkey.Length == 0 || sha1 == null) { unqueried++; return []; }
                return
                [
                    Make(kind, value, evidence, tag, sha1, $"Changes to registry key {Short(subkey)} by this file", "DeviceRegistryEvents", "low",
                        "DeviceRegistryEvents", $"| where InitiatingProcessSHA1 == {Literal(sha1)}",
                        // A delete keeps the key in PreviousRegistryKey and leaves RegistryKey empty.
                        $"| where RegistryKey endswith {Literal("\\" + subkey)} or PreviousRegistryKey endswith {Literal("\\" + subkey)}",
                        $"| project {Base}, ActionType, RegistryKey, RegistryValueName, PreviousRegistryKey, PreviousRegistryValueName, InitiatingProcessFileName, SHA1 = InitiatingProcessSHA1"),
                ];
            default:
                return [];
        }
    }

    // The file name, its folder and whether the path names a drive or share; the query matches on exactly these.
    internal static (string Leaf, string Folder, bool Rooted) FilePathParts(string value)
    {
        var leaf = value[(value.LastIndexOfAny(['\\', '/']) + 1)..];
        var folder = value[..Math.Max(0, value.Length - leaf.Length - 1)];
        var rooted = value.Length > 2 && (char.IsAsciiLetter(value[0]) && value[1] == ':' || value.StartsWith(@"\\", StringComparison.Ordinal));
        return (leaf, folder, rooted);
    }

    // RegistryKey spells the hive out and holds the user's SID under
    // HKEY_CURRENT_USER, so the query matches the path below the hive.
    internal static string SubKey(string value)
    {
        var path = value.Trim('\\');
        int slash = path.IndexOf('\\');
        bool hive = path.StartsWith("HKEY_", StringComparison.OrdinalIgnoreCase)
            || (slash > 0 ? path[..slash] : path).ToUpperInvariant() is "HKLM" or "HKCU" or "HKCR" or "HKU";
        if (!hive) return path;
        return slash > 0 ? path[(slash + 1)..] : "";
    }

    // One query per list of names; a list past the character cap goes to the next query.
    private static List<Hunt> LibraryQueries(List<KeyValuePair<(string Kind, string Value), string>> libraries, string? sha1, bool scoped, ref int over)
    {
        var hunts = new List<Hunt>();
        if (sha1 == null || libraries.Count == 0) return hunts;
        var names = libraries.OrderBy(l => l.Key.Value.ToLowerInvariant(), StringComparer.Ordinal).ToList();
        var chunks = new List<List<KeyValuePair<(string Kind, string Value), string>>> { new() };
        int chars = 0;
        foreach (var n in names)
        {
            int size = Literal(n.Key.Value).Length + 2;
            if (chars + size > MaxLibraryListChars && chunks[^1].Count > 0) { chunks.Add([]); chars = 0; }
            chunks[^1].Add(n);
            chars += size;
        }
        foreach (var chunk in chunks)
        {
            if (hunts.Count >= MaxPerKind) { over += chunk.Count; continue; }
            var values = chunk.Select(c => c.Key.Value).ToList();
            var key = string.Join('\n', values.Select(v => v.ToLowerInvariant()));
            var evidence = chunk.Select(c => c.Value).Aggregate(IndicatorEvidence.Stronger);
            var title = values.Count == 1 ? $"{Short(values[0])} loaded from the folder of the file" : $"{values.Count} libraries loaded from the folder of the file";
            hunts.Add(new Hunt(Id("dll_name", key, scoped ? "-new" : "", sha1), title, "DeviceImageLoadEvents", string.Join('\n',
            [
                "DeviceImageLoadEvents", $"| where InitiatingProcessSHA1 == {Literal(sha1)}",
                $"| where FileName in~ ({string.Join(", ", values.Select(Literal))})",
                "| where isnotempty(InitiatingProcessFolderPath)",
                $"| extend LoaderDir = {FolderOf("InitiatingProcessFolderPath", "InitiatingProcessFileName")}",
                $"| extend DllDir = {FolderOf("FolderPath", "FileName")}",
                "| where DllDir == LoaderDir",
                // A program in the system folder loads its DLLs from there by design.
                "| where not(DllDir endswith @'\\windows\\system32' or DllDir endswith @'\\windows\\syswow64')",
                $"| project {Base}, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessFolderPath",
            ]), [.. values.Select(v => $"{HuntKind.DllName}:{v}")], evidence) { Severity = "medium" });
        }
        return hunts;
    }

    // Names are compared as Windows compares them, except where a case change is a different value.
    private sealed class FactKeyComparer : IEqualityComparer<(string Kind, string Value)>
    {
        private static bool Folds(string kind) =>
            kind is HuntKind.DllName or HuntKind.OriginalFileName or HuntKind.Domain or HuntKind.NamedPipe or HuntKind.FilePath or HuntKind.RegistryKey;

        public bool Equals((string Kind, string Value) a, (string Kind, string Value) b) =>
            a.Kind == b.Kind && string.Equals(a.Value, b.Value, Folds(a.Kind) ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

        public int GetHashCode((string Kind, string Value) k) =>
            HashCode.Combine(k.Kind, Folds(k.Kind) ? StringComparer.OrdinalIgnoreCase.GetHashCode(k.Value) : StringComparer.Ordinal.GetHashCode(k.Value));
    }

    // Learn names a folder, telemetry often holds the full path: either form
    // gives the folder, lower case, without a trailing backslash.
    private static string FolderOf(string path, string name) =>
        $"tolower(iff({path} endswith strcat('\\\\', {name}), substring({path}, 0, strlen({path}) - strlen({name}) - 1), trim_end(@'\\\\', {path})))";

    private static Hunt Network(string kind, string value, string evidence, string tag, string? only, string? file, string title, string filter) =>
        Make(kind, value, evidence, tag, file, title, "DeviceNetworkEvents", "low",
            "DeviceNetworkEvents", only, $"| where {filter}",
            $"| project {Base}, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, SHA1 = InitiatingProcessSHA1");

    // DNS and TLS rows hold the name in AdditionalFields and name no process,
    // so the query cannot be limited to one file.
    private static Hunt Lookups(string kind, string value, string evidence, string host) =>
        Make(kind, value, evidence, "-lookups", null, $"DNS and TLS names {Short(host)} on any device", "DeviceNetworkEvents", "low",
            "DeviceNetworkEvents", "| where ActionType in ('DnsConnectionInspected', 'SslConnectionInspected')",
            $"| where AdditionalFields has {Literal(host)}",
            $"| project {Base}, ActionType, AdditionalFields") with { HuntingOnly = true };

    // The CN of a distinguished name, else the value.
    internal static string SignerName(string value)
    {
        int at = value.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
        if (at < 0) return value;
        var rest = value[(at + 3)..];
        int comma = rest.IndexOf(',');
        return (comma < 0 ? rest : rest[..comma]).Trim().Trim('"');
    }

    internal static string PipeName(string value)
    {
        var v = value.Trim();
        int at = v.IndexOf(@"pipe\", StringComparison.OrdinalIgnoreCase);
        return (at >= 0 ? v[(at + 5)..] : v).Trim('\\');
    }
}
