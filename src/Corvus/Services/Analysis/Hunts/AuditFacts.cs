using System.Net;
using System.Text.RegularExpressions;
using Corvus.Core;

namespace Corvus.Services.Analysis.Hunts;

/// <summary>
/// The hashes of the summarized file: its file digests, and its Authenticode digests when it is a PE image
/// that was read whole; <see cref="Unread"/> names why the Authenticode digests are null.
/// </summary>
public sealed record ImageDigests(string FileName, string Sha1, string Sha256, string? AuthenticodeSha1, string? AuthenticodeSha256, string? Unread)
{
    /// <summary>The digests of <paramref name="file"/> read from <paramref name="input"/>; the Authenticode digests are null for a streamed or non-PE file.</summary>
    public static ImageDigests Of(FileInput input, InspectionService.FileFacts file)
    {
        var name = Path.GetFileName(file.Path);
        bool pe = input.Head.Length >= 2 && input.Head[0] == 'M' && input.Head[1] == 'Z';
        if (!pe) return new(name, file.Sha1, file.Sha256, null, null, "the file is not a PE image");
        if (input.Streamed) return new(name, file.Sha1, file.Sha256, null, null, $"the image is over {FileInput.StreamAbove:N0} bytes and was streamed");
        var sha1 = Certificates.AuthenticodeDigest(input.Bytes, System.Security.Cryptography.HashAlgorithmName.SHA1);
        var sha256 = Certificates.AuthenticodeDigest(input.Bytes, System.Security.Cryptography.HashAlgorithmName.SHA256);
        return sha1 == null || sha256 == null
            ? new(name, file.Sha1, file.Sha256, null, null, "the image or its certificate table is unreadable")
            : new(name, file.Sha1, file.Sha256, Convert.ToHexStringLower(sha1), Convert.ToHexStringLower(sha256), null);
    }
}

/// <summary>A fact an audit output leaves out, with the reason.</summary>
public sealed record Withheld(string Fact, string Reason);

/// <summary>A fact the proof kept: its kind, value and the highest severity of the queries that read it.</summary>
public sealed record KeptFact(string Kind, string Value, string Severity);

/// <summary>Picks the facts of a proven hunt set that an audit output may carry: file hash, domain, URL and address facts the proof kept.</summary>
public static partial class AuditFacts
{
    private static readonly string[] Kinds = [HuntKind.Sha1, HuntKind.Domain, HuntKind.Url, HuntKind.Ipv4, HuntKind.Ipv6];

    private static readonly string[] Severities = ["informational", "low", "medium", "high"];

    [GeneratedRegex(@"[\p{C}\s]", RegexOptions.CultureInvariant)]
    private static partial Regex Unusable();

    /// <summary>
    /// The facts of <paramref name="set"/> that every detection query reading them kept, and the facts left out with their reason.
    /// A fact the proof dropped or left for review, a network value found only as a string, a benign host or subdomain of one,
    /// a non-routable address, a non-ASCII name, a URL with user information and a value no indicator can carry are withheld;
    /// a kind with no indicator is counted once. Values are normalized and a repeat is kept once. A URL loses its fragment.
    /// Throws InvalidArgument for a set with no proof.
    /// </summary>
    public static (List<KeptFact> Kept, List<Withheld> Withheld) Of(HuntSet set)
    {
        if (set.Proof == null)
            throw new ToolError(ErrorCode.InvalidArgument, "indicatorsPath and policyPath write only the facts the proof kept.", "pass cleanFolder, a folder of clean files, with them");
        var byFact = new Dictionary<string, List<Hunt>>(StringComparer.Ordinal);
        foreach (var h in set.Hunts)
            foreach (var f in h.Facts)
            {
                if (!byFact.TryGetValue(f, out var list)) byFact[f] = list = [];
                list.Add(h);
            }
        var kept = new Dictionary<(string Kind, string Value), KeptFact>();
        var withheld = new List<Withheld>();
        var unsupported = new SortedDictionary<string, int>(StringComparer.Ordinal);
        foreach (var (fact, hunts) in byFact.OrderBy(p => Order(p.Key)).ThenBy(p => p.Key, StringComparer.Ordinal))
        {
            int colon = fact.IndexOf(':', StringComparison.Ordinal);
            var (kind, value) = colon < 0 ? (fact, "") : (fact[..colon], fact[(colon + 1)..]);
            if (!Kinds.Contains(kind)) { unsupported[kind] = unsupported.GetValueOrDefault(kind) + 1; continue; }
            var shown = Redacted(fact);
            var reading = hunts.Where(h => !h.HuntingOnly && h.Table != "DeviceFileCertificateInfo").ToList();
            if (reading.Count == 0) { withheld.Add(new(shown, "no detection query reads it")); continue; }
            // A query with no verdict is not a kept query.
            var refused = reading.Where(h => h.Proof?.Verdict != "keep").OrderBy(h => h.Proof?.Verdict == "drop" ? 0 : 1).FirstOrDefault();
            if (refused != null)
            {
                withheld.Add(new(shown, refused.Proof == null ? "no proof verdict" : $"{refused.Proof.Verdict}: {refused.Proof.Reason}"));
                continue;
            }
            var (reason, normal) = Check(set, kind, value, reading);
            if (reason != null) { withheld.Add(new(shown, reason)); continue; }
            int severity = reading.Max(h => Math.Max(0, Array.IndexOf(Severities, h.Severity)));
            var key = (kind, normal);
            kept[key] = kept.TryGetValue(key, out var seen) && Array.IndexOf(Severities, seen.Severity) >= severity ? seen : new(kind, normal, Severities[severity]);
        }
        foreach (var (kind, count) in unsupported)
            withheld.Add(new(kind, kind == HuntKind.Signer
                ? $"{count:N0} fact(s): a certificate indicator takes a leaf certificate thumbprint, and a signer name covers every file the publisher signs"
                : $"{count:N0} fact(s): no indicator or file rule has this kind"));
        return ([.. kept.Values], withheld);
    }

    /// <summary>One line stating how much of the clean folder the proof read and whether the scan was complete; empty for a set with no proof.</summary>
    public static string ProofNote(HuntSet set)
    {
        if (set.Proof is not { } p) return "";
        var c = p.Clean;
        return $"Proof: {c.Read:N0} of {c.Found:N0} clean files read, {c.NotRead:N0} not read, {c.Skipped:N0} past maxFiles, {c.Inaccessible:N0} folders or links not entered; "
            + $"minFiles {p.MinFiles:N0}; the scan is {(c.Complete ? "complete" : "partial")}.";
    }

    private static int Order(string fact)
    {
        int colon = fact.IndexOf(':', StringComparison.Ordinal);
        return Math.Max(0, HuntKind.All.ToList().IndexOf(colon < 0 ? fact : fact[..colon]));
    }

    // User information may hold a password: a withheld URL fact never shows it.
    private static string Redacted(string fact) => UserInfo().Replace(fact, "$1[user information removed]@");

    [GeneratedRegex(@"^(url:[A-Za-z][A-Za-z0-9+.\-]*://)[^/?#]*@", RegexOptions.CultureInvariant)]
    private static partial Regex UserInfo();

    /// <summary>The eight-segment form Learn gives for an IPv6 indicator, such as 2001:4860:4860:0:0:0:0:8888.</summary>
    internal static string Address(IPAddress ip)
    {
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6) return ip.ToString();
        var b = ip.GetAddressBytes();
        return string.Join(':', Enumerable.Range(0, 8).Select(i => ((b[2 * i] << 8) | b[2 * i + 1]).ToString("x", System.Globalization.CultureInfo.InvariantCulture)));
    }

    // The reason a value cannot be an indicator, else null, and its normalized value.
    private static (string? Reason, string Normal) Check(HuntSet set, string kind, string value, List<Hunt> reading)
    {
        if (kind == HuntKind.Sha1) return value.Length == 40 && value.All(char.IsAsciiHexDigit) ? (null, value.ToLowerInvariant()) : ("not 40 hex digits", value);
        if (Unusable().IsMatch(value)) return ("the value holds spaces or control characters", value);
        if (value.Any(c => c > 0x7F)) return ("not ASCII: no punycode is written, since Learn names none", value);
        // The class of a fact read from the file, else the strongest class of
        // the queries of a saved set.
        var known = set.Facts.Where(f => f.Kind == kind && f.Value.Trim() == value).Select(f => f.Evidence).ToList();
        int rank = known.Count > 0 ? known.Max(Rank) : reading.Min(h => Rank(h.Evidence));
        if (rank < Rank(IndicatorEvidence.Reference))
            return ("found only as a string: an indicator reads every device and cannot be limited to this file", value);
        const string Benign = "a benign host or a subdomain of one: schema, certificate or timestamp infrastructure";
        const string Internal = "not an external address: Learn takes external IP addresses only";
        switch (kind)
        {
            case HuntKind.Domain:
                var name = value.TrimEnd('.').ToLowerInvariant();
                if (name.Length == 0 || !name.Contains('.')) return ("not a domain name", value);
                return BenignHosts.Covers(name) ? (Benign, value) : (null, name);
            case HuntKind.Url:
                if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")) return ("not an absolute http or https URL", value);
                if (uri.UserInfo.Length > 0) return ("the URL holds user information, which may be a password", value);
                if (BenignHosts.Covers(uri.Host)) return (Benign, value);
                if (IPAddress.TryParse(uri.Host.Trim('[', ']'), out var host) && !KqlHunts.IsRoutable(host)) return (Internal, value);
                int hash = value.IndexOf('#', StringComparison.Ordinal);
                return (null, hash < 0 ? value : value[..hash]);
            default:
                if (!IPAddress.TryParse(value, out var ip)) return ("not an address", value);
                return KqlHunts.IsRoutable(ip) ? (null, Address(ip)) : (Internal, value);
        }
    }

    private static int Rank(string evidence) => Math.Max(0, Array.IndexOf(IndicatorEvidence.Classes, evidence));
}
