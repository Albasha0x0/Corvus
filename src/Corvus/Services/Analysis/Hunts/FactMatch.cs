using System.Net;

namespace Corvus.Services.Analysis.Hunts;

/// <summary>Tests a clean file's facts the way a query matches its rows, so a hit here is a row the query would return.</summary>
internal static class FactMatch
{
    /// <summary>How a query fact is tested: an exact key among a file's keys, or a term inside a file's host or signer text.</summary>
    internal readonly record struct Probe(string Group, string Text);

    private const string Key = "key", Host = "host", Signer = "signer";

    /// <summary>The tests a hit of <paramref name="kind"/> and <paramref name="value"/> passes; none when the query written for it reads no row.</summary>
    internal static List<Probe> Query(string kind, string value)
    {
        var v = value.Trim();
        switch (kind)
        {
            case HuntKind.Sha1: return [new(Key, "sha1:" + Lower(v))];
            case HuntKind.OriginalFileName: return [new(Key, "orig:" + Lower(v))];
            case HuntKind.DllName: return [new(Key, "dll:" + Lower(v))];
            case HuntKind.Signer: return [new(Signer, Lower(KqlHunts.SignerName(v)))];
            case HuntKind.Domain: return [new(Host, Lower(v))];
            case HuntKind.Ipv4 or HuntKind.Ipv6: return [new(Key, "ip:" + Address(v))];
            case HuntKind.Url:
                if (Uri.TryCreate(v, UriKind.Absolute, out var uri) && uri.HostNameType == UriHostNameType.Dns) return [new(Host, Lower(uri.Host))];
                var probes = new List<Probe> { new(Key, "url:" + Lower(v)) };
                if (uri != null && IPAddress.TryParse(uri.Host.Trim('[', ']'), out var ip)) probes.Add(new(Key, "ip:" + ip));
                return probes;
            case HuntKind.NamedPipe:
                var pipe = KqlHunts.PipeName(v);
                return pipe.Length == 0 ? [] : [new(Key, "pipe:" + Lower(pipe))];
            case HuntKind.RegistryKey:
                var subkey = KqlHunts.SubKey(v);
                return subkey.Length == 0 ? [] : [new(Key, "reg:" + Lower(subkey))];
            case HuntKind.FilePath:
                var (leaf, _, rooted) = KqlHunts.FilePathParts(v);
                if (leaf.Length == 0) return [];
                return [new(Key, rooted ? "path:" + Lower(Fold(v)) : "leaf:" + Lower(leaf))];
            default: return [];
        }
    }

    /// <summary>What a clean file's facts offer to a probe: its keys, host texts and signer texts.</summary>
    internal sealed class Profile
    {
        private readonly HashSet<string> _keys = new(StringComparer.Ordinal);
        private readonly List<string> _hosts = [];
        private readonly List<string> _signers = [];

        /// <summary>The profile of <paramref name="facts"/>.</summary>
        internal Profile(IEnumerable<HuntFact> facts)
        {
            foreach (var f in facts) Add(f.Kind, f.Value.Trim());
        }

        /// <summary>Whether a query with this probe would return a row for the file.</summary>
        internal bool Has(Probe p) => p.Group switch
        {
            Key => _keys.Contains(p.Text),
            Host => _hosts.Any(h => HasTerm(h, p.Text)),
            _ => _signers.Any(s => HasTerm(s, p.Text)),
        };

        private void Add(string kind, string v)
        {
            switch (kind)
            {
                case HuntKind.Sha1: _keys.Add("sha1:" + Lower(v)); break;
                case HuntKind.OriginalFileName: _keys.Add("orig:" + Lower(v)); break;
                case HuntKind.DllName: _keys.Add("dll:" + Lower(v)); break;
                case HuntKind.Signer: _signers.Add(Lower(v)); break;
                case HuntKind.Domain: _hosts.Add(Lower(v)); break;
                case HuntKind.Ipv4 or HuntKind.Ipv6: _keys.Add("ip:" + Address(v)); break;
                case HuntKind.Url:
                    _hosts.Add(Lower(v));
                    _keys.Add("url:" + Lower(v));
                    if (Uri.TryCreate(v, UriKind.Absolute, out var uri) && IPAddress.TryParse(uri.Host.Trim('[', ']'), out var ip)) _keys.Add("ip:" + ip);
                    break;
                // An endswith match: every tail that starts after a backslash is a key.
                case HuntKind.NamedPipe: AddTails("pipe:", KqlHunts.PipeName(v)); break;
                case HuntKind.RegistryKey: AddTails("reg:", KqlHunts.SubKey(v)); break;
                case HuntKind.FilePath:
                    var (leaf, _, _) = KqlHunts.FilePathParts(v);
                    if (leaf.Length == 0) break;
                    _keys.Add("path:" + Lower(Fold(v)));
                    _keys.Add("leaf:" + Lower(leaf));
                    break;
            }
        }

        private void AddTails(string prefix, string path)
        {
            if (path.Length == 0) return;
            var lower = Lower(path);
            _keys.Add(prefix + lower);
            for (int i = lower.IndexOf('\\', StringComparison.Ordinal); i >= 0; i = lower.IndexOf('\\', i + 1)) _keys.Add(prefix + lower[(i + 1)..]);
        }
    }

    private static string Lower(string v) => v.ToLowerInvariant();

    private static string Fold(string path) => path.Replace('/', '\\');

    // RemoteIP is compared as the canonical text of the address.
    private static string Address(string v) => IPAddress.TryParse(v, out var ip) ? ip.ToString() : Lower(v);

    // KQL has: the term is whole, bounded by characters that are not letters or digits.
    private static bool HasTerm(string text, string term)
    {
        if (term.Length == 0) return false;
        for (int i = text.IndexOf(term, StringComparison.Ordinal); i >= 0; i = text.IndexOf(term, i + 1, StringComparison.Ordinal))
        {
            bool before = i == 0 || !char.IsLetterOrDigit(text[i - 1]);
            int end = i + term.Length;
            if (before && (end == text.Length || !char.IsLetterOrDigit(text[end]))) return true;
        }
        return false;
    }
}
