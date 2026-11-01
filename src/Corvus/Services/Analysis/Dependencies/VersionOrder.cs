using System.Globalization;
using System.Numerics;
using System.Text.RegularExpressions;

namespace Corvus.Services.Analysis.Dependencies;

/// <summary>Orders package versions as each OSV ecosystem does.</summary>
internal static partial class VersionOrder
{
    /// <summary>The OSV ecosystem name of a component ecosystem, null when OSV has no records for it.</summary>
    internal static string? Osv(string ecosystem) => ecosystem switch
    {
        "nuget" => "NuGet",
        "cargo" => "crates.io",
        "pypi" => "PyPI",
        "golang" => "Go",
        "maven" => "Maven",
        _ => null,
    };

    /// <summary>The sign of a against b in the ecosystem; null when unorderable.</summary>
    internal static int? Compare(string osvEcosystem, string a, string b) => osvEcosystem switch
    {
        "NuGet" => Semantic(a, b, 4, true, false),
        "crates.io" or "npm" => Semantic(a, b, 3, false, false),
        "Go" => Semantic(a, b, 3, false, true),
        "PyPI" => Pep440(a, b),
        "Maven" => Maven(a, b),
        _ => null,
    };

    // Numbers of any length compare by digits, so a 25-digit build number does not overflow.
    private static int Digits(string a, string b)
    {
        a = a.TrimStart('0');
        b = b.TrimStart('0');
        return a.Length != b.Length ? a.Length.CompareTo(b.Length) : string.CompareOrdinal(a, b);
    }

    private static bool AllDigits(string s) => s.Length > 0 && s.All(char.IsAsciiDigit);

    private static int? Semantic(string a, string b, int maxCore, bool ignoreCase, bool go)
    {
        if (Split(a, maxCore, go) is not { } x || Split(b, maxCore, go) is not { } y) return null;
        for (int i = 0; i < maxCore; i++)
        {
            var c = Digits(x.Core[i], y.Core[i]);
            if (c != 0) return Math.Sign(c);
        }
        // A version without a pre-release label is later than one with it.
        if (x.Labels.Length == 0 || y.Labels.Length == 0)
            return x.Labels.Length == y.Labels.Length ? 0 : x.Labels.Length == 0 ? 1 : -1;
        for (int i = 0; i < Math.Min(x.Labels.Length, y.Labels.Length); i++)
        {
            var (p, q) = (x.Labels[i], y.Labels[i]);
            int c = AllDigits(p) && AllDigits(q) ? Digits(p, q)
                : AllDigits(p) ? -1 : AllDigits(q) ? 1
                : string.Compare(p, q, ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
            if (c != 0) return Math.Sign(c);
        }
        return Math.Sign(x.Labels.Length.CompareTo(y.Labels.Length));
    }

    private static (string[] Core, string[] Labels)? Split(string version, int maxCore, bool go)
    {
        var s = version.Trim();
        if (go && s.StartsWith("go", StringComparison.Ordinal) && s.Length > 2 && char.IsAsciiDigit(s[2]))
            s = s[2..];
        if (s.StartsWith('v') || s.StartsWith('V')) s = s[1..];
        var plus = s.IndexOf('+');
        if (plus >= 0) s = s[..plus];
        var dash = s.IndexOf('-');
        var core = (dash < 0 ? s : s[..dash]).Split('.');
        if (core.Length > maxCore || core.Any(p => !AllDigits(p))) return null;
        var labels = dash < 0 ? [] : s[(dash + 1)..].Split('.');
        if (labels.Any(l => l.Length == 0)) return null;
        return ([.. core, .. Enumerable.Repeat("0", maxCore - core.Length)], labels);
    }

    [GeneratedRegex(
        @"^v?(?:(\d+)!)?(\d+(?:\.\d+)*)" +
        @"(?:[-_.]?(alpha|a|beta|b|preview|pre|c|rc)[-_.]?(\d*))?" +
        @"(?:-(\d+)|[-_.]?(?:post|rev|r)[-_.]?(\d*))?" +
        @"(?:[-_.]?dev[-_.]?(\d*))?" +
        @"(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex Pep440Pattern();

    private sealed record Pep(
        BigInteger Epoch, BigInteger[] Release, int PreRank, BigInteger Pre,
        BigInteger? Post, BigInteger? Dev, string[] Local);

    private static BigInteger Number(string s) => s.Length == 0 ? 0 : BigInteger.Parse(s, CultureInfo.InvariantCulture);

    private static Pep? ParsePep(string version)
    {
        var m = Pep440Pattern().Match(version.Trim());
        if (!m.Success) return null;
        var release = m.Groups[2].Value.Split('.').Select(Number).ToList();
        while (release.Count > 1 && release[^1].IsZero) release.RemoveAt(release.Count - 1);
        // No pre-release label ranks after every labelled one.
        int pre = 3;
        if (m.Groups[3].Success)
            pre = m.Groups[3].Value.ToLowerInvariant() switch { "a" or "alpha" => 0, "b" or "beta" => 1, _ => 2 };
        BigInteger? post = m.Groups[5].Success ? Number(m.Groups[5].Value) : m.Groups[6].Success ? Number(m.Groups[6].Value) : null;
        // A development release of a final version sorts before that version's pre-releases.
        if (!m.Groups[3].Success && post == null && m.Groups[7].Success) pre = -1;
        return new(m.Groups[1].Success ? Number(m.Groups[1].Value) : 0, [.. release], pre,
            m.Groups[4].Success ? Number(m.Groups[4].Value) : 0, post,
            m.Groups[7].Success ? Number(m.Groups[7].Value) : null,
            m.Groups[8].Success ? m.Groups[8].Value.ToLowerInvariant().Split('.', '-', '_') : []);
    }

    private static int? Pep440(string a, string b)
    {
        if (ParsePep(a) is not { } x || ParsePep(b) is not { } y) return null;
        int c = x.Epoch.CompareTo(y.Epoch);
        for (int i = 0; c == 0 && i < Math.Max(x.Release.Length, y.Release.Length); i++)
            c = (i < x.Release.Length ? x.Release[i] : BigInteger.Zero)
                .CompareTo(i < y.Release.Length ? y.Release[i] : BigInteger.Zero);
        if (c == 0) c = x.PreRank.CompareTo(y.PreRank);
        if (c == 0) c = x.Pre.CompareTo(y.Pre);
        if (c == 0) c = Optional(x.Post, y.Post, absent: -1);
        if (c == 0) c = Optional(x.Dev, y.Dev, absent: 1);
        for (int i = 0; c == 0 && i < Math.Min(x.Local.Length, y.Local.Length); i++)
        {
            var (p, q) = (x.Local[i], y.Local[i]);
            c = AllDigits(p) && AllDigits(q) ? Digits(p, q)
                : AllDigits(p) ? 1 : AllDigits(q) ? -1 : string.CompareOrdinal(p, q);
        }
        if (c == 0) c = x.Local.Length.CompareTo(y.Local.Length);
        return Math.Sign(c);
    }

    // An absent post-release sorts before any, an absent development release after any.
    private static int Optional(BigInteger? x, BigInteger? y, int absent) => (x, y) switch
    {
        (null, null) => 0,
        (null, _) => absent,
        (_, null) => -absent,
        _ => x!.Value.CompareTo(y!.Value),
    };

    // Maven token rank: pre-release below 5, sp and unknown above, nonzero numbers top.
    private static int Rank(string token) => AllDigits(token)
        ? token.TrimStart('0').Length == 0 ? 5 : 100
        : token switch
        {
            "alpha" or "a" => 0, "beta" or "b" => 1, "milestone" or "m" => 2, "rc" or "cr" => 3, "snapshot" => 4,
            "ga" or "final" or "release" => 5, "sp" => 6, _ => 7,
        };

    // Simplified Maven order: split at '.', '-' and digit/letter changes.
    private static int? Maven(string a, string b)
    {
        var x = MavenTokens(a);
        var y = MavenTokens(b);
        if (x == null || y == null) return null;
        for (int i = 0; i < Math.Max(x.Count, y.Count); i++)
        {
            var p = i < x.Count ? x[i] : "0";
            var q = i < y.Count ? y[i] : "0";
            int c = AllDigits(p) && AllDigits(q) ? Digits(p, q) : Rank(p).CompareTo(Rank(q));
            if (c == 0 && Rank(p) == 7) c = string.CompareOrdinal(p, q);
            if (c != 0) return Math.Sign(c);
        }
        return 0;
    }

    private static List<string>? MavenTokens(string version)
    {
        var tokens = MavenToken().Matches(version.Trim().ToLowerInvariant()).Select(m => m.Value).ToList();
        if (tokens.Count == 0) return null;
        // Trailing zero and release tokens do not change the order.
        while (tokens.Count > 1 && Rank(tokens[^1]) == 5) tokens.RemoveAt(tokens.Count - 1);
        return tokens;
    }

    [GeneratedRegex(@"\d+|[a-z]+", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex MavenToken();
}
