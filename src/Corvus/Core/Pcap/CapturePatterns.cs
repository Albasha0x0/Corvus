namespace Corvus.Core.Pcap;

/// <summary>
/// Patterns worth reviewing in a capture's summary: many long, high-entropy DNS names under one domain (data carried in
/// DNS names), and connections from one host to one server at a regular interval (a periodic check-in).
/// </summary>
internal static class CapturePatterns
{
    private const int MinNames = 20, MinLabel = 20, MinConnections = 6;
    private const double MinEntropy = 3.5, MaxSpread = 0.1;

    public static List<string> Find(CaptureAnalysis c)
    {
        var found = new List<string>();
        foreach (var g in c.DnsNames().Select(d => d.Name).GroupBy(Domain).Where(g => g.Count() >= MinNames))
        {
            var labels = g.Select(n => n.Split('.')[0]).ToList();
            double length = labels.Average(l => l.Length), entropy = labels.Average(Entropy);
            if (length >= MinLabel && entropy >= MinEntropy)
                found.Add($"DNS names: {g.Count()} distinct names under {g.Key}, first labels {length:0} characters on average with {entropy:0.0} bits of entropy per character (data carried in DNS names?)");
        }
        // DNS (its names are judged above) and NTP (periodic by design) are left out
        foreach (var g in c.Flows().Where(f => !f.Server.EndsWith(":53", StringComparison.Ordinal) && !f.Server.EndsWith(":123", StringComparison.Ordinal))
                     .GroupBy(f => (Client: Host(f.Client), f.Server, f.Protocol)))
        {
            var starts = g.Select(f => f.First).Order().ToList();
            if (starts.Count < MinConnections) continue;
            var gaps = starts.Zip(starts.Skip(1), (a, b) => (b - a).TotalSeconds).ToList();
            double mean = gaps.Average();
            if (mean < 1) continue;
            double spread = Math.Sqrt(gaps.Average(x => (x - mean) * (x - mean))) / mean;
            if (spread <= MaxSpread)
                found.Add($"periodic {g.Key.Protocol}: {g.Key.Client} to {g.Key.Server} every {mean:0.#} s ({starts.Count} connections, interval spread {spread:P0})");
        }
        return found;
    }

    /// <summary>The last two labels of a name (three under a two-letter second-level label such as co.uk).</summary>
    private static string Domain(string name)
    {
        var labels = name.TrimEnd('.').Split('.');
        int keep = labels.Length >= 3 && labels[^2].Length <= 3 && labels[^1].Length == 2 ? 3 : 2;
        return string.Join('.', labels[^Math.Min(keep, labels.Length)..]);
    }

    private static string Host(string endpoint) => endpoint.StartsWith('[') ? endpoint[..(endpoint.IndexOf(']') + 1)] : endpoint.Split(':')[0];

    /// <summary>Shannon entropy in bits per character.</summary>
    internal static double Entropy(string s)
    {
        if (s.Length == 0) return 0;
        return -s.GroupBy(ch => ch).Select(g => (double)g.Count() / s.Length).Sum(p => p * Math.Log2(p));
    }
}
