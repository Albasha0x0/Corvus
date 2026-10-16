using System.Text;

namespace Corvus.Core.Pcap;

/// <summary>
/// TLS secrets in the NSS key log format (SSLKEYLOGFILE): "CLIENT_RANDOM &lt;random&gt; &lt;master secret&gt;" for TLS 1.2
/// and the TLS 1.3 traffic secrets, each keyed by the ClientHello random. Read from a key log file or the decryption
/// secrets blocks of a pcapng.
/// </summary>
internal sealed class TlsKeyLog
{
    private readonly Dictionary<string, Dictionary<string, byte[]>> _byRandom = new(StringComparer.Ordinal);

    public int Sessions => _byRandom.Count;

    /// <summary>Lines of key log text; comments, blank and unreadable lines are skipped.</summary>
    public void Add(string text)
    {
        foreach (var raw in text.Split('\n'))
        {
            var parts = raw.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 3 || parts[0].StartsWith('#') || parts[1].Length != 64) continue;
            byte[] secret;
            try { secret = Convert.FromHexString(parts[2]); }
            catch (FormatException) { continue; }
            var random = parts[1].ToLowerInvariant();
            if (!_byRandom.TryGetValue(random, out var secrets)) _byRandom[random] = secrets = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            secrets[parts[0]] = secret;
        }
    }

    public void Add(ReadOnlySpan<byte> text) => Add(Encoding.ASCII.GetString(text));

    /// <summary>A secret of a session ("CLIENT_RANDOM", "CLIENT_TRAFFIC_SECRET_0"...), or null.</summary>
    public byte[]? Find(ReadOnlySpan<byte> clientRandom, string label) =>
        _byRandom.TryGetValue(Convert.ToHexStringLower(clientRandom), out var s) ? s.GetValueOrDefault(label) : null;
}
