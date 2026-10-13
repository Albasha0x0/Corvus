using System.Text;
using dnlib.DotNet;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>
/// A decoded embedded item. Detail is the assembly name, PE machine and type, or the first 200 characters of text.
/// </summary>
public sealed record EmbeddedContent(
    string Source,
    IReadOnlyList<string> Encoding,
    string Kind,
    long Size,
    string Sha256,
    double Entropy,
    string? Detail,
    string? SavedTo = null,
    string? LoadedAs = null)
{
    /// <summary>The decoded bytes (not serialized).</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public byte[] Bytes { get; init; } = [];

    /// <summary>"inferred" for a brute-forced XOR key or a high-entropy guess; null when the decode chain is exact.</summary>
    public string? Basis => Kind.StartsWith("high-entropy", StringComparison.Ordinal) || Encoding.Any(e => e.Contains("brute-forced", StringComparison.Ordinal)) ? "inferred" : null;
}

/// <summary>
/// Finds embedded content in resources, static byte arrays and long string literals. Candidates are decoded up to
/// <see cref="MaxDecodeDepth"/> steps (hex, base64, gzip / zlib, header-derived XOR, raw deflate) until a known kind is
/// reached. XOR over text without a known header is only tried via <see cref="TryXorText"/> (opt-in). Undecoded data of
/// 1 KB or more at 7.5+ bits per byte is reported as high-entropy data.
/// </summary>
public static class Embedded
{
    private const int MinStringLength = 64;
    private const int MinBlobLength = 64;
    private const int MaxDecodeDepth = 4;
    private const int MaxXorKey = 16;
    private const double EncryptedEntropy = 7.5;
    private const int MinEncryptedSize = 1024;

    /// <summary>Kinds reported without further decoding: everything except text, unrecognized data and .resources containers.</summary>
    private static bool IsBinaryKind(string kind) => kind is not ("text" or "data" or ".resources");

    /// <param name="xorText">Also brute-force repeating XOR keys over unrecognized data (see <see cref="TryXorText"/>).</param>
    public static List<EmbeddedContent> Find(ModuleScan scan, AnalysisLimits limits, CancellationToken ct, bool xorText = false)
    {
        var found = new List<EmbeddedContent>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        void Add(EmbeddedContent p)
        {
            if (found.Count < limits.MaxItems && seen.Add(p.Sha256 + "|" + p.Source)) found.Add(p);
        }

        foreach (var r in scan.Resources)
        {
            ct.ThrowIfCancellationRequested();
            var source = $"resource '{r.Name}'";
            if (r.Bytes != null) Examine(r.Bytes, source, [], Add, limits, reportRaw: true, xorText);
            else if (r.Text != null && r.Text.Length >= MinStringLength) ExamineText(r.Text, source, Add, limits, xorText);
        }
        foreach (var d in scan.Data)
        {
            ct.ThrowIfCancellationRequested();
            if (d.Data.Length < MinBlobLength) continue;
            var used = d.UsedIn.Count > 0 ? $" (used in {Format.MemberLabel(d.UsedIn[0])}{(d.UsedIn.Count > 1 ? $" +{d.UsedIn.Count - 1}" : "")})" : "";
            Examine(d.Data, $"static data {Format.MemberLabel(d.Field)}{used}", [], Add, limits, reportRaw: true, xorText);
        }
        foreach (var s in scan.Strings)
        {
            ct.ThrowIfCancellationRequested();
            if (s.Value.Length >= MinStringLength) ExamineText(s.Value, $"string {s.Location.Where}", Add, limits, xorText);
        }
        return found;
    }

    /// <summary>Hex is tried before base64 because every hex string is also valid base64.</summary>
    private static void ExamineText(string text, string source, Action<EmbeddedContent> add, AnalysisLimits limits, bool xorText)
    {
        var trimmed = text.Trim();
        if (TryHex(trimmed, limits) is { } hex) Examine(hex, source, ["hex"], add, limits, reportRaw: false, xorText);
        else if (TryBase64(trimmed, limits) is { } b64) Examine(b64, source, ["base64"], add, limits, reportRaw: false, xorText);
    }

    /// <summary>Decodes recursively and reports the result.</summary>
    /// <param name="reportRaw">Also report undecoded data that is a known binary kind or has high entropy.</param>
    private static void Examine(byte[] data, string source, List<string> chain, Action<EmbeddedContent> add, AnalysisLimits limits, bool reportRaw,
        bool xorText)
    {
        var kind = Blob.Identify(data);
        if (kind == ".resources" && chain.Count == 0) return; // entries are examined individually
        if (IsBinaryKind(kind) && kind is not ("gzip" or "zlib"))
        {
            if (chain.Count > 0 || reportRaw) add(Make(data, source, chain, kind));
            return;
        }
        if (chain.Count >= MaxDecodeDepth) return;

        if (kind is "gzip" or "zlib" && Blob.TryDecompress(data, kind, limits.MaxItemBytes) is { } inflated)
        {
            Examine(inflated, source, [.. chain, kind], add, limits, reportRaw: true, xorText);
            return;
        }
        if (kind == "text")
        {
            var text = Encoding.UTF8.GetString(data).Trim();
            if (TryHex(text, limits) is { } hex) { Examine(hex, source, [.. chain, "hex"], add, limits, reportRaw: true, xorText); return; }
            if (TryBase64(text, limits) is { } b64) { Examine(b64, source, [.. chain, "base64"], add, limits, reportRaw: true, xorText); return; }
            if (xorText && reportRaw && TryXorText(data) is { } textXor)
            {
                Examine(textXor.Decoded, source, [.. chain, XorLabel(textXor)], add, limits, reportRaw: true, xorText: false);
                return;
            }
            if (chain.Count > 0 && text.Length >= 16) add(Make(data, source, chain, "text"));
            return;
        }
        // XOR key recovered from a known file header.
        if (data.Length >= MinBlobLength && TryXor(data) is { } xor)
        {
            Examine(xor.Decoded, source, [.. chain, $"xor key {Convert.ToHexStringLower(xor.Key)}"], add, limits, reportRaw: true, xorText);
            return;
        }
        // Raw deflate has no header; accept only recognizable output.
        if (data.Length >= MinBlobLength && Blob.TryDecompress(data, "deflate", limits.MaxItemBytes) is { Length: > 0 } deflated
            && (IsBinaryKind(Blob.Identify(deflated)) || Blob.Identify(deflated) == "text" && deflated.Length >= 32))
        {
            Examine(deflated, source, [.. chain, "deflate"], add, limits, reportRaw: true, xorText);
            return;
        }
        // Opt-in: repeating-key XOR over text, no known header.
        if (xorText && reportRaw && TryXorText(data) is { } brute)
        {
            Examine(brute.Decoded, source, [.. chain, XorLabel(brute)], add, limits, reportRaw: true, xorText: false);
            return;
        }
        if (reportRaw && data.Length >= MinEncryptedSize && Blob.Entropy(data) >= EncryptedEntropy)
            add(Make(data, source, chain, "high-entropy data (encrypted or compressed?)"));
    }

    private static EmbeddedContent Make(byte[] data, string source, List<string> chain, string kind)
    {
        string? detail = null;
        if (kind == "text")
        {
            var text = Encoding.UTF8.GetString(data);
            detail = text.Length > 200 ? text[..200] + "…" : text;
        }
        else if (kind == ".NET assembly")
        {
            try
            {
                using var m = ModuleDefMD.Load(data);
                detail = m.Assembly?.FullName ?? m.Name;
            }
            catch (Exception) { detail = "unreadable metadata"; }
        }
        else if (PeImage.TryParse(data) is { } pe)
        {
            detail = $"{pe.MachineName} {(pe.IsDll ? "DLL" : "EXE")}";
        }
        return new EmbeddedContent(source, chain, kind, data.Length, Blob.Sha256(data), Math.Round(Blob.Entropy(data), 2), detail) { Bytes = data };
    }

    /// <summary>Strict base64 (standard or URL alphabet; whitespace allowed); null when the text is not base64.</summary>
    internal static byte[]? TryBase64(string text, AnalysisLimits limits)
    {
        if (text.Length < 16 || text.Length / 4 * 3 > limits.MaxItemBytes) return null;
        var sb = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            if (char.IsWhiteSpace(c)) continue;
            if (c is '-') sb.Append('+');
            else if (c is '_') sb.Append('/');
            else if (char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '=') sb.Append(c);
            else return null;
        }
        var s = sb.ToString().TrimEnd('=');
        if (s.Length < 16 || s.Length % 4 == 1) return null;
        // Require mixed character classes so plain identifiers are not taken as base64.
        if (!s.Any(char.IsAsciiDigit) && !(s.Any(char.IsAsciiLetterUpper) && s.Any(char.IsAsciiLetterLower))) return null;
        s = s.PadRight(s.Length + (4 - s.Length % 4) % 4, '=');
        try { return Convert.FromBase64String(s); }
        catch (FormatException) { return null; }
    }

    internal static byte[]? TryHex(string text, AnalysisLimits limits)
    {
        var s = text.Replace(" ", "").Replace("-", "");
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s[2..];
        if (s.Length < 32 || s.Length % 2 != 0 || s.Length / 2 > limits.MaxItemBytes || !s.All(char.IsAsciiHexDigit)) return null;
        return Convert.FromHexString(s);
    }

    /// <summary>Known file headers used as plaintext to recover an XOR key.</summary>
    private static readonly (string Kind, byte[] Header)[] KnownHeaders =
    [
        // Standard DOS header emitted by PE linkers.
        ("pe", [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        ("zip", [0x50, 0x4B, 0x03, 0x04]),
        ("gzip", [0x1F, 0x8B, 0x08]),
    ];

    /// <summary>
    /// Repeating-key XOR derived as header XOR data. Accepted only if the key is periodic across the whole header and
    /// the decoded data parses as the format.
    /// </summary>
    internal static (byte[] Key, byte[] Decoded)? TryXor(byte[] data)
        => TryXorWithHeaders(data);

    private const int MinXorTextLength = 32;

    private const int MaxXorKeyLength = 16;

    /// <summary>E.g. "xor key 5a (brute-forced, UTF-16 text)".</summary>
    private static string XorLabel((byte[] Key, byte[] Decoded, bool Utf16) x) =>
        $"xor key {Convert.ToHexStringLower(x.Key)} (brute-forced{(x.Utf16 ? ", UTF-16 text" : "")})";

    /// <summary>
    /// Brute-forces a repeating XOR key (1-16 bytes) over UTF-8 or UTF-16LE text with no known header. Key length is
    /// chosen by column index of coincidence; each key byte by per-column text likelihood, then refined. Accepted only
    /// when the input is unreadable and the decode passes <see cref="ReadableText"/>. UTF-16 results are returned as UTF-8.
    /// </summary>
    internal static (byte[] Key, byte[] Decoded, bool Utf16)? TryXorText(byte[] data)
    {
        if (data.Length < MinXorTextLength) return null;
        var sample = data.AsSpan(0, Math.Min(data.Length, 4096)).ToArray();
        if (ReadableText(sample, utf16: false) || ReadableText(sample, utf16: true)) return null;
        // XORed text keeps a skewed byte distribution per key column (index of coincidence well above 1/256).
        var lengths = Enumerable.Range(1, MaxXorKeyLength).Where(l => sample.Length / l >= 24)
            .Select(l => (Length: l, Coincidence: Coincidence(sample, l))).ToList();
        if (lengths.Count == 0) return null;
        double top = lengths.Max(x => x.Coincidence);
        if (top < 0.02) return null; // flat: compressed, encrypted or random
        var candidates = lengths.Where(x => x.Coincidence >= Math.Max(0.02, top * 0.6)).Select(x => x.Length).Take(3).ToList();
        // UTF-16 first: its XORed zero high bytes can otherwise refine into look-alike UTF-8 letters.
        foreach (bool utf16 in new[] { true, false })
            foreach (int length in candidates)
            {
                var scored = new byte[length];
                var counts = new int[2 * 256]; // a column's bytes by value; UTF-16 keeps low and high bytes apart
                var present = new List<int>();
                for (int column = 0; column < length; column++)
                {
                    Array.Clear(counts);
                    present.Clear();
                    for (int i = column; i < sample.Length; i += length)
                        if (counts[(utf16 && i % 2 == 1 ? 256 : 0) + sample[i]]++ == 0) present.Add((utf16 && i % 2 == 1 ? 256 : 0) + sample[i]);
                    // The weights of the column's bytes XOR k, summed per distinct byte: the same integer as summing per byte.
                    int bestScore = int.MinValue;
                    for (int k = 0; k < 256; k++)
                    {
                        int score = 0;
                        foreach (int at in present)
                            score += counts[at] * (utf16 ? (at >= 256 ? Utf16HighWeights : Utf16LowWeights) : Utf8Weights)[(at & 0xFF) ^ k];
                        if (score > bestScore) { bestScore = score; scored[column] = (byte)k; }
                    }
                }
                // Candidates: scored key refined by ASCII bigrams, by UTF-8 readability, and crib-seeded keys.
                var tries = new List<(byte[] Key, bool[] Fixed, bool Utf8Script)> { (scored, new bool[length], false) };
                if (!utf16)
                {
                    tries.Add((scored, new bool[length], true));
                    foreach (var crib in Cribs)
                    {
                        var key = (byte[])scored.Clone();
                        var fixedBytes = new bool[length];
                        for (int i = 0; i < Math.Min(length, crib.Length) && i < sample.Length; i++) { key[i] = (byte)(sample[i] ^ crib[i]); fixedBytes[i] = true; }
                        if (key.AsSpan().SequenceEqual(scored)) continue;
                        tries.Add((key, fixedBytes, false));
                    }
                }
                (byte[] Key, double Score)? best = null;
                var slice = sample.Length > 512 ? sample[..512] : sample;
                // Skip refinement unless the first-pass decode is mostly printable or non-ASCII.
                if (!utf16 && Apply(slice, scored) is var firstPass
                    && firstPass.Count(c => c is >= 0x20 and < 0x7F or 9 or 10 or 13 or >= 0x80) < firstPass.Length * 0.85)
                    continue;
                var seenKeys = new HashSet<string>(StringComparer.Ordinal);
                foreach (var (start0, fixedBytes, utf8Script) in tries)
                {
                    var key = (byte[])start0.Clone();
                    if (!utf16)
                    {
                        if (!utf8Script) RefineByBigrams(slice, key, fixedBytes);
                        else if (Apply(sample, key) is var first && !ReadableText(first, utf16: false) && first.Count(c => c == ' ') is var spaces
                                 && spaces >= first.Length * 0.03 && spaces <= first.Length * 0.4)
                            RefineForUtf8(sample.AsSpan(0, Math.Min(sample.Length, 1024)).ToArray(), key);
                        else continue;
                    }
                    if (key.All(b => b == 0) || !seenKeys.Add(Convert.ToHexString(key))) continue;
                    var decoded = Apply(sample, key);
                    if (!ReadableText(decoded, utf16) || Repeats(decoded, length) || !utf16 && Utf16Shaped(decoded)) continue;
                    double rank = utf16 ? 0 : BigramScore(decoded);
                    if (best == null || rank > best.Value.Score) best = (key, rank);
                }
                if (best is not { } chosen) continue;
                var shortest = Shortest(chosen.Key); // a detected length may be a multiple of the true key length
                var full = Apply(data, shortest);
                if (!ReadableText(full.AsSpan(0, Math.Min(full.Length, 65536)).ToArray(), utf16)) continue;
                return (shortest, utf16 ? Encoding.UTF8.GetBytes(Encoding.Unicode.GetString(full)) : full, utf16);
            }
        return null;
    }

    /// <summary>Common configuration prefixes used as known plaintext for the first key bytes.</summary>
    private static readonly byte[][] Cribs = new[] { "{\"", "[{\"", "[\"", "https://", "http://", "<?xml ", "<config", "[" }
        .Select(Encoding.ASCII.GetBytes).ToArray();

    /// <summary>ASCII bigram log-probabilities trained on mixed prose, JSON, URLs, INI, XML, paths and code.</summary>
    private static readonly double[,] Bigrams = TrainBigrams(
        "The quick brown fox jumps over the lazy dog. Quarterly notes, not for sharing with anyone outside the team. " +
        "Please send the report to the staging server before the end of the day, and keep a copy of the settings. " +
        "{\"name\":\"value\",\"url\":\"https://update.example.com/api/v1/check\",\"interval\":300,\"enabled\":true," +
        "\"servers\":[\"https://cdn.example.net/files/latest.zip\",\"http://10.0.0.1:8080/upload\"],\"path\":\"C:\\\\Users\\\\Public\"}\n" +
        "https://www.example.org/index.html?id=42&lang=en\nhttp://download.example.com/setup.exe\n" +
        "[settings]\nhost=relay.example.com\nport=443\nuser=admin\npassword=secret\ntimeout=30\nlog_level=info\n" +
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><configuration><appSettings><add key=\"server\" value=\"https://example.com\" />" +
        "</appSettings></configuration>\n" +
        "public static void Main(string[] args) { var client = new HttpClient(); var data = await client.GetStringAsync(url); }\n" +
        "SELECT name, value FROM settings WHERE id = 1; INSERT INTO log (time, message) VALUES (now(), 'started');\n" +
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run /usr/local/bin/service --config /etc/app/config.json\n");

    private static double[,] TrainBigrams(string text)
    {
        var counts = new double[128, 128];
        for (int a = 0; a < 128; a++)
            for (int b = 0; b < 128; b++)
                counts[a, b] = 0.05; // smoothing for unseen pairs
        for (int i = 0; i + 1 < text.Length; i++)
            if (text[i] < 128 && text[i + 1] < 128) counts[text[i], text[i + 1]] += 1;
        var logs = new double[128, 128];
        for (int a = 0; a < 128; a++)
        {
            double row = 0;
            for (int b = 0; b < 128; b++) row += counts[a, b];
            for (int b = 0; b < 128; b++) logs[a, b] = Math.Log(counts[a, b] / row);
        }
        return logs;
    }

    /// <summary>Bigram table over all byte values; pairs with non-text bytes score -12.</summary>
    private static readonly double[] PairTable = BuildPairTable();

    private static double[] BuildPairTable()
    {
        static bool Text(int c) => c < 128 && (c >= 0x20 || c is 9 or 10 or 13) && c != 0x7F;
        var table = new double[256 * 256];
        for (int a = 0; a < 256; a++)
            for (int b = 0; b < 256; b++)
                table[a * 256 + b] = Text(a) && Text(b) ? Bigrams[a, b] : -12;
        return table;
    }

    private static double Pair(byte a, byte b) => PairTable[a * 256 + b];

    private static double BigramScore(byte[] decoded)
    {
        double score = 0;
        for (int i = 0; i + 1 < decoded.Length; i++) score += Pair(decoded[i], decoded[i + 1]);
        return score / Math.Max(1, decoded.Length - 1);
    }

    /// <summary>Coordinate ascent on non-crib key bytes, maximizing bigram likelihood.</summary>
    private static void RefineByBigrams(byte[] sample, byte[] key, bool[] fixedBytes)
    {
        int length = key.Length, n = sample.Length;
        var decoded = new byte[n];
        for (int i = 0; i < n; i++) decoded[i] = (byte)(sample[i] ^ key[i % length]);
        var table = PairTable;
        for (int pass = 0; pass < 2; pass++)
            for (int column = 0; column < length; column++)
            {
                if (fixedBytes[column]) continue;
                double bestScore = double.NegativeInfinity;
                int best = key[column];
                for (int k = 0; k < 256; k++)
                {
                    // Only this column changes; score just the pairs it belongs to.
                    double score = 0;
                    for (int i = column; i < n; i += length)
                    {
                        int c = sample[i] ^ k;
                        if (i > 0) score += table[decoded[i - 1] * 256 + c];
                        if (i + 1 < n) score += table[c * 256 + decoded[i + 1]];
                    }
                    if (score > bestScore) { bestScore = score; best = k; }
                }
                key[column] = (byte)best;
                for (int i = column; i < n; i += length) decoded[i] = (byte)(sample[i] ^ best);
            }
    }

    /// <summary>Coordinate ascent on key bytes, maximizing UTF-8 readability of the decode.</summary>
    private static void RefineForUtf8(byte[] sample, byte[] key)
    {
        // Rewards letters, spaces and valid multi-byte sequences; penalizes controls and invalid sequences.
        static int Score(byte[] d)
        {
            int score = 0;
            for (int i = 0; i < d.Length;)
            {
                byte c = d[i];
                if (c < 0x80)
                {
                    score += c is (byte)' ' or >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z' ? 2
                        : c is 9 or 10 or 13 or >= (byte)'0' and <= (byte)'9' or (byte)'.' or (byte)',' ? 1
                        : c < 0x20 || c == 0x7F ? -5 : -1;
                    i++;
                    continue;
                }
                int extra = c is >= 0xC2 and <= 0xDF ? 1 : c is >= 0xE0 and <= 0xEF ? 2 : c is >= 0xF0 and <= 0xF4 ? 3 : 0;
                bool valid = extra > 0;
                for (int k = 1; valid && k <= extra; k++)
                    valid = i + k < d.Length && (d[i + k] & 0xC0) == 0x80;
                if (valid) { score += 2; i += extra + 1; }
                else { score -= 5; i++; }
            }
            return score;
        }
        // Per-column scoring can be off by a constant XOR for all bytes; try a whole-key shift first.
        var shifted = new byte[key.Length];
        int bestShift = 0, bestShiftScore = int.MinValue;
        for (int c = 0; c < 256; c++)
        {
            for (int i = 0; i < key.Length; i++) shifted[i] = (byte)(key[i] ^ c);
            int score = Score(Apply(sample, shifted));
            if (score > bestShiftScore) { bestShiftScore = score; bestShift = c; }
        }
        for (int i = 0; i < key.Length; i++) key[i] ^= (byte)bestShift;

        for (int pass = 0; pass < 2; pass++)
            for (int column = 0; column < key.Length; column++)
            {
                int best = Score(Apply(sample, key));
                byte keep = key[column];
                for (int k = 0; k < 256; k++)
                {
                    key[column] = (byte)k;
                    int score = Score(Apply(sample, key));
                    if (score > best) { best = score; keep = (byte)k; }
                }
                key[column] = keep;
            }
    }

    private static byte[] Apply(byte[] data, byte[] key)
    {
        var result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++) result[i] = (byte)(data[i] ^ key[i % key.Length]);
        return result;
    }

    private static readonly int[] Utf8Weights = [.. Enumerable.Range(0, 256).Select(b => Utf8Weight((byte)b))];
    private static readonly int[] Utf16LowWeights = [.. Enumerable.Range(0, 256).Select(b => Utf16Weight((byte)b, high: false))];
    private static readonly int[] Utf16HighWeights = [.. Enumerable.Range(0, 256).Select(b => Utf16Weight((byte)b, high: true))];

    /// <summary>Text likelihood weight of a UTF-8 byte.</summary>
    private static int Utf8Weight(byte c) => c switch
    {
        (byte)' ' => 6,
        (byte)'e' or (byte)'t' or (byte)'a' or (byte)'o' or (byte)'i' or (byte)'n' or (byte)'s' or (byte)'h' or (byte)'r' => 4,
        >= (byte)'a' and <= (byte)'z' => 3,
        >= (byte)'A' and <= (byte)'Z' => 2,
        >= (byte)'0' and <= (byte)'9' or (byte)'.' or (byte)',' or (byte)'\n' or (byte)'\r' or (byte)'\t' or (byte)'\'' or (byte)'"' or (byte)'-' => 1,
        >= 0x21 and <= 0x7E => 0,
        >= 0x80 and <= 0xBF or >= 0xC2 and <= 0xF4 => 1, // UTF-8 lead and continuation bytes
        _ => -8,
    };

    /// <summary>Text likelihood weight of a UTF-16LE byte; high bytes are 0 for Latin or a script's code page.</summary>
    private static int Utf16Weight(byte c, bool high) => high
        ? c switch { 0 => 4, 0x03 or 0x04 or 0x05 or 0x06 or 0x09 or 0x0E or 0x30 => 2, >= 0x4E and <= 0x9F or >= 0xAC and <= 0xD7 => 1, _ => -4 }
        : c switch
        {
            (byte)' ' => 5,
            (byte)'e' or (byte)'t' or (byte)'a' or (byte)'o' or (byte)'i' or (byte)'n' or (byte)'s' or (byte)'h' or (byte)'r' => 3,
            >= (byte)'a' and <= (byte)'z' => 2,
            >= 0x21 and <= 0x7E => 1,
            0 => -4,
            _ => 0,
        };

    /// <summary>Natural language or structured text (JSON, XML, config lines) in UTF-8 or UTF-16LE.</summary>
    private static bool ReadableText(byte[] bytes, bool utf16) => NaturalText(bytes, utf16) || StructuredText(bytes, utf16);

    private static readonly System.Text.RegularExpressions.Regex ConfigLine = new(
        @"^(?:[a-z][a-z0-9+.\-]*://[\w.\-]*[a-z][\w.\-]*\S*|[a-z_][\w.\-\[\] ]{0,63}\s*[=:]\s*\S.*|(?=[\w.\-]*[a-z])[\w\-]+(?:\.[\w\-]+)+:\d{1,5}|[a-z]:\\[\w .\\\-]*[a-z][\w .\\\-]*|/(?:[\w.\-]*[a-z][\w.\-]*/?)+|#\s*[a-z].*|;\s*[a-z].*|\[[a-z][^\]]*\])$",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>
    /// JSON or XML that parses (a truncated sample is allowed), or lines that are mostly URLs, key/value pairs,
    /// host:port, paths, comments or [sections].
    /// </summary>
    private static bool StructuredText(byte[] bytes, bool utf16)
    {
        if (utf16 && bytes.Length % 2 == 1) bytes = bytes[..^1];
        string text;
        try { text = (utf16 ? new UnicodeEncoding(false, false, true) : (Encoding)new UTF8Encoding(false, true)).GetString(TrimPartial(bytes, utf16)); }
        catch (DecoderFallbackException) { return false; }
        text = text.Trim();
        if (text.Length < 24 || text.Any(c => char.IsControl(c) && c is not ('\n' or '\r' or '\t'))) return false;
        if (text.Count(c => c is >= ' ' and <= '~' or '\n' or '\r' or '\t') < text.Length * 0.9) return false;
        if (text.Count(char.IsLetter) < text.Count(c => !char.IsWhiteSpace(c)) * 0.3) return false; // numeric tables

        if (text[0] is '{' or '[')
        {
            try
            {
                var utf8 = Encoding.UTF8.GetBytes(text);
                var reader = new System.Text.Json.Utf8JsonReader(utf8, isFinalBlock: false, state: default);
                int tokens = 0, names = 0;
                while (reader.Read())
                {
                    tokens++;
                    if (reader.TokenType == System.Text.Json.JsonTokenType.PropertyName) names++;
                }
                return tokens >= 6 && (names >= 2 || tokens >= 10);
            }
            catch (System.Text.Json.JsonException) { return false; }
        }
        if (text[0] == '<')
        {
            if (System.Text.RegularExpressions.Regex.Count(text, @"<[A-Za-z_][\w.:\-]*(\s[^<>]*)?/?>") < 3) return false;
            try
            {
                using var xml = System.Xml.XmlReader.Create(new StringReader(text), new System.Xml.XmlReaderSettings { DtdProcessing = System.Xml.DtdProcessing.Prohibit, XmlResolver = null });
                while (xml.Read()) { }
                return true;
            }
            catch (System.Xml.XmlException ex)
            {
                // Truncated sample: accept if well-formed up to the cut.
                return ex.LineNumber >= text.Count(c => c == '\n') && bytes.Length >= 4096;
            }
        }
        var lines = text.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
        if (lines.Count < 2) lines = text.Split(';', '|').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
        if (lines.Count < 2) return false;
        int matching = lines.Count(l => ConfigLine.IsMatch(l));
        return matching >= 2 && matching >= lines.Count * 0.9;
    }

    private static bool NaturalText(byte[] bytes, bool utf16)
    {
        if (utf16 && bytes.Length % 2 == 1) bytes = bytes[..^1];
        string text;
        try { text = (utf16 ? new UnicodeEncoding(false, false, true) : (Encoding)new UTF8Encoding(false, true)).GetString(TrimPartial(bytes, utf16)); }
        catch (DecoderFallbackException) { return false; }
        if (text.Length < MinXorTextLength) return false;
        int letters = 0, whitespace = 0, other = 0, words = 0, wordLetters = 0;
        var distinct = new HashSet<char>();
        bool inWord = false;
        foreach (var c in text)
        {
            if (char.IsControl(c) && c is not ('\n' or '\r' or '\t')) return false;
            if (char.IsLetter(c)) { letters++; distinct.Add(char.ToLowerInvariant(c)); wordLetters++; if (!inWord) { words++; inWord = true; } continue; }
            inWord = false;
            if (char.IsWhiteSpace(c)) whitespace++;
            else other++;
        }
        int visible = letters + other;
        if (!(visible > 0 && letters >= visible * 0.5 && distinct.Count >= 10)) return false;
        var letterChars = text.Where(char.IsLetter).ToList();
        int dominant = letterChars.GroupBy(Script).OrderByDescending(g => g.Count()).First().Key;
        // Real text stays within one script plus ASCII; wrong-key decodes scatter across unrelated Unicode blocks.
        int stray = text.Count(c => !(char.IsWhiteSpace(c) || c is >= ' ' and <= '~' || char.IsLetter(c) && (Script(c) == dominant || Script(c) == 0)
                                      || c is >= '\u2010' and <= '\u205E' or >= '\u3000' and <= '\u303F' or >= '\uFF01' and <= '\uFF5E'
                                      || char.IsDigit(c) || (char.IsPunctuation(c) && Script(c) == dominant)));
        if (stray > text.Length * 0.03) return false;
        if (dominant == 0)
        {
            // Latin text has vowels and words longer than two letters on average.
            var wordLengths = System.Text.RegularExpressions.Regex.Matches(text, @"\p{L}+").Select(m => m.Length).ToList();
            if (wordLengths.Count >= 10 && wordLengths.Average() < 3.0) return false;
            var runs = System.Text.RegularExpressions.Regex.Matches(text, @"\p{L}{3,}").Select(m => m.Value).ToList();
            if (runs.Count >= 5 && runs.Count(w => w.Any(c => "aeiouyAEIOUYàáâäèéêëìíîïòóôöùúûü".Contains(c))) < runs.Count * 0.8) return false;
            if (text.Count(c => c < 128) >= text.Length * 0.9 && BigramScore(Encoding.ASCII.GetBytes(text)) < -4.2) return false;
        }
        else if (dominant is 5 or 6)
        {
            // CJK / Hangul text repeats common characters; random code points do not.
            int covered = letterChars.GroupBy(c => c).Select(g => g.Count()).OrderByDescending(n => n).Take(30).Sum();
            if (letterChars.Count >= 60 && covered < letterChars.Count * 0.35) return false;
        }
        // Natural text keeps most letters in one script and repeats letter pairs.
        var scripts = text.Where(char.IsLetter).GroupBy(Script).Select(g => g.Count()).OrderByDescending(n => n).ToList();
        if (scripts[0] < letters * 0.8) return false;
        var pairs = new Dictionary<int, int>();
        for (int i = 0; i + 1 < text.Length; i++)
            if (char.IsLetter(text[i]) && char.IsLetter(text[i + 1]))
            {
                int pair = (text[i] << 16) | text[i + 1];
                pairs[pair] = pairs.GetValueOrDefault(pair) + 1;
            }
        int totalPairs = pairs.Values.Sum();
        if (totalPairs >= 40 && pairs.Values.Where(n => n > 1).Sum() < totalPairs * 0.15) return false;
        return letters >= visible * 0.5 && distinct.Count >= 10
               && whitespace >= text.Length * 0.03 && whitespace <= text.Length * 0.40
               && words > 0 && wordLetters / (double)words is >= 2 and <= 15;
    }

    /// <summary>Coarse script class: Latin, Greek / Cyrillic, Hebrew / Arabic, Indic, Thai, CJK / kana, Hangul, other.</summary>
    private static int Script(char c) => c switch
    {
        <= 'ɏ' => 0,
        >= 'Ͱ' and <= 'ԯ' => 1,
        >= '֐' and <= 'ࣿ' or >= 'יִ' and <= '﻿' => 2,
        >= 'ऀ' and <= '෿' => 3,
        >= '฀' and <= '໿' => 4,
        >= '぀' and <= 'ヿ' or >= '㐀' and <= '鿿' or >= '豈' and <= '﫿' => 5,
        >= '가' and <= '힯' or >= 'ᄀ' and <= 'ᇿ' => 6,
        _ => 7,
    };

    /// <summary>Mean index of coincidence over the columns of a given key length.</summary>
    private static double Coincidence(byte[] sample, int length)
    {
        double total = 0;
        var counts = new int[256];
        for (int column = 0; column < length; column++)
        {
            Array.Clear(counts);
            int n = 0;
            for (int i = column; i < sample.Length; i += length) { counts[sample[i]]++; n++; }
            long same = 0;
            foreach (var c in counts) same += (long)c * (c - 1);
            total += n > 1 ? same / ((double)n * (n - 1)) : 0;
        }
        return total / length;
    }

    /// <summary>Drops a trailing incomplete UTF-8 sequence.</summary>
    private static byte[] TrimPartial(byte[] bytes, bool utf16)
    {
        if (utf16) return bytes;
        int end = bytes.Length, back = 0;
        while (end > 0 && back < 3 && (bytes[end - 1] & 0xC0) == 0x80) { end--; back++; }
        if (end > 0 && bytes[end - 1] >= 0xC0) return bytes[..(end - 1)]; // lead byte without continuation
        return back > 0 && end > 0 && bytes[end - 1] < 0x80 ? bytes[..end] : bytes;
    }

    /// <summary>
    /// True when even or odd positions are dominated by three values: UTF-16 text misread as UTF-8.
    /// </summary>
    private static bool Utf16Shaped(byte[] bytes)
    {
        // Non-ASCII UTF-8 also alternates byte classes; exclude it.
        if (bytes.Count(c => c >= 0x80) >= bytes.Length * 0.1) return false;
        foreach (int parity in new[] { 0, 1 })
        {
            var counts = new int[256];
            int n = 0;
            for (int i = parity; i < bytes.Length; i += 2) { counts[bytes[i]]++; n++; }
            if (n >= 16 && counts.OrderByDescending(c => c).Take(3).Sum() >= n * 0.8) return true;
        }
        return false;
    }

    /// <summary>Reduces a key that repeats a shorter period (abcabc) to that period.</summary>
    private static byte[] Shortest(byte[] key)
    {
        for (int p = 1; p < key.Length; p++)
            if (key.Length % p == 0 && Enumerable.Range(0, key.Length).All(i => key[i] == key[i % p])) return key[..p];
        return key;
    }

    /// <summary>True when the decode is mostly repeated key-length blocks (structured data, not text).</summary>
    private static bool Repeats(byte[] decoded, int length)
    {
        int width = Math.Max(length, 4), blocks = decoded.Length / width;
        if (blocks < 4) return false;
        var seen = new HashSet<string>();
        for (int b = 0; b < blocks; b++) seen.Add(Convert.ToHexString(decoded, b * width, width));
        return seen.Count < blocks / 2;
    }

    /// <summary>
    /// Validates gzip beyond the magic (which any recovered key reproduces): reserved flags clear and ISIZE matches.
    /// </summary>
    private static bool IsRealGzip(byte[] data)
    {
        if (data.Length < 18 || (data[3] & 0xE0) != 0) return false;
        if (Blob.TryDecompress(data, "gzip", 64L * 1024 * 1024) is not { Length: > 0 } inflated) return false;
        return BitConverter.ToUInt32(data, data.Length - 4) == (uint)inflated.Length;
    }

    /// <summary>
    /// Validates zip beyond the local header (which any recovered key reproduces): the archive opens with printable entry names.
    /// </summary>
    private static bool IsRealZip(byte[] data)
    {
        try
        {
            using var zip = new System.IO.Compression.ZipArchive(new MemoryStream(data, writable: false), System.IO.Compression.ZipArchiveMode.Read);
            var entries = zip.Entries;
            return entries.Count > 0 && entries.All(e => e.FullName.Length > 0 && e.FullName.All(c => !char.IsControl(c)));
        }
        catch (Exception) { return false; }
    }

    private static (byte[] Key, byte[] Decoded)? TryXorWithHeaders(byte[] data)
    {
        foreach (var (kind, header) in KnownHeaders)
        {
            if (data.Length < header.Length) continue;
            for (int keyLength = 1; keyLength <= Math.Min(MaxXorKey, header.Length); keyLength++)
            {
                // Keys longer than half the header are not confirmed by periodicity; parsing validates them.
                var key = new byte[keyLength];
                for (int i = 0; i < keyLength; i++) key[i] = (byte)(data[i] ^ header[i]);
                if (key.All(b => b == 0)) break;
                bool consistent = true;
                for (int i = keyLength; i < header.Length && consistent; i++)
                    consistent = (byte)(data[i] ^ key[i % keyLength]) == header[i];
                if (!consistent) continue;
                var decoded = new byte[data.Length];
                for (int i = 0; i < data.Length; i++) decoded[i] = (byte)(data[i] ^ key[i % keyLength]);
                bool valid = kind switch
                {
                    "pe" => PeImage.TryParse(decoded) != null,
                    "zip" => IsRealZip(decoded),
                    _ => IsRealGzip(decoded),
                };
                if (valid) return (key, decoded);
            }
        }
        return null;
    }
}
