using System.Text;
using dnlib.DotNet;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services.Analysis;

/// <summary>
/// One embedded item after decoding: its source, encoding chain, kind, size, SHA-256, entropy, and a detail (assembly
/// name, PE machine and DLL / EXE, or the first 200 characters of text). SavedTo / LoadedAs are set when written / loaded.
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
}

/// <summary>
/// Finds embedded content in a scanned module: embedded resources, .resources entries, static byte arrays of 64 bytes
/// or more (array initializers in &lt;PrivateImplementationDetails&gt;) and string literals of 64 characters or more.
/// Each candidate is decoded repeatedly, up to 4 steps, through hex, base64, gzip / zlib, XOR and raw deflate until it
/// is a recognized kind: a PE / .NET / NativeAOT image, an archive, an ELF or Mach-O binary, or text of 16 characters or
/// more. XOR keys are recovered from the known first bytes of a PE (keys up to 16 bytes), ZIP (up to 4) or gzip (up to
/// 3) file, so XOR straight over text is not decoded unless the opt-in single-byte search (<see cref="TryXorText"/>) is on. Raw deflate is accepted only when the result is a recognized kind
/// or text of 32 bytes or more. Undecoded resources and arrays of 1 KB or more with entropy of 7.5 bits per byte or more
/// are reported as high-entropy data. Bounded by <see cref="AnalysisLimits"/>; nothing is executed.
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

    /// <summary>
    /// Embedded content of <paramref name="scan"/>. <paramref name="xorText"/>: also brute-force repeating XOR keys over
    /// unrecognized resource / array data that is not readable as it is (see <see cref="TryXorText"/>).
    /// </summary>
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

    /// <summary>
    /// Text that may be hex or base64; plain text is not a payload by itself. Hex is tried first: every hex string is
    /// also made of base64 characters, so base64 first would decode hex into garbage.
    /// </summary>
    private static void ExamineText(string text, string source, Action<EmbeddedContent> add, AnalysisLimits limits, bool xorText)
    {
        var trimmed = text.Trim();
        if (TryHex(trimmed, limits) is { } hex) Examine(hex, source, ["hex"], add, limits, reportRaw: false, xorText);
        else if (TryBase64(trimmed, limits) is { } b64) Examine(b64, source, ["base64"], add, limits, reportRaw: false, xorText);
    }

    /// <summary>
    /// Decodes <paramref name="data"/> as far as it goes and reports the result. <paramref name="reportRaw"/>: also report
    /// undecoded data that is a recognized binary kind or has high entropy (resources and static arrays, not decoded strings).
    /// </summary>
    private static void Examine(byte[] data, string source, List<string> chain, Action<EmbeddedContent> add, AnalysisLimits limits, bool reportRaw,
        bool xorText)
    {
        var kind = Blob.Identify(data);
        if (kind == ".resources" && chain.Count == 0) return; // a .resources container: its entries are examined one by one
        if (IsBinaryKind(kind) && kind is not ("gzip" or "zlib"))
        {
            if (chain.Count > 0 || reportRaw) add(Make(data, source, chain, kind));
            return;
        }
        if (chain.Count >= MaxDecodeDepth) return;

        // compressed
        if (kind is "gzip" or "zlib" && Blob.TryDecompress(data, kind, limits.MaxItemBytes) is { } inflated)
        {
            Examine(inflated, source, [.. chain, kind], add, limits, reportRaw: true, xorText);
            return;
        }
        // text that is itself encoded, or readable text produced by decoding
        if (kind == "text")
        {
            var text = Encoding.UTF8.GetString(data).Trim();
            if (TryHex(text, limits) is { } hex) { Examine(hex, source, [.. chain, "hex"], add, limits, reportRaw: true, xorText); return; } // before base64: see ExamineText
            if (TryBase64(text, limits) is { } b64) { Examine(b64, source, [.. chain, "base64"], add, limits, reportRaw: true, xorText); return; }
            if (xorText && reportRaw && TryXorText(data) is { } textXor)
            {
                Examine(textXor.Decoded, source, [.. chain, XorLabel(textXor)], add, limits, reportRaw: true, xorText: false);
                return;
            }
            if (chain.Count > 0 && text.Length >= 16) add(Make(data, source, chain, "text"));
            return;
        }
        // XOR with a key recovered from a known file header
        if (data.Length >= MinBlobLength && TryXor(data) is { } xor)
        {
            Examine(xor.Decoded, source, [.. chain, $"xor key {Convert.ToHexStringLower(xor.Key)}"], add, limits, reportRaw: true, xorText);
            return;
        }
        // raw deflate (Costura, custom packers): only accept a result that is recognizable
        if (data.Length >= MinBlobLength && Blob.TryDecompress(data, "deflate", limits.MaxItemBytes) is { Length: > 0 } deflated
            && (IsBinaryKind(Blob.Identify(deflated)) || Blob.Identify(deflated) == "text" && deflated.Length >= 32))
        {
            Examine(deflated, source, [.. chain, "deflate"], add, limits, reportRaw: true, xorText);
            return;
        }
        // opt-in: repeating-key XOR over text (no known header to recover the key from)
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

    // ------------------------------------------------------------------ decoders

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
        // a plain word or identifier is not base64: require a mix of character classes
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

    /// <summary>Known first bytes of file formats, used to recover an XOR key from the start of the data.</summary>
    private static readonly (string Kind, byte[] Header)[] KnownHeaders =
    [
        // the standard DOS header every PE linker writes
        ("pe", [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        ("zip", [0x50, 0x4B, 0x03, 0x04]),
        ("gzip", [0x1F, 0x8B, 0x08]),
    ];

    /// <summary>
    /// A repeating-key XOR whose key makes the data start with a known header: the key is the header XOR the data, and
    /// it is accepted only when it repeats with its period across the whole known header and the decoded data parses
    /// (a PE header, a zip archive or a gzip stream). Keys of all zero bytes (no XOR) are ignored.
    /// </summary>
    internal static (byte[] Key, byte[] Decoded)? TryXor(byte[] data)
        => TryXorWithHeaders(data);

    private const int MinXorTextLength = 32;

    private const int MaxXorKeyLength = 16;

    /// <summary>"xor key 5a (brute-forced)", with ", UTF-16 text" when the plaintext was UTF-16.</summary>
    private static string XorLabel((byte[] Key, byte[] Decoded, bool Utf16) x) =>
        $"xor key {Convert.ToHexStringLower(x.Key)} (brute-forced{(x.Utf16 ? ", UTF-16 text" : "")})";

    /// <summary>
    /// XOR over text without a known header: repeating keys of 1 to 16 bytes, for UTF-8 text (any script) and UTF-16LE
    /// text. Key lengths come from the index of coincidence of the columns (flat data is skipped at once); each key byte
    /// is chosen for its column by how text-like it makes it, and for text in other scripts refined against the whole
    /// decode (multi-byte characters span columns). A key is accepted only when the input is not readable text in
    /// either encoding as it is, and the decode is: valid in that encoding; at least 32 characters with no control
    /// characters but whitespace; half or more letters among the non-space characters, ten or more distinct ones, 80%
    /// of them in one script; letter pairs that repeat (15% or more of them); 3-40% whitespace, words of 2-15 letters
    /// on average; not a repeating block of the key length. UTF-16 results are returned as UTF-8.
    /// </summary>
    internal static (byte[] Key, byte[] Decoded, bool Utf16)? TryXorText(byte[] data)
    {
        if (data.Length < MinXorTextLength) return null;
        var sample = data.AsSpan(0, Math.Min(data.Length, 4096)).ToArray();
        if (ReadableText(sample, utf16: false) || ReadableText(sample, utf16: true)) return null; // readable already
        // the key length: text XORed with a repeating key keeps text's uneven byte distribution in every column of the
        // key's length (index of coincidence well above random data's 1/256); the shortest such length first
        var lengths = Enumerable.Range(1, MaxXorKeyLength).Where(l => sample.Length / l >= 24)
            .Select(l => (Length: l, Coincidence: Coincidence(sample, l))).ToList();
        if (lengths.Count == 0) return null;
        double top = lengths.Max(x => x.Coincidence);
        if (top < 0.02) return null; // flat: compressed, encrypted or random data
        var candidates = lengths.Where(x => x.Coincidence >= Math.Max(0.02, top * 0.6)).Select(x => x.Length).Take(3).ToList();
        // UTF-16 first: its zero high bytes, XORed, can be refined into look-alike UTF-8 letters
        foreach (bool utf16 in new[] { true, false })
            foreach (int length in candidates)
            {
                var scored = new byte[length];
                for (int column = 0; column < length; column++)
                {
                    int bestScore = int.MinValue;
                    for (int k = 0; k < 256; k++)
                    {
                        int score = 0;
                        for (int i = column; i < sample.Length; i += length)
                            score += utf16 ? Utf16Weight((byte)(sample[i] ^ k), i % 2 == 1) : Utf8Weight((byte)(sample[i] ^ k));
                        if (score > bestScore) { bestScore = score; scored[column] = (byte)k; }
                    }
                }
                // the scored key refined two ways (by ASCII character pairs; as UTF-8 text in another script, whose
                // multi-byte characters span columns), and keys whose first bytes come from what configuration usually
                // starts with ({", https://, <?xml...), refined by pairs; validation keeps the ones that give text
                var tries = new List<(byte[] Key, bool[] Fixed, bool Utf8Script)> { (scored, new bool[length], false) };
                if (!utf16)
                {
                    tries.Add((scored, new bool[length], true));
                    foreach (var crib in Cribs)
                    {
                        var key = (byte[])scored.Clone();
                        var fixedBytes = new bool[length];
                        for (int i = 0; i < Math.Min(length, crib.Length) && i < sample.Length; i++) { key[i] = (byte)(sample[i] ^ crib[i]); fixedBytes[i] = true; }
                        if (key.AsSpan().SequenceEqual(scored)) continue; // the crib agrees with the scored key: nothing new
                        tries.Add((key, fixedBytes, false));
                    }
                }
                (byte[] Key, double Score)? best = null;
                var slice = sample.Length > 512 ? sample[..512] : sample;
                // text under its per-column key is already nearly all printable (or another script's bytes); tables
                // and code are not, and refining them is wasted time
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
                    if (key.All(b => b == 0) || !seenKeys.Add(Convert.ToHexString(key))) continue; // no XOR, or tried already
                    var decoded = Apply(sample, key);
                    if (!ReadableText(decoded, utf16) || Repeats(decoded, length) || !utf16 && Utf16Shaped(decoded)) continue;
                    double rank = utf16 ? 0 : BigramScore(decoded);
                    if (best == null || rank > best.Value.Score) best = (key, rank);
                }
                if (best is not { } chosen) continue;
                var shortest = Shortest(chosen.Key); // 3 key bytes over 2-byte characters repeat every 6 bytes
                var full = Apply(data, shortest);
                if (!ReadableText(full.AsSpan(0, Math.Min(full.Length, 65536)).ToArray(), utf16)) continue;
                return (shortest, utf16 ? Encoding.UTF8.GetBytes(Encoding.Unicode.GetString(full)) : full, utf16);
            }
        return null;
    }

    /// <summary>What hidden configuration usually starts with: known plaintext for the first key bytes.</summary>
    private static readonly byte[][] Cribs = new[] { "{\"", "[{\"", "[\"", "https://", "http://", "<?xml ", "<config", "[" }
        .Select(Encoding.ASCII.GetBytes).ToArray();

    /// <summary>
    /// Log-probabilities of ASCII character pairs, learnt from a sample of prose, JSON, URLs, INI, XML, paths and code:
    /// what makes "https://a.example" likelier than a decode with one key byte off.
    /// </summary>
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
                counts[a, b] = 0.05; // unseen pairs: unlikely, not impossible
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

    /// <summary>The pair table over all byte values: non-text bytes score -12.</summary>
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

    /// <summary>Coordinate ascent over the key bytes not fixed by a crib, three passes, on the pairs each byte is part of.</summary>
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
                    // only this column's bytes change: score the pairs they are in
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

    /// <summary>Coordinate ascent over the key bytes, two passes, on how readable the UTF-8 decode is.</summary>
    private static void RefineForUtf8(byte[] sample, byte[] key)
    {
        // a UTF-8 scan: letters and spaces up, whole multi-byte characters up, invalid sequences and controls down
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
                // a lead byte and its continuation bytes, all present
                int extra = c is >= 0xC2 and <= 0xDF ? 1 : c is >= 0xE0 and <= 0xEF ? 2 : c is >= 0xF0 and <= 0xF4 ? 3 : 0;
                bool valid = extra > 0;
                for (int k = 1; valid && k <= extra; k++)
                    valid = i + k < d.Length && (d[i + k] & 0xC0) == 0x80;
                if (valid) { score += 2; i += extra + 1; }
                else { score -= 5; i++; }
            }
            return score;
        }
        // the per-column choice can be off by one constant for every byte (a script's lead byte taken for a space):
        // try shifting the whole key first
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

    /// <summary>How text-like a byte of UTF-8 text is: spaces and letters most, controls and invalid UTF-8 bytes strongly against.</summary>
    private static int Utf8Weight(byte c) => c switch
    {
        (byte)' ' => 6,
        (byte)'e' or (byte)'t' or (byte)'a' or (byte)'o' or (byte)'i' or (byte)'n' or (byte)'s' or (byte)'h' or (byte)'r' => 4, // the most frequent letters
        >= (byte)'a' and <= (byte)'z' => 3,
        >= (byte)'A' and <= (byte)'Z' => 2,
        >= (byte)'0' and <= (byte)'9' or (byte)'.' or (byte)',' or (byte)'\n' or (byte)'\r' or (byte)'\t' or (byte)'\'' or (byte)'"' or (byte)'-' => 1,
        >= 0x21 and <= 0x7E => 0,
        >= 0x80 and <= 0xBF or >= 0xC2 and <= 0xF4 => 1, // continuation and lead bytes of other scripts
        _ => -8,
    };

    /// <summary>The same for UTF-16LE: the high byte of a character is 0 for Latin text, or a script's page (Arabic 06, Cyrillic 04...).</summary>
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

    /// <summary>Readable text in UTF-8 or UTF-16LE: natural language, or structured text (JSON, XML, config / URL lines).</summary>
    private static bool ReadableText(byte[] bytes, bool utf16) => NaturalText(bytes, utf16) || StructuredText(bytes, utf16);

    private static readonly System.Text.RegularExpressions.Regex ConfigLine = new(
        @"^(?:[a-z][a-z0-9+.\-]*://[\w.\-]*[a-z][\w.\-]*\S*|[a-z_][\w.\-\[\] ]{0,63}\s*[=:]\s*\S.*|(?=[\w.\-]*[a-z])[\w\-]+(?:\.[\w\-]+)+:\d{1,5}|[a-z]:\\[\w .\\\-]*[a-z][\w .\\\-]*|/(?:[\w.\-]*[a-z][\w.\-]*/?)+|#\s*[a-z].*|;\s*[a-z].*|\[[a-z][^\]]*\])$",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>
    /// Configuration hidden this way is usually structured, not prose: JSON (tokens read without error, a cut sample
    /// allowed), XML (tags, well-formed when whole), or lines that are almost all URLs, key=value / key: value pairs,
    /// host:port, paths, comments or [sections]. Printable, no control characters but whitespace, 24+ characters.
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
        if (text.Count(char.IsLetter) < text.Count(c => !char.IsWhiteSpace(c)) * 0.3) return false; // tables of numbers are not configuration

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
            if (System.Text.RegularExpressions.Regex.Matches(text, @"<[A-Za-z_][\w.:\-]*(\s[^<>]*)?/?>").Count < 3) return false;
            try
            {
                using var xml = System.Xml.XmlReader.Create(new StringReader(text), new System.Xml.XmlReaderSettings { DtdProcessing = System.Xml.DtdProcessing.Prohibit, XmlResolver = null });
                while (xml.Read()) { }
                return true;
            }
            catch (System.Xml.XmlException ex)
            {
                // a sample cut inside the document: well-formed as far as it goes
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
        // real text stays within its script, Latin, digits and the usual punctuation; data decoded with a wrong key
        // scatters over unrelated blocks (U+FFDF, Lepcha, Glagolitic, zero-width marks)
        int stray = text.Count(c => !(char.IsWhiteSpace(c) || c is >= ' ' and <= '~' || char.IsLetter(c) && (Script(c) == dominant || Script(c) == 0)
                                      || c is >= '\u2010' and <= '\u205E' or >= '\u3000' and <= '\u303F' or >= '\uFF01' and <= '\uFF5E'
                                      || char.IsDigit(c) || (char.IsPunctuation(c) && Script(c) == dominant)));
        if (stray > text.Length * 0.03) return false;
        if (dominant == 0)
        {
            // Latin-script words have vowels; decoded tables give consonant runs ("Rmjb Qafn")
            // and words of real length: decoded tables give runs of two letters ("gi cj cd nd ag")
            var wordLengths = System.Text.RegularExpressions.Regex.Matches(text, @"\p{L}+").Select(m => m.Length).ToList();
            if (wordLengths.Count >= 10 && wordLengths.Average() < 3.0) return false;
            var runs = System.Text.RegularExpressions.Regex.Matches(text, @"\p{L}{3,}").Select(m => m.Value).ToList();
            if (runs.Count >= 5 && runs.Count(w => w.Any(c => "aeiouyAEIOUYàáâäèéêëìíîïòóôöùúûü".Contains(c))) < runs.Count * 0.8) return false;
            if (text.Count(c => c < 128) >= text.Length * 0.9 && BigramScore(Encoding.ASCII.GetBytes(text)) < -4.2) return false;
        }
        else if (dominant is 5 or 6)
        {
            // natural Chinese / Japanese / Korean repeats its common characters; code points from random data do not
            int covered = letterChars.GroupBy(c => c).Select(g => g.Count()).OrderByDescending(n => n).Take(30).Sum();
            if (letterChars.Count >= 60 && covered < letterChars.Count * 0.35) return false;
        }
        // natural text keeps most letters in one script and repeats letter pairs; random code units that happen to be
        // letters (CJK, Hangul) spread over scripts and almost never repeat a pair
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

    /// <summary>A coarse script of a letter: Latin, Greek / Cyrillic, Hebrew / Arabic, Indic, Thai, CJK / kana, Hangul, other.</summary>
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

    /// <summary>Mean index of coincidence of the columns of a key length: the chance two bytes of a column are equal.</summary>
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

    /// <summary>A sample cut mid-character: drop the incomplete UTF-8 sequence at its end.</summary>
    private static byte[] TrimPartial(byte[] bytes, bool utf16)
    {
        if (utf16) return bytes;
        int end = bytes.Length, back = 0;
        while (end > 0 && back < 3 && (bytes[end - 1] & 0xC0) == 0x80) { end--; back++; }
        if (end > 0 && bytes[end - 1] >= 0xC0) return bytes[..(end - 1)]; // a lead byte whose continuation is cut off
        return back > 0 && end > 0 && bytes[end - 1] < 0x80 ? bytes[..end] : bytes;
    }

    /// <summary>
    /// Every other byte drawn from a handful of values (the top three fill 80% of the even or of the odd positions):
    /// UTF-16 text decoded as if it were UTF-8, not UTF-8 text.
    /// </summary>
    private static bool Utf16Shaped(byte[] bytes)
    {
        // (text in another script alternates lead and continuation bytes too, but is not ASCII)
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

    /// <summary>A key that is a shorter key repeated (abcabc): the shorter one.</summary>
    private static byte[] Shortest(byte[] key)
    {
        for (int p = 1; p < key.Length; p++)
            if (key.Length % p == 0 && Enumerable.Range(0, key.Length).All(i => key[i] == key[i % p])) return key[..p];
        return key;
    }

    /// <summary>Decoded text that is mostly the same block of the key's length again and again: a structure, not text.</summary>
    private static bool Repeats(byte[] decoded, int length)
    {
        int width = Math.Max(length, 4), blocks = decoded.Length / width;
        if (blocks < 4) return false;
        var seen = new HashSet<string>();
        for (int b = 0; b < blocks; b++) seen.Add(Convert.ToHexString(decoded, b * width, width));
        return seen.Count < blocks / 2;
    }

    /// <summary>
    /// A gzip stream that decompresses to something, with reserved flag bits clear and a trailer whose size field matches
    /// (a 3-byte key always reproduces the 3-byte magic, and the decompressor accepts some garbage without error).
    /// </summary>
    private static bool IsRealGzip(byte[] data)
    {
        if (data.Length < 18 || (data[3] & 0xE0) != 0) return false;
        if (Blob.TryDecompress(data, "gzip", 64L * 1024 * 1024) is not { Length: > 0 } inflated) return false;
        return BitConverter.ToUInt32(data, data.Length - 4) == (uint)inflated.Length;
    }

    /// <summary>
    /// A zip archive that opens: a central directory with at least one entry whose names are printable. (A key recovered
    /// from the 4-byte local header always reproduces that header, so the header alone proves nothing.)
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
                // a key longer than half the known header is not confirmed by repetition: only trust it if the result parses
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
