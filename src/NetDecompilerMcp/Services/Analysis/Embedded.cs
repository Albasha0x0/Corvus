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
    /// Embedded content of <paramref name="scan"/>. <paramref name="xorText"/>: also brute-force single-byte XOR keys over
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
                Examine(textXor.Decoded, source, [.. chain, $"xor key {textXor.Key:x2} (brute-forced)"], add, limits, reportRaw: true, xorText: false);
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
        // opt-in: single-byte XOR over text (no known header to recover the key from)
        if (xorText && reportRaw && TryXorText(data) is { } brute)
        {
            Examine(brute.Decoded, source, [.. chain, $"xor key {brute.Key:x2} (brute-forced)"], add, limits, reportRaw: true, xorText: false);
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
    private const double XorTextMinScore = 0.85;
    private const double XorTextMinGain = 0.25;

    /// <summary>
    /// Single-byte XOR over text, by trying every key (1..255). A key is accepted only when the input is not readable
    /// as it is (score below 0.85) and the best decode: is at least 32 bytes; is printable text without NUL bytes
    /// (<see cref="Blob.LooksLikeText"/>); does not look like UTF-16 (one byte value in 40% or more of the even or of the
    /// odd positions); has 3-40% spaces; scores 0.85 or more; and beats the input's score by 0.25 or more. The score is
    /// the share of ASCII letters, digits, whitespace and common punctuation, with letters and spaces required to be at
    /// least 60%. Multi-byte keys, UTF-16 text and non-ASCII text are not recovered.
    /// </summary>
    internal static (byte Key, byte[] Decoded)? TryXorText(byte[] data)
    {
        if (data.Length < MinXorTextLength) return null;
        var sample = data.AsSpan(0, Math.Min(data.Length, 4096));
        double input = TextScore(sample);
        if (input >= XorTextMinScore) return null; // readable already: XOR could only shift it to other readable text
        (byte Key, double Score)? best = null;
        var decoded = new byte[sample.Length];
        for (int k = 1; k < 256; k++)
        {
            for (int i = 0; i < sample.Length; i++) decoded[i] = (byte)(sample[i] ^ k);
            if (!Blob.LooksLikeText(decoded) || LooksLikeUtf16(decoded)) continue;
            int spaces = decoded.Count(b => b == ' ');
            if (spaces < decoded.Length * 0.03 || spaces > decoded.Length * 0.40) continue;
            double score = TextScore(decoded);
            if (best == null || score > best.Value.Score) best = ((byte)k, score);
        }
        if (best is not { } b || b.Score < XorTextMinScore || b.Score - input < XorTextMinGain) return null;
        var full = new byte[data.Length];
        for (int i = 0; i < data.Length; i++) full[i] = (byte)(data[i] ^ b.Key);
        return Blob.LooksLikeText(full) ? (b.Key, full) : null;
    }

    /// <summary>Share of ASCII letters, digits, whitespace and common punctuation; 0 when letters and spaces are under 60%.</summary>
    private static double TextScore(ReadOnlySpan<byte> bytes)
    {
        int letters = 0, other = 0;
        foreach (var c in bytes)
        {
            if (c is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z' or (byte)' ') letters++;
            else if (c is >= (byte)'0' and <= (byte)'9' or (byte)'\n' or (byte)'\r' or (byte)'\t' or (byte)'.' or (byte)',' or (byte)';' or (byte)':'
                     or (byte)'\'' or (byte)'"' or (byte)'!' or (byte)'?' or (byte)'-' or (byte)'(' or (byte)')' or (byte)'/') other++;
        }
        if (bytes.Length == 0 || letters < bytes.Length * 0.6) return 0;
        return (double)(letters + other) / bytes.Length;
    }

    /// <summary>One byte value in 40% or more of the even or of the odd positions: UTF-16 text, or text XORed with UTF-16 in mind.</summary>
    private static bool LooksLikeUtf16(byte[] bytes)
    {
        foreach (int parity in new[] { 0, 1 })
        {
            var counts = new int[256];
            int n = 0;
            for (int i = parity; i < bytes.Length; i += 2) { counts[bytes[i]]++; n++; }
            if (n > 0 && counts.Max() >= n * 0.4) return true;
        }
        return false;
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
                    "zip" => Blob.Identify(decoded) == "zip" && decoded.AsSpan().LastIndexOf("PK\x05\x06"u8) >= 0,
                    _ => Blob.TryDecompress(decoded, "gzip", 64L * 1024 * 1024) != null,
                };
                if (valid) return (key, decoded);
            }
        }
        return null;
    }
}
