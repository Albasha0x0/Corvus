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
/// 3) file, so XOR straight over text is not decoded. Raw deflate is accepted only when the result is a recognized kind
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

    public static List<EmbeddedContent> Find(ModuleScan scan, AnalysisLimits limits, CancellationToken ct)
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
            if (r.Bytes != null) Examine(r.Bytes, source, [], Add, limits, reportRaw: true);
            else if (r.Text != null && r.Text.Length >= MinStringLength) ExamineText(r.Text, source, Add, limits);
        }
        foreach (var d in scan.Data)
        {
            ct.ThrowIfCancellationRequested();
            if (d.Data.Length < MinBlobLength) continue;
            var used = d.UsedIn.Count > 0 ? $" (used in {Format.MemberLabel(d.UsedIn[0])}{(d.UsedIn.Count > 1 ? $" +{d.UsedIn.Count - 1}" : "")})" : "";
            Examine(d.Data, $"static data {Format.MemberLabel(d.Field)}{used}", [], Add, limits, reportRaw: true);
        }
        foreach (var s in scan.Strings)
        {
            ct.ThrowIfCancellationRequested();
            if (s.Value.Length >= MinStringLength) ExamineText(s.Value, $"string {s.Location.Where}", Add, limits);
        }
        return found;
    }

    /// <summary>
    /// Text that may be hex or base64; plain text is not a payload by itself. Hex is tried first: every hex string is
    /// also made of base64 characters, so base64 first would decode hex into garbage.
    /// </summary>
    private static void ExamineText(string text, string source, Action<EmbeddedContent> add, AnalysisLimits limits)
    {
        var trimmed = text.Trim();
        if (TryHex(trimmed, limits) is { } hex) Examine(hex, source, ["hex"], add, limits, reportRaw: false);
        else if (TryBase64(trimmed, limits) is { } b64) Examine(b64, source, ["base64"], add, limits, reportRaw: false);
    }

    /// <summary>
    /// Decodes <paramref name="data"/> as far as it goes and reports the result. <paramref name="reportRaw"/>: also report
    /// undecoded data that is a recognized binary kind or has high entropy (resources and static arrays, not decoded strings).
    /// </summary>
    private static void Examine(byte[] data, string source, List<string> chain, Action<EmbeddedContent> add, AnalysisLimits limits, bool reportRaw)
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
            Examine(inflated, source, [.. chain, kind], add, limits, reportRaw: true);
            return;
        }
        // text that is itself encoded, or readable text produced by decoding
        if (kind == "text")
        {
            var text = Encoding.UTF8.GetString(data).Trim();
            if (TryHex(text, limits) is { } hex) { Examine(hex, source, [.. chain, "hex"], add, limits, reportRaw: true); return; } // before base64: see ExamineText
            if (TryBase64(text, limits) is { } b64) { Examine(b64, source, [.. chain, "base64"], add, limits, reportRaw: true); return; }
            if (chain.Count > 0 && text.Length >= 16) add(Make(data, source, chain, "text"));
            return;
        }
        // XOR with a key recovered from a known file header
        if (data.Length >= MinBlobLength && TryXor(data) is { } xor)
        {
            Examine(xor.Decoded, source, [.. chain, $"xor key {Convert.ToHexStringLower(xor.Key)}"], add, limits, reportRaw: true);
            return;
        }
        // raw deflate (Costura, custom packers): only accept a result that is recognizable
        if (data.Length >= MinBlobLength && Blob.TryDecompress(data, "deflate", limits.MaxItemBytes) is { Length: > 0 } deflated
            && (IsBinaryKind(Blob.Identify(deflated)) || Blob.Identify(deflated) == "text" && deflated.Length >= 32))
        {
            Examine(deflated, source, [.. chain, "deflate"], add, limits, reportRaw: true);
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
