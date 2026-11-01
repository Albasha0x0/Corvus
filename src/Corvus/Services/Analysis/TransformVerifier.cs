using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>
/// Dry-run encode or decode of a byte range with a block cipher.
/// Nothing is written and the key is never echoed.
/// </summary>
public static class TransformVerifier
{
    /// <summary>
    /// One run. Vector is the published vector of the algorithm and mode;
    /// Validation covers the caller's range. Direction and Padding are null
    /// when no range ran.
    /// </summary>
    public sealed record TransformRecord(string Algorithm, string Mode, string? Direction, string? Padding, long Offset, long Length, long OutputLength,
        string Vector, string Validation, string? OutputSha256)
    {
        /// <summary>Follow-up notes; null when none.</summary>
        public IReadOnlyList<string>? Notes { get; init; }

        /// <summary>Container header or XALZ block in the output; null when neither.</summary>
        public string? Structure { get; init; }
    }

    /// <summary>Algorithm names the dry run accepts.</summary>
    public static readonly IReadOnlyList<string> Algorithms = ["aes-128", "blowfish"];

    /// <summary>Mode names the dry run accepts.</summary>
    public static readonly IReadOnlyList<string> Modes = ["ecb", "cbc"];

    /// <summary>Largest range transformed in one call, bytes.</summary>
    public const long MaxRange = 64L << 20;

    // Bytes between cancellation checks; a power of two.
    private const int ChunkSize = 1 << 20;

    // Published vectors: FIPS 197 C.1, SP 800-38A F.2.1, and the Blowfish
    // zero-key and CBC test sets.
    private static readonly Dictionary<(string, string), (string Key, string Iv, string Plain, string Cipher)> Vectors = new()
    {
        [("aes-128", "ecb")] = ("000102030405060708090a0b0c0d0e0f", "", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        [("aes-128", "cbc")] = ("2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172a", "7649abac8119b246cee98e9b12e9197d"),
        [("blowfish", "ecb")] = ("0000000000000000", "", "0000000000000000", "4ef997456198dd78"),
        [("blowfish", "cbc")] = ("0123456789abcdeff0e1d2c3b4a59687", "fedcba9876543210",
            "37363534333231204e6f77206973207468652074696d6520666f722000000000",
            "6b77b4d63006dee605b156e27403979358deb9e7154616d959f1652bd5ff92cc"),
    };

    /// <summary>
    /// Runs the published vector, then the range of <paramref name="path"/>
    /// when a parameter file is given; refuses unknown names and bad parameters.
    /// </summary>
    public static TransformRecord Run(string path, string algorithm, string? mode, string? parameterFile, CancellationToken ct = default)
    {
        var alg = algorithm.Trim().ToLowerInvariant();
        var md = (mode ?? "ecb").Trim().ToLowerInvariant();
        if (!Algorithms.Contains(alg)) throw Refuse($"Unknown algorithm '{algorithm}'.", $"pass algorithm as one of {string.Join(", ", Algorithms)}");
        if (!Modes.Contains(md)) throw Refuse($"Unknown mode '{mode}'.", $"pass mode as one of {string.Join(", ", Modes)}");

        var vectorOk = CheckVector(alg, md);
        var vectorText = vectorOk ? "match" : "mismatch";
        string[] vectorNote = vectorOk ? [] : ["The published vector does not match, so this build's cipher is wrong: do not trust any range result."];
        if (parameterFile == null)
            return new TransformRecord(alg, md, null, null, 0, 0, 0, vectorText, "not run: no parameterFile", null)
            {
                Notes = [.. vectorNote, "Only the published vector ran; pass parameterFile (JSON: key, iv, expected (hex), direction, padding, offset, length) to transform a range of path."],
            };

        var p = ReadParameters(parameterFile);
        var key = Hex(Text(p, "key") ?? throw Refuse("parameterFile has no key.", "add \"key\": \"<hex>\""));
        byte[]? iv = null;
        try
        {
            var ivText = Text(p, "iv");
            if (ivText != null) iv = Hex(ivText);
            var direction = (Text(p, "direction") ?? "decode").ToLowerInvariant();
            var padding = (Text(p, "padding") ?? "pkcs7").ToLowerInvariant();
            if (direction is not ("decode" or "encode")) throw Refuse($"Unknown direction '{direction}'.", "set direction to decode or encode");
            if (padding is not ("pkcs7" or "zeros" or "none")) throw Refuse($"Unknown padding '{padding}'.", "set padding to pkcs7, zeros or none");
            long offset = Number(p, "offset", 0), length = Number(p, "length", -1);

            var full = InputFiles.RequireRegularFile(path, "range file");
            if (!File.Exists(full)) throw new ToolError(ErrorCode.NotFound, $"{full} is not a file.", "pass the file that holds the range as path");
            long size = new FileInfo(full).Length;
            if (offset < 0 || offset > size) throw Refuse($"offset {offset} is outside the {size:N0}-byte file.", "set offset between 0 and the file size");
            if (length < 0) length = size - offset;
            if (length > size - offset) throw Refuse($"length {length} runs past the file end ({size - offset:N0} bytes remain).", "shorten length or omit it");
            if (length == 0) throw Refuse($"The range is empty (offset {offset}, length 0).", "set offset and length to cover at least one block");
            if (length > MaxRange) throw Refuse($"length {length:N0} is over the {MaxRange:N0}-byte range limit.", "set a shorter length in parameterFile");
            var input = new byte[length];
            using (var fs = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                fs.Seek(offset, SeekOrigin.Begin);
                for (int at = 0; at < input.Length; at += ChunkSize)
                {
                    ct.ThrowIfCancellationRequested();
                    fs.ReadExactly(input, at, Math.Min(ChunkSize, input.Length - at));
                }
            }

            var result = Transform(alg, md, direction == "encode", key, iv, input, padding, ct, out var output, out var note);
            if (!result) throw Refuse(note, "check the key length, the iv length and that length is a whole number of blocks");
            var expected = Text(p, "expected");
            var paddingNote = direction == "decode" && padding != "none" ? note : null;
            var match = expected == null ? null : output.AsSpan().SequenceEqual(Hex(expected)) ? "expected output matches" : "expected output differs";
            var validation = match == null ? paddingNote ?? "no expected output given" : paddingNote == null ? match : $"{match}; {paddingNote}";
            return new TransformRecord(alg, md, direction, padding, offset, length, output.Length, vectorText, validation,
                Convert.ToHexStringLower(SHA256.HashData(output)))
            { Notes = vectorNote.Length == 0 ? null : vectorNote, Structure = direction == "decode" ? Structure(output) : null };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            if (iv != null) CryptographicOperations.ZeroMemory(iv);
        }
    }

    // Same readers as the image survey and the XALZ extractor.
    private static string? Structure(byte[] output) =>
        ContainerHeaderRules.DescribeLayout(output)
        ?? (Blob.TryXalz(output, MaxRange) is { } lz4 ? $"XALZ LZ4 block, {lz4.Length:N0} bytes expanded" : null);

    private static bool CheckVector(string alg, string mode)
    {
        var v = Vectors[(alg, mode)];
        byte[] key = Hex(v.Key), plain = Hex(v.Plain), cipher = Hex(v.Cipher);
        byte[]? iv = v.Iv.Length == 0 ? null : Hex(v.Iv);
        return Transform(alg, mode, true, key, iv, plain, "none", default, out var encoded, out _) && encoded.AsSpan().SequenceEqual(cipher)
            && Transform(alg, mode, false, key, iv, cipher, "none", default, out var decoded, out _) && decoded.AsSpan().SequenceEqual(plain);
    }

    // False with the reason in `note` when the parameters do not fit the
    // algorithm; otherwise `note` reports the padding.
    private static bool Transform(string alg, string mode, bool encode, byte[] key, byte[]? iv, byte[] input, string padding, CancellationToken ct, out byte[] output, out string note)
    {
        output = [];
        int size = alg == "aes-128" ? 16 : BlowfishCipher.BlockSize;
        if (alg == "aes-128" && key.Length != 16) { note = $"aes-128 takes a 16-byte key, got {key.Length}."; return false; }
        if (alg == "blowfish" && (key.Length < 4 || key.Length > 56)) { note = $"blowfish takes a 4 to 56 byte key, got {key.Length}."; return false; }
        if (mode == "cbc" && (iv == null || iv.Length != size)) { note = $"cbc needs a {size}-byte iv."; return false; }

        var data = encode ? Pad(input, size, padding) : input;
        if (data.Length % size != 0)
        {
            note = $"length {input.Length} is not a whole number of {size}-byte blocks.";
            return false;
        }

        using var aes = alg == "aes-128" ? Aes.Create() : null;
        if (aes != null) aes.Key = key;
        using var bf = aes == null ? new BlowfishCipher(key) : null;
        void Block(bool forward, byte[] from, byte[] to)
        {
            if (aes != null) { if (forward) aes.EncryptEcb(from, to, PaddingMode.None); else aes.DecryptEcb(from, to, PaddingMode.None); }
            else if (forward) bf!.EncryptBlock(from, to);
            else bf!.DecryptBlock(from, to);
        }

        var result = new byte[data.Length];
        var chain = iv?.ToArray() ?? new byte[size];
        var inBlock = new byte[size];
        var outBlock = new byte[size];
        for (int at = 0; at < data.Length; at += size)
        {
            if ((at & ChunkSize - 1) == 0) ct.ThrowIfCancellationRequested();
            Array.Copy(data, at, inBlock, 0, size);
            if (encode)
            {
                if (mode == "cbc") for (int j = 0; j < size; j++) inBlock[j] ^= chain[j];
                Block(true, inBlock, outBlock);
                Array.Copy(outBlock, chain, size);
            }
            else
            {
                Block(false, inBlock, outBlock);
                if (mode == "cbc") for (int j = 0; j < size; j++) outBlock[j] ^= chain[j];
                Array.Copy(inBlock, chain, size);
            }
            Array.Copy(outBlock, 0, result, at, size);
        }

        note = "no padding removed";
        if (!encode && padding == "pkcs7")
        {
            int n = result[^1];
            bool valid = n >= 1 && n <= size && result.AsSpan(result.Length - n).IndexOfAnyExcept((byte)n) < 0;
            note = valid ? "pkcs7 padding valid" : "pkcs7 padding invalid";
            if (valid) result = result[..^n];
        }
        else if (!encode && padding == "zeros")
        {
            int end = result.Length;
            while (end > 0 && result[end - 1] == 0) end--;
            note = $"zeros padding: {result.Length - end} trailing zero byte(s) removed";
            result = result[..end];
        }
        output = result;
        return true;
    }

    private static byte[] Pad(byte[] input, int size, string padding)
    {
        if (padding == "none") return input;
        int add = padding == "pkcs7" ? size - input.Length % size : (size - input.Length % size) % size;
        var padded = new byte[input.Length + add];
        input.CopyTo(padded, 0);
        if (padding == "pkcs7") Array.Fill(padded, (byte)add, input.Length, add);
        return padded;
    }

    private static JsonObject ReadParameters(string file)
    {
        var full = Path.GetFullPath(file);
        if (!File.Exists(full)) throw new ToolError(ErrorCode.NotFound, $"{full} is not a file.", "pass a JSON file with key, iv, direction, padding, offset, length, expected");
        try { return JsonNode.Parse(File.ReadAllText(full)) as JsonObject ?? throw new FormatException(); }
        catch (Exception e) when (e is System.Text.Json.JsonException or FormatException)
        {
            throw Refuse($"{full} is not a JSON object.", "write {\"key\": \"<hex>\", \"iv\": \"<hex>\"}");
        }
    }

    private static string? Text(JsonObject o, string name) => o[name] switch
    {
        null => null,
        JsonValue v when v.TryGetValue<string>(out var s) => s,
        _ => throw Refuse($"{name} must be a JSON string.", $"write \"{name}\" as a string in parameterFile"),
    };

    private static long Number(JsonObject o, string name, long fallback) => o[name] switch
    {
        null => fallback,
        JsonValue v when v.TryGetValue<long>(out var n) && v.GetValueKind() == System.Text.Json.JsonValueKind.Number && !v.ToJsonString().Contains('.') => n,
        _ => throw Refuse($"{name} must be a JSON integer.", $"write \"{name}\" as a whole number in parameterFile"),
    };

    private static byte[] Hex(string text)
    {
        try { return Convert.FromHexString(text.Replace(" ", "")); }
        catch (FormatException) { throw Refuse("A parameter is not hexadecimal.", "write key, iv and expected as hex digit pairs"); }
    }

    private static ToolError Refuse(string message, string next) => new(ErrorCode.InvalidArgument, message, next);
}
