using System.Security.Cryptography;

namespace Corvus.Core.Documents;

/// <summary>
/// The PDF standard security handler opened with the empty user password, which a document that opens without asking for
/// one carries: RC4 (40 to 128 bits, revisions 2 to 4), AES-128 (AESV2) and AES-256 (AESV3, revisions 5 and 6). A file
/// that needs a password stays encrypted, with a note.
/// </summary>
internal sealed class PdfSecurity
{
    private static readonly byte[] Pad =
    [
        0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
        0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
    ];

    private readonly byte[] _key;
    private readonly string _streamMethod, _stringMethod;
    public string Description { get; }

    private PdfSecurity(byte[] key, string streams, string strings, string description)
    {
        _key = key;
        _streamMethod = streams;
        _stringMethod = strings;
        Description = description;
    }

    /// <summary>The handler of an encrypted file opened with the empty password; null when the file is not encrypted or the password is not empty (noted).</summary>
    public static PdfSecurity? Open(PdfFile pdf)
    {
        var trailer = pdf.Trailer;
        if (trailer == null || trailer["Encrypt"] == null) return null;
        if (pdf.Resolve(trailer["Encrypt"]) is not PdfDict e) { pdf.Notes.Add("the /Encrypt dictionary is missing"); return null; }
        try
        {
            var s = Standard(pdf, e, trailer);
            pdf.Notes.Add(s == null ? "encrypted with a user password: strings and streams are not decrypted" : $"encrypted ({s.Description}) with the empty user password: decrypted");
            return s;
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or IndexOutOfRangeException or InvalidCastException)
        {
            pdf.Notes.Add($"the encryption dictionary is damaged: {ex.Message}");
            return null;
        }
    }

    private static PdfSecurity? Standard(PdfFile pdf, PdfDict e, PdfDict trailer)
    {
        if (e.Name("Filter") != "Standard") { pdf.Notes.Add($"security handler /{e.Name("Filter")} is not read"); return null; }
        int v = Int(pdf.Resolve(e["V"]), 0), r = Int(pdf.Resolve(e["R"]), 2);
        byte[] o = Bytes(pdf.Resolve(e["O"])), u = Bytes(pdf.Resolve(e["U"]));
        string streams = "RC4", strings = "RC4";
        if (v >= 4)
        {
            var cf = pdf.Resolve(e["CF"]) as PdfDict;
            string Method(string key)
            {
                var name = e.Name(key) ?? "Identity";
                if (name == "Identity") return "Identity";
                var f = pdf.Resolve(cf?[name]) as PdfDict;
                return f?.Name("CFM") switch { "AESV2" => "AES", "AESV3" => "AES", "V2" => "RC4", "None" => "Identity", _ => "RC4" };
            }
            streams = Method("StmF");
            strings = Method("StrF");
        }
        if (r >= 5)
        {
            if (u.Length < 48 || Bytes(pdf.Resolve(e["UE"])) is not { Length: >= 32 } ue) return null;
            var check = r == 5 ? SHA256.HashData(u.AsSpan(32, 8)) : Hash2B([], u.AsSpan(32, 8).ToArray(), []);
            if (!check.AsSpan(0, 32).SequenceEqual(u.AsSpan(0, 32))) return null;
            var intermediate = r == 5 ? SHA256.HashData(u.AsSpan(40, 8)) : Hash2B([], u.AsSpan(40, 8).ToArray(), []);
            using var aes = Aes.Create();
            aes.Key = intermediate[..32];
            var key = aes.DecryptCbc(ue.AsSpan(0, 32), new byte[16], PaddingMode.None);
            return new PdfSecurity(key, streams, strings, $"AES-256, revision {r}");
        }
        int length = r == 2 ? 5 : Math.Clamp(Int(pdf.Resolve(e["Length"]), 40) / 8, 5, 16);
        var id = pdf.Resolve(trailer["ID"]) is PdfArray { Items.Count: > 0 } ids && pdf.Resolve(ids.Items[0]) is PdfString first ? first.Bytes : [];
        // /P is a signed 32-bit value; some writers store its unsigned form
        int p = pdf.Resolve(e["P"]) is PdfNumber pn ? unchecked((int)(long)pn.Value) : 0;
        bool metadata = pdf.Resolve(e["EncryptMetadata"]) is not PdfKeyword { Value: "false" };
        var input = new List<byte>(Pad);
        input.AddRange(o.Take(32));
        input.AddRange(BitConverter.GetBytes(p));
        input.AddRange(id);
        if (r >= 4 && !metadata) input.AddRange([0xFF, 0xFF, 0xFF, 0xFF]);
        var hash = MD5.HashData([.. input]);
        if (r >= 3) for (int i = 0; i < 50; i++) hash = MD5.HashData(hash.AsSpan(0, length));
        var fileKey = hash[..length];
        // the empty user password checks against /U
        bool ok;
        if (r == 2) ok = Rc4(fileKey, Pad).AsSpan().SequenceEqual(u.AsSpan(0, Math.Min(32, u.Length)));
        else
        {
            var x = Rc4(fileKey, MD5.HashData([.. Pad, .. id]));
            for (int i = 1; i <= 19; i++) x = Rc4(fileKey.Select(k => (byte)(k ^ i)).ToArray(), x);
            ok = u.Length >= 16 && x.AsSpan().SequenceEqual(u.AsSpan(0, 16));
        }
        return ok ? new PdfSecurity(fileKey, streams, strings, $"{(streams == "AES" ? "AES-128" : $"RC4 {length * 8}-bit")}, revision {r}") : null;
    }

    /// <summary>ISO 32000-2 algorithm 2.B (revision 6).</summary>
    private static byte[] Hash2B(byte[] password, byte[] salt, byte[] userKey)
    {
        var k = SHA256.HashData([.. password, .. salt, .. userKey]);
        using var aes = Aes.Create();
        for (int round = 0; ; round++)
        {
            var one = new List<byte>(password.Length + k.Length + userKey.Length);
            one.AddRange(password); one.AddRange(k); one.AddRange(userKey);
            var k1 = new byte[one.Count * 64];
            for (int i = 0; i < 64; i++) one.CopyTo(k1, i * one.Count);
            aes.Key = k[..16];
            var encrypted = aes.EncryptCbc(k1, k.AsSpan(16, 16), PaddingMode.None);
            int sum = 0;
            for (int i = 0; i < 16; i++) sum += encrypted[i];
            k = (sum % 3) switch { 0 => SHA256.HashData(encrypted), 1 => SHA384.HashData(encrypted), _ => SHA512.HashData(encrypted) };
            if (round >= 63 && encrypted[^1] <= round - 32) break;
            if (round > 1000) break;
        }
        return k[..32];
    }

    /// <summary>The bytes of a string or stream of object (<paramref name="number"/>, <paramref name="generation"/>) decrypted.</summary>
    public byte[] Decrypt(byte[] data, int number, int generation, bool stream)
    {
        var method = stream ? _streamMethod : _stringMethod;
        if (method == "Identity") return data;
        byte[] key = _key;
        if (_key.Length != 32)
        {
            var input = new List<byte>(_key) { (byte)number, (byte)(number >> 8), (byte)(number >> 16), (byte)generation, (byte)(generation >> 8) };
            if (method == "AES") input.AddRange("sAlT"u8.ToArray());
            key = MD5.HashData([.. input])[..Math.Min(_key.Length + 5, 16)];
        }
        if (method == "RC4") return Rc4(key, data);
        if (data.Length < 32 || data.Length % 16 != 0) return data.Length >= 16 ? data[16..] : [];
        using var aes = Aes.Create();
        aes.Key = key;
        try { return aes.DecryptCbc(data.AsSpan(16), data.AsSpan(0, 16), PaddingMode.PKCS7); }
        catch (CryptographicException) { return aes.DecryptCbc(data.AsSpan(16), data.AsSpan(0, 16), PaddingMode.None); }
    }

    private static byte[] Rc4(byte[] key, byte[] data)
    {
        var s = new byte[256];
        for (int i = 0; i < 256; i++) s[i] = (byte)i;
        for (int i = 0, j = 0; i < 256; i++)
        {
            j = (j + s[i] + key[i % key.Length]) & 0xFF;
            (s[i], s[j]) = (s[j], s[i]);
        }
        var o = new byte[data.Length];
        for (int k = 0, i = 0, j = 0; k < data.Length; k++)
        {
            i = (i + 1) & 0xFF;
            j = (j + s[i]) & 0xFF;
            (s[i], s[j]) = (s[j], s[i]);
            o[k] = (byte)(data[k] ^ s[(s[i] + s[j]) & 0xFF]);
        }
        return o;
    }

    private static int Int(PdfValue? v, int fallback) => v is PdfNumber n ? (int)n.Value : fallback;
    private static byte[] Bytes(PdfValue? v) => v is PdfString s ? s.Bytes : [];
}
