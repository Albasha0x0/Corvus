using System.Security.Cryptography;
using System.Text;

namespace Corvus.Tests;

/// <summary>Writes a small PDF under the standard security handler, revisions 2 to 4 (ISO 32000-1 7.6.3), with RC4 or AESV2.</summary>
internal sealed class PdfAesV2Fixtures
{
    private static readonly byte[] Pad =
    [
        0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
        0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
    ];

    private static readonly byte[] Id = Enumerable.Range(0, 16).Select(i => (byte)(i * 7 + 3)).ToArray();

    public const string Target = "notepad.exe";
    public const string Script = "app.alert('hello');";

    public int Revision { get; init; } = 4;
    public bool Aes { get; init; } = true;
    public bool EncryptMetadata { get; init; } = true;
    public bool IdentityStreams { get; init; }
    public bool IdentityStrings { get; init; }
    public string Filter { get; init; } = "Standard";
    public string UserPassword { get; init; } = "";
    public string OwnerPassword { get; init; } = "owner";

    /// <summary>The file with every string and stream under the handler's methods, or unchanged where a filter is /Identity.</summary>
    public byte[] Build()
    {
        int length = Revision == 2 ? 5 : 16;
        int p = -4;
        var ownerKey = MD5.HashData(Padded(OwnerPassword));
        if (Revision >= 3) for (int i = 0; i < 50; i++) ownerKey = MD5.HashData(ownerKey);
        ownerKey = ownerKey[..length];
        var o = Rc4(ownerKey, Padded(UserPassword));
        if (Revision >= 3) for (int i = 1; i <= 19; i++) o = Rc4(ownerKey.Select(k => (byte)(k ^ i)).ToArray(), o);
        var input = new List<byte>(Padded(UserPassword));
        input.AddRange(o);
        input.AddRange(BitConverter.GetBytes(p));
        input.AddRange(Id);
        if (Revision >= 4 && !EncryptMetadata) input.AddRange([0xFF, 0xFF, 0xFF, 0xFF]);
        var key = MD5.HashData([.. input]);
        if (Revision >= 3) for (int i = 0; i < 50; i++) key = MD5.HashData(key.AsSpan(0, length));
        key = key[..length];
        byte[] u;
        if (Revision == 2) u = Rc4(key, Pad);
        else
        {
            u = Rc4(key, MD5.HashData([.. Pad, .. Id]));
            for (int i = 1; i <= 19; i++) u = Rc4(key.Select(k => (byte)(k ^ i)).ToArray(), u);
            u = [.. u, .. new byte[16]];
        }

        byte[] Encipher(int number, byte[] data, bool stream)
        {
            if (stream ? IdentityStreams : IdentityStrings) return data;
            var seed = new List<byte>(key) { (byte)number, (byte)(number >> 8), (byte)(number >> 16), 0, 0 };
            if (Aes) seed.AddRange("sAlT"u8.ToArray());
            var objectKey = MD5.HashData([.. seed])[..Math.Min(length + 5, 16)];
            if (!Aes) return Rc4(objectKey, data);
            var iv = Enumerable.Range(0, 16).Select(i => (byte)(i + number)).ToArray();
            using var aes = System.Security.Cryptography.Aes.Create();
            aes.Key = objectKey;
            return [.. iv, .. aes.EncryptCbc(data, iv, PaddingMode.PKCS7)];
        }

        string Str(int number, string s) => "<" + Convert.ToHexString(Encipher(number, Encoding.Latin1.GetBytes(s), false)) + ">";

        var encrypt = Revision switch
        {
            2 => $"<< /Filter /{Filter} /V 1 /R 2 /Length 40 /P {p} /O <{Convert.ToHexString(o)}> /U <{Convert.ToHexString(u)}> >>",
            3 => $"<< /Filter /{Filter} /V 2 /R 3 /Length 128 /P {p} /O <{Convert.ToHexString(o)}> /U <{Convert.ToHexString(u)}> >>",
            _ => $"<< /Filter /{Filter} /V 4 /R 4 /Length 128 /P {p} /O <{Convert.ToHexString(o)}> /U <{Convert.ToHexString(u)}> " +
                 $"/CF << /StdCF << /CFM /{(Aes ? "AESV2" : "V2")} /AuthEvent /DocOpen /Length 16 >> >> " +
                 $"/StmF /{(IdentityStreams ? "Identity" : "StdCF")} /StrF /{(IdentityStrings ? "Identity" : "StdCF")}" +
                 $"{(EncryptMetadata ? "" : " /EncryptMetadata false")} >>",
        };

        var script = Encipher(5, Encoding.Latin1.GetBytes(Script), true);
        var metadata = EncryptMetadata ? Encipher(6, Encoding.Latin1.GetBytes("<x:xmpmeta/>"), true) : Encoding.Latin1.GetBytes("<x:xmpmeta/>");
        var objects = new (int Number, string Body, byte[]? Stream)[]
        {
            (1, "<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R /Metadata 6 0 R >>", null),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", null),
            (3, "<< /Type /Page /Parent 2 0 R >>", null),
            (4, $"<< /S /Launch /Win << /F {Str(4, Target)} >> /Next << /S /JavaScript /JS 5 0 R >> >>", null),
            (5, "<< >>", script),
            (6, "<< /Type /Metadata /Subtype /XML >>", metadata),
            (7, encrypt, null),
        };

        var output = new MemoryStream();
        void Text(string s) => output.Write(Encoding.Latin1.GetBytes(s));
        Text("%PDF-1.6\n%âãÏÓ\n");
        var offsets = new SortedDictionary<int, long>();
        foreach (var (number, body, stream) in objects)
        {
            offsets[number] = output.Position;
            var withLength = stream == null ? body : body.TrimEnd().TrimEnd('>').TrimEnd('>') + $" /Length {stream.Length} >>";
            Text($"{number} 0 obj\n{withLength}\n");
            if (stream != null) { Text("stream\n"); output.Write(stream); Text("\nendstream\n"); }
            Text("endobj\n");
        }
        long xref = output.Position;
        Text("xref\n");
        foreach (var (number, at) in offsets) Text($"{number} 1\n{at:D10} 00000 n \n");
        var hexId = Convert.ToHexString(Id);
        Text($"trailer\n<< /Size 8 /Root 1 0 R /Encrypt 7 0 R /ID [<{hexId}> <{hexId}>] >>\nstartxref\n{xref}\n%%EOF\n");
        return output.ToArray();
    }

    private static byte[] Padded(string password)
    {
        var b = Encoding.Latin1.GetBytes(password);
        return [.. b.Take(32), .. Pad.Take(32 - Math.Min(32, b.Length))];
    }

    private static byte[] Rc4(byte[] key, byte[] data) => PdfFixtures.Rc4(key, data);
}
