using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace Corvus.Tests;

/// <summary>An in-test PDF writer: numbered objects (dictionaries as text, optional stream data), an xref table and trailer, incremental updates and RC4 encryption.</summary>
internal sealed class PdfFixtures
{
    private readonly List<(int Number, string Body, byte[]? Stream)> _objects = [];
    private readonly List<List<(int Number, string Body, byte[]? Stream)>> _updates = [];
    public string TrailerExtra { get; set; } = "";
    public byte[]? EncryptionKey { get; private set; }

    public PdfFixtures Add(int number, string body, byte[]? stream = null)
    {
        _objects.Add((number, body, stream));
        return this;
    }

    /// <summary>A later revision appended after the first %%EOF.</summary>
    public PdfFixtures Update(params (int Number, string Body)[] objects)
    {
        _updates.Add([.. objects.Select(o => (o.Number, o.Body, (byte[]?)null))]);
        return this;
    }

    public static byte[] Deflate(byte[] data)
    {
        var ms = new MemoryStream();
        using (var z = new ZLibStream(ms, CompressionLevel.Optimal, leaveOpen: true)) z.Write(data);
        return ms.ToArray();
    }

    public static byte[] Deflate(string text) => Deflate(Encoding.Latin1.GetBytes(text));

    private static readonly byte[] Pad =
    [
        0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
        0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
    ];

    private static readonly byte[] Id = Enumerable.Range(0, 16).Select(i => (byte)(i * 11)).ToArray();

    /// <summary>Encrypts strings in parentheses and streams with RC4 128-bit, revision 3, the empty user password; object <paramref name="number"/> holds the /Encrypt dictionary.</summary>
    public PdfFixtures EncryptRc4(int number, string ownerPassword = "owner")
    {
        // algorithm 3: O from the owner password; algorithm 2: the file key; algorithm 5: U
        var ownerKey = MD5.HashData(Padded(ownerPassword));
        for (int i = 0; i < 50; i++) ownerKey = MD5.HashData(ownerKey);
        var o = Rc4(ownerKey, Pad);
        for (int i = 1; i <= 19; i++) o = Rc4(ownerKey.Select(k => (byte)(k ^ i)).ToArray(), o);
        int p = -4;
        var key = MD5.HashData([.. Pad, .. o, .. BitConverter.GetBytes(p), .. Id]);
        for (int i = 0; i < 50; i++) key = MD5.HashData(key);
        var u = Rc4(key, MD5.HashData([.. Pad, .. Id]));
        for (int i = 1; i <= 19; i++) u = Rc4(key.Select(k => (byte)(k ^ i)).ToArray(), u);
        EncryptionKey = key;
        Add(number, $"<< /Filter /Standard /V 2 /R 3 /Length 128 /P {p} /O <{Convert.ToHexString(o)}> /U <{Convert.ToHexString(u)}{new string('0', 32)}> >>");
        TrailerExtra += $" /Encrypt {number} 0 R";
        _encryptObject = number;
        return this;
    }

    private int _encryptObject = -1;

    private static byte[] Padded(string password) => [.. Encoding.Latin1.GetBytes(password).Take(32), .. Pad.Take(32 - Math.Min(32, password.Length))];

    public static byte[] Rc4(byte[] key, byte[] data)
    {
        var s = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
        for (int i = 0, j = 0; i < 256; i++) { j = (j + s[i] + key[i % key.Length]) & 0xFF; (s[i], s[j]) = (s[j], s[i]); }
        var o = new byte[data.Length];
        for (int k = 0, i = 0, j = 0; k < data.Length; k++)
        {
            i = (i + 1) & 0xFF; j = (j + s[i]) & 0xFF; (s[i], s[j]) = (s[j], s[i]);
            o[k] = (byte)(data[k] ^ s[(s[i] + s[j]) & 0xFF]);
        }
        return o;
    }

    private byte[] ObjectKey(int number) =>
        MD5.HashData([.. EncryptionKey!, (byte)number, (byte)(number >> 8), (byte)(number >> 16), 0, 0])[..16];

    /// <summary>Literal strings "(...)" without escapes rewritten as encrypted hex strings.</summary>
    private string EncryptStrings(int number, string body) =>
        System.Text.RegularExpressions.Regex.Replace(body, @"\(([^()\\]*)\)", m => "<" + Convert.ToHexString(Rc4(ObjectKey(number), Encoding.Latin1.GetBytes(m.Groups[1].Value))) + ">");

    public byte[] Build(string version = "1.7")
    {
        var output = new MemoryStream();
        void Text(string s) => output.Write(Encoding.Latin1.GetBytes(s));
        Text($"%PDF-{version}\n%âãÏÓ\n");
        int size = 0;
        void Section(List<(int Number, string Body, byte[]? Stream)> objects, long? previous)
        {
            var offsets = new SortedDictionary<int, long>();
            foreach (var (number, body0, stream0) in objects)
            {
                offsets[number] = output.Position;
                var encrypt = EncryptionKey != null && number != _encryptObject;
                var body = encrypt ? EncryptStrings(number, body0) : body0;
                var stream = stream0 != null && encrypt ? Rc4(ObjectKey(number), stream0) : stream0;
                if (stream != null && !body.Contains("/Length", StringComparison.Ordinal)) body = body.TrimEnd().TrimEnd('>').TrimEnd('>') + $" /Length {stream.Length} >>";
                Text($"{number} 0 obj\n{body}\n");
                if (stream != null) { Text("stream\n"); output.Write(stream); Text("\nendstream\n"); }
                Text("endobj\n");
                size = Math.Max(size, number + 1);
            }
            long xref = output.Position;
            Text("xref\n");
            foreach (var (number, at) in offsets) Text($"{number} 1\n{at:D10} 00000 n \n");
            var prev = previous is { } p ? $" /Prev {p}" : "";
            var id = $" /ID [<{Convert.ToHexString(Id)}> <{Convert.ToHexString(Id)}>]";
            Text($"trailer\n<< /Size {size} /Root 1 0 R{TrailerExtra}{id}{prev} >>\nstartxref\n{xref}\n%%EOF\n");
            _lastXref = xref;
        }
        Section(_objects, null);
        foreach (var update in _updates) Section(update, _lastXref);
        return output.ToArray();
    }

    private long _lastXref;
}
