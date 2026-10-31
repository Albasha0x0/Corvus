using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Encrypted zips opened with the password the caller gives, and the entries named as not read without it.</summary>
public sealed class ArchivePasswordTests
{
    private const string Secret = "correct horse battery";

    private static readonly byte[] Assembly = File.ReadAllBytes(Env.FixturePath);

    private static readonly (string Name, byte[] Data)[] Files = [("lib/app.dll", Assembly), ("readme.txt", "hello"u8.ToArray())];

    /// <summary>A zip with every entry encrypted: ZipCrypto (APPNOTE 6.1) or WinZip AES-256 AE-2, stored without compression.</summary>
    internal static byte[] Zip(string password, bool aes, params (string Name, byte[] Data)[] files)
    {
        var output = new MemoryStream();
        var central = new MemoryStream();
        foreach (var (name, data) in files)
        {
            uint crc = aes ? 0 : Crc(data);
            var body = aes ? AesBody(data, password) : CryptoBody(data, password, crc);
            var nameBytes = Encoding.UTF8.GetBytes(name);
            // 0x9901: AE-2, vendor AE, strength 3 (256-bit), stored.
            byte[] extra = aes ? [0x01, 0x99, 7, 0, 2, 0, (byte)'A', (byte)'E', 3, 0, 0] : [];
            ushort method = aes ? (ushort)99 : (ushort)0;
            long local = output.Position;
            Write(output, 0x04034B50u, (ushort)51, (ushort)1, method, (ushort)0, (ushort)0x21, crc, (uint)body.Length, (uint)data.Length, (ushort)nameBytes.Length, (ushort)extra.Length);
            output.Write(nameBytes); output.Write(extra); output.Write(body);
            Write(central, 0x02014B50u, (ushort)51, (ushort)51, (ushort)1, method, (ushort)0, (ushort)0x21, crc, (uint)body.Length, (uint)data.Length,
                (ushort)nameBytes.Length, (ushort)extra.Length, (ushort)0, (ushort)0, (ushort)0, 0u, (uint)local);
            central.Write(nameBytes); central.Write(extra);
        }
        long start = output.Position;
        central.WriteTo(output);
        Write(output, 0x06054B50u, (ushort)0, (ushort)0, (ushort)files.Length, (ushort)files.Length, (uint)central.Length, (uint)start, (ushort)0);
        return output.ToArray();
    }

    private static void Write(Stream s, params object[] fields)
    {
        var b = new byte[4];
        foreach (var f in fields)
        {
            switch (f)
            {
                case uint u: BinaryPrimitives.WriteUInt32LittleEndian(b, u); s.Write(b); break;
                case ushort h: BinaryPrimitives.WriteUInt16LittleEndian(b, h); s.Write(b, 0, 2); break;
            }
        }
    }

    private static uint Crc(byte[] data)
    {
        uint crc = 0xFFFFFFFF;
        foreach (var b in data) crc = Step(crc, b);
        return ~crc;
    }

    private static uint Step(uint crc, byte b)
    {
        crc ^= b;
        for (int i = 0; i < 8; i++) crc = (crc & 1) != 0 ? crc >> 1 ^ 0xEDB88320 : crc >> 1;
        return crc;
    }

    private static byte[] CryptoBody(byte[] data, string password, uint crc)
    {
        uint k0 = 0x12345678, k1 = 0x23456789, k2 = 0x34567890;
        void Update(byte c)
        {
            k0 = Step(k0, c);
            k1 = (k1 + (k0 & 0xFF)) * 134775813 + 1;
            k2 = Step(k2, (byte)(k1 >> 24));
        }
        byte Next() { uint t = (k2 | 2) & 0xFFFF; return (byte)(t * (t ^ 1) >> 8); }
        foreach (var c in Encoding.UTF8.GetBytes(password)) Update(c);
        var header = new byte[12];
        RandomNumberGenerator.Fill(header.AsSpan(0, 11));
        header[11] = (byte)(crc >> 24);
        var result = new byte[12 + data.Length];
        var plain = header.Concat(data).ToArray();
        for (int i = 0; i < plain.Length; i++)
        {
            byte key = Next();
            result[i] = (byte)(plain[i] ^ key);
            Update(plain[i]);
        }
        return result;
    }

    private static byte[] AesBody(byte[] data, string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var derived = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, 1000, HashAlgorithmName.SHA1, 66);
        var key = derived[..32];
        var cipher = new byte[data.Length];
        using var aes = Aes.Create();
        aes.Key = key;
        var counter = new byte[16];
        var stream = new byte[16];
        for (int i = 0; i < data.Length; i += 16)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(counter, (ulong)(i / 16 + 1));
            aes.EncryptEcb(counter, stream, PaddingMode.None);
            for (int j = 0; j < 16 && i + j < data.Length; j++) cipher[i + j] = (byte)(data[i + j] ^ stream[j]);
        }
        var mac = HMACSHA1.HashData(derived.AsSpan(32, 32), cipher)[..10];
        return [.. salt, .. derived.AsSpan(64, 2).ToArray(), .. cipher, .. mac];
    }

    private static ContainerContents Open(byte[] zip, string? password)
    {
        using var _ = ContainerPassword.Enter(password);
        return Containers.Open(zip, "locked.zip", AnalysisLimits.Default, default, allFiles: true);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void An_encrypted_zip_opens_with_the_password(bool aes)
    {
        var contents = Open(Zip(Secret, aes, Files), Secret);
        Assert.Equal(Assembly, contents.Items.Single(i => i.Name == "lib/app.dll").Bytes);
        Assert.Equal("hello"u8.ToArray(), contents.Items.Single(i => i.Name == "readme.txt").Bytes);
        Assert.DoesNotContain(contents.Notes, n => n.Contains("not read"));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_wrong_password_names_each_entry_as_not_read(bool aes)
    {
        var contents = Open(Zip(Secret, aes, Files), "another password");
        Assert.Empty(contents.Items);
        Assert.Contains("lib/app.dll: not read (the password did not decrypt it).", contents.Notes);
        Assert.Contains("readme.txt: not read (the password did not decrypt it).", contents.Notes);
        Assert.DoesNotContain(contents.Notes, n => n.Contains("another password") || n.Contains(Secret));
    }

    [Fact]
    public void An_encrypted_zip_without_a_password_names_each_entry_as_not_read()
    {
        var contents = Open(Zip(Secret, aes: true, Files), null);
        Assert.Empty(contents.Items);
        Assert.Contains("lib/app.dll: not read (encrypted; pass password to read it).", contents.Notes);
    }

    [Fact]
    public void A_password_leaves_an_unencrypted_zip_unchanged()
    {
        var plain = new MemoryStream();
        using (var zip = new ZipArchive(plain, ZipArchiveMode.Create, leaveOpen: true))
            using (var s = zip.CreateEntry("lib/app.dll").Open()) s.Write(Assembly);
        Assert.Equal("lib/app.dll", Assert.Single(Open(plain.ToArray(), Secret).Items).Name);
    }

    [Fact]
    public void Unpack_writes_the_files_of_an_encrypted_zip_with_the_password()
    {
        using var dir = new TempDir();
        var workspace = new AssemblyWorkspace(new ServerOptions());
        var path = Path.Combine(dir.Path, "locked.zip");
        File.WriteAllBytes(path, Zip(Secret, aes: true, Files));
        var extraction = new UnpackService(workspace).Extract(path, Path.Combine(dir.Path, "out"), AnalysisLimits.Default, default, password: Secret);
        Assert.Contains(extraction.Files, f => f.Path.EndsWith("readme.txt"));
        Assert.DoesNotContain(extraction.Notes, n => n.Contains(Secret));
    }
}
