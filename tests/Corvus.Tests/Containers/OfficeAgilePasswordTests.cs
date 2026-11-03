using Corvus.Core;
using Corvus.Core.Documents;

namespace Corvus.Tests;

/// <summary>Agile OOXML encryption: hash algorithms, key sizes, segment boundaries and refused input.</summary>
public sealed class OfficeAgilePasswordTests
{
    private const string Secret = "caller secret";

    private static byte[] Payload(int size) => Enumerable.Range(0, size).Select(i => (byte)(i * 7 + 3)).ToArray();

    private static (byte[]? Package, string Reason) Open(byte[] package, string hash = "SHA512", int keyBits = 256, int spin = 100,
        Func<string, string>? edit = null, string password = Secret)
    {
        var (info, encrypted) = AgileEncryptionFixtures.Build(package, Secret, hash, keyBits, spin, edit);
        using var _ = ContainerPassword.Enter(password);
        return OfficeCrypto.Decrypt(info, encrypted, 1 << 20);
    }

    [Theory]
    [InlineData("SHA1")]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void An_agile_package_opens_for_each_hash_algorithm(string hash)
    {
        var payload = Payload(5000);
        var (plain, reason) = Open(payload, hash);
        Assert.Equal(payload, plain);
        Assert.Contains("agile encryption", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void An_agile_package_opens_for_a_128_bit_key()
    {
        var payload = Payload(5000);
        Assert.Equal(payload, Open(payload, "SHA1", 128).Package);
        Assert.Equal(payload, Open(payload, "SHA256", 128).Package);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4095)]
    [InlineData(4096)]
    [InlineData(4097)]
    [InlineData(9000)]
    public void An_agile_package_opens_across_segment_boundaries(int size)
    {
        var payload = Payload(size);
        Assert.Equal(payload, Open(payload).Package);
    }

    [Fact]
    public void An_agile_package_with_a_wrong_password_is_named_wrong()
    {
        var (plain, reason) = Open(Payload(100), password: "another secret");
        Assert.Null(plain);
        Assert.Equal("the password did not decrypt it", reason);
    }

    [Fact]
    public void An_agile_package_with_an_unknown_hash_is_refused_by_name()
    {
        var (plain, reason) = Open(Payload(100), edit: x => x.Replace("hashAlgorithm=\"SHA512\"", "hashAlgorithm=\"MD5\"", StringComparison.Ordinal));
        Assert.Null(plain);
        Assert.Contains("MD5", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void An_agile_package_with_a_spin_count_over_the_limit_is_refused_by_name()
    {
        var (plain, reason) = Open(Payload(100), edit: x => x.Replace("spinCount=\"100\"", "spinCount=\"10000001\"", StringComparison.Ordinal));
        Assert.Null(plain);
        Assert.Contains("spin count 10000001", reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("spinCount=\"100\"", "spinCount=\"many\"")]
    [InlineData("keyBits=\"256\" hashSize", "keyBits=\"\" hashSize")]
    [InlineData("saltValue=\"", "saltValue=\"%%")]
    [InlineData("encryptedKeyValue=\"", "encryptedKeyValue=\"%%")]
    public void An_agile_package_with_damaged_key_data_is_refused_as_damaged(string from, string to)
    {
        var (plain, reason) = Open(Payload(100), edit: x => x.Replace(from, to, StringComparison.Ordinal));
        Assert.Null(plain);
        Assert.StartsWith("damaged encryption data", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void An_agile_package_with_a_non_aes_key_cipher_is_refused_by_name()
    {
        var (plain, reason) = Open(Payload(100), edit: x => x.Replace("cipherAlgorithm=\"AES\"", "cipherAlgorithm=\"RC2\"", StringComparison.Ordinal));
        Assert.Null(plain);
        Assert.Contains("not AES", reason, StringComparison.Ordinal);
    }
}