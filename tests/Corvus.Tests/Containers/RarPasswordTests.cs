using Corvus.Core;
using Corvus.Core.Archives;

namespace Corvus.Tests;

/// <summary>Encrypted RAR 5 archives opened with the password the caller gives, and the entries named as not read without it.</summary>
public sealed class RarPasswordTests
{
    private const string Secret = "correct horse battery";

    private static readonly (string Name, byte[] Data)[] Files = [("lib/app.bin", [.. Enumerable.Range(0, 100).Select(i => (byte)i)]), ("readme.txt", "hello"u8.ToArray())];

    private static ContainerContents Open(byte[] rar, string? password)
    {
        using var _ = ContainerPassword.Enter(password);
        return Containers.Open(rar, "locked.rar", AnalysisLimits.Default, default, allFiles: true);
    }

    [Fact]
    public void An_encrypted_rar5_opens_with_the_password()
    {
        var contents = Open(RarEncryptedFixtures.Rar5(Secret, false, Files), Secret);
        Assert.Equal(Files[0].Data, contents.Items.Single(i => i.Name == "lib/app.bin").Bytes);
        Assert.Equal(Files[1].Data, contents.Items.Single(i => i.Name == "readme.txt").Bytes);
        Assert.DoesNotContain(contents.Notes, n => n.Contains("not read"));
    }

    [Fact]
    public void An_encrypted_rar5_header_opens_with_the_password()
    {
        var contents = Open(RarEncryptedFixtures.Rar5(Secret, true, Files), Secret);
        Assert.Equal(Files[1].Data, contents.Items.Single(i => i.Name == "readme.txt").Bytes);
    }

    [Fact]
    public void A_wrong_password_names_each_rar5_entry_as_not_read()
    {
        var contents = Open(RarEncryptedFixtures.Rar5(Secret, false, Files), "another password");
        Assert.Empty(contents.Items);
        Assert.Contains("lib/app.bin: not read (the password did not decrypt it).", contents.Notes);
        Assert.Contains("readme.txt: not read (the password did not decrypt it).", contents.Notes);
        Assert.DoesNotContain(contents.Notes, n => n.Contains("another password") || n.Contains(Secret));
    }

    [Fact]
    public void An_encrypted_rar5_without_a_password_names_each_entry_as_not_read()
    {
        var contents = Open(RarEncryptedFixtures.Rar5(Secret, false, Files), null);
        Assert.Empty(contents.Items);
        Assert.Contains("lib/app.bin: not read (encrypted; pass password to read it).", contents.Notes);
        Assert.Contains("readme.txt: not read (encrypted; pass password to read it).", contents.Notes);
    }

    [Fact]
    public void An_encrypted_rar5_header_with_a_wrong_password_is_refused_by_name()
    {
        var error = Assert.Throws<ToolError>(() => Open(RarEncryptedFixtures.Rar5(Secret, true, Files), "another password"));
        Assert.Contains("locked.rar", error.Message);
        Assert.Contains("did not open with the password", error.Message);
        Assert.DoesNotContain("another password", error.Message);
    }

    [Fact]
    public void Rar5_service_names_of_an_encrypted_header_are_reported_as_unknown()
    {
        var rar = RarEncryptedFixtures.Rar5(Secret, true, Files);
        Assert.True(Rar5Streams.HeadersEncrypted(new MemoryStream(rar)));
        Assert.Empty(Rar5Streams.Names(new MemoryStream(rar)));
        Assert.Contains(Open(rar, Secret).Notes, n => n.Contains("stream records unknown"));
    }
}
