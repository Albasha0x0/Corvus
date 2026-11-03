using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Encrypted 7z archives opened with the password the caller gives, and the entries named as not read without it.</summary>
public sealed class SevenZipPasswordTests
{
    private const string Secret = "correct horse battery";

    private static readonly byte[] Assembly = File.ReadAllBytes(Env.FixturePath);

    private static readonly (string Name, byte[] Data)[] Files = [("lib/app.dll", Assembly), ("readme.txt", "hello"u8.ToArray())];

    private static ContainerContents Open(byte[] archive, string? password)
    {
        using var _ = ContainerPassword.Enter(password);
        return Containers.Open(archive, "locked.7z", AnalysisLimits.Default, default, allFiles: true);
    }

    [Fact]
    public void An_encrypted_7z_opens_with_the_password()
    {
        var contents = Open(SevenZipEncryptedFixtures.Build(Secret, false, Files), Secret);
        Assert.Equal(Assembly, contents.Items.Single(i => i.Name == "lib/app.dll").Bytes);
        Assert.Equal("hello"u8.ToArray(), contents.Items.Single(i => i.Name == "readme.txt").Bytes);
        Assert.DoesNotContain(contents.Notes, n => n.Contains("not read"));
    }

    [Fact]
    public void A_wrong_password_names_each_7z_entry_as_not_read()
    {
        var contents = Open(SevenZipEncryptedFixtures.Build(Secret, false, Files), "another password");
        Assert.Empty(contents.Items);
        Assert.Contains("lib/app.dll: not read (the password did not decrypt it).", contents.Notes);
        Assert.Contains("readme.txt: not read (the password did not decrypt it).", contents.Notes);
        Assert.DoesNotContain(contents.Notes, n => n.Contains("another password") || n.Contains(Secret));
    }

    [Fact]
    public void An_encrypted_7z_without_a_password_names_each_entry_as_not_read()
    {
        var contents = Open(SevenZipEncryptedFixtures.Build(Secret, false, Files), null);
        Assert.Empty(contents.Items);
        Assert.Contains("lib/app.dll: not read (encrypted; pass password to read it).", contents.Notes);
        Assert.Contains("readme.txt: not read (encrypted; pass password to read it).", contents.Notes);
    }

    [Fact]
    public void An_encrypted_7z_header_opens_with_the_password()
    {
        var contents = Open(SevenZipEncryptedFixtures.Build(Secret, true, Files), Secret);
        Assert.Equal(Assembly, contents.Items.Single(i => i.Name == "lib/app.dll").Bytes);
        Assert.DoesNotContain(contents.Notes, n => n.Contains("not read"));
    }

    [Theory]
    [InlineData("another password")]
    [InlineData(null)]
    public void An_encrypted_7z_header_with_a_wrong_password_is_refused_by_name(string? password)
    {
        var archive = SevenZipEncryptedFixtures.Build(Secret, true, Files);
        using var _ = ContainerPassword.Enter(password);
        var error = Assert.Throws<ToolError>(() => Containers.Open(archive, "locked.7z", AnalysisLimits.Default, default, allFiles: true));
        Assert.Equal(ErrorCode.MalformedInput, error.Code);
        Assert.Contains("locked.7z", error.Message);
        Assert.Contains("password", error.Message);
        Assert.DoesNotContain("another password", error.Message);
    }

    [Fact]
    public void A_password_leaves_an_unencrypted_7z_unchanged()
    {
        var contents = Open(SevenZipEncryptedFixtures.Build(null, false, Files[1..]), Secret);
        Assert.Equal("readme.txt", Assert.Single(contents.Items).Name);
    }
}
