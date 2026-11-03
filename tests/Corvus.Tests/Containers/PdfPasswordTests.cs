using Corvus.Core;
using Corvus.Core.Documents;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Opening PDFs of every standard-handler revision with a given password, and the note for each refusal.</summary>
public sealed class PdfPasswordTests
{
    private static PdfFileView.Facts View(byte[] pdf, string? password)
    {
        using var _ = ContainerPassword.Enter(password);
        return (PdfFileView.Facts)new PdfFileView().Inspect(new FileInput("a.pdf", pdf, Blob.Identify(pdf)), default)!.Detail;
    }

    private static void AssertReadable(PdfFileView.Facts f)
    {
        Assert.Contains(f.Actions, a => a is { Type: "Launch" } && a.Target == PdfAesV2Fixtures.Target);
        Assert.Equal(PdfAesV2Fixtures.Script.Length, Assert.Single(f.Scripts).Length);
    }

    [Fact]
    public void An_aes_128_pdf_opens_with_the_given_user_password()
    {
        var f = View(new PdfAesV2Fixtures { UserPassword = "open sesame" }.Build(), "open sesame");
        Assert.Equal("AES-128, revision 4", f.Encryption);
        Assert.Contains("encrypted (AES-128, revision 4) with the given user password: decrypted", f.Notes);
        AssertReadable(f);
    }

    [Fact]
    public void A_wrong_password_names_an_aes_128_pdf_as_not_decrypted()
    {
        var f = View(new PdfAesV2Fixtures { UserPassword = "open sesame" }.Build(), "another password");
        Assert.Equal("user password (not decrypted)", f.Encryption);
        Assert.Contains(f.Notes, n => n.Contains("the password did not decrypt it"));
        Assert.DoesNotContain(f.Actions, a => a.Target == PdfAesV2Fixtures.Target);
    }

    [Fact]
    public void A_40_bit_rc4_pdf_opens_with_the_given_user_password()
    {
        var pdf = new PdfAesV2Fixtures { Revision = 2, Aes = false, UserPassword = "open sesame" }.Build();
        var f = View(pdf, "open sesame");
        Assert.Equal("RC4 40-bit, revision 2", f.Encryption);
        AssertReadable(f);
        Assert.Equal("user password (not decrypted)", View(pdf, "another password").Encryption);
    }

    [Fact]
    public void A_pdf_with_unencrypted_metadata_opens_with_the_given_user_password()
    {
        var f = View(new PdfAesV2Fixtures { EncryptMetadata = false, UserPassword = "open sesame" }.Build(), "open sesame");
        Assert.Equal("AES-128, revision 4", f.Encryption);
        AssertReadable(f);
    }

    [Fact]
    public void A_pdf_with_identity_stream_and_string_filters_is_read_unchanged()
    {
        var pdf = new PdfAesV2Fixtures { IdentityStreams = true, IdentityStrings = true, UserPassword = "open sesame" }.Build();
        var f = View(pdf, "open sesame");
        Assert.Contains(f.Notes, n => n.Contains("with the given user password: decrypted"));
        AssertReadable(f);
    }

    [Fact]
    public void A_non_standard_security_handler_is_named_not_read()
    {
        var f = View(new PdfAesV2Fixtures { Filter = "Custom" }.Build(), "open sesame");
        Assert.Contains("security handler /Custom is not read", f.Notes);
        Assert.DoesNotContain(f.Notes, n => n.Contains("the password did not decrypt it"));
        Assert.DoesNotContain(f.Actions, a => a.Target == PdfAesV2Fixtures.Target);
    }

    [Fact]
    public void An_owner_password_is_not_tried_and_the_note_says_so()
    {
        var pdf = new PdfAesV2Fixtures { UserPassword = "open sesame", OwnerPassword = "owner key" }.Build();
        var f = View(pdf, "owner key");
        Assert.Equal("user password (not decrypted)", f.Encryption);
        Assert.Contains(f.Notes, n => n.Contains("the owner password is not tried"));
        Assert.DoesNotContain(f.Notes, n => n.Contains("owner key"));
    }

    [Fact]
    public void A_non_ascii_password_opens_revision_3_and_revision_6()
    {
        const string password = "pässwörd é";
        var r3 = View(new PdfAesV2Fixtures { Revision = 3, Aes = false, UserPassword = password }.Build(), password);
        Assert.Equal("RC4 128-bit, revision 3", r3.Encryption);
        AssertReadable(r3);
        var r6 = View(PdfDocumentTests.Base().EncryptAes256(9, password, 6).Build(), password);
        Assert.Equal("AES-256, revision 6", r6.Encryption);
        Assert.Contains(r6.Actions, a => a.Target == "notepad.exe readme.txt");
    }
}
