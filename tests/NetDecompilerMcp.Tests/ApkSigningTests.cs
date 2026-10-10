using System.Security.Cryptography;
using NetDecompilerMcp.Core.Mobile;
using static NetDecompilerMcp.Tests.ApkTestSigner;

namespace NetDecompilerMcp.Tests;

/// <summary>APK signature verification over APKs signed by <see cref="ApkTestSigner"/>: every scheme, tampering, stripping, rotation.</summary>
public class ApkSigningTests
{
    private static readonly Key Signer = Rsa("CN=Android Debug, O=Android, C=US");
    private static readonly Key EcSigner = Ec();

    private static byte[] FullySigned(Key key) =>
        SignBlocks(Zip(SignV1(Entries, key)), (ApkSigning.V2BlockId, false, [new(key)]), (ApkSigning.V3BlockId, true, [new(key, MinSdk: 24)]));

    [Fact]
    public void V1V2V3_AreVerified_WithCertificateDetails()
    {
        var report = ApkSigning.Verify(FullySigned(Signer));
        Assert.True(report.Verdict == ApkSigning.Verified, Describe(report));
        Assert.Equal(["v1", "v2", "v3"], report.Schemes.Select(s => s.Scheme));
        Assert.Contains(ApkSigning.V2BlockId, report.BlockIds);
        var v3 = report.Schemes[2].Signers.Single();
        Assert.Equal(24, v3.MinSdk);
        Assert.Equal(int.MaxValue, v3.MaxSdk);
        var cert = v3.Certificates.Single();
        Assert.True(cert.IsDebug);
        Assert.Equal("RSA", cert.KeyAlgorithm);
        Assert.Equal(2048, cert.KeySize);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Signer.Cert.RawData)), cert.Sha256);
        Assert.Equal(["RSASSA-PKCS1-v1_5 with SHA2-256"], v3.Algorithms);
        Assert.Equal(cert.Sha256, report.Schemes[0].Signers.Single().Certificates.Single().Sha256);
    }

    [Fact]
    public void EcdsaAndRsaPss_AndPerSectionV1Digests_AreVerified()
    {
        var pss = Rsa(algorithm: 0x0102);
        var apk = SignBlocks(Zip(SignV1(Entries, EcSigner, apkSigned: "2", wholeManifestDigest: false)),
            (ApkSigning.V2BlockId, false, [new(EcSigner), new(pss)]));
        var report = ApkSigning.Verify(apk);
        Assert.True(report.Verdict == ApkSigning.Verified, Describe(report));
        Assert.Equal(2, report.Schemes[1].Signers.Count);
        Assert.Equal("EC", report.Schemes[0].Signers.Single().Certificates.Single().KeyAlgorithm);
    }

    [Fact]
    public void ChangedContent_IsAMismatchInEveryScheme()
    {
        var apk = FullySigned(Signer);
        // The stored classes.dex payload follows its local header; flip one of its bytes.
        int at = IndexOf(apk, "classes.dex"u8) + "classes.dex".Length + 100;
        apk[at] ^= 0xFF;
        var report = ApkSigning.Verify(apk);
        Assert.Equal(ApkSigning.Mismatch, report.Verdict);
        Assert.All(report.Schemes, s => Assert.Equal(ApkSigning.Mismatch, s.Verdict));
        Assert.Contains(report.Schemes[1].Signers.Single().Reasons, r => r.Contains("content digest differs"));
    }

    [Fact]
    public void AddedEntry_AndBrokenSignature_AreMismatches()
    {
        var apk = SignBlocks(Zip([.. SignV1(Entries, Signer, apkSigned: null), ("extra.txt", "x"u8.ToArray())]),
            (ApkSigning.V2BlockId, false, [new(Signer, BreakSignature: true)]));
        var report = ApkSigning.Verify(apk);
        Assert.Contains(report.Schemes[0].Reasons, r => r.Contains("extra.txt is not in the manifest"));
        Assert.Contains(report.Schemes[1].Signers.Single().Reasons, r => r.Contains("does not verify"));
    }

    [Fact]
    public void StrippedNewerSchemes_AreDetected()
    {
        // v1 says v2 and v3 were made, the v2 signer says v3 was made; only v2 is present.
        var apk = SignBlocks(Zip(SignV1(Entries, Signer)), (ApkSigning.V2BlockId, false, [new(Signer, StrippingProtection: true)]));
        var report = ApkSigning.Verify(apk);
        Assert.Equal(ApkSigning.Mismatch, report.Verdict);
        Assert.Contains(report.Schemes[0].Signers.Single().Reasons, r => r.Contains("v3 signature was made") && r.Contains("stripped"));
        Assert.Contains(report.Schemes[1].Signers.Single().Reasons, r => r.Contains("stripped"));
    }

    [Fact]
    public void Rotation_V3AndV31_LineageIsVerified()
    {
        var lineage = Lineage(Signer, EcSigner);
        var apk = SignBlocks(Zip(Entries),
            (ApkSigning.V3BlockId, true, [new(Signer, MaxSdk: 32)]),
            (ApkSigning.V31BlockId, true, [new(EcSigner, MinSdk: 33, Lineage: lineage)]));
        var report = ApkSigning.Verify(apk);
        Assert.True(report.Verdict == ApkSigning.Verified, Describe(report));
        var v31 = report.Schemes.Single(s => s.Scheme == "v3.1").Signers.Single();
        Assert.Equal(33, v31.MinSdk);
        Assert.Equal(2, v31.Lineage.Count);
        Assert.Equal("RSA", v31.Lineage[0].Certificate.KeyAlgorithm);
        Assert.Equal("EC", v31.Lineage[1].Certificate.KeyAlgorithm);
        Assert.Contains(0x3ba06f8cu, v31.AttributeIds);

        var broken = ApkSigning.Verify(SignBlocks(Zip(Entries), (ApkSigning.V3BlockId, true, [new(EcSigner, Lineage: Lineage(Signer, EcSigner, breakIt: true))])));
        Assert.Contains(broken.Schemes.Single().Signers.Single().Reasons, r => r.Contains("not signed by the previous certificate"));
        var wrongEnd = ApkSigning.Verify(SignBlocks(Zip(Entries), (ApkSigning.V3BlockId, true, [new(Signer, Lineage: lineage)])));
        Assert.Contains(wrongEnd.Schemes.Single().Signers.Single().Reasons, r => r.Contains("does not end at the signer"));
    }

    [Fact]
    public void V4_IdsigIsVerified_AndAWrongRootIsAMismatch()
    {
        var apk = SignBlocks(Zip(Entries), (ApkSigning.V2BlockId, false, [new(Signer)]));
        var (cd, eocd) = Layout(Zip(Entries));
        var digest = ContentDigest(Zip(Entries), cd, eocd, HashAlgorithmName.SHA256);
        var report = ApkSigning.Verify(apk, V4(apk, Signer, digest));
        Assert.True(report.Verdict == ApkSigning.Verified, Describe(report));
        Assert.Equal("v4", report.Schemes[^1].Scheme);

        var wrong = ApkSigning.Verify(apk, V4(apk, Signer, digest, rootOverride: new byte[32]));
        Assert.Contains(wrong.Schemes[^1].Signers.Single().Reasons, r => r.Contains("Merkle root differs"));
        Assert.Contains(ApkSigning.Verify(apk, V4(apk, Signer, new byte[32])).Schemes[^1].Signers.Single().Reasons, r => r.Contains("APK digest"));
    }

    [Fact]
    public void Unsigned_UnknownAlgorithm_AndNotAZip()
    {
        Assert.Equal(ApkSigning.Unsigned, ApkSigning.Verify(Zip(Entries)).Verdict);
        var notZip = ApkSigning.Verify(new byte[100]);
        Assert.Equal(ApkSigning.Unsigned, notZip.Verdict);
        Assert.NotEmpty(notZip.Issues);
        var unknown = ApkSigning.Verify(SignBlocks(Zip(Entries), (ApkSigning.V2BlockId, false, [new(Signer, AlgorithmOverride: 0x0999)])));
        Assert.Equal(ApkSigning.Unsupported, unknown.Verdict);
        // A verity-only signer: the signature verifies, the verity digest is not recomputed.
        var verity = ApkSigning.Verify(SignBlocks(Zip(Entries), (ApkSigning.V2BlockId, false, [new(Signer, AlgorithmOverride: 0x0421)])));
        Assert.Equal(ApkSigning.Unsupported, verity.Verdict);
        Assert.Contains(verity.Schemes[0].Signers[0].Reasons, r => r.Contains("verity"));
    }

    [Fact]
    public void MutatedApks_NeverThrow() => Fuzz(60, 120);

    [Fact]
    [Trait("Speed", "Slow")]
    public void MutatedApks_NeverThrow_Long() => Fuzz(1000, 2000);

    private static void Fuzz(int whole, int block)
    {
        var apk = FullySigned(EcSigner);
        var failures = FormatFuzz.Run(apk, b => ApkSigning.Verify(b), whole);
        // Mutations focused on the signing block (it ends at the central directory), where the length-prefixed structures are.
        var (cd, _) = Layout(apk);
        int start = (int)Math.Max(0, cd - 1500);
        var region = apk.AsSpan(start, (int)cd - start).ToArray();
        failures.AddRange(FormatFuzz.Run(region, b =>
        {
            var copy = (byte[])apk.Clone();
            b.AsSpan(0, Math.Min(b.Length, region.Length)).CopyTo(copy.AsSpan(start));
            ApkSigning.Verify(copy);
        }, block));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    private static int IndexOf(byte[] data, ReadOnlySpan<byte> what) => data.AsSpan().IndexOf(what);

    private static string Describe(ApkSignatureReport r) =>
        string.Join("\n", r.Schemes.Select(s => $"{s.Scheme}: {s.Verdict} {string.Join("; ", s.Reasons)} | " +
            string.Join(" | ", s.Signers.Select(x => $"{x.Verdict}: {string.Join("; ", x.Reasons)}")))) + "\n" + string.Join("\n", r.Issues);
}
