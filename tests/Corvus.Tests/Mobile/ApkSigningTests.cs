using System.Security.Cryptography;
using Corvus.Core.Mobile;
using static Corvus.Tests.ApkTestSigner;

namespace Corvus.Tests;

/// <summary>APK signature verification over APKs signed by <see cref="ApkTestSigner"/>: every scheme, tampering, stripping, rotation.</summary>
public class ApkSigningTests
{
    private static readonly Key Signer = Rsa("CN=Android Debug, O=Android, C=US");
    private static readonly Key EcSigner = Ec();

    private static byte[] FullySigned(Key key) =>
        SignBlocks(Zip(SignV1(Entries, key)), (ApkSigning.V2BlockId, false, [new(key)]), (ApkSigning.V3BlockId, true, [new(key, MinSdk: 24)]));

    [Fact]
    public void V1_v2_and_v3_are_verified_with_certificate_details()
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
    public void ECDSA_RSA_PSS_and_per_section_v1_digests_are_verified()
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
    public void Changed_content_is_a_mismatch_in_every_scheme()
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
    public void Added_entry_and_broken_signature_are_mismatches()
    {
        var apk = SignBlocks(Zip([.. SignV1(Entries, Signer, apkSigned: null), ("extra.txt", "x"u8.ToArray())]),
            (ApkSigning.V2BlockId, false, [new(Signer, BreakSignature: true)]));
        var report = ApkSigning.Verify(apk);
        Assert.Contains(report.Schemes[0].Reasons, r => r.Contains("extra.txt is not in the manifest"));
        Assert.Contains(report.Schemes[1].Signers.Single().Reasons, r => r.Contains("does not verify"));
    }

    [Fact]
    public void Stripped_newer_schemes_are_detected()
    {
        // v1 says v2 and v3 were made, the v2 signer says v3 was made; only v2 is present.
        var apk = SignBlocks(Zip(SignV1(Entries, Signer)), (ApkSigning.V2BlockId, false, [new(Signer, StrippingProtection: true)]));
        var report = ApkSigning.Verify(apk);
        Assert.Equal(ApkSigning.Mismatch, report.Verdict);
        Assert.Contains(report.Schemes[0].Signers.Single().Reasons, r => r.Contains("v3 signature was made") && r.Contains("stripped"));
        Assert.Contains(report.Schemes[1].Signers.Single().Reasons, r => r.Contains("stripped"));
    }

    [Fact]
    public void Rotation_v3_and_v31_lineage_is_verified()
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
    public void V4_idsig_is_verified_and_a_wrong_root_is_a_mismatch()
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
    public void Unsigned_unknown_algorithm_and_non_zip_inputs_get_their_verdicts()
    {
        Assert.Equal(ApkSigning.Unsigned, ApkSigning.Verify(Zip(Entries)).Verdict);
        var notZip = ApkSigning.Verify(new byte[100]);
        Assert.Equal(ApkSigning.Unsigned, notZip.Verdict);
        Assert.NotEmpty(notZip.Issues);
        var unknown = ApkSigning.Verify(SignBlocks(Zip(Entries), (ApkSigning.V2BlockId, false, [new(Signer, AlgorithmOverride: 0x0999)])));
        Assert.Equal(ApkSigning.Unsupported, unknown.Verdict);
        // A verity signer needs the signing block at a page boundary.
        var verity = ApkSigning.Verify(SignBlocks(Zip(Entries), (ApkSigning.V2BlockId, false, [new(Signer, AlgorithmOverride: 0x0421)])));
        Assert.Equal(ApkSigning.Mismatch, verity.Verdict);
        Assert.Contains(verity.Schemes[0].Signers[0].Reasons, r => r.Contains("4096-byte boundary"));
    }

    [Fact]
    public void A_package_read_from_a_file_stream_verifies_as_its_bytes()
    {
        var big = new byte[3 << 20];
        new Random(5).NextBytes(big);
        var zip = AlignForVerity(Zip([.. SignV1([.. Entries, ("assets/big.bin", big)], Signer)]));
        var apk = SignBlocks(zip, (ApkSigning.V2BlockId, false, [new(Signer, Verity: true)]), (ApkSigning.V3BlockId, true, [new(EcSigner, MinSdk: 24)]));
        var idsig = V4(apk, EcSigner, VerityDigest(zip));
        using var dir = new TempDir();
        var path = dir.File("big.apk");
        File.WriteAllBytes(path, apk);
        using var stream = File.OpenRead(path);
        var streamed = ApkSigning.Verify(stream, idsig);
        Assert.True(streamed.Verdict == ApkSigning.Verified, Describe(streamed));
        Assert.Equal(Describe(ApkSigning.Verify(apk, idsig)), Describe(streamed));
        Assert.Equal(["v1", "v2", "v3", "v4"], streamed.Schemes.Select(s => s.Scheme));
    }

    [Fact]
    public void Verity_content_digest_is_recomputed_in_v2_v3_and_v4()
    {
        var zip = AlignForVerity(Zip(Entries));
        var apk = SignBlocks(zip, (ApkSigning.V2BlockId, false, [new(Signer, Verity: true)]), (ApkSigning.V3BlockId, true, [new(EcSigner, Verity: true)]));
        var report = ApkSigning.Verify(apk, V4(apk, EcSigner, VerityDigest(zip)));
        Assert.True(report.Verdict == ApkSigning.Verified, Describe(report));
        Assert.Contains("RSASSA-PKCS1-v1_5 with SHA2-256 (verity)", report.Schemes.Single(s => s.Scheme == "v2").Signers.Single().Algorithms);
        Assert.Contains("ECDSA with SHA2-256 (verity)", report.Schemes.Single(s => s.Scheme == "v3").Signers.Single().Algorithms);
        Assert.Equal("v3", report.Schemes[^1].Signers.Single().Extends);

        // The digest signed under the verity id is a chunked one: the recomputed verity digest differs.
        var wrong = ApkSigning.Verify(SignBlocks(zip, (ApkSigning.V2BlockId, false, [new(Signer, AlgorithmOverride: 0x0421)])));
        Assert.Contains(wrong.Schemes[0].Signers[0].Reasons, r => r.Contains("(verity): the content digest differs"));
        var changed = (byte[])apk.Clone();
        changed[IndexOf(changed, "mmmm"u8)] ^= 1;
        Assert.All(ApkSigning.Verify(changed).Schemes, s => Assert.Equal(ApkSigning.Mismatch, s.Verdict));
    }

    [Fact]
    public void Multiple_signers_v3_ranges_v31_rotation_and_v4_blocks_verify()
    {
        var third = Rsa("CN=Third");
        var lineage = Lineage(Signer, EcSigner);
        var zip = Zip(Entries);
        var (cd, eocd) = Layout(zip);
        var digest = ContentDigest(zip, cd, eocd, HashAlgorithmName.SHA256);
        var apk = SignBlocks(zip,
            (ApkSigning.V3BlockId, true, [new(Signer, MinSdk: 24, MaxSdk: 27, RotationMinSdk: 33), new(Signer, MinSdk: 28, MaxSdk: 32, RotationMinSdk: 33)]),
            (ApkSigning.V31BlockId, true, [new(EcSigner, MinSdk: 33, Lineage: lineage)]));
        var report = ApkSigning.Verify(apk, V4(apk, Signer, digest, null, (ApkSigning.V31BlockId, EcSigner, digest)));
        Assert.True(report.Verdict == ApkSigning.Verified, Describe(report));
        var v3 = report.Schemes.Single(s => s.Scheme == "v3");
        Assert.Equal([24, 28], v3.Signers.Select(s => s.MinSdk!.Value));
        Assert.All(v3.Signers, s => Assert.Equal(33, s.RotationMinSdk));
        var node = report.Schemes.Single(s => s.Scheme == "v3.1").Signers.Single().Lineage[0];
        Assert.Equal(["installed_data", "shared_uid", "permission"], node.Capabilities);
        var v4 = report.Schemes.Single(s => s.Scheme == "v4");
        Assert.Equal(["v3", "v3.1"], v4.Signers.Select(s => s.Extends!));
        Assert.Equal("EC", v4.Signers[1].Certificates.Single().KeyAlgorithm);

        // A v4 block signed by a key no v3.1 signer has.
        var stranger = ApkSigning.Verify(apk, V4(apk, Signer, digest, null, (ApkSigning.V31BlockId, third, digest)));
        Assert.Contains(stranger.Schemes[^1].Signers[1].Reasons, r => r.Contains("not the one of a v3.1 signer"));
        Assert.Equal(ApkSigning.Mismatch, stranger.Verdict);

        // Overlapping SDK ranges, lineages that are not one history, and a v3.1 start other than the rotation SDK.
        var overlap = ApkSigning.Verify(SignBlocks(zip, (ApkSigning.V3BlockId, true, [new(Signer, MinSdk: 24, MaxSdk: 30), new(EcSigner, MinSdk: 28)])));
        Assert.Contains(overlap.Schemes.Single().Reasons, r => r.Contains("overlapping SDK ranges (24-30 and 28-"));
        var forked = ApkSigning.Verify(SignBlocks(zip, (ApkSigning.V3BlockId, true,
            [new(EcSigner, MinSdk: 24, MaxSdk: 30, Lineage: lineage), new(Signer, MinSdk: 31, Lineage: Lineage(third, Signer))])));
        Assert.Contains(forked.Schemes.Single().Reasons, r => r.Contains("not the start of the longest lineage"));
        var late = ApkSigning.Verify(SignBlocks(zip,
            (ApkSigning.V3BlockId, true, [new(Signer, MaxSdk: 32, RotationMinSdk: 33)]),
            (ApkSigning.V31BlockId, true, [new(EcSigner, MinSdk: 34, Lineage: lineage)])));
        Assert.Contains(late.Schemes.Single(s => s.Scheme == "v3.1").Reasons, r => r.Contains("rotation-min-sdk-version is 33"));
    }

    [Fact]
    public void Package_facts_list_every_signer_with_the_idsig_beside_the_file()
    {
        using var dir = new TempDir();
        var zip = AndroidSamples.Apk();
        var (cd, eocd) = Layout(zip);
        var digest = ContentDigest(zip, cd, eocd, HashAlgorithmName.SHA256);
        var apk = SignBlocks(zip,
            (ApkSigning.V3BlockId, true, [new(Signer, MaxSdk: 32, RotationMinSdk: 33)]),
            (ApkSigning.V31BlockId, true, [new(EcSigner, MinSdk: 33, Lineage: Lineage(Signer, EcSigner))]));
        var path = dir.File("app.apk");
        File.WriteAllBytes(path, apk);
        File.WriteAllBytes(path + ".idsig", V4(apk, Signer, digest, null, (ApkSigning.V31BlockId, EcSigner, digest)));
        var facts = Corvus.Services.Mobile.AndroidPackageService.Facts(path, apk, default)!;
        Assert.Equal("verified (v3 verified, v3.1 verified, v4 verified)", facts.Signature);
        Assert.Equal(4, facts.Signers.Count);
        Assert.StartsWith("v3 signer 1: CN=Android Debug", facts.Signers[0]);
        Assert.Contains("SDK 24-32, rotated signer from SDK 33, verified", facts.Signers[0]);
        Assert.Contains("SDK 33+, verified; lineage CN=Android Debug, O=Android, C=US [installed_data, shared_uid, permission] -> CN=Test EC Signer [", facts.Signers[1]);
        Assert.StartsWith("v4 signer 2 (for v3.1): CN=Test EC Signer", facts.Signers[3]);
    }

    // Regression: a central directory size of about 500 MB for a signature
    // block entry was allocated before the entry was read.
    [Fact]
    public void A_declared_entry_size_past_its_data_is_not_allocated()
    {
        var apk = FullySigned(EcSigner);
        // The last copy of the name is the one in the central directory.
        int name = apk.AsSpan().LastIndexOf("META-INF/CERT.EC"u8);
        int entry = apk.AsSpan(0, name).LastIndexOf("PK\u0001\u0002"u8);
        apk[entry + 27] = 0x1E;
        long before = GC.GetAllocatedBytesForCurrentThread();
        ApkSigning.Verify(apk);
        Assert.InRange(GC.GetAllocatedBytesForCurrentThread() - before, 0, 64L << 20);
    }

    [Fact]
    [FuzzEntry(typeof(ApkSigning))]
    public void Mutated_APKs_never_throw() => Fuzz(60, 120);

    [Fact]
    [Trait("Speed", "Slow")]
    public void Mutated_APKs_never_throw_over_a_long_run() => Fuzz(1000, 2000);

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
