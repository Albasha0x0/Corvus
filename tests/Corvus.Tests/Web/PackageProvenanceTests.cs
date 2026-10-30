using System.Formats.Asn1;
using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Services.Web.Packages;

namespace Corvus.Tests;

/// <summary>Provenance beside a package, checked against a trust root, log key and npm key the test creates.</summary>
public sealed class PackageProvenanceTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly ECDsa _rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256), _logKey = ECDsa.Create(ECCurve.NamedCurves.nistP256),
        _npmKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly X509Certificate2 _root;
    private readonly string _logId;
    private readonly DateTimeOffset _signed = DateTimeOffset.UtcNow.AddDays(-1);
    private readonly Func<string> _trustRoot = PackageProvenance.TrustRoot, _npmKeys = PackageProvenance.NpmKeys;

    public PackageProvenanceTests()
    {
        _root = Authority("CN=test-root", _rootKey);
        _logId = Convert.ToBase64String(SHA256.HashData(_logKey.ExportSubjectPublicKeyInfo()));
        var trustRoot = new JsonObject
        {
            ["certificateAuthorities"] = new JsonArray(new JsonObject
            {
                ["certChain"] = new JsonObject { ["certificates"] = new JsonArray(new JsonObject { ["rawBytes"] = Convert.ToBase64String(_root.RawData) }) },
                ["validFor"] = new JsonObject { ["start"] = "2020-01-01T00:00:00Z" },
            }),
            ["tlogs"] = new JsonArray(new JsonObject
            {
                ["baseUrl"] = "https://log.example.invalid",
                ["publicKey"] = new JsonObject { ["rawBytes"] = Convert.ToBase64String(_logKey.ExportSubjectPublicKeyInfo()), ["keyDetails"] = "PKIX_ECDSA_P256_SHA_256" },
                ["logId"] = new JsonObject { ["keyId"] = _logId },
            }),
        }.ToJsonString();
        var npmKeys = new JsonObject
        {
            ["keys"] = new JsonArray(
                new JsonObject { ["keyid"] = "SHA256:test-current", ["expires"] = null, ["key"] = Convert.ToBase64String(_npmKey.ExportSubjectPublicKeyInfo()) },
                new JsonObject { ["keyid"] = "SHA256:test-expired", ["expires"] = "2020-01-01T00:00:00.000Z", ["key"] = Convert.ToBase64String(_npmKey.ExportSubjectPublicKeyInfo()) }),
        }.ToJsonString();
        PackageProvenance.TrustRoot = () => trustRoot;
        PackageProvenance.NpmKeys = () => npmKeys;
    }

    public void Dispose()
    {
        PackageProvenance.TrustRoot = _trustRoot;
        PackageProvenance.NpmKeys = _npmKeys;
        _root.Dispose();
        _dir.Dispose();
    }

    private static X509Certificate2 Authority(string name, ECDsa key)
    {
        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        return request.CreateSelfSigned(new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2040, 1, 1, 0, 0, 0, TimeSpan.Zero));
    }

    private static X509Extension Utf8(string oid, string value)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.WriteCharacterString(UniversalTagNumber.UTF8String, value);
        return new X509Extension(oid, w.Encode(), false);
    }

    // A short-lived leaf as a Fulcio-style authority issues it: a workflow URI and the source repository and commit.
    private X509Certificate2 Leaf(ECDsa key, X509Certificate2 issuer)
    {
        var request = new CertificateRequest("CN=", key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddUri(new Uri("https://example.invalid/helper/.github/workflows/release.yml@refs/tags/v1.0.1"));
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.3")], false));
        request.CertificateExtensions.Add(Utf8("1.3.6.1.4.1.57264.1.8", "https://token.example.invalid"));
        request.CertificateExtensions.Add(Utf8("1.3.6.1.4.1.57264.1.12", "https://example.invalid/helper"));
        request.CertificateExtensions.Add(Utf8("1.3.6.1.4.1.57264.1.13", "0123456789abcdef0123456789abcdef01234567"));
        return request.Create(issuer, _signed.AddMinutes(-1), _signed.AddMinutes(10), [1, 2, 3, 4]);
    }

    private string Package(string version = "1.0.1", string? repository = null)
    {
        var path = _dir.File("helper-1.0.1.tgz");
        using (var fs = File.Create(path))
        using (var gz = new GZipStream(fs, CompressionLevel.Fastest))
        using (var tar = new TarWriter(gz, TarEntryFormat.Ustar))
            tar.WriteEntry(new UstarTarEntry(TarEntryType.RegularFile, "package/package.json")
                { DataStream = new MemoryStream(Encoding.UTF8.GetBytes($$"""{"name":"example-helper","version":"{{version}}"{{(repository == null ? "" : ",\"repository\":\"" + repository + "\"")}}}""")) });
        return path;
    }

    private static byte[] Pae(string type, byte[] body) => [.. Encoding.UTF8.GetBytes($"DSSEv1 {type.Length} {type} {body.Length} "), .. body];

    private JsonObject LogEntry(long index)
    {
        var body = Convert.ToBase64String("{\"kind\":\"dsse\"}"u8.ToArray());
        var canonical = $"{{\"body\":\"{body}\",\"integratedTime\":{_signed.ToUnixTimeSeconds()},\"logID\":\"{Convert.ToHexStringLower(Convert.FromBase64String(_logId))}\",\"logIndex\":{index}}}";
        return new JsonObject
        {
            ["logIndex"] = index.ToString(), ["logId"] = new JsonObject { ["keyId"] = _logId }, ["integratedTime"] = _signed.ToUnixTimeSeconds().ToString(),
            ["inclusionPromise"] = new JsonObject { ["signedEntryTimestamp"] = Convert.ToBase64String(_logKey.SignData(Encoding.UTF8.GetBytes(canonical), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)) },
            ["canonicalizedBody"] = body,
        };
    }

    private static byte[] Statement(string package) => JsonSerializer.SerializeToUtf8Bytes(new JsonObject
    {
        ["_type"] = "https://in-toto.io/Statement/v1",
        ["subject"] = new JsonArray(new JsonObject { ["name"] = Path.GetFileName(package), ["digest"] = new JsonObject { ["sha256"] = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(package))) } }),
        ["predicateType"] = "https://slsa.dev/provenance/v1",
    });

    /// <summary>A Sigstore bundle for <paramref name="package"/> signed by a leaf of <paramref name="issuer"/>, which holds its key.</summary>
    private void Bundle(string package, X509Certificate2? issuer = null)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaf = Leaf(key, issuer ?? _root);
        var payload = Statement(package);
        const string type = "application/vnd.in-toto+json";
        File.WriteAllText(package + ".sigstore.json", new JsonObject
        {
            ["mediaType"] = "application/vnd.dev.sigstore.bundle.v0.3+json",
            ["verificationMaterial"] = new JsonObject
            {
                ["certificate"] = new JsonObject { ["rawBytes"] = Convert.ToBase64String(leaf.RawData) },
                ["tlogEntries"] = new JsonArray(LogEntry(41)),
            },
            ["dsseEnvelope"] = new JsonObject
            {
                ["payload"] = Convert.ToBase64String(payload), ["payloadType"] = type,
                ["signatures"] = new JsonArray(new JsonObject { ["sig"] = Convert.ToBase64String(key.SignData(Pae(type, payload), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)) }),
            },
        }.ToJsonString());
    }

    [Fact]
    public void A_sigstore_bundle_beside_a_package_verifies_digest_signature_chain_and_log_offline()
    {
        var package = Package();
        Bundle(package);
        var r = PackageReview.Review(package, default)!;
        var a = Assert.Single(r.Provenance!);
        Assert.Equal(("sigstore bundle", "verified (sha256)", "verified"), (a.Format, a.Digest, a.Signature));
        Assert.StartsWith("verified (test-root, at ", a.Chain, StringComparison.Ordinal);
        Assert.Equal("verified (https://log.example.invalid, index 41)", a.Log);
        Assert.Equal(("https://example.invalid/helper/.github/workflows/release.yml@refs/tags/v1.0.1", "https://token.example.invalid", "https://example.invalid/helper", "0123456789abcdef0123456789abcdef01234567"),
            (a.Signer, a.Issuer, a.Repository, a.Commit));
        Assert.DoesNotContain(r.Findings, f => f.Category == "provenance");
    }

    [Fact]
    public void A_package_changed_after_signing_fails_its_digest_as_a_noteworthy_finding()
    {
        var package = Package();
        Bundle(package);
        Package("1.0.2");
        var r = PackageReview.Review(package, default);
        Assert.Equal("failed: the subject's sha256 differs from the package file's", Assert.Single(r!.Provenance!).Digest);
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "provenance", Path: "helper-1.0.1.tgz.sigstore.json" } && f.Detail.StartsWith("sigstore bundle digest failed", StringComparison.Ordinal));
    }

    [Fact]
    public void A_certificate_from_an_authority_outside_the_trust_root_fails_its_chain()
    {
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = Authority("CN=other-root", otherKey);
        var package = Package();
        Bundle(package, other);
        var a = Assert.Single(PackageReview.Review(package, default)!.Provenance!);
        Assert.Equal("verified", a.Signature);
        Assert.StartsWith("failed: ", a.Chain, StringComparison.Ordinal);
    }

    [Fact]
    public void An_npm_publish_attestation_is_checked_against_the_pinned_npm_key_and_its_expiry()
    {
        var package = Package();
        var payload = JsonSerializer.SerializeToUtf8Bytes(new JsonObject
        {
            ["_type"] = "https://in-toto.io/Statement/v1",
            ["subject"] = new JsonArray(new JsonObject { ["name"] = "pkg:npm/example-helper@1.0.1", ["digest"] = new JsonObject { ["sha512"] = Convert.ToHexStringLower(SHA512.HashData(File.ReadAllBytes(package))) } }),
            ["predicateType"] = "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
        });
        const string type = "application/vnd.in-toto+json";
        var sig = Convert.ToBase64String(_npmKey.SignData(Pae(type, payload), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
        JsonObject Attestation(string keyId) => new()
        {
            ["predicateType"] = "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
            ["bundle"] = new JsonObject
            {
                ["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.2",
                ["verificationMaterial"] = new JsonObject { ["publicKey"] = new JsonObject { ["hint"] = keyId }, ["tlogEntries"] = new JsonArray(LogEntry(7)) },
                ["dsseEnvelope"] = new JsonObject { ["payload"] = Convert.ToBase64String(payload), ["payloadType"] = type, ["signatures"] = new JsonArray(new JsonObject { ["sig"] = sig, ["keyid"] = keyId }) },
            },
        };
        File.WriteAllText(package + ".attestations.json", new JsonObject { ["attestations"] = new JsonArray(Attestation("SHA256:test-current"), Attestation("SHA256:test-expired")) }.ToJsonString());
        var list = PackageReview.Review(package, default)!.Provenance!;
        Assert.Equal(("verified (sha512)", "verified", "not used", "SHA256:test-current"), (list[0].Digest, list[0].Signature, list[0].Chain, list[0].Signer));
        Assert.StartsWith("failed: signed ", list[1].Signature, StringComparison.Ordinal);
        Assert.EndsWith("after npm key SHA256:test-expired expired (2020-01-01)", list[1].Signature, StringComparison.Ordinal);
    }

    [Fact]
    public void An_update_that_drops_its_signed_provenance_shows_a_removed_policy_row()
    {
        var package = Package();
        Bundle(package);
        var signed = PackageReview.Review(package, default)!;
        File.Delete(package + ".sigstore.json");
        var unsigned = PackageReview.Review(package, default)!;
        var (rows, summary) = Corvus.Services.Analysis.CapabilityChanges.Policy(signed, unsigned, []);
        var row = Assert.Single(rows);
        Assert.Equal(("removed", "provenance dropped: sigstore bundle by https://example.invalid/helper/.github/workflows/release.yml"), (row.Kind, row.Key));
        Assert.Contains("removed: 1 signed provenance", summary, StringComparison.Ordinal);
    }

    [Fact]
    public void A_provenance_file_that_is_not_json_is_reported_unknown_rather_than_absent()
    {
        var package = Package();
        File.WriteAllText(package + ".sigstore.json", "not json");
        var r = PackageReview.Review(package, default)!;
        Assert.Null(r.Provenance);
        Assert.Contains(r.Notes, n => n.StartsWith("provenance helper-1.0.1.tgz.sigstore.json: not read (", StringComparison.Ordinal) && n.EndsWith("its attestations are unknown", StringComparison.Ordinal));
    }

    [Fact]
    public void A_signed_source_repository_other_than_the_declared_one_is_a_review_finding()
    {
        var package = Package(repository: "https://example.invalid/other/helper");
        Bundle(package);
        var r = PackageReview.Review(package, default)!;
        Assert.Contains(r.Findings, f => f is { Rule: "package/provenance-repository", Level: "review", Category: "provenance" }
            && f.Detail.Contains("https://example.invalid/helper differs from the declared repository https://example.invalid/other/helper", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("git+https://example.invalid/helper.git")]
    [InlineData("https://EXAMPLE.invalid/Helper/")]
    [InlineData("git@example.invalid:helper")]
    public void A_declared_repository_written_another_way_raises_no_provenance_finding(string declared)
    {
        var package = Package(repository: declared);
        Bundle(package);
        Assert.DoesNotContain(PackageReview.Review(package, default)!.Findings, f => f.Category == "provenance");
    }

    [Fact]
    public void A_manifest_without_a_repository_raises_no_provenance_finding()
    {
        var package = Package();
        Bundle(package);
        Assert.DoesNotContain(PackageReview.Review(package, default)!.Findings, f => f.Category == "provenance");
    }
}
