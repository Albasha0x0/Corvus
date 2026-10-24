using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace Corvus.Services.Web.Packages;

/// <summary>
/// A signed statement about a package read from a provenance file beside it. Digest, Signature, Chain and Log are
/// "verified", "failed: why" or "unknown: why"; Chain is "not used" for a statement signed by a registry key.
/// </summary>
/// <param name="Format">sigstore bundle, npm attestations, or pypi provenance.</param>
/// <param name="Digest">Whether a subject's digest equals the package file's.</param>
/// <param name="Signer">The certificate's identity (a workflow URI or an email), or the registry key id.</param>
/// <param name="Log">The transparency log entry: signed by a log the trust root names, at LogIndex and Integrated.</param>
public sealed record PackageAttestation(string File, string Format, string? PredicateType, string Digest, string Signature, string? Signer, string? Issuer,
    string? Repository, string? Commit, string? Workflow, string Chain, string Log, long? LogIndex, DateTimeOffset? Integrated);

/// <summary>
/// Reads and checks the provenance files beside a package: a Sigstore bundle (file.sigstore.json, file.sigstore), the npm
/// registry's attestations response (file.attestations.json) and PyPI's provenance (file.provenance, file.provenance.json,
/// file.publish.attestation). Offline: certificates chain to the pinned Sigstore trust root and npm statements to npm's
/// pinned attestation keys; nothing is fetched. Revocation is not checked.
/// </summary>
internal static class PackageProvenance
{
    /// <summary>Provenance file suffixes, in the order they are read.</summary>
    internal static readonly string[] Suffixes = [".sigstore.json", ".sigstore", ".attestations.json", ".provenance", ".provenance.json", ".publish.attestation"];

    private const int MaxFile = 4 << 20, MaxAttestations = 20;

    // Fulcio certificate extensions (sigstore/fulcio docs/oid-info.md); 1.1 holds raw text, the others DER UTF8String.
    private const string IssuerV1 = "1.3.6.1.4.1.57264.1.1", IssuerV2 = "1.3.6.1.4.1.57264.1.8", BuildSigner = "1.3.6.1.4.1.57264.1.9",
        SourceRepository = "1.3.6.1.4.1.57264.1.12", SourceDigest = "1.3.6.1.4.1.57264.1.13";

    /// <summary>The pinned trust root (sigstore/root-signing targets/trusted_root.json at c9bda74a, 2025-09-22); tests replace it.</summary>
    internal static Func<string> TrustRoot { get; set; } = () => Resource("sigstore-trusted-root.json");

    /// <summary>npm's attestation keys (registry.npmjs.org/-/npm/v1/keys, read 2026-10-25); tests replace them.</summary>
    internal static Func<string> NpmKeys { get; set; } = () => Resource("npm-attestation-keys.json");

    private static string Resource(string name)
    {
        using var s = typeof(PackageProvenance).Assembly.GetManifestResourceStream("Corvus.Services.Web.Packages.TrustRoots." + name)
            ?? throw new InvalidOperationException($"{name} is not embedded");
        using var r = new StreamReader(s);
        return r.ReadToEnd();
    }

    private sealed record Statement(string Format, byte[] Payload, string PayloadType, byte[] Signature, byte[]? Certificate, string? KeyId, JsonElement[] LogEntries);

    /// <summary>The attestations in the provenance files beside <paramref name="package"/>, and notes on what could not be read.</summary>
    public static (List<PackageAttestation> Attestations, List<string> Notes) Read(string package, CancellationToken ct)
    {
        var attestations = new List<PackageAttestation>();
        var notes = new List<string>();
        var found = Suffixes.Select(s => package + s).Where(File.Exists).ToList();
        if (found.Count == 0) return (attestations, notes);
        byte[] bytes = File.ReadAllBytes(package);
        var digests = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["sha256"] = Convert.ToHexStringLower(SHA256.HashData(bytes)),
            ["sha512"] = Convert.ToHexStringLower(SHA512.HashData(bytes)),
        };
        foreach (var file in found)
        {
            ct.ThrowIfCancellationRequested();
            var name = Path.GetFileName(file);
            if (new FileInfo(file).Length > MaxFile)
            {
                notes.Add($"provenance {name}: over {MaxFile >> 20} MiB, not read; its attestations are unknown");
                continue;
            }
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllBytes(file));
                var statements = Statements(doc.RootElement).Take(MaxAttestations + 1).ToList();
                if (statements.Count == 0) notes.Add($"provenance {name}: no Sigstore bundle, npm attestation or PyPI attestation in it");
                if (statements.Count > MaxAttestations) notes.Add($"provenance {name}: the first {MaxAttestations} attestations are read");
                attestations.AddRange(statements.Take(MaxAttestations).Select(s => Check(name, s, digests)));
            }
            catch (Exception ex) when (ex is JsonException or FormatException or InvalidOperationException or KeyNotFoundException)
            {
                notes.Add($"provenance {name}: not read ({ex.Message}); its attestations are unknown");
            }
        }
        return (attestations, notes);
    }

    // --- formats ---

    private static IEnumerable<Statement> Statements(JsonElement root)
    {
        if (Str(root, "mediaType") is { } media && media.StartsWith("application/vnd.dev.sigstore.bundle", StringComparison.Ordinal))
        {
            if (Bundle(root, "sigstore bundle") is { } s) yield return s;
        }
        else if (root.TryGetProperty("attestations", out var npm) && npm.ValueKind == JsonValueKind.Array)
        {
            foreach (var a in npm.EnumerateArray())
                if (a.TryGetProperty("bundle", out var b) && Bundle(b, "npm attestations") is { } s) yield return s;
        }
        else if (root.TryGetProperty("attestation_bundles", out var pypi) && pypi.ValueKind == JsonValueKind.Array)
        {
            foreach (var group in pypi.EnumerateArray())
                foreach (var a in Items(group, "attestations"))
                    if (Pep740(a) is { } s) yield return s;
        }
        else if (Pep740(root) is { } single) yield return single;
    }

    private static Statement? Bundle(JsonElement bundle, string format)
    {
        if (!bundle.TryGetProperty("dsseEnvelope", out var env)) return null;
        var material = bundle.GetProperty("verificationMaterial");
        byte[]? cert = material.TryGetProperty("certificate", out var c) ? B64(Str(c, "rawBytes"))
            : material.TryGetProperty("x509CertificateChain", out var chain) ? Items(chain, "certificates").Select(x => B64(Str(x, "rawBytes"))).FirstOrDefault()
            : null;
        var sig = Items(env, "signatures").FirstOrDefault();
        var key = (material.TryGetProperty("publicKey", out var pk) ? Str(pk, "hint") : null) ?? (Str(sig, "keyid") is { Length: > 0 } k ? k : null);
        return new Statement(format, B64(Str(env, "payload"))!, Str(env, "payloadType") ?? "", B64(Str(sig, "sig")) ?? [], cert, key,
            [.. Items(material, "tlogEntries")]);
    }

    // PEP 740: the envelope's statement is signed as DSSE with the in-toto payload type.
    private static Statement? Pep740(JsonElement a)
    {
        if (!a.TryGetProperty("envelope", out var env) || !a.TryGetProperty("verification_material", out var material)) return null;
        return new Statement("pypi provenance", B64(Str(env, "statement"))!, "application/vnd.in-toto+json", B64(Str(env, "signature")) ?? [],
            B64(Str(material, "certificate")), null, [.. Items(material, "transparency_entries")]);
    }

    // --- checks ---

    private static PackageAttestation Check(string file, Statement s, IReadOnlyDictionary<string, string> digests)
    {
        string? predicate = null, digest;
        try
        {
            using var statement = JsonDocument.Parse(s.Payload);
            predicate = Str(statement.RootElement, "predicateType");
            var subjects = Items(statement.RootElement, "subject").ToList();
            var named = subjects.SelectMany(x => x.TryGetProperty("digest", out var d) && d.ValueKind == JsonValueKind.Object ? d.EnumerateObject() : Enumerable.Empty<JsonProperty>())
                .Where(d => digests.ContainsKey(d.Name)).Select(d => (d.Name, Value: d.Value.GetString())).ToList();
            var equal = named.Where(d => string.Equals(d.Value, digests[d.Name], StringComparison.OrdinalIgnoreCase)).Select(d => d.Name).FirstOrDefault();
            digest = named.Count == 0 ? "unknown: no sha256 or sha512 subject digest"
                : equal != null ? $"verified ({equal})"
                : $"failed: the subject's {named[0].Name} differs from the package file's";
        }
        catch (JsonException) { digest = "unknown: the statement is not JSON"; }

        var entry = s.LogEntries.FirstOrDefault();
        long? index = entry.ValueKind == JsonValueKind.Object && long.TryParse(Str(entry, "logIndex"), NumberStyles.None, CultureInfo.InvariantCulture, out long i) ? i : null;
        DateTimeOffset? integrated = entry.ValueKind == JsonValueKind.Object && long.TryParse(Str(entry, "integratedTime"), NumberStyles.None, CultureInfo.InvariantCulture, out long t)
            ? DateTimeOffset.FromUnixTimeSeconds(t) : null;
        var log = entry.ValueKind == JsonValueKind.Object ? LogEntry(entry, index, integrated) : "unknown: no transparency log entry";
        var pae = Pae(s.PayloadType, s.Payload);

        if (s.Certificate == null)
        {
            // A registry-signed statement: npm signs its publish attestation with a key it publishes.
            var signature = s.KeyId == null ? "unknown: no certificate or key named" : NpmKey(s.KeyId, integrated) is var (key, why) && key == null ? why!
                : Verify(key!, pae, s.Signature) ? "verified" : "failed: the signature does not match the npm key";
            return new(file, s.Format, predicate, digest, signature, s.KeyId, null, null, null, null, "not used", log, index, integrated);
        }
        using var cert = X509CertificateLoader.LoadCertificate(s.Certificate);
        string sig;
        using (var ec = cert.GetECDsaPublicKey())
            sig = ec == null ? "unknown: the certificate's key is not ECDSA" : Verify(ec, pae, s.Signature) ? "verified" : "failed: the signature does not match the certificate";
        return new(file, s.Format, predicate, digest, sig, Identity(cert), Extension(cert, IssuerV2) ?? Extension(cert, IssuerV1, raw: true),
            Extension(cert, SourceRepository), Extension(cert, SourceDigest), Extension(cert, BuildSigner), Chain(cert, integrated), log, index, integrated);
    }

    /// <summary>DSSE pre-authentication encoding: "DSSEv1 len(type) type len(body) body".</summary>
    private static byte[] Pae(string type, byte[] body) =>
        [.. Encoding.UTF8.GetBytes($"DSSEv1 {Encoding.UTF8.GetByteCount(type)} {type} {body.Length} "), .. body];

    private static bool Verify(ECDsa key, byte[] data, byte[] signature)
    {
        var hash = key.KeySize > 256 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;
        try { return key.VerifyData(data, signature, hash, DSASignatureFormat.Rfc3279DerSequence); }
        catch (CryptographicException) { return false; }
    }

    private static (ECDsa? Key, string? Why) NpmKey(string keyId, DateTimeOffset? at)
    {
        using var doc = JsonDocument.Parse(NpmKeys());
        var match = Items(doc.RootElement, "keys").FirstOrDefault(k => Str(k, "keyid") == keyId);
        if (match.ValueKind != JsonValueKind.Object) return (null, $"unknown: npm key {keyId} is not among the pinned keys");
        if (Str(match, "expires") is { } e && DateTimeOffset.TryParse(e, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var expires) && at > expires)
            return (null, $"failed: signed {at:yyyy-MM-dd}, after npm key {keyId} expired ({expires:yyyy-MM-dd})");
        var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(Str(match, "key")!), out _);
        return (key, null);
    }

    /// <summary>The leaf chained to a Fulcio root of the trust root, at the log's time (a leaf lives minutes).</summary>
    private static string Chain(X509Certificate2 leaf, DateTimeOffset? at)
    {
        if (at == null) return "unknown: no log time to check the short-lived certificate at";
        using var doc = JsonDocument.Parse(TrustRoot());
        var cas = Items(doc.RootElement, "certificateAuthorities")
            .Where(ca => Window(ca, at.Value))
            .Select(ca => Items(ca.GetProperty("certChain"), "certificates").Select(c => X509CertificateLoader.LoadCertificate(B64(Str(c, "rawBytes"))!)).ToList())
            .ToList();
        try
        {
            if (cas.Count == 0) return $"failed: no certificate authority of the trust root was valid at {at:u}";
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationTime = at.Value.UtcDateTime;
            chain.ChainPolicy.VerificationTimeIgnored = false;
            foreach (var certs in cas)
            {
                chain.ChainPolicy.CustomTrustStore.Add(certs[^1]);
                foreach (var c in certs.Take(certs.Count - 1)) chain.ChainPolicy.ExtraStore.Add(c);
            }
            if (!chain.Build(leaf))
                return "failed: " + string.Join("; ", chain.ChainStatus.Select(st => st.StatusInformation.Trim()).Where(x => x.Length > 0).Distinct().Take(2));
            var root = chain.ChainElements[^1].Certificate;
            return $"verified ({root.GetNameInfo(X509NameType.SimpleName, false)}, at {at:u})";
        }
        finally
        {
            foreach (var c in cas.SelectMany(x => x)) c.Dispose();
        }
    }

    private static bool Window(JsonElement entry, DateTimeOffset at)
    {
        if (!entry.TryGetProperty("validFor", out var v)) return true;
        static DateTimeOffset? When(JsonElement v, string n) => Str(v, n) is { } s ? DateTimeOffset.Parse(s, CultureInfo.InvariantCulture) : null;
        return (When(v, "start") is not { } start || at >= start) && (When(v, "end") is not { } end || at <= end);
    }

    /// <summary>
    /// The entry's signed entry timestamp checked with the log's key from the trust root, over the canonical JSON of
    /// body, integrated time, log id and index (Rekor's SET).
    /// </summary>
    private static string LogEntry(JsonElement entry, long? index, DateTimeOffset? integrated)
    {
        var keyId = entry.TryGetProperty("logId", out var id) ? Str(id, "keyId") : null;
        using var doc = JsonDocument.Parse(TrustRoot());
        var log = Items(doc.RootElement, "tlogs").FirstOrDefault(l => l.TryGetProperty("logId", out var lid) && Str(lid, "keyId") == keyId);
        if (log.ValueKind != JsonValueKind.Object) return $"unknown: log {keyId ?? "(none)"} is not in the trust root";
        var url = Str(log, "baseUrl");
        var set = entry.TryGetProperty("inclusionPromise", out var p) ? B64(Str(p, "signedEntryTimestamp")) : null;
        if (set == null) return $"unknown: {url} entry has no signed entry timestamp; its inclusion proof is not checked";
        var details = log.GetProperty("publicKey");
        var kind = Str(details, "keyDetails") ?? "an unnamed key";
        if (!kind.StartsWith("PKIX_ECDSA_P256", StringComparison.Ordinal)) return $"unknown: {url} signs with {kind}, not checked";
        if (index == null || integrated == null || Str(entry, "canonicalizedBody") is not { } body) return "unknown: the entry lacks its index, time or body";
        var canonical = $"{{\"body\":\"{body}\",\"integratedTime\":{integrated.Value.ToUnixTimeSeconds()},\"logID\":\"{Convert.ToHexStringLower(B64(keyId)!)}\",\"logIndex\":{index}}}";
        using var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(B64(Str(details, "rawBytes"))!, out _);
        return Verify(key, Encoding.UTF8.GetBytes(canonical), set) ? $"verified ({url}, index {index})" : $"failed: the signed entry timestamp does not match {url}'s key";
    }

    // --- certificate fields ---

    /// <summary>The first URI or email of the subject alternative names, or null.</summary>
    private static string? Identity(X509Certificate2 cert)
    {
        if (cert.Extensions["2.5.29.17"] is not { } san) return null;
        try
        {
            var seq = new AsnReader(san.RawData, AsnEncodingRules.DER).ReadSequence();
            while (seq.HasData)
            {
                var tag = seq.PeekTag();
                if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue is 1 or 6)
                    return seq.ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, tag.TagValue));
                seq.ReadEncodedValue();
            }
        }
        catch (AsnContentException) { }
        return null;
    }

    private static string? Extension(X509Certificate2 cert, string oid, bool raw = false)
    {
        if (cert.Extensions[oid] is not { } e) return null;
        if (raw) return Encoding.UTF8.GetString(e.RawData);
        try { return new AsnReader(e.RawData, AsnEncodingRules.DER).ReadCharacterString(UniversalTagNumber.UTF8String); }
        catch (AsnContentException) { return Encoding.UTF8.GetString(e.RawData); }
    }

    // --- JSON ---

    private static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) ? v.ValueKind switch { JsonValueKind.String => v.GetString(), JsonValueKind.Number => v.GetRawText(), _ => null } : null;

    private static IEnumerable<JsonElement> Items(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array ? v.EnumerateArray() : [];

    private static byte[]? B64(string? s) => s == null ? null : Convert.FromBase64String(s);
}
