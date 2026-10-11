using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Corvus.Native;

namespace Corvus.Core.Mobile;

public sealed record ApkCertificate(string Subject, string Issuer, string Sha256, string KeyAlgorithm, int KeySize, DateTime NotBefore, DateTime NotAfter,
    bool IsDebug);

/// <summary>A certificate of a v3 rotation lineage, oldest first; <paramref name="Flags"/> are the capabilities granted to it.</summary>
public sealed record ApkLineageNode(ApkCertificate Certificate, uint Flags)
{
    /// <summary>The capability flags by name: installed_data, shared_uid, permission, rollback, auth.</summary>
    public IReadOnlyList<string> Capabilities => [.. CapabilityNames.Where(c => (Flags & c.Bit) != 0).Select(c => c.Name)];

    private static readonly (uint Bit, string Name)[] CapabilityNames = [(1, "installed_data"), (2, "shared_uid"), (4, "permission"), (8, "rollback"), (16, "auth")];
}

public sealed record ApkSigner(IReadOnlyList<ApkCertificate> Certificates, IReadOnlyList<string> Algorithms, int? MinSdk, int? MaxSdk, string Verdict,
    IReadOnlyList<string> Reasons, IReadOnlyList<ApkLineageNode> Lineage, IReadOnlyList<uint> AttributeIds)
{
    /// <summary>v3: the SDK from which the v3.1 block's rotated signer applies (rotation-min-sdk-version attribute).</summary>
    public int? RotationMinSdk { get; init; }
    /// <summary>v4: the scheme whose signer this one extends (v2, v3 or v3.1).</summary>
    public string? Extends { get; init; }
}

/// <summary>One signature scheme found in the file: "v1", "v2", "v3", "v3.1" or "v4".</summary>
public sealed record ApkSchemeResult(string Scheme, string Verdict, IReadOnlyList<ApkSigner> Signers, IReadOnlyList<string> Reasons);

/// <summary>
/// The signatures of an APK. <see cref="Verdict"/> is "verified", "mismatch", "unsigned" or "unsupported_algorithm"
/// (the worst over the schemes present); <see cref="BlockIds"/> lists every entry of the APK Signing Block.
/// </summary>
public sealed record ApkSignatureReport(string Verdict, IReadOnlyList<ApkSchemeResult> Schemes, IReadOnlyList<uint> BlockIds, IReadOnlyList<ParseIssue> Issues);

/// <summary>
/// Verifies APK signatures: JAR signing (v1), the APK Signature Scheme v2, v3 and v3.1 blocks (signatures over the signed
/// data, certificates, SDK ranges, rotation lineage, and the chunked content digests recomputed from the file), and a v4
/// .idsig beside it (signature and the Merkle root of the file). Says what was checked; never claims trust in a
/// certificate. Never throws on malformed input.
/// </summary>
public static class ApkSigning
{
    public const string Verified = "verified", Mismatch = "mismatch", Unsigned = "unsigned", Unsupported = "unsupported_algorithm";

    public const uint V2BlockId = 0x7109871a, V3BlockId = 0xf05368c0, V31BlockId = 0x1b93ad61;
    private const uint ProofOfRotationId = 0x3ba06f8c, StrippingProtectionId = 0xbeeff00d, RotationMinSdkId = 0x559f8b02;

    private enum ContentDigest { Sha256Chunked, Sha512Chunked, Verity }

    private sealed record Algorithm(uint Id, string Name, string Key, HashAlgorithmName Hash, bool Pss, ContentDigest Digest);

    private static readonly Dictionary<uint, Algorithm> Algorithms = new Algorithm[]
    {
        new(0x0101, "RSASSA-PSS with SHA2-256", "RSA", HashAlgorithmName.SHA256, true, ContentDigest.Sha256Chunked),
        new(0x0102, "RSASSA-PSS with SHA2-512", "RSA", HashAlgorithmName.SHA512, true, ContentDigest.Sha512Chunked),
        new(0x0103, "RSASSA-PKCS1-v1_5 with SHA2-256", "RSA", HashAlgorithmName.SHA256, false, ContentDigest.Sha256Chunked),
        new(0x0104, "RSASSA-PKCS1-v1_5 with SHA2-512", "RSA", HashAlgorithmName.SHA512, false, ContentDigest.Sha512Chunked),
        new(0x0201, "ECDSA with SHA2-256", "EC", HashAlgorithmName.SHA256, false, ContentDigest.Sha256Chunked),
        new(0x0202, "ECDSA with SHA2-512", "EC", HashAlgorithmName.SHA512, false, ContentDigest.Sha512Chunked),
        new(0x0301, "DSA with SHA2-256", "DSA", HashAlgorithmName.SHA256, false, ContentDigest.Sha256Chunked),
        new(0x0421, "RSASSA-PKCS1-v1_5 with SHA2-256 (verity)", "RSA", HashAlgorithmName.SHA256, false, ContentDigest.Verity),
        new(0x0423, "ECDSA with SHA2-256 (verity)", "EC", HashAlgorithmName.SHA256, false, ContentDigest.Verity),
        new(0x0425, "DSA with SHA2-256 (verity)", "DSA", HashAlgorithmName.SHA256, false, ContentDigest.Verity),
    }.ToDictionary(a => a.Id);

    private static string AlgorithmName(uint id) => Algorithms.TryGetValue(id, out var a) ? a.Name : $"unknown 0x{id:x4}";

    /// <summary>Verifies <paramref name="apk"/>; <paramref name="idsig"/> is the v4 signature file beside it, when there is one.</summary>
    public static ApkSignatureReport Verify(byte[] apk, byte[]? idsig = null, AnalysisLimits? limits = null)
    {
        var v = new Verifier(apk, limits ?? AnalysisLimits.Default);
        return v.Run(idsig);
    }

    private sealed class Verifier(byte[] apk, AnalysisLimits limits)
    {
        private readonly List<ParseIssue> _issues = [];
        private readonly List<ApkSchemeResult> _schemes = [];
        private readonly List<uint> _blockIds = [];
        private readonly Dictionary<ContentDigest, byte[]> _digests = [];
        private long _eocd = -1, _cdOffset, _blockStart = -1;

        public ApkSignatureReport Run(byte[]? idsig)
        {
            if (!FindCentralDirectory()) return new(Unsigned, [], [], _issues);
            var blocks = SigningBlock();
            var v3 = blocks.FirstOrDefault(b => b.Id == V3BlockId);
            V1(blocks);
            if (blocks.FirstOrDefault(b => b.Id == V2BlockId) is { Value: not null } v2) _schemes.Add(SchemeV2V3("v2", v2.Value, false, v3.Value != null));
            if (v3.Value != null) _schemes.Add(SchemeV2V3("v3", v3.Value, true, false));
            if (blocks.FirstOrDefault(b => b.Id == V31BlockId) is { Value: not null } v31) _schemes.Add(SchemeV2V3("v3.1", v31.Value, true, false));
            if (Rotation().ToList() is { Count: > 0 } rotation && _schemes.FindIndex(x => x.Scheme == "v3.1") is var at and >= 0)
                _schemes[at] = _schemes[at] with { Verdict = Mismatch, Reasons = [.. _schemes[at].Reasons, .. rotation] };
            if (idsig != null) _schemes.Add(V4(idsig));
            string verdict = _schemes.Count == 0 ? Unsigned : Worst(_schemes.Select(s => s.Verdict));
            return new(verdict, _schemes, _blockIds, _issues);
        }

        private static string Worst(IEnumerable<string> verdicts)
        {
            var all = verdicts.ToList();
            return all.Contains(Mismatch) ? Mismatch : all.Contains(Unsupported) ? Unsupported : all.Count == 0 ? Mismatch : Verified;
        }

        // ---- ZIP layout ----

        private bool FindCentralDirectory()
        {
            for (long at = apk.Length - 22; at >= Math.Max(0, apk.Length - 22 - 0xFFFF); at--)
            {
                if (BinaryPrimitives.ReadUInt32LittleEndian(apk.AsSpan((int)at)) != 0x06054b50) continue;
                if (at + 22 + BinaryPrimitives.ReadUInt16LittleEndian(apk.AsSpan((int)at + 20)) != apk.Length) continue;
                _eocd = at;
                _cdOffset = BinaryPrimitives.ReadUInt32LittleEndian(apk.AsSpan((int)at + 16));
                if (_cdOffset == 0xFFFFFFFF && at >= 20 && BinaryPrimitives.ReadUInt32LittleEndian(apk.AsSpan((int)at - 20)) == 0x07064b50)
                {
                    var record = BinaryPrimitives.ReadUInt64LittleEndian(apk.AsSpan((int)at - 12));
                    if (record + 56 <= (ulong)at && BinaryPrimitives.ReadUInt32LittleEndian(apk.AsSpan((int)record)) == 0x06064b50)
                        _cdOffset = (long)BinaryPrimitives.ReadUInt64LittleEndian(apk.AsSpan((int)record + 48));
                }
                if (_cdOffset > at)
                {
                    _issues.Add(new("zip", $"the central directory offset 0x{_cdOffset:x} is past the end record", at));
                    return false;
                }
                return true;
            }
            _issues.Add(new("zip", "no end of central directory record: not a ZIP file", null));
            return false;
        }

        private List<(uint Id, byte[]? Value)> SigningBlock()
        {
            var result = new List<(uint, byte[]?)>();
            if (_cdOffset < 32 || !apk.AsSpan((int)_cdOffset - 16, 16).SequenceEqual("APK Sig Block 42"u8)) return result;
            ulong size = BinaryPrimitives.ReadUInt64LittleEndian(apk.AsSpan((int)_cdOffset - 24));
            if (size < 24 || size > (ulong)_cdOffset - 8)
            {
                _issues.Add(new("signing block", $"block size {size} does not fit before the central directory", _cdOffset - 24));
                return result;
            }
            long start = _cdOffset - (long)size - 8;
            if (BinaryPrimitives.ReadUInt64LittleEndian(apk.AsSpan((int)start)) != size)
            {
                _issues.Add(new("signing block", "the two size fields of the block differ", start));
                return result;
            }
            _blockStart = start;
            long end = _cdOffset - 24;
            for (long at = start + 8; at < end;)
            {
                if (at + 12 > end) { _issues.Add(new("signing block", "truncated entry", at)); break; }
                ulong length = BinaryPrimitives.ReadUInt64LittleEndian(apk.AsSpan((int)at));
                if (length < 4 || length > (ulong)(end - at - 8)) { _issues.Add(new("signing block", $"entry of {length} bytes does not fit", at)); break; }
                uint id = BinaryPrimitives.ReadUInt32LittleEndian(apk.AsSpan((int)at + 8));
                _blockIds.Add(id);
                result.Add((id, apk.AsSpan((int)at + 12, (int)length - 4).ToArray()));
                at += 8 + (long)length;
            }
            return result;
        }

        // ---- v2, v3, v3.1 ----

        private ApkSchemeResult SchemeV2V3(string scheme, byte[] value, bool v3, bool v3Present)
        {
            var signers = new List<ApkSigner>();
            var reasons = new List<string>();
            int p = 0;
            if (!Lp(value, ref p, out var list)) return new(scheme, Mismatch, [], ["the signer list is malformed"]);
            for (int q = 0; q < list.Length;)
            {
                if (!Lp(list, ref q, out var signer)) { reasons.Add("a signer is malformed"); break; }
                signers.Add(Signer(signer, v3, v3Present));
            }
            if (signers.Count == 0) reasons.Add("no signers");
            if (v3) reasons.AddRange(SignerSet(signers));
            return new(scheme, reasons.Count > 0 ? Mismatch : Worst(signers.Select(s => s.Verdict)), signers, reasons);
        }

        private ApkSigner Signer(ReadOnlySpan<byte> s, bool v3, bool v3Present)
        {
            var reasons = new List<string>();
            var certificates = new List<ApkCertificate>();
            var lineage = new List<ApkLineageNode>();
            var attributeIds = new List<uint>();
            ApkSigner Fail(string reason) => new(certificates, [], null, null, Mismatch, [.. reasons, reason], lineage, attributeIds);

            int p = 0;
            if (!Lp(s, ref p, out var signedData)) return Fail("signed data is malformed");
            int? minSdk = null, maxSdk = null;
            if (v3)
            {
                if (p + 8 > s.Length) return Fail("SDK range is missing");
                minSdk = (int)BinaryPrimitives.ReadUInt32LittleEndian(s[p..]);
                maxSdk = (int)BinaryPrimitives.ReadUInt32LittleEndian(s[(p + 4)..]);
                p += 8;
            }
            if (!Lp(s, ref p, out var signatures) || !Lp(s, ref p, out var publicKey)) return Fail("signatures or public key are malformed");

            // Signed data: digests, certificates, (v3: SDK range), additional attributes.
            int d = 0;
            if (!Lp(signedData, ref d, out var digestList) || !Lp(signedData, ref d, out var certList)) return Fail("signed data is malformed");
            var digests = Pairs(digestList);
            foreach (var der in Items(certList)) if (Certificate(der) is { } c) certificates.Add(c.Info);
            if (v3)
            {
                if (d + 8 > signedData.Length) return Fail("signed data lacks the SDK range");
                if ((int)BinaryPrimitives.ReadUInt32LittleEndian(signedData[d..]) != minSdk || (int)BinaryPrimitives.ReadUInt32LittleEndian(signedData[(d + 4)..]) != maxSdk)
                    reasons.Add("the SDK range of the signer and of its signed data differ");
                d += 8;
            }
            if (!Lp(signedData, ref d, out var attributes)) return Fail("additional attributes are malformed");
            int? rotationMinSdk = null;
            foreach (var (id, attribute) in Pairs(attributes, prefixed: false))
            {
                attributeIds.Add(id);
                if (id == StrippingProtectionId && !v3 && !v3Present)
                    reasons.Add("the v2 signature says a v3 signature was made, but there is none (stripped)");
                if (id == ProofOfRotationId && v3) Lineage(attribute, lineage, reasons, certificates.FirstOrDefault());
                if (id == RotationMinSdkId && v3 && attribute.Length >= 4) rotationMinSdk = (int)BinaryPrimitives.ReadUInt32LittleEndian(attribute);
            }

            var sigs = Pairs(signatures);
            if (sigs.Count == 0) return Fail("no signatures");
            if (!sigs.Select(x => x.Id).SequenceEqual(digests.Select(x => x.Id)))
                reasons.Add("the signature algorithms and the digest algorithms of the signed data differ");
            var leaf = Items(certList).FirstOrDefault();
            if (leaf == null) reasons.Add("no certificate");
            else if (Certificate(leaf) is { } first && !first.Spki.AsSpan().SequenceEqual(publicKey))
                reasons.Add("the public key differs from the first certificate's");

            // Signatures this build cannot check are notes, not failures: another signature of the signer may still verify.
            var notes = new List<string>();
            bool anyVerified = false;
            foreach (var (id, signature) in sigs)
            {
                if (!Algorithms.TryGetValue(id, out var algorithm)) { notes.Add($"signature algorithm 0x{id:x4} is unknown"); continue; }
                switch (VerifySignature(algorithm, publicKey, signedData, signature))
                {
                    case true: break;
                    case false: reasons.Add($"the {algorithm.Name} signature does not verify"); continue;
                    case null: notes.Add($"{algorithm.Name} signatures cannot be checked on this host"); continue;
                }
                var expected = digests.FirstOrDefault(x => x.Id == id).Value;
                if (algorithm.Digest == ContentDigest.Verity && _blockStart % 4096 != 0)
                {
                    reasons.Add($"{algorithm.Name}: the signing block does not start at a 4096-byte boundary, which a verity digest requires");
                    continue;
                }
                if (expected == null || !Content(algorithm.Digest).AsSpan().SequenceEqual(expected))
                    reasons.Add($"{algorithm.Name}: the content digest differs from the file (the APK changed after signing)");
                else anyVerified = true;
            }
            return new(certificates, sigs.Select(x => AlgorithmName(x.Id)).ToList(), minSdk, maxSdk, Outcome(reasons, notes, anyVerified), [.. reasons, .. notes],
                lineage, attributeIds) { RotationMinSdk = rotationMinSdk };
        }

        /// <summary>Several v3 signers each cover their own SDK range, and their rotation lineages are one history: each the start of the longest.</summary>
        private static IEnumerable<string> SignerSet(List<ApkSigner> signers)
        {
            for (int i = 0; i < signers.Count; i++)
                for (int j = i + 1; j < signers.Count; j++)
                    if (signers[i].MinSdk is { } a0 && signers[i].MaxSdk is { } a1 && signers[j].MinSdk is { } b0 && signers[j].MaxSdk is { } b1 && a0 <= b1 && b0 <= a1)
                        yield return $"signers {i + 1} and {j + 1} cover overlapping SDK ranges ({a0}-{a1} and {b0}-{b1})";
            var longest = signers.MaxBy(x => x.Lineage.Count)?.Lineage ?? [];
            for (int i = 0; i < signers.Count; i++)
            {
                var own = signers[i].Lineage;
                if (own.Count > 0 && !own.Select(n => n.Certificate.Sha256).SequenceEqual(longest.Take(own.Count).Select(n => n.Certificate.Sha256)))
                    yield return $"signer {i + 1}'s rotation lineage is not the start of the longest lineage of the block";
            }
        }

        /// <summary>The v3.1 signers apply from the SDK the v3 signer names (rotation-min-sdk-version); below it the v3 signer does.</summary>
        private IEnumerable<string> Rotation()
        {
            var v3 = _schemes.FirstOrDefault(x => x.Scheme == "v3");
            var v31 = _schemes.FirstOrDefault(x => x.Scheme == "v3.1");
            if (v3 == null || v31 == null || v3.Signers.Select(x => x.RotationMinSdk).FirstOrDefault(x => x != null) is not { } minSdk) yield break;
            foreach (var signer in v31.Signers)
                if (signer.MinSdk is { } m && m != minSdk)
                    yield return $"the v3.1 signer starts at SDK {m}, but the v3 signer's rotation-min-sdk-version is {minSdk}";
        }

        private static string Outcome(List<string> failures, List<string> notes, bool anyVerified) =>
            failures.Count > 0 ? Mismatch : anyVerified ? Verified : notes.Count > 0 ? Unsupported : Mismatch;

        /// <summary>Proof of rotation: each certificate signs the next; the last must be the signer's.</summary>
        private void Lineage(byte[] value, List<ApkLineageNode> lineage, List<string> reasons, ApkCertificate? signer)
        {
            if (value.Length < 4 || BinaryPrimitives.ReadUInt32LittleEndian(value) != 1) { reasons.Add("the rotation lineage has an unknown version"); return; }
            byte[]? last = null;
            uint lastAlgorithm = 0;
            for (int p = 4; p < value.Length;)
            {
                if (!Lp(value, ref p, out var node)) { reasons.Add("a rotation lineage node is malformed"); return; }
                int q = 0;
                if (!Lp(node, ref q, out var signed) || q + 8 > node.Length) { reasons.Add("a rotation lineage node is malformed"); return; }
                uint flags = BinaryPrimitives.ReadUInt32LittleEndian(node[q..]), algorithm = BinaryPrimitives.ReadUInt32LittleEndian(node[(q + 4)..]);
                q += 8;
                if (!Lp(node, ref q, out var signature)) { reasons.Add("a rotation lineage node is malformed"); return; }
                int r = 0;
                if (!Lp(signed, ref r, out var der) || r + 4 > signed.Length || Certificate(der.ToArray()) is not { } cert)
                {
                    reasons.Add("a rotation lineage certificate is malformed");
                    return;
                }
                if (last != null)
                {
                    if (BinaryPrimitives.ReadUInt32LittleEndian(signed[r..]) != lastAlgorithm) reasons.Add($"lineage node {lineage.Count + 1}: the signing algorithm ids differ");
                    if (!Algorithms.TryGetValue(lastAlgorithm, out var a)) reasons.Add($"lineage node {lineage.Count + 1}: algorithm 0x{lastAlgorithm:x4} is unknown");
                    else if (VerifySignature(a, last, signed, signature) != true)
                        reasons.Add($"lineage node {lineage.Count + 1}: not signed by the previous certificate");
                }
                lineage.Add(new(cert.Info, flags));
                (last, lastAlgorithm) = (cert.Spki, algorithm);
            }
            if (signer != null && lineage.Count > 0 && lineage[^1].Certificate.Sha256 != signer.Sha256)
                reasons.Add("the rotation lineage does not end at the signer's certificate");
        }

        /// <summary>True when the signature verifies, false when it does not, null when the host cannot check it.</summary>
        private static bool? VerifySignature(Algorithm a, ReadOnlySpan<byte> spki, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            try
            {
                switch (a.Key)
                {
                    case "RSA":
                        using (var rsa = RSA.Create())
                        {
                            rsa.ImportSubjectPublicKeyInfo(spki, out _);
                            return rsa.VerifyData(data, signature, a.Hash, a.Pss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
                        }
                    case "EC":
                        using (var ec = ECDsa.Create())
                        {
                            ec.ImportSubjectPublicKeyInfo(spki, out _);
                            return ec.VerifyData(data, signature, a.Hash, DSASignatureFormat.Rfc3279DerSequence);
                        }
                    default:
                        using (var dsa = DSA.Create())
                        {
                            dsa.ImportSubjectPublicKeyInfo(spki, out _);
                            return dsa.VerifyData(data, signature, a.Hash, DSASignatureFormat.Rfc3279DerSequence);
                        }
                }
            }
            catch (PlatformNotSupportedException) { return null; }
            catch (CryptographicException) { return false; }
        }

        /// <summary>
        /// The content digest of the file over the entries, the central directory and the end record pointing at the
        /// signing block: chunked SHA-256 / SHA-512, or the verity root (8 zero bytes of salt) followed by the length.
        /// </summary>
        private byte[] Content(ContentDigest kind)
        {
            if (_digests.TryGetValue(kind, out var done)) return done;
            var hash = kind == ContentDigest.Sha512Chunked ? HashAlgorithmName.SHA512 : HashAlgorithmName.SHA256;
            var eocd = apk.AsSpan((int)_eocd).ToArray();
            BinaryPrimitives.WriteUInt32LittleEndian(eocd.AsSpan(16), (uint)_blockStart);
            ReadOnlyMemory<byte>[] sections = [apk.AsMemory(0, (int)_blockStart), apk.AsMemory((int)_cdOffset, (int)(_eocd - _cdOffset)), eocd];
            if (kind == ContentDigest.Verity)
            {
                var data = new byte[sections.Sum(x => x.Length)];
                int at = 0;
                foreach (var section in sections) { section.Span.CopyTo(data.AsSpan(at)); at += section.Length; }
                var encoded = new byte[40];
                MerkleRoot(data, new byte[8]).CopyTo(encoded, 0);
                BinaryPrimitives.WriteInt64LittleEndian(encoded.AsSpan(32), data.Length);
                return _digests[kind] = encoded;
            }
            const int Chunk = 1 << 20;
            long chunks = sections.Sum(s => (s.Length + (long)Chunk - 1) / Chunk);
            using var top = IncrementalHash.CreateHash(hash);
            Span<byte> prefix = stackalloc byte[5];
            prefix[0] = 0x5a;
            BinaryPrimitives.WriteUInt32LittleEndian(prefix[1..], (uint)chunks);
            top.AppendData(prefix);
            using var one = IncrementalHash.CreateHash(hash);
            foreach (var section in sections)
                for (int at = 0; at < section.Length; at += Chunk)
                {
                    var chunk = section.Span.Slice(at, Math.Min(Chunk, section.Length - at));
                    prefix[0] = 0xa5;
                    BinaryPrimitives.WriteUInt32LittleEndian(prefix[1..], (uint)chunk.Length);
                    one.AppendData(prefix);
                    one.AppendData(chunk);
                    top.AppendData(one.GetHashAndReset());
                }
            return _digests[kind] = top.GetHashAndReset();
        }

        // ---- v4 ----

        private ApkSchemeResult V4(byte[] idsig)
        {
            ApkSchemeResult Fail(string reason) => new("v4", Mismatch, [], [reason]);
            if (idsig.Length < 4) return Fail("the .idsig file is truncated");
            uint version = BinaryPrimitives.ReadUInt32LittleEndian(idsig);
            int p = 4;
            if (version != 2) return new("v4", Unsupported, [], [$".idsig version {version} is not supported (2 is)"]);
            if (!Lp(idsig, ref p, out var hashing) || !Lp(idsig, ref p, out var signing)) return Fail("the .idsig file is malformed");
            if (hashing.Length < 5) return Fail("hashing info is malformed");
            uint hashAlgorithm = BinaryPrimitives.ReadUInt32LittleEndian(hashing);
            byte log2 = hashing[4];
            int h = 5;
            if (!Lp(hashing, ref h, out var salt) || !Lp(hashing, ref h, out var rootHash)) return Fail("hashing info is malformed");

            // The Merkle tree is the file's, shared by every signer.
            var treeReasons = new List<string>();
            var treeNotes = new List<string>();
            if (hashAlgorithm != 1 || log2 != 12) treeNotes.Add($"hash algorithm {hashAlgorithm} with 2^{log2}-byte blocks is not supported (SHA-256, 4096)");
            else if (!MerkleRoot(apk, salt.ToArray()).AsSpan().SequenceEqual(rootHash)) treeReasons.Add("the Merkle root differs from the file (the APK changed after signing)");
            var hashingInfo = new V4Hashing(hashAlgorithm, log2, salt.ToArray(), rootHash.ToArray());

            // Signing infos: the v3 (or v2) signer's, then one block per further scheme (v3.1) with its block id.
            int s = 0;
            if (!V4SigningInfo(signing, ref s, out var first)) return Fail("signing info is malformed");
            var infos = new List<(string Scheme, byte[] Info)> { (_schemes.Any(x => x.Scheme == "v3") ? "v3" : "v2", first.ToArray()) };
            var reasons = new List<string>();
            while (s < signing.Length)
            {
                if (s + 4 > signing.Length) { reasons.Add("a signing info block is truncated"); break; }
                uint blockId = BinaryPrimitives.ReadUInt32LittleEndian(signing[s..]);
                s += 4;
                if (!Lp(signing, ref s, out var block)) { reasons.Add("a signing info block is malformed"); break; }
                infos.Add((blockId == V31BlockId ? "v3.1" : $"block 0x{blockId:x8}", block.ToArray()));
            }
            if (!_schemes.Any(x => x.Scheme is "v2" or "v3" or "v3.1")) reasons.Add("v4 needs a v2 or v3 signature, and there is none");
            var signers = infos.Select(i => V4Signer(i.Scheme, i.Info, hashingInfo, treeReasons, treeNotes)).ToList();
            var verdict = reasons.Count > 0 ? Mismatch : Worst(signers.Select(x => x.Verdict));
            return new("v4", verdict, signers, reasons);
        }

        private sealed record V4Hashing(uint Algorithm, byte Log2, byte[] Salt, byte[] Root);

        private static bool V4SigningInfo(ReadOnlySpan<byte> s, ref int p, out ReadOnlySpan<byte> info)
        {
            int start = p;
            info = default;
            for (int i = 0; i < 4; i++) if (!Lp(s, ref p, out _)) return false;
            if (p + 4 > s.Length) return false;
            p += 4;
            if (!Lp(s, ref p, out _)) return false;
            info = s[start..p];
            return true;
        }

        /// <summary>One v4 signer: its signature over the hashing info and its own fields, its APK digest, and its certificate against the scheme it extends.</summary>
        private ApkSigner V4Signer(string scheme, byte[] info, V4Hashing hashing, List<string> treeReasons, List<string> treeNotes)
        {
            var reasons = new List<string>(treeReasons);
            var notes = new List<string>(treeNotes);
            int s = 0;
            ReadOnlySpan<byte> span = info;
            if (!Lp(span, ref s, out var apkDigest) || !Lp(span, ref s, out var der) || !Lp(span, ref s, out var additional) || !Lp(span, ref s, out var publicKey)
                || s + 4 > span.Length)
                return new([], [], null, null, Mismatch, ["signing info is malformed"], [], []);
            uint algorithmId = BinaryPrimitives.ReadUInt32LittleEndian(span[s..]);
            s += 4;
            if (!Lp(span, ref s, out var signature)) return new([], [], null, null, Mismatch, ["signing info is malformed"], [], []);
            var cert = Certificate(der.ToArray());

            // The signed data: size, file size, hashing info, and the APK digest, certificate and additional data.
            var signed = new MemoryStream();
            void U32(uint v) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(b, v); signed.Write(b); }
            void Bytes(ReadOnlySpan<byte> b) { U32((uint)b.Length); signed.Write(b); }
            int size = 4 + 8 + 4 + 1 + 4 + hashing.Salt.Length + 4 + hashing.Root.Length + 4 + apkDigest.Length + 4 + der.Length + 4 + additional.Length;
            U32((uint)size);
            Span<byte> fileSize = stackalloc byte[8];
            BinaryPrimitives.WriteInt64LittleEndian(fileSize, apk.Length);
            signed.Write(fileSize);
            U32(hashing.Algorithm);
            signed.WriteByte(hashing.Log2);
            Bytes(hashing.Salt); Bytes(hashing.Root); Bytes(apkDigest); Bytes(der); Bytes(additional);

            if (!Algorithms.TryGetValue(algorithmId, out var algorithm)) notes.Add($"signature algorithm 0x{algorithmId:x4} is unknown");
            else
                switch (VerifySignature(algorithm, publicKey, signed.ToArray(), signature))
                {
                    case false: reasons.Add($"the {algorithm.Name} signature does not verify"); break;
                    case null: notes.Add($"{algorithm.Name} signatures cannot be checked on this host"); break;
                }
            if (cert != null && !cert.Spki.AsSpan().SequenceEqual(publicKey))
                reasons.Add("the public key differs from the certificate's");
            // The APK digest is a v2 / v3 content digest of the file: chunked SHA-256 or SHA-512, or verity.
            var claimed = apkDigest.ToArray();
            if (_blockStart < 0 || !new[] { ContentDigest.Sha256Chunked, ContentDigest.Sha512Chunked, ContentDigest.Verity }.Any(k => Content(k).AsSpan().SequenceEqual(claimed)))
                reasons.Add("the APK digest is not the content digest of the file");
            // The certificate is the one of a signer of the scheme it extends.
            if (cert != null && _schemes.FirstOrDefault(x => x.Scheme == scheme) is { } extended
                && !extended.Signers.Any(x => x.Certificates.FirstOrDefault()?.Sha256 == cert.Info.Sha256))
                reasons.Add($"the certificate is not the one of a {scheme} signer");
            List<ApkCertificate> certificates = cert != null ? [cert.Info] : [];
            // Every check must pass: one that could not run leaves the file unverified.
            string verdict = Outcome(reasons, notes, anyVerified: notes.Count == 0);
            return new ApkSigner(certificates, [AlgorithmName(algorithmId)], null, null, verdict, [.. reasons, .. notes], [], []) { Extends = scheme };
        }

        /// <summary>fs-verity Merkle root of <paramref name="data"/>: salted SHA-256 of 4 KiB blocks (zero padded), level by level, until one block remains.</summary>
        private static byte[] MerkleRoot(byte[] data, byte[] salt)
        {
            const int Block = 4096;
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            byte[] Hash(ReadOnlySpan<byte> block)
            {
                sha.AppendData(salt);
                sha.AppendData(block);
                if (block.Length < Block) sha.AppendData(new byte[Block - block.Length]);
                return sha.GetHashAndReset();
            }
            byte[] level = data;
            do
            {
                var next = new byte[((level.Length + Block - 1) / Block) * 32];
                for (int i = 0; i * Block < level.Length; i++)
                    Hash(level.AsSpan(i * Block, Math.Min(Block, level.Length - i * Block))).CopyTo(next, i * 32);
                level = next;
            } while (level.Length > Block);
            return Hash(level);
        }

        // ---- v1 (JAR signing) ----

        private void V1(List<(uint Id, byte[]? Value)> blocks)
        {
            ZipArchive? zip = null;
            var entries = new Dictionary<string, ZipArchiveEntry>(StringComparer.Ordinal);
            try
            {
                zip = new ZipArchive(new MemoryStream(apk, writable: false), ZipArchiveMode.Read);
                foreach (var e in zip.Entries) entries.TryAdd(e.FullName, e); // the central directory is read here
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException or ArgumentException)
            {
                _issues.Add(new("zip", "entries could not be listed: " + ex.Message, null));
                zip?.Dispose();
                return;
            }
            using (zip)
            {
                var signatureFiles = entries.Keys.Where(n => n.StartsWith("META-INF/", StringComparison.OrdinalIgnoreCase) && n.EndsWith(".SF", StringComparison.OrdinalIgnoreCase) && n.Count(c => c == '/') == 1).ToList();
                if (signatureFiles.Count == 0) return;
                var reasons = new List<string>();
                var signers = new List<ApkSigner>();
                if (!entries.TryGetValue("META-INF/MANIFEST.MF", out var manifestEntry) || Read(manifestEntry) is not { } manifest)
                {
                    _schemes.Add(new("v1", Mismatch, [], ["META-INF/MANIFEST.MF is missing"]));
                    return;
                }
                var sections = Manifest.Parse(manifest);
                foreach (var sf in signatureFiles)
                    signers.Add(V1Signer(sf, entries, manifest, sections, blocks));
                reasons.AddRange(V1Entries(entries, sections));
                var verdict = reasons.Count > 0 ? Mismatch : Worst(signers.Select(s => s.Verdict));
                _schemes.Add(new("v1", verdict, signers, reasons));
            }
        }

        private ApkSigner V1Signer(string sfName, Dictionary<string, ZipArchiveEntry> entries, byte[] manifest, Manifest sections, List<(uint Id, byte[]? Value)> blocks)
        {
            var reasons = new List<string>();
            var certificates = new List<ApkCertificate>();
            var stem = sfName[..^3];
            var block = new[] { ".RSA", ".DSA", ".EC" }.Select(x => stem + x).FirstOrDefault(entries.ContainsKey);
            if (block == null || Read(entries[sfName]) is not { } sf || Read(entries[block]) is not { } pkcs7)
                return new([], [], null, null, Mismatch, [$"{sfName}: no readable signature block beside it"], [], []);
            try
            {
                var cms = new SignedCms(new ContentInfo(sf), detached: true);
                cms.Decode(pkcs7);
                foreach (var info in cms.SignerInfos)
                    if (info.Certificate is { } c) certificates.Add(Describe(c));
                cms.CheckSignature(verifySignatureOnly: true);
            }
            catch (CryptographicException ex) { reasons.Add($"{block}: the signature over {sfName} does not verify ({ex.Message})"); }
            catch (PlatformNotSupportedException) { return new(certificates, [], null, null, Unsupported, [$"{block}: cannot be checked on this host"], [], []); }

            var signature = Manifest.Parse(sf);
            if (signature.Main.TryGetValue("X-Android-APK-Signed", out var schemes))
                foreach (var id in schemes.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                {
                    uint blockId = id switch { "2" => V2BlockId, "3" => V3BlockId, _ => 0 };
                    if (blockId != 0 && !blocks.Any(b => b.Id == blockId)) reasons.Add($"{sfName} says a v{id} signature was made, but there is none (stripped)");
                }
            var algorithms = new List<string>();
            bool wholeManifest = false;
            foreach (var (key, digest) in signature.Main)
                if (key.EndsWith("-Digest-Manifest", StringComparison.OrdinalIgnoreCase) && Hash(key[..^"-Digest-Manifest".Length]) is { } h)
                {
                    algorithms.Add(h.Name!);
                    wholeManifest |= Base64Equals(HashBytes(h, manifest), digest);
                }
            if (!wholeManifest)
                foreach (var (name, attributes) in signature.Sections)
                {
                    if (!sections.Raw.TryGetValue(name, out var raw)) { reasons.Add($"{sfName} names {name}, which the manifest lacks"); continue; }
                    foreach (var (key, digest) in attributes)
                        if (key.EndsWith("-Digest", StringComparison.OrdinalIgnoreCase) && Hash(key[..^"-Digest".Length]) is { } h && !Base64Equals(HashBytes(h, raw), digest))
                            reasons.Add($"{sfName}: the manifest section of {name} differs");
                }
            return new(certificates, algorithms.Distinct().ToList(), null, null, reasons.Count == 0 ? Verified : Mismatch, reasons, [], []);
        }

        /// <summary>Every entry is listed in the manifest with digests that match its content.</summary>
        private IEnumerable<string> V1Entries(Dictionary<string, ZipArchiveEntry> entries, Manifest manifest)
        {
            foreach (var (name, entry) in entries)
            {
                if (name.EndsWith('/') || IsSignatureFile(name)) continue;
                if (!manifest.Sections.TryGetValue(name, out var attributes)) { yield return $"{name} is not in the manifest (added after signing)"; continue; }
                foreach (var (key, digest) in attributes)
                {
                    if (!key.EndsWith("-Digest", StringComparison.OrdinalIgnoreCase) || Hash(key[..^"-Digest".Length]) is not { } h) continue;
                    if (Read(entry) is not { } content) { yield return $"{name} could not be read"; break; }
                    if (!Base64Equals(HashBytes(h, content), digest)) yield return $"{name}: the content differs from the manifest digest";
                }
            }
            foreach (var name in manifest.Sections.Keys)
                if (!entries.ContainsKey(name)) yield return $"the manifest lists {name}, which is missing";
        }

        private static bool IsSignatureFile(string name)
        {
            if (!name.StartsWith("META-INF/", StringComparison.OrdinalIgnoreCase) || name.Count(c => c == '/') != 1) return false;
            var file = name[9..].ToUpperInvariant();
            return file == "MANIFEST.MF" || file.EndsWith(".SF", StringComparison.Ordinal) || file.EndsWith(".RSA", StringComparison.Ordinal)
                || file.EndsWith(".DSA", StringComparison.Ordinal) || file.EndsWith(".EC", StringComparison.Ordinal) || file.StartsWith("SIG-", StringComparison.Ordinal);
        }

        private byte[]? Read(ZipArchiveEntry entry)
        {
            if (entry.Length > limits.MaxItemBytes)
            {
                _issues.Add(new("zip", $"{entry.FullName} is larger than {limits.MaxItemBytes} bytes and is not read", null));
                return null;
            }
            try
            {
                using var s = entry.Open();
                var buffer = new MemoryStream((int)entry.Length);
                s.CopyTo(buffer);
                return buffer.ToArray();
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException or NotSupportedException)
            {
                _issues.Add(new("zip", $"{entry.FullName}: {ex.Message}", null));
                return null;
            }
        }

        private static HashAlgorithmName? Hash(string name) => name.ToUpperInvariant() switch
        {
            "SHA1" or "SHA-1" => HashAlgorithmName.SHA1,
            "SHA-256" => HashAlgorithmName.SHA256,
            "SHA-384" => HashAlgorithmName.SHA384,
            "SHA-512" => HashAlgorithmName.SHA512,
            _ => null,
        };

        private static byte[] HashBytes(HashAlgorithmName h, byte[] data)
        {
            using var hash = IncrementalHash.CreateHash(h);
            hash.AppendData(data);
            return hash.GetHashAndReset();
        }

        private static bool Base64Equals(byte[] digest, string base64) =>
            Convert.ToBase64String(digest) == base64.Trim();

        // ---- shared ----

        /// <summary>A parsed certificate and its SubjectPublicKeyInfo (empty when the key cannot be read).</summary>
        private sealed record LoadedCert(ApkCertificate Info, byte[] Spki);

        private LoadedCert? Certificate(ReadOnlySpan<byte> der)
        {
            try
            {
                using var c = X509CertificateLoader.LoadCertificate(der);
                return new(Describe(c), Guard(() => c.PublicKey.ExportSubjectPublicKeyInfo(), []));
            }
            catch (CryptographicException ex)
            {
                _issues.Add(new("certificate", "a certificate could not be read: " + ex.Message, null));
                return null;
            }
        }

        /// <summary>Certificate fields that cannot be decoded (malformed key or times) read as empty instead of throwing.</summary>
        private static ApkCertificate Describe(X509Certificate2 c)
        {
            var oid = Guard(() => c.PublicKey.Oid.Value, null);
            var (algorithm, size) = oid switch
            {
                "1.2.840.113549.1.1.1" => ("RSA", Guard(() => { using var k = c.GetRSAPublicKey(); return k?.KeySize ?? 0; }, 0)),
                "1.2.840.10045.2.1" => ("EC", Guard(() => { using var k = c.GetECDsaPublicKey(); return k?.KeySize ?? 0; }, 0)),
                "1.2.840.10040.4.1" => ("DSA", Guard(() => { using var k = c.GetDSAPublicKey(); return k?.KeySize ?? 0; }, 0)),
                _ => (oid ?? "?", 0),
            };
            var subject = Guard(() => c.Subject, "");
            return new(subject, Guard(() => c.Issuer, ""), Convert.ToHexStringLower(SHA256.HashData(c.RawData)), algorithm, size,
                Guard(() => c.NotBefore.ToUniversalTime(), default), Guard(() => c.NotAfter.ToUniversalTime(), default),
                subject.Contains("CN=Android Debug", StringComparison.Ordinal));
        }

        private static T Guard<T>(Func<T> read, T fallback)
        {
            try { return read(); }
            catch (Exception ex) when (ex is CryptographicException or ArgumentException or PlatformNotSupportedException) { return fallback; }
        }

        /// <summary>A uint32 little-endian length-prefixed slice at <paramref name="p"/>.</summary>
        private static bool Lp(ReadOnlySpan<byte> s, ref int p, out ReadOnlySpan<byte> value)
        {
            value = default;
            if (p < 0 || p + 4 > s.Length) return false;
            uint length = BinaryPrimitives.ReadUInt32LittleEndian(s[p..]);
            if (length > (uint)(s.Length - p - 4)) return false;
            value = s.Slice(p + 4, (int)length);
            p += 4 + (int)length;
            return true;
        }

        /// <summary>A sequence of length-prefixed items.</summary>
        private static List<byte[]> Items(ReadOnlySpan<byte> s)
        {
            var items = new List<byte[]>();
            for (int p = 0; p < s.Length;)
            {
                if (!Lp(s, ref p, out var item)) break;
                items.Add(item.ToArray());
            }
            return items;
        }

        /// <summary>
        /// A sequence of length-prefixed (uint32 id, value) pairs. Digests and signatures wrap the value in another length
        /// prefix (<paramref name="prefixed"/>); additional attributes do not.
        /// </summary>
        private static List<(uint Id, byte[] Value)> Pairs(ReadOnlySpan<byte> s, bool prefixed = true)
        {
            var pairs = new List<(uint, byte[])>();
            foreach (var item in Items(s))
            {
                if (item.Length < 4) break;
                uint id = BinaryPrimitives.ReadUInt32LittleEndian(item);
                int p = 4;
                if (!prefixed) pairs.Add((id, item[4..]));
                else if (Lp(item, ref p, out var inner)) pairs.Add((id, inner.ToArray()));
                else break;
            }
            return pairs;
        }
    }

    /// <summary>A JAR manifest or signature file: main attributes and named sections, with each section's raw bytes.</summary>
    private sealed class Manifest
    {
        public Dictionary<string, string> Main { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, Dictionary<string, string>> Sections { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, byte[]> Raw { get; } = new(StringComparer.Ordinal);

        public static Manifest Parse(byte[] bytes)
        {
            var m = new Manifest();
            int at = 0;
            bool main = true;
            while (at < bytes.Length)
            {
                // A section ends after an empty line; its raw bytes include that line.
                int start = at;
                var lines = new List<string>();
                while (at < bytes.Length)
                {
                    int end = at;
                    while (end < bytes.Length && bytes[end] != '\n' && bytes[end] != '\r') end++;
                    var line = Encoding.UTF8.GetString(bytes, at, end - at);
                    if (end < bytes.Length && bytes[end] == '\r') end++;
                    if (end < bytes.Length && bytes[end] == '\n') end++;
                    at = end;
                    if (line.Length == 0) break;
                    if (line[0] == ' ' && lines.Count > 0) lines[^1] += line[1..];
                    else lines.Add(line);
                }
                var attributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var line in lines)
                {
                    int colon = line.IndexOf(": ", StringComparison.Ordinal);
                    if (colon > 0) attributes[line[..colon]] = line[(colon + 2)..];
                }
                if (main)
                {
                    foreach (var (k, v) in attributes) m.Main[k] = v;
                    main = false;
                }
                else if (attributes.TryGetValue("Name", out var name))
                {
                    m.Sections.TryAdd(name, attributes);
                    m.Raw.TryAdd(name, bytes[start..at]);
                }
            }
            return m;
        }
    }
}
