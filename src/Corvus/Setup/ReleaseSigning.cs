using System.Security.Cryptography;

namespace Corvus.Setup;

/// <summary>The release signing key and the check of SHA256SUMS.sig, an ECDSA P-256 signature (SHA-256, DER) of SHA256SUMS.</summary>
internal static class ReleaseSigning
{
    /// <summary>The value <see cref="PublicKey"/> holds until a signing key is published: signatures are then reported unknown.</summary>
    public const string Placeholder = "NO-RELEASE-SIGNING-KEY-PUBLISHED";

    /// <summary>
    /// The release signing public key: SubjectPublicKeyInfo DER in base64, one
    /// line. install.ps1 and install.sh hold the same value.
    /// </summary>
    public const string PublicKey = Placeholder;

    /// <summary>The release asset that holds the signature of <see cref="Installation.ChecksumManifest"/>.</summary>
    public const string SignatureAsset = "SHA256SUMS.sig";

    /// <summary>What the signature check concluded: verified, unknown (the reason is in the message) or refused.</summary>
    internal enum SignatureState { Verified, Unknown, Refused }

    /// <summary>A signature check's conclusion and the line to print for it.</summary>
    internal sealed record SignatureCheck(SignatureState State, string Message);

    /// <summary>
    /// Checks <paramref name="signature"/> (null: the release has none) over
    /// <paramref name="manifest"/> with <paramref name="publicKey"/>. A require
    /// of "0" skips the check; the placeholder key reports unknown.
    /// </summary>
    internal static SignatureCheck Check(ReadOnlySpan<byte> manifest, byte[]? signature, string publicKey, string? require)
    {
        if (require == "0") return new(SignatureState.Unknown, $"Signature not checked ({Installation.RequireAttestationVariable}=0).");
        if (publicKey == Placeholder) return new(SignatureState.Unknown, $"Signature of {Installation.ChecksumManifest} not checked: no release signing key is published yet.");
        if (signature is not { Length: > 0 })
            return new(SignatureState.Refused, $"The release has no {SignatureAsset}; refusing an unsigned {Installation.ChecksumManifest}. Nothing was installed.");
        bool valid;
        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);
            valid = key.VerifyData(manifest, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException) { valid = false; }
        return valid
            ? new(SignatureState.Verified, $"Signature verified: {Installation.ChecksumManifest} is signed by the release key.")
            : new(SignatureState.Refused, $"{SignatureAsset} does not verify with the release key: {Installation.ChecksumManifest} was altered or signed by another key. Nothing was installed.");
    }
}
