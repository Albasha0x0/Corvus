using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;
using Corvus.Native.Pe;

namespace Corvus.Native.MachO;

/// <summary>
/// A CodeDirectory blob. Hashes of special slots (Info.plist 1, requirements 2, resources 3, entitlements 5, DER
/// entitlements 7, ...) sit before <see cref="HashOffset"/>, code page hashes after it. <see cref="CdHash"/> is the hash
/// of the whole blob with its own hash type, truncated to 20 bytes.
/// </summary>
public sealed record CodeDirectory(uint Slot, uint Version, uint Flags, string Identifier, string? TeamId, byte HashType, byte HashSize, byte PageSizeLog2,
    ulong CodeLimit, uint SpecialSlots, uint CodeSlots, byte Platform, ulong ExecSegmentBase, ulong ExecSegmentLimit, ulong ExecSegmentFlags,
    uint HashOffset, byte[] CdHash, byte[] Blob)
{
    public string HashName => HashType switch { 1 => "sha1", 2 => "sha256", 3 => "sha256-truncated", 4 => "sha384", _ => $"hash type {HashType}" };
    public string CdHashHex => Convert.ToHexStringLower(CdHash);
    /// <summary>CS_ADHOC: signed without a certificate.</summary>
    public bool IsAdHoc => (Flags & 0x2) != 0;
    /// <summary>Bytes hashed per code slot; 0 means one hash over everything up to the code limit.</summary>
    public uint PageSize => PageSizeLog2 == 0 ? 0 : 1u << PageSizeLog2;

    /// <summary>The hash of special slot <paramref name="slot"/> (1-based), empty when out of range.</summary>
    public ReadOnlySpan<byte> SpecialSlotHash(int slot) =>
        slot >= 1 && slot <= SpecialSlots && HashOffset >= slot * HashSize && HashOffset <= Blob.Length ? Blob.AsSpan((int)(HashOffset - slot * HashSize), HashSize) : [];

    /// <summary>The hash of code page <paramref name="index"/>, empty when out of range.</summary>
    public ReadOnlySpan<byte> CodeSlotHash(int index) =>
        index >= 0 && index < CodeSlots && (long)HashOffset + (long)(index + 1) * HashSize <= Blob.Length ? Blob.AsSpan((int)(HashOffset + index * HashSize), HashSize) : [];
}

/// <summary>
/// The embedded signature (LC_CODE_SIGNATURE SuperBlob): code directories, requirements, entitlements (XML and DER)
/// and the CMS signature, whose signer is named but not verified.
/// </summary>
public sealed record CodeSignature(IReadOnlyList<(uint Slot, uint Offset, uint Magic, uint Length)> Blobs, IReadOnlyList<CodeDirectory> CodeDirectories,
    string? Entitlements, byte[]? DerEntitlements, IReadOnlyList<CodeRequirement>? Requirements, byte[]? Cms, string? SignerSubject)
{
    /// <summary>Requirements in the set; null when the signature has no requirement set.</summary>
    public int? RequirementCount => Requirements?.Count;

    /// <summary>The code directory in slot 0, else the first alternate.</summary>
    public CodeDirectory? Primary => CodeDirectories.FirstOrDefault(c => c.Slot == 0) ?? CodeDirectories.FirstOrDefault();
    public string? Identifier => Primary?.Identifier;
    public string? TeamId => Primary?.TeamId;
    /// <summary>Ad-hoc: CS_ADHOC set or no CMS signature data.</summary>
    public bool IsAdHoc => Primary?.IsAdHoc == true || Cms is not { Length: > 0 };

    private const int MaxBlobs = 64;

    /// <summary>Parses a SuperBlob; problems are logged and what was read is returned.</summary>
    internal static CodeSignature Parse(ByteView data, IssueLog log)
    {
        var blobs = new List<(uint, uint, uint, uint)>();
        var directories = new List<CodeDirectory>();
        string? entitlements = null, subject = null;
        byte[]? der = null, cms = null;
        IReadOnlyList<CodeRequirement>? requirements = null;
        // Signature blobs are big-endian whatever the image's byte order.
        var be = new ByteView(data.Span(0, data.Length).ToArray(), true);
        if (be.U32(0) != 0xFADE0CC0)
        {
            log.Add($"code signature magic 0x{be.U32(0):X8} is not a SuperBlob");
            return new CodeSignature(blobs, directories, null, null, null, null, null);
        }
        uint count = Math.Min(be.U32(8), MaxBlobs);
        for (uint i = 0; i < count; i++)
        {
            uint slot = be.U32(12 + 8L * i), offset = be.U32(16 + 8L * i);
            uint magic = be.U32(offset), length = be.U32(offset + 4);
            blobs.Add((slot, offset, magic, length));
            if (length < 8 || !be.Has(offset, length))
            {
                log.Add($"code signature blob {i} (slot 0x{slot:X}) at +0x{offset:X} with length {length} lies outside the signature");
                continue;
            }
            var blob = be.Slice(offset, length);
            switch (magic)
            {
                case 0xFADE0C02:
                    if (ParseDirectory(slot, blob, log) is { } cd) directories.Add(cd);
                    break;
                case 0xFADE0C01: requirements = CodeRequirements.Parse(blob.Span(0, length), log); break;
                case 0xFADE7171: entitlements = Encoding.UTF8.GetString(blob.Span(8, length - 8)); break;
                case 0xFADE7172: der = blob.Span(8, length - 8).ToArray(); break;
                case 0xFADE0B01:
                    cms = blob.Span(8, length - 8).ToArray();
                    subject = Signer(cms, log);
                    break;
            }
        }
        return new CodeSignature(blobs, directories, entitlements, der, requirements, cms, subject);
    }

    private static CodeDirectory? ParseDirectory(uint slot, ByteView cd, IssueLog log)
    {
        if (cd.Length < 44)
        {
            log.Add($"code directory in slot 0x{slot:X} is truncated");
            return null;
        }
        uint version = cd.U32(8), flags = cd.U32(12), hashOffset = cd.U32(16), identOffset = cd.U32(20), special = cd.U32(24), code = cd.U32(28);
        ulong limit = cd.U32(32);
        byte hashSize = cd.U8(36), hashType = cd.U8(37), platform = cd.U8(38), pageSize = cd.U8(39);
        string? team = version >= 0x20200 && cd.U32(48) is var teamOffset and > 0 ? cd.CString(teamOffset, 256) : null;
        if (version >= 0x20300 && cd.U64(56) != 0) limit = cd.U64(56);
        ulong execBase = 0, execLimit = 0, execFlags = 0;
        if (version >= 0x20400) (execBase, execLimit, execFlags) = (cd.U64(64), cd.U64(72), cd.U64(80));
        string identifier = cd.CString(identOffset, 1024) ?? "";
        if ((long)hashOffset + (long)code * hashSize > cd.Length || (long)special * hashSize > hashOffset)
            log.Add($"code directory in slot 0x{slot:X}: hash slots lie outside the blob");
        var bytes = cd.Span(0, cd.Length).ToArray();
        byte[] full = hashType switch { 1 => SHA1.HashData(bytes), 4 => SHA384.HashData(bytes), _ => SHA256.HashData(bytes) };
        return new CodeDirectory(slot, version, flags, identifier, team, hashType, hashSize, pageSize, limit, special, code, platform, execBase, execLimit, execFlags,
            hashOffset, full.AsSpan(0, 20).ToArray(), bytes);
    }

    /// <summary>The subject of the first CMS signer's certificate (the chain is not verified).</summary>
    private static string? Signer(byte[] cms, IssueLog log)
    {
        if (cms.Length == 0) return null;
        try
        {
            var signed = new SignedCms();
            signed.Decode(cms);
            return signed.SignerInfos.Count > 0 ? signed.SignerInfos[0].Certificate?.Subject : null;
        }
        catch (CryptographicException ex)
        {
            log.Add($"the CMS signature does not decode: {ex.Message}");
            return null;
        }
    }
}
