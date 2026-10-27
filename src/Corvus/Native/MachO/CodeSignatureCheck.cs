using System.Security.Cryptography;

namespace Corvus.Native.MachO;

/// <summary>A slice's code page and Info.plist hashes checked against its code directory; the CMS signer is named, never verified, so no verdict says trusted.</summary>
public sealed record SignatureVerdict(string Verdict, string? Identifier, string? TeamId, string? Signer, int Pages, int PagesDiffering, IReadOnlyList<string> Reasons)
{
    public static SignatureVerdict Of(MachOFile image, byte[]? infoPlist = null)
    {
        if (image.CodeSignature is not { Primary: { } cd } sig)
            return new("unsigned", null, null, null, 0, 0, ["no LC_CODE_SIGNATURE"]);
        var reasons = new List<string>();
        var bytes = image.FileBytes.Span;
        int pages = 0, differing = 0;
        if (cd.CodeLimit > (ulong)bytes.Length) reasons.Add($"the code limit {cd.CodeLimit:N0} is past the end of the slice ({bytes.Length:N0} bytes)");
        else if (Hash(cd.HashType) is not { } hash) reasons.Add($"{cd.HashName} is not checked");
        else
        {
            long limit = (long)cd.CodeLimit, size = cd.PageSize == 0 ? limit : cd.PageSize;
            for (long at = 0; at < limit && pages < cd.CodeSlots; at += size, pages++)
            {
                var expected = cd.CodeSlotHash(pages);
                var actual = hash(bytes.Slice((int)at, (int)Math.Min(size, limit - at)));
                if (expected.Length == 0 || !actual.AsSpan(0, expected.Length).SequenceEqual(expected)) differing++;
            }
            if (pages != cd.CodeSlots) reasons.Add($"{cd.CodeSlots} code slots for {pages} pages up to the code limit");
            if (differing > 0) reasons.Add($"{differing} of {pages} code pages differ from their hashes");
            if (infoPlist != null && cd.SpecialSlotHash(1) is { Length: > 0 } plistSlot && !plistSlot.ToArray().All(b => b == 0)
                && !hash(infoPlist).AsSpan(0, plistSlot.Length).SequenceEqual(plistSlot))
                reasons.Add("Info.plist differs from the hash it was signed with");
        }
        bool linker = (cd.Flags & 0x20000) != 0;
        string kind = linker ? "linker-signed (ad-hoc)" : sig.IsAdHoc ? "ad-hoc signed" : $"signed by {CommonName(sig.SignerSubject) ?? "an unnamed signer"}";
        string verdict = reasons.Count == 0
            ? $"{kind}; all {pages} code pages match" + (sig.IsAdHoc ? "" : "; the certificate chain is not checked")
            : differing > 0 || reasons.Any(r => r.StartsWith("Info.plist", StringComparison.Ordinal)) ? $"damaged: {kind}, modified after signing" : $"{kind}; not fully checked";
        return new(verdict, cd.Identifier, cd.TeamId, sig.SignerSubject, pages, differing, reasons);
    }

    /// <summary>The CN of an X.500 subject ("Developer ID Application: Name (TEAM)"), else the subject.</summary>
    private static string? CommonName(string? subject) =>
        subject?.Split(", ").FirstOrDefault(p => p.StartsWith("CN=", StringComparison.Ordinal))?[3..] ?? subject;

    private static Func<ReadOnlySpan<byte>, byte[]>? Hash(byte type) => type switch
    {
        1 => b => SHA1.HashData(b),
        2 or 3 => b => SHA256.HashData(b),
        4 => b => SHA384.HashData(b),
        _ => null,
    };
}
