using Corvus.Native;
using Corvus.Native.Pe;

namespace Corvus.Services;

/// <summary>Cautions about where a native patch lands and what a save does to the file; each warning starts with its code.</summary>
public static class PatchWarnings
{
    /// <summary>Warning code: the section is executable and writable.</summary>
    public const string WritableExecutable = "writable_executable_section";

    /// <summary>Warning code: the bytes around the site look compressed or encrypted.</summary>
    public const string HighEntropy = "high_entropy_section";

    /// <summary>Warning code: the save leaves an Authenticode signature that no longer matches.</summary>
    public const string SignatureInvalidated = "signature_invalidated";

    // Entropy is read from this many bytes around the site, not the whole section.
    private const uint Window = 1 << 16;

    // Below this many bytes the entropy of a window says nothing.
    private const uint MinWindow = 0x1000;

    /// <summary>The warnings for patches at <paramref name="rvas"/>, one per section and kind; empty when none apply.</summary>
    public static IReadOnlyList<string> ForSites(INativeImage image, IEnumerable<uint> rvas)
    {
        var warnings = new List<string>();
        var seen = new HashSet<(string, string)>();
        var buffer = new byte[Window];
        foreach (var rva in rvas)
        {
            if (image.SectionAt(rva) is not { } section) continue;
            var where = $"{NativeAddress.Va(image, rva)} is in {section.Name}";
            if ((section.Access & SectionAccess.Write) != 0 && section.IsExecutable && seen.Add((section.Name, WritableExecutable)))
                warnings.Add($"{WritableExecutable}: {where}, which is writable and executable; a protector may rewrite or check these bytes at run time.");
            if (!seen.Add((section.Name, HighEntropy))) continue;
            var entropy = WindowEntropy(image, section, rva, buffer);
            if (entropy >= PackerDetection.HighEntropy)
                warnings.Add($"{HighEntropy}: {where}, entropy {entropy:0.00} around the site (compressed or encrypted); the file bytes may not be the code that runs.");
        }
        return warnings;
    }

    /// <summary>The warning for a PE image that carries an Authenticode signature, or null; a patched save leaves it invalid.</summary>
    public static string? ForSignature(INativeImage image) => image is PeFile { CertificateTable: not null }
        ? $"{SignatureInvalidated}: the image carries an Authenticode signature that no longer matches the patched file; stripSignature=true on save_native removes it."
        : null;

    private static double WindowEntropy(INativeImage image, NativeSection section, uint rva, byte[] buffer)
    {
        // A malformed section must not push the window past the 32-bit address space.
        long sectionEnd = Math.Min((long)section.Rva + Math.Min(section.RawSize == 0 ? section.MappedSize : section.RawSize, section.MappedSize), uint.MaxValue);
        long start = Math.Max(section.Rva, Math.Min(rva - Window / 2L, sectionEnd - Window));
        if (start < section.Rva) start = section.Rva;
        long span = Math.Min(Window, sectionEnd - start);
        if (span < MinWindow) return 0;
        long size = image.FileBackedLength((uint)start, span);
        return size < MinWindow ? 0 : PackerDetection.Entropy(image, (uint)start, (uint)size, buffer);
    }
}
