using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Elf;
using Corvus.Native.MachO;

namespace Corvus.Services.Analysis;

/// <summary>What summarize_file reports for an ELF or Mach-O image (one slice of a universal file).</summary>
public sealed record NativeImageFacts(
    string Format,
    string Machine,
    string Kind,
    string? Slice,
    IReadOnlyList<string>? Slices,
    string? BuildId,
    IReadOnlyList<string> Dependencies,
    int Imports,
    int Exports,
    int Symbols,
    int DeclaredFunctions,
    string? Platform,
    string? Signature,
    IReadOnlyList<string>? Entitlements,
    bool Encrypted,
    int Issues)
{
    private const int MaxDependencies = 32;

    /// <summary>Facts and highlights for an ELF or Mach-O file; null for anything else or an unreadable image.</summary>
    public static (NativeImageFacts Facts, List<string> Highlights)? Of(string path, byte[] bytes)
    {
        INativeImage image;
        try
        {
            image = NativeImageLoader.Detect(bytes) switch
            {
                NativeFileKind.Elf => ElfFile.FromBytes(bytes, path),
                NativeFileKind.MachO or NativeFileKind.MachOFat => MachOFile.FromBytes(bytes, path),
                _ => null!,
            };
        }
        catch (ToolError) { return null; }
        if (image == null) return null;
        var highlights = new List<string>();
        string? platform = null, signature = null;
        IReadOnlyList<string>? entitlements = null;
        switch (image)
        {
            case ElfFile elf:
                if (elf.AndroidIdent is { } a) platform = $"Android API {a.ApiLevel}" + (a.NdkVersion is { Length: > 0 } ndk ? $", NDK {ndk}" : "");
                if (elf.SectionHeaders.Count == 0) highlights.Add("ELF without section headers: sections are read from the load segments.");
                if (elf.IsMappedDump) highlights.Add("ELF memory image: read as mapped.");
                break;
            case MachOFile m:
                if (m.BuildVersion is { } bv) platform = $"{bv.PlatformName} {MachONames.Version(bv.MinOs)} (SDK {MachONames.Version(bv.Sdk)})";
                if (m.CodeSignature is { } sig)
                {
                    signature = (sig.IsAdHoc ? "ad-hoc" : sig.SignerSubject ?? "signed") + (sig.Identifier != null ? $", identifier {sig.Identifier}" : "") +
                                (sig.TeamId != null ? $", team {sig.TeamId}" : "");
                    entitlements = EntitlementKeys(sig.Entitlements);
                }
                if (m.Slices.Count > 0) highlights.Add($"Universal binary: {string.Join(", ", m.Slices.Select(s => s.Name))}; summarized: {m.Slice!.Name}.");
                break;
        }
        bool encrypted = image.EncryptedRanges.Count > 0;
        if (encrypted) highlights.Add("Code is FairPlay-encrypted (LC_ENCRYPTION_INFO cryptid != 0): analyze a decrypted copy.");
        if (entitlements is { Count: > 0 }) highlights.Add($"Entitlements: {string.Join(", ", entitlements.Take(8))}" + (entitlements.Count > 8 ? ", …" : ""));
        var facts = new NativeImageFacts(image.Format == ImageFormat.Elf ? (image.Is64Bit ? "ELF64" : "ELF32") : $"Mach-O {(image.Is64Bit ? "64" : "32")}-bit",
            image.MachineName, image.KindText(), (image as MachOFile)?.Slice?.Name,
            image is MachOFile { Slices.Count: > 0 } fat ? [.. fat.Slices.Select(s => s.Name)] : null,
            image.BuildId, [.. image.Dependencies.Take(MaxDependencies)], image.Imports.Count, image.Exports.Count, image.Symbols.Count,
            image.DeclaredFunctions.Count, platform, signature, entitlements, encrypted, image.Issues.Count);
        return (facts, highlights);
    }

    // NonBacktracking matches in linear time, so no match timeout.
    private static readonly System.Text.RegularExpressions.Regex EntitlementKey = new("<key>([^<]{1,256})</key>", System.Text.RegularExpressions.RegexOptions.NonBacktracking);

    /// <summary>The keys of an entitlements property list (plist XML), in order.</summary>
    private static List<string>? EntitlementKeys(string? xml)
    {
        if (string.IsNullOrEmpty(xml)) return null;
        var keys = new List<string>();
        foreach (System.Text.RegularExpressions.Match k in EntitlementKey.Matches(xml))
            keys.Add(k.Groups[1].Value);
        return keys;
    }
}
