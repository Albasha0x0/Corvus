using System.Buffers.Binary;
using System.Text;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native;

/// <summary>A packer or protector a file shows signs of: its name, packer / protector / suspicious, and what shows it.</summary>
public sealed record PackerFinding(string Name, string Kind, string Evidence);

/// <summary>
/// Detection only (nothing is unpacked): UPX on PE, ELF and Mach-O by its section names, the UPX! pack header (PE version marker,
/// ELF / Mach-O l_info and p_info, the trailer) and the stub's info string; PE packers and protectors by their section names;
/// otherwise compressed or encrypted code by entropy, code sections empty on disk and writable code at the entry point.
/// </summary>
public static class PackerDetection
{
    private const double HighEntropy = 7.2;
    private static readonly byte[] UpxMagic = "UPX!"u8.ToArray();
    private static readonly byte[] UpxInfo = "This file is packed with the UPX"u8.ToArray();

    private static readonly (string Prefix, string Name, string Kind)[] SectionNames =
    [
        ("UPX", "UPX", "packer"), (".aspack", "ASPack", "packer"), (".adata", "ASPack", "packer"), (".petite", "Petite", "packer"),
        (".nsp", "NsPack", "packer"), (".MPRESS", "MPRESS", "packer"), ("PEC2", "PECompact", "packer"), ("pec1", "PECompact", "packer"),
        ("FSG!", "FSG", "packer"), (".RLPack", "RLPack", "packer"), (".packed", "RLPack", "packer"), ("kkrunchy", "kkrunchy", "packer"),
        ("MEW", "MEW", "packer"), (".boom", "The Boomerang", "packer"), (".neolit", "NeoLite", "packer"),
        (".themida", "Themida", "protector"), (".winlice", "WinLicense", "protector"), (".vmp", "VMProtect", "protector"),
        (".enigma", "Enigma Protector", "protector"), (".yP", "Y0da Protector", "protector"), (".svkp", "SVKP", "protector"),
        (".pelock", "PELock", "protector"), ("ExeS", "EXE Stealth", "protector"), (".sforce", "StarForce", "protector"),
    ];

    /// <summary>The UPX format numbers seen most (UPX's own table), for the evidence text.</summary>
    private static string UpxFormat(byte format) => format switch
    {
        9 => "win32/pe", 12 => "linux/i386", 21 => "wince/arm", 22 => "linux/amd64", 23 => "linux/arm", 29 => "macos/i386",
        34 => "macos/amd64", 35 => "dylib/amd64", 36 => "win64/pe", 37 => "macos/arm64", 42 => "linux/arm64",
        _ => $"format {format}",
    };

    /// <summary>Findings for a file read whole; the image is opened from the bytes (PE, ELF, Mach-O); none for anything else.</summary>
    public static IReadOnlyList<PackerFinding> OfFile(string path, byte[] bytes)
    {
        INativeImage? image = null;
        try
        {
            image = NativeImageLoader.Detect(bytes) switch
            {
                NativeFileKind.Pe => Pe.PeFile.FromBytes(bytes, path),
                NativeFileKind.Elf => Elf.ElfFile.FromBytes(bytes, path),
                NativeFileKind.MachO or NativeFileKind.MachOFat => MachO.MachOFile.FromBytes(bytes, path),
                _ => null,
            };
        }
        catch (ToolError) { }
        return image == null ? [] : Detect(image, bytes);
    }

    public static IReadOnlyList<PackerFinding> Detect(INativeImage image, ReadOnlySpan<byte> file)
    {
        var result = new List<PackerFinding>();
        if (Upx(image, file) is { } upx) result.Add(upx);
        foreach (var group in image.Sections.Select(s => (s.Name, Rule: SectionNames.FirstOrDefault(r => s.Name.StartsWith(r.Prefix, StringComparison.Ordinal))))
                     .Where(x => x.Rule.Name != null && image.Format == ImageFormat.Pe).GroupBy(x => x.Rule.Name))
        {
            if (result.Any(r => r.Name == group.Key)) continue;
            var rule = group.First().Rule;
            result.Add(new PackerFinding(rule.Name, rule.Kind, $"section names {string.Join(", ", group.Select(x => x.Name).Distinct())}"));
        }
        if (result.Count == 0) result.AddRange(Heuristics(image));
        return result;
    }

    private static PackerFinding? Upx(INativeImage image, ReadOnlySpan<byte> file)
    {
        var evidence = new List<string>();
        var sections = image.Sections.Where(s => s.Name.StartsWith("UPX", StringComparison.Ordinal) || s.Name.EndsWith(",UPX_DATA", StringComparison.Ordinal)).Select(s => s.Name).ToList();
        if (sections.Count > 0) evidence.Add($"section names {string.Join(", ", sections)}");
        var head = file[..Math.Min(file.Length, 0x2000)];
        int at = head.IndexOf(UpxMagic);
        if (at >= 0)
        {
            if (image.Format == ImageFormat.Pe)
            {
                // "<version>\0UPX!", then the header's version and format bytes
                string? version = null;
                if (at >= 2 && head[at - 1] == 0)
                {
                    int start = at - 1;
                    while (start > 0 && at - 1 - start < 10 && head[start - 1] is (>= (byte)'0' and <= (byte)'9') or (byte)'.') start--;
                    if (start < at - 1) version = Encoding.ASCII.GetString(head[start..(at - 1)]);
                }
                evidence.Add($"UPX! pack header at file 0x{at:X}" + (version != null ? $", UPX {version}" : "") + (at + 6 <= head.Length ? $", {UpxFormat(head[at + 5])}" : ""));
            }
            else if (at >= 4 && at + 20 <= head.Length)
            {
                // l_info: checksum, "UPX!", l_lsize, l_version, l_format; then p_info: p_progid, p_filesize, p_blocksize
                byte version = head[at + 6], format = head[at + 7];
                uint unpacked = BinaryPrimitives.ReadUInt32LittleEndian(head[(at + 12)..]);
                evidence.Add($"l_info at file 0x{at - 4:X} (UPX! version {version}, {UpxFormat(format)}), p_info: unpacked size {unpacked:N0} bytes");
            }
            else evidence.Add($"UPX! at file 0x{at:X}");
        }
        var tail = file[Math.Max(0, file.Length - 0x1000)..];
        int trailer = tail.LastIndexOf(UpxMagic);
        if (trailer >= 0 && file.Length - tail.Length + trailer != at) evidence.Add($"UPX! trailer at file 0x{file.Length - tail.Length + trailer:X}");
        int info = file.IndexOf(UpxInfo);
        if (info >= 0) evidence.Add($"stub string \"$Info: This file is packed with the UPX executable packer\" at file 0x{Math.Max(0, info - 7):X}");
        // a lone magic is weak: real UPX output has two signs or more
        return evidence.Count >= 2 || sections.Count > 0 ? new PackerFinding("UPX", "packer", string.Join("; ", evidence)) : null;
    }

    private static IEnumerable<PackerFinding> Heuristics(INativeImage image)
    {
        var buffer = new byte[1 << 16];
        foreach (var s in image.Sections.Where(s => s.IsExecutable))
        {
            if (s.RawSize == 0 && s.VirtualSize >= 0x10000)
            {
                yield return new PackerFinding("unknown packer", "suspicious", $"code section {s.Name} is {s.VirtualSize:N0} bytes in memory and empty on disk (filled at run time)");
                continue;
            }
            // Only bytes from the file: a raw size past its end would count up to 4 GB of zero fill.
            uint size = (uint)image.FileBackedLength(s.Rva, Math.Min(s.RawSize, s.MappedSize));
            if (size < 0x1000) continue;
            double entropy = Entropy(image, s.Rva, size, buffer);
            if (entropy >= HighEntropy)
                yield return new PackerFinding("unknown packer", "suspicious", $"code section {s.Name} has entropy {entropy:0.00} over {size:N0} bytes (compressed or encrypted)");
        }
        if (image.EntryPointRva != 0 && image.SectionAt(image.EntryPointRva) is { } entry && (entry.Access & SectionAccess.Write) != 0 && entry.IsExecutable)
            yield return new PackerFinding("unknown packer", "suspicious", $"the entry point is in {entry.Name}, writable and executable");
    }

    /// <summary>Shannon entropy in bits per byte of the mapped bytes.</summary>
    private static double Entropy(INativeImage image, uint rva, uint size, byte[] buffer)
    {
        Span<long> counts = stackalloc long[256];
        long total = 0;
        for (uint done = 0; done < size;)
        {
            int n = image.Read(rva + done, buffer.AsSpan(0, (int)Math.Min(buffer.Length, size - done)));
            if (n <= 0) break;
            foreach (byte b in buffer.AsSpan(0, n)) counts[b]++;
            total += n;
            done += (uint)n;
        }
        if (total == 0) return 0;
        double h = 0;
        foreach (long c in counts)
            if (c > 0) { double p = (double)c / total; h -= p * Math.Log2(p); }
        return h;
    }
}
