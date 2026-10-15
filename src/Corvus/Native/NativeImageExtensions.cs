namespace Corvus.Native;

public static class NativeImageExtensions
{
    /// <summary>The instruction set as the file names it: "Mips (EM_MIPS)", "EM_S390", "X64".</summary>
    public static string ArchName(this INativeImage image) =>
        image.Arch is NativeArch.Other or NativeArch.Unknown ? image.MachineName
        : image.MachineName.Equals(image.Arch.ToString(), StringComparison.OrdinalIgnoreCase) ? image.MachineName : $"{image.Arch} ({image.MachineName})";

    /// <summary>What the image is, in one line: "EM_AARCH64 ELF64 shared object", "arm64 Mach-O MH_DYLIB (slice ...)", or the PE kind.</summary>
    public static string KindText(this INativeImage image) => image switch
    {
        Elf.ElfFile elf => $"{elf.MachineName} ELF{(elf.Is64Bit ? "64" : "32")} {elf.KindName}",
        MachO.MachOFile m => $"{m.MachineName} Mach-O {m.FileTypeName}" + (m.Slice != null ? $" (slice {m.Slice.Name} of {string.Join(", ", m.Slices.Select(s => s.Name))})" : ""),
        RawCodeImage raw => $"raw {raw.MachineName} code at 0x{raw.ImageBase:X}, entry 0x{raw.ImageBase + raw.EntryPointRva:X}",
        WasmImage wasm => $"WebAssembly module (version {wasm.Module.Version}); addresses are file offsets",
        Pe.PeFile pe => $"{(Pe.PeHybrid.Of(pe) is { } h ? h.Kind : pe.MachineName)} {(pe.IsDll ? "DLL" : "executable")}, {pe.SubsystemName}",
        _ => $"{image.MachineName} {(image.IsDll ? "DLL" : "executable")}",
    };

    /// <summary>
    /// Length of the prefix of [rva, rva + length) whose bytes come from the file; the rest of a section is zero fill.
    /// Binary search over <see cref="INativeImage.TryRvaToFileOffset"/> (the file-backed part of a section is a prefix).
    /// </summary>
    public static long FileBackedLength(this INativeImage image, uint rva, long length)
    {
        length = Math.Min(length, (long)uint.MaxValue + 1 - rva);
        if (length <= 0 || !image.TryRvaToFileOffset(rva, out _)) return 0;
        if (image.TryRvaToFileOffset((uint)(rva + length - 1), out _)) return length;
        long lo = 1, hi = length - 1; // lo bytes are backed, hi + 1 are not
        while (lo < hi)
        {
            long mid = lo + (hi - lo + 1) / 2;
            if (image.TryRvaToFileOffset((uint)(rva + mid - 1), out _)) lo = mid;
            else hi = mid - 1;
        }
        return lo;
    }
}
