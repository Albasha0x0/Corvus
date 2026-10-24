using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Elf;
using Corvus.Native.MachO;

namespace Corvus.Services;

/// <summary>
/// Where the Il2Cpp reader finds things in an Il2Cpp binary of any format: image base and size, executable and
/// initialized-data areas with their file layout, the file offset of an RVA as built, and whether code pointers carry
/// the Thumb bit. Built from the PE section table (a memory image normalized first) or from the ELF / Mach-O readers.
/// </summary>
public sealed class Il2CppBinaryLayout
{
    /// <summary>A section; <see cref="RawOffset"/> is where its bytes are in the buffer handed to the library.</summary>
    public sealed record Area(string Name, uint Rva, uint Size, ulong RawOffset, uint RawSize, bool Executable, bool InitializedData)
    {
        public bool Contains(uint rva) => rva >= Rva && rva - Rva < Size;
    }

    private readonly Func<uint, ulong?> _originalOffset;

    private Il2CppBinaryLayout(ImageFormat format, NativeArch arch, bool is64, ulong imageBase, uint sizeOfImage, IReadOnlyList<Area> areas,
        Func<uint, ulong?> originalOffset, string? buildId)
    {
        Format = format;
        Arch = arch;
        Is64 = is64;
        ImageBase = imageBase;
        SizeOfImage = sizeOfImage;
        Areas = areas;
        _originalOffset = originalOffset;
        BuildId = buildId;
    }

    public ImageFormat Format { get; }
    public NativeArch Arch { get; }
    public bool Is64 { get; }
    public ulong ImageBase { get; }
    public uint SizeOfImage { get; }
    public IReadOnlyList<Area> Areas { get; }
    public string? BuildId { get; }

    /// <summary>32-bit ARM code pointers have bit 0 set for Thumb functions; the function starts one byte lower.</summary>
    public bool ThumbPointers => Arch == NativeArch.Arm;

    public Area? AreaAt(uint rva) => Areas.FirstOrDefault(a => a.Contains(rva));

    /// <summary>The RVA of a pointer into the image, or null.</summary>
    public uint? Rva(ulong pointer) => pointer >= ImageBase && pointer - ImageBase < SizeOfImage ? (uint)(pointer - ImageBase) : null;

    /// <summary>The RVA of a code pointer (Thumb bit cleared), or null.</summary>
    public uint? CodeRva(ulong pointer) => Rva(ThumbPointers ? pointer & ~1UL : pointer);

    /// <summary>The offset of an RVA in the file as built (also for a memory image); null outside its file data.</summary>
    public ulong? FileOffset(uint rva) => _originalOffset(rva);

    public bool InCode(ulong pointer) => CodeRva(pointer) is { } rva && AreaAt(rva) is { Executable: true };

    /// <summary>Whether the file at <paramref name="path"/> is a 32-bit ARM ELF or thin Mach-O, from its header.</summary>
    public static bool IsArm32(string path)
    {
        try
        {
            using var f = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            Span<byte> head = stackalloc byte[20];
            if (RandomAccess.Read(f, head, 0) < head.Length) return false;
            return NativeImageLoader.Detect(head) switch
            {
                NativeFileKind.Elf => head[4] == 1 && BinaryPrimitives.ReadUInt16LittleEndian(head[18..]) == 40, // ELFCLASS32, EM_ARM
                NativeFileKind.MachO => BinaryPrimitives.ReadUInt32LittleEndian(head) == 0xFEEDFACE && BinaryPrimitives.ReadUInt32LittleEndian(head[4..]) == 12, // CPU_TYPE_ARM
                _ => false,
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    /// <summary>A PE layout: <paramref name="header"/> as the library reads the bytes, <paramref name="original"/> as the file was built.</summary>
    public static Il2CppBinaryLayout FromPe(MappedPeLayout.Header header, MappedPeLayout.Header original) =>
        new(ImageFormat.Pe, header.Machine switch { 0x14C => NativeArch.X86, 0x8664 => NativeArch.X64, 0xAA64 => NativeArch.Arm64, 0x1C4 => NativeArch.Arm, _ => NativeArch.Unknown },
            header.Is64, header.ImageBase, header.SizeOfImage,
            [.. header.Sections.Select(s => new Area(s.Name, s.Rva, Math.Max(s.VirtualSize, s.RawSize), s.RawOffset, Math.Min(s.RawSize, Math.Max(s.VirtualSize, 1u)),
                s.Executable, s.Characteristics is 0x40000040 or 0xC0000040))], // read-only and writable initialized data
            original.FileOffset, null);

    /// <summary>An ELF or Mach-O layout; the library reads the same bytes the image was parsed from.</summary>
    public static Il2CppBinaryLayout FromImage(INativeImage image, Func<uint, ulong?>? originalOffset = null)
    {
        var areas = image.Sections.Select(s => new Area(s.Name, s.Rva, s.MappedSize, s.RawOffset, s.RawSize, s.IsExecutable,
            !s.IsExecutable && s.RawSize > 0 && HoldsData(image.Format, s.Name))).ToList();
        return new(image.Format, image.Arch, image.Is64Bit, image.ImageBase, image.SizeOfImage, areas,
            originalOffset ?? (rva => image.TryRvaToFileOffset(rva, out var o) ? (ulong)o : null), image.BuildId);
    }

    /// <summary>Sections that can hold metadata usage slots: data, not tables the linker writes (relocations, symbols, unwind).</summary>
    private static bool HoldsData(ImageFormat format, string name) => format switch
    {
        ImageFormat.MachO => name.StartsWith("__DATA", StringComparison.Ordinal),
        _ => !(name.StartsWith(".rel", StringComparison.Ordinal) || name.StartsWith(".dyn", StringComparison.Ordinal) || name.StartsWith(".gnu", StringComparison.Ordinal)
               || name.StartsWith(".eh_frame", StringComparison.Ordinal) || name.StartsWith(".note", StringComparison.Ordinal) || name.StartsWith(".hash", StringComparison.Ordinal)
               || name.StartsWith(".gcc_except", StringComparison.Ordinal) || name.StartsWith(".ARM", StringComparison.Ordinal) || name.StartsWith(".got", StringComparison.Ordinal)),
    };

    /// <summary>What the bytes of an Il2Cpp binary are: the buffer the library reads, its layout, and notes on what was done to it.</summary>
    public sealed record Opened(byte[] Bytes, Il2CppBinaryLayout Layout, bool MemoryImage, string? Note);

    /// <summary>
    /// Opens an Il2Cpp binary for the reader: a PE (a memory image is normalized to its file layout), an ELF (a memory
    /// image gets file offsets equal to its addresses), or a Mach-O (the chosen slice of a universal file). Encrypted
    /// Mach-O code (FairPlay) is refused with reason encrypted_fairplay; other formats with binary_format_unsupported.
    /// </summary>
    public static Opened Open(byte[] bytes, string path, string? slice = null)
    {
        switch (NativeImageLoader.Detect(bytes))
        {
            case NativeFileKind.Pe:
                var original = MappedPeLayout.Parse(bytes) ?? throw Unsupported(path, "its PE headers are unreadable");
                bool mapped = MappedPeLayout.IsMapped(bytes, original);
                if (mapped) MappedPeLayout.Normalize(bytes, original);
                var header = MappedPeLayout.Parse(bytes)!;
                return new Opened(bytes, FromPe(header, original), mapped,
                    mapped ? $"{Path.GetFileName(path)} is a memory image of the loaded module (sections at their RVAs, image base 0x{header.ImageBase:X}); read as such" : null);
            case NativeFileKind.Elf:
                var elf = ElfFile.FromBytes(bytes, path);
                if (!elf.IsMappedDump) return new Opened(bytes, FromImage(elf), false, null);
                var loads = elf.Segments.Where(s => s.IsLoad).ToList();
                ulong? Built(uint rva)
                {
                    ulong va = elf.ImageBase + rva;
                    var s = loads.FirstOrDefault(l => va >= l.VirtualAddress && va - l.VirtualAddress < l.FileSize);
                    return s == null ? null : s.Offset + (va - s.VirtualAddress);
                }
                NormalizeElfDump(bytes, elf);
                return new Opened(bytes, FromImage(elf, Built), true,
                    $"{Path.GetFileName(path)} is a memory image of the loaded library (segments at their addresses, image base 0x{elf.ImageBase:X}); read as such");
            case NativeFileKind.MachO or NativeFileKind.MachOFat:
                var macho = MachOFile.FromBytes(bytes, path, slice);
                if (macho.EncryptedRanges.Count > 0)
                    throw new ToolError(ErrorCode.Unsupported,
                        $"{path}{(macho.Slice != null ? $" [{macho.Slice.Name}]" : "")} is encrypted (LC_ENCRYPTION_INFO cryptid {macho.EncryptedRanges[0].CryptId}, " +
                        $"{macho.EncryptedRanges.Sum(r => (long)r.Size)} bytes): reason encrypted_fairplay — its code and data cannot be read from the file.",
                        "load a decrypted copy of the binary (a memory dump of the running app) beside the metadata");
                var thin = macho.Slice != null ? macho.FileBytes.ToArray() : bytes;
                return new Opened(thin, FromImage(macho), false, macho.Slice != null ? $"universal binary: slice {macho.Slice.Name} read" : null);
            default:
                throw Unsupported(path, "it is not a PE, ELF or Mach-O image");
        }
    }

    private static ToolError Unsupported(string path, string why) =>
        new(ErrorCode.Unsupported, $"{path} cannot be read as an Il2Cpp binary: {why} (reason binary_format_unsupported).",
            "pass the build's GameAssembly.dll, libil2cpp.so, UnityFramework or GameAssembly.dylib/.so; for WebGL builds load dummy assemblies with [Address] attributes");

    /// <summary>
    /// Rewrites the program headers of an ELF memory image in place so every PT_LOAD's file data is at its address, and
    /// drops the section headers (their offsets describe the file as built, not the image).
    /// </summary>
    private static void NormalizeElfDump(byte[] b, ElfFile elf)
    {
        bool is64 = elf.Is64Bit;
        ulong phoff = is64 ? BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(32)) : BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(28));
        int entry = BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(is64 ? 54 : 42));
        int count = BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(is64 ? 56 : 44));
        for (int i = 0; i < count; i++)
        {
            long at = (long)phoff + (long)i * entry;
            if (at < 0 || at + (is64 ? 56 : 32) > b.Length) break;
            var p = b.AsSpan((int)at);
            if (BinaryPrimitives.ReadUInt32LittleEndian(p) is not (1 or 2)) continue; // PT_LOAD, PT_DYNAMIC
            ulong va = is64 ? BinaryPrimitives.ReadUInt64LittleEndian(p[16..]) : BinaryPrimitives.ReadUInt32LittleEndian(p[8..]);
            ulong mem = is64 ? BinaryPrimitives.ReadUInt64LittleEndian(p[40..]) : BinaryPrimitives.ReadUInt32LittleEndian(p[20..]);
            ulong offset = va - elf.ImageBase;
            ulong size = offset >= (ulong)b.Length ? 0 : Math.Min(mem, (ulong)b.Length - offset);
            if (is64)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(p[8..], offset);
                BinaryPrimitives.WriteUInt64LittleEndian(p[32..], size);
            }
            else
            {
                BinaryPrimitives.WriteUInt32LittleEndian(p[4..], (uint)offset);
                BinaryPrimitives.WriteUInt32LittleEndian(p[16..], (uint)size);
            }
        }
        if (is64) BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(40), 0);
        else BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(32), 0);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(is64 ? 60 : 48), 0);
    }
}
