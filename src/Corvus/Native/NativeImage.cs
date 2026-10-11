namespace Corvus.Native;

/// <summary>Instruction set of a native image. Architectures after <see cref="Arm64"/> are reported, never decoded by the code index.</summary>
public enum NativeArch
{
    Unknown,
    X86,
    X64,
    Arm,
    Arm64,
    Mips,
    PowerPc,
    RiscV,
    Other,
}

/// <summary>Container format of a native image.</summary>
public enum ImageFormat
{
    Pe,
    Elf,
    MachO,
}

[Flags]
public enum SectionAccess
{
    None = 0,
    Read = 1,
    Write = 2,
    Execute = 4,
    /// <summary>Marked as containing code (IMAGE_SCN_CNT_CODE), independent of the execute permission.</summary>
    Code = 8,
}

/// <summary>A section of the mapped image; addresses are RVAs.</summary>
public sealed record NativeSection(string Name, uint Rva, uint VirtualSize, uint RawOffset, uint RawSize, SectionAccess Access, uint Characteristics)
{
    /// <summary>Mapped extent: the virtual size, or the raw size when the virtual size is 0.</summary>
    public uint MappedSize => VirtualSize != 0 ? VirtualSize : RawSize;

    public bool Contains(uint rva) => rva >= Rva && rva - Rva < MappedSize;

    public bool IsExecutable => (Access & (SectionAccess.Execute | SectionAccess.Code)) != 0;
}

/// <summary>
/// One imported function. <see cref="SlotRva"/> is the IAT slot the loader fills, which code reads through
/// ("call [slot]"); for delay-loaded imports it is the delay IAT slot.
/// </summary>
public sealed record NativeImport(string Module, string? Name, ushort? Ordinal, ushort Hint, uint SlotRva, bool IsDelayLoad);

/// <summary>
/// One exported entry. <see cref="ForwardedTo"/> is set (and <see cref="Rva"/> points at the forwarder string) for forwarded exports;
/// <see cref="Version"/> is an ELF symbol version as the name's suffix: @@NAME for the default, @NAME for another.
/// </summary>
public sealed record NativeExport(string? Name, uint Ordinal, uint Rva, string? ForwardedTo, string? Version = null);

/// <summary>A function range from the exception directory (.pdata) on x64, ARM64 and ARM.</summary>
public sealed record RuntimeFunction(uint BeginRva, uint EndRva, uint UnwindInfoRva);

/// <summary>Something the parser could not read or that looks wrong; results are still returned for the rest.</summary>
public sealed record ParseIssue(string Area, string Message, long? FileOffset = null);

public enum ImageSymbolKind
{
    Other,
    Function,
    Object,
}

public enum ImageSymbolBinding
{
    Global,
    Weak,
    Local,
}

/// <summary>
/// A defined symbol of the image's own symbol tables (ELF .dynsym/.symtab, Mach-O nlist). <see cref="Version"/> is the
/// ELF symbol version. PE images list none: PDB symbols are separate.
/// </summary>
public sealed record ImageSymbol(string Name, uint Rva, ulong Size, ImageSymbolKind Kind, ImageSymbolBinding Binding, string? Section, string? Version = null);

/// <summary>Where a declared function start comes from.</summary>
public enum DeclaredSource
{
    /// <summary>Unwind tables: ELF .eh_frame / .eh_frame_hdr, ARM .ARM.exidx, Mach-O compact unwind and __eh_frame.</summary>
    Unwind,
    /// <summary>Mach-O LC_FUNCTION_STARTS.</summary>
    FunctionStarts,
    /// <summary>A function symbol.</summary>
    Symbol,
    /// <summary>An initializer or finalizer array entry (.init_array, __mod_init_func, __init_offsets).</summary>
    Initializer,
}

/// <summary>A function start the image declares outside its code; <see cref="Size"/> when the source gives one.</summary>
public readonly record struct DeclaredFunction(uint Rva, uint? Size, DeclaredSource Source);

/// <summary>A range whose file bytes are encrypted (Mach-O LC_ENCRYPTION_INFO with a nonzero cryptid).</summary>
public sealed record EncryptedRange(uint Rva, uint Size, uint CryptId);

/// <summary>
/// A native executable image as loaded from disk: headers, mapped sections and the directories code analysis needs.
/// Implementations snapshot the file into memory, never throw on malformed content after construction, and
/// report what they could not read in <see cref="Issues"/>.
/// </summary>
public interface INativeImage
{
    ImageFormat Format => ImageFormat.Pe;
    string Path { get; }
    /// <summary>Lowercase hex SHA-256 of the file bytes the image was built from.</summary>
    string Sha256 { get; }
    NativeArch Arch { get; }
    bool Is64Bit { get; }
    /// <summary>The machine type as the format names it (PE IMAGE_FILE_MACHINE_*, ELF e_machine, Mach-O CPU type).</summary>
    string MachineName => Arch.ToString();
    /// <summary>Length of the file the image was read from.</summary>
    long FileSize => 0;
    bool IsDll { get; }
    ulong ImageBase { get; }
    /// <summary>Entry point RVA, 0 when there is none (resource-only DLLs).</summary>
    uint EntryPointRva { get; }
    uint SizeOfImage { get; }
    IReadOnlyList<NativeSection> Sections { get; }
    IReadOnlyList<NativeImport> Imports { get; }
    IReadOnlyList<NativeExport> Exports { get; }
    /// <summary>Sorted by <see cref="RuntimeFunction.BeginRva"/>; empty for x86.</summary>
    IReadOnlyList<RuntimeFunction> RuntimeFunctions { get; }
    /// <summary>RVAs of every location the base relocations patch (pointer-sized absolute addresses), sorted.</summary>
    IReadOnlyList<uint> RelocationRvas { get; }
    IReadOnlyList<uint> TlsCallbackRvas { get; }
    IReadOnlyList<ParseIssue> Issues { get; }
    /// <summary>Defined symbols of the image's symbol tables, sorted by RVA.</summary>
    IReadOnlyList<ImageSymbol> Symbols => [];
    /// <summary>Function starts from unwind tables, function-start lists and initializer arrays, sorted by RVA.</summary>
    IReadOnlyList<DeclaredFunction> DeclaredFunctions => [];
    /// <summary>Libraries the image links against (PE import modules, ELF DT_NEEDED, Mach-O dylib load commands), in load order.</summary>
    IReadOnlyList<string> Dependencies => [];
    /// <summary>Build identity for symbol lookup: PE CodeView GUID and age, GNU build-id, Mach-O LC_UUID; lowercase hex.</summary>
    string? BuildId => null;
    IReadOnlyList<EncryptedRange> EncryptedRanges => [];

    /// <summary>
    /// Copies mapped bytes starting at <paramref name="rva"/> into <paramref name="destination"/> as the loader would
    /// map them (headers, section raw data, zero fill past raw data). Returns the number of bytes copied, which is
    /// less than requested only at the end of the image or at an unmapped gap. Pointers the loader fixes up hold
    /// their targets at <see cref="ImageBase"/> (ELF and Mach-O rebases applied); bound import slots read as 0.
    /// </summary>
    int Read(uint rva, Span<byte> destination);

    bool TryRvaToFileOffset(uint rva, out long fileOffset);
    bool TryFileOffsetToRva(long fileOffset, out uint rva);

    /// <summary>Section containing <paramref name="rva"/>, or null for headers or unmapped addresses.</summary>
    NativeSection? SectionAt(uint rva);
}
