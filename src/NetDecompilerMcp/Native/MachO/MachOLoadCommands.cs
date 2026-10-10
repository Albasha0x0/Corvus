namespace NetDecompilerMcp.Native.MachO;

/// <summary>A load command; commands without a typed record below are kept as this base record.</summary>
public record MachOLoadCommand(uint Command, long Offset, uint Size)
{
    public string Name => MachONames.Command(Command);
}

public sealed record MachOSection(string SegmentName, string Name, ulong Address, ulong Size, uint Offset, uint Align, uint RelocationOffset,
    uint RelocationCount, uint Flags, uint Reserved1, uint Reserved2)
{
    /// <summary>S_* section type (the low byte of the flags).</summary>
    public uint Type => Flags & 0xFF;
    public bool HasInstructions => (Flags & 0x80000400) != 0;
    /// <summary>Zero-fill sections (S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL) have no file data.</summary>
    public bool IsZeroFill => Type is 0x1 or 0xC or 0x12;
    public string FullName => $"{SegmentName},{Name}";
}

public sealed record MachOSegment(uint Command, long Offset, uint Size, string SegmentName, ulong VmAddress, ulong VmSize, ulong FileOffset, ulong FileSize,
    uint MaxProtection, uint InitProtection, uint Flags, IReadOnlyList<MachOSection> Sections) : MachOLoadCommand(Command, Offset, Size)
{
    public bool Readable => (InitProtection & 1) != 0;
    public bool Writable => (InitProtection & 2) != 0;
    public bool Executable => (InitProtection & 4) != 0;
}

public enum MachODylibKind
{
    Load,
    Weak,
    Reexport,
    Upward,
    Lazy,
    /// <summary>LC_ID_DYLIB: the library's own install name.</summary>
    Id,
}

public sealed record MachODylibCommand(uint Command, long Offset, uint Size, MachODylibKind Kind, string Path, uint Timestamp, uint CurrentVersion,
    uint CompatibilityVersion) : MachOLoadCommand(Command, Offset, Size);

/// <summary>LC_RPATH, LC_LOAD_DYLINKER, LC_ID_DYLINKER, LC_DYLD_ENVIRONMENT: one string.</summary>
public sealed record MachOStringCommand(uint Command, long Offset, uint Size, string Value) : MachOLoadCommand(Command, Offset, Size);

public sealed record MachOUuidCommand(uint Command, long Offset, uint Size, byte[] Uuid) : MachOLoadCommand(Command, Offset, Size);

/// <summary>LC_BUILD_VERSION, or an LC_VERSION_MIN_* command (its platform derived from the command).</summary>
public sealed record MachOBuildVersionCommand(uint Command, long Offset, uint Size, uint Platform, uint MinOs, uint Sdk, IReadOnlyList<(uint Tool, uint Version)> Tools)
    : MachOLoadCommand(Command, Offset, Size)
{
    public string PlatformName => MachONames.Platform(Platform);
}

public sealed record MachOMainCommand(uint Command, long Offset, uint Size, ulong EntryOffset, ulong StackSize) : MachOLoadCommand(Command, Offset, Size);

/// <summary>LC_UNIXTHREAD / LC_THREAD with the program counter of the first recognized thread state (null when unknown).</summary>
public sealed record MachOThreadCommand(uint Command, long Offset, uint Size, uint Flavor, ulong? ProgramCounter) : MachOLoadCommand(Command, Offset, Size);

/// <summary>A linkedit_data_command: code signature, function starts, data in code, chained fixups, exports trie, ...</summary>
public sealed record MachOLinkEditCommand(uint Command, long Offset, uint Size, uint DataOffset, uint DataSize) : MachOLoadCommand(Command, Offset, Size);

public sealed record MachODyldInfoCommand(uint Command, long Offset, uint Size, uint RebaseOffset, uint RebaseSize, uint BindOffset, uint BindSize,
    uint WeakBindOffset, uint WeakBindSize, uint LazyBindOffset, uint LazyBindSize, uint ExportOffset, uint ExportSize) : MachOLoadCommand(Command, Offset, Size);

public sealed record MachOSymtabCommand(uint Command, long Offset, uint Size, uint SymbolOffset, uint SymbolCount, uint StringOffset, uint StringSize)
    : MachOLoadCommand(Command, Offset, Size);

public sealed record MachODysymtabCommand(uint Command, long Offset, uint Size, uint LocalIndex, uint LocalCount, uint ExternalIndex, uint ExternalCount,
    uint UndefinedIndex, uint UndefinedCount, uint IndirectOffset, uint IndirectCount) : MachOLoadCommand(Command, Offset, Size);

/// <summary>LC_ENCRYPTION_INFO[_64]: <see cref="CryptOffset"/> is a file offset; a nonzero <see cref="CryptId"/> means encrypted (FairPlay).</summary>
public sealed record MachOEncryptionCommand(uint Command, long Offset, uint Size, uint CryptOffset, uint CryptSize, uint CryptId) : MachOLoadCommand(Command, Offset, Size);

/// <summary>LC_FILESET_ENTRY of a kernel collection (listed, not mapped).</summary>
public sealed record MachOFilesetEntryCommand(uint Command, long Offset, uint Size, ulong VmAddress, ulong FileOffset, string EntryId) : MachOLoadCommand(Command, Offset, Size);
