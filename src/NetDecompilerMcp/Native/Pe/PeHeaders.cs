namespace NetDecompilerMcp.Native.Pe;

/// <summary>IMAGE_FILE_HEADER.</summary>
public sealed record PeCoffHeader(
    ushort Machine,
    ushort NumberOfSections,
    uint TimeDateStamp,
    uint PointerToSymbolTable,
    uint NumberOfSymbols,
    ushort SizeOfOptionalHeader,
    ushort Characteristics);

/// <summary>IMAGE_OPTIONAL_HEADER32 / 64; <see cref="BaseOfData"/> is 0 for PE32+.</summary>
public sealed record PeOptionalHeader(
    ushort Magic,
    byte MajorLinkerVersion,
    byte MinorLinkerVersion,
    uint SizeOfCode,
    uint SizeOfInitializedData,
    uint SizeOfUninitializedData,
    uint AddressOfEntryPoint,
    uint BaseOfCode,
    uint BaseOfData,
    ulong ImageBase,
    uint SectionAlignment,
    uint FileAlignment,
    ushort MajorOperatingSystemVersion,
    ushort MinorOperatingSystemVersion,
    ushort MajorImageVersion,
    ushort MinorImageVersion,
    ushort MajorSubsystemVersion,
    ushort MinorSubsystemVersion,
    uint Win32VersionValue,
    uint SizeOfImage,
    uint SizeOfHeaders,
    uint CheckSum,
    ushort Subsystem,
    ushort DllCharacteristics,
    ulong SizeOfStackReserve,
    ulong SizeOfStackCommit,
    ulong SizeOfHeapReserve,
    ulong SizeOfHeapCommit,
    uint LoaderFlags,
    uint NumberOfRvaAndSizes);

/// <summary>A data directory entry. For <see cref="PeDirectory.Security"/> the address is a file offset, not an RVA.</summary>
public sealed record PeDataDirectory(int Index, string Name, uint Rva, uint Size)
{
    public bool IsPresent => Rva != 0 && Size != 0;
}

/// <summary>
/// How the loader maps a section (rules in PeFile.BuildLayout): <see cref="LoadedFileOffset"/> / <see cref="LoadedFileSize"/>
/// are the file bytes copied, <see cref="MappedSize"/> the virtual extent rounded up to the section alignment.
/// </summary>
public sealed record PeSectionLayout(NativeSection Section, uint MappedSize, long LoadedFileOffset, uint LoadedFileSize, IReadOnlyList<string> CharacteristicNames);

/// <summary>Exploit mitigations the headers, load config and debug directory declare.</summary>
/// <param name="Aslr">DYNAMIC_BASE set and relocations not stripped.</param>
/// <param name="HighEntropyVa">64-bit ASLR with HIGH_ENTROPY_VA.</param>
/// <param name="Dep">NX_COMPAT set, or a 64-bit image (DEP is always on for 64-bit processes).</param>
/// <param name="ControlFlowGuard">GUARD_CF set and the load config marks the code CF-instrumented.</param>
/// <param name="SafeSeh">x86 only: the load config has an SEH handler table.</param>
/// <param name="NoSeh">NO_SEH: the image uses no structured exception handlers.</param>
/// <param name="GsCookie">The load config names a /GS security cookie.</param>
/// <param name="ForceIntegrity">FORCE_INTEGRITY: the loader requires a valid signature.</param>
/// <param name="AppContainer">APPCONTAINER: must run in an app container.</param>
/// <param name="CetCompatible">CET shadow stack compatible (DLLCHARACTERISTICS_EX_CET_COMPAT).</param>
/// <param name="Xfg">eXtended Flow Guard (GUARD_XFG_ENABLED).</param>
/// <param name="EhContinuation">EH continuation metadata (GUARD_EH_CONTINUATION_TABLE_PRESENT).</param>
public sealed record PeMitigations(
    bool Aslr,
    bool HighEntropyVa,
    bool Dep,
    bool ControlFlowGuard,
    bool SafeSeh,
    bool NoSeh,
    bool GsCookie,
    bool ForceIntegrity,
    bool AppContainer,
    bool CetCompatible,
    bool Xfg,
    bool EhContinuation);

/// <summary>Data directory indexes.</summary>
public static class PeDirectory
{
    public const int Export = 0;
    public const int Import = 1;
    public const int Resource = 2;
    public const int Exception = 3;
    public const int Security = 4;
    public const int BaseRelocation = 5;
    public const int Debug = 6;
    public const int Architecture = 7;
    public const int GlobalPtr = 8;
    public const int Tls = 9;
    public const int LoadConfig = 10;
    public const int BoundImport = 11;
    public const int Iat = 12;
    public const int DelayImport = 13;
    public const int ClrRuntimeHeader = 14;
    public const int Reserved = 15;

    public static string Name(int index) => index switch
    {
        Export => "EXPORT",
        Import => "IMPORT",
        Resource => "RESOURCE",
        Exception => "EXCEPTION",
        Security => "SECURITY",
        BaseRelocation => "BASERELOC",
        Debug => "DEBUG",
        Architecture => "ARCHITECTURE",
        GlobalPtr => "GLOBALPTR",
        Tls => "TLS",
        LoadConfig => "LOAD_CONFIG",
        BoundImport => "BOUND_IMPORT",
        Iat => "IAT",
        DelayImport => "DELAY_IMPORT",
        ClrRuntimeHeader => "COM_DESCRIPTOR",
        _ => "RESERVED",
    };
}

/// <summary>Names of header constants and flags (winnt.h spelling without the IMAGE_ prefixes).</summary>
public static class PeNames
{
    /// <summary>XOR masks crossgen applies to the machine field of a ReadyToRun image built for each target OS.</summary>
    public static readonly (ushort Mask, string Os)[] ReadyToRunOsMasks =
        [(0, "Windows"), (0x7B79, "Linux"), (0x4644, "Apple"), (0xADC4, "FreeBSD"), (0x1993, "NetBSD"), (0x1992, "SunOS")];

    /// <summary>The target OS when <paramref name="machine"/> names an architecture only after removing a non-Windows ReadyToRun mask; null otherwise.</summary>
    public static string? NonWindowsReadyToRunOs(ushort machine)
    {
        if (Arch(machine) != NativeArch.Unknown) return null;
        foreach (var (mask, os) in ReadyToRunOsMasks)
            if (mask != 0 && Arch((ushort)(machine ^ mask)) != NativeArch.Unknown) return os;
        return null;
    }

    public static NativeArch Arch(ushort machine) => machine switch
    {
        0x014c => NativeArch.X86,
        0x8664 => NativeArch.X64,
        0xaa64 or 0xa641 => NativeArch.Arm64, // ARM64, ARM64EC
        0x01c0 or 0x01c2 or 0x01c4 => NativeArch.Arm, // ARM, THUMB, ARMNT
        _ => NativeArch.Unknown,
    };

    public static string Machine(ushort machine) => machine switch
    {
        0x0000 => "UNKNOWN",
        0x014c => "I386",
        0x8664 => "AMD64",
        0xaa64 => "ARM64",
        0xa641 => "ARM64EC",
        0xa64e => "ARM64X",
        0x01c0 => "ARM",
        0x01c2 => "THUMB",
        0x01c4 => "ARMNT",
        0x0200 => "IA64",
        0x0166 => "R4000",
        0x0169 => "WCEMIPSV2",
        0x0266 => "MIPS16",
        0x01a2 => "SH3",
        0x01a6 => "SH4",
        0x01f0 => "POWERPC",
        0x0ebc => "EBC",
        0x5032 => "RISCV32",
        0x5064 => "RISCV64",
        0x5128 => "RISCV128",
        0x6232 => "LOONGARCH32",
        0x6264 => "LOONGARCH64",
        _ => $"0x{machine:X4}",
    };

    public static string Subsystem(ushort subsystem) => subsystem switch
    {
        0 => "UNKNOWN",
        1 => "NATIVE",
        2 => "WINDOWS_GUI",
        3 => "WINDOWS_CUI",
        5 => "OS2_CUI",
        7 => "POSIX_CUI",
        8 => "NATIVE_WINDOWS",
        9 => "WINDOWS_CE_GUI",
        10 => "EFI_APPLICATION",
        11 => "EFI_BOOT_SERVICE_DRIVER",
        12 => "EFI_RUNTIME_DRIVER",
        13 => "EFI_ROM",
        14 => "XBOX",
        16 => "WINDOWS_BOOT_APPLICATION",
        _ => subsystem.ToString(),
    };

    private static readonly (uint Flag, string Name)[] FileFlags =
    [
        (0x0001, "RELOCS_STRIPPED"), (0x0002, "EXECUTABLE_IMAGE"), (0x0004, "LINE_NUMS_STRIPPED"), (0x0008, "LOCAL_SYMS_STRIPPED"),
        (0x0010, "AGGRESSIVE_WS_TRIM"), (0x0020, "LARGE_ADDRESS_AWARE"), (0x0080, "BYTES_REVERSED_LO"), (0x0100, "32BIT_MACHINE"),
        (0x0200, "DEBUG_STRIPPED"), (0x0400, "REMOVABLE_RUN_FROM_SWAP"), (0x0800, "NET_RUN_FROM_SWAP"), (0x1000, "SYSTEM"),
        (0x2000, "DLL"), (0x4000, "UP_SYSTEM_ONLY"), (0x8000, "BYTES_REVERSED_HI"),
    ];

    private static readonly (uint Flag, string Name)[] DllFlags =
    [
        (0x0020, "HIGH_ENTROPY_VA"), (0x0040, "DYNAMIC_BASE"), (0x0080, "FORCE_INTEGRITY"), (0x0100, "NX_COMPAT"),
        (0x0200, "NO_ISOLATION"), (0x0400, "NO_SEH"), (0x0800, "NO_BIND"), (0x1000, "APPCONTAINER"), (0x2000, "WDM_DRIVER"),
        (0x4000, "GUARD_CF"), (0x8000, "TERMINAL_SERVER_AWARE"),
    ];

    private static readonly (uint Flag, string Name)[] SectionFlags =
    [
        (0x00000008, "TYPE_NO_PAD"), (0x00000020, "CNT_CODE"), (0x00000040, "CNT_INITIALIZED_DATA"), (0x00000080, "CNT_UNINITIALIZED_DATA"),
        (0x00000200, "LNK_INFO"), (0x00000800, "LNK_REMOVE"), (0x00001000, "LNK_COMDAT"), (0x00004000, "NO_DEFER_SPEC_EXC"),
        (0x00008000, "GPREL"), (0x01000000, "LNK_NRELOC_OVFL"), (0x02000000, "MEM_DISCARDABLE"), (0x04000000, "MEM_NOT_CACHED"),
        (0x08000000, "MEM_NOT_PAGED"), (0x10000000, "MEM_SHARED"), (0x20000000, "MEM_EXECUTE"), (0x40000000, "MEM_READ"),
        (0x80000000, "MEM_WRITE"),
    ];

    private static readonly (uint Flag, string Name)[] GuardFlagNames =
    [
        (0x00000100, "CF_INSTRUMENTED"), (0x00000200, "CFW_INSTRUMENTED"), (0x00000400, "CF_FUNCTION_TABLE_PRESENT"),
        (0x00000800, "SECURITY_COOKIE_UNUSED"), (0x00001000, "PROTECT_DELAYLOAD_IAT"), (0x00002000, "DELAYLOAD_IAT_IN_ITS_OWN_SECTION"),
        (0x00004000, "CF_EXPORT_SUPPRESSION_INFO_PRESENT"), (0x00008000, "CF_ENABLE_EXPORT_SUPPRESSION"), (0x00010000, "CF_LONGJUMP_TABLE_PRESENT"),
        (0x00020000, "RF_INSTRUMENTED"), (0x00040000, "RF_ENABLE"), (0x00080000, "RF_STRICT"), (0x00100000, "RETPOLINE_PRESENT"),
        (0x00400000, "EH_CONTINUATION_TABLE_PRESENT"), (0x00800000, "XFG_ENABLED"), (0x01000000, "CASTGUARD_PRESENT"),
        (0x02000000, "MEMCPY_PRESENT"),
    ];

    private static readonly (uint Flag, string Name)[] ExDllFlags =
    [
        (0x01, "CET_COMPAT"), (0x02, "CET_COMPAT_STRICT_MODE"), (0x04, "CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE"),
        (0x08, "CET_DYNAMIC_APIS_ALLOW_IN_PROC"), (0x10, "CET_RESERVED_1"), (0x20, "CET_RESERVED_2"),
        (0x40, "FORWARD_CFI_COMPAT"), (0x80, "HOTPATCH_COMPATIBLE"),
    ];

    public static IReadOnlyList<string> FileCharacteristics(ushort value) => Flags(value, FileFlags);
    public static IReadOnlyList<string> DllCharacteristics(ushort value) => Flags(value, DllFlags);
    public static IReadOnlyList<string> ExDllCharacteristics(uint value) => Flags(value, ExDllFlags);

    public static IReadOnlyList<string> GuardFlags(uint value)
    {
        var names = Flags(value & 0x0FFFFFFF, GuardFlagNames).ToList();
        if (value >> 28 is var stride and not 0) names.Add($"CF_FUNCTION_TABLE_SIZE_{stride}");
        return names;
    }

    public static IReadOnlyList<string> SectionCharacteristics(uint value)
    {
        var names = Flags(value & ~0x00F00000u, SectionFlags).ToList();
        uint align = (value >> 20) & 0xF;
        if (align != 0) names.Add(align <= 14 ? $"ALIGN_{1u << (int)(align - 1)}BYTES" : $"ALIGN_0x{align:X}");
        return names;
    }

    /// <summary>Set flags in table order, then any unnamed bits as hex.</summary>
    private static IReadOnlyList<string> Flags(uint value, (uint Flag, string Name)[] table)
    {
        var names = new List<string>();
        uint known = 0;
        foreach (var (flag, name) in table)
        {
            known |= flag;
            if ((value & flag) != 0) names.Add(name);
        }
        if ((value & ~known) != 0) names.Add($"0x{value & ~known:X}");
        return names;
    }
}
