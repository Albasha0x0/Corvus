namespace Corvus.Native.MachO;

/// <summary>Names of Mach-O constants.</summary>
public static class MachONames
{
    public const uint CpuX86 = 7, CpuX64 = 0x01000007, CpuArm = 12, CpuArm64 = 0x0100000C, CpuArm64_32 = 0x0200000C, CpuPpc = 18, CpuPpc64 = 0x01000012;

    public static NativeArch Arch(uint cpu) => cpu switch
    {
        CpuX86 => NativeArch.X86,
        CpuX64 => NativeArch.X64,
        CpuArm => NativeArch.Arm,
        CpuArm64 or CpuArm64_32 => NativeArch.Arm64,
        CpuPpc or CpuPpc64 => NativeArch.PowerPc,
        _ => NativeArch.Other,
    };

    /// <summary>The architecture name lipo and the linker use for a CPU type and subtype (capability bits ignored).</summary>
    public static string CpuName(uint cpu, uint subType)
    {
        uint sub = subType & 0x00FFFFFF;
        return cpu switch
        {
            CpuX86 => "i386",
            CpuX64 => sub == 8 ? "x86_64h" : "x86_64",
            CpuArm64 => sub switch { 2 => "arm64e", 1 => "arm64v8", _ => "arm64" },
            CpuArm64_32 => "arm64_32",
            CpuArm => sub switch
            {
                5 => "armv4t",
                6 => "armv6",
                7 => "armv5",
                9 => "armv7",
                10 => "armv7f",
                11 => "armv7s",
                12 => "armv7k",
                13 => "armv8",
                14 => "armv6m",
                15 => "armv7m",
                16 => "armv7em",
                _ => "arm",
            },
            CpuPpc => "ppc",
            CpuPpc64 => "ppc64",
            _ => $"cpu{cpu:X}:{sub}",
        };
    }

    public static string FileType(uint type) => type switch
    {
        1 => "MH_OBJECT",
        2 => "MH_EXECUTE",
        3 => "MH_FVMLIB",
        4 => "MH_CORE",
        5 => "MH_PRELOAD",
        6 => "MH_DYLIB",
        7 => "MH_DYLINKER",
        8 => "MH_BUNDLE",
        9 => "MH_DYLIB_STUB",
        10 => "MH_DSYM",
        11 => "MH_KEXT_BUNDLE",
        12 => "MH_FILESET",
        _ => $"MH_0x{type:X}",
    };

    public static string Command(uint cmd) => cmd switch
    {
        0x1 => "LC_SEGMENT",
        0x2 => "LC_SYMTAB",
        0x4 => "LC_THREAD",
        0x5 => "LC_UNIXTHREAD",
        0xB => "LC_DYSYMTAB",
        0xC => "LC_LOAD_DYLIB",
        0xD => "LC_ID_DYLIB",
        0xE => "LC_LOAD_DYLINKER",
        0xF => "LC_ID_DYLINKER",
        0x19 => "LC_SEGMENT_64",
        0x1A => "LC_ROUTINES_64",
        0x1B => "LC_UUID",
        0x1D => "LC_CODE_SIGNATURE",
        0x1E => "LC_SEGMENT_SPLIT_INFO",
        0x20 => "LC_LAZY_LOAD_DYLIB",
        0x21 => "LC_ENCRYPTION_INFO",
        0x22 => "LC_DYLD_INFO",
        0x24 => "LC_VERSION_MIN_MACOSX",
        0x25 => "LC_VERSION_MIN_IPHONEOS",
        0x26 => "LC_FUNCTION_STARTS",
        0x27 => "LC_DYLD_ENVIRONMENT",
        0x29 => "LC_DATA_IN_CODE",
        0x2A => "LC_SOURCE_VERSION",
        0x2B => "LC_DYLIB_CODE_SIGN_DRS",
        0x2C => "LC_ENCRYPTION_INFO_64",
        0x2D => "LC_LINKER_OPTION",
        0x2E => "LC_LINKER_OPTIMIZATION_HINT",
        0x2F => "LC_VERSION_MIN_TVOS",
        0x30 => "LC_VERSION_MIN_WATCHOS",
        0x31 => "LC_NOTE",
        0x32 => "LC_BUILD_VERSION",
        0x80000018 => "LC_LOAD_WEAK_DYLIB",
        0x8000001C => "LC_RPATH",
        0x8000001F => "LC_REEXPORT_DYLIB",
        0x80000022 => "LC_DYLD_INFO_ONLY",
        0x80000023 => "LC_LOAD_UPWARD_DYLIB",
        0x80000028 => "LC_MAIN",
        0x80000033 => "LC_DYLD_EXPORTS_TRIE",
        0x80000034 => "LC_DYLD_CHAINED_FIXUPS",
        0x80000035 => "LC_FILESET_ENTRY",
        _ => $"LC_0x{cmd:X}",
    };

    public static string Platform(uint platform) => platform switch
    {
        1 => "macos",
        2 => "ios",
        3 => "tvos",
        4 => "watchos",
        5 => "bridgeos",
        6 => "maccatalyst",
        7 => "iossimulator",
        8 => "tvossimulator",
        9 => "watchossimulator",
        10 => "driverkit",
        11 => "visionos",
        12 => "visionossimulator",
        _ => $"platform {platform}",
    };

    /// <summary>A packed X.Y.Z version (nibbles xxxx.yy.zz).</summary>
    public static string Version(uint v) => (v & 0xFF) == 0 ? $"{v >> 16}.{(v >> 8) & 0xFF}" : $"{v >> 16}.{(v >> 8) & 0xFF}.{v & 0xFF}";

    /// <summary>The library a two-level ordinal names: 0 self, -1 main executable, -2 flat namespace, -3 weak lookup, n the nth dylib.</summary>
    public static string? Library(int ordinal, IReadOnlyList<string> dylibs) => ordinal switch
    {
        0 => "self",
        -1 => "main-executable",
        -2 => "flat-namespace",
        -3 => "weak-lookup",
        > 0 when ordinal <= dylibs.Count => dylibs[ordinal - 1],
        _ => null,
    };

    public static string PointerFormat(ushort format) => format switch
    {
        1 => "DYLD_CHAINED_PTR_ARM64E",
        2 => "DYLD_CHAINED_PTR_64",
        3 => "DYLD_CHAINED_PTR_32",
        4 => "DYLD_CHAINED_PTR_32_CACHE",
        5 => "DYLD_CHAINED_PTR_32_FIRMWARE",
        6 => "DYLD_CHAINED_PTR_64_OFFSET",
        7 => "DYLD_CHAINED_PTR_ARM64E_KERNEL",
        8 => "DYLD_CHAINED_PTR_64_KERNEL_CACHE",
        9 => "DYLD_CHAINED_PTR_ARM64E_USERLAND",
        10 => "DYLD_CHAINED_PTR_ARM64E_FIRMWARE",
        11 => "DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE",
        12 => "DYLD_CHAINED_PTR_ARM64E_USERLAND24",
        13 => "DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE",
        _ => $"pointer format {format}",
    };
}
