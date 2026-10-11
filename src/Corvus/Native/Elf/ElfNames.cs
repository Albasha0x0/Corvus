namespace Corvus.Native.Elf;

/// <summary>What a relocation does to its location, as far as the image view and imports are concerned.</summary>
public enum ElfRelocationKind
{
    None,
    /// <summary>Base + addend (R_*_RELATIVE, RELR).</summary>
    Relative,
    /// <summary>Symbol value + addend (R_AARCH64_ABS64, R_X86_64_64, R_ARM_ABS32, ...).</summary>
    Absolute,
    /// <summary>GOT entry bound to a symbol (R_*_GLOB_DAT).</summary>
    GlobalData,
    /// <summary>PLT slot bound to a symbol (R_*_JUMP_SLOT).</summary>
    JumpSlot,
    /// <summary>Value computed by a resolver function at load time (R_*_IRELATIVE).</summary>
    IRelative,
    Copy,
    Tls,
    Other,
}

/// <summary>Names of ELF constants, and the per-architecture meaning of relocation types.</summary>
public static class ElfNames
{
    public const ushort EmX86 = 3, EmMips = 8, EmMipsLe = 10, EmPpc = 20, EmPpc64 = 21, EmArm = 40, EmX64 = 62, EmAarch64 = 183, EmRiscV = 243;

    public static NativeArch Arch(ushort machine) => machine switch
    {
        EmX86 => NativeArch.X86,
        EmX64 => NativeArch.X64,
        EmArm => NativeArch.Arm,
        EmAarch64 => NativeArch.Arm64,
        EmMips or EmMipsLe => NativeArch.Mips,
        EmPpc or EmPpc64 => NativeArch.PowerPc,
        EmRiscV => NativeArch.RiscV,
        0 => NativeArch.Unknown,
        _ => NativeArch.Other,
    };

    public static string Machine(ushort machine) => machine switch
    {
        EmX86 => "EM_386",
        EmX64 => "EM_X86_64",
        EmArm => "EM_ARM",
        EmAarch64 => "EM_AARCH64",
        EmMips => "EM_MIPS",
        EmMipsLe => "EM_MIPS_RS3_LE",
        EmPpc => "EM_PPC",
        EmPpc64 => "EM_PPC64",
        EmRiscV => "EM_RISCV",
        2 => "EM_SPARC",
        22 => "EM_S390",
        43 => "EM_SPARCV9",
        50 => "EM_IA_64",
        258 => "EM_LOONGARCH",
        _ => $"EM_{machine}",
    };

    public static string FileType(ushort type) => type switch
    {
        0 => "ET_NONE",
        1 => "ET_REL",
        2 => "ET_EXEC",
        3 => "ET_DYN",
        4 => "ET_CORE",
        _ => $"ET_0x{type:X}",
    };

    public static string SegmentType(uint type) => type switch
    {
        0 => "PT_NULL",
        1 => "PT_LOAD",
        2 => "PT_DYNAMIC",
        3 => "PT_INTERP",
        4 => "PT_NOTE",
        5 => "PT_SHLIB",
        6 => "PT_PHDR",
        7 => "PT_TLS",
        0x6474E550 => "PT_GNU_EH_FRAME",
        0x6474E551 => "PT_GNU_STACK",
        0x6474E552 => "PT_GNU_RELRO",
        0x6474E553 => "PT_GNU_PROPERTY",
        0x70000000 => "PT_ARM_ARCHEXT / PT_MIPS_REGINFO",
        0x70000001 => "PT_ARM_EXIDX",
        0x70000003 => "PT_MIPS_ABIFLAGS",
        _ => $"PT_0x{type:X}",
    };

    public static string SectionType(uint type) => type switch
    {
        0 => "SHT_NULL",
        1 => "SHT_PROGBITS",
        2 => "SHT_SYMTAB",
        3 => "SHT_STRTAB",
        4 => "SHT_RELA",
        5 => "SHT_HASH",
        6 => "SHT_DYNAMIC",
        7 => "SHT_NOTE",
        8 => "SHT_NOBITS",
        9 => "SHT_REL",
        11 => "SHT_DYNSYM",
        14 => "SHT_INIT_ARRAY",
        15 => "SHT_FINI_ARRAY",
        16 => "SHT_PREINIT_ARRAY",
        17 => "SHT_GROUP",
        19 => "SHT_RELR",
        0x60000001 => "SHT_ANDROID_REL",
        0x60000002 => "SHT_ANDROID_RELA",
        0x6FFFFFF6 => "SHT_GNU_HASH",
        0x6FFFFFFD => "SHT_GNU_verdef",
        0x6FFFFFFE => "SHT_GNU_verneed",
        0x6FFFFFFF => "SHT_GNU_versym",
        0x70000001 => "SHT_ARM_EXIDX",
        0x70000003 => "SHT_ARM_ATTRIBUTES",
        _ => $"SHT_0x{type:X}",
    };

    public static ElfRelocationKind Kind(ushort machine, uint type) => machine switch
    {
        EmAarch64 => type switch
        {
            0 => ElfRelocationKind.None,
            257 or 258 => ElfRelocationKind.Absolute,
            1024 => ElfRelocationKind.Copy,
            1025 => ElfRelocationKind.GlobalData,
            1026 => ElfRelocationKind.JumpSlot,
            1027 => ElfRelocationKind.Relative,
            1028 or 1029 or 1030 or 1031 => ElfRelocationKind.Tls,
            1032 => ElfRelocationKind.IRelative,
            _ => ElfRelocationKind.Other,
        },
        EmX64 => type switch
        {
            0 => ElfRelocationKind.None,
            1 or 10 => ElfRelocationKind.Absolute,
            5 => ElfRelocationKind.Copy,
            6 => ElfRelocationKind.GlobalData,
            7 => ElfRelocationKind.JumpSlot,
            8 or 38 => ElfRelocationKind.Relative,
            16 or 17 or 18 or 36 => ElfRelocationKind.Tls,
            37 => ElfRelocationKind.IRelative,
            _ => ElfRelocationKind.Other,
        },
        EmX86 => type switch
        {
            0 => ElfRelocationKind.None,
            1 => ElfRelocationKind.Absolute,
            5 => ElfRelocationKind.Copy,
            6 => ElfRelocationKind.GlobalData,
            7 => ElfRelocationKind.JumpSlot,
            8 => ElfRelocationKind.Relative,
            14 or 35 or 36 or 37 => ElfRelocationKind.Tls,
            42 => ElfRelocationKind.IRelative,
            _ => ElfRelocationKind.Other,
        },
        EmArm => type switch
        {
            0 => ElfRelocationKind.None,
            2 => ElfRelocationKind.Absolute,
            20 => ElfRelocationKind.Copy,
            21 => ElfRelocationKind.GlobalData,
            22 => ElfRelocationKind.JumpSlot,
            23 => ElfRelocationKind.Relative,
            17 or 18 or 19 => ElfRelocationKind.Tls,
            160 => ElfRelocationKind.IRelative,
            _ => ElfRelocationKind.Other,
        },
        EmRiscV => type switch
        {
            0 => ElfRelocationKind.None,
            1 or 2 => ElfRelocationKind.Absolute,
            3 => ElfRelocationKind.Relative,
            4 => ElfRelocationKind.Copy,
            5 => ElfRelocationKind.JumpSlot,
            6 or 7 or 8 or 9 or 10 or 11 => ElfRelocationKind.Tls,
            58 => ElfRelocationKind.IRelative,
            _ => ElfRelocationKind.Other,
        },
        EmPpc or EmPpc64 => type switch
        {
            0 => ElfRelocationKind.None,
            1 or 38 => ElfRelocationKind.Absolute,
            19 => ElfRelocationKind.Copy,
            20 => ElfRelocationKind.GlobalData,
            21 => ElfRelocationKind.JumpSlot,
            22 => ElfRelocationKind.Relative,
            248 => ElfRelocationKind.IRelative,
            _ => ElfRelocationKind.Other,
        },
        _ => type == 0 ? ElfRelocationKind.None : ElfRelocationKind.Other,
    };

    /// <summary>Width in bytes of the location an absolute relocation writes (4 for the 32-bit forms in 64-bit images).</summary>
    public static int AbsoluteWidth(ushort machine, uint type, bool is64) => machine switch
    {
        EmAarch64 => type == 258 ? 4 : 8,
        EmX64 => type == 10 ? 4 : 8,
        EmRiscV => type == 1 ? 4 : 8,
        EmPpc64 => type == 1 ? 4 : 8,
        _ => is64 ? 8 : 4,
    };

    public static string RelocationType(ushort machine, uint type) => (machine, type) switch
    {
        (_, 0) => "R_NONE",
        (EmAarch64, 257) => "R_AARCH64_ABS64",
        (EmAarch64, 258) => "R_AARCH64_ABS32",
        (EmAarch64, 1024) => "R_AARCH64_COPY",
        (EmAarch64, 1025) => "R_AARCH64_GLOB_DAT",
        (EmAarch64, 1026) => "R_AARCH64_JUMP_SLOT",
        (EmAarch64, 1027) => "R_AARCH64_RELATIVE",
        (EmAarch64, 1028) => "R_AARCH64_TLS_DTPMOD64",
        (EmAarch64, 1029) => "R_AARCH64_TLS_DTPREL64",
        (EmAarch64, 1030) => "R_AARCH64_TLS_TPREL64",
        (EmAarch64, 1031) => "R_AARCH64_TLSDESC",
        (EmAarch64, 1032) => "R_AARCH64_IRELATIVE",
        (EmX64, 1) => "R_X86_64_64",
        (EmX64, 2) => "R_X86_64_PC32",
        (EmX64, 5) => "R_X86_64_COPY",
        (EmX64, 6) => "R_X86_64_GLOB_DAT",
        (EmX64, 7) => "R_X86_64_JUMP_SLOT",
        (EmX64, 8) => "R_X86_64_RELATIVE",
        (EmX64, 10) => "R_X86_64_32",
        (EmX64, 16) => "R_X86_64_DTPMOD64",
        (EmX64, 17) => "R_X86_64_DTPOFF64",
        (EmX64, 18) => "R_X86_64_TPOFF64",
        (EmX64, 36) => "R_X86_64_TLSDESC",
        (EmX64, 37) => "R_X86_64_IRELATIVE",
        (EmX64, 38) => "R_X86_64_RELATIVE64",
        (EmX86, 1) => "R_386_32",
        (EmX86, 2) => "R_386_PC32",
        (EmX86, 5) => "R_386_COPY",
        (EmX86, 6) => "R_386_GLOB_DAT",
        (EmX86, 7) => "R_386_JUMP_SLOT",
        (EmX86, 8) => "R_386_RELATIVE",
        (EmX86, 14) => "R_386_TLS_TPOFF",
        (EmX86, 35) => "R_386_TLS_DTPMOD32",
        (EmX86, 36) => "R_386_TLS_DTPOFF32",
        (EmX86, 37) => "R_386_TLS_TPOFF32",
        (EmX86, 42) => "R_386_IRELATIVE",
        (EmArm, 2) => "R_ARM_ABS32",
        (EmArm, 3) => "R_ARM_REL32",
        (EmArm, 17) => "R_ARM_TLS_DTPMOD32",
        (EmArm, 18) => "R_ARM_TLS_DTPOFF32",
        (EmArm, 19) => "R_ARM_TLS_TPOFF32",
        (EmArm, 20) => "R_ARM_COPY",
        (EmArm, 21) => "R_ARM_GLOB_DAT",
        (EmArm, 22) => "R_ARM_JUMP_SLOT",
        (EmArm, 23) => "R_ARM_RELATIVE",
        (EmArm, 160) => "R_ARM_IRELATIVE",
        (EmRiscV, 1) => "R_RISCV_32",
        (EmRiscV, 2) => "R_RISCV_64",
        (EmRiscV, 3) => "R_RISCV_RELATIVE",
        (EmRiscV, 4) => "R_RISCV_COPY",
        (EmRiscV, 5) => "R_RISCV_JUMP_SLOT",
        (EmRiscV, 58) => "R_RISCV_IRELATIVE",
        (EmMips or EmMipsLe, 2) => "R_MIPS_32",
        (EmMips or EmMipsLe, 3) => "R_MIPS_REL32",
        (EmMips or EmMipsLe, 126) => "R_MIPS_COPY",
        (EmMips or EmMipsLe, 127) => "R_MIPS_JUMP_SLOT",
        (EmPpc or EmPpc64, 1) => "R_PPC_ADDR32",
        (EmPpc or EmPpc64, 19) => "R_PPC_COPY",
        (EmPpc or EmPpc64, 20) => "R_PPC_GLOB_DAT",
        (EmPpc or EmPpc64, 21) => "R_PPC_JMP_SLOT",
        (EmPpc or EmPpc64, 22) => "R_PPC_RELATIVE",
        (EmPpc64, 38) => "R_PPC64_ADDR64",
        _ => $"R_{Machine(machine)[3..]}_{type}",
    };
}
