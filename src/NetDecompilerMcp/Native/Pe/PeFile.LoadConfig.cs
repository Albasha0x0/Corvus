namespace NetDecompilerMcp.Native.Pe;

/// <summary>
/// An entry of a guard table: a target RVA and, when the table stride is above 4 bytes, the first metadata byte
/// (0x1 suppressed call, 0x2 export suppressed, 0x4 language exception handler, 0x8 XFG hash present).
/// </summary>
public sealed record PeGuardEntry(uint Rva, byte Flags);

/// <summary>
/// IMAGE_LOAD_CONFIG_DIRECTORY32 / 64. Fields past the structure's Size are 0. Pointer fields are VAs as stored; the
/// tables they point at are decoded into RVAs.
/// </summary>
public sealed record PeLoadConfig(
    uint Size,
    uint TimeDateStamp,
    ushort MajorVersion,
    ushort MinorVersion,
    uint GlobalFlagsClear,
    uint GlobalFlagsSet,
    uint CriticalSectionDefaultTimeout,
    ushort DependentLoadFlags,
    ulong SecurityCookie,
    ulong SeHandlerTable,
    ulong SeHandlerCount,
    ulong GuardCfCheckFunctionPointer,
    ulong GuardCfDispatchFunctionPointer,
    ulong GuardCfFunctionTable,
    ulong GuardCfFunctionCount,
    uint GuardFlags,
    ulong GuardAddressTakenIatEntryTable,
    ulong GuardAddressTakenIatEntryCount,
    ulong GuardLongJumpTargetTable,
    ulong GuardLongJumpTargetCount,
    ulong DynamicValueRelocTable,
    ulong ChpeMetadataPointer,
    ulong EnclaveConfigurationPointer,
    ulong VolatileMetadataPointer,
    ulong GuardEhContinuationTable,
    ulong GuardEhContinuationCount,
    ulong GuardXfgCheckFunctionPointer,
    ulong GuardXfgDispatchFunctionPointer,
    ulong GuardXfgTableDispatchFunctionPointer,
    IReadOnlyList<uint> SeHandlerRvas,
    IReadOnlyList<PeGuardEntry> GuardCfFunctions,
    IReadOnlyList<PeGuardEntry> GuardAddressTakenIatEntries,
    IReadOnlyList<PeGuardEntry> GuardLongJumpTargets,
    IReadOnlyList<PeGuardEntry> GuardEhContinuationTargets)
{
    public IReadOnlyList<string> GuardFlagNames => PeNames.GuardFlags(GuardFlags);
    /// <summary>Bytes per guard table entry: a 4-byte RVA plus the metadata size in the top nibble of the guard flags.</summary>
    public int GuardTableStride => 4 + (int)(GuardFlags >> 28);
}

public sealed partial class PeFile
{
    private PeLoadConfig? ParseLoadConfig(IssueLog log)
    {
        var dir = Directory(PeDirectory.LoadConfig);
        if (dir.Rva == 0) return null;
        if (!TryU32(dir.Rva, out uint size))
        {
            log.Add($"load config at RVA 0x{dir.Rva:X} is outside the mapped image");
            return null;
        }
        if (size == 0) size = dir.Size;
        int maxSize = Is64Bit ? 320 : 192;
        var block = new byte[Math.Min(size, (uint)maxSize)];
        int available = Read(dir.Rva, block);
        if (available < block.Length) log.Add($"load config (Size 0x{size:X}) runs out of the mapped image after 0x{available:X} bytes", RvaToOffsetOrNull(dir.Rva));
        if (size < 0x40) log.Add($"load config Size 0x{size:X} is smaller than the oldest layout (0x40)", RvaToOffsetOrNull(dir.Rva));

        uint F32(int at) => at + 4 <= available ? Le32(block, at) : 0;
        ushort F16(int at) => at + 2 <= available ? Le16(block, at) : (ushort)0;
        ulong FPtr(int at32, int at64) => Is64Bit ? (at64 + 8 <= available ? Le64(block, at64) : 0) : F32(at32);

        uint guardFlags = F32(Is64Bit ? 144 : 88);
        int stride = 4 + (int)(guardFlags >> 28);
        ulong sehTable = FPtr(64, 96), sehCount = FPtr(68, 104);
        ulong cfTable = FPtr(80, 128), cfCount = FPtr(84, 136);
        ulong iatTable = FPtr(104, 160), iatCount = FPtr(108, 168);
        ulong ljTable = FPtr(112, 176), ljCount = FPtr(116, 184);
        ulong ehTable = FPtr(164, 264), ehCount = FPtr(168, 272);

        var seh = new List<uint>();
        if (sehTable != 0 && sehCount != 0)
            foreach (var e in GuardTable(sehTable, sehCount, 4, "SEH handler table", log)) seh.Add(e.Rva);

        return new PeLoadConfig(
            Size: size,
            TimeDateStamp: F32(4),
            MajorVersion: F16(8),
            MinorVersion: F16(10),
            GlobalFlagsClear: F32(12),
            GlobalFlagsSet: F32(16),
            CriticalSectionDefaultTimeout: F32(20),
            DependentLoadFlags: F16(Is64Bit ? 78 : 54),
            SecurityCookie: FPtr(60, 88),
            SeHandlerTable: sehTable,
            SeHandlerCount: sehCount,
            GuardCfCheckFunctionPointer: FPtr(72, 112),
            GuardCfDispatchFunctionPointer: FPtr(76, 120),
            GuardCfFunctionTable: cfTable,
            GuardCfFunctionCount: cfCount,
            GuardFlags: guardFlags,
            GuardAddressTakenIatEntryTable: iatTable,
            GuardAddressTakenIatEntryCount: iatCount,
            GuardLongJumpTargetTable: ljTable,
            GuardLongJumpTargetCount: ljCount,
            DynamicValueRelocTable: FPtr(120, 192),
            ChpeMetadataPointer: FPtr(124, 200),
            EnclaveConfigurationPointer: FPtr(156, 248),
            VolatileMetadataPointer: FPtr(160, 256),
            GuardEhContinuationTable: ehTable,
            GuardEhContinuationCount: ehCount,
            GuardXfgCheckFunctionPointer: FPtr(172, 280),
            GuardXfgDispatchFunctionPointer: FPtr(176, 288),
            GuardXfgTableDispatchFunctionPointer: FPtr(180, 296),
            SeHandlerRvas: seh,
            GuardCfFunctions: GuardTable(cfTable, cfCount, stride, "CFG function table", log),
            GuardAddressTakenIatEntries: GuardTable(iatTable, iatCount, stride, "CFG address-taken IAT table", log),
            GuardLongJumpTargets: GuardTable(ljTable, ljCount, stride, "CFG longjmp target table", log),
            GuardEhContinuationTargets: GuardTable(ehTable, ehCount, stride, "EH continuation table", log));
    }

    /// <summary><paramref name="count"/> entries of <paramref name="stride"/> bytes at VA <paramref name="va"/>.</summary>
    private List<PeGuardEntry> GuardTable(ulong va, ulong count, int stride, string what, IssueLog log)
    {
        var result = new List<PeGuardEntry>();
        if (va == 0 || count == 0) return result;
        if (!TryVaToRva(va, out uint rva))
        {
            log.Add($"{what} VA 0x{va:X} is below the image base");
            return result;
        }
        if (count > PeLimits.MaxGuardTableEntries)
        {
            log.Add($"{what} declares {count} entries; the first {PeLimits.MaxGuardTableEntries} are read");
            count = PeLimits.MaxGuardTableEntries;
        }
        var bytes = new byte[(int)Math.Min(count, (ulong)FitCount(rva, stride)) * stride];
        int read = Read(rva, bytes) / stride;
        if ((ulong)read < count) log.Add($"{what} at RVA 0x{rva:X} runs out of the mapped image after {read} of {count} entries", RvaToOffsetOrNull(rva));
        result.Capacity = read;
        for (int i = 0; i < read; i++)
            result.Add(new PeGuardEntry(Le32(bytes, i * stride), stride > 4 ? bytes[i * stride + 4] : (byte)0));
        return result;
    }
}
