using System.Buffers.Binary;

namespace NetDecompilerMcp.Native.Pe;

/// <summary>IMAGE_REL_BASED_* types; 5, 7, 8 and 9 are machine specific (named here for ARM, RISC-V and MIPS).</summary>
public enum PeRelocationType : byte
{
    Absolute = 0,
    High = 1,
    Low = 2,
    HighLow = 3,
    HighAdj = 4,
    /// <summary>ARM MOVW/MOVT pair; MIPS_JMPADDR; RISCV_HIGH20.</summary>
    ArmMov32 = 5,
    Reserved = 6,
    /// <summary>Thumb-2 MOVW/MOVT pair; RISCV_LOW12I.</summary>
    ThumbMov32 = 7,
    /// <summary>RISCV_LOW12S; LOONGARCH_MARK_LA.</summary>
    RiscVLow12S = 8,
    /// <summary>MIPS_JMPADDR16; IA64_IMM64.</summary>
    MipsJmpAddr16 = 9,
    Dir64 = 10,
}

/// <summary>A base relocation: the patched location and how. <see cref="Parameter"/> is the extra entry of HIGHADJ.</summary>
public sealed record PeRelocation(uint Rva, PeRelocationType Type, ushort Parameter = 0);

public sealed partial class PeFile
{
    private sealed record RelocationTable(IReadOnlyList<PeRelocation> All, IReadOnlyList<uint> PointerRvas)
    {
        public static readonly RelocationTable Empty = new([], []);
    }

    /// <summary>
    /// Relocation blocks (page RVA, block size, 16-bit entries) across the directory. A block smaller than its header
    /// ends the walk, as it ends the loader's.
    /// </summary>
    private RelocationTable ParseRelocations(IssueLog log)
    {
        var dir = Directory(PeDirectory.BaseRelocation);
        if (dir.Rva == 0 || dir.Size == 0) return RelocationTable.Empty;
        var budget = new WorkBudget(log);
        var all = new List<PeRelocation>();
        var pointers = new List<uint>();
        var pointerType = Is64Bit ? PeRelocationType.Dir64 : PeRelocationType.HighLow;
        long at = dir.Rva, end = (long)dir.Rva + dir.Size;
        bool unknownReported = false, outsideReported = false;
        while (at + 8 <= end)
        {
            if (!budget.Step()) break;
            if (!TryU32(at, out uint page) || !TryU32(at + 4, out uint blockSize))
            {
                log.Add($"relocation block at RVA 0x{at:X} is outside the mapped image", RvaToOffsetOrNull(at));
                break;
            }
            if (blockSize < 8)
            {
                if (page != 0 || blockSize != 0)
                    log.Add($"relocation block at RVA 0x{at:X} has size {blockSize}; the walk stops", RvaToOffsetOrNull(at));
                break;
            }
            long blockEnd = at + blockSize;
            if (blockEnd > end)
            {
                log.Add($"relocation block at RVA 0x{at:X} (size 0x{blockSize:X}) runs past the end of the directory; cut", RvaToOffsetOrNull(at));
                blockEnd = end;
            }
            int count = (int)((blockEnd - at - 8) / 2);
            var entries = ReadBlock(at + 8, count * 2);
            if (entries == null)
            {
                log.Add($"relocation entries at RVA 0x{at + 8:X} are outside the mapped image", RvaToOffsetOrNull(at));
                break;
            }
            if (!budget.Step(count)) break;
            for (int i = 0; i < count; i++)
            {
                ushort e = BinaryPrimitives.ReadUInt16LittleEndian(entries.AsSpan(i * 2));
                var type = (PeRelocationType)(e >> 12);
                if (type == PeRelocationType.Absolute) continue;
                uint rva = unchecked(page + (uint)(e & 0xFFF));
                ushort parameter = 0;
                if (type == PeRelocationType.HighAdj && i + 1 < count)
                    parameter = BinaryPrimitives.ReadUInt16LittleEndian(entries.AsSpan(++i * 2));
                if ((byte)type > (byte)PeRelocationType.Dir64 && !unknownReported)
                {
                    unknownReported = true;
                    log.Add($"unknown relocation type {(int)type} at RVA 0x{rva:X}");
                }
                if (!outsideReported && (long)rva + 4 > Optional.SizeOfImage)
                {
                    outsideReported = true;
                    log.Add($"relocation at RVA 0x{rva:X} patches outside SizeOfImage");
                }
                if (all.Count >= PeLimits.MaxRelocations)
                {
                    log.Add($"more than {PeLimits.MaxRelocations} relocations; the rest are not read");
                    return Finish();
                }
                all.Add(new PeRelocation(rva, type, parameter));
                if (type == pointerType) pointers.Add(rva);
            }
            at += blockSize;
        }
        return Finish();

        RelocationTable Finish()
        {
            pointers.Sort();
            int n = 0;
            for (int i = 0; i < pointers.Count; i++)
                if (n == 0 || pointers[i] != pointers[n - 1]) pointers[n++] = pointers[i];
            pointers.RemoveRange(n, pointers.Count - n);
            return new RelocationTable(all, pointers);
        }
    }
}
