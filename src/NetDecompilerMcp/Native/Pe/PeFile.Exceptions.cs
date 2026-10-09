using System.Buffers.Binary;

namespace NetDecompilerMcp.Native.Pe;

public sealed partial class PeFile
{
    /// <summary>
    /// The exception directory as function ranges. x64: RUNTIME_FUNCTION (begin, end, unwind info). ARM64 and ARM:
    /// (begin, unwind data) where the low two bits of the unwind data select packed unwind data (function length in
    /// bits 2-12) or an .xdata record (function length in bits 0-17 of its first word); lengths count 4-byte units on
    /// ARM64 and 2-byte units on ARM. Packed entries have an unwind info RVA of 0.
    /// </summary>
    private IReadOnlyList<RuntimeFunction> ParseRuntimeFunctions(IssueLog log)
    {
        var dir = Directory(PeDirectory.Exception);
        if (dir.Rva == 0 || dir.Size == 0) return [];
        var arch = Arch;
        int entrySize = arch switch
        {
            NativeArch.X64 => 12,
            NativeArch.Arm64 or NativeArch.Arm => 8,
            _ => 0,
        };
        if (entrySize == 0)
        {
            log.Add($"exception directory present on {MachineName}, which has no RUNTIME_FUNCTION table; ignored");
            return [];
        }
        if (dir.Size % entrySize != 0)
            log.Add($"exception directory size 0x{dir.Size:X} is not a multiple of the {entrySize}-byte entry");
        long count = dir.Size / entrySize;
        if (count > PeLimits.MaxRuntimeFunctions)
        {
            log.Add($"{count} runtime functions declared; the first {PeLimits.MaxRuntimeFunctions} are read");
            count = PeLimits.MaxRuntimeFunctions;
        }
        var bytes = new byte[Math.Min(count, FitCount(dir.Rva, entrySize)) * entrySize];
        int read = Read(dir.Rva, bytes) / entrySize;
        if (read < count)
            log.Add($"exception directory runs out of the mapped image after {read} of {count} entries", RvaToOffsetOrNull(dir.Rva));

        var budget = new WorkBudget(log);
        var result = new List<RuntimeFunction>(read);
        int invalid = 0;
        uint unitShift = arch == NativeArch.Arm64 ? 2u : 1u;
        for (int i = 0; i < read; i++)
        {
            if (!budget.Step()) break;
            var e = bytes.AsSpan(i * entrySize);
            uint begin = BinaryPrimitives.ReadUInt32LittleEndian(e), end, unwind;
            if (arch == NativeArch.X64)
            {
                end = BinaryPrimitives.ReadUInt32LittleEndian(e[4..]);
                unwind = BinaryPrimitives.ReadUInt32LittleEndian(e[8..]);
                if (begin == 0 && end == 0 && unwind == 0) continue;
            }
            else
            {
                uint unwindData = BinaryPrimitives.ReadUInt32LittleEndian(e[4..]);
                if (begin == 0 && unwindData == 0) continue;
                if (arch == NativeArch.Arm) begin &= ~1u; // Thumb bit
                uint length;
                if ((unwindData & 3) == 0)
                {
                    unwind = unwindData;
                    if (!TryU32(unwindData, out uint header))
                    {
                        invalid++;
                        continue;
                    }
                    length = (header & 0x3FFFF) << (int)unitShift;
                }
                else
                {
                    unwind = 0;
                    length = ((unwindData >> 2) & 0x7FF) << (int)unitShift;
                }
                end = unchecked(begin + length);
            }
            if (end <= begin || Locate(begin) < 0)
            {
                invalid++;
                continue;
            }
            result.Add(new RuntimeFunction(begin, end, unwind));
        }
        if (invalid > 0) log.Add($"{invalid} runtime function entries have an empty or unmapped range or unreadable unwind data; skipped");
        for (int i = 1; i < result.Count; i++)
            if (result[i].BeginRva < result[i - 1].BeginRva)
            {
                log.Add("runtime functions are not sorted by begin address; unwinding (a binary search) can miss some");
                result.Sort((a, b) => a.BeginRva.CompareTo(b.BeginRva));
                break;
            }
        return result;
    }
}
